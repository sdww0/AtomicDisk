// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

use core::cell::RefCell;

use crate::{
    bail,
    bio::MemDisk,
    ensure,
    os::{Arc, HashMap},
    pfs::sys::{
        cache::LruCache,
        file::{FileInner, FileStatus, OpenMode, OpenOptions},
        host::{
            self, block_file::BlockFile, journal::RecoveryJournal, HostFs, RecoveryHandler,
            RECOVERY_NODE_SIZE,
        },
        keys::{FsKeyGen, RestoreKey},
        metadata::{
            MetadataInfo, FILENAME_MAX_LEN, FULLNAME_MAX_LEN, MD_USER_DATA_SIZE, SGX_FILE_ID,
            SGX_FILE_MAJOR_VERSION,
        },
        node::{FileNode, FileNodeRef, NodeType, NODE_SIZE},
    },
    prelude::*,
    AeadKey, BlockSet, Errno,
};

pub const SE_PAGE_SIZE: usize = 0x1000;
macro_rules! is_page_aligned {
    ($num:expr) => {
        $num & (SE_PAGE_SIZE - 1) == 0
    };
}

pub const DEFAULT_CACHE_SIZE: usize = 2400 * SE_PAGE_SIZE;

impl<D: BlockSet> FileInner<D> {
    pub fn open(
        path: &str,
        disk: D,
        opts: &OpenOptions,
        mode: &OpenMode,
        cache_size: Option<usize>,
    ) -> Result<Self> {
        let cache_size = Self::check_cache_size(cache_size)?;
        let file_name = path;
        let key_gen = FsKeyGen::new(mode)?;

        let mut host_file = BlockFile::create(Self::subdisk_for_data(&disk)?);
        let mut journal = RecoveryJournal::create(Self::subdisk_for_journal(&disk)?);

        let mut offset = 0;
        let (metadata, root_mht, rollback_nodes) = {
            let (metadata, root_mht, rollback_nodes) =
                match Self::open_file(&mut host_file, file_name, &key_gen, mode) {
                    Ok((_metadata, _root_mht)) => {
                        // use recovery file to discard all uncommitted nodes
                        let rollback_nodes =
                            Self::recover_and_reopen_file(&mut host_file, &mut journal)?;
                        let (metadata, root_mht) =
                            Self::open_file(&mut host_file, file_name, &key_gen, mode)?;
                        (metadata, root_mht, rollback_nodes)
                    }
                    Err(e) if e.errno() == Errno::RecoveryNeeded => {
                        let rollback_nodes =
                            Self::recover_and_reopen_file(&mut host_file, &mut journal)?;

                        let (metadata, root_mht) =
                            Self::open_file(&mut host_file, file_name, &key_gen, mode)?;
                        (metadata, root_mht, rollback_nodes)
                    }
                    Err(e) => bail!(e),
                };

            if opts.append && !opts.update {
                offset = metadata.encrypted_plain.size;
            }
            (metadata, root_mht, rollback_nodes)
        };

        let mut protected_file = Self {
            host_file,
            metadata,
            root_mht,
            key_gen,
            opts: *opts,
            need_writing: false,
            end_of_file: false,
            max_cache_page: cache_size,
            offset,
            last_error: None,
            status: FileStatus::NotInitialized,
            journal,
            journal_enabled: false,
            cache: LruCache::new(cache_size),
        };
        if !rollback_nodes.is_empty() {
            protected_file.rollback_nodes(rollback_nodes)?;
        }
        protected_file.status = FileStatus::Ok;
        Ok(protected_file)
    }

    pub fn create(
        path: &str,
        disk: D,
        opts: &OpenOptions,
        mode: &OpenMode,
        cache_size: Option<usize>,
    ) -> Result<Self> {
        let cache_size = Self::check_cache_size(cache_size)?;
        let file_name = path;
        // Self::check_open_param(path, file_name, opts, mode)?;

        let key_gen = FsKeyGen::new(mode)?;

        //Self::check_file_exist(opts, mode, path)?;
        // 10MB
        let host_file = BlockFile::create(Self::subdisk_for_data(&disk)?);
        let journal = RecoveryJournal::create(Self::subdisk_for_journal(&disk)?);
        let need_writing = true;
        let (metadata, root_mht, rollback_nodes) = {
            let metadata = Self::new_file(file_name, mode)?;
            (
                metadata,
                FileNode::new_root_ref(mode.into()),
                HashMap::new(),
            )
        };

        let mut protected_file = Self {
            host_file,
            metadata,
            root_mht,
            key_gen,
            opts: *opts,
            need_writing,
            end_of_file: false,
            max_cache_page: cache_size,
            offset: 0,
            last_error: None,
            status: FileStatus::NotInitialized,
            journal,
            journal_enabled: false,
            cache: LruCache::new(cache_size),
        };
        if !rollback_nodes.is_empty() {
            protected_file.rollback_nodes(rollback_nodes)?;
        }
        protected_file.status = FileStatus::Ok;
        Ok(protected_file)
    }

    fn open_file(
        host_file: &mut dyn HostFs,
        file_name: &str,
        key_gen: &dyn RestoreKey,
        mode: &OpenMode,
    ) -> Result<(MetadataInfo, FileNodeRef)> {
        let mut metadata = MetadataInfo::default();
        metadata.read_from_disk(host_file)?;

        ensure!(
            metadata.node.metadata.plaintext.file_id == SGX_FILE_ID,
            Error::with_msg(Errno::SgxError, "SGX_FILE_ID mismatch")
        );
        ensure!(
            metadata.node.metadata.plaintext.major_version == SGX_FILE_MAJOR_VERSION,
            Error::with_msg(Errno::SgxError, "SGX_FILE_MAJOR_VERSION mismatch")
        );
        ensure!(
            !metadata.update_flag(),
            Error::with_msg(Errno::SgxError, "Recovery needed")
        );

        let encrypt_flags = mode.into();
        ensure!(
            encrypt_flags == metadata.encrypt_flags(),
            Error::with_msg(Errno::InvalidArgs, "encrypt_flags mismatch")
        );

        let key_policy = mode.key_policy();
        if mode.is_auto_key() {
            ensure!(
                key_policy.unwrap() == metadata.key_policy(),
                Error::with_msg(Errno::InvalidArgs, "key_policy mismatch")
            );
        }

        let key = match mode.import_key() {
            Some(key) => {
                metadata.set_key_policy(key_policy.unwrap());
                *key
            }
            None => metadata.restore_key(key_gen)?,
        };
        metadata.decrypt(&key)?;

        let meta_file_name = metadata.file_name()?;
        ensure!(
            meta_file_name == file_name,
            Error::with_msg(Errno::SgxError, "Name mismatch")
        );

        let mut root_mht = FileNode::new_root(encrypt_flags);
        if metadata.encrypted_plain.size > MD_USER_DATA_SIZE {
            root_mht.read_from_disk(host_file)?;
            root_mht.decrypt(
                &metadata.encrypted_plain.mht_key,
                &metadata.encrypted_plain.mht_gmac,
            )?;
            root_mht.new_node = false;
        }
        Ok((metadata, FileNode::build_ref(root_mht)))
    }

    #[inline]
    fn new_file(file_name: &str, mode: &OpenMode) -> Result<MetadataInfo> {
        let mut metadata = MetadataInfo::new();

        metadata.set_encrypt_flags(mode.into());
        if let Some(key_policy) = mode.key_policy() {
            metadata.set_key_policy(key_policy);
        }
        metadata.encrypted_plain.file_name[0..file_name.len()]
            .copy_from_slice(file_name.as_bytes());

        Ok(metadata)
    }

    pub fn rollback_nodes(
        &mut self,
        rollback_nodes: HashMap<u64, Arc<RefCell<FileNode>>>,
    ) -> Result<()> {
        for (physical_number, data_node) in rollback_nodes {
            assert!(Self::is_data_node(physical_number));

            data_node.borrow_mut().encrypt_flags = self.metadata.encrypt_flags();

            let mht_logical_number = RecoveryHandler::calculate_mht_logical_number(physical_number);

            let parent_mht = self.get_mht_node_by_logic_number(mht_logical_number)?;
            // udpated the parent of data node
            data_node.borrow_mut().parent = Some(parent_mht);

            self.rollback_data_node(physical_number, data_node)?;

            // Only rollback data nodes, mht nodes should be calculated by data nodes' key and mac
        }
        Ok(())
    }

    #[inline]
    fn recover_and_reopen_file(
        host_file: &mut BlockFile<D>,
        journal: &mut RecoveryJournal<D>,
    ) -> Result<HashMap<u64, Arc<RefCell<FileNode>>>> {
        // TODO check recovery file size

        let roll_back_nodes = host::journal::recovery(host_file, journal)?;

        Ok(roll_back_nodes)
    }

    #[inline]
    fn check_open_param(path: &str, name: &str, opts: &OpenOptions, mode: &OpenMode) -> Result<()> {
        let path_len = path.len();
        ensure!(
            (path_len > 0 && path_len < FULLNAME_MAX_LEN - 1),
            Error::with_msg(Errno::InvalidArgs, "path length invalid")
        );

        let name_len = name.len();
        ensure!(
            name_len > 0,
            Error::with_msg(Errno::InvalidArgs, "name length invalid")
        );
        ensure!(
            name_len < FILENAME_MAX_LEN - 1,
            Error::with_msg(Errno::InvalidArgs, "name length invalid")
        );

        opts.check()?;
        mode.check()?;

        Ok(())
    }

    #[inline]
    fn check_cache_size(cache_size: Option<usize>) -> Result<usize> {
        cache_size
            .or(Some(DEFAULT_CACHE_SIZE))
            .and_then(|cache_size| {
                if is_page_aligned!(cache_size) {
                    Some(cache_size / SE_PAGE_SIZE)
                } else {
                    None
                }
            })
            .ok_or_else(|| Error::with_msg(Errno::InvalidArgs, "cache size invalid"))
    }

    fn subdisk_for_data(disk: &D) -> Result<D> {
        disk.subset(0..disk.nblocks() * 7 / 8)
    }

    fn subdisk_for_journal(disk: &D) -> Result<D> {
        disk.subset(disk.nblocks() * 7 / 8..disk.nblocks())
    }
}
