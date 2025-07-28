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

use super::host::{block_file::BlockFile, journal::RecoveryJournal};
use crate::{
    bail,
    bio::MemDisk,
    ensure,
    os::{Arc, HashMap, Mutex, SeekFrom},
    pfs::{
        sgx::KeyPolicy,
        sys::{
            cache::LruCache,
            keys::FsKeyGen,
            metadata::MetadataInfo,
            node::{FileNode, FileNodeRef},
            EncryptMode,
        },
    },
    prelude::{Error, Result},
    AeadKey, AeadMac, BlockSet, Errno,
};

mod close;
mod flush;
mod node;
mod open;
mod other;
mod read;
mod write;

#[derive(Debug)]
pub struct ProtectedFile<D> {
    file: Mutex<FileInner<D>>,
}

#[derive(Debug)]
pub struct FileInner<D> {
    host_file: BlockFile<D>,
    metadata: MetadataInfo,
    root_mht: FileNodeRef,
    key_gen: FsKeyGen,
    opts: OpenOptions,
    need_writing: bool,
    end_of_file: bool,
    max_cache_page: usize,
    offset: usize,
    last_error: Option<Error>,
    status: FileStatus,
    journal: RecoveryJournal<D>,
    journal_enabled: bool,
    cache: LruCache<FileNode>,
}

impl<D: BlockSet> ProtectedFile<D> {
    pub fn open(
        disk: D,
        path: &str,
        opts: &OpenOptions,
        mode: &OpenMode,
        cache_size: Option<usize>,
    ) -> Result<Self> {
        let file = FileInner::open(path.as_ref(), disk, opts, mode, cache_size)?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }
    pub fn create(
        disk: D,
        path: &str,
        opts: &OpenOptions,
        mode: &OpenMode,
        cache_size: Option<usize>,
    ) -> Result<Self> {
        let file = FileInner::create(path.as_ref(), disk, opts, mode, cache_size)?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }

    pub fn write(&self, buf: &[u8]) -> Result<usize> {
        let mut file = self.file.lock();
        file.write(buf).map_err(|error| {
            file.set_last_error(error);
            error
        })
    }

    pub fn write_at(&self, buf: &[u8], offset: u64) -> Result<usize> {
        let mut file = self.file.lock();
        file.write_at(buf, offset).map_err(|error| {
            file.set_last_error(error);
            error
        })
    }

    pub fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let mut file = self.file.lock();
        file.read(buf).map_err(|error| {
            file.set_last_error(error);
            error
        })
    }

    pub fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize> {
        let mut file = self.file.lock();
        file.read_at(buf, offset).map_err(|error| {
            file.set_last_error(error);
            error
        })
    }

    #[cfg(feature = "asterinas")]
    pub fn read_at_with_writer(
        &self,
        writer: &mut ostd::mm::VmWriter,
        offset: u64,
    ) -> Result<usize> {
        let mut file = self.file.lock();
        file.read_at_with_writer(writer, offset).map_err(|error| {
            file.set_last_error(error);
            error
        })
    }

    #[cfg(feature = "asterinas")]
    pub fn write_at_with_reader(
        &self,
        reader: &mut ostd::mm::VmReader,
        offset: u64,
    ) -> Result<usize> {
        let mut file = self.file.lock();
        file.write_at_with_reader(reader, offset).map_err(|error| {
            file.set_last_error(error);
            error
        })
    }

    pub fn tell(&self) -> Result<u64> {
        let mut file = self.file.lock();
        file.tell().map_err(|error| {
            file.set_last_error(error);
            error
        })
    }

    pub fn seek(&self, pos: SeekFrom) -> Result<u64> {
        let mut file = self.file.lock();
        file.seek(pos).map_err(|error| {
            file.set_last_error(error);
            error
        })
    }

    pub fn set_len(&self, size: u64) -> Result<()> {
        let mut file = self.file.lock();
        file.set_len(size).map_err(|error| {
            file.set_last_error(error);
            error
        })
    }

    pub fn flush(&self) -> Result<()> {
        let mut file = self.file.lock();
        file.flush().map_err(|error| {
            file.set_last_error(error);
            error
        })
    }

    pub fn file_size(&self) -> Result<u64> {
        let file = self.file.lock();
        file.file_size()
    }

    pub fn get_eof(&self) -> bool {
        let file = self.file.lock();
        file.get_eof()
    }

    pub fn get_error(&self) -> Option<Error> {
        let file = self.file.lock();
        file.get_last_error()
    }

    pub fn clear_cache(&self) -> Result<()> {
        let mut file = self.file.lock();
        file.clear_cache().map_err(|error| {
            file.set_last_error(error);
            error
        })
    }

    pub fn clear_error(&self) -> Result<()> {
        let mut file = self.file.lock();
        file.clear_error().map_err(|error| {
            file.set_last_error(error);
            error
        })
    }

    pub fn get_metadata_mac(&self) -> Result<AeadMac> {
        let mut file = self.file.lock();
        file.get_metadata_mac().map_err(|error| {
            file.set_last_error(error);
            error
        })
    }

    pub fn close(&self) -> Result<()> {
        let mut file = self.file.lock();
        file.close(CloseMode::Normal).map(|_| ())
    }

    pub fn rename<P: AsRef<str>, Q: AsRef<str>>(&self, old_name: P, new_name: Q) -> Result<()> {
        let mut file = self.file.lock();
        file.rename(old_name.as_ref(), new_name.as_ref())
            .map_err(|error| {
                file.set_last_error(error);
                error
            })
    }

    pub fn remove(path: &str) -> Result<()> {
        FileInner::<D>::remove(path)
    }

    #[cfg(test)]
    pub fn rollback_nodes(
        &self,
        rollback_nodes: HashMap<u64, Arc<RefCell<FileNode>>>,
    ) -> Result<()> {
        let mut file = self.file.lock();
        file.rollback_nodes(rollback_nodes)
    }
}

#[allow(dead_code)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FileStatus {
    Ok,
    NotInitialized,
    FlushError,
    WriteToDiskFailed,
    CryptoError,
    Corrupted,
    MemoryCorrupted,
    Closed,
}

impl FileStatus {
    #[inline]
    pub fn is_ok(&self) -> bool {
        matches!(*self, FileStatus::Ok)
    }
}

impl Default for FileStatus {
    #[inline]
    fn default() -> Self {
        FileStatus::NotInitialized
    }
}

#[derive(Clone, Copy, Debug)]
pub struct OpenOptions {
    pub read: bool,
    pub write: bool,
    pub append: bool,
    pub binary: bool,
    pub update: bool,
}

#[allow(dead_code)]
impl OpenOptions {
    pub fn new() -> OpenOptions {
        OpenOptions {
            read: false,
            write: false,
            append: false,
            binary: false,
            update: false,
        }
    }

    #[inline]
    pub fn read(mut self, read: bool) -> Self {
        self.read = read;
        self
    }
    #[inline]
    pub fn write(mut self, write: bool) -> Self {
        self.write = write;
        self
    }
    #[inline]
    pub fn append(mut self, append: bool) -> Self {
        self.append = append;
        self
    }
    #[inline]
    pub fn update(mut self, update: bool) -> Self {
        self.update = update;
        self
    }
    #[inline]
    pub fn binary(mut self, binary: bool) -> Self {
        self.binary = binary;
        self
    }
    #[inline]
    pub fn readonly(&self) -> bool {
        self.read && !self.update
    }

    pub fn check(&self) -> Result<()> {
        match (self.read, self.write, self.append) {
            (true, false, false) => Ok(()),
            (false, true, false) => Ok(()),
            (false, false, true) => Ok(()),
            _ => Err(Error::new(Errno::InvalidArgs)),
        }
    }
}

impl Default for OpenOptions {
    fn default() -> OpenOptions {
        OpenOptions::new()
    }
}

impl Eq for AeadKey {}

impl PartialEq for AeadKey {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OpenMode {
    AutoKey(KeyPolicy),
    UserKey(AeadKey),
    IntegrityOnly,
    ImportKey((AeadKey, KeyPolicy)),
    ExportKey,
}

impl OpenMode {
    #[inline]
    pub fn is_auto_key(&self) -> bool {
        matches!(*self, Self::AutoKey(_))
    }

    #[inline]
    pub fn is_integrity_only(&self) -> bool {
        matches!(*self, Self::IntegrityOnly)
    }

    #[inline]
    pub fn is_import_key(&self) -> bool {
        matches!(*self, Self::ImportKey(_))
    }

    #[inline]
    pub fn is_export_key(&self) -> bool {
        matches!(*self, Self::ExportKey)
    }

    #[inline]
    pub fn user_key(&self) -> Option<&AeadKey> {
        match self {
            Self::UserKey(key) => Some(key),
            _ => None,
        }
    }

    #[inline]
    pub fn import_key(&self) -> Option<&AeadKey> {
        match self {
            Self::ImportKey((key, _)) => Some(key),
            _ => None,
        }
    }

    #[inline]
    pub fn key_policy(&self) -> Option<KeyPolicy> {
        match self {
            Self::AutoKey(key_policy) | Self::ImportKey((_, key_policy)) => Some(*key_policy),
            _ => None,
        }
    }

    pub fn check(&self) -> Result<()> {
        match self {
            Self::AutoKey(key_policy) | Self::ImportKey((_, key_policy)) => {
                ensure!(key_policy.is_valid(), Error::new(Errno::InvalidArgs));
                ensure!(
                    key_policy.intersects(KeyPolicy::MRENCLAVE | KeyPolicy::MRSIGNER),
                    Error::new(Errno::InvalidArgs)
                );
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

impl From<EncryptMode> for OpenMode {
    fn from(encrypt_mode: EncryptMode) -> OpenMode {
        match encrypt_mode {
            //#[cfg(feature = "tfs")]
            EncryptMode::EncryptAutoKey(key_policy) => Self::AutoKey(key_policy),
            EncryptMode::EncryptUserKey(key) => Self::UserKey(key),
            EncryptMode::IntegrityOnly => Self::IntegrityOnly,
        }
    }
}

impl From<&EncryptMode> for OpenMode {
    fn from(encrypt_mode: &EncryptMode) -> OpenMode {
        match encrypt_mode {
            //  #[cfg(feature = "tfs")]
            EncryptMode::EncryptAutoKey(key_policy) => Self::AutoKey(*key_policy),
            EncryptMode::EncryptUserKey(key) => Self::UserKey(*key),
            EncryptMode::IntegrityOnly => Self::IntegrityOnly,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CloseMode {
    Normal,
    Import,
    Export,
}

#[cfg(test)]
mod test {
    use std::{path::Path, sync::Once};

    use log::info;
    use open::SE_PAGE_SIZE;

    use super::*;
    use crate::pfs::sys::{metadata::EncryptFlags, node::NodeType};

    static INIT_LOG: Once = Once::new();

    fn init_logger() {
        INIT_LOG.call_once(|| {
            env_logger::builder()
                .is_test(true)
                .filter_level(log::LevelFilter::Debug)
                .try_init()
                .unwrap();
        });
    }

    #[test]
    fn simple_read_write() {
        init_logger();
        let file_path = String::from("test.data");
        let opts = OpenOptions::new().read(false).write(true).append(false);
        let disk = MemDisk::create(1024).unwrap();
        let file = ProtectedFile::create(
            disk,
            &file_path,
            &opts,
            &OpenMode::UserKey(AeadKey::default()),
            None,
        )
        .unwrap();
        file.write(b"hello").unwrap();
        file.flush().unwrap();

        let mut read_buffer = vec![0u8; 5];
        file.seek(SeekFrom::Start(0)).unwrap();
        file.read(&mut read_buffer).unwrap();
        assert_eq!(read_buffer, b"hello");
    }

    #[test]
    fn sync_test() {
        init_logger();
        let file_path = String::from("test.data");
        let opts = OpenOptions::new().read(false).write(true);
        let disk = MemDisk::create(1024).unwrap();
        let file = ProtectedFile::create(
            disk.clone(),
            &file_path,
            &opts,
            &OpenMode::UserKey(AeadKey::default()),
            None,
        )
        .unwrap();
        let data = vec![1u8; 4096];
        file.write_at(&data, 0).unwrap();
        file.flush().unwrap();

        let data = vec![1u8; 4096];
        file.write_at(&data, 0).unwrap();
        file.flush().unwrap();

        drop(file);
        let file = ProtectedFile::open(
            disk,
            &file_path,
            &opts,
            &OpenMode::UserKey(AeadKey::default()),
            None,
        )
        .unwrap();
        let mut read_buffer = vec![0u8; 4096];
        file.read(&mut read_buffer).unwrap();
        assert_eq!(read_buffer, vec![1u8; 4096]);
    }

    #[test]
    fn multiple_block_write() {
        init_logger();
        let file_path = String::from("test.data");
        let _ = std::fs::File::create(&file_path).unwrap();
        let disk = MemDisk::create(1024).unwrap();
        let key = AeadKey::default();
        let opts = OpenOptions::new().read(false).write(false).append(true);
        let file =
            ProtectedFile::create(disk, &file_path, &opts, &OpenMode::UserKey(key), None).unwrap();

        let block_size = 4 * 1024;
        let block_number = 100;
        let write_buffer = vec![1u8; block_size];
        for _ in 0..block_number {
            file.write(&write_buffer).unwrap();
        }
        file.flush().unwrap();

        file.seek(SeekFrom::Start(0)).unwrap();
        let mut read_buffer = vec![0u8; block_size];
        for _ in 0..block_number {
            file.read(&mut read_buffer).unwrap();
            assert_eq!(read_buffer, vec![1u8; block_size]);
        }
    }

    #[test]
    fn seek_and_read() {
        init_logger();
        let file_path = String::from("test.data");
        let disk = MemDisk::create(1024).unwrap();
        let key = AeadKey::default();
        let opts = OpenOptions::new().read(false).write(true);
        let file =
            ProtectedFile::create(disk, &file_path, &opts, &OpenMode::UserKey(key), None).unwrap();

        let block_size = 4 * 1024;
        let block_number = 100;
        let write_buffer = vec![1u8; block_size];
        for i in 0..block_number {
            file.write_at(&write_buffer, i * block_size as u64).unwrap();
        }
        file.flush().unwrap();

        let pos = SeekFrom::Start(3072 as u64);

        let write_buffer = vec![2u8; block_size];
        file.seek(pos).unwrap();
        file.write(&write_buffer).unwrap();
        file.flush().unwrap();

        let mut read_buffer = vec![0u8; block_size];
        file.seek(pos).unwrap();
        file.read(&mut read_buffer).unwrap();
        assert_eq!(read_buffer, vec![2u8; block_size]);
    }

    #[test]
    fn skip_metadata_node() {
        init_logger();
        let offset = 3072;
        let block_size = 4 * 1024;
        let block_number = 100;

        let file_path = String::from("test.data");
        let disk = MemDisk::create(block_number * 2).unwrap();
        let key = AeadKey::default();
        let opts = OpenOptions::new().read(false).write(true);
        let file =
            ProtectedFile::create(disk, &file_path, &opts, &OpenMode::UserKey(key), None).unwrap();

        let write_buffer = vec![1u8; block_size];
        for i in 0..block_number {
            file.write_at(&write_buffer, (i * block_size + offset) as u64)
                .unwrap();
        }
        file.flush().unwrap();
    }

    #[test]
    fn ignore_mht_node_when_recovery() {
        init_logger();
        let source_path = String::from("test.data");
        let opts = OpenOptions::new().read(false).write(true);
        let key = AeadKey::default();
        let disk = MemDisk::create(1024).unwrap();
        let file = ProtectedFile::create(disk, &source_path, &opts, &OpenMode::UserKey(key), None)
            .unwrap();

        let block_size = 4 * 1024;
        let block_number = 100;
        const META_OFFSET: u64 = 3072;

        let write_buffer = vec![2u8; block_size];
        let offset = 5 * block_size as u64 + META_OFFSET;
        file.write_at(&write_buffer, offset).unwrap();

        // write enought to trigger eviction
        for i in 10..block_number {
            let offset = i * block_size as u64 + META_OFFSET;
            let write_buffer = vec![3u8; block_size];
            file.write_at(&write_buffer, offset).unwrap();
        }
        file.flush().unwrap();

        let write_buffer = vec![3u8; block_size];
        file.write_at(&write_buffer, offset).unwrap();

        // // write enought to trigger eviction
        for i in block_number..2 * block_number {
            let offset = i * block_size as u64 + META_OFFSET;
            let write_buffer = vec![3u8; block_size];
            file.write_at(&write_buffer, offset).unwrap();
        }

        let mut read_buffer = vec![0u8; block_size];
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.read(&mut read_buffer).unwrap();

        println!("{:?}", read_buffer);

        drop(file);
    }

    #[test]
    fn rollback_nodes() {
        let source_path = String::from("test.data");
        let opts = OpenOptions::new().read(false).write(true);
        let key = AeadKey::default();
        let disk = MemDisk::create(1024).unwrap();
        let file = ProtectedFile::create(
            disk.clone(),
            &source_path,
            &opts,
            &OpenMode::UserKey(key),
            None,
        )
        .unwrap();

        let block_size = 4 * 1024;
        let block_number = 100;
        const META_OFFSET: u64 = 3072;

        let write_buffer = vec![2u8; block_size];
        let offset = 5 * block_size as u64 + META_OFFSET;
        file.write_at(&write_buffer, offset).unwrap();

        // write enought to trigger eviction
        for i in 10..block_number {
            let offset = i * block_size as u64 + META_OFFSET;
            let write_buffer = vec![3u8; block_size];
            file.write_at(&write_buffer, offset).unwrap();
        }
        file.flush().unwrap();

        drop(file);

        let file =
            ProtectedFile::open(disk, &source_path, &opts, &OpenMode::UserKey(key), None).unwrap();

        let mut rollback_nodes = HashMap::new();
        let mut node1 = FileNode::new(NodeType::Data, 13, 15, EncryptFlags::UserKey);
        node1.plaintext.as_mut().copy_from_slice(&[3u8; 4096]);
        let mut node2 = FileNode::new(NodeType::Data, 14, 16, EncryptFlags::UserKey);
        node2.plaintext.as_mut().copy_from_slice(&[3u8; 4096]);
        let mut node3 = FileNode::new(NodeType::Data, 15, 17, EncryptFlags::UserKey);
        node3.plaintext.as_mut().copy_from_slice(&[3u8; 4096]);
        rollback_nodes.insert(15, Arc::new(RefCell::new(node1)));
        rollback_nodes.insert(16, Arc::new(RefCell::new(node2)));
        rollback_nodes.insert(17, Arc::new(RefCell::new(node3)));

        file.rollback_nodes(rollback_nodes).unwrap();

        file.flush().unwrap();

        let begin_offset = 13 * block_size as u64 + META_OFFSET;
        let mut read_buffer = vec![0u8; block_size];
        file.seek(SeekFrom::Start(begin_offset)).unwrap();
        file.read(&mut read_buffer).unwrap();
        assert_eq!(read_buffer, vec![3u8; block_size]);
    }
}
