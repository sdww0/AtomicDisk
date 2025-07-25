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

use crate::{
    bail, ensure,
    os::Vec,
    pfs::sys::{
        file::{FileInner, FileStatus},
        host::{self, HostFs},
        metadata::MD_USER_DATA_SIZE,
        node::FileNodeRef,
    },
    prelude::{Error, Result, *},
    BlockSet, Errno,
};

impl<D: BlockSet> FileInner<D> {
    pub fn flush(&mut self) -> Result<()> {
        ensure!(self.status.is_ok(), Error::new(Errno::BadStatus));

        let result = self.internal_flush(true);
        if result.is_err() && self.status.is_ok() {
            self.set_file_status(FileStatus::FlushError);
        }
        result
    }

    pub fn internal_flush(&mut self, flush: bool) -> Result<()> {
        if !self.need_writing {
            return Ok(());
        }

        if self.is_need_write_node() {
            if self.journal_enabled {
                self.write_recovery_file().map_err(|error| {
                    self.set_file_status(FileStatus::FlushError);
                    error
                })?;
            }

            self.set_update_flag(flush).map_err(|error| {
                self.set_file_status(FileStatus::FlushError);
                error
            })?;

            self.update_nodes().map_err(|error| {
                self.clear_update_flag();
                #[cfg(not(feature = "linux"))]
                error!("update nodes failed: {:?}", error);
                self.set_file_status(FileStatus::FlushError);
                error
            })?;
        }

        self.update_metadata().map_err(|error| {
            self.clear_update_flag();
            self.set_file_status(FileStatus::CryptoError);
            error
        })?;

        self.write_to_disk(flush).map_err(|error| {
            self.set_file_status(FileStatus::WriteToDiskFailed);
            error
        })?;

        self.need_writing = false;
        Ok(())
    }

    pub fn write_to_disk(&mut self, flush: bool) -> Result<()> {
        if self.is_need_write_node() {
            for mut node in self.cache.iter().rev().filter_map(|node| {
                let node = node.borrow_mut();
                if node.need_writing {
                    Some(node)
                } else {
                    None
                }
            }) {
                node.write_to_disk(&mut self.host_file)?;
            }
            self.root_mht
                .borrow_mut()
                .write_to_disk(&mut self.host_file)?;
        }

        self.metadata.write_to_disk(&mut self.host_file)?;

        if flush {
            self.host_file.flush()?;
            if self.journal_enabled {
                self.journal.commit()?;
                // flush the recovery file to disk
                self.journal.flush()?;
                // all nodes are persisted on disk, the recovery file is no longer needed
                self.journal.reset()?;
            }
        }
        Ok(())
    }

    fn update_nodes(&mut self) -> Result<()> {
        // 1. encrypt the changed data
        // 2. set the KEY+GMAC in the parent MHT
        // 3. set the need_writing flag for all the parents
        for mut data_node in self.cache.iter().filter_map(|node| {
            let node = node.borrow_mut();
            if node.is_data() && node.need_writing {
                Some(node)
            } else {
                None
            }
        }) {
            let key = data_node.derive_key(&mut self.key_gen)?;
            data_node.encrypt(&key)?;

            let mut parent = data_node.parent.clone();
            while let Some(mht) = parent {
                let mut mht = mht.borrow_mut();
                if !mht.is_root_mht() {
                    mht.need_writing = true;
                    parent = mht.parent.clone();
                } else {
                    break;
                }
            }
        }

        // add all the mht nodes that needs writing to a list
        let mut mht_nodes = self
            .cache
            .iter()
            .filter_map(|node| {
                let borrow = node.borrow();
                if borrow.is_mht() && borrow.need_writing {
                    Some(node.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<FileNodeRef>>();

        // sort the list from the last node to the first (bottom layers first)
        mht_nodes.sort_by(|a, b| b.borrow().cmp(&a.borrow()));

        for mut mht_node in mht_nodes.iter().map(|node| node.borrow_mut()) {
            let key = mht_node.derive_key(&mut self.key_gen)?;
            mht_node.encrypt(&key)?;
        }

        // update mht root gmac in the meta data node
        let mut root_mht = self.root_mht.borrow_mut();
        let key = root_mht.derive_key(&mut self.key_gen)?;
        let mac = root_mht.encrypt(&key)?;

        self.metadata.encrypted_plain.mht_key = key;
        self.metadata.encrypted_plain.mht_gmac = mac;

        Ok(())
    }

    #[inline]
    fn update_metadata(&mut self) -> Result<()> {
        let key = self.metadata.derive_key(&mut self.key_gen)?;
        self.metadata.encrypt(&key)
    }

    #[inline]
    fn is_need_write_node(&self) -> bool {
        self.metadata.encrypted_plain.size > MD_USER_DATA_SIZE
            && self.root_mht.borrow().need_writing
    }

    fn set_update_flag(&mut self, flush: bool) -> Result<()> {
        self.metadata.set_update_flag(1);
        let result = self.metadata.write_to_disk(&mut self.host_file);
        self.metadata.set_update_flag(0);
        result?;

        if flush {
            self.host_file.flush().map_err(|error| {
                let _ = self.metadata.write_to_disk(&mut self.host_file);
                error
            })?;
        }
        Ok(())
    }

    fn clear_update_flag(&mut self) {
        assert!(!self.metadata.update_flag());
        let _ = self.metadata.write_to_disk(&mut self.host_file);
        let _ = self.host_file.flush();
    }

    fn write_recovery_file_node(&mut self) -> Result<()> {
        let journal = &mut self.journal;
        let mut mht_nodes = alloc::vec![];
        let mut data_nodes = alloc::vec![];
        for node in self.cache.iter().filter_map(|node| {
            let node = node.borrow();
            if node.need_writing && !node.new_node {
                Some(node)
            } else {
                None
            }
        }) {
            //node.write_recovery_file(&mut file)?;
            if node.is_mht() {
                mht_nodes.push(node.clone());
            } else {
                data_nodes.push(node.clone());
            }
        }

        //  mht_nodes.sort_by(|a, b| b.logic_number.cmp(&a.logic_number));

        for node in mht_nodes.iter() {
            node.write_recovery_file(journal)?;
        }

        for node in data_nodes.iter() {
            node.write_recovery_file(journal)?;
        }

        let root_mht = self.root_mht.borrow();
        if root_mht.need_writing && !root_mht.new_node {
            root_mht.write_recovery_file(journal)?;
        }

        self.metadata.write_recovery_file(journal)
    }

    #[inline]
    fn write_recovery_file(&mut self) -> Result<()> {
        self.write_recovery_file_node().map_err(|error| {
            let _ = self.journal.reset();
            error
        })
    }
}
