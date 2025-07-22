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
    os::SeekFrom,
    pfs::sys::{
        file::FileInner,
        metadata::MD_USER_DATA_SIZE,
        node::{FileNodeRef, NODE_SIZE},
    },
    prelude::{Error, Result, *},
    BlockSet, Errno,
};

impl<D: BlockSet> FileInner<D> {
    pub fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        ensure!(
            self.opts.write || self.opts.append || self.opts.update,
            Error::with_msg(Errno::PermissionDenied, "permission denied")
        );

        if self.opts.append {
            self.offset = self.metadata.encrypted_plain.size;
        }

        let mut left_to_write = buf.len();
        let mut offset = 0;

        // the first block of user data is written in the meta-data encrypted part
        if self.offset < MD_USER_DATA_SIZE {
            let len = left_to_write.min(MD_USER_DATA_SIZE - self.offset);
            self.metadata.encrypted_plain.data[self.offset..self.offset + len]
                .copy_from_slice(&buf[offset..offset + len]);
            left_to_write -= len;
            offset += len;
            self.offset += len;

            if self.offset > self.metadata.encrypted_plain.size {
                self.metadata.encrypted_plain.size = self.offset;
            }
            self.need_writing = true;
        }

        while left_to_write > 0 {
            let file_node = match self.get_data_node() {
                Ok(node) => node,
                Err(error) => {
                    #[cfg(not(feature = "linux"))]
                    error!("get_data_node error: {:?}", error);
                    self.set_last_error(error.clone());
                    return Err(error);
                }
            };

            let offset_in_node = (self.offset - MD_USER_DATA_SIZE) % NODE_SIZE;
            let len = left_to_write.min(NODE_SIZE - offset_in_node);
            file_node.borrow_mut().plaintext.as_mut()[offset_in_node..offset_in_node + len]
                .copy_from_slice(&buf[offset..offset + len]);

            left_to_write -= len;
            offset += len;
            self.offset += len;

            if self.offset > self.metadata.encrypted_plain.size {
                self.metadata.encrypted_plain.size = self.offset;
            }

            let mut file_node = file_node.borrow_mut();
            if !file_node.need_writing {
                file_node.need_writing = true;

                let mut parent = file_node.parent.clone();
                while let Some(mht) = parent {
                    let mut mht = mht.borrow_mut();
                    if !mht.is_root_mht() {
                        mht.need_writing = true;
                        parent = mht.parent.clone();
                    } else {
                        break;
                    }
                }

                self.root_mht.borrow_mut().need_writing = true;
                self.need_writing = true;
            }
        }
        Ok(offset)
    }

    pub fn write_at(&mut self, buf: &[u8], offset: u64) -> Result<usize> {
        let cur_offset = self.offset;
        let file_size = self.metadata.encrypted_plain.size as u64;

        if offset > file_size {
            self.seek(SeekFrom::End(0))?;

            static ZEROS: [u8; 0x1000] = [0; 0x1000];
            let mut left_to_write = offset - file_size;
            while left_to_write > 0 {
                let len = left_to_write.min(0x1000) as usize;
                let written_len = self.write(&ZEROS[..len]).map_err(|error| {
                    self.offset = cur_offset;
                    error
                })?;
                left_to_write -= written_len as u64;
            }
        }

        self.seek(SeekFrom::Start(offset)).map_err(|error| {
            self.offset = cur_offset;
            error
        })?;
        let result = self.write(buf);
        self.offset = cur_offset;

        result
    }

    pub fn rollback_data_node(
        &mut self,
        physical_number: u64,
        data_node: FileNodeRef,
    ) -> Result<()> {
        let mut file_node = data_node.borrow_mut();
        if !file_node.need_writing {
            file_node.need_writing = true;

            let mut parent = file_node.parent.clone();
            while let Some(mht) = parent {
                let mut mht = mht.borrow_mut();
                if !mht.is_root_mht() {
                    mht.need_writing = true;
                    parent = mht.parent.clone();
                } else {
                    break;
                }
            }

            self.root_mht.borrow_mut().need_writing = true;
            self.need_writing = true;
        }
        self.cache.push(physical_number, data_node.clone());
        Ok(())
    }

    #[cfg(feature = "asterinas")]
    pub fn write_at_with_reader(
        &mut self,
        reader: ostd::mm::VmReader<ostd::mm::Infallible>,
        offset: u64,
    ) -> Result<usize> {
        let cur_offset = self.offset;
        let file_size = self.metadata.encrypted_plain.size as u64;

        if offset > file_size {
            self.seek(SeekFrom::End(0))?;

            static ZEROS: [u8; 0x1000] = [0; 0x1000];
            let mut left_to_write = offset - file_size;
            while left_to_write > 0 {
                let len = left_to_write.min(0x1000) as usize;
                let written_len = self.write(&ZEROS[..len]).map_err(|error| {
                    self.offset = cur_offset;
                    error
                })?;
                left_to_write -= written_len as u64;
            }
        }

        self.seek(SeekFrom::Start(offset)).map_err(|error| {
            self.offset = cur_offset;
            error
        })?;
        let result = self.write_with_reader(reader);
        self.offset = cur_offset;

        result
    }

    #[cfg(feature = "asterinas")]
    pub fn write_with_reader(
        &mut self,
        mut reader: ostd::mm::VmReader<ostd::mm::Infallible>,
    ) -> Result<usize> {
        if !reader.has_remain() {
            return Ok(0);
        }

        ensure!(
            self.opts.write || self.opts.append || self.opts.update,
            Error::with_msg(Errno::PermissionDenied, "permission denied")
        );

        if self.opts.append {
            self.offset = self.metadata.encrypted_plain.size;
        }

        let mut left_to_write = reader.remain();
        let mut offset = 0;

        // the first block of user data is written in the meta-data encrypted part
        if self.offset < MD_USER_DATA_SIZE {
            use ostd::mm::VmWriter;

            let len = left_to_write.min(MD_USER_DATA_SIZE - self.offset);
            reader.read(&mut VmWriter::from(
                &mut self.metadata.encrypted_plain.data[self.offset..self.offset + len],
            ));

            left_to_write -= len;
            offset += len;
            self.offset += len;

            if self.offset > self.metadata.encrypted_plain.size {
                self.metadata.encrypted_plain.size = self.offset;
            }
            self.need_writing = true;
        }

        while left_to_write > 0 {
            use ostd::mm::VmWriter;

            let file_node = match self.get_data_node() {
                Ok(node) => node,
                Err(error) => {
                    #[cfg(not(feature = "linux"))]
                    error!("get_data_node error: {:?}", error);
                    self.set_last_error(error.clone());
                    return Err(error);
                }
            };

            let offset_in_node = (self.offset - MD_USER_DATA_SIZE) % NODE_SIZE;
            let len = left_to_write.min(NODE_SIZE - offset_in_node);

            reader.read(&mut VmWriter::from(
                &mut file_node.borrow_mut().plaintext.as_mut()
                    [offset_in_node..offset_in_node + len],
            ));

            left_to_write -= len;
            offset += len;
            self.offset += len;

            if self.offset > self.metadata.encrypted_plain.size {
                self.metadata.encrypted_plain.size = self.offset;
            }

            let mut file_node = file_node.borrow_mut();
            if !file_node.need_writing {
                file_node.need_writing = true;

                let mut parent = file_node.parent.clone();
                while let Some(mht) = parent {
                    let mut mht = mht.borrow_mut();
                    if !mht.is_root_mht() {
                        mht.need_writing = true;
                        parent = mht.parent.clone();
                    } else {
                        break;
                    }
                }

                self.root_mht.borrow_mut().need_writing = true;
                self.need_writing = true;
            }
        }
        Ok(offset)
    }
}
