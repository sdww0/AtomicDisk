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

use super::sgx::KeyPolicy;
use crate::os::SeekFrom;
use crate::os::String;
use crate::os::Vec;
use crate::pfs::sys as fs_imp;
use crate::prelude::*;
use crate::{AeadKey, AeadMac, BlockSet};


/// Options and flags which can be used to configure how a file is opened.
///
/// This builder exposes the ability to configure how a SgxFile is opened and
/// what operations are permitted on the open file. The SgxFile::open and
/// SgxFile::create methods are aliases for commonly used options using this
/// builder.
///
#[derive(Clone, Debug)]
pub struct OpenOptions(fs_imp::OpenOptions);

#[derive(Clone, Debug)]
pub struct EncryptMode(fs_imp::EncryptMode);

/// A reference to an open Sgxfile on the filesystem.
///
/// An instance of a `SgxFile` can be read and/or written depending on what options
/// it was opened with. SgxFiles also implement [`Seek`] to alter the logical cursor
/// that the file contains internally.
///
/// SgxFiles are automatically closed when they go out of scope.
pub struct SgxFile<D> {
    inner: fs_imp::SgxFile<D>,
}

unsafe impl<D: BlockSet> Send for SgxFile<D> {}
unsafe impl<D: BlockSet> Sync for SgxFile<D> {}


impl<D: BlockSet> SgxFile<D> {
    //#[cfg(feature = "tfs")]
    pub fn open(disk: D, path: &str) -> Result<SgxFile<D>> {
        OpenOptions::new().read(true).open(disk, path)
    }

    //#[cfg(feature = "tfs")]
    pub fn create(disk: D, path: &str) -> Result<SgxFile<D>> {
        OpenOptions::new().write(true).open(disk, path)
    }

    //#[cfg(feature = "tfs")]
    pub fn append(disk: D, path: &str) -> Result<SgxFile<D>> {
        OpenOptions::new().append(true).open(disk, path)
    }

    pub fn open_with_key(disk: D, path: &str, key: AeadKey) -> Result<SgxFile<D>> {
        OpenOptions::new().read(true).open_with_key(disk, path, key)
    }

    pub fn create_with_key(disk: D, path: &str, key: AeadKey) -> Result<SgxFile<D>> {
        OpenOptions::new()
            .write(true)
            .read(true)
            .create_with_key(disk, path, key, None)
    }

    pub fn append_with_key(disk: D, path: &str, key: AeadKey) -> Result<SgxFile<D>> {
        OpenOptions::new()
            .append(true)
            .open_with_key(disk, path, key)
    }

    pub fn open_integrity_only(disk: D, path: &str) -> Result<SgxFile<D>> {
        OpenOptions::new()
            .read(true)
            .open_integrity_only(disk, path)
    }

    pub fn create_integrity_only(disk: D, path: &str) -> Result<SgxFile<D>> {
        OpenOptions::new()
            .write(true)
            .open_integrity_only(disk, path)
    }

    pub fn append_integrity_only(disk: D, path: &str) -> Result<SgxFile<D>> {
        OpenOptions::new()
            .append(true)
            .open_integrity_only(disk, path)
    }

    pub fn open_with(
        disk: D,
        path: &str,
        encrypt_mode: EncryptMode,
        cache_size: Option<usize>,
    ) -> Result<SgxFile<D>> {
        OpenOptions::new()
            .read(true)
            .open_with(disk, path, encrypt_mode, cache_size)
    }

    pub fn create_with(
        disk: D,
        path: &str,
        encrypt_mode: EncryptMode,
        cache_size: Option<usize>,
    ) -> Result<SgxFile<D>> {
        OpenOptions::new()
            .write(true)
            .open_with(disk, path, encrypt_mode, cache_size)
    }

    pub fn append_with(
        disk: D,
        path: &str,
        encrypt_mode: EncryptMode,
        cache_size: Option<usize>,
    ) -> Result<SgxFile<D>> {
        OpenOptions::new()
            .append(true)
            .open_with(disk, path, encrypt_mode, cache_size)
    }

    pub fn options() -> OpenOptions {
        OpenOptions::new()
    }

    pub fn set_len(&self, size: u64) -> Result<()> {
        self.inner.set_len(size)
    }

    pub fn tell(&self) -> Result<u64> {
        self.inner.tell()
    }

    pub fn file_size(&self) -> Result<u64> {
        self.inner.file_size()
    }

    pub fn is_eof(&self) -> bool {
        self.inner.is_eof()
    }

    pub fn clear_error(&self) -> Result<()> {
        self.inner.clear_error()
    }

    pub fn clear_cache(&self) -> Result<()> {
        self.inner.clear_cache()
    }

    pub fn get_mac(&self) -> Result<AeadMac> {
        self.inner.get_mac()
    }

    pub fn rename<P: AsRef<str>>(&self, old_name: P, new_name: P) -> Result<()> {
        self.inner.rename(old_name.as_ref(), new_name.as_ref())
    }

    pub fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize> {
        self.inner.read_at(buf, offset)
    }

    pub fn write_at(&self, buf: &[u8], offset: u64) -> Result<usize> {
        self.inner.write_at(buf, offset)
    }

    #[cfg(feature = "asterinas")]
    pub fn read_at_with_writer(
        &self,
        writer: ostd::mm::VmWriter<ostd::mm::Infallible>,
        offset: u64,
    ) -> Result<usize> {
        self.inner.read_at_with_writer(writer, offset)
    }

    #[cfg(feature = "asterinas")]
    pub fn write_at_with_reader(
        &self,
        reader: ostd::mm::VmReader<ostd::mm::Infallible>,
        offset: u64,
    ) -> Result<usize> {
        self.inner.write_at_with_reader(reader, offset)
    }

    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.inner.read(buf)
    }
    pub fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.inner.write(buf)
    }
    pub fn flush(&self) -> Result<()> {
        self.inner.flush()
    }

    pub fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
        self.inner.seek(pos)
    }
}

/// Indicates how much extra capacity is needed to read the rest of the file.
fn buffer_capacity_required<D: BlockSet>(file: &SgxFile<D>) -> usize {
    let size = file.file_size().unwrap_or(0);
    let pos = file.tell().unwrap_or(0);
    // Don't worry about `usize` overflow because reading will fail regardless
    // in that case.
    size.saturating_sub(pos) as usize
}

impl OpenOptions {
    /// Creates a blank new set of options ready for configuration.
    pub fn new() -> OpenOptions {
        OpenOptions(fs_imp::OpenOptions::new())
    }

    /// Sets the option for read access.
    pub fn read(&mut self, read: bool) -> &mut OpenOptions {
        self.0.read(read);
        self
    }

    /// Sets the option for write access.
    pub fn write(&mut self, write: bool) -> &mut OpenOptions {
        self.0.write(write);
        self
    }

    /// Sets the option for the append mode.
    pub fn append(&mut self, append: bool) -> &mut OpenOptions {
        self.0.append(append);
        self
    }

    /// Sets the option for update a previous file.
    pub fn update(&mut self, update: bool) -> &mut OpenOptions {
        self.0.update(update);
        self
    }

    /// Sets the option for binary a file.
    pub fn binary(&mut self, binary: bool) -> &mut OpenOptions {
        self.0.binary(binary);
        self
    }

    /// Opens a file at `path` with the options specified by `self`.

    pub fn open<D: BlockSet>(&self, disk: D, path: &str) -> Result<SgxFile<D>> {
        self.open_with(disk, path, EncryptMode::auto_key(None), None)
    }

    pub fn open_with_key<D: BlockSet>(
        &self,
        disk: D,
        path: &str,
        key: AeadKey,
    ) -> Result<SgxFile<D>> {
        self.open_with(disk, path, EncryptMode::user_key(key), None)
    }

    pub fn open_integrity_only<D: BlockSet>(&self, disk: D, path: &str) -> Result<SgxFile<D>> {
        self.open_with(disk, path, EncryptMode::integrity_only(), None)
    }

    pub fn open_with<D: BlockSet>(
        &self,
        disk: D,
        path: &str,
        encrypt_mode: EncryptMode,
        cache_size: Option<usize>,
    ) -> Result<SgxFile<D>> {
        let inner = fs_imp::SgxFile::open(disk, path, &self.0, &encrypt_mode.0, cache_size)?;
        Ok(SgxFile { inner })
    }
    pub fn create_with_key<D: BlockSet>(
        &self,
        disk: D,
        path: &str,
        key: AeadKey,
        cache_size: Option<usize>,
    ) -> Result<SgxFile<D>> {
        self.create(disk, path, EncryptMode::user_key(key), cache_size)
    }
    pub fn create_integrity_only<D: BlockSet>(
        &self,
        disk: D,
        path: &str,
        cache_size: Option<usize>,
    ) -> Result<SgxFile<D>> {
        self.create(disk, path, EncryptMode::integrity_only(), cache_size)
    }
    pub fn create<D: BlockSet>(
        &self,
        disk: D,
        path: &str,
        encrypt_mode: EncryptMode,
        cache_size: Option<usize>,
    ) -> Result<SgxFile<D>> {
        let inner = fs_imp::SgxFile::create(disk, path, &self.0, &encrypt_mode.0, cache_size)?;
        Ok(SgxFile { inner })
    }
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl EncryptMode {
    #[inline]
    pub fn auto_key(key_policy: Option<KeyPolicy>) -> EncryptMode {
        EncryptMode(fs_imp::EncryptMode::EncryptAutoKey(
            key_policy.unwrap_or(KeyPolicy::MRSIGNER),
        ))
    }

    #[inline]
    pub fn user_key(key: AeadKey) -> EncryptMode {
        EncryptMode(fs_imp::EncryptMode::EncryptUserKey(key))
    }

    #[inline]
    pub fn integrity_only() -> EncryptMode {
        EncryptMode(fs_imp::EncryptMode::IntegrityOnly)
    }
}
