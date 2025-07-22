//! Non-std with alloc and core modules
//!
//!

pub(super) mod random;

pub use alloc::collections::BTreeMap;
use alloc::format;
/// Reuse implementations in `alloc` crate.
pub use alloc::{
    boxed::Box,
    string::{String, ToString},
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{marker::PhantomData, ptr::NonNull};

use aes_gcm::aead::{AeadMut, AeadMutInPlace};
/// Reuse implementations of `hashbrown` crate.
pub use hashbrown::{HashMap, HashSet};
use log::{debug, info, warn};
/// Reuse the `Mutex` and `MutexGuard` implementation.
pub use ostd::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard, RwMutex};
use pod::Pod;
use serde::{Deserialize, Serialize};

use crate::{
    error::Errno,
    prelude::{Error, Result},
};

// /// Reuse `std::thread::ThreadId`.
// pub type Tid = std::thread::ThreadId;

// /// A struct to get the current thread id.
// pub struct CurrentThread;

// impl CurrentThread {
//     pub fn id() -> Tid {
//         std::thread::current().id()
//     }
// }

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum SeekFrom {
    /// Sets the offset to the provided number of bytes.
    Start(u64),

    /// Sets the offset to the size of this object plus the specified number of
    /// bytes.
    ///
    /// It is possible to seek beyond the end of an object, but it's an error to
    /// seek before byte 0.
    End(i64),

    /// Sets the offset to the current position plus the specified number of
    /// bytes.
    ///
    /// It is possible to seek beyond the end of an object, but it's an error to
    /// seek before byte 0.
    Current(i64),
}

pub const PAGE_SIZE: usize = 4096;

struct PageAllocator;

impl PageAllocator {
    /// Allocate memory buffer with specific size.
    ///
    /// The `len` indicates the number of pages.
    fn alloc(len: usize) -> Option<NonNull<u8>> {
        if len == 0 {
            return None;
        }

        // SAFETY: the `count` is non-zero, then the `Layout` has
        // non-zero size, so it's safe.
        unsafe {
            let layout =
                alloc::alloc::Layout::from_size_align_unchecked(len * PAGE_SIZE, PAGE_SIZE);
            let ptr = alloc::alloc::alloc(layout);
            NonNull::new(ptr)
        }
    }

    /// Deallocate memory buffer at the given `ptr` and `len`.
    ///
    /// # Safety
    ///
    /// The caller should make sure that:
    /// * `ptr` must denote the memory buffer currently allocated via
    ///   `PageAllocator::alloc`,
    ///
    /// * `len` must be the same size that was used to allocate the
    ///   memory buffer.
    unsafe fn dealloc(ptr: *mut u8, len: usize) {
        // SAFETY: the caller should pass valid `ptr` and `len`.
        unsafe {
            let layout =
                alloc::alloc::Layout::from_size_align_unchecked(len * PAGE_SIZE, PAGE_SIZE);
            alloc::alloc::dealloc(ptr, layout)
        }
    }
}

/// A struct for `PAGE_SIZE` aligned memory buffer.
#[derive(Clone)]
pub struct Pages {
    ptr: NonNull<u8>,
    len: usize,
    _p: PhantomData<[u8]>,
}

// SAFETY: `Pages` owns the memory buffer, so it can be safely
// transferred across threads.
unsafe impl Send for Pages {}

impl Pages {
    /// Allocate specific number of pages.
    pub fn alloc(len: usize) -> Result<Self> {
        let ptr = PageAllocator::alloc(len).ok_or(Error::with_msg(
            Errno::OutOfMemory,
            "page allocation failed",
        ))?;
        Ok(Self {
            ptr,
            len,
            _p: PhantomData,
        })
    }

    /// Return the number of pages.
    pub fn len(&self) -> usize {
        self.len
    }
}

impl Drop for Pages {
    fn drop(&mut self) {
        // SAFETY: `ptr` is `NonNull` and allocated by `PageAllocator::alloc`
        // with the same size of `len`, so it's valid and safe.
        unsafe { PageAllocator::dealloc(self.ptr.as_mut(), self.len) }
    }
}

impl core::ops::Deref for Pages {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        // SAFETY: `ptr` is `NonNull` and points valid memory with proper length.
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.len * PAGE_SIZE) }
    }
}

impl core::ops::DerefMut for Pages {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: `ptr` is `NonNull` and points valid memory with proper length.
        unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len * PAGE_SIZE) }
    }
}

/// A random number generator.
pub struct Rng;

impl crate::util::Rng for Rng {
    fn new(_seed: &[u8]) -> Self {
        Self
    }

    fn fill_bytes(&self, dest: &mut [u8]) -> Result<()> {
        random::getrandom(dest).map_err(|_| Error::new(Errno::OsSpecUnknown))
    }
}

/// A macro to define byte_array_types used by `Aead` or `Skcipher`.
macro_rules! new_byte_array_type {
    ($name:ident, $n:expr) => {
        #[repr(C)]
        #[derive(Copy, Clone, Pod, Debug, Default, Deserialize, Serialize)]
        pub struct $name([u8; $n]);

        impl $name {
            pub fn new(array: [u8; $n]) -> Self {
                Self(array)
            }

            pub fn inner(&self) -> &[u8; $n] {
                &self.0
            }
        }

        impl core::ops::Deref for $name {
            type Target = [u8];

            fn deref(&self) -> &Self::Target {
                self.0.as_slice()
            }
        }

        impl core::ops::DerefMut for $name {
            fn deref_mut(&mut self) -> &mut Self::Target {
                self.0.as_mut_slice()
            }
        }

        impl crate::util::RandomInit for $name {
            fn random() -> Self {
                use crate::util::Rng;

                let mut result = Self::default();
                let rng = self::Rng::new(&[]);
                rng.fill_bytes(&mut result).unwrap_or_default();
                result
            }
        }
    };
}

const AES_GCM_KEY_SIZE: usize = 16;
const AES_GCM_IV_SIZE: usize = 12;
const AES_GCM_MAC_SIZE: usize = 16;

new_byte_array_type!(AeadKey, AES_GCM_KEY_SIZE);
new_byte_array_type!(AeadIv, AES_GCM_IV_SIZE);
new_byte_array_type!(AeadMac, AES_GCM_MAC_SIZE);

/// An `AEAD` cipher.
pub struct Aead;

impl Aead {
    /// Construct an `Aead` instance.
    pub fn new() -> Self {
        Self
    }
}
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};

impl crate::util::Aead for Aead {
    type Key = AeadKey;
    type Iv = AeadIv;
    type Mac = AeadMac;

    fn encrypt(
        &self,
        input: &[u8],
        key: &Self::Key,
        iv: &Self::Iv,
        aad: &[u8],
        output: &mut [u8],
    ) -> Result<Self::Mac> {
        let mut aes_gcm = Aes128Gcm::new_from_slice(key).unwrap();

        let result = aes_gcm
            .encrypt(Nonce::from_slice(&iv), input)
            .map_err(|_| Error::new(Errno::EncryptFailed))?;
        // Ignore additional authenticated data (AAD) for now.
        output.copy_from_slice(&result.as_slice()[..input.len()]);
        let mac = AeadMac::from_bytes(&result[input.len()..]);
        debug!("Encrypting data with Aead: input 8 bytes prefix: {}, output 8 bytes prefix: {}, key: {}, mac: {}",             input[..8]
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>(),             output[..8]
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>(),key.0.iter().map(|b| format!("{:02x}", b)).collect::<String>(),            mac.0.iter().map(|b| format!("{:02x}", b)).collect::<String>()
);

        Ok(mac)
    }

    fn decrypt(
        &self,
        input: &[u8],
        key: &Self::Key,
        iv: &Self::Iv,
        aad: &[u8],
        mac: &Self::Mac,
        output: &mut [u8],
    ) -> Result<()> {
        let mut aes_gcm = Aes128Gcm::new_from_slice(key).unwrap();

        debug!(
            "Decrypting data with Aead: input 8 bytes prefix: {}, key: {}, mac : {}",
            input[..8]
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>(),
            key.0
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>(),
            mac.0
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        );

        let combine_input = [input, mac].concat();
        let res = aes_gcm
            .decrypt(Nonce::from_slice(&iv), &*combine_input)
            .map_err(|_| Error::new(Errno::DecryptFailed))?;
        // Ignore additional authenticated data (AAD) for now.
        output.copy_from_slice(&res.as_slice()[..input.len()]);

        Ok(())
    }
}

const AES_CTR_KEY_SIZE: usize = 16;
const AES_CTR_IV_SIZE: usize = 16;

new_byte_array_type!(SkcipherKey, AES_CTR_KEY_SIZE);
new_byte_array_type!(SkcipherIv, AES_CTR_IV_SIZE);

/// A symmetric key cipher.
pub struct Skcipher;

impl Skcipher {
    /// Construct a `Skcipher` instance.
    pub fn new() -> Self {
        Self
    }
}

use aes::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
type Aes128Ctr64LE = ctr::Ctr64LE<aes::Aes128>;

impl crate::util::Skcipher for Skcipher {
    type Key = SkcipherKey;
    type Iv = SkcipherIv;

    fn encrypt(
        &self,
        input: &[u8],
        key: &Self::Key,
        iv: &Self::Iv,
        output: &mut [u8],
    ) -> Result<()> {
        let mut cipher = Aes128Ctr64LE::new(
            aes::cipher::generic_array::GenericArray::from_slice(&key.0),
            aes::cipher::generic_array::GenericArray::from_slice(&iv.0),
        );
        output.copy_from_slice(input);
        cipher.apply_keystream(output);

        Ok(())
    }

    fn decrypt(
        &self,
        input: &[u8],
        key: &Self::Key,
        iv: &Self::Iv,
        output: &mut [u8],
    ) -> Result<()> {
        let mut cipher = Aes128Ctr64LE::new(
            aes::cipher::generic_array::GenericArray::from_slice(&key.0),
            aes::cipher::generic_array::GenericArray::from_slice(&iv.0),
        );
        output.copy_from_slice(input);
        cipher.apply_keystream(output);
        Ok(())
    }
}
