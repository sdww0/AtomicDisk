// SPDX-License-Identifier: MPL-2.0

#![expect(unused_variables)]

use ostd::sync::SpinLock;
use rand::{rngs::StdRng, Error as RandError, RngCore};
use spin::Once;

use crate::{prelude::*, Errno};

static RNG: Once<SpinLock<StdRng>> = Once::new();

/// Fill `dest` with random bytes.
///
/// It's cryptographically secure, as documented in [`rand::rngs::StdRng`].
pub fn getrandom(dst: &mut [u8]) -> Result<()> {
    Ok(RNG.get().unwrap().lock().try_fill_bytes(dst)?)
}

pub fn init() {
    // The seed used to initialize the RNG is required to be secure and unpredictable.

    use ostd::arch::read_random;
    use rand::SeedableRng;

    let mut seed = <StdRng as SeedableRng>::Seed::default();
    let mut chunks = seed.as_mut().chunks_exact_mut(size_of::<u64>());
    for chunk in chunks.by_ref() {
        let src = read_random()
            .expect("read_random failed multiple times")
            .to_ne_bytes();
        chunk.copy_from_slice(&src);
    }
    let tail = chunks.into_remainder();
    let n = tail.len();
    if n > 0 {
        let src = read_random()
            .expect("read_random failed multiple times")
            .to_ne_bytes();
        tail.copy_from_slice(&src[..n]);
    }

    RNG.call_once(|| SpinLock::new(StdRng::from_seed(seed)));
}

impl From<RandError> for Error {
    fn from(value: RandError) -> Self {
        Error::new(Errno::OsSpecUnknown)
    }
}
