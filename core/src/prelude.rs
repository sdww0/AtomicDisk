pub(crate) use crate::{
    bio::{BlockId, BLOCK_SIZE},
    error::{Errno::*, Error},
    os::{Arc, Box, String, ToString, Vec, Weak},
    return_errno, return_errno_with_msg,
    util::{align_down, align_up, Aead as _, RandomInit, Rng as _, Skcipher as _},
};

pub(crate) type Result<T> = core::result::Result<T, Error>;

pub(crate) use core::fmt::{self, Debug};

#[cfg(not(feature = "linux"))]
pub(crate) use log::{debug, error, info, trace, warn};

#[cfg(feature = "linux")]
pub(crate) use crate::vec;
