// SPDX-License-Identifier: GPL-2.0-only

use core::fmt;

/// Why a frame or field couldn't be parsed or built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The input ended inside the named field.
    Truncated(&'static str),
    /// The named field holds a value this crate can't interpret.
    Invalid(&'static str),
    /// Building: the named field is too long for its length field.
    TooLong(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Truncated(what) => write!(f, "truncated {what}"),
            Error::Invalid(what) => write!(f, "invalid {what}"),
            Error::TooLong(what) => write!(f, "{what} too long for its length field"),
        }
    }
}

impl core::error::Error for Error {}
