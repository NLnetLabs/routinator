//! Utilities for handling strings.

use std::str;


//------------ str_from_ascii ------------------------------------------------

/// Converts a sequence of ASCII octets into a str.
pub fn str_from_ascii(src: &[u8]) -> Result<&str, AsciiError> {
    if src.is_ascii() {
        Ok(unsafe { str::from_utf8_unchecked(src) })
    }
    else {
        Err(AsciiError)
    }
}


//------------ AsciiError ----------------------------------------------------

pub struct AsciiError;

