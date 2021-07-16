//! Utilities for handling strings.

use std::str;
use std::fmt::Write;


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

/// Appends the hex representation of a bytes slice to a string.
pub fn append_hex(src: &[u8], target: &mut String) {
    for &ch in src {
        write!(target, "{:02x}", ch).expect(
            "appending to string failed"
        );
    }
}


//------------ AsciiError ----------------------------------------------------

pub struct AsciiError;

