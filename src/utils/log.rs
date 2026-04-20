//! Utilities for handling error messages.

use std::error::Error;


/// Unroll the error sources to get a full error message.
pub fn unroll_error(err: &dyn Error) -> String {
    match err.source() {
        Some(err) => format!("{} ({})", err, unroll_error(err)),
        None => format!("{}", err)
    }
}


