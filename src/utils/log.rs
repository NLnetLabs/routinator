//! Utilities for handling error messages.

use std::error::Error;


/// Unroll the error sources to get a full error message.
pub fn unroll_error(err: &dyn Error) -> String {
    let mut errors = Vec::new();

    let mut source = err.source();
    while let Some(err) = source {
        let msg = err.to_string();
        if !errors.contains(&msg) {
            errors.push(msg);
        }
        source = err.source();
    }
    
    errors.join(" -> ")
}
