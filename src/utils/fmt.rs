//! Tools for formatting.

use std::fmt;

//------------ WriteOrPanic --------------------------------------------------

/// A target for writing formatted data into without error.
///
/// This provides a method `write_fmt` for use with the `write!` macro and
/// friends that does not return a result. Rather, it panics if an error
/// occurs.
pub trait WriteOrPanic {
    fn write_fmt(&mut self, args: fmt::Arguments);
}

impl WriteOrPanic for Vec<u8> {
    fn write_fmt(&mut self, args: fmt::Arguments) {
        std::io::Write::write_fmt(self, args).expect("formatting failed");
    }
}

impl WriteOrPanic for String {
    fn write_fmt(&mut self, args: fmt::Arguments) {
        std::fmt::Write::write_fmt(self, args).expect("formatting failed");
    }
}

