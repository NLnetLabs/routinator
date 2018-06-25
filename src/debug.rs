//! Macros for last-resort debugging.
//!
//! Since error reporting of the BER parser is limited on purpose, debugging
//! code using it may be difficult. To remedy this somewhat, this module
//! contains a macro `xerr!()` that will panic if the `extra-debug` feature
//! is enable during build or resolve into whatever the expression it
//! encloses resolves to otherwise. Use it whenever you initially produce an
//! error, i.e.:
//!
//! ```rust,ignore
//! if foo {
//!     xerr!(Err(Error::Malformed))
//! }
//! ```
//!
//! or, with an early return:
//!
//! ```rust,ignore
//! if foo {
//!     xerr!(return Err(Error::Malformed)));
//! }
//! ```
//!
//! By enabling `extra-debug` and setting the `RUST_BACKTRACE`
//! environment variable, you can create a proper backtrace whenever the
//! code reaches one of these booby-trapped points.

#[cfg(feature = "extra-debug")]
#[allow(unused_macros)]
macro_rules! xerr {
    ($test:expr) => { panic!("extra debugging enabled") };
}

#[cfg(not(feature = "extra-debug"))]
#[allow(unused_macros)]
macro_rules! xerr {
    ($test:expr) => { $test };
}

