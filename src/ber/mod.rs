//! Parsing of data in Basic Encoding Rules.
//!
//! While RFC 6488 demands that Signed Objects are always encoded using
//! Distinguished Encoding Rules (DER), the underlying Cryptographic Message
//! Syntax (CMS) defined by (currently) RFC 5652 allows Basic Encoding Rules
//! (BER), resulting in real ROAs that are encoded in the latter.
//! Consequently, we have to be able to decode both rules and this is what
//! this module does. Since DER is really just BER with a number of
//! limitiations, this is less of a problem then it may sound.
//!
//! Either rules are defined in ITU-T recommendation X.690. We only implement
//! a subset of the complete rules that is necessary for the task at hand.
//! To identify cases where that wasn’t enough, this module has a special
//! error value `Error::Unimplemented`.
//!
//! Because all the data we encounter is small, we can operate on in-memory
//! data and use the `untrusted` crate for that.

pub use self::bstring::BitString;
pub use self::content::Content;
pub use self::error::Error;
pub use self::length::Length;
pub use self::oid::Oid;
pub use self::ostring::OctetString;
pub use self::tag::Tag;
pub use self::reader::ReaderExt;

mod bstring;
mod content;
mod error;
mod length;
mod oid;
mod ostring;
mod reader;
mod tag;

