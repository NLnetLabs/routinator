//! Parsing of data in Basic Encoding Rules.
//!
//! This modules provides means to parse data encoded in ASN.1’s _Basic
//! Encoding Rules_ as defined in ITU recommendation X.690 as well as their
//! stricter companions _Cannonical Encoding Rules_ and _Distringuished
//! Encoding Rules._
//!
//! These rules encode data as a stream of nested values. Each value is
//! has an indication of its type, called a [`Tag`]. It can either be
//! [`Primitive`], in which case it contains the actual data for a value,
//! or [`Constructed`], in which case it contains a sequence of more values.
//!
//! The decoder operates in a streaming fashion. It will read data from
//! something encoding the [`Source`] trait which provides access to the
//! data stream in a way digestible by the decoder.
//!
//! All actual decoding happens through closures which receive a reference
//! to a value and are supposed to handle this value completely. If they
//! return with content of the value still unparsed, an error will occur.
//!
//! This module uses the [bytes] crate’s [`Bytes`] type to store byte
//! sequences in a reasonably cheap yet owned fashion. It implements
//! [`Source`] for [`Bytes`], optimizing for a case where if you have a
//! complete message, you can take out parts of it cheaply.
//!
//! If you have such a message, you can begin parsing by determining the
//! [`Mode`] you want to parse the message in: `Mode::Ber`, `Mode::Cer`,
//! or `Mode::Der`. If you are unsure, use `Mode::Ber` as that is the most
//! general and therefore most Postel-compatible for parsing. Pass your
//! source to the `Mode`’s `decode` method and provide a means to deal with
//! the content:
//!
//! ```rust,ignore
//! let bytes = load_bytes_somehow();
//! Mode::Ber.decode(bytes, |cons| {
//!     cons.take_u64()
//! })?;
//! ```
//!
//! This would parse a BER encoded message that consists of a single
//! INTEGER.
//!
//! The module also provides a number of types for commonly encountered
//! types that warrant special treatment, specifically [`BitString`]
//! and [`OctetString`] for the two fundamental ASN.1 string types, and
//! [`Oid`] for ASN.1 OCTET IDENTIFIERs.
//!
//! [bytes]: ../../bytes/index.html
//! [`Bytes`]: ../../bytes/struct.Bytes.html
//! [`BitString`]: struct.BitString.html
//! [`Constructed`]: struct.Constructed.html
//! [`Mode`]: enum.Mode.html
//! [`Oid`]: struct.Oid.html
//! [`OctetString`]: struct.OctetString.html
//! [`Primitive`]: struct.Primitive.html
//! [`Source`]: trait.Source.html
//! [`Tag`]: struct.Tag.html

pub use self::bstring::BitString;
pub use self::content::{Content, Constructed, Mode, Primitive};
pub use self::error::Error;
pub use self::int::{Integer, Unsigned};
pub use self::oid::Oid;
pub use self::ostring::{
    OctetString, OctetStringSource, OctetStringIter, OctetStringOctets
};
pub use self::source::{CaptureSource, LimitedSource, Source};
pub use self::tag::Tag;

mod bstring;
mod content;
mod error;
mod int;
mod length;
mod oid;
mod ostring;
mod source;
mod tag;

