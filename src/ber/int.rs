//! BER encoded integers.
//!
//! This is a private module. Its public content is being re-exported by the
//! parent module.
//!
//! TODO: Add more useful things to these types.

use bytes::Bytes;
use super::content::{Constructed, Primitive};
use super::error::Error;
use super::source::Source;
use super::tag::Tag;


//------------ Integer -------------------------------------------------------

/// A BER encoded integer.
///
/// As integers are variable length in BER, this type is just a simple wrapper
/// atop the underlying `Bytes` value containing the raw content. A value of
/// this type is a signed integer. If a value is defined as an unsigned
/// integer, i.e., as `INTEGER (0..MAX)`, you should use the sibling type
/// `Unsigned` instead.
///
/// In addition to these two generic types, the content decoders also provide
/// methods to parse integers into native integer types such as `i8`. If the
/// range of such a type is obviously enough, you might want to consider
/// using these methods instead.
///
/// # BER Encoding
///
/// In BER, an INTEGER is encoded as a primitive value with the content octets
/// providing a variable-length, big-endian, two‘s complement byte sequence of
/// that integer. Thus, the most-significant bit of the first octet serves as
/// the sign bit.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Integer(Bytes);

impl Integer {
    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_primitive_if(Tag::INTEGER, Self::take_content_from)
    }

    pub fn take_content_from<S: Source>(
        prim: &mut Primitive<S>
    ) -> Result<Self, S::Err> {
        let res = prim.take_all()?;
        match (res.get(0), res.get(1).map(|x| x & 0x80 != 0)) {
            (Some(0), Some(false)) => {
                xerr!(return Err(Error::Malformed.into()))
            }
            (Some(0xFF), Some(true)) => {
                xerr!(return Err(Error::Malformed.into()))
            }
            (None, _) => {
                xerr!(return Err(Error::Malformed.into()))
            }
            _ => { }
        }
        Ok(Integer(res))
    }
}


//------------ Unsigned ------------------------------------------------------

/// A BER encoded unsigned integer.
///
/// As integers are variable length in BER, this type is just a simple wrapper
/// atop the underlying `Bytes` value containing the raw content. It
/// guarantees that the wrapped integer is greater or equal to 0. This equals
/// an integer defined as `INTEGER (0..MAX)` in ASN.1.
///
/// If you need a integer without any restrictions, you can use `Integer`. If
/// you have even stricter range restrictions, you can also use the methods
/// provided on the content types to decode into Rust’s primitive integer
/// types such as `u16`.
///
/// # BER Encoding
///
/// In BER, an INTEGER is encoded as a primitive value with the content octets
/// providing a variable-length, big-endian, two‘s complement byte sequence of
/// that integer. Thus, the most-significant bit of the first octet serves as
/// the sign bit and, for an unsigned integer, has to be unset.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Unsigned(Bytes);

impl Unsigned {
    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_primitive_if(Tag::INTEGER, Self::take_content_from)
    }

    pub fn take_content_from<S: Source>(
        prim: &mut Primitive<S>
    ) -> Result<Self, S::Err> {
        let res = prim.take_all()?;
        match (res.get(0), res.get(1).map(|x| x & 0x80 != 0)) {
            (Some(0), Some(false)) => {
                xerr!(return Err(Error::Malformed.into()))
            }
            (Some(0xFF), Some(true)) => {
                xerr!(return Err(Error::Malformed.into()))
            }
            (Some(x), _) if x & 0x80 != 0 => {
                xerr!(return Err(Error::Malformed.into()))
            }
            (None, _) => {
                xerr!(return Err(Error::Malformed.into()))
            }
            _ => { }
        }
        Ok(Unsigned(res))
    }
}

