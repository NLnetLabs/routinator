//! BER-encoded BIT STRINGs.
//!
//! This is an internal module. Its public types are re-exported by the
//! parent.

use bytes::Bytes;
use super::content::{Content, Constructed, Mode};
use super::error::Error;
use super::source::Source;
use super::tag::Tag;


//------------ BitString -----------------------------------------------------

/// A BIT STRING value.
///
/// Bit strings are a sequence of bits. They do not need to contain a multiple
/// of eight bits. Bit strings can be encoded either as a primitive or
/// constructed value.
///
/// If encoded as a primitive, the first octet of the
/// content contains the number of unused bits in the last octet and the
/// following octets contain the bits with the first bit in the most
/// significant bit of the octet.
///
/// In the constructed encoding, the bit string is represented as a sequence
/// of bit strings which in turn may either be constructed or primitive
/// encodings. The only limitation in this nesting is that only the last
/// primitively encoded bit string may have a non-zero number of unused bits.
///
/// With BER, the sender can choose either form of encoding. With CER, the
/// primitive encoding should be chosen if its length would be no more than
/// 1000 octets long. Otherwise, the constructed encoding is to be chosen
/// which must contain a sequence of primitively encoded bit strings. Each of
/// these except for the last one must have content of exactly 1000 octets.
/// The last one must be a least one and at most 1000 octets of content.
/// With DER, only the primitive form is allowed.
///
/// # Limitation
///
/// At this time, the `BitString` type does not implement the constructed
/// encoding of a bit string.
#[derive(Clone, Debug)]
pub struct BitString {
    unused: u8,
    bits: Bytes,
}

impl BitString {
    pub fn bit(&self, bit: usize) -> bool {
        let idx = bit >> 3;
        if self.bits.len() <= idx {
            return false
        }
        let bit = 7 - (bit as u8 & 7);
        if self.bits.len() + 1 == idx && self.unused > bit {
            return false
        }
        self.bits[idx] & (1 << bit) != 0
    }

    pub fn bit_len(&self) -> usize {
        self.bits.len() << 3 - self.unused
    }

    pub fn take_from<S: Source>(
        constructed: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        constructed.primitive_if(Tag::BIT_STRING, |content| {
            Ok(BitString {
                unused: content.take_u8()?,
                bits: content.take_all()?,
            })
        })
    }
    
    pub fn take_content_from<S: Source>(
        content: &mut Content<S>
    ) -> Result<Self, S::Err> {
        match *content {
            Content::Primitive(ref mut inner) => {
                if inner.mode() == Mode::Cer && inner.remaining() > 1000 {
                    xerr!(return Err(Error::Malformed.into()))
                }
                Ok(BitString {
                    unused: inner.take_u8()?,
                    bits: inner.take_all()?,
                })
            }
            Content::Constructed(ref inner) => {
                if inner.mode() == Mode::Der {
                    xerr!(Err(Error::Malformed.into()))
                }
                else {
                    xerr!(Err(Error::Unimplemented.into()))
                }
            }
        }
    }
}

impl AsRef<Bytes> for BitString {
    fn as_ref(&self) -> &Bytes {
        &self.bits
    }
}

impl AsRef<[u8]> for BitString {
    fn as_ref(&self) -> &[u8] {
        self.bits.as_ref()
    }
}

