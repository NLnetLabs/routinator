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
/// of eight bits.
/// 
/// You can parse a bit string value out of a constructed value using the
/// `take_from` method. The `parse_content` method parses the content octets
/// of a bit string value.
///
/// Once you have a value, you can ask for the number of bits available via
/// the `bit_len` method or ask for the bit at a certain index via `bit`.
/// The type also implements `AsRef<[u8]>` and `AsRef<Bytes>` to allow access
/// to the complete bit string at once. Note, however, that the last octet
/// may not be fully used.
///
/// # BER Encoding
///
/// When encoded in BER, bit strings can either be a primitive or
/// constructed value.
///
/// If encoded as a primitive value, the first octet of the
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BitString {
    /// The number of unused bits in the last byte.
    unused: u8,

    /// The bytes of the bit string.
    bits: Bytes,
}

impl BitString {
    /// Returns the value of the given bit.
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

    /// Returns the number of bits in the bit string.
    pub fn bit_len(&self) -> usize {
        (self.bits.len() << 3) - (self.unused as usize)
    }

    /// Returns the number of unused bits in the last octet.
    pub fn unused(&self) -> u8 {
        self.unused
    }

    /// Returns the number of octets in the bit string.
    pub fn octet_len(&self) -> usize {
        self.bits.len()
    }

    /// Returns an iterator over the octets in the bit string.
    pub fn octets(&self) -> BitStringIter {
        BitStringIter(self.bits.iter())
    }

    pub fn octet_slice(&self) -> Option<&[u8]> {
        Some(self.bits.as_ref())
    }
}

/// # Parsing
///
impl BitString {
    /// Takes a single bit string value from constructed content.
    pub fn take_from<S: Source>(
        constructed: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        constructed.take_value_if(Tag::BIT_STRING, Self::parse_content)
    }

    /// Skip over a single bit string value inside constructed content.
    pub fn skip_in<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<(), S::Err> {
        cons.take_value_if(Tag::BIT_STRING, Self::skip_content)
    }
 
    /// Parses the content octets of a bit string value.
    pub fn parse_content<S: Source>(
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

    /// Skips over the content octets of a bit string value.
    pub fn skip_content<S: Source>(
        content: &mut Content<S>
    ) -> Result<(), S::Err> {
        match *content {
            Content::Primitive(ref mut inner) => {
                if inner.mode() == Mode::Cer && inner.remaining() > 1000 {
                    xerr!(return Err(Error::Malformed.into()))
                }
                inner.skip_all()
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


//------------ BitStringIter -------------------------------------------------

/// An iterator over the octets in the bit string.
#[derive(Clone, Debug)]
pub struct BitStringIter<'a>(::std::slice::Iter<'a, u8>);

impl<'a> Iterator for BitStringIter<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        self.0.next().map(|x| *x)
    }
}

