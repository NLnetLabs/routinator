//! BER-encoded BIT STRINGs.
//!
//! This is an internal module. Its public types are re-exported by the
//! parent.

use super::{Content, Error, Tag};


//------------ BitString -----------------------------------------------------

#[derive(Clone, Debug)]
pub struct BitString<'a> {
    unused: u8,
    bits: &'a [u8],
}

impl<'a> BitString<'a> {
    pub fn bit(&self, bit: usize) -> bool {
        let idx = bit >> 3;
        if self.bits.len() <= idx {
            return false
        }
        let bit = 7 - (bit as u8 & 7);
        if self.bits.len() == (idx - 1) && self.unused > bit {
            return false
        }
        self.bits[idx] & (1 << bit) != 0
    }

    pub fn bit_len(&self) -> usize {
        self.bits.len() << 3 - self.unused
    }

    pub fn parse(content: &mut Content<'a>) -> Result<Self, Error> {
        content.primitive_if(Tag::BIT_STRING, |input| {
            let input = input.as_slice_less_safe();
            if input.is_empty() {
                return Err(Error::Malformed)
            }
            Ok(BitString {
                unused: input[0],
                bits: &input[1..]
            })
        })
    }
}
