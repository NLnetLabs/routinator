use std::fmt;
use super::error::Error;
use super::source::Source;


//------------ Tag -----------------------------------------------------------

/// The identifier octets of an encoded value, aka its tag.
//
//  For the moment, the tag is stored as a single `u8` with the constructed
//  bit always cleared. Whether a value is primitive or constructed is
//  indicated via the type used for the value itself.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Tag(u8);

impl Tag {
    const CONTEXT_SPECIFIC: u8 = 0x80;

    pub const END_OF_VALUE: Self = Tag(0x00);
    pub const BOOLEAN: Self = Tag(0x01);
    pub const INTEGER: Self = Tag(0x02);
    pub const BIT_STRING: Self = Tag(0x03);
    pub const OCTET_STRING: Self = Tag(0x04);
    pub const NULL: Self = Tag(0x05);
    pub const OID: Self = Tag(0x06);
    pub const SEQUENCE: Self = Tag(0x10);
    pub const SET: Self = Tag(0x11);
    pub const UTC_TIME: Self = Tag(0x17);
    pub const GENERALIZED_TIME: Self = Tag(0x18);

    pub const CTX_0: Self = Tag(Tag::CONTEXT_SPECIFIC | 0);
    pub const CTX_1: Self = Tag(Tag::CONTEXT_SPECIFIC | 1);
    pub const CTX_2: Self = Tag(Tag::CONTEXT_SPECIFIC | 2);
    pub const CTX_3: Self = Tag(Tag::CONTEXT_SPECIFIC | 3);
    pub const CTX_4: Self = Tag(Tag::CONTEXT_SPECIFIC | 4);
    pub const CTX_5: Self = Tag(Tag::CONTEXT_SPECIFIC | 5);
    pub const CTX_6: Self = Tag(Tag::CONTEXT_SPECIFIC | 6);
}

impl Tag {
    pub fn take_from<S: Source>(
        source: &mut S,
    ) -> Result<(Self, bool), S::Err> {
        let byte = source.take_u8()?;
        if (byte & 0x1F) == 0x1F {
            // If all five lower bits are 1, the tag is encoded in multiple
            // bytes. We don’t support that.
            xerr!(return Err(Error::Unimplemented.into()))
        }
        Ok((Tag(byte & 0xdf), byte & 0x20 != 0))
    }

    pub fn take_from_if<S: Source>(
        self,
        source: &mut S,
    ) -> Result<Option<bool>, S::Err> {
        if source.request(1)? == 0 {
            return Ok(None)
        }
        let byte = source.slice()[0];
        let (tag, compressed) = (Tag(byte & 0xdf), byte & 0x20 != 0);
        if tag == self {
            source.advance(1)?;
            Ok(Some(compressed))
        }
        else {
            Ok(None)
        }
    }
}


impl fmt::Debug for Tag {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Tag::BOOLEAN => write!(f, "BOOLEAN"),
            Tag::INTEGER => write!(f, "INTEGER"),
            Tag::BIT_STRING => write!(f, "BIT STRING"),
            Tag::OCTET_STRING => write!(f, "OCTET STRING"),
            Tag::NULL => write!(f, "NULL"),
            Tag::OID => write!(f, "OBJECT IDENTIFIER"),
            Tag::SEQUENCE => write!(f, "SEQUENCE"),
            Tag::SET => write!(f, "SET"),
            Tag::CTX_0 => write!(f, "[0]"),
            Tag::CTX_1 => write!(f, "[1]"),
            Tag::CTX_2 => write!(f, "[2]"),
            Tag::CTX_3 => write!(f, "[3]"),
            _ => write!(f, "Tag(0x{:02x})", self.0)
        }
    }
}

