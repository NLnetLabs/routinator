
use std::fmt;
use untrusted::Reader;
use super::error::Error;

//------------ Tag -----------------------------------------------------------

/// The identifier octets of an encoded value, aka its tag.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Tag(u8);

impl Tag {
    const CONSTRUCTED: u8 = 0x20;
    const CONTEXT_SPECIFIC: u8 = 0x80;

    pub const END_OF_VALUE: Self = Tag(0x00);
    pub const BOOLEAN: Self = Tag(0x01);
    pub const INTEGER: Self = Tag(0x02);
    pub const BIT_STRING: Self = Tag(0x03);
    pub const OCTET_STRING: Self = Tag(0x04);
    pub const NULL: Self = Tag(0x05);
    pub const OID: Self = Tag(0x06);
    pub const SEQUENCE: Self = Tag(Tag::CONSTRUCTED | 0x10);
    pub const SET: Self = Tag(Tag::CONSTRUCTED | 0x11);
    pub const UTC_TIME: Self = Tag(0x17);
    pub const GENERALIZED_TIME: Self = Tag(0x18);

    pub const OCTET_STRING_CON: Self = Tag(0x04| Tag::CONSTRUCTED);

    pub const CTX_CON_0: Self
        = Tag(Tag::CONTEXT_SPECIFIC | Tag::CONSTRUCTED | 0);
    pub const CTX_CON_1: Self
        = Tag(Tag::CONTEXT_SPECIFIC | Tag::CONSTRUCTED | 1);
    pub const CTX_CON_2: Self
        = Tag(Tag::CONTEXT_SPECIFIC | Tag::CONSTRUCTED | 2);
    pub const CTX_CON_3: Self
        = Tag(Tag::CONTEXT_SPECIFIC | Tag::CONSTRUCTED | 3);

    pub const CTX_0: Self = Tag(Tag::CONTEXT_SPECIFIC | 0);
    pub const CTX_1: Self = Tag(Tag::CONTEXT_SPECIFIC | 0);
    pub const CTX_2: Self = Tag(Tag::CONTEXT_SPECIFIC | 0);
    pub const CTX_3: Self = Tag(Tag::CONTEXT_SPECIFIC | 0);
}

impl Tag {
    pub fn parse<'a>(input: &mut Reader<'a>) -> Result<Self, Error> {
        let byte = input.read_byte()?;
        if (byte & 0x1F) == 0x1F {
            // If all five lower bits are 1, the tag is encoded in multiple
            // bytes. We don’t support that.
            Err(Error::Unimplemented)
        }
        else {
            Ok(Tag(byte))
        }
    }

    pub fn peek<'a>(&self, reader: &Reader<'a>) -> bool {
        if reader.at_end() {
            false
        }
        else {
            reader.peek(self.0)
        }
    }

    pub fn is_primitive(&self) -> bool {
        self.0 & 0x20 == 0
    }

    pub fn primitive(&self) -> Tag {
        Tag(self.0 & 0xdf)
    }

    pub fn constructed(&self) -> Tag {
        Tag(self.0 | 0x20)
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
            Tag::CTX_CON_0 => write!(f, "[0]"),
            Tag::CTX_CON_1 => write!(f, "[1]"),
            Tag::CTX_CON_2 => write!(f, "[2]"),
            Tag::CTX_CON_3 => write!(f, "[3]"),
            _ => write!(f, "Tag(0x{:02x})", self.0)
        }
    }
}
