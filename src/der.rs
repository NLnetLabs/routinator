//! DER Parsing.
//!
//! This is based on `ring::der`.

use untrusted::{EndOfInput, Input, Reader};


//------------ Tag -----------------------------------------------------------

/// An ASN.1 tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Tag(u8);

impl Tag {
    const CONSTRUCTED: u8 = 0x20;
    const CONTEXT_SPECIFIC: u8 = 0x80;

    pub const BOOLEAN: Self = Tag(0x01);
    pub const INTEGER: Self = Tag(0x02);
    pub const BIT_STRING: Self = Tag(0x03);
    pub const OCTET_STRING: Self = Tag(0x04);
    pub const NULL: Self = Tag(0x05);
    pub const OID: Self = Tag(0x06);
    pub const SEQUENCE: Self = Tag(Tag::CONSTRUCTED | 0x10);
    pub const SET: Self = Tag(Tag::CONSTRUCTED | 0x11);

    pub const CTX_CON_1: Self
        = Tag(Tag::CONTEXT_SPECIFIC | Tag::CONSTRUCTED | 1);
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
}


//------------ Parse functions -----------------------------------------------

pub fn parse_value<'a>(
    input: &mut Reader<'a>
) -> Result<(Tag, Input<'a>), Error> {
    let tag = Tag::parse(input)?;
    
    let length = match input.read_byte()? {
        // Bit 7 clear: rest is the length
        n if (n & 0x80) == 0 => n as usize,
        
        // But 7 set: rest is the number of bytes encoding the length.
        // This is only allowed if above option doesn’t fit.
        // Two of those should be enough.
        0x81 => {
            let n = input.read_byte()?;
            if n < 128 {
                return Err(Error::Malformed)
            }
            n as usize
        }
        0x82 => {
            let n = ((input.read_byte()? as usize) << 8)
                  | (input.read_byte()? as usize);
            if n < 256 {
                return Err(Error::Malformed)
            }
            n
        }
        _ => return Err(Error::Unimplemented)
    };
    Ok((tag, input.skip_and_get_input(length)?))
}

pub fn parse_expected<'a>(
    input: &mut Reader<'a>,
    expected: Tag,
) -> Result<Input<'a>, Error> {
    let (tag, inner) = parse_value(input)?;
    if tag != expected {
        Err(Error::Malformed)
    }
    else {
        Ok(inner)
    }
}

pub fn parse_nested<'a, F, T>(
    input: &mut Reader<'a>,
    expected: Tag,
    parse: F
) -> Result<T, Error>
where F: FnOnce(&mut Reader<'a>) -> Result<T, Error> {
    let inner = parse_expected(input, expected)?;
    inner.read_all(Error::Malformed, parse)
}


//------------ Oid -----------------------------------------------------------

pub struct Oid<'a>(Input<'a>);

impl<'a> Oid<'a> {
    pub fn parse(input: &mut Reader<'a>) -> Result<Self, Error> {
        parse_expected(input, Tag::OID).map(Oid)
    }
}


//------------ Error ---------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub enum Error {
    /// Malformed DER.
    Malformed,

    /// DER uses features we haven’t implemented.
    Unimplemented,
}

impl From<EndOfInput> for Error {
    fn from(_: EndOfInput) -> Error {
        Error::Malformed
    }
}

