//! The identifer octets of a BER encoded value.
//!
//! This is a private module. Its public content is being re-exported by the
//! parent module.
use std::fmt;
use super::error::Error;
use super::source::Source;


//------------ Tag -----------------------------------------------------------

/// The tag of a BER encoded value.
///
/// Each BER encoded value starts with a sequence of one or more octets called
/// the _identifier octets._ They encode both the tag of the value as well as
/// whether the value is primitive or constructed. This type represents the
/// tag while the latter is represented by the decoder types `Primitive` or
/// `Constructed`.
///
/// The tag in turn consists of two parts: the class and the number – the
/// `Tag` type includes both of them.
///
/// At the moment, you can only compare two tags. All necessary values are
/// defined as associated constants; there is no other way to create new tag
/// values.
///
/// # Limitations
///
/// At this time, we can only decode single-octet identifier octets. That is,
/// we only support tag number between 0 and 31.
//
//  For the moment, the tag is stored as a single `u8` with the constructed
//  bit always cleared. Whether a value is primitive or constructed is
//  indicated via the type used for the value itself.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Tag(u8);

impl Tag {
    /// The tag value representing the ‘context-specific’ class.
    const CONTEXT_SPECIFIC: u8 = 0x80;

    /// The tag marking the end-of-value in an indefinite length value.
    ///
    /// This is UNIVERSAL 0.
    pub const END_OF_VALUE: Self = Tag(0x00);

    /// The tag for the BOOLEAN type, UNIVERSAL 1.
    pub const BOOLEAN: Self = Tag(0x01);

    /// The tag for the INTEGER type, UNIVERSAL 2.
    pub const INTEGER: Self = Tag(0x02);

    /// The tag for the BIT STRING type, UNIVERSAL 3.
    pub const BIT_STRING: Self = Tag(0x03);

    /// The tag for the OCTET STRING type, UNIVERSAL 4.
    pub const OCTET_STRING: Self = Tag(0x04);

    /// The tag for the NULL type, UNIVERSAL 5.
    pub const NULL: Self = Tag(0x05);

    /// The tag for the OBJECT IDENTIFIER type, UNIVERSAL 6.
    pub const OID: Self = Tag(0x06);

    /// The tag for the REAL type, UNIVERSAL 9.
    pub const REAL: Self = Tag(0x09);

    /// The tag for the SEQUENCE and SEQUENCE OF types, UNIVERSAL 16.
    pub const SEQUENCE: Self = Tag(0x10);

    /// The tag for the SET and SET OF types, UNIVERSAL 17.
    pub const SET: Self = Tag(0x11);

    /// The tag for the IA5String type, UNIVERSAL 22.
    pub const IA5_STRING: Self = Tag(0x16);

    /// The tag for the UTCTime type, UNIVERSAL 23.
    pub const UTC_TIME: Self = Tag(0x17);

    /// The tag for the GeneralizedType type, UNIVERAL 24.
    pub const GENERALIZED_TIME: Self = Tag(0x18);

    /// The tag context specific tag [0].
    pub const CTX_0: Self = Tag(Tag::CONTEXT_SPECIFIC | 0);

    /// The tag context specific tag [1].
    pub const CTX_1: Self = Tag(Tag::CONTEXT_SPECIFIC | 1);

    /// The tag context specific tag [2].
    pub const CTX_2: Self = Tag(Tag::CONTEXT_SPECIFIC | 2);

    /// The tag context specific tag [3].
    pub const CTX_3: Self = Tag(Tag::CONTEXT_SPECIFIC | 3);

    /// The tag context specific tag [4].
    pub const CTX_4: Self = Tag(Tag::CONTEXT_SPECIFIC | 4);

    /// The tag context specific tag [5].
    pub const CTX_5: Self = Tag(Tag::CONTEXT_SPECIFIC | 5);

    /// The tag context specific tag [6].
    pub const CTX_6: Self = Tag(Tag::CONTEXT_SPECIFIC | 6);
}

impl Tag {
    /// Takes a tag from the beginning of a source.
    ///
    /// Upon success, returns both the tag and whether the value is
    /// constructed. If there are no more octets available in the source,
    /// an error is returned.
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

    /// Takes a tag from the beginning of a resource if it matches this tag.
    ///
    /// If there is no more data available in the source or if the tag is
    /// something else, returns `Ok(None)`. If the tag matches `self`, returns
    /// whether the value is constructed.
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

