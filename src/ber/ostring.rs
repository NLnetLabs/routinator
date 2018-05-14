//! A BER-encoded OCTET STRING.
//!
//! This is an internal module. It’s public types are re-exportet by the
//! parent.

use ring::digest;
use untrusted::Input;
use super::{Content, Error, Tag};


/// A BER-encoded OCTET STRING.
//
//  A value of this type contains the complete value of the octet string,
//  tag, length, and all. This is so we can deal with complex constructed
//  values correctly.
//
//  Note that we only need the tag to determine whether the value is of the
//  constructed variety but otherwise ignore both the class and the number
//  so we can deal with IMPLICIT values.
#[derive(Clone, Debug)]
pub struct OctetString<'a>(Input<'a>);

impl<'a> OctetString<'a> {
    pub fn parse_if(
        content: &mut Content<'a>,
        mut expected: Tag
    ) -> Result<Self, Error> {
        content.recursive_input(&mut |tag, _| {
            if tag != expected.primitive() && tag != expected.constructed() {
                return Err(Error::Malformed)
            }
            expected = Tag::OCTET_STRING;
            Ok(())
        }).map(OctetString)
    }

    pub fn parse(content: &mut Content<'a>) -> Result<Self, Error> {
        Self::parse_if(content, Tag::OCTET_STRING)
    }

    pub fn sha256(&self) -> digest::Digest {
        let mut context = digest::Context::new(&digest::SHA256);
        Content::parse(self.0.clone(), |content| {
            content.recursive_input(&mut |_, input| {
                if let Some(input) = input {
                    context.update(input.as_slice_less_safe())
                }
                Ok(())
            }).unwrap();
            Ok(())
        }).unwrap();
        context.finish()
    }
}

