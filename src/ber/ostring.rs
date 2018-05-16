//! A BER-encoded OCTET STRING.
//!
//! This is an internal module. It’s public types are re-exportet by the
//! parent.

use ring::digest;
use untrusted::{Input, Reader};
use super::{Content, Error, Length, Tag};


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

    pub fn iter(&self) -> OctetStringIter<'a> {
        OctetStringIter::new(self)
    }
}

impl<'a, 'b> PartialEq<OctetString<'b>> for OctetString<'a> {
    fn eq(&self, other: &OctetString<'b>) -> bool {
        // Short-cut: if both are primitive, we can compare slices.
        if Tag::from(self.0.as_slice_less_safe()[0]).is_primitive()
            && Tag::from(other.0.as_slice_less_safe()[0]).is_primitive()
        {
            // We can compare including the length octets since they need
            // to be identical under proper encoding.
            self.0.as_slice_less_safe()[1..]
                == other.0.as_slice_less_safe()[1..]
        }
        else {
            let mut self_iter = self.iter();
            let mut other_iter = other.iter();
            loop {
                match (self_iter.next(), other_iter.next()) {
                    (None, None) => return true,
                    (Some(left), Some(right)) if left == right => { }
                    _ => return false
                }
            }
        }
    }
}

impl<'a> Eq for OctetString<'a> { }

impl<'a> IntoIterator for OctetString<'a> {
    type Item = u8;
    type IntoIter = OctetStringIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a, 'b> IntoIterator for &'b OctetString<'a> {
    type Item = u8;
    type IntoIter = OctetStringIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}


//------------ OctetStringIter -----------------------------------------------

/// An iterator over the bytes in an octet string.
//
//  It turns out that a complex octet string is basically a sequence of
//  primitive octet strings interrupted by a bunch of constructed octet
//  string tags and length octets plus end-of-value markers both of which
//  we can simply skip. So the iterator needs to have a reader and how many
//  bytes are left in the current primitive. If that number is updated to
//  zero, we continue to the next primitive, so if it actually ever is zero
//  in the struct, we are done.
#[derive(Debug)]
pub struct OctetStringIter<'a> {
    reader: Reader<'a>,
    left: usize,
}

impl<'a> OctetStringIter<'a> {
    fn new(s: &OctetString<'a>) -> Self {
        let mut res = OctetStringIter {
            reader: Reader::new(s.0.clone()),
            left: 0,
        };
        res.advance();
        res
    }

    /// Advances the iterator to the next primitive segment.
    fn advance(&mut self) {
        while !self.reader.at_end() {
            let tag = Tag::parse(&mut self.reader).unwrap();
            let length = Length::parse(&mut self.reader).unwrap();
            if tag.is_primitive() {
                if tag != Tag::END_OF_VALUE {
                    if let Length::Definite(len) = length {
                        self.left = len;
                        break;
                    }
                    else {
                        panic!("indefinite primitive")
                    }
                }
            }
        }
    }
}

impl<'a> Iterator for OctetStringIter<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.left == 0 {
            None
        }
        else {
            let res = self.reader.read_byte().unwrap();
            self.left -= 1;
            if self.left == 0 {
                self.advance();
            }
            Some(res)
        }
    }
}

