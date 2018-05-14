
use std::fmt;
use super::{Content, Error, Tag};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Oid<'a>(pub &'a [u8]);

impl<'a> Oid<'a> {
    pub fn parse<'r>(content: &mut Content<'a>) -> Result<Self, Error> {
        content.primitive_if(Tag::OID, |input| {
            Ok(Oid(input.as_slice_less_safe()))
        })
    }

    pub fn skip_if(&self, content: &mut Content<'a>) -> Result<(), Error> {
        if Self::parse(content)? == *self {
            Ok(())
        }
        else {
            Err(Error::Malformed)
        }
    }

    pub fn iter(&self) -> IdIter {
        IdIter(self.0)
    }
}
        
impl<'a> fmt::Display for Oid<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut ids = self.iter();
        let first = ids.next().unwrap();
        write!(f, "{}.{}", first / 40, first % 40)?;
        for id in ids {
            write!(f, ".{}", id)?;
        }
        Ok(())
    }
}

pub struct IdIter<'a>(&'a [u8]);

impl<'a> Iterator for IdIter<'a> {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            return None
        }
        let mut tail = self.0;
        let mut res = 0;
        for _ in 0..4 {
            let first = match tail.split_first() {
                Some((x, rest)) => {
                    tail = rest;
                    *x
                }
                None => panic!("invalid OID")
            };
            res = (res << 7) | (first & 0x7f) as u32;
            if first < 0x80 {
                self.0 = tail;
                return Some(res)
            }
        }
        panic!("Invalid OID.");
    }
}

