//! Object Identifiers.
//!
//! This is a private module. Its public content is re-exportet by the parent.

use std::fmt;
use bytes::Bytes;
use super::content::Constructed;
use super::error::Error;
use super::source::Source;
use super::tag::Tag;


//------------ Oid -----------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Oid<T: AsRef<[u8]>=Bytes>(pub T);

impl Oid<Bytes> {
    pub fn skip_in<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<(), S::Err> {
        cons.take_primitive_if(Tag::OID, |prim| prim.skip_all())
    }

    pub fn skip_opt_in<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Option<()>, S::Err> {
        cons.take_opt_primitive_if(Tag::OID, |prim| prim.skip_all())
    }

    pub fn take_from<S: Source>(
        constructed: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        constructed.take_primitive_if(Tag::OID, |content| {
            content.take_all().map(Oid)
        })
    }

    pub fn take_opt_from<S: Source>(
        constructed: &mut Constructed<S>
    ) -> Result<Option<Self>, S::Err> {
        constructed.take_opt_primitive_if(Tag::OID, |content| {
            content.take_all().map(Oid)
        })
    }
}

impl<T: AsRef<[u8]>> Oid<T> {
    pub fn skip_if<S: Source>(
        &self,
        constructed: &mut Constructed<S>
    ) -> Result<(), S::Err> {
        constructed.take_primitive_if(Tag::OID, |content| {
            let len = content.remaining();
            content.request(len)?;
            if &content.slice()[..len] == self.0.as_ref() {
                content.skip_all()?;
                Ok(())
            }
            else {
                xerr!(Err(Error::Malformed.into()))
            }
        })
    }

    pub fn iter(&self) -> Result<IdIter, Error> {
        let mut sublen = 0;
        for &ch in self.0.as_ref() {
            if ch & 0x80 != 0 {
                sublen += 1;
                if sublen == 1 && ch == 0x80 {
                    xerr!(return Err(Error::Malformed))
                }
                if sublen == 5 {
                    xerr!(return Err(Error::Unimplemented))
                }
            }
            else {
                sublen = 0
            }
        }
        if sublen != 0 {
            xerr!(return Err(Error::Malformed))
        }
        Ok(IdIter(self.0.as_ref()))
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Oid<T> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<T: AsRef<[u8]>, U: AsRef<[u8]>> PartialEq<U> for Oid<T> {
    fn eq(&self, other: &U) -> bool {
        self.0.as_ref() == other.as_ref()
    }
}

impl<T: AsRef<[u8]>> Eq for Oid<T> { }


impl<T: AsRef<[u8]>> fmt::Display for Oid<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.iter() {
            Ok(mut ids) => {
                let first = ids.next().unwrap();
                write!(f, "{}.{}", first / 40, first % 40)?;
                for id in ids {
                    write!(f, ".{}", id)?;
                }
            }
            Err(Error::Malformed) => write!(f, "malformed")?,
            Err(Error::Unimplemented) => write!(f, "unimplemented")?,
        }
        Ok(())
    }
}


//------------ IdIter --------------------------------------------------------

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

