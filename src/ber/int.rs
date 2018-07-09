//! BER encoded integers.

use bytes::Bytes;
use super::content::{Constructed, Primitive};
use super::error::Error;
use super::source::Source;
use super::tag::Tag;


//------------ Integer -------------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Integer(Bytes);

impl Integer {
    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_primitive_if(Tag::INTEGER, Self::take_content_from)
    }

    pub fn take_content_from<S: Source>(
        prim: &mut Primitive<S>
    ) -> Result<Self, S::Err> {
        let res = prim.take_all()?;
        match (res.get(0), res.get(1).map(|x| x & 0x80 != 0)) {
            (Some(0), Some(false)) => {
                xerr!(return Err(Error::Malformed.into()))
            }
            (Some(0xFF), Some(true)) => {
                xerr!(return Err(Error::Malformed.into()))
            }
            (None, _) => {
                xerr!(return Err(Error::Malformed.into()))
            }
            _ => { }
        }
        Ok(Integer(res))
    }
}


//------------ Unsigned ------------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Unsigned(Bytes);

impl Unsigned {
    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_primitive_if(Tag::INTEGER, Self::take_content_from)
    }

    pub fn take_content_from<S: Source>(
        prim: &mut Primitive<S>
    ) -> Result<Self, S::Err> {
        let res = prim.take_all()?;
        match (res.get(0), res.get(1).map(|x| x & 0x80 != 0)) {
            (Some(0), Some(false)) => {
                xerr!(return Err(Error::Malformed.into()))
            }
            (Some(0xFF), Some(true)) => {
                xerr!(return Err(Error::Malformed.into()))
            }
            (Some(x), _) if x & 0x80 != 0 => {
                xerr!(return Err(Error::Malformed.into()))
            }
            (None, _) => {
                xerr!(return Err(Error::Malformed.into()))
            }
            _ => { }
        }
        Ok(Unsigned(res))
    }
}

