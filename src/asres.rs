//! IP Resources for use with RPKI certificates.
//!
//! The types herein are defined in RFC 3779 for use with certificates in
//! general. RFC 6487 specifies how to use them with RPKI certificates. In
//! particular, it prohibits the use of RDI values. Additionally, if the
//! "inherit" value is not used, the set of identifiers must be non-empty.

use std::{fmt, ops};
use bytes::Bytes;
use super::ber::{Constructed, Content, Error, Mode, Source, Tag};
use super::x509::ValidationError;


//------------ AsResources ---------------------------------------------------

#[derive(Clone, Debug)]
pub enum AsResources {
    Inherit,
    Ids(AsIdBlocks),
}

impl AsResources {

    pub fn is_inherited(&self) -> bool {
        match self {
            AsResources::Inherit => true,
            _ =>  false
        }
    }

    pub fn to_blocks(&self) -> Result<AsIdBlocks, ValidationError> {
        match self {
            AsResources::Inherit => Err(ValidationError),
            AsResources::Ids(ref some) => Ok(some.clone()),
        }
    }

    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            cons.take_constructed_if(Tag::CTX_0, |cons| {
                cons.take_value(|tag, content| {
                    if tag == Tag::NULL {
                        content.to_null()?;
                        Ok(AsResources::Inherit)
                    }
                    else if tag == Tag::SEQUENCE {
                        AsIdBlocks::parse_content(content)
                            .map(AsResources::Ids)
                    }
                    else {
                        xerr!(Err(Error::Malformed.into()))
                    }
                })
            })
        })
    }
}


//------------ AsBlocks ------------------------------------------------------

#[derive(Clone, Debug)]
pub struct AsBlocks(Option<AsIdBlocks>);

impl AsBlocks {
    pub fn from_resources(
        res: Option<&AsResources>
    ) -> Result<Self, ValidationError> {
        match res {
            Some(AsResources::Inherit) => Err(ValidationError),
            Some(AsResources::Ids(ref some)) => {
                Ok(AsBlocks(Some(some.clone())))
            }
            None => Ok(AsBlocks(None))
        }
    }

    pub fn encompasses(
        &self,
        res: Option<&AsResources>
    ) -> Result<Self, ValidationError> {
        match res {
            Some(AsResources::Inherit) => Ok(self.clone()),
            Some(AsResources::Ids(ref inner)) => {
                match self.0 {
                    Some(ref outer) => {
                        if outer.encompasses(inner) {
                            Ok(AsBlocks(Some(inner.clone())))
                        }
                        else {
                            Err(ValidationError)
                        }
                    }
                    None => Err(ValidationError)
                }
            }
            None => Ok(AsBlocks(None))
        }
    }
}


//------------ AsIdBlocks ----------------------------------------------------

#[derive(Clone, Debug)]
pub struct AsIdBlocks(Bytes);

impl AsIdBlocks {
    pub fn iter(&self) -> AsIdBlockIter {
        AsIdBlockIter(self.0.as_ref())
    }
}

impl AsIdBlocks {
    fn parse_content<S: Source>(
        content: &mut Content<S>
    ) -> Result<Self, S::Err> {
        let cons = content.as_constructed()?;
        cons.capture(|cons| {
            while let Some(()) = AsBlock::skip_opt_in(cons)? { }
            Ok(())
        }).map(AsIdBlocks)
    }

    fn encompasses(&self, other: &AsIdBlocks) -> bool {
        // Numbers need to be in increasing order. So we can loop over the
        // blocks in other and check that self keeps pace.
        let mut siter = self.iter();
        let mut oiter = other.iter();
        let (mut sas, mut oas) = match (siter.next(), oiter.next()) {
            (_, None) => return true,
            (None, Some(_)) => return false,
            (Some(sas), Some(oas)) => (sas, oas),
        };
        loop {
            // If they start below us, we don’t encompass them.
            if oas.min() < sas.min() {
                return false
            }
            // It they start above us, we need to go to the next range.
            else if oas.min() > sas.max() {
                sas = match siter.next() {
                    Some(sas) => sas,
                    None => return false,
                }
            }
            // If they end above us we lift their start to our end plus 1.
            else if oas.max() > sas.max() {
                // This can’t happen if sas.max() is u32::MAX (because
                // oas.max() can never be greater than that), so this
                // should be safe.
                oas.set_min(sas.max() + 1)
            }
            // If they neither start below us nor end above us, we cover them
            // and take the next block.
            else {
                oas = match oiter.next() {
                    Some(oas) => oas,
                    None => return true
                }
            }
        }
    }
}


//------------ AsIdBlockIter -------------------------------------------------

pub struct AsIdBlockIter<'a>(&'a [u8]);

impl<'a> Iterator for AsIdBlockIter<'a> {
    type Item = AsBlock;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            None
        }
        else {
            Mode::Der.decode(&mut self.0, AsBlock::take_opt_from).unwrap()
        }
    }
}


//------------ AsBlock ---------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub enum AsBlock {
    Id(AsId),
    Range(AsRange),
}

impl AsBlock {
    pub fn min(&self) -> AsId {
        match *self {
            AsBlock::Id(id) => id,
            AsBlock::Range(ref range) => range.min(),
        }
    }

    pub fn max(&self) -> AsId {
        match *self {
            AsBlock::Id(id) => id,
            AsBlock::Range(ref range) => range.max(),
        }
    }

    pub fn set_min(&mut self, id: AsId) {
        if id < self.max() {
            *self = AsBlock::Range(AsRange::new(id, self.max()))
        }
        else if id == self.max() {
            *self = AsBlock::Id(id)
        }
        else {
            panic!("trying to set minimum beyond current maximum");
        }
    }

    pub fn set_max(&mut self, id: AsId) {
        if id > self.min() {
            *self = AsBlock::Range(AsRange::new(self.min(), id))
        }
        else if id == self.min() {
            *self = AsBlock::Id(id)
        }
        else {
            panic!("trying to set maximum below current minimum");
        }
    }
}

impl AsBlock {
    fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Option<Self>, S::Err> {
        cons.take_opt_value(|tag, content| {
            if tag == Tag::INTEGER {
                AsId::parse_content(content).map(AsBlock::Id)
            }
            else if tag == Tag::SEQUENCE {
                AsRange::parse_content(content).map(AsBlock::Range)
            }
            else {
                xerr!(Err(Error::Malformed.into()))
            }
        })
    }

    fn skip_opt_in<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Option<()>, S::Err> {
        cons.take_opt_value(|tag, content| {
            if tag == Tag::INTEGER {
                AsId::skip_content(content)
            }
            else if tag == Tag::SEQUENCE {
                AsRange::skip_content(content)
            }
            else {
                xerr!(Err(Error::Malformed.into()))
            }
        })
    }
}


//------------ AsId ----------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AsId(u32);

impl AsId {
    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_u32().map(AsId)
    }

    fn skip_in<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<(), S::Err> {
        cons.take_u32().map(|_| ())
    }

    fn parse_content<S: Source>(
        content: &mut Content<S>
    ) -> Result<Self, S::Err> {
        content.to_u32().map(AsId)
    }

    fn skip_content<S: Source>(
        content: &mut Content<S>
    ) -> Result<(), S::Err> {
        content.to_u32().map(|_| ())
    }
}

impl ops::Add<u32> for AsId {
    type Output = Self;

    fn add(self, rhs: u32) -> Self {
        AsId(self.0.checked_add(rhs).unwrap())
    }
}

impl fmt::Display for AsId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "AS{}", self.0)
    }
}


//------------ AsRange -------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct AsRange {
    min: AsId,
    max: AsId,
}

impl AsRange {
    pub fn new(min: AsId, max: AsId) -> Self {
        AsRange { min, max }
    }

    pub fn min(&self) -> AsId {
        self.min
    }

    pub fn max(&self) -> AsId {
        self.max
    }
}

impl AsRange {
    fn parse_content<S: Source>(
        content: &mut Content<S>
    ) -> Result<Self, S::Err> {
        let cons = content.as_constructed()?;
        Ok(AsRange {
            min: AsId::take_from(cons)?,
            max: AsId::take_from(cons)?,
        })
    }

    fn skip_content<S: Source>(
        content: &mut Content<S>
    ) -> Result<(), S::Err> {
        let cons = content.as_constructed()?;
        AsId::skip_in(cons)?;
        AsId::skip_in(cons)?;
        Ok(())
    }
}

