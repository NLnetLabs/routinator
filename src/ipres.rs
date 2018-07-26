//! IP Resources for use with RPKI certificates.
//!
//! The types herein are defined in RFC 3779 for use with certificates in
//! general. RFC 6487 specifies how to use them with RPKI certificates. In
//! particular, it prohibits the use of Subsequent AFI values for address
//! families, making them always 16 bit. Additionally, if the "inherit"
//! value is not used for an address family, the set of addresses must be
//! non-empty.

use bytes::Bytes;
use super::ber::{
    BitString, Constructed, Content, Error, Mode, OctetString, Source, Tag,
};
use super::roa::RoaIpAddress;
use super::x509::ValidationError;


//------------ IpResources ---------------------------------------------------

/// The IP Address Resources of an RPKI Certificate.
///
/// This type contains these resources as parsed from the certificate. Apart
/// from parsing, you won’t use this type much. Instead, you’ll convert it
/// into a list of address blocks via `IpAddressBlocks::from_resources`.
#[derive(Clone, Debug)]
pub struct IpResources {
    /// The IPv4 address resources if present.
    v4: Option<AddressChoice>,

    /// The IPv6 address resources if present.
    v6: Option<AddressChoice>,
}

impl IpResources {
    /// Takes the IP resources from the beginning of a constructed value.
    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            let mut v4 = None;
            let mut v6 = None;
            while let Some(()) = cons.take_opt_sequence(|cons| {
                let af = AddressFamily::take_from(cons)?;
                match af {
                    AddressFamily::Ipv4 => {
                        if v4.is_some() {
                            xerr!(return Err(Error::Malformed.into()));
                        }
                        v4 = Some(AddressChoice::take_from(cons)?);
                    }
                    AddressFamily::Ipv6 => {
                        if v6.is_some() {
                            xerr!(return Err(Error::Malformed.into()));
                        }
                        v6 = Some(AddressChoice::take_from(cons)?);
                    }
                }
                Ok(())
            })? { }
            if v4.is_none() && v6.is_none() {
                xerr!(return Err(Error::Malformed.into()));
            }
            Ok(IpResources { v4, v6 })
        })
    }
}


//------------ AddressChoice -------------------------------------------------

/// The choice of per-family address resources.
///
/// This can either be an actual list of address blocks or `Inherit`, which
/// instructs to just keep using the address blocks from the issuer
/// certificate.
#[derive(Clone, Debug)]
pub enum AddressChoice {
    Inherit,
    Blocks(AddressBlocks),
}

impl AddressChoice {
    /// Returns whether the choice is for inheriting.
    pub fn is_inherited(&self) -> bool {
        match *self {
            AddressChoice::Inherit => true,
            _ => false
        }
    }

    /// Converts the choice into a list of address blocks.
    ///
    /// If the inherit choice is present, this will result in a
    /// validation error.
    pub fn to_blocks(&self) -> Result<AddressBlocks, ValidationError> {
        match *self {
            AddressChoice::Inherit => Err(ValidationError),
            AddressChoice::Blocks(ref blocks) => Ok(blocks.clone())
        }
    }
}

impl AddressChoice {
    /// Takes an address choice from the beginning of a constructed value.
    fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_value(|tag, content| {
            if tag == Tag::NULL {
                content.to_null()?;
                Ok(AddressChoice::Inherit)
            }
            else if tag == Tag::SEQUENCE {
                AddressBlocks::parse_content(content)
                    .map(AddressChoice::Blocks)
            }
            else {
                xerr!(Err(Error::Malformed.into()))
            }
        })
    }
}


//------------ IpAddressBlocks -----------------------------------------------

/// A list of IP address blocks.
///
/// This type actually contains two optional lists of address blocks, one each
/// for IPv4 and IPv6.
#[derive(Clone, Debug)]
pub struct IpAddressBlocks {
    v4: Option<AddressBlocks>,
    v6: Option<AddressBlocks>,
}

impl IpAddressBlocks {
    /// Creates a list of IP address blocks from IP resources.
    ///
    /// If no resources are present, creates an empty list. If either of the
    /// families in the resources has chosen the inherit choice, the function
    /// will return a validation error.
    pub fn from_resources(
        res: Option<&IpResources>
    ) -> Result<Self, ValidationError> {
        match res {
            Some(res) => {
                Ok(IpAddressBlocks {
                    v4: match res.v4.as_ref() {
                        Some(res) => Some(res.to_blocks()?),
                        None => None,
                    },
                    v6: match res.v6.as_ref() {
                        Some(res) => Some(res.to_blocks()?),
                        None => None,
                    }
                })
            }
            None =>
                Ok(IpAddressBlocks {
                    v4: None,
                    v6: None
                })
        }
    }

    /// Produces a new value if `res` is encompassed by this value.
    ///
    /// If `res` is `None`, an empy set of blocks is returned. Otherwise,
    /// checks whether any blocks in `res` are encompassed by `self`, that
    /// is, they either are the same or are smaller.
    pub fn encompasses(
        &self,
        res: Option<&IpResources>
    ) -> Result<Self, ValidationError> {
        let res = match res {
            Some(res) => res,
            None => &IpResources { v4: None, v6: None }
        };
        Ok(IpAddressBlocks {
            v4: AddressBlocks::encompasses(self.v4.as_ref(), res.v4.as_ref())?,
            v6: AddressBlocks::encompasses(self.v6.as_ref(), res.v6.as_ref())?,
        })
    }

    /// Returns a reference to the IPv4 address blocks if there are any.
    pub fn v4(&self) -> Option<&AddressBlocks> {
        self.v4.as_ref()
    }

    /// Returns a reference to the IPv6 address blocks if there are any.
    pub fn v6(&self) -> Option<&AddressBlocks> {
        self.v6.as_ref()
    }
}


//------------ AddressBlocks -------------------------------------------------

/// A sequence of address ranges for one address family.
#[derive(Clone, Debug)]
pub struct AddressBlocks(Bytes);

impl AddressBlocks {
    /// Returns an iterator over the address ranges in the block.
    pub fn iter(&self) -> AddressBlocksIter {
        AddressBlocksIter(self.0.as_ref())
    }

    /// Returns whether the address blocks cover the given ROA address prefix.
    pub fn contain(&self, addr: &RoaIpAddress) -> bool {
        let (min, max) = addr.range();
        for range in self.iter() {
            if range.min() <= min && range.max() >= max {
                return true
            }
        }
        false
    }
}

impl AddressBlocks {
    /// Parses the content of an address block sequence.
    fn parse_content<S: Source>(
        content: &mut Content<S>
    ) -> Result<Self, S::Err> {
        content.as_constructed()?.capture(|cons| {
            while let Some(()) = AddressRange::skip_opt_in(cons)? {
            }
            Ok(())
        }).map(AddressBlocks)
    }

    /// Checks that `outer` encompasses `inner`.
    ///
    /// Encompasses means that `outer` covers all the IP addresses covered
    /// by `inner`. For this function, `inner` can either be an address block
    /// sequence itself or is to inherit the blocks from `outer`. The
    /// function will return the sequence to use – which will be `outer` for
    /// the inherit option – or an error.
    ///
    /// If `inner` is `None`, the result will be `Ok(None)`. If `outer` is
    /// `None`, `inner` has to be `None`, too, or an error will happen.
    fn encompasses(
        outer: Option<&Self>,
        inner: Option<&AddressChoice>
    ) -> Result<Option<Self>, ValidationError> {
        match (outer, inner) {
            (Some(outer), Some(AddressChoice::Inherit)) => {
                Ok(Some(outer.clone()))
            }
            (None, Some(AddressChoice::Inherit)) => Ok(None),
            (Some(outer), Some(AddressChoice::Blocks(inner))) => {
                if outer._encompasses(inner) {
                    Ok(Some(inner.clone()))
                }
                else {
                    Err(ValidationError)
                }
            }
            (_, None) => Ok(None),
            _ => Err(ValidationError)
        }
    }

    /// Returns whether an address block sequence is encompassed by `self`.
    fn _encompasses(&self, other: &Self) -> bool {
        // Everything is supposed to be in increasing order. So we can treat
        // prefixes and blocks both as address ranges (which they actually 
        // are, of course), and can treat them as 128 bit unsigned integers.
        // Then we loop over the ranges in other and check that self covers
        // those.
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
                // This can’t happen if sas.max() is u128::MAX (because
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


//------------ AddressBlocksIter ---------------------------------------------

/// An iterator over the address ranges in an address block sequence.
///
/// You can get a value of this type via `AddressBlocks::iter`.
pub struct AddressBlocksIter<'a>(&'a [u8]);

impl<'a> Iterator for AddressBlocksIter<'a> {
    type Item = AddressRange;
    
    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            None
        }
        else {
            Mode::Der.decode(&mut self.0, AddressRange::take_opt_from).unwrap()
        }
    }
}


//------------ AddressRange --------------------------------------------------

/// An IP address range.
///
/// This type appears in two variants in RFC 3779, either as a single prefix
/// (IPAddress) or as a range (IPAddressRange). Both cases actually cover a
/// consecutive range of addresses, so there is a minimum and a maximum
/// address covered by them. We simply model both of them as ranges of those
/// minimums and maximums.
///
/// Since all values are encoded are prefixes, we can use the same type for
/// both IPv4 and IPv6 by using 128 bit addresses in either case and use only
/// the upper 32 bits for IPv4.
#[derive(Clone, Debug)]
pub struct AddressRange {
    /// The smallest IP address that is part of this range.
    min: u128,

    /// The largest IP address that is part of this range.
    ///
    /// Note that this means that, unlike normal Rust ranges, our range is
    /// inclusive at the upper end. This is necessary to represent a range
    /// that goes all the way to the last address (which, for instance,
    /// `::0/0` does).
    max: u128,
}

impl AddressRange {
    /// Returns the smallest IP address that is part of this range.
    pub fn min(&self) -> u128 {
        self.min
    }

    /// Returns the largest IP address that is still part of this range.
    pub fn max(&self) -> u128 {
        self.max
    }

    /// Sets a new minimum IP address.
    ///
    /// # Panics
    ///
    /// If you try to set the minimum to value larger than the current
    /// maximum, the method will panic.
    pub fn set_min(&mut self, min: u128) {
        if min <= self.max() {
            self.min = min
        }
        else {
            panic!("trying to set minimum beyond current maximum");
        }
    }

    /// Sets a new maximum IP address.
    ///
    /// # Panics
    ///
    /// If you try to set the minimum to value smaller than the current
    /// minimum, the method will panic.
    pub fn set_max(&mut self, max: u128) {
        if max > self.min() {
            self.max = max
        }
        else {
            panic!("trying to set maximum below current minimum");
        }
    }
}

impl AddressRange {
    /// Takes an option address range from the beginning of a value.
    fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Option<Self>, S::Err> {
        cons.take_opt_value(|tag, content| {
            if tag == Tag::BIT_STRING {
                Self::parse_address_content(content)
            }
            else if tag == Tag::SEQUENCE {
                Self::parse_range_content(content)
            }
            else {
                xerr!(Err(Error::Malformed.into()))
            }
        })
    }

    /// Skips over the address range at the beginning of a value.
    fn skip_opt_in<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Option<()>, S::Err> {
        Self::take_opt_from(cons).map(|x| x.map(|_| ()))
    }

    /// Parses the content of the IPAddress variant of an address range.
    fn parse_address_content<S: Source>(
        content: &mut Content<S>
    ) -> Result<Self, S::Err> {
        let bs = BitString::parse_content(content)?;
        Ok(AddressRange {
            min: Self::min_from_bits(&bs)?,
            max: Self::max_from_bits(&bs)?,
        })
    }

    /// Parses the content of the IPAddressRange variant of an address range.
    fn parse_range_content<S: Source>(
        content: &mut Content<S>
    ) -> Result<Self, S::Err> {
        let mut cons = content.as_constructed()?;
        Ok(AddressRange {
            min: Self::min_from_bits(&BitString::take_from(&mut cons)?)?,
            max: Self::max_from_bits(&BitString::take_from(&mut cons)?)?,
        })
    }

    /// Calculates the minumum IP address from a bit string.
    fn min_from_bits(bs: &BitString) -> Result<u128, Error> {
        if bs.octet_len() == 0 {
            return Ok(0)
        }
        let (addr, mask) = Self::from_bits(bs)?;
        let addr = addr & !mask; // clear unused bits even if the should be
        Ok(addr << ((16 - bs.octet_len()) * 8))
    }

    /// Calculates the maximum IP address from a bit string.
    fn max_from_bits(bs: &BitString) -> Result<u128, Error> {
        if bs.octet_len() == 0 {
            return Ok(!0)
        }
        let (addr, mask) = Self::from_bits(bs)?;
        let mut addr = addr | mask; // set unused bits.
        for _ in bs.octet_len()..16 {
            addr = addr << 8 | 0xFF
        }
        Ok(addr)
    }

    /// Calculates the minumum and maximum IP addresses from a bit string.
    fn from_bits(bs: &BitString) -> Result<(u128, u128), Error> {
        if bs.octet_len() > 16 {
            xerr!(return Err(Error::Malformed.into()))
        }
        let mut addr = 0;
        for octet in bs.octets() {
            addr = (addr << 8) | (octet as u128)
        }

        let mut mask = 0;
        for _ in 0..bs.unused() {
            mask = mask << 1 | 0x01;
        }
        Ok((addr, mask))
    }
}


//------------ AddressFamily -------------------------------------------------

/// The address family of an IP resources value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressFamily {
    /// IPv4.
    ///
    /// This is encoded by a two byte octet string with value `0x00 0x01`.
    Ipv4,

    /// IPv6.
    ///
    /// This is encoded by a two byte octet string with value `0x00 0x02`.
    Ipv6
}

impl AddressFamily {
    /// Takes a single address family from the beginning of a value.
    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        let str = OctetString::take_from(cons)?;
        let mut octets = str.octets();
        let first = match octets.next() {
            Some(first) => first,
            None => xerr!(return Err(Error::Malformed.into()))
        };
        let second = match octets.next() {
            Some(second) => second,
            None => xerr!(return Err(Error::Malformed.into()))
        };
        if let Some(_) = octets.next() {
            xerr!(return Err(Error::Malformed.into()))
        }
        match (first, second) {
            (0, 1) => Ok(AddressFamily::Ipv4),
            (0, 2) => Ok(AddressFamily::Ipv6),
            _ => xerr!(Err(Error::Malformed.into())),
        }
    }
}

