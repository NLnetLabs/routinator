
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;
use rpki::asres::AsId;
use rpki::roa::{FriendlyRoaIpAddress, RouteOriginAttestation};
use super::slurm::LocalExceptions;


//------------ RouteOrigins --------------------------------------------------

#[derive(Clone, Debug)]
pub struct RouteOrigins {
    origins: Vec<RouteOriginAttestation>
}

impl RouteOrigins {
    pub fn new() -> Self {
        RouteOrigins { origins: Vec::new() }
    }

    pub fn push(&mut self, attestation: RouteOriginAttestation) {
        self.origins.push(attestation)
    }

    pub fn merge(&mut self, mut other: RouteOrigins) {
        self.origins.append(&mut other.origins)
    }

    pub fn len(&self) -> usize {
        self.origins.len()
    }

    pub fn drain(self) -> impl Iterator<Item=RouteOriginAttestation> {
        self.origins.into_iter()
    }

    pub fn iter(&self) -> impl Iterator<Item=&RouteOriginAttestation> {
        self.origins.iter()
    }
}


//------------ AddressOrigins ------------------------------------------------

#[derive(Clone, Debug)]
pub enum AddressOrigins {
    Regular(Vec<AddressOrigin>),
    Unique(HashSet<AddressOrigin>),
}

impl AddressOrigins {
    pub fn from_route_origins(
        origins: RouteOrigins,
        exceptions: &LocalExceptions,
        unique: bool
    ) -> Self {
        let mut res = if unique {
            AddressOrigins::Unique(HashSet::new())
        }
        else {
            AddressOrigins::Regular(Vec::new())
        };
        for roa in origins.drain() {
            for addr in roa.iter() {
                let addr = AddressOrigin::from_roa(roa.as_id(), addr);
                if exceptions.keep_origin(&addr) {
                    res.push(addr)
                }
            }
        }
        for addr in exceptions.assertions() {
            res.push(addr.clone())
        }
        res
    }

    fn push(&mut self, addr: AddressOrigin) {
        match *self {
            AddressOrigins::Regular(ref mut vec) => vec.push(addr),
            AddressOrigins::Unique(ref mut set) => {
                set.insert(addr);
            }
        }
    }

    pub fn iter(&self) -> AddressOriginsIter {
        AddressOriginsIter::new(self)
    }
}


//------------ AddressOriginsIter --------------------------------------------

pub enum AddressOriginsIter<'a> {
    Regular(::std::slice::Iter<'a, AddressOrigin>),
    Unique(::std::collections::hash_set::Iter<'a, AddressOrigin>),
}

impl<'a> AddressOriginsIter<'a> {
    fn new(from: &'a AddressOrigins) -> Self {
        match *from {
            AddressOrigins::Regular(ref inner) => {
                AddressOriginsIter::Regular(inner.iter())
            }
            AddressOrigins::Unique(ref inner) => {
                AddressOriginsIter::Unique(inner.iter())
            }
        }
    }
}

impl<'a> Iterator for AddressOriginsIter<'a> {
    type Item = &'a AddressOrigin;

    fn next(&mut self) -> Option<Self::Item> {
        match *self {
            AddressOriginsIter::Regular(ref mut inner) => inner.next(),
            AddressOriginsIter::Unique(ref mut inner) => inner.next(),
        }
    }
}


//------------ AddressOrigin -------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct AddressOrigin {
    as_id: AsId,
    prefix: AddressPrefix,
    max_length: u8,
}

impl AddressOrigin {
    pub fn new(as_id: AsId, prefix: AddressPrefix, max_length: u8) -> Self {
        AddressOrigin { as_id, prefix, max_length }
    }

    fn from_roa(as_id: AsId, addr: FriendlyRoaIpAddress) -> Self {
        AddressOrigin {
            as_id,
            prefix: AddressPrefix::from(&addr),
            max_length: addr.max_length()
        }
    }

    pub fn as_id(&self) -> AsId {
        self.as_id
    }

    pub fn prefix(&self) -> AddressPrefix {
        self.prefix
    }

    pub fn address(&self) -> IpAddr {
        self.prefix.address()
    }

    pub fn address_length(&self) ->u8 {
        self.prefix.address_length()
    }

    pub fn max_length(&self) -> u8 {
        self.max_length
    }
}


//------------ AddressPrefix -------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AddressPrefix {
    addr: IpAddr,
    len: u8,
}

impl AddressPrefix {
    pub fn new(addr: IpAddr, len: u8) -> Self {
        AddressPrefix{addr, len}
    }

    pub fn address(self) -> IpAddr {
        self.addr
    }

    pub fn address_length(self) -> u8 {
        self.len
    }

    pub fn covers(self, other: Self) -> bool {
        // XXX TEST THIS!!!11eleven
        match (self.addr, other.addr) {
            (IpAddr::V4(left), IpAddr::V4(right)) => {
                if self.len > other.len {
                    return false
                }
                let left = u32::from(left) & !(::std::u32::MAX >> self.len);
                let right = u32::from(right) & !(::std::u32::MAX >> self.len);
                left == right
            }
            (IpAddr::V6(left), IpAddr::V6(right)) => {
                if self.len > other.len {
                    return false
                }
                let left = u128::from(left) & !(::std::u128::MAX >> self.len);
                let right = u128::from(right) & !(::std::u128::MAX >> self.len);
                left == right
            }
            _ => false
        }
    }
}

impl<'a> From<&'a FriendlyRoaIpAddress> for AddressPrefix {
    fn from(addr: &'a FriendlyRoaIpAddress) -> Self {
        AddressPrefix {
            addr: addr.address(),
            len: addr.address_length(),
        }
    }
}

impl FromStr for AddressPrefix {
    type Err = FromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut iter = s.splitn(2, '/');
        let addr = iter.next().ok_or_else(|| FromStrError(s.into()))?;
        let len = iter.next().ok_or_else(|| FromStrError(s.into()))?;
        let addr = IpAddr::from_str(addr)
                          .map_err(|_| FromStrError(s.into()))?;
        let len = u8::from_str(len)
                     .map_err(|_| FromStrError(s.into()))?;
        Ok(AddressPrefix { addr, len })
    }
}


//------------ FromStrError --------------------------------------------------

#[derive(Clone, Debug, Fail)]
#[fail(display="bad prefix {}", _0)]
pub struct FromStrError(String);


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
pub mod tests {

    use super::*;

    fn make_pfx(s: &str, l: u8) -> AddressPrefix {
        AddressPrefix::new(s.parse().unwrap(), l)
    }

    #[test]
    fn should_find_covered_prefixes() {
        let outer = make_pfx("10.0.0.0", 16);
        let sibling = make_pfx("10.1.0.0", 16);
        let inner_low = make_pfx("10.0.0.0", 24);
        let inner_mid = make_pfx("10.0.61.0", 24);
        let inner_hi = make_pfx("10.0.255.0", 24);

        assert!(! outer.covers(sibling));
        assert!(outer.covers(inner_low));
        assert!(outer.covers(inner_mid));
        assert!(outer.covers(inner_hi));
    }




}