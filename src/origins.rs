
use std::collections::HashSet;
use std::net::IpAddr;
use rpki::asres::AsId;
use rpki::roa::{FriendlyRoaIpAddress, RouteOriginAttestation};


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
    pub fn from_route_origins(origins: RouteOrigins, unique: bool) -> Self {
        if unique {
            let mut res = HashSet::new();
            for roa in origins.drain() {
                for addr in roa.iter() {
                    res.insert(AddressOrigin::new(roa.as_id(), addr));
                }
            }
            AddressOrigins::Unique(res)
        }
        else {
            let mut res = Vec::new();
            for roa in origins.drain() {
                for addr in roa.iter() {
                    res.push(AddressOrigin::new(roa.as_id(), addr));
                }
            }
            AddressOrigins::Regular(res)
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
    addr: FriendlyRoaIpAddress,
}

impl AddressOrigin {
    fn new(as_id: AsId, addr: FriendlyRoaIpAddress) -> Self {
        AddressOrigin { as_id, addr }
    }

    pub fn as_id(&self) -> AsId {
        self.as_id
    }

    pub fn address(&self) -> IpAddr {
        self.addr.address()
    }

    pub fn address_length(&self) ->u8 {
        self.addr.address_length()
    }

    pub fn max_length(&self) -> u8 {
        self.addr.max_length()
    }
}

