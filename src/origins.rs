
use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
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
pub struct AddressOrigins {
    origins: HashSet<AddressOrigin>,
}

impl AddressOrigins {
    pub fn new() -> Self {
        AddressOrigins {
            origins: HashSet::new()
        }
    }

    pub fn from_route_origins(
        origins: RouteOrigins,
        exceptions: &LocalExceptions,
    ) -> Self {
        let mut res = Self::new();
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
        let _ = self.origins.insert(addr);
    }

    pub fn iter(&self) -> impl Iterator<Item=&AddressOrigin> {
        self.origins.iter()
    }
}


//------------ OriginsDiff ---------------------------------------------------

#[derive(Clone, Debug)]
pub struct OriginsDiff {
    serial: u32,
    // We are using `HashSet`s here for easy unique-ing.
    announce: HashSet<AddressOrigin>,
    withdraw: HashSet<AddressOrigin>,
}

impl OriginsDiff {
    pub fn construct(
        mut current: AddressOrigins,
        origins: Option<RouteOrigins>,
        exceptions: &LocalExceptions,
        serial: u32
    ) -> (AddressOrigins, Self) {
        let mut next = AddressOrigins::new();
        let mut announce = HashSet::new();

        if let Some(origins) = origins {
            for roa in origins.drain() {
                for addr in roa.iter() {
                    let addr = AddressOrigin::from_roa(roa.as_id(), addr);
                    if !exceptions.keep_origin(&addr) {
                        continue
                    }

                    if !current.origins.remove(&addr) {
                        let _ = announce.insert(addr.clone());
                    }
                    next.push(addr)
                }
            }
        }
        for addr in exceptions.assertions() {
            // Exceptions could have changed, so let’s be thorough here.
            if !current.origins.remove(&addr) {
                let _ = announce.insert(addr.clone());
            }
            next.push(addr.clone())
        }
        let withdraw = current.origins.drain().collect();
        (next, OriginsDiff { serial, announce, withdraw })
    }

    pub fn serial(&self) -> u32 {
        self.serial
    }

    pub fn announce(&self) -> impl Iterator<Item=&AddressOrigin> {
        self.announce.iter()
    }

    pub fn withdraw(&self) -> impl Iterator<Item=&AddressOrigin> {
        self.withdraw.iter()
    }
}


//------------ OriginsHistory ------------------------------------------------

#[derive(Clone, Debug)]
pub struct OriginsHistory {
    current: AddressOrigins,
    diffs: VecDeque<OriginsDiff>,
    keep: usize,
}

impl OriginsHistory {
    pub fn new(current: AddressOrigins, keep: usize) -> Self {
        OriginsHistory {
            current,
            diffs: VecDeque::with_capacity(keep),
            keep
        }
    }

    pub fn push_diff(&mut self, diff: OriginsDiff) {
        if self.diffs.len() == self.keep {
            let _ = self.diffs.pop_back();
        }
        self.diffs.push_front(diff)
    }

    pub fn iter_diffs(&self) -> impl Iterator<Item=&OriginsDiff> {
        self.diffs.iter()
    }

    pub fn current(&self) -> &AddressOrigins {
        &self.current
    }

    pub fn serial(&self) -> u32 {
        match self.diffs.front() {
            Some(diff) => diff.serial(),
            None => 0
        }
    }

    pub fn update(
        history: Arc<RwLock<Self>>,
        origins: Option<RouteOrigins>,
        exceptions: &LocalExceptions
    ) {
        let (serial, current) = {
            let history = history.read().unwrap();
            let serial = history.serial().wrapping_add(1);
            let current = history.current.clone();
            (serial, current)
        };
        let (next, diff) = OriginsDiff::construct(
            current, origins, exceptions, serial
        );
        let mut history = history.write().unwrap();
        history.current = next;
        history.push_diff(diff);
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
