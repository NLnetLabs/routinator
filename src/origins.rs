/// Route origins.
///
/// The types in this module store route origins, sets of route origins, and
/// the history of changes necessary for RTR.

use std::{ops, slice, vec};
use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use rpki::asres::AsId;
use rpki::roa::{FriendlyRoaIpAddress, RouteOriginAttestation};
use super::slurm::LocalExceptions;


//------------ RouteOrigins --------------------------------------------------

/// The raw list of route origin attestations from RPKI.
///
/// This type is used to collect all the valid route origins as they fall out
/// of RPKI repository validation. It is an intermediary type used as input
/// for generating the real origins kept in [`AddressOrigins`].
///
/// [`AddressOrigins`]: struct.AddressOrigins.html
#[derive(Clone, Debug)]
pub struct RouteOrigins {
    /// The list of route origin attestations.
    origins: Vec<RouteOriginAttestation>
}

impl RouteOrigins {
    /// Creates a new, empty list of route origins.
    pub fn new() -> Self {
        RouteOrigins { origins: Vec::new() }
    }

    /// Appends the given attestation to the set.
    ///
    /// The attestation will simply be added to the end of the list. No
    /// checking for duplicates is being done.
    pub fn push(&mut self, attestation: RouteOriginAttestation) {
        self.origins.push(attestation)
    }

    /// Merges another list of route origins into this one.
    ///
    /// Despite the name, this method doesn’t do any duplicate checking,
    /// either.
    pub fn merge(&mut self, mut other: RouteOrigins) {
        self.origins.append(&mut other.origins)
    }

    /// Returns the number of attestations in the list.
    pub fn len(&self) -> usize {
        self.origins.len()
    }

    /// Returns an iterator over the attestations in the list.
    pub fn iter(&self) -> slice::Iter<RouteOriginAttestation> {
        self.origins.iter()
    }
}

impl IntoIterator for RouteOrigins {
    type Item = RouteOriginAttestation;
    type IntoIter = vec::IntoIter<RouteOriginAttestation>;

    fn into_iter(self) -> Self::IntoIter {
        self.origins.into_iter()
    }
}

impl<'a> IntoIterator for &'a RouteOrigins {
    type Item = &'a RouteOriginAttestation;
    type IntoIter = slice::Iter<'a, RouteOriginAttestation>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}


//------------ AddressOrigins ------------------------------------------------

/// A set of address origin statements.
///
/// This type contains a list of [`AddressOrigin`] statements. While it is
/// indeed a set, that is, it doesn’t contain duplicates, it is accessible
/// like a slice of address origins, to which it even derefs. This is so that
/// we can iterate over the set using indexes instead of references.
///
/// [`AddressOrigin`]: struct.AddressOrigin.html
#[derive(Clone, Debug)]
pub struct AddressOrigins {
    /// A list of (unique) address origins.
    origins: Vec<AddressOrigin>,
}

impl AddressOrigins {
    /// Creates a new, empty set of address origins.
    pub fn new() -> Self {
        AddressOrigins {
            origins: Vec::new()
        }
    }

    /// Creates a set from the raw route origins and exceptions.
    ///
    /// The function will take all the address origins in `origins`, drop
    /// duplicates, drop the origins filtered in `execptions` and add the
    /// assertions from `exceptions`.
    pub fn from_route_origins(
        origins: RouteOrigins,
        exceptions: &LocalExceptions,
    ) -> Self {
        let mut res = HashSet::new();
        for roa in origins {
            for addr in roa.iter() {
                let addr = AddressOrigin::from_roa(roa.as_id(), addr);
                if exceptions.keep_origin(&addr) {
                    let _ = res.insert(addr);
                }
            }
        }
        for addr in exceptions.assertions() {
            let _ = res.insert(addr.clone());
        }
        AddressOrigins {
            origins: res.into_iter().collect()
        }
    }

    /// Returns an iterator over the address orgins.
    pub fn iter(&self) -> slice::Iter<AddressOrigin> {
        self.origins.iter()
    }
}


//--- From

impl From<HashSet<AddressOrigin>> for AddressOrigins {
    fn from(set: HashSet<AddressOrigin>) -> Self {
        AddressOrigins {
            origins: set.into_iter().collect()
        }
    }
}


//--- Deref and AsRef

impl ops::Deref for AddressOrigins {
    type Target = [AddressOrigin];

    fn deref(&self) -> &Self::Target {
        self.origins.as_ref()
    }
}

impl AsRef<[AddressOrigin]> for AddressOrigins {
    fn as_ref(&self) -> &[AddressOrigin] {
        self.origins.as_ref()
    }
}


//------------ OriginsDiff ---------------------------------------------------

#[derive(Clone, Debug)]
pub struct OriginsDiff {
    serial: u32,
    announce: Vec<AddressOrigin>,
    withdraw: Vec<AddressOrigin>,
}

impl OriginsDiff {
    pub fn empty(serial: u32) -> Self {
        OriginsDiff {
            serial,
            announce: Vec::new(),
            withdraw: Vec::new()
        }
    }

    pub fn is_empty(&self) -> bool {
        self.announce.is_empty() && self.withdraw.is_empty()
    }

    pub fn construct(
        mut current: HashSet<AddressOrigin>,
        origins: Option<RouteOrigins>,
        exceptions: &LocalExceptions,
        serial: u32
    ) -> (AddressOrigins, Self) {
        let mut next = HashSet::new();
        let mut announce = HashSet::new();

        if let Some(origins) = origins {
            for roa in origins {
                for addr in roa.iter() {
                    let addr = AddressOrigin::from_roa(roa.as_id(), addr);
                    if !exceptions.keep_origin(&addr) {
                        continue
                    }
                    if next.insert(addr.clone()) {
                        if !current.remove(&addr) {
                            let _ = announce.insert(addr);
                        }
                    }
                }
            }
        }
        for addr in exceptions.assertions() {
            // Exceptions could have changed, so let’s be thorough here.
            if next.insert(addr.clone()) {
                if !current.remove(addr) {
                    announce.insert(addr.clone());
                }
            }
        }
        let withdraw: Vec<_> = current.into_iter().collect();
        let announce: Vec<_> = announce.into_iter().collect();
        debug!(
            "Diff with {} announced and {} withdrawn.",
            announce.len(), withdraw.len()
        );
        (next.into(), OriginsDiff { serial, announce, withdraw })
    }

    pub fn serial(&self) -> u32 {
        self.serial
    }

    pub fn announce(&self) -> &[AddressOrigin] {
        self.announce.as_ref()
    }

    pub fn withdraw(&self) -> &[AddressOrigin] {
        self.withdraw.as_ref()
    }

    pub fn unwrap(
        self
    ) -> (u32, Vec<AddressOrigin>, Vec<AddressOrigin>) {
        (self.serial, self.announce, self.withdraw)
    }
}


//------------ DiffMerger ----------------------------------------------------

#[derive(Clone, Debug)]
struct DiffMerger {
    serial: u32,
    announce: HashSet<AddressOrigin>,
    withdraw: HashSet<AddressOrigin>,
}

impl DiffMerger {
    fn new(diff: &OriginsDiff) -> Self {
        DiffMerger {
            serial: diff.serial,
            announce: diff.announce.iter().map(Clone::clone).collect(),
            withdraw: diff.withdraw.iter().map(Clone::clone).collect(),
        }
    }

    fn merge(&mut self, diff: &OriginsDiff) {
        self.serial = diff.serial;
        for origin in &diff.announce {
            if !self.withdraw.remove(origin) {
                self.announce.insert(origin.clone());
            }
        }
        for origin in &diff.withdraw {
            if !self.announce.remove(origin) {
                self.withdraw.insert(origin.clone());
            }
        }
    }

    fn into_diff(self) -> Arc<OriginsDiff> {
        Arc::new(OriginsDiff {
            serial: self.serial,
            announce: self.announce.into_iter().collect(),
            withdraw: self.withdraw.into_iter().collect(),
        })
    }
}


//------------ OriginsHistory ------------------------------------------------

#[derive(Clone, Debug)]
pub struct OriginsHistory(Arc<RwLock<HistoryInner>>);

#[derive(Clone, Debug)]
pub struct HistoryInner {
    current: Arc<AddressOrigins>,
    diffs: VecDeque<Arc<OriginsDiff>>,
    keep: usize,
}

impl OriginsHistory {
    pub fn new(current: AddressOrigins, keep: usize) -> Self {
        OriginsHistory(Arc::new(RwLock::new(
            HistoryInner {
                current: Arc::new(current),
                diffs: VecDeque::with_capacity(keep),
                keep
            }
        )))
    }

    pub fn current(&self) -> Arc<AddressOrigins> {
        self.0.read().unwrap().current.clone()
    }

    pub fn get(&self, serial: u32) -> Option<Arc<OriginsDiff>> {
        let history = self.0.read().unwrap();
        if let Some(diff) = history.diffs.back() {
            if diff.serial() < serial {
                // If they give us a future serial, we reset.
                return None
            }
            else if diff.serial() == serial {
                return Some(Arc::new(OriginsDiff::empty(serial)))
            }
            else if diff.serial() == serial + 1 {
                // This relies on serials increasing by one always.
                return Some(diff.clone())
            }
        }
        else {
            if serial == 0 {
                return Some(Arc::new(OriginsDiff::empty(serial)))
            }
            else {
                // That pesky future serial again.
                return None
            }
        }
        let mut iter = history.diffs.iter();
        while let Some(diff) = iter.next() {
            if serial < diff.serial() {
                return None
            }
            else if diff.serial() == serial {
                break
            }
        }
        // We already know that the serial’s diff was’t last, so unwrap is
        // fine.
        let mut res = DiffMerger::new(iter.next().unwrap().as_ref());
        for diff in iter {
            res.merge(diff.as_ref())
        }
        Some(res.into_diff())
    }

    pub fn serial(&self) -> u32 {
        self.0.read().unwrap().serial()
    }

    pub fn current_and_serial(&self) -> (Arc<AddressOrigins>, u32) {
        let history = self.0.read().unwrap();
        (history.current.clone(), history.serial())
    }

    pub fn update(
        &self,
        origins: Option<RouteOrigins>,
        exceptions: &LocalExceptions
    ) -> bool {
        let (serial, current) = {
            let history = self.0.read().unwrap();
            let serial = history.serial().wrapping_add(1);
            let current = history.current.clone();
            (serial, current)
        };
        let current: HashSet<_> = current.iter().map(Clone::clone).collect();
        let (next, diff) = OriginsDiff::construct(
            current, origins, exceptions, serial
        );
        if !diff.is_empty() {
            let mut history = self.0.write().unwrap();
            history.current = Arc::new(next);
            history.push_diff(diff);
            true
        }
        else {
            false
        }
    }

}

impl HistoryInner {
    pub fn serial(&self) -> u32 {
        match self.diffs.front() {
            Some(diff) => diff.serial(),
            None => 0
        }
    }

    pub fn push_diff(&mut self, diff: OriginsDiff) {
        if self.diffs.len() == self.keep {
            let _ = self.diffs.pop_back();
        }
        self.diffs.push_front(Arc::new(diff))
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
