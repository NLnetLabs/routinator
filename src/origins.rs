/// Route origins.
///
/// The types in this module store route origins, sets of route origins, and
/// the history of changes necessary for RTR.

use std::{hash, ops, slice, vec};
use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use rpki::asres::AsId;
use rpki::cert::ResourceCert;
use rpki::roa::{FriendlyRoaIpAddress, RouteOriginAttestation};
use rpki::tal::TalInfo;
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


//--- IntoIterator

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
/// we can iterate over the set using indexes instead of references, avoiding
/// self-referential types in futures.
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
        extra_info: bool,
    ) -> Self {
        let mut res = HashSet::new();
        for mut roa in origins {
            let info = OriginInfo::from_roa(&mut roa, extra_info);
            for addr in roa.iter() {
                let addr = AddressOrigin::from_roa(
                    roa.as_id(),
                    addr,
                    info.clone()
                );
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

/// The difference between two address origin lists.
///
/// A value of this types keeps two lists. One lists, _announce_ contains the
/// address origins added in this diff, the second, _withdraw_ those that
/// were removed. In addition, the `serial` field holds a serial number for
/// this diff.
///
/// You can create a diff via the `construct` method from a set of address
/// origins, route origins, and exceptions.
#[derive(Clone, Debug)]
pub struct OriginsDiff {
    /// The serial number of this diff.
    ///
    /// Serial numbers start from zero and are guaranteed to be incremented
    /// by one between versions of address origin sets.
    serial: u32,

    /// The address origins added by this diff.
    announce: Vec<AddressOrigin>,

    /// The address origins removed by this diff.
    withdraw: Vec<AddressOrigin>,
}

impl OriginsDiff {
    /// Creates an empty origins diff with the given serial number.
    ///
    /// Both the announce and withdraw lists will be empty.
    pub fn empty(serial: u32) -> Self {
        OriginsDiff {
            serial,
            announce: Vec::new(),
            withdraw: Vec::new()
        }
    }

    /// Returns whether this is an empty diff.
    ///
    /// A diff is empty if both the accounce and withdraw lists are empty.
    pub fn is_empty(&self) -> bool {
        self.announce.is_empty() && self.withdraw.is_empty()
    }

    /// Constructs a diff.
    ///
    /// The method takes the previous list of address origins as a set (so
    /// that there are definitely no duplicates), a list of route origins
    /// gained from validation, a list of local exceptions, and the serial
    /// number of the current version.
    ///
    /// It will create and return the new list of address origins from the
    /// route origins and a origins diff between the new and old address
    /// origins with the serial number of `serial` plus one.
    pub fn construct(
        mut current: HashSet<AddressOrigin>,
        origins: Option<RouteOrigins>,
        exceptions: &LocalExceptions,
        serial: u32,
        extra_info: bool,
    ) -> (AddressOrigins, Self) {
        let mut next = HashSet::new();
        let mut announce = HashSet::new();

        if let Some(origins) = origins {
            for mut roa in origins {
                let info = OriginInfo::from_roa(&mut roa, extra_info);
                for addr in roa.iter() {
                    let addr = AddressOrigin::from_roa(
                        roa.as_id(), addr, info.clone()
                    );
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
        info!(
            "Diff with {} announced and {} withdrawn.",
            announce.len(), withdraw.len()
        );
        (next.into(), OriginsDiff { serial, announce, withdraw })
    }

    /// Returns the serial number of this origins diff.
    pub fn serial(&self) -> u32 {
        self.serial
    }

    /// Returns a slice with the address origins added by this diff.
    pub fn announce(&self) -> &[AddressOrigin] {
        self.announce.as_ref()
    }

    /// Returns a slice with the address origins removed by this diff.
    pub fn withdraw(&self) -> &[AddressOrigin] {
        self.withdraw.as_ref()
    }

    /// Unwraps the diff into the serial number, announce and withdraw lists.
    pub fn unwrap(
        self
    ) -> (u32, Vec<AddressOrigin>, Vec<AddressOrigin>) {
        (self.serial, self.announce, self.withdraw)
    }
}


//------------ DiffMerger ----------------------------------------------------

/// A helper struct that allows merging two diffs into a combined diff.
///
/// This works like a builder type. You create a merged from the oldest diff
/// via the `new` method, add additional diffs via `merge`, and finally
/// convert the merger into a regular diff via `into_diff`.
#[derive(Clone, Debug)]
struct DiffMerger {
    /// The serial number of the combined diff.
    serial: u32,

    /// The set of added address origins.
    announce: HashSet<AddressOrigin>,

    /// The set of removed address origins.
    withdraw: HashSet<AddressOrigin>,
}

impl DiffMerger {
    /// Creates a diff merged based on the
    fn new(diff: &OriginsDiff) -> Self {
        DiffMerger {
            serial: diff.serial,
            announce: diff.announce.iter().map(Clone::clone).collect(),
            withdraw: diff.withdraw.iter().map(Clone::clone).collect(),
        }
    }

    /// Merges a diff.
    ///
    /// After, the serial number will be that of `diff`. Address origins that
    /// are in `diff`’s announce list are added to the merger’s announce set
    /// unless they are in the merger’s withdraw set, in which case they are
    /// removed from the merger’s withdraw set. Origins in `diff`’s withdraw
    /// set are removed from the merger’s announce set if they are in it or
    /// added to the merger’s withdraw set otherwise.
    ///
    /// (This looks much simpler in code than in prose …)
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

    /// Converts the merger into an origin diff with the same content.
    fn into_diff(self) -> Arc<OriginsDiff> {
        Arc::new(OriginsDiff {
            serial: self.serial,
            announce: self.announce.into_iter().collect(),
            withdraw: self.withdraw.into_iter().collect(),
        })
    }
}


//------------ OriginsHistory ------------------------------------------------

/// A shareable history of address orgins.
///
/// A value of this type allows access to the currently valid list of address
/// origins and a list of diffs from earlier versions. The latter list is
/// limited to a certain length. Older diffs are dropped.
///
/// These things are all hidden away behind an arc and a lock so you can copy
/// and share values relatively cheaply and in a safe way.
#[derive(Clone, Debug)]
pub struct OriginsHistory(Arc<RwLock<HistoryInner>>);

/// The inner, raw data of the origins history.
#[derive(Clone, Debug)]
pub struct HistoryInner {
    /// The current full set of adress origins.
    current: Arc<AddressOrigins>,

    /// A queue with a number of diffs.
    ///
    /// The newest diff will be at the front of the queue.
    diffs: VecDeque<Arc<OriginsDiff>>,

    /// The number of diffs to keep.
    keep: usize,
}

impl OriginsHistory {
    /// Creates a new history from the given initial data.
    ///
    /// The history will start out with `current` as its initial address
    /// origins, an empty diff list, and a maximum length of the diff list
    /// of `keep`.
    pub fn new(current: AddressOrigins, keep: usize) -> Self {
        OriginsHistory(Arc::new(RwLock::new(
            HistoryInner {
                current: Arc::new(current),
                diffs: VecDeque::with_capacity(keep),
                keep
            }
        )))
    }

    /// Returns a reference to the current list of address origins.
    pub fn current(&self) -> Arc<AddressOrigins> {
        self.0.read().unwrap().current.clone()
    }

    /// Returns a diff from the given serial number.
    ///
    /// The serial is what the requestor has last seen. The method produces
    /// a diff from that version to the current version if it can. If it
    /// can’t, either because it doesn’t have enough history data or because
    /// the serial is actually in the future.
    ///
    /// The method current doesn’t correctly treat serial number wrap around.
    /// See [issue #38](https://github.com/NLnetLabs/routinator/issues/38).
    pub fn get(&self, serial: u32) -> Option<Arc<OriginsDiff>> {
        debug!("Fetching diff for serial {}", serial);
        let history = self.0.read().unwrap();
        if let Some(diff) = history.diffs.front() {
            debug!("Our current serial is {}", diff.serial);
            if diff.serial() < serial {
                // If they give us a future serial, we reset.
                debug!("Future, forcing reset.");
                return None
            }
            else if diff.serial() == serial {
                debug!("Same, producing empty diff.");
                return Some(Arc::new(OriginsDiff::empty(serial)))
            }
            else if diff.serial() == serial + 1 {
                // This relies on serials increasing by one always.
                debug!("One behind, just clone.");
                return Some(diff.clone())
            }
        }
        else {
            debug!("We are at serial 0.");
            if serial == 0 {
                debug!("Same, returning empty diff.");
                return Some(Arc::new(OriginsDiff::empty(serial)))
            }
            else {
                // That pesky future serial again.
                debug!("Future, forcing reset.");
                return None
            }
        }
        debug!("Merging diffs.");
        let mut iter = history.diffs.iter().rev();
        while let Some(diff) = iter.next() {
            if serial < diff.serial() {
                return None
            }
            else if diff.serial() == serial {
                break
            }
        }
        // We already know that the serial’s diff wasn’t last, so unwrap is
        // fine.
        let mut res = DiffMerger::new(iter.next().unwrap().as_ref());
        for diff in iter {
            res.merge(diff.as_ref())
        }
        Some(res.into_diff())
    }

    /// Returns the serial number of the current version of the origin list.
    pub fn serial(&self) -> u32 {
        self.0.read().unwrap().serial()
    }

    /// Returns the current list of address origins and its serial number.
    pub fn current_and_serial(&self) -> (Arc<AddressOrigins>, u32) {
        let history = self.0.read().unwrap();
        (history.current.clone(), history.serial())
    }

    /// Updates the history.
    ///
    /// Produces a new list of address origins based on the route origins
    /// and local exceptions. If this list differs from the current list
    /// of address origins, adds a new version to the history.
    ///
    /// The method returns whether it added a new version.
    ///
    /// Note also that the method has to acquire the write lock on the
    /// history.
    pub fn update(
        &self,
        origins: Option<RouteOrigins>,
        exceptions: &LocalExceptions,
        extra_info: bool,
    ) -> bool {
        let (serial, current) = {
            let history = self.0.read().unwrap();
            let serial = history.serial().wrapping_add(1);
            let current = history.current.clone();
            (serial, current)
        };
        let current: HashSet<_> = current.iter().map(Clone::clone).collect();
        let (next, diff) = OriginsDiff::construct(
            current, origins, exceptions, serial, extra_info
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
    /// Returns the current serial.
    ///
    /// This is either the serial of the first diff or 0 if there are no
    /// diffs.
    pub fn serial(&self) -> u32 {
        match self.diffs.front() {
            Some(diff) => diff.serial(),
            None => 0
        }
    }

    /// Appends a new diff dropping old ones if necessary.
    pub fn push_diff(&mut self, diff: OriginsDiff) {
        if self.diffs.len() == self.keep {
            let _ = self.diffs.pop_back();
        }
        self.diffs.push_front(Arc::new(diff))
    }
}


//------------ AddressOrigin -------------------------------------------------

/// A validated address orgin.
///
/// This is what RFC 6811 calls a ‘Validated ROA Payload.’ It consists of an
/// IP address prefix, a maximum length, and the origin AS number. In
/// addition, the address origin stores information about the trust anchor
/// this origin was derived from.
#[derive(Clone, Debug)]
pub struct AddressOrigin {
    /// The origin AS number.
    as_id: AsId,

    /// The IP address prefix.
    prefix: AddressPrefix,

    /// The maximum authorized prefix length of a route.
    max_length: u8,

    /// Extra origin information.
    info: OriginInfo,
}

impl AddressOrigin {
    /// Creates a new address origin without trust anchor information.
    pub fn new(
        as_id: AsId,
        prefix: AddressPrefix,
        max_length: u8,
        info: OriginInfo,
    ) -> Self {
        AddressOrigin { as_id, prefix, max_length, info: info }
    }

    /// Creates a new address origin from ROA content.
    fn from_roa(
        as_id: AsId,
        addr: FriendlyRoaIpAddress,
        info: OriginInfo
    ) -> Self {
        AddressOrigin {
            as_id,
            prefix: AddressPrefix::from(&addr),
            max_length: addr.max_length(),
            info
        }
    }

    /// Returns the origin AS number.
    pub fn as_id(&self) -> AsId {
        self.as_id
    }

    /// Returns the IP address prefix.
    pub fn prefix(&self) -> AddressPrefix {
        self.prefix
    }

    /// Returns the address part of the IP address prefix.
    pub fn address(&self) -> IpAddr {
        self.prefix.address()
    }

    /// Returns the length part of the IP address prefix.
    pub fn address_length(&self) ->u8 {
        self.prefix.address_length()
    }

    /// Returns the maximum authorized route prefix length.
    pub fn max_length(&self) -> u8 {
        self.max_length
    }

    /// Returns a reference to the resource certificate if available.
    pub fn cert(&self) -> Option<&ResourceCert> {
        self.info.cert()
    }

    /// Returns the name of the TAL that this origin as based on.
    ///
    /// If there isn’t one, the name becomes `"N/A"`
    pub fn tal_name(&self) -> &str {
        self.info.tal_name()
    }
}


//--- PartialEq and Eq

impl PartialEq for AddressOrigin {
    fn eq(&self, other: &Self) -> bool {
        self.as_id == other.as_id
        && self.prefix == other.prefix 
        && self.max_length == other.max_length
    }
}

impl Eq for AddressOrigin { }


//--- Hash

impl hash::Hash for AddressOrigin {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.as_id.hash(state);
        self.prefix.hash(state);
        self.max_length.hash(state);
    }
}


//------------ AddressPrefix -------------------------------------------------

/// An IP address prefix: an IP address and a prefix length.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AddressPrefix {
    addr: IpAddr,
    len: u8,
}

impl AddressPrefix {
    /// Creates a new prefix from an address and a length.
    pub fn new(addr: IpAddr, len: u8) -> Self {
        AddressPrefix{addr, len}
    }

    /// Returns the IP address part of a prefix.
    pub fn address(self) -> IpAddr {
        self.addr
    }

    /// Returns the length part of a prefix.
    pub fn address_length(self) -> u8 {
        self.len
    }

    /// Returns whether `self` covers `other`.
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


//------------ OriginInfo ----------------------------------------------------

/// Extended information about an origin.
#[derive(Clone, Debug)]
pub enum OriginInfo {
    /// No information.
    None,

    /// The resource certificate of a ROA.
    RoaCert(Arc<ResourceCert>),

    /// The trust anchor info of a ROA.
    RoaTal(Arc<TalInfo>),

    /// The path of a local exceptions file.
    Exception(Arc<PathBuf>),
}

impl OriginInfo {
    fn from_roa(roa: &mut RouteOriginAttestation, extra_info: bool) -> Self {
        if let Some(cert) = roa.take_cert() {
            if extra_info {
                OriginInfo::RoaCert(Arc::new(cert))
            }
            else {
                OriginInfo::RoaTal(cert.into_tal())
            }
        }
        else {
            OriginInfo::None
        }
    }

    fn cert(&self) -> Option<&ResourceCert> {
        match *self {
            OriginInfo::RoaCert(ref cert) => Some(cert),
            _ => None
        }
    }

    fn tal_name(&self) -> &str {
        match *self {
            OriginInfo::RoaCert(ref cert) => cert.tal().name(),
            OriginInfo::RoaTal(ref tal) => tal.name(),
            _ => "N/A"
        }
    }
}


//------------ FromStrError --------------------------------------------------

/// Creating an IP address prefix from a string has failed.
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

        assert!(!outer.covers(sibling));
        assert!(outer.covers(inner_low));
        assert!(outer.covers(inner_mid));
        assert!(outer.covers(inner_hi));
    }
}

