/// Route origins.
///
/// The types in this module store route origins, sets of route origins, and
/// the history of changes necessary for RTR.

use std::{cmp, error, fmt, hash, ops, slice, vec};
use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime};
use log::{debug, info};
use rpki::uri;
use rpki::cert::{ResourceCert, TbsCert};
use rpki::resources::AsId;
use rpki::roa::{FriendlyRoaIpAddress, RouteOriginAttestation};
use rpki::tal::TalInfo;
use rpki::x509::{Time, Validity};
use rpki_rtr::payload::{Action, Ipv4Prefix, Ipv6Prefix, Payload, Timing};
use rpki_rtr::server::VrpSource;
use rpki_rtr::state::{Serial, State};
use serde::{Deserialize, Deserializer};
use crate::config::Config;
use crate::metrics::{Metrics, ServerMetrics, TalMetrics};
use crate::slurm::{ExceptionInfo, LocalExceptions};


//------------ OriginsReport -------------------------------------------------

/// The output of a validation run.
#[derive(Debug, Default)]
pub struct OriginsReport {
    origins: Vec<RouteOrigins>,
    tals: Vec<Arc<TalInfo>>,
}

impl OriginsReport {
    pub fn new() -> Self {
        OriginsReport {
            origins: Vec::new(),
            tals: Vec::new(),
        }
    }

    pub fn with_capacity(capacity: usize, tals: Vec<Arc<TalInfo>>) -> Self {
        OriginsReport {
            origins: Vec::with_capacity(capacity),
            tals
        }
    }

    pub fn push_origins(&mut self, origins: RouteOrigins) {
        self.origins.push(origins)
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
///
/// Various things are kept behind an arc in here so we can hand out copies
/// to long-running tasks (like producing the CSV in the HTTP server) without
/// instead of holding the lock.
#[derive(Clone, Debug)]
struct HistoryInner {
    /// The current full set of adress origins.
    current: Option<Arc<AddressOrigins>>,

    /// A queue with a number of diffs.
    ///
    /// The newest diff will be at the front of the queue.
    diffs: VecDeque<Arc<OriginsDiff>>,

    /// The current metrics.
    metrics: Option<Arc<Metrics>>,

    /// The server metrics.
    server_metrics: Arc<ServerMetrics>,

    /// The session ID.
    session: u16,

    /// The number of diffs to keep.
    keep: usize,

    /// The time to wait between updates,
    refresh: Duration,

    /// The instant when we started an update the last time.
    last_update_start: Instant,

    /// The instant we successfully (!) finished an update the last time.
    last_update_done: Option<Instant>,

    /// The duration of the last update run.
    last_update_duration: Option<Duration>,

    /// The instant when we are scheduled to start the next update.
    next_update_start: SystemTime,

    /// Default RTR timing.
    timing: Timing,
}

impl OriginsHistory {
    /// Creates a new history from the given initial data.
    pub fn new(
        config: &Config,
    ) -> Self {
        OriginsHistory(Arc::new(RwLock::new(
            HistoryInner {
                next_update_start: SystemTime::now() + config.refresh,
                current: None,
                diffs: VecDeque::with_capacity(config.history_size),
                metrics: None,
                server_metrics: Arc::new(Default::default()),
                session: {
                    SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH).unwrap()
                        .as_secs() as u16
                },
                keep: config.history_size,
                refresh: config.refresh,
                last_update_start: Instant::now(),
                last_update_done: None,
                last_update_duration: None,
                timing: Timing {
                    refresh: config.refresh.as_secs() as u32,
                    retry: config.retry.as_secs() as u32,
                    expire: config.expire.as_secs() as u32,
                }
            }
        )))
    }

    /// Returns whether the history is active already.
    pub fn is_active(&self) -> bool {
        self.0.read().unwrap().current.is_some()
    }

    /// Returns a reference to the current list of address origins.
    pub fn current(&self) -> Option<Arc<AddressOrigins>> {
        self.0.read().unwrap().current.clone()
    }

    /// Returns the duration until the next refresh should start.
    pub fn refresh_wait(&self) -> Duration {
        self.0.read().unwrap().next_update_start
        .duration_since(SystemTime::now())
        .unwrap_or_else(|_| Duration::from_secs(0))
    }

    /// Returns the duration until a new set of data is available.
    pub fn update_wait(&self) -> Duration {
        let (start, duration, refresh) = {
            let l = self.0.read().unwrap();
            (l.next_update_start, l.last_update_duration, l.refresh)
        };
        let start = match duration {
            Some(duration) => start + duration + duration,
            None => start + refresh,
        };
        start.duration_since(SystemTime::now()).unwrap_or_else(|_| refresh)
    }

    /// Returns a diff from the given serial number.
    ///
    /// The serial is what the requestor has last seen. The method produces
    /// a diff from that version to the current version if it can. If it
    /// can’t, either because it doesn’t have enough history data or because
    /// the serial is actually in the future.
    pub fn get(&self, serial: Serial) -> Option<Arc<OriginsDiff>> {
        self.0.read().unwrap().get(serial)
    }

    /// Returns the serial number of the current version of the origin list.
    pub fn serial(&self) -> Serial {
        self.0.read().unwrap().serial()
    }

    /// Returns the current list of address origins and its serial number.
    pub fn current_and_serial(&self) -> Option<(Arc<AddressOrigins>, Serial)> {
        let history = self.0.read().unwrap();
        history.current.clone().map(|current| {
            (current, history.serial())
        })
    }
    
    pub fn current_and_metrics(
        &self
    ) -> Option<(Arc<AddressOrigins>, Arc<Metrics>)> {
        let history = self.0.read().unwrap();
        let current = history.current.clone()?;
        let metrics = history.metrics.clone()?;
        Some((current, metrics))
    }

    pub fn metrics(&self) -> Option<Arc<Metrics>> {
        self.0.read().unwrap().metrics.clone()
    }

    pub fn server_metrics(&self) -> Arc<ServerMetrics> {
        self.0.read().unwrap().server_metrics.clone()
    }

    pub fn update_times(
        &self
    ) -> (Instant, Option<Instant>, Option<Duration>) {
        let locked = self.0.read().unwrap();
        (
            locked.last_update_start,
            locked.last_update_done,
            locked.last_update_duration,
        )
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
        report: OriginsReport,
        mut metrics: Metrics,
        exceptions: &LocalExceptions,
    ) -> bool {
        match self.current_and_serial() {
            Some((current, serial)) => {
                let current: HashSet<_> =
                    current.iter().map(Clone::clone).collect();
                let (next, diff) = OriginsDiff::construct(
                    current, report, exceptions, serial, &mut metrics,
                );
                let mut history = self.0.write().unwrap();
                history.metrics = Some(Arc::new(metrics));
                if !diff.is_empty() {
                    history.current = Some(Arc::new(next));
                    history.push_diff(diff);
                    true
                }
                else {
                    false
                }
            }
            None => {
                let origins = AddressOrigins::from_report(
                    report, exceptions, &mut metrics
                );
                let mut history = self.0.write().unwrap();
                history.metrics = Some(Arc::new(metrics));
                history.current = Some(Arc::new(origins));
                true
            }
        }
    }

    /// Marks the beginning of an update cycle.
    pub fn mark_update_start(&self) {
        self.0.write().unwrap().last_update_start = Instant::now();
    }

    /// Marks the end of an update cycle.
    pub fn mark_update_done(&self) {
        let mut locked = self.0.write().unwrap();
        locked.last_update_done = Some(Instant::now());
        locked.last_update_duration = Some(locked.last_update_start.elapsed());
        locked.next_update_start = SystemTime::now() + locked.refresh;
        if let Some(refresh) = locked.current.as_ref().and_then(|c| c.refresh) {
            let refresh = SystemTime::from(refresh);
            if refresh < locked.next_update_start {
                locked.next_update_start = refresh;
            }
        }
    }
}

impl VrpSource for OriginsHistory {
    type FullIter = AddressOriginsIter;
    type DiffIter = DiffIter;

    fn ready(&self) -> bool {
        self.is_active()
    }

    fn notify(&self) -> State {
        let history = self.0.read().unwrap();
        State::from_parts(history.session, history.serial())
    }

    fn full(&self) -> (State, Self::FullIter) {
        let history = self.0.read().unwrap();
        (
            State::from_parts(history.session, history.serial()),
            AddressOriginsIter::new(
                history.current.clone().unwrap_or_default()
            )
        )
    }

    fn diff(
        &self, state: State
    ) -> Option<(State, Self::DiffIter)> {
        let history = self.0.read().unwrap();
        if history.session != state.session() {
            return None
        }
        history.get(state.serial()).map(|diff| {
            (
                State::from_parts(history.session, history.serial()),
                DiffIter::new(diff)
            )
        })
    }

    fn timing(&self) -> Timing {
        let this = self.0.read().unwrap();
        let mut res = this.timing;
        res.refresh = this.next_refresh().as_secs() as u32;
        res
    }
}

impl HistoryInner {
    /// Returns the current serial.
    ///
    /// This is either the serial of the first diff or 0 if there are no
    /// diffs.
    pub fn serial(&self) -> Serial {
        match self.diffs.front() {
            Some(diff) => diff.serial(),
            None => Serial(0)
        }
    }

    /// Appends a new diff dropping old ones if necessary.
    pub fn push_diff(&mut self, diff: OriginsDiff) {
        if self.diffs.len() == self.keep {
            let _ = self.diffs.pop_back();
        }
        self.diffs.push_front(Arc::new(diff))
    }

    /// Returns a diff from the given serial number.
    ///
    /// The serial is what the requestor has last seen. The method produces
    /// a diff from that version to the current version if it can. If it
    /// can’t, either because it doesn’t have enough history data or because
    /// the serial is actually in the future.
    pub fn get(&self, serial: Serial) -> Option<Arc<OriginsDiff>> {
        debug!("Fetching diff for serial {}", serial);
        if let Some(diff) = self.diffs.front() {
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
            else if diff.serial() == serial.add(1) {
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
        let mut iter = self.diffs.iter().rev();
        while let Some(diff) = iter.next() {
            match diff.serial().partial_cmp(&serial) {
                Some(cmp::Ordering::Greater) => return None,
                Some(cmp::Ordering::Equal) => break,
                _ => continue
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

    /// Returns the time a client should wait for its next refresh.
    fn next_refresh(&self) -> Duration {
        // Next update starts at last_update_done + refresh. It should finish
        // about last_update_duration later. Let’s double that to be safe. If
        // we don’t have a last_update_duration, we just use two minute as a
        // guess.
        let duration = self.last_update_duration.map(|some| 2 * some)
                           .unwrap_or_else(|| Duration::from_secs(120));
        let from = self.last_update_done.unwrap_or_else(|| {
            self.last_update_start + duration
        });
        self.refresh.checked_sub(
            Instant::now().saturating_duration_since(from)
        ).unwrap_or_else(|| Duration::from_secs(0)) + duration
    }
}


//------------ RouteOrigins --------------------------------------------------

/// The raw list of route origin attestations from RPKI.
///
/// This type is used to collect all the valid route origins as they fall out
/// of RPKI repository validation. It is an intermediary type used as input
/// for generating the real origins kept in [`AddressOrigins`].
///
/// [`AddressOrigins`]: struct.AddressOrigins.html
#[derive(Clone, Debug, Default)]
pub struct RouteOrigins {
    /// The list of valid ROAs.
    origins: Vec<RouteOrigin>,

    /// The time when this set needs to be refreshed at the latest.
    refresh: Option<Time>,
}

impl RouteOrigins {
    /// Creates a new, empty list of route origins.
    pub fn new() -> Self {
        Default::default()
    }

    /// Appends the given attestation to the set.
    ///
    /// The attestation will simply be added to the end of the list. No
    /// checking for duplicates is being done.
    pub fn push(
        &mut self,
        attestation: RouteOriginAttestation,
        tal_index: usize,
    ) {
        self.origins.push(RouteOrigin::new(attestation, tal_index));
    }

    /// Updates the refresh time.
    ///
    /// If the time given is earlier than our current refresh time, sets the
    /// time given as the new refresh time.
    pub fn update_refresh(&mut self, cert: &TbsCert) {
        let refresh = cert.validity().not_after();
        if let Some(time) = self.refresh {
            if time < refresh {
                return
            }
        }
        self.refresh = Some(refresh)
    }

    /// Returns whether the list of attestations is empty.
    pub fn is_empty(&self) -> bool {
        self.origins.is_empty()
    }

    /// Returns the number of attestations in the list.
    pub fn len(&self) -> usize {
        self.origins.len()
    }

    /// Returns an iterator over the attestations in the list.
    pub fn iter(&self) -> slice::Iter<RouteOrigin> {
        self.origins.iter()
    }
}


//--- IntoIterator

impl IntoIterator for RouteOrigins {
    type Item = RouteOrigin;
    type IntoIter = vec::IntoIter<RouteOrigin>;

    fn into_iter(self) -> Self::IntoIter {
        self.origins.into_iter()
    }
}

impl<'a> IntoIterator for &'a RouteOrigins {
    type Item = &'a RouteOrigin;
    type IntoIter = slice::Iter<'a, RouteOrigin>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}


//------------ RouteOrigin ---------------------------------------------------

/// A single route origin attestation.
///
/// We don’t really need to keep the whole RPKI object around, so we don’t.
/// This type collects all the information we do need later.
#[derive(Clone, Debug)]
pub struct RouteOrigin {
    /// The ASN of the ROA.
    as_id: AsId,

    /// The addresses of the ROA.
    addrs: Vec<FriendlyRoaIpAddress>,

    /// The ROA information for the ROA.
    info: OriginInfo,

    /// The index of the TAL the ROA is derived from.
    ///
    /// We keep this for quicker calculations of TAL metrics.
    tal_index: usize,
}

impl RouteOrigin {
    /// Creates a new value from the ROA itself and the TAL index.
    pub fn new(mut roa: RouteOriginAttestation, tal_index: usize) -> Self {
        RouteOrigin {
            as_id: roa.as_id(),
            addrs: roa.iter().collect(),
            info: OriginInfo::from_roa(&mut roa),
            tal_index
        }
    }

    pub fn as_id(&self) -> AsId {
        self.as_id
    }

    pub fn addrs(&self) -> &[FriendlyRoaIpAddress] {
        &self.addrs
    }

    pub fn info(&self) -> &OriginInfo {
        &self.info
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
#[derive(Clone, Debug, Default)]
pub struct AddressOrigins {
    /// A list of (unique) address origins.
    origins: Vec<AddressOrigin>,

    /// The time when this set needs to be refreshed at the latest.
    refresh: Option<Time>,
}

impl AddressOrigins {
    /// Creates a new, empty set of address origins.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a set from the raw route origins and exceptions.
    ///
    /// The function will take all the address origins in `origins`, drop
    /// duplicates, drop the origins filtered in `execptions` and add the
    /// assertions from `exceptions`.
    pub fn from_report(
        report: OriginsReport,
        exceptions: &LocalExceptions,
        metrics: &mut Metrics,
    ) -> Self {
        let mut res = HashSet::new();
        let mut refresh = None;

        let mut tal_metrics_vec: Vec<_> = report.tals.iter().map(|tal| {
            TalMetrics::new(tal.clone())
        }).collect();

        for item in report.origins {
            if let Some(time) = item.refresh {
                match refresh {
                    Some(current) if current > time => refresh = Some(time),
                    Some(_) => { }
                    None => refresh = Some(time)
                }
            }
            for origin in item {
                let tal_metrics = &mut tal_metrics_vec[origin.tal_index];
                tal_metrics.roas += 1;
                for addr in origin.addrs {
                    tal_metrics.vrps += 1;
                    let addr = AddressOrigin::from_roa(
                        origin.as_id,
                        addr,
                        origin.info.clone()
                    );
                    if exceptions.keep_origin(&addr) {
                        let _ = res.insert(addr);
                    }
                }
            }
        }
        for addr in exceptions.assertions() {
            let _ = res.insert(addr.clone());
        }
        metrics.set_tals(tal_metrics_vec);
        AddressOrigins {
            origins: res.into_iter().collect(),
            refresh
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
            origins: set.into_iter().collect(),
            refresh: None,
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

impl AsRef<Self> for AddressOrigins {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl AsRef<[AddressOrigin]> for AddressOrigins {
    fn as_ref(&self) -> &[AddressOrigin] {
        self.origins.as_ref()
    }
}


//------------ AddressOriginsIter --------------------------------------------

#[derive(Clone, Debug)]
pub struct AddressOriginsIter {
    origins: Arc<AddressOrigins>,
    pos: usize
}

impl AddressOriginsIter {
    fn new(origins: Arc<AddressOrigins>) -> Self {
        AddressOriginsIter { origins, pos: 0 }
    }
}

impl Iterator for AddressOriginsIter {
    type Item = Payload;

    fn next(&mut self) -> Option<Payload> {
        let res = self.origins.origins.get(self.pos)?;
        self.pos += 1;
        Some(res.payload())
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
    serial: Serial,

    /// The address origins added by this diff.
    announce: Vec<AddressOrigin>,

    /// The address origins removed by this diff.
    withdraw: Vec<AddressOrigin>,
}

impl OriginsDiff {
    /// Creates an empty origins diff with the given serial number.
    ///
    /// Both the announce and withdraw lists will be empty.
    pub fn empty(serial: Serial) -> Self {
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
        report: OriginsReport,
        exceptions: &LocalExceptions,
        serial: Serial,
        metrics: &mut Metrics,
    ) -> (AddressOrigins, Self) {
        let mut next = HashSet::new();
        let mut announce = HashSet::new();

        let mut tal_metrics_vec: Vec<_> = report.tals.iter().map(|tal| {
            TalMetrics::new(tal.clone())
        }).collect();

        for item in report.origins {
            for origin in item {
                let tal_metrics = &mut tal_metrics_vec[origin.tal_index];
                tal_metrics.roas += 1;
                for addr in origin.addrs {
                    tal_metrics.vrps += 1;
                    let addr = AddressOrigin::from_roa(
                        origin.as_id, addr, origin.info.clone()
                    );
                    if !exceptions.keep_origin(&addr) {
                        continue
                    }
                    if next.insert(addr.clone()) && !current.remove(&addr) {
                        let _ = announce.insert(addr);
                    }
                }
            }
        }
        metrics.set_tals(tal_metrics_vec);
        for addr in exceptions.assertions() {
            // Exceptions could have changed, so let’s be thorough here.
            if next.insert(addr.clone()) && !current.remove(addr)  {
                announce.insert(addr.clone());
            }
        }
        let withdraw: Vec<_> = current.into_iter().collect();
        let announce: Vec<_> = announce.into_iter().collect();
        info!(
            "Diff with {} announced and {} withdrawn.",
            announce.len(), withdraw.len()
        );
        let serial = serial.add(1);
        (next.into(), OriginsDiff { serial, announce, withdraw })
    }

    /// Returns the serial number of this origins diff.
    pub fn serial(&self) -> Serial {
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
    ) -> (Serial, Vec<AddressOrigin>, Vec<AddressOrigin>) {
        (self.serial, self.announce, self.withdraw)
    }
}


//------------ DiffIter ------------------------------------------------------

#[derive(Clone, Debug)]
pub struct DiffIter {
    /// The diff we are iterating over.
    diff: Arc<OriginsDiff>,
    
    /// The position of the iterator.
    ///
    /// If it is `Ok(some)` we are in announcements, if it is `Err(some)` we
    /// are in withdrawals.
    pos: Result<usize, usize>,
}

impl DiffIter {
    fn new(diff: Arc<OriginsDiff>) -> Self {
        DiffIter { diff, pos: Ok(0) }
    }
}

impl Iterator for DiffIter {
    type Item = (Action, Payload);

    fn next(&mut self) -> Option<Self::Item> {
        match self.pos {
            Ok(pos) => {
                match self.diff.announce.get(pos) {
                    Some(res) => {
                        self.pos = Ok(pos + 1);
                        Some((Action::Announce, res.payload()))
                    }
                    None => {
                        self.pos = Err(0);
                        self.next()
                    }
                }
            }
            Err(pos) => {
                match self.diff.withdraw.get(pos) {
                    Some(res) => {
                        self.pos = Err(pos + 1);
                        Some((Action::Withdraw, res.payload()))
                    }
                    None => None
                }
            }
        }
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
    serial: Serial,

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
        AddressOrigin { as_id, prefix, max_length, info }
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

    /// Returns the RTR payload for the origin.
    pub fn payload(&self) -> Payload {
        match self.address() {
            IpAddr::V4(addr) => {
                Payload::V4(Ipv4Prefix {
                    prefix: addr,
                    prefix_len: self.address_length(),
                    max_len: self.max_length(),
                    asn: self.as_id().into(),
                })
            }
            IpAddr::V6(addr) => {
                Payload::V6(Ipv6Prefix {
                    prefix: addr,
                    prefix_len: self.address_length(),
                    max_len: self.max_length(),
                    asn: self.as_id().into(),
                })
            }
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

    /// Returns a ROA information if available.
    pub fn roa_info(&self) -> Option<&RoaInfo> {
        self.info.roa_info()
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

    /// Returns whether the prefix is for an IPv4 address.
    pub fn is_v4(self) -> bool {
        self.addr.is_ipv4()
    }

    /// Returns whether the prefix is for an IPv6 address.
    pub fn is_v6(self) -> bool {
        self.addr.is_ipv6()
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
                if self.len > 31 {
                    left == right
                }
                else if self.len > other.len {
                    false
                }
                else {
                    let left = u32::from(left)
                             & !(::std::u32::MAX >> self.len);
                    let right = u32::from(right)
                              & !(::std::u32::MAX >> self.len);
                    left == right
                }
            }
            (IpAddr::V6(left), IpAddr::V6(right)) => {
                if self.len > 127 {
                    left == right
                }
                else if self.len > other.len {
                    false
                }
                else {
                    let left = u128::from(left)
                             & !(::std::u128::MAX >> self.len);
                    let right = u128::from(right)
                              & !(::std::u128::MAX >> self.len);
                    left == right
                }
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

impl<'de> Deserialize<'de> for AddressPrefix {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D
    ) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = AddressPrefix;

            fn expecting(
                &self, formatter: &mut fmt::Formatter
            ) -> fmt::Result {
                write!(formatter, "a string with a IPv4 or IPv6 prefix")
            }

            fn visit_str<E: serde::de::Error>(
                self, v: &str
            ) -> Result<Self::Value, E> {
                AddressPrefix::from_str(v).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

impl fmt::Display for AddressPrefix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}


//------------ OriginInfo ----------------------------------------------------

/// Extended information about an origin.
#[derive(Clone, Debug)]
pub enum OriginInfo {
    /// No information.
    None,

    /// The resource certificate of a ROA.
    RoaInfo(Arc<RoaInfo>),

    /// The path of a local exceptions file.
    Exception(ExceptionInfo),
}

impl OriginInfo {
    fn from_roa(roa: &mut RouteOriginAttestation) -> Self {
        if let Some(cert) = roa.take_cert() {
            OriginInfo::RoaInfo(Arc::new(RoaInfo::from_ee_cert(cert)))
        }
        else {
            OriginInfo::None
        }
    }

    fn roa_info(&self) -> Option<&RoaInfo> {
        match *self {
            OriginInfo::RoaInfo(ref info) => Some(info),
            _ => None
        }
    }

    fn tal_name(&self) -> &str {
        match *self {
            OriginInfo::RoaInfo(ref info) => info.tal.name(),
            _ => "N/A"
        }
    }
}


//------------ RoaInfo -------------------------------------------------------

/// Information about a ROA.
#[derive(Clone, Debug)]
pub struct RoaInfo {
    /// The TAL the ROA is derived from.
    pub tal: Arc<TalInfo>,

    /// The rsync URI identifying the ROA.
    pub uri: Option<uri::Rsync>,

    /// The validity of the ROA.
    ///
    /// This isn’t being trimmed via the CA certificate or anything so the
    /// actual validity may be shorter.
    pub validity: Validity,
}

impl RoaInfo {
    fn from_ee_cert(cert: ResourceCert) -> Self {
        RoaInfo {
            uri: cert.signed_object().cloned().map(|mut uri| {
                uri.unshare(); uri
            }),
            validity: cert.validity(),
            tal: cert.into_tal(),
        }
    }
}


//------------ FromStrError --------------------------------------------------

/// Creating an IP address prefix from a string has failed.
#[derive(Clone, Debug)]
pub struct FromStrError(String);

impl fmt::Display for FromStrError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "bad prefix {}", self.0)
    }
}

impl error::Error for FromStrError { }


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

