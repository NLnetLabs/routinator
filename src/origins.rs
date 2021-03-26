/// Route origins.
///
/// The types in this module store route origins, sets of route origins, and
/// the history of changes necessary for RTR.

use std::{cmp, error, fmt, hash, ops, slice, vec};
use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use crossbeam_queue::SegQueue;
use log::{info, warn};
use rpki::uri;
use rpki::repository::cert::{ResourceCert, TbsCert};
use rpki::repository::resources::{AsId, IpBlocks, IpBlocksBuilder};
use rpki::repository::roa::{
    FriendlyRoaIpAddress, RoaStatus, RouteOriginAttestation
};
use rpki::repository::tal::{Tal, TalInfo, TalUri};
use rpki::repository::x509::{Time, Validity};
use rpki::rtr::payload::{Action, Ipv4Prefix, Ipv6Prefix, Payload, Timing};
use rpki::rtr::server::VrpSource;
use rpki::rtr::state::{Serial, State};
use serde::{Deserialize, Deserializer};
use crate::config::{Config, FilterPolicy};
use crate::error::Failed;
use crate::metrics::{Metrics, ServerMetrics};
use crate::process::LogOutput;
use crate::engine::{ProcessCa, ProcessRun};
use crate::slurm::{ExceptionInfo, LocalExceptions};


//------------ OriginsReport -------------------------------------------------

/// The output of a validation run.
#[derive(Debug, Default)]
pub struct OriginsReport {
    origins: SegQueue<RouteOrigins>,
    tals: Mutex<Vec<Arc<TalInfo>>>,
    filter: Mutex<InvalidResourcesBuilder>,
}

impl OriginsReport {
    pub fn new() -> Self {
        OriginsReport {
            origins: SegQueue::new(),
            tals: Mutex::new(Vec::new()),
            filter: Mutex::new(Default::default()),
        }
    }

    #[deprecated]
    pub fn with_capacity(_capacity: usize, _tals: Vec<Arc<TalInfo>>) -> Self {
        Self::new()
    }

    pub fn push_origins(&self, origins: RouteOrigins) {
        self.origins.push(origins)
    }
}

impl<'a> ProcessRun for &'a OriginsReport {
    type ProcessCa = ProcessRouteOrigins<'a>;

    fn process_ta(
        &self, _tal: &Tal, _uri: &TalUri, _cert: &ResourceCert,
        tal_index: usize
    ) -> Result<Option<Self::ProcessCa>, Failed> {
        Ok(Some(ProcessRouteOrigins {
            report: self,
            origins: RouteOrigins::new(),
            tal_index,
            repository_index: None,
        }))
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
        repository_index: Option<usize>,
    ) {
        self.origins.push(RouteOrigin::new(
            attestation, tal_index, repository_index,
        ));
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


//------------ ProcessRouteOrigins -------------------------------------------

#[derive(Clone, Debug)]
pub struct ProcessRouteOrigins<'a> {
    report: &'a OriginsReport,
    origins: RouteOrigins,
    tal_index: usize,
    repository_index: Option<usize>,
}

impl<'a> ProcessCa for ProcessRouteOrigins<'a> {
    fn repository_index(&mut self, repository_index: usize) {
        self.repository_index = Some(repository_index)
    }

    fn update_refresh(&mut self, not_after: Time) {
        match self.origins.refresh {
            Some(current) => {
                self.origins.refresh = Some(cmp::min(current, not_after))
            }
            None => self.origins.refresh = Some(not_after),
        }
    }

    fn want(&self, uri: &uri::Rsync) -> Result<bool, Failed> {
        Ok(uri.ends_with(".cer") || uri.ends_with(".roa"))
    }

    fn process_ca(
        &mut self, _uri: &uri::Rsync, _cert: &ResourceCert,
    ) -> Result<Option<Self>, Failed> {
        Ok(Some(ProcessRouteOrigins {
            report: self.report,
            origins: RouteOrigins::new(),
            tal_index: self.tal_index,
            repository_index: None,
        }))
    }

    fn process_roa(
        &mut self, _uri: &uri::Rsync, route: RouteOriginAttestation
    ) -> Result<(), Failed> {
        if let RoaStatus::Valid { ref cert } = *route.status() {
            self.update_refresh(cert.validity().not_after());
        }
        self.origins.push(route, self.tal_index, self.repository_index);
        Ok(())
    }

    fn commit(self) {
        self.report.origins.push(self.origins);
    }

    fn cancel(self, cert: &ResourceCert) {
        if let Some(uri) = cert.ca_repository() {
            warn!("CA for {} rejected, resources marked as unsafe:", uri);
            for block in cert.v4_resources().iter() {
                warn!("   {}", block.display_v4());
            }
            for block in cert.v6_resources().iter() {
                warn!("   {}", block.display_v6());
            }
            for block in cert.as_resources().iter() {
                warn!("   {}", block);
            }
        }
        self.report.filter.lock().unwrap().extend_from_cert(cert);
    }
}


//------------ InvalidResources ----------------------------------------------

/// Collects the invalid resources encountered during validation.
///
/// Currently, we only collect address blocks that need to be filtered. We
/// will also start collecting AS blocks once that becomes actually necessary.
#[derive(Clone, Debug, Default)]
struct InvalidResources {
    v4: IpBlocks,
    v6: IpBlocks,
}

impl InvalidResources {
    fn keep_address(&self, addr: &FriendlyRoaIpAddress) -> bool {
        if addr.is_v4() {
            !self.v4.intersects_block(addr.prefix())
        }
        else {
            !self.v6.intersects_block(addr.prefix())
        }
    }
}


//------------ InvalidResourcesBuilder ---------------------------------------

/// A builder for invalid resources encountered during validation.
#[derive(Clone, Debug, Default)]
struct InvalidResourcesBuilder {
    /// The IPv4 blocks to filter.
    v4: IpBlocksBuilder,

    /// The IPv6 blocks to filter.
    v6: IpBlocksBuilder,
}

impl InvalidResourcesBuilder {
    fn extend_from_cert(&mut self, cert: &ResourceCert) {
        self.v4.extend(
            cert.v4_resources().iter().filter(|block| !block.is_slash_zero())
        );
        self.v6.extend(
            cert.v6_resources().iter().filter(|block| !block.is_slash_zero())
        );
    }

    fn finalize(self) -> InvalidResources {
        InvalidResources {
            v4: self.v4.finalize(),
            v6: self.v6.finalize(),
        }
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
/// holding the lock.
#[derive(Debug)]
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

    /// How to deal with unsafe VRPs.
    unsafe_vrps: FilterPolicy,

    /// The instant when we started an update the last time.
    last_update_start: DateTime<Utc>,

    /// The instant we successfully (!) finished an update the last time.
    last_update_done: Option<DateTime<Utc>>,

    /// The duration of the last update run.
    last_update_duration: Option<Duration>,

    /// The instant when we are scheduled to start the next update.
    next_update_start: SystemTime,

    /// Default RTR timing.
    timing: Timing,

    /// Optional logging output.
    log: Option<LogOutput>,
}

impl OriginsHistory {
    /// Creates a new history from the given initial data.
    pub fn new(
        config: &Config,
        log: Option<LogOutput>,
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
                unsafe_vrps: config.unsafe_vrps,
                last_update_start: Utc::now(),
                last_update_done: None,
                last_update_duration: None,
                timing: Timing {
                    refresh: config.refresh.as_secs() as u32,
                    retry: config.retry.as_secs() as u32,
                    expire: config.expire.as_secs() as u32,
                },
                log
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
        start.duration_since(SystemTime::now()).unwrap_or(refresh)
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
    ) -> (DateTime<Utc>, Option<DateTime<Utc>>, Option<Duration>) {
        let locked = self.0.read().unwrap();
        (
            locked.last_update_start,
            locked.last_update_done,
            locked.last_update_duration,
        )
    }

    pub fn log(&self) -> Bytes {
        match self.0.read().unwrap().log {
            Some(ref log) => log.get_output(),
            None => Bytes::new(),
        }
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
        let origins = AddressOriginSet::from_report(
            report, exceptions, &mut metrics,
            self.0.read().unwrap().unsafe_vrps,
        );
        match self.current_and_serial() {
            Some((current, serial)) => {
                let diff = OriginsDiff::construct(
                    &current.to_set(), &origins, serial
                );
                let mut history = self.0.write().unwrap();
                history.metrics = Some(Arc::new(metrics));
                if !diff.is_empty() {
                    info!(
                        "Diff with {} announced and {} withdrawn.",
                        diff.announce().len(), diff.withdraw().len()
                    );
                    history.current = Some(Arc::new(origins.into()));
                    history.push_diff(diff);
                    true
                }
                else {
                    false
                }
            }
            None => {
                let mut history = self.0.write().unwrap();
                history.metrics = Some(Arc::new(metrics));
                history.current = Some(Arc::new(origins.into()));
                true
            }
        }
    }

    /// Marks the beginning of an update cycle.
    pub fn mark_update_start(&self) {
        let mut locked = self.0.write().unwrap();
        locked.last_update_start = Utc::now();
        if let Some(log) = locked.log.as_mut() {
            log.start()
        }
    }

    /// Marks the end of an update cycle.
    pub fn mark_update_done(&self) {
        let mut locked = self.0.write().unwrap();
        let now = Utc::now();
        locked.last_update_done = Some(now);
        locked.last_update_duration = Some(
            now.signed_duration_since(locked.last_update_start)
                .to_std().unwrap_or_else(|_| Duration::from_secs(0))
        );
        locked.next_update_start = SystemTime::now() + locked.refresh;
        if let Some(refresh) = locked.current.as_ref().and_then(|c| c.refresh) {
            let refresh = SystemTime::from(refresh);
            if refresh < locked.next_update_start {
                locked.next_update_start = refresh;
            }
        }
        if let Some(log) = locked.log.as_mut() {
            log.flush();
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
        if let Some(diff) = self.diffs.front() {
            if diff.serial() < serial {
                // If they give us a future serial, we reset.
                return None
            }
            else if diff.serial() == serial {
                return Some(Arc::new(OriginsDiff::empty(serial)))
            }
            else if diff.serial() == serial.add(1) {
                // This relies on serials increasing by one always.
                return Some(diff.clone())
            }
        }
        else if serial == 0 {
                return Some(Arc::new(OriginsDiff::empty(serial)))
        }
        else {
            // That pesky future serial again.
            return None
        }
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
        // Next update should finish about last_update_duration after
        // next_update_start. Let’s double that to be safe. If we don’t have
        // a last_update_duration, we just use two minute as a guess.
        let start_in = self.next_update_start
                           .duration_since(SystemTime::now())
                           .unwrap_or_else(|_| Duration::from_secs(0));
        let duration = self.last_update_duration.map(|some| 2 * some)
                           .unwrap_or_else(|| Duration::from_secs(120));
        start_in + duration
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

    /// The index of the TAL in the metrics.
    tal_index: usize,

    /// The index of the repository in the metrics.
    repository_index: Option<usize>,
}

impl RouteOrigin {
    /// Creates a new value from the ROA itself and the TAL index.
    pub fn new(
        mut roa: RouteOriginAttestation,
        tal_index: usize,
        repository_index: Option<usize>,
    ) -> Self {
        RouteOrigin {
            as_id: roa.as_id(),
            addrs: roa.iter().collect(),
            info: OriginInfo::from_roa(&mut roa),
            tal_index,
            repository_index,
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


//------------ AddressOriginSet ----------------------------------------------

/// The address origin statements as a set.
#[derive(Clone, Debug, Default)]
pub struct AddressOriginSet {
    /// The set.
    origins: HashSet<AddressOrigin>,

    /// The time when this set needs to be refreshed at the latest.
    refresh: Option<Time>,
}

impl AddressOriginSet {
    /// Creates a new, empty set of address origins.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a set from the raw route origins and exceptions.
    ///
    /// The function will take all the address origins in `origins`, drop
    /// duplicates, drop the origins filtered in `exceptions` and add the
    /// assertions from `exceptions`.
    pub fn from_report(
        report: OriginsReport,
        exceptions: &LocalExceptions,
        metrics: &mut Metrics,
        unsafe_vrps: FilterPolicy,
    ) -> Self {
        let mut origins = HashSet::new();
        let mut refresh = None;

        let filter = report.filter.into_inner().unwrap().finalize();

        while let Some(item) = report.origins.pop() {
            if let Some(time) = item.refresh {
                match refresh {
                    Some(current) if current > time => refresh = Some(time),
                    Some(_) => { }
                    None => refresh = Some(time)
                }
            }
            for origin in item {
                let tal_metrics = &mut metrics.tals[origin.tal_index].vrps;
                let mut repo_metrics = match origin.repository_index {
                    Some(index) => Some(&mut metrics.repositories[index].vrps),
                    None => None,
                };
                for addr in origin.addrs {
                    tal_metrics.valid += 1;
                    repo_metrics.as_mut().map(|vrps| vrps.valid += 1);
                    metrics.vrps.valid += 1;

                    if !filter.keep_address(&addr) {
                        tal_metrics.marked_unsafe += 1;
                        repo_metrics.as_mut().map(|v| v.marked_unsafe += 1);
                        metrics.vrps.marked_unsafe += 1;
                        match unsafe_vrps {
                            FilterPolicy::Reject => {
                                warn!(
                                    "Filtering potentially unsafe VRP \
                                     ({}/{}-{}, {})",
                                    addr.address(), addr.address_length(),
                                    addr.max_length(), origin.as_id
                                );
                                continue;
                            }
                            FilterPolicy::Warn => {
                                warn!(
                                    "Encountered potentially unsafe VRP \
                                     ({}/{}-{}, {})",
                                    addr.address(), addr.address_length(),
                                    addr.max_length(), origin.as_id
                                );
                            }
                            FilterPolicy::Accept => { }
                        }
                    }

                    let addr = AddressOrigin::from_roa(
                        origin.as_id,
                        addr,
                        origin.info.clone()
                    );
                    if !exceptions.keep_origin(&addr) {
                        tal_metrics.locally_filtered += 1;
                        repo_metrics.as_mut().map(|v| v.locally_filtered += 1);
                        metrics.vrps.locally_filtered += 1;
                        continue;
                    }

                    if origins.insert(addr) {
                        tal_metrics.contributed += 1;
                        repo_metrics.as_mut().map(|v| v.contributed += 1);
                        metrics.vrps.contributed += 1;
                    }
                    else {
                        tal_metrics.duplicate += 1;
                        repo_metrics.as_mut().map(|v| v.duplicate += 1);
                        metrics.vrps.duplicate += 1;
                    }
                }
            }
        }
        for addr in exceptions.assertions() {
            if origins.insert(addr.clone()) {
                metrics.local.contributed += 1;
            }
            else {
                metrics.local.duplicate += 1;
            }
        }
        let res = AddressOriginSet {
            origins, refresh
        };
        res
    }
}

impl From<AddressOrigins> for AddressOriginSet {
    fn from(src: AddressOrigins) -> Self {
        AddressOriginSet {
            origins: src.origins.into_iter().collect(),
            refresh: src.refresh
        }
    }
}


//------------ AddressOrigins ------------------------------------------------

/// The address origin statements as a slice.
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
        unsafe_vrps: FilterPolicy,
    ) -> Self {
        AddressOriginSet::from_report(
            report, exceptions, metrics, unsafe_vrps
        ).into()
    }

    /// Converts the origins into a set of origins.
    pub fn to_set(&self) -> AddressOriginSet {
        AddressOriginSet {
            origins: self.origins.iter().cloned().collect(),
            refresh: self.refresh
        }
    }

    /// Returns an iterator over the address orgins.
    pub fn iter(&self) -> slice::Iter<AddressOrigin> {
        self.origins.iter()
    }
}


//--- From

impl From<AddressOriginSet> for AddressOrigins {
    fn from(src: AddressOriginSet) -> Self {
        AddressOrigins {
            origins: src.origins.into_iter().collect(),
            refresh: src.refresh
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
    pub fn construct(
        current: &AddressOriginSet,
        next: &AddressOriginSet,
        serial: Serial,
    ) -> Self {
        OriginsDiff {
            announce: {
                next.origins.difference(
                    &current.origins
                ).cloned().collect()
            },
            withdraw: {
                current.origins.difference(
                    &next.origins
                ).cloned().collect()
            },
            serial: serial.add(1)
        }
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

    /// Returns whether the prefix `self` covers  the prefix`other`.
    pub fn covers(self, other: Self) -> bool {
        match (self.addr, other.addr) {
            (IpAddr::V4(left), IpAddr::V4(right)) => {
                if self.len > 31 && other.len > 31 {
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
                if self.len > 127 && other.len > 127 {
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
    Roa(Arc<RoaInfo>),

    /// The resource certificate of multiple ROAs.
    MultipleRoas(Vec<Arc<RoaInfo>>),

    /// The path of a local exceptions file.
    Exception(ExceptionInfo),
}

impl OriginInfo {
    fn from_roa(
        roa: &mut RouteOriginAttestation
    ) -> Self {
        if let Some(cert) = roa.take_cert() {
            OriginInfo::Roa(Arc::new(RoaInfo::from_ee_cert(cert)))
        }
        else {
            OriginInfo::None
        }
    }

    /*
    fn add_roa(
        &mut self,
        roa: &mut RouteOriginAttestation
    ) {
        if let OriginInfo::MultipleRoas(mut ref vec) = self {
            vec.push
        let old = mem::replace(self, OriginInfo::None);
        *self = Origin
    }
    */

    fn roa_info(&self) -> Option<&RoaInfo> {
        match *self {
            OriginInfo::Roa(ref info) => Some(info),
            _ => None
        }
    }

    fn tal_name(&self) -> &str {
        match *self {
            OriginInfo::Roa(ref info) => info.tal.name(),
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
pub mod test_covers {

    use super::*;

    fn make_pfx(s: &str, l: u8) -> AddressPrefix {
        AddressPrefix::new(s.parse().unwrap(), l)
    }

    #[test]
    fn should_find_covered_prefixes_v4() {
        let outer = make_pfx("10.0.0.0", 16);
        let host_roa = make_pfx("10.0.0.0", 32);
        let sibling = make_pfx("10.1.0.0", 16);
        let inner_low = make_pfx("10.0.0.0", 24);
        let inner_mid = make_pfx("10.0.61.0", 24);
        let inner_hi = make_pfx("10.0.255.0", 24);
        let supernet = make_pfx("10.0.0.0", 8);

        // Does not cover a sibling/neighbor prefix.
        assert!(!outer.covers(sibling));

        // Covers subnets at the extremes and middle of the supernet.
        assert!(outer.covers(inner_low));
        assert!(outer.covers(inner_mid));
        assert!(outer.covers(inner_hi));

        // Does not cover host-ROA and network: 10.0/32 not cover  10.0/16.
        assert!(!host_roa.covers(outer));

        // Does not cover supernet (10.0/16 does not cover 10/8).
        assert!(!outer.covers(supernet));
    }

    #[test]
    fn should_find_covered_prefixes_v6() {
        let outer = make_pfx("2001:db8::", 32);
        let host_roa = make_pfx("2001:db8::", 128);
        let sibling = make_pfx("2001:db9::", 32);
        let inner_low = make_pfx("2001:db8::", 48);
        let inner_mid = make_pfx("2001:db8:8000::", 48);
        let inner_hi = make_pfx("2001:db8:FFFF::", 48);
        let supernet = make_pfx("2001::", 24);

        // Does not cover a sibling/neighbor prefix.
        assert!(!outer.covers(sibling));

        // Covers subnets at the extremes and middle of the supernet.
        assert!(outer.covers(inner_low));
        assert!(outer.covers(inner_mid));
        assert!(outer.covers(inner_hi));

        // Does not cover host-ROA and network: 2001:db8::/128
        // does not cover  2001:db8::/32.
        assert!(!host_roa.covers(outer));

        // Does not cover supernet (2001:db8::/32 does not cover 2001::/24).
        assert!(!outer.covers(supernet));
    }
}

