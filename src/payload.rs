/// Payload data set derive from validation runs.
///
/// This module contains types to store the data derived from the RPKI
/// repository as well as complete sets of this data, diffs between
/// consecutive versions of such sets, and the history of sets and diffs.

use std::{cmp, ops};
use std::collections::hash_map;
use std::collections::{HashMap, HashSet, VecDeque};
use std::convert::TryFrom;
use std::hash::Hash;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};
use chrono::{DateTime, Utc};
use crossbeam_queue::SegQueue;
use log::{info, warn};
use routecore::addr;
use routecore::bgpsec::KeyIdentifier;
use rpki::repository::cert::{Cert, ResourceCert};
use rpki::repository::resources::{AsBlocks, IpBlock, IpBlocks, IpBlocksBuilder};
use rpki::repository::roa::RouteOriginAttestation;
use rpki::repository::tal::{Tal, TalInfo, TalUri};
use rpki::repository::x509::{Time, Validity};
use rpki::rtr::payload::{Action, Payload, RouteOrigin, RouterKey, Timing};
use rpki::rtr::pdu::RouterKeyInfo;
use rpki::rtr::server::{PayloadDiff, PayloadSet, PayloadSource};
use rpki::rtr::state::{Serial, State};
use rpki::uri;
use crate::config::{Config, FilterPolicy};
use crate::engine::{CaCert, Engine, ProcessPubPoint, ProcessRun};
use crate::error::Failed;
use crate::metrics::{Metrics, VrpMetrics};
use crate::slurm::{ExceptionInfo, LocalExceptions};


//============ Part One. During Validation ===================================
//
// The following types are used during a validation run to collect the
// valid published data.


//------------ ValidationReport ----------------------------------------------

/// The result of a validation run.
#[derive(Debug)]
pub struct ValidationReport {
    /// The data from all the valid publication points.
    ///
    /// When a publication point has been successfully validated, it pushes
    /// its data to this queue.
    pub_points: SegQueue<PubPoint>,

    /// Filter for invalid resources.
    ///
    /// If a publication point is rejected, the resources from its CA
    /// certificate are added to this.
    rejected: RejectedResourcesBuilder,

    /// Should we include BGPsec router keys?
    enable_bgpsec: bool,
}

impl ValidationReport {
    /// Creates a new, empty validation report.
    pub fn new(enable_bgpsec: bool) -> Self {
        ValidationReport {
            pub_points: Default::default(),
            rejected: Default::default(),
            enable_bgpsec
        }
    }

    /// Creates a new validation report by running the engine.
    pub fn process(
        engine: &Engine, enable_bgpsec: bool
    ) -> Result<(Self, Metrics), Failed> {
        let report = Self::new(enable_bgpsec);
        let mut run = engine.start(&report)?;
        run.process()?;
        run.cleanup()?;
        let metrics = run.done();
        Ok((report, metrics))
    }
}

impl<'a> ProcessRun for &'a ValidationReport {
    type PubPoint = PubPointProcessor<'a>;

    fn process_ta(
        &self,
        _tal: &Tal, _uri: &TalUri, cert: &CaCert,
        tal_index: usize,
    ) -> Result<Option<Self::PubPoint>, Failed> {
        Ok(Some(
            PubPointProcessor {
                report: self,
                pub_point: PubPoint::new_ta(cert, tal_index),
                validity: cert.combined_validity(),
            }
        ))
    }
}


//------------ PubPointProcessor ---------------------------------------------

/// Collects all the data for a publication point.
///
/// This type is used to during validation of a publication point. It collects
/// all the published data and eventually contributes it to a validation
/// report.
#[derive(Clone, Debug)]
pub struct PubPointProcessor<'a> {
    /// The validation report payload is contributed to.
    report: &'a ValidationReport,

    /// The data being collected.
    pub_point: PubPoint,

    /// The (combined) validity of the CA certificate.
    validity: Validity,
}

impl<'a> ProcessPubPoint for PubPointProcessor<'a> {
    fn repository_index(&mut self, repository_index: usize) {
        self.pub_point.repository_index = Some(repository_index)
    }

    fn update_refresh(&mut self, not_after: Time) {
        self.pub_point.refresh = cmp::min(
            self.pub_point.refresh, not_after
        );
    }

    fn want(&self, _uri: &uri::Rsync) -> Result<bool, Failed> {
        // While we actually only care for ROAs right now, we want everything
        // processed for statistics.
        Ok(true)
    }

    fn process_ca(
        &mut self, _uri: &uri::Rsync, cert: &CaCert,
    ) -> Result<Option<Self>, Failed> {
        Ok(Some(
            PubPointProcessor {
                report: self.report,
                pub_point: PubPoint::new_ca(&self.pub_point, cert),
                validity: cert.combined_validity(),
            }
        ))
    }

    fn process_ee_cert(
        &mut self, uri: &uri::Rsync, cert: Cert, ca_cert: &CaCert,
    ) -> Result<(), Failed> {
        if !self.report.enable_bgpsec {
            return Ok(())
        }
        if
            cert.as_resources().is_inherited()
            || !cert.as_resources().is_present()
        {
            warn!(
                "{}: router certificate does not contain AS resources.", uri
            );
            return Ok(())
        }
        let asns = match cert.as_resources().to_blocks() {
            Ok(blocks) => blocks,
            Err(_) => {
                warn!(
                    "{}: router certificate contains invalid AS resources.",
                    uri
                );
                return Ok(())
            }
        };
        let id = cert.subject_key_identifier();
        let key = cert.subject_public_key_info();
        if !key.allow_router_cert() {
            warn!(
                "{}: router certifcate has invalid key algorithm.", uri
            );
            return Ok(())
        }
        let key = match RouterKeyInfo::new(key.to_info_bytes()) {
            Ok(key) => key,
            Err(_) => {
                warn!(
                    "{}: excessively large key in router certificate.", uri
                );
                return Ok(())
            }
        };
        self.pub_point.update_refresh(cert.validity().not_after());
        self.pub_point.add_router_key(
            asns, id, key, Arc::new(PublishInfo::ee_cert(&cert, uri, ca_cert))
        );
        Ok(())
    }

    fn process_roa(
        &mut self,
        _uri: &uri::Rsync,
        cert: ResourceCert,
        route: RouteOriginAttestation
    ) -> Result<(), Failed> {
        self.pub_point.update_refresh(cert.validity().not_after());
        self.pub_point.add_roa(
            route, Arc::new(PublishInfo::signed_object(&cert, self.validity))
        );
        Ok(())
    }

    fn restart(&mut self) -> Result<(), Failed> {
        self.pub_point.restart();
        Ok(())
    }

    fn commit(self) {
        if !self.pub_point.is_empty() {
            self.report.pub_points.push(self.pub_point);
        }
    }

    fn cancel(self, cert: &CaCert) {
        warn!(
            "CA for {} rejected, resources marked as unsafe:",
            cert.ca_repository()
        );
        for block in cert.cert().v4_resources().iter() {
            warn!("   {}", block.display_v4());
        }
        for block in cert.cert().v6_resources().iter() {
            warn!("   {}", block.display_v6());
        }
        for block in cert.cert().as_resources().iter() {
            warn!("   {}", block);
        }
        self.report.rejected.extend_from_cert(cert);
    }
}


//------------ PubPoint ------------------------------------------------------

/// The raw data published by a publication point.
///
/// This type collects all the data published so it is available for later
/// processing.
#[derive(Clone, Debug)]
struct PubPoint {
    /// The list of valid payload and its publish information.
    payload: Vec<(Payload, Arc<PublishInfo>)>,

    /// The time when the publication point needs to be refreshed.
    refresh: Time,

    /// The initial value of `refresh`.
    ///
    /// We need this for restarting processing.
    orig_refresh: Time,

    /// The index of the TALs for the payload in the metrics.
    tal_index: usize,

    /// The index of the repository containing the payload in the metrics.
    repository_index: Option<usize>,
}

impl PubPoint {
    /// Creates a new publication point for a trust anchor CA.
    fn new_ta(cert: &CaCert, tal_index: usize) -> Self {
        let refresh = cert.cert().validity().not_after(); 
        PubPoint {
            payload: Vec::new(),
            refresh,
            orig_refresh: refresh,
            tal_index,
            repository_index: None,
        }
    }

    /// Creates a new publication for a regular CA.
    fn new_ca(parent: &PubPoint, cert: &CaCert) -> Self {
        let refresh = cmp::min(
            parent.refresh, cert.cert().validity().not_after()
        );
        PubPoint {
            payload: Vec::new(),
            refresh,
            orig_refresh: refresh,
            tal_index: parent.tal_index,
            repository_index: None,
        }
    }

    /// Returns whether there is nothing published via this point.
    pub fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }

    /// Updates the refresh time to be no later than the given time.
    fn update_refresh(&mut self, refresh: Time) {
        self.refresh = cmp::min(self.refresh, refresh)
    }

    /// Restarts processing for the publication point.
    fn restart(&mut self) {
        self.payload.clear();
        self.refresh = self.orig_refresh;
    }

    /// Adds the content of a ROA to the payload.
    fn add_roa(
        &mut self,
        roa: RouteOriginAttestation,
        info: Arc<PublishInfo>,
    ) {
        self.payload.extend(roa.iter_origins().map(|origin| {
            (origin.into(), info.clone())
        }));
    }

    /// Adds the content of a router key to the payload.
    fn add_router_key(
        &mut self,
        asns: AsBlocks,
        key_id: KeyIdentifier,
        key_info: RouterKeyInfo,
        info: Arc<PublishInfo>,
    ) {
        self.payload.extend(asns.iter_asns().map(|asn| {
            (RouterKey::new(key_id, asn, key_info.clone()).into(), info.clone())
        }));
    }
}


//------------ RejectedResourcesBuilder --------------------------------------

/// A builder for invalid resources encountered during validation.
#[derive(Debug, Default)]
struct RejectedResourcesBuilder {
    /// The queue of rejected IP blocks.
    ///
    /// The first element is whether the block is for IPv4.
    blocks: SegQueue<(bool, IpBlock)>,
}

impl RejectedResourcesBuilder {
    fn extend_from_cert(&self, cert: &CaCert) {
        for block in cert.cert().v4_resources().iter().filter(|block|
            !block.is_slash_zero()
        ) {
            self.blocks.push((true, block));
        }
        for block in cert.cert().v6_resources().iter().filter(|block|
            !block.is_slash_zero()
        ) {
            self.blocks.push((false, block));
        }
    }

    fn finalize(self) -> RejectedResources {
        let mut v4 = IpBlocksBuilder::new();
        let mut v6 = IpBlocksBuilder::new();
        while let Some((is_v4, block)) = self.blocks.pop() {
            if is_v4 {
                v4.push(block);
            }
            else {
                v6.push(block);
            }
        }
        RejectedResources {
            v4: v4.finalize(),
            v6: v6.finalize()
        }
    }
}


//------------ RejectedResources ---------------------------------------------

/// The resources from publication points that had to be rejected.
#[derive(Clone, Debug)]
pub struct RejectedResources {
    v4: IpBlocks,
    v6: IpBlocks
}

impl RejectedResources {
    /// Checks whether a prefix should be kept.
    pub fn keep_prefix(&self, prefix: addr::Prefix) -> bool {
        let raw = rpki::repository::resources::Prefix::new(
            prefix.addr(), prefix.len()
        );
        if prefix.is_v4() {
            !self.v4.intersects_block(raw)
        }
        else {
            !self.v6.intersects_block(raw)
        }
    }
}


//============ Part Two. After Validation ====================================


//------------ SharedHistory -------------------------------------------------

/// A shareable history of the validated payload.
#[derive(Clone, Debug)]
pub struct SharedHistory(Arc<RwLock<PayloadHistory>>);

impl SharedHistory {
    /// Creates a new shared history from the configuration.
    pub fn from_config(config: &Config) -> Self {
        SharedHistory(Arc::new(RwLock::new(
            PayloadHistory::from_config(config)
        )))
    }

    /// Provides access to the underlying history.
    pub fn read(&self) -> impl ops::Deref<Target = PayloadHistory> + '_ {
        self.0.read().expect("Payload history lock poisoned")
    }

    /// Provides write access to the underlying history.
    ///
    /// This is private because access is only through dedicated update
    /// methods.
    fn write(&self) -> impl ops::DerefMut<Target = PayloadHistory> + '_ {
        self.0.write().expect("Payload history lock poisoned")
    }

    /// Updates the history.
    ///
    /// Produces a new snapshot based on a validation report and local
    /// exceptions. If this snapshot differs from the current one, adds a
    /// new version to the history.
    ///
    /// The method returns whether it has indeed added a new version.
    pub fn update(
        &self,
        report: ValidationReport,
        exceptions: &LocalExceptions,
        mut metrics: Metrics
    ) -> bool {
        let snapshot = SnapshotBuilder::from_report(
            report, exceptions, &mut metrics,
            self.read().unsafe_vrps
        );

        let (current, serial) = {
            let read = self.read();
            (read.current(), read.serial())
        };

        let delta = current.as_ref().and_then(|current| {
            PayloadDelta::construct(&current.to_builder(), &snapshot, serial)
        });

        let mut history = self.write();
        history.metrics = Some(metrics.into());
        if let Some(delta) = delta {
            // Data has changed.
            info!(
                "Delta with {} announced and {} withdrawn items.",
                delta.announce.len(),
                delta.withdraw.len(),
            );
            history.current = Some(snapshot.into_snapshot().into());
            history.push_delta(delta);
            true
        }
        else if current.is_none() {
            // This is the first snapshot ever.
            history.current = Some(snapshot.into_snapshot().into());
            true
        }
        else {
            // Nothing has changed.
            false
        }
    }

    /// Marks the beginning of an update cycle.
    pub fn mark_update_start(&self) {
        self.write().last_update_start = Utc::now();
    }

    /// Marks the end of an update cycle.
    pub fn mark_update_done(&self) {
        let mut locked = self.write();
        let now = Utc::now();
        locked.last_update_done = Some(now);
        locked.last_update_duration = Some(
            now.signed_duration_since(locked.last_update_start)
                .to_std().unwrap_or_else(|_| Duration::from_secs(0))
        );
        locked.next_update_start = SystemTime::now() + locked.refresh;
        if let Some(refresh) = locked.current.as_ref().and_then(|c|
            c.refresh()
        ) {
            let refresh = SystemTime::from(refresh);
            if refresh < locked.next_update_start {
                locked.next_update_start = refresh;
            }
        }
        locked.created = {
            if let Some(created) = locked.created {
                // Since we increase the time, the created time may
                // actually have moved into the future.
                if now.timestamp() <= created.timestamp() {
                    Some(created + chrono::Duration::seconds(1))
                }
                else {
                    Some(now)
                }
            }
            else {
                Some(now)
            }
        };
    }
}


//--- PayloadSource

impl PayloadSource for SharedHistory {
    type Set = SnapshotVrpIter;
    type Diff = DeltaVrpIter;

    fn ready(&self) -> bool {
        self.read().is_active()
    }

    fn notify(&self) -> State {
        let read = self.read();
        State::from_parts(read.rtr_session(), read.serial())
    }

    fn full(&self) -> (State, Self::Set) {
        let read = self.read();
        (
            State::from_parts(read.rtr_session(), read.serial()),
            SnapshotVrpIter::new(read.current.clone().unwrap_or_default())
        )
    }

    fn diff(&self, state: State) -> Option<(State, Self::Diff)> {
        let read = self.read();
        if read.rtr_session() != state.session() {
            return None
        }
        read.delta_since(state.serial()).map(|delta| {
            (
                State::from_parts(read.rtr_session(), read.serial()),
                DeltaVrpIter::new(delta)
            )
        })
    }

    fn timing(&self) -> Timing {
        let read = self.read();
        let mut res = read.timing;
        res.refresh = u32::try_from(
            read.update_wait().as_secs()
        ).unwrap_or(u32::MAX);
        res
    }
}


//------------ PayloadHistory ------------------------------------------------

/// The history of the validated payload.
#[derive(Clone, Debug)]
pub struct PayloadHistory {
    /// The current full set of payload data.
    current: Option<Arc<PayloadSnapshot>>,

    /// A queue with a number of deltas.
    ///
    /// The newest delta will be at the fron of the queue. This delta will
    /// also deliver the current serial number.
    deltas: VecDeque<Arc<PayloadDelta>>,

    /// The current metrics.
    metrics: Option<Arc<Metrics>>,

    /// The session ID.
    session: u64,

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

    /// The creation time of the current data set.
    ///
    /// This is the same as last_update_done, except when that would be
    /// within the same second as the previous update, in which case we
    /// move it to the next second. This is necessary as the time used in
    /// conditional HTTP requests only has second-resolution.
    created: Option<DateTime<Utc>>,

    /// Default RTR timing.
    timing: Timing,
}

impl PayloadHistory {
    /// Creates a new history from the configuration.
    pub fn from_config(config: &Config) -> Self {
        PayloadHistory {
            current: None,
            deltas: VecDeque::with_capacity(config.history_size),
            metrics: None,
            session: {
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH).unwrap()
                    .as_secs()
            },
            keep: config.history_size,
            refresh: config.refresh,
            unsafe_vrps: config.unsafe_vrps,
            last_update_start: Utc::now(),
            last_update_done: None,
            last_update_duration: None,
            next_update_start: SystemTime::now() + config.refresh,
            created: None,
            timing: Timing {
                refresh: config.refresh.as_secs() as u32,
                retry: config.retry.as_secs() as u32,
                expire: config.expire.as_secs() as u32,
            },
        }
    }

    /// Pushes a new delta to the history
    fn push_delta(&mut self, delta: PayloadDelta) {
        if self.deltas.len() == self.keep {
            let _ = self.deltas.pop_back();
        }
        self.deltas.push_front(Arc::new(delta))
    }

    /// Returns whether the history is already active.
    ///
    /// The history becoes active once the first validation has finished.
    pub fn is_active(&self) -> bool {
        self.current.is_some()
    }

    /// Returns a shareable reference to the current payload snapshot.
    ///
    /// If the history isn’t active yet, returns `None`.
    pub fn current(&self) -> Option<Arc<PayloadSnapshot>> {
        self.current.clone()
    }

    /// Returns the duration until the next refresh should start.
    pub fn refresh_wait(&self) -> Duration {
        self.next_update_start
        .duration_since(SystemTime::now())
        .unwrap_or_else(|_| Duration::from_secs(0))
    }

    /// Returns the duration until a new set of data will likely be available.
    ///
    /// Because the update duration can vary widely, this is a guess at best.
    pub fn update_wait(&self) -> Duration {
        // Next update should finish about last_update_duration after
        // next_update_start. Let’s double that to be safe. If we don’t have
        // a last_update_duration, we just use two minute as a guess.
        let start = match self.last_update_duration {
            Some(duration) => self.next_update_start + duration + duration,
            None => self.next_update_start + self.refresh
        };
        start.duration_since(SystemTime::now()).unwrap_or(self.refresh)
    }

    /// Returns a delta from the given serial number to the current set.
    ///
    /// The serial is what the requestor has last seen. The method produces
    /// a delta from that version to the current version if it can. If it
    /// can’t, this is either because it doesn’t have enough history data or
    /// because the serial is actually in the future.
    ///
    /// The method returns an arc’d delta so it can return the delta from the
    /// previous version which is the most likely scenario for RTR.
    pub fn delta_since(&self, serial: Serial) -> Option<Arc<PayloadDelta>> {
        // First, handle all special cases that won’t result in us iterating
        // over the list of deltas.
        if let Some(delta) = self.deltas.front() {
            if delta.serial() < serial {
                // If they give us a future serial, we refuse to play.
                return None
            }
            else if delta.serial() == serial {
                // They already have the current version: empty delta.
                return Some(Arc::new(PayloadDelta::empty(serial)))
            }
            else if delta.serial() == serial.add(1) {
                // They are just one behind. Give them a clone of the delta.
                return Some(delta.clone())
            }
        }
        else {
            // We don’t have deltas yet, so we are on serial 0, too.
            if serial == 0 {
                return Some(Arc::new(PayloadDelta::empty(serial)))
            }
            else {
                return None
            }
        };

        // Iterate backwards over the deltas. Skip over those older than we
        // need.
        let mut iter = self.deltas.iter().rev();
        for delta in &mut iter {
            // delta.serial() is the target serial of the delta, serial is
            // the target serial the caller has. So we can skip over anything
            // smaller.
            match delta.serial().partial_cmp(&serial) {
                Some(cmp::Ordering::Greater) => return None,
                Some(cmp::Ordering::Equal) => break,
                _ => continue
            }
        }

        Some(DeltaMerger::from_iter(iter).into_delta())
    }

    /// Returns the serial number of the current data set.
    pub fn serial(&self) -> Serial {
        self.deltas.front().map(|delta| {
            delta.serial()
        }).unwrap_or_else(|| 0.into())
    }

    /// Returns the session ID.
    pub fn session(&self) -> u64 {
        self.session
    }

    /// Returns the RTR version of the session ID.
    ///
    /// This is the last 16 bits of the full session ID.
    pub fn rtr_session(&self) -> u16 {
        self.session as u16
    }

    /// Returns the current metrics if they are available yet.
    pub fn metrics(&self) -> Option<Arc<Metrics>> {
        self.metrics.clone()
    }

    /// Returns the time the last update was started.
    pub fn last_update_start(&self) -> DateTime<Utc> {
        self.last_update_start
    }

    /// Returns the time the last update has concluded.
    pub fn last_update_done(&self) -> Option<DateTime<Utc>> {
        self.last_update_done
    }

    /// Returns the time the last update has concluded.
    pub fn last_update_duration(&self) -> Option<Duration> {
        self.last_update_duration
    }

    /// Returns the time the current payload snapshot was created.
    ///
    /// The value returned guarantees that no two snapshots where created
    /// within the second. Consequently, it may occasionally be off by a
    /// second or two.
    pub fn created(&self) -> Option<DateTime<Utc>> {
        self.created
    }
}


//------------ PayloadSnapshot -----------------------------------------------

/// The complete set of validated payload data.
#[derive(Clone, Debug)]
pub struct PayloadSnapshot {
    /// A list of RPKI payload.
    ///
    /// This list contains an ordered sequence of unique payload.
    payload: Vec<(Payload, PayloadInfo)>,

    /// The time when this snapshot was created.
    created: DateTime<Utc>,

    /// The time when this snapshot needs to be refreshed at the latest.
    refresh: Option<Time>,
}


impl PayloadSnapshot {
    /// Creates a new, empty snapshot.
    pub fn new() -> Self {
        Default::default()
    }

    /// Creates a new snapshot from a report.
    ///
    /// The function takes all the data from `report` and removes any
    /// duplicates. Depending on the `unsafe_vrps` policy, it may remove all
    /// data for resources listed in `report`’s rejected resources. Finally,
    /// it removes entries filtered in `exceptions` and adds assertions from
    /// `exceptions`. It also updates the `metrics` and constructs all
    /// necessary meta information for the data.
    pub fn from_report(
        report: ValidationReport,
        exceptions: &LocalExceptions,
        metrics: &mut Metrics,
        unsafe_vrps: FilterPolicy
    ) -> Self {
        SnapshotBuilder::from_report(
            report, exceptions, metrics, unsafe_vrps
        ).into_snapshot()
    }

    /// Returns when this snapshot was created.
    pub fn created(&self) -> DateTime<Utc> {
        self.created
    }

    /// Returns when this snapshot should be refreshed at the latest.
    ///
    /// Returns `None` if there is no known refresh time.
    fn refresh(&self) -> Option<Time> {
        self.refresh
    }

    /// Returns an slice of the payload.
    pub fn payload(&self) -> &[(Payload, PayloadInfo)] {
        &self.payload
    }

    /// Returns an iterator over the route origins.
    pub fn origins(
        &self
    ) -> impl Iterator<Item = (RouteOrigin, &PayloadInfo)> + '_ {
        self.payload().iter().filter_map(|item| {
            match item.0 {
                Payload::Origin(origin) => Some((origin, &item.1)),
                _ => None
            }
        })
    }

    /// Converts a shared snapshot into a VRP iterator.
    pub fn into_vrp_iter(self: Arc<Self>) -> SnapshotVrpIter {
        SnapshotVrpIter::new(self)
    }

    /// Returns a snapshot builder based in this snapshot.
    fn to_builder(&self) -> SnapshotBuilder {
        SnapshotBuilder {
            payload: self.payload.iter().cloned().collect(),
            created: self.created,
            refresh: self.refresh,
        }
    }
}


//--- Default

impl Default for PayloadSnapshot {
    fn default() -> Self {
        PayloadSnapshot {
            payload: Vec::new(),
            created: Utc::now(),
            refresh: None
        }
    }
}


//--- AsRef

impl AsRef<PayloadSnapshot> for PayloadSnapshot {
    fn as_ref(&self) -> &Self {
        self
    }
}


//----------- SnapshotVrpIter ------------------------------------------------

/// An iterator over the VRPs of a shared snapshot.
#[derive(Clone, Debug)]
pub struct SnapshotVrpIter {
    /// The shared snapshot.
    snapshot: Arc<PayloadSnapshot>,

    /// The position of the next item within the payload of the snapshot.
    pos: usize,
}

impl SnapshotVrpIter {
    /// Creates a new iterator from a shared snapshot.
    fn new(snapshot: Arc<PayloadSnapshot>) -> Self {
        SnapshotVrpIter {
            snapshot,
            pos: 0
        }
    }

    /// Converts the iterator into one that only return origins.
    pub fn origins(self) -> SnapshotOriginsIter {
        SnapshotOriginsIter(self)
    }
}

impl PayloadSet for SnapshotVrpIter {
    fn next(&mut self) -> Option<&Payload> {
        let res = &self.snapshot.payload.get(self.pos)?.0;
        self.pos += 1;
        Some(res)

    }
}


//------------ SnapshotOriginsIter -------------------------------------------

/// An iterator over only the route origins in a snapshot.
#[derive(Clone, Debug)]
pub struct SnapshotOriginsIter(SnapshotVrpIter);

impl Iterator for SnapshotOriginsIter {
    type Item = RouteOrigin;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Payload::Origin(origin) = self.0.next()? {
                return Some(*origin)
            }
        }
    }
}


//------------ SnapshotBuilder -----------------------------------------------

/// The representation of a snapshot during history updates.
#[derive(Clone, Debug)]
struct SnapshotBuilder {
    /// A set of RPKI payload.
    payload: HashMap<Payload, PayloadInfo>,

    /// The time when this snapshot was created.
    created: DateTime<Utc>,

    /// The time when this snapshot needs to be refreshed at the latest.
    refresh: Option<Time>,
}


impl SnapshotBuilder {
    /// Creates a new snapshot builder from a report.
    ///
    /// The function takes all the data from `report` and removes any
    /// duplicates. Depending on the `unsafe_vrps` policy, it may remove all
    /// data for resources listed in `report`’s rejected resources. Finally,
    /// it removes entries filtered in `exceptions` and adds assertions from
    /// `exceptions`. It also updates the `metrics` and constructs all
    /// necessary meta information for the data.
    fn from_report(
        report: ValidationReport,
        exceptions: &LocalExceptions,
        metrics: &mut Metrics,
        unsafe_vrps: FilterPolicy
    ) -> Self {
        let mut res = SnapshotBuilder {
            payload: HashMap::new(),
            created: metrics.time,
            refresh: None
        };
        let rejected = report.rejected.finalize();

        // Process all publication points from the report.
        while let Some(pub_point) = report.pub_points.pop() {
            res.update_refresh(pub_point.refresh);
            
            for (payload, roa_info) in pub_point.payload {
                let mut point_metrics = AllVrpMetrics::new(
                    metrics, pub_point.tal_index, pub_point.repository_index,
                    &payload
                );
                point_metrics.update(|m| m.valid += 1);

                if let Payload::Origin(origin) = payload {
                    // Does the origin have rejected resources?
                    if !rejected.keep_prefix(origin.prefix.prefix()) {
                        point_metrics.update(|m| m.marked_unsafe += 1);
                        if unsafe_vrps != FilterPolicy::Accept {
                            warn!(
                                "Filtering potentially unsafe VRP \
                                 ({}/{}-{}, {})",
                                origin.prefix.addr(),
                                origin.prefix.prefix_len(),
                                origin.prefix.resolved_max_len(),
                                origin.asn
                            );
                        }
                        if unsafe_vrps == FilterPolicy::Reject {
                            continue
                        }
                    }
                }

                // Is the origin to be filtered locally?
                if !exceptions.keep_payload(&payload) {
                    point_metrics.update(|m| m.locally_filtered += 1);
                    continue
                }

                // Insert the origin. If we have it already, we need to
                // update its info instead.
                match res.payload.entry(payload) {
                    hash_map::Entry::Vacant(entry) => {
                        entry.insert(roa_info.into());
                        point_metrics.update(|m| m.contributed += 1);
                    }
                    hash_map::Entry::Occupied(mut entry) => {
                        entry.get_mut().add_published(roa_info);
                        point_metrics.update(|m| m.duplicate += 1);
                    }
                }
            }
        }

        // Add the assertions from the local exceptions.
        for (payload, info) in exceptions.assertions() {
            match res.payload.entry(payload.clone()) {
                hash_map::Entry::Vacant(entry) => {
                    entry.insert(info.into());
                    metrics.local.for_payload(payload).contributed += 1;
                    metrics.payload.for_payload(payload).contributed += 1;
                }
                hash_map::Entry::Occupied(mut entry) => {
                    entry.get_mut().add_local(info);
                    metrics.local.for_payload(payload).duplicate += 1;
                    metrics.payload.for_payload(payload).duplicate += 1;
                }
            }
        }

        metrics.finalize();
        res
    }

    /// Updates the refresh time.
    fn update_refresh(&mut self, refresh: Time) {
        self.refresh = match self.refresh {
            Some(old) => Some(cmp::min(old, refresh)),
            None => Some(refresh)
        }
    }

    /// Converts the builder into a snapshot.
    fn into_snapshot(self) -> PayloadSnapshot {
        let mut payload: Vec<_> = self.payload.into_iter().collect();
        payload.sort_by(|left, right| left.0.cmp(&right.0));
        PayloadSnapshot {
            payload,
            created: self.created,
            refresh: self.refresh,
        }
    }
}

impl Default for SnapshotBuilder {
    fn default() -> Self {
        SnapshotBuilder {
            payload: HashMap::new(),
            created: Utc::now(),
            refresh: None
        }
    }
}


//------------ AllVrpMetrics -------------------------------------------------

/// A helper struct to simplify changing all VRP metrics for a repository.
struct AllVrpMetrics<'a> {
    tal: &'a mut VrpMetrics,
    repo: Option<&'a mut VrpMetrics>,
    all: &'a mut VrpMetrics,
}

impl<'a> AllVrpMetrics<'a> {
    fn new(
        metrics: &'a mut Metrics, tal_index: usize, repo_index: Option<usize>,
        payload: &Payload,
    ) -> Self {
        AllVrpMetrics {
            tal: metrics.tals[tal_index].payload.for_payload(payload),
            repo: match repo_index {
                Some(index) => {
                    Some(
                        metrics.repositories[index]
                            .payload.for_payload(payload)
                    )
                }
                None => None
            },
            all: metrics.payload.for_payload(payload),
        }
    }

    fn update(&mut self, op: impl Fn(&mut VrpMetrics)) {
        op(self.tal);
        if let Some(ref mut repo) = self.repo {
            op(repo)
        }
        op(self.all)
    }
}


//------------ PayloadDelta --------------------------------------------------

/// The changes between two payload snapshots.
#[derive(Clone, Debug)]
pub struct PayloadDelta {
    /// The target serial number of this delta.
    ///
    /// This is the serial number of the payload history that this delta will
    /// be resulting in when applied.
    serial: Serial,

    /// Payload to be added by this delta.
    ///
    /// The vec is ordered.
    announce: Vec<Payload>,

    /// Payload to be removed by this delta.
    ///
    /// This vec is orderd.
    withdraw: Vec<Payload>,
}

impl PayloadDelta {
    /// Constructs a new delta from a previous and a new snapshot.
    ///
    /// Returns `None` if the old and new snapshot are, in fact, identical.
    fn construct(
        current: &SnapshotBuilder, next: &SnapshotBuilder, serial: Serial
    ) -> Option<Self> {
        let announce = added_keys(&next.payload, &current.payload);
        let withdraw = added_keys(&current.payload, &next.payload);
        if !announce.is_empty() || !withdraw.is_empty() {
            Some(PayloadDelta {
                serial: serial.add(1),
                announce,
                withdraw,
            })
        }
        else {
            None
        }
    }

    /// Creates an empty delta with the given target serial number.
    pub fn empty(serial: Serial) -> Self {
        PayloadDelta {
            serial,
            announce: Vec::new(),
            withdraw: Vec::new(),
        }
    }

    /// Returns whether this is an empty delta.
    ///
    /// A delta is empty if there is nothing announced and nothing withdrawn.
    pub fn is_empty(&self) -> bool {
        self.announce.is_empty() && self.withdraw.is_empty()
    }

    /// Returns the target serial number of the delta.
    pub fn serial(&self) -> Serial {
        self.serial
    }

    /// Returns a slice with the payload announced by this delta.
    pub fn announce(&self) ->  &[Payload] {
        &self.announce
    }

    /// Returns a slice with the payload withdrawn by this delta.
    pub fn withdraw(&self) ->  &[Payload] {
        &self.withdraw
    }
}


//------------ DeltaVrpIter --------------------------------------------------

/// An iterator over the changed VRPs of a shared delta.
#[derive(Clone, Debug)]
pub struct DeltaVrpIter {
    /// The shared delta we are iterating over.
    delta: Arc<PayloadDelta>,

    /// The index of the next item to be returned.
    ///
    /// If it is `Ok(some)` we are in announcements, if it is `Err(some)` we
    /// are in withdrawals.
    pos: Result<usize, usize>,
}

impl DeltaVrpIter {
    /// Creates a new iterator from a shared delta.
    fn new(delta: Arc<PayloadDelta>) -> Self {
        DeltaVrpIter {
            delta,
            pos: Ok(0)
        }
    }
}

impl PayloadDiff for DeltaVrpIter {
    fn next(&mut self) -> Option<(&Payload, Action)> {
        match self.pos {
            Ok(pos) => {
                match self.delta.announce.get(pos) {
                    Some(res) => {
                        self.pos = Ok(pos + 1);
                        Some((res, Action::Announce))
                    }
                    None => {
                        self.pos = Err(0);
                        match self.delta.withdraw.get(pos) {
                            Some(res) => {
                                self.pos = Err(pos + 1);
                                Some((res, Action::Withdraw))
                            }
                            None => None
                        }
                    }
                }
            }
            Err(pos) => {
                match self.delta.withdraw.get(pos) {
                    Some(res) => {
                        self.pos = Err(pos + 1);
                        Some((res, Action::Withdraw))
                    }
                    None => None
                }
            }
        }
    }
}


//------------ DeltaMerger ---------------------------------------------------

/// Allows merging a sequence of deltas into a combined delta.
#[derive(Clone, Debug, Default)]
struct DeltaMerger {
    /// The target serial number of the combined diff.
    serial: Serial,

    /// The set of added payload.
    announce: HashSet<Payload>,

    /// The set of removed payload.
    withdraw: HashSet<Payload>,
}

impl DeltaMerger {
    /// Creates a merger from an iterator of deltas.
    fn from_iter<'a>(
        mut iter: impl Iterator<Item = &'a Arc<PayloadDelta>>
    ) -> Self {
        let mut res = match iter.next() {
            Some(delta) => Self::new(delta),
            None => return Self::default()
        };

        for delta in iter {
            res.merge(delta)
        }

        res
    }

    /// Creates a new merger from an initial delta.
    fn new(delta: &PayloadDelta) -> Self {
        DeltaMerger {
            serial: delta.serial,
            announce: delta.announce.iter().cloned().collect(),
            withdraw: delta.withdraw.iter().cloned().collect(),
        }
    }

    /// Merges a diff.
    ///
    /// After, the serial number will be that of `diff`. Payload that is
    /// in `diff`’s announce list is added to the merger’s announce set
    /// unless it is in the merger’s withdraw set, in which case it is
    /// removed from the merger’s withdraw set. Payload in `diff`’s withdraw
    /// set is removed from the merger’s announce set if it is in it or
    /// added to the merger’s withdraw set otherwise.
    ///
    /// (This looks much simpler in code than in prose …)
    fn merge(&mut self, delta: &PayloadDelta) {
        self.serial = delta.serial;
        for origin in &delta.announce {
            if !self.withdraw.remove(origin) {
                self.announce.insert(origin.clone());
            }
        }
        for origin in &delta.withdraw {
            if !self.announce.remove(origin) {
                self.withdraw.insert(origin.clone());
            }
        }
    }

    /// Converts the merger into a delta.
    fn into_delta(self) -> Arc<PayloadDelta> {
        Arc::new(PayloadDelta {
            serial: self.serial,
            announce: self.announce.into_iter().collect(),
            withdraw: self.withdraw.into_iter().collect(),
        })
    }
}


//============ Part Three. Payload Source Information ========================
//
// Some output formats need information about the source of the information
// presented. This part contains the types for that.


//------------ PayloadInfo ---------------------------------------------------

/// Information about the sources of a payload item.
#[derive(Clone, Debug)]
pub struct PayloadInfo {
    /// The head of a linked list of origin infos.
    ///
    /// We are abusing `Result` here to distinguish between origins from
    /// published objects and from local exceptions. If you squint real hard,
    /// this even kind of makes sense.
    head: Result<Arc<PublishInfo>, Arc<ExceptionInfo>>,

    /// The tail of the linked list.
    tail: Option<Box<PayloadInfo>>,
}


impl PayloadInfo {
    fn add_published(&mut self, info: Arc<PublishInfo>) {
        self.tail = Some(Box::new(PayloadInfo {
            head: Ok(info),
            tail: self.tail.take()
        }));
    }

    fn add_local(&mut self, info: Arc<ExceptionInfo>) {
        self.tail = Some(Box::new(PayloadInfo {
            head: Err(info),
            tail: self.tail.take()
        }));
    }

    /// Returns an iterator over the chain of information.
    pub fn iter(&self) -> PayloadInfoIter {
        PayloadInfoIter { info: Some(self) }
    }

    /// Returns the name of the first TAL if available.
    pub fn tal_name(&self) -> Option<&str> {
        self.head.as_ref().map(|info| info.tal.name()).ok()
    }

    /// Returns the URI of the first ROA if available.
    pub fn uri(&self) -> Option<&uri::Rsync> {
        self.head.as_ref().ok().and_then(|info| info.uri.as_ref())
    }

    /// Returns the validity of the first ROA if available.
    ///
    pub fn validity(&self) -> Option<Validity> {
        self.head.as_ref().map(|info| info.roa_validity).ok()
    }

    /// Returns the published object info if available.
    pub fn publish_info(&self) -> Option<&PublishInfo> {
        match self.head {
            Ok(ref info) => Some(info),
            Err(_) => None
        }
    }

    /// Returns the exception info if available.
    pub fn exception_info(&self) -> Option<&ExceptionInfo> {
        match self.head {
            Ok(_) => None,
            Err(ref info) => Some(info),
        }
    }
}


//--- From

impl From<Arc<PublishInfo>> for PayloadInfo {
    fn from(src: Arc<PublishInfo>) -> Self {
        PayloadInfo { head: Ok(src), tail: None }
    }
}

impl From<Arc<ExceptionInfo>> for PayloadInfo {
    fn from(src: Arc<ExceptionInfo>) -> Self {
        PayloadInfo { head: Err(src), tail: None }
    }
}

//--- IntoIterator

impl<'a> IntoIterator for &'a PayloadInfo {
    type Item = &'a PayloadInfo;
    type IntoIter = PayloadInfoIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}


//------------ PayloadInfoIter -----------------------------------------------

/// An iterator over origin information.
#[derive(Clone, Debug)]
pub struct PayloadInfoIter<'a> {
    info: Option<&'a PayloadInfo>,
}

impl<'a> Iterator for PayloadInfoIter<'a> {
    type Item = &'a PayloadInfo;

    fn next(&mut self) -> Option<Self::Item> {
        let res = self.info?;
        self.info = res.tail.as_ref().map(AsRef::as_ref);
        Some(res)
    }
}


//------------ PublishInfo ---------------------------------------------------

/// Information about the published object payload came from.
#[derive(Clone, Debug)]
pub struct PublishInfo {
    /// The TAL the ROA is derived from.
    pub tal: Arc<TalInfo>,

    /// The rsync URI identifying the ROA.
    pub uri: Option<uri::Rsync>,

    /// The validity of the ROA itself.
    pub roa_validity: Validity,

    /// The validity of the validation chain.
    pub chain_validity: Validity,
}

impl PublishInfo {
    /// Creates a new origin info from the EE certificate of a ROA
    fn signed_object(cert: &ResourceCert, ca_validity: Validity) -> Self {
        PublishInfo {
            tal: cert.tal().clone(),
            uri: cert.signed_object().cloned().map(|mut uri| {
                uri.unshare(); uri
            }),
            roa_validity: cert.validity(),
            chain_validity: cert.validity().trim(ca_validity),
        }
    }

    fn ee_cert(cert: &Cert, uri: &uri::Rsync, ca_cert: &CaCert) -> Self {
        PublishInfo {
            tal: ca_cert.cert().tal().clone(),
            uri: Some(uri.clone()),
            roa_validity: cert.validity(),
            chain_validity: cert.validity().trim(ca_cert.combined_validity())
        }
    }

}


//============ Part Four. The Attic ==========================================

/// Returns the keys in `this` that are not in `other` as a vec.
fn added_keys<K: Clone + Hash + Eq, V>(
    this: &HashMap<K, V>, other: &HashMap<K, V>
) -> Vec<K> {
    this.keys().filter(|key| !other.contains_key(key)).cloned().collect()
}


//============ Appendix One. The Tests =======================================

#[cfg(test)]
mod test {
    use std::str::FromStr;
    use super::*;

    fn make_prefix(s: &str, l: u8) -> addr::Prefix {
        addr::Prefix::new(s.parse().unwrap(), l).unwrap()
    }

    #[test]
    fn address_prefix_covers_v4() {
        let outer = make_prefix("10.0.0.0", 16);
        let host_roa = make_prefix("10.0.0.0", 32);
        let sibling = make_prefix("10.1.0.0", 16);
        let inner_low = make_prefix("10.0.0.0", 24);
        let inner_mid = make_prefix("10.0.61.0", 24);
        let inner_hi = make_prefix("10.0.255.0", 24);
        let supernet = make_prefix("10.0.0.0", 8);

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
    fn address_prefix_covers_v6() {
        let outer = make_prefix("2001:db8::", 32);
        let host_roa = make_prefix("2001:db8::", 128);
        let sibling = make_prefix("2001:db9::", 32);
        let inner_low = make_prefix("2001:db8::", 48);
        let inner_mid = make_prefix("2001:db8:8000::", 48);
        let inner_hi = make_prefix("2001:db8:FFFF::", 48);
        let supernet = make_prefix("2001::", 24);

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

    #[test]
    #[allow(clippy::mutable_key_type)]
    fn payload_delta_construct() {
        fn origin(as_id: u32, prefix: &str, max_len: u8) -> Payload {
            RouteOrigin::new(
                addr::MaxLenPrefix::new(
                    addr::Prefix::from_str(prefix).unwrap(),
                    Some(max_len)
                ).unwrap(),
                as_id.into(),
            ).into()
        }
        let o0 = origin(10, "10.0.0.0/10", 10);
        let o1 = origin(11, "10.0.0.0/11", 11);
        let o2 = origin(12, "10.0.0.0/12", 12);
        let o3 = origin(13, "10.0.0.0/13", 13);
        let o4 = origin(14, "10.0.0.0/14", 14);

        let info = PayloadInfo::from(Arc::new(ExceptionInfo::default()));
        let mut current = SnapshotBuilder::default();
        current.payload.insert(o0.clone(), info.clone());
        current.payload.insert(o1.clone(), info.clone());
        current.payload.insert(o2.clone(), info.clone());
        current.payload.insert(o3.clone(), info.clone());
        let mut next = SnapshotBuilder::default();
        next.payload.insert(o0, info.clone());
        next.payload.insert(o2, info.clone());
        next.payload.insert(o4.clone(), info);
        let delta = PayloadDelta::construct(
            &current, &next, 12.into()
        ).unwrap();

        assert_eq!(delta.serial, Serial::from(13));
        let mut add: HashSet<_> = delta.announce.into_iter().collect();
        let mut sub: HashSet<_> = delta.withdraw.into_iter().collect();

        assert!(add.remove(&o4));
        assert!(add.is_empty());

        assert!(sub.remove(&o1));
        assert!(sub.remove(&o3));
        assert!(sub.is_empty());

        assert!(
            PayloadDelta::construct(&current, &current, 10.into()).is_none()
        );
    }

    #[test]
    fn fn_added_keys() {
        use std::iter::FromIterator;

        assert_eq!(
            added_keys(
                &HashMap::from_iter(
                    vec![(1, ()), (2, ()), (3, ()), (4, ())].into_iter()
                ),
                &HashMap::from_iter(
                    vec![(2, ()), (4, ()), (5, ())].into_iter()
                )
            ).into_iter().collect::<HashSet<_>>(),
            HashSet::from_iter(vec![1, 3].into_iter()),
        );
    }
}

