/// Payload data set derive from validation runs.
///
/// This module contains types to store the data derived from the RPKI
/// repository as well as complete sets of this data, diffs between
/// consecutive versions of such sets, and the history of sets and diffs.

use std::{cmp, error, fmt, ops};
use std::cmp::Ordering;
use std::collections::hash_map;
use std::collections::{HashMap, HashSet, VecDeque};
use std::convert::TryFrom;
use std::hash::Hash;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};
use chrono::{DateTime, Utc};
use crossbeam_queue::SegQueue;
use log::warn;
use rpki::repository::cert::ResourceCert;
use rpki::repository::resources::{
    AsId, IpBlock, IpBlocks, IpBlocksBuilder, Prefix
};
use rpki::repository::roa::{
    FriendlyRoaIpAddress, RouteOriginAttestation
};
use rpki::repository::tal::{Tal, TalInfo, TalUri};
use rpki::repository::x509::{Time, Validity};
use rpki::rtr::payload::{Action, Ipv4Prefix, Ipv6Prefix, Payload, Timing};
use rpki::rtr::server::VrpSource;
use rpki::rtr::state::{Serial, State};
use rpki::uri;
use serde::{Deserialize, Deserializer};
use crate::config::{Config, FilterPolicy};
use crate::engine::{CaCert, ProcessCa, ProcessRun};
use crate::error::Failed;
use crate::metrics::{Metrics, VrpMetrics};
use crate::slurm::{ExceptionInfo, LocalExceptions};


//============ Part One. During Validation ===================================
//
// The following types are used during a validation run to collect the
// valid published data.


//------------ ValidationReport ----------------------------------------------

/// The result of a validation run.
#[derive(Debug, Default)]
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
}

impl ValidationReport {
    /// Creates a new, empty validation report.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a> ProcessRun for &'a ValidationReport {
    type ProcessCa = PubPointProcessor<'a>;

    fn process_ta(
        &self,
        _tal: &Tal, _uri: &TalUri, cert: &CaCert,
        tal_index: usize,
    ) -> Result<Option<Self::ProcessCa>, Failed> {
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

impl<'a> ProcessCa for PubPointProcessor<'a> {
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

    fn process_roa(
        &mut self,
        _uri: &uri::Rsync,
        cert: ResourceCert,
        route: RouteOriginAttestation
    ) -> Result<(), Failed> {
        self.pub_point.update_refresh(cert.validity().not_after());
        self.pub_point.add_roa(
            route, Arc::new(RoaInfo::new(&cert, self.validity))
        );
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
    /// The list of valid ROA origins and their ROA information.
    origins: Vec<(RouteOrigin, Arc<RoaInfo>)>,

    /// The time when the publication point needs to be refreshed.
    refresh: Time,

    /// The index of the TALs for these origins in the metrics.
    tal_index: usize,

    /// The index of the repository containing these origins in the metrics.
    repository_index: Option<usize>,
}

impl PubPoint {
    /// Creates a new publication point for a trust anchor CA.
    fn new_ta(cert: &CaCert, tal_index: usize) -> Self {
        PubPoint {
            origins: Vec::new(),
            refresh: cert.cert().validity().not_after(),
            tal_index,
            repository_index: None,
        }
    }

    /// Creates a new publication for a regular CA.
    fn new_ca(parent: &PubPoint, cert: &CaCert) -> Self {
        PubPoint {
            origins: Vec::new(),
            refresh: cmp::min(
                parent.refresh, cert.cert().validity().not_after()
            ),
            tal_index: parent.tal_index,
            repository_index: None,
        }
    }

    /// Returns whether there is nothing published via this point.
    pub fn is_empty(&self) -> bool {
        self.origins.is_empty()
    }

    /// Updates the refresh time to be no later than the given time.
    fn update_refresh(&mut self, refresh: Time) {
        self.refresh = cmp::min(self.refresh, refresh)
    }

    /// Adds the content of a ROA to the origins.
    fn add_roa(
        &mut self,
        roa: RouteOriginAttestation,
        info: Arc<RoaInfo>,
    ) {
        self.origins.extend(roa.iter().map(|prefix| {
            (RouteOrigin::from_roa(roa.as_id(), prefix), info.clone())
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
    pub fn keep_prefix(&self, prefix: AddressPrefix) -> bool {
        if prefix.is_v4() {
            !self.v4.intersects_block(prefix)
        }
        else {
            !self.v6.intersects_block(prefix)
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
        history.current = Some(snapshot.into_snapshot().into());
        history.metrics = Some(metrics.into());
        if let Some(delta) = delta {
            history.push_delta(delta);
            true
        }
        else {
            // If we didn’t have a snapshot before, we added a version even
            // if there is no delta.
            current.is_none()
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


//--- VrpSource

impl VrpSource for SharedHistory {
    type FullIter = SnapshotVrpIter;
    type DiffIter = DeltaVrpIter;

    fn ready(&self) -> bool {
        self.read().is_active()
    }

    fn notify(&self) -> State {
        let read = self.read();
        State::from_parts(read.rtr_session(), read.serial())
    }

    fn full(&self) -> (State, Self::FullIter) {
        let read = self.read();
        (
            State::from_parts(read.rtr_session(), read.serial()),
            SnapshotVrpIter::new(read.current.clone().unwrap_or_default())
        )
    }

    fn diff(&self, state: State) -> Option<(State, Self::DiffIter)> {
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
        while let Some(delta) = iter.next() {
            // delta.serial() is the target serial of the detla, serial is
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
#[derive(Clone, Debug, Default)]
pub struct PayloadSnapshot {
    /// A list of route origins.
    ///
    /// This list contains an ordered sequence of unique origins.
    origins: Vec<(RouteOrigin, OriginInfo)>,

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

    /// Returns when this snapshot should be refreshed at the latest.
    ///
    /// Returns `None` if there is no known refresh time.
    fn refresh(&self) -> Option<Time> {
        self.refresh
    }

    /// Returns an slice of all the route origins.
    pub fn origins(&self) -> &[(RouteOrigin, OriginInfo)] {
        &self.origins
    }

    /// Returns a snapshot builder based in this snapshot.
    fn to_builder(&self) -> SnapshotBuilder {
        SnapshotBuilder {
            origins: self.origins.iter().cloned().collect(),
            refresh: self.refresh
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

    /// The position of the next item within the origins of the snapshot.
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
}

impl Iterator for SnapshotVrpIter {
    type Item = Payload;

    fn next(&mut self) -> Option<Self::Item> {
        let res = self.snapshot.origins.get(self.pos)?;
        self.pos += 1;
        Some(res.0.to_payload())
    }
}


//------------ SnapshotBuilder -----------------------------------------------

/// The representation of a snapshot during history updates.
#[derive(Clone, Debug, Default)]
struct SnapshotBuilder {
    /// A set of route origins.
    origins: HashMap<RouteOrigin, OriginInfo>,

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
        let mut res = Self::default();
        let rejected = report.rejected.finalize();

        // Process all publication points from the report.
        while let Some(pub_point) = report.pub_points.pop() {
            res.update_refresh(pub_point.refresh);
            let mut point_metrics = AllVrpMetrics::new(
                metrics, pub_point.tal_index, pub_point.repository_index
            );
            
            for (origin, roa_info) in pub_point.origins {
                point_metrics.update(|m| m.valid += 1);

                // Does the origih have rejected resources?
                if !rejected.keep_prefix(origin.prefix()) {
                    point_metrics.update(|m| m.marked_unsafe += 1);
                    if unsafe_vrps != FilterPolicy::Accept {
                        warn!(
                            "Filtering potentially unsafe VRP \
                             ({}/{}-{}, {})",
                            origin.address(),
                            origin.address_length(),
                            origin.max_length(),
                            origin.as_id()
                        );
                    }
                    if unsafe_vrps == FilterPolicy::Reject {
                        continue
                    }
                }

                // Is the origin to be filtered locally?
                if !exceptions.keep_origin(origin) {
                    point_metrics.update(|m| m.locally_filtered += 1);
                    continue
                }

                // Insert the origin. If we have it already, we need to
                // update its info instead.
                match res.origins.entry(origin) {
                    hash_map::Entry::Vacant(entry) => {
                        entry.insert(roa_info.into());
                        point_metrics.update(|m| m.contributed += 1);
                    }
                    hash_map::Entry::Occupied(mut entry) => {
                        entry.get_mut().add_roa(roa_info);
                        point_metrics.update(|m| m.duplicate += 1);
                    }
                }
            }
        }

        // Add the assertions from the local exceptions.
        for (origin, info) in exceptions.origin_assertions() {
            match res.origins.entry(origin) {
                hash_map::Entry::Vacant(entry) => {
                    entry.insert(info.into());
                    metrics.local.contributed += 1;
                    metrics.vrps.contributed += 1;
                }
                hash_map::Entry::Occupied(mut entry) => {
                    entry.get_mut().add_local(info);
                    metrics.local.duplicate += 1;
                    metrics.vrps.duplicate += 1;
                }
            }
        }

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
        let mut origins: Vec<_> = self.origins.into_iter().collect();
        origins.sort_by(|left, right| left.0.cmp(&right.0));
        PayloadSnapshot {
            origins,
            refresh: self.refresh
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
        metrics: &'a mut Metrics, tal_index: usize, repo_index: Option<usize>
    ) -> Self {
        AllVrpMetrics {
            tal: &mut metrics.tals[tal_index].vrps,
            repo: match repo_index {
                Some(index) => Some(&mut metrics.repositories[index].vrps),
                None => None
            },
            all: &mut metrics.vrps,
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

    /// Route origins to be added by this delta.
    ///
    /// The vec is ordered.
    announced_origins: Vec<RouteOrigin>,

    /// Route origins to be removed by this delta.
    ///
    /// This vec is orderd.
    withdrawn_origins: Vec<RouteOrigin>,
}

impl PayloadDelta {
    /// Constructs a new delta from a previous and a new snapshot.
    ///
    /// Returns `None` if the old and new snapshot are, in fact, identical.
    fn construct(
        current: &SnapshotBuilder, next: &SnapshotBuilder, serial: Serial
    ) -> Option<Self> {
        let announce = key_difference(&next.origins, &current.origins);
        let withdraw = key_difference(&current.origins, &next.origins);
        if !announce.is_empty() || !withdraw.is_empty() {
            Some(PayloadDelta {
                serial,
                announced_origins: announce,
                withdrawn_origins: withdraw,
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
            announced_origins: Vec::new(),
            withdrawn_origins: Vec::new(),
        }
    }

    /// Returns whether this is an empty delta.
    ///
    /// A delta is empty if there is nothing announced and nothing withdrawn.
    pub fn is_empty(&self) -> bool {
        self.announced_origins.is_empty() && self.withdrawn_origins.is_empty()
    }

    /// Returns the target serial number of the delta.
    pub fn serial(&self) -> Serial {
        self.serial
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

impl Iterator for DeltaVrpIter {
    type Item = (Action, Payload);

    fn next(&mut self) -> Option<Self::Item> {
        match self.pos {
            Ok(pos) => {
                match self.delta.announced_origins.get(pos) {
                    Some(res) => {
                        self.pos = Ok(pos + 1);
                        Some((Action::Announce, res.to_payload()))
                    }
                    None => {
                        self.pos = Err(0);
                        self.next()
                    }
                }
            }
            Err(pos) => {
                match self.delta.withdrawn_origins.get(pos) {
                    Some(res) => {
                        self.pos = Err(pos + 1);
                        Some((Action::Withdraw, res.to_payload()))
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

    /// The set of added route origins.
    announced_origins: HashSet<RouteOrigin>,

    /// The set of removed route origins.
    withdrawn_origins: HashSet<RouteOrigin>,
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
            announced_origins:
                delta.announced_origins.iter().cloned().collect(),
            withdrawn_origins:
                delta.withdrawn_origins.iter().cloned().collect(),
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
    fn merge(&mut self, delta: &PayloadDelta) {
        self.serial = delta.serial;
        for origin in &delta.announced_origins {
            if !self.withdrawn_origins.remove(origin) {
                self.announced_origins.insert(*origin);
            }
        }
        for origin in &delta.withdrawn_origins {
            if !self.announced_origins.remove(origin) {
                self.withdrawn_origins.insert(*origin);
            }
        }
    }

    /// Converts the merger into a delta.
    fn into_delta(self) -> Arc<PayloadDelta> {
        Arc::new(PayloadDelta {
            serial: self.serial,
            announced_origins: self.announced_origins.into_iter().collect(),
            withdrawn_origins: self.withdrawn_origins.into_iter().collect(),
        })
    }
}


//------------ RouteOrigin ---------------------------------------------------

/// A validated route origin authorization.
///
/// This is what RFC 6811 calls a ‘Validated ROA Payload.’ It consists of an
/// IP address prefix, a maximum length, and the origin AS number.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RouteOrigin {
    /// The origin AS number.
    as_id: AsId,

    /// The IP address prefix.
    prefix: AddressPrefix,

    /// The maximum authorized prefix length of a route.
    max_length: u8,
}

impl RouteOrigin {
    /// Creates a new route origin from its components.
    pub fn new(
        as_id: AsId,
        prefix: AddressPrefix,
        max_length: u8,
    ) -> Self {
        RouteOrigin { as_id, prefix, max_length }
    }

    /// Creates a new route origin from information from a ROA.
    fn from_roa(as_id: AsId, prefix: FriendlyRoaIpAddress) -> Self {
        Self::new(as_id, prefix.into(), prefix.max_length())
    }

    /// Returns the AS number authorized to originate a route.
    pub fn as_id(self) -> AsId {
        self.as_id
    }

    /// Returns the prefix of this authorization.
    pub fn prefix(self) -> AddressPrefix {
        self.prefix
    }

    /// Returns the address part of the prefix of this authorization.
    pub fn address(self) -> IpAddr {
        self.prefix.address()
    }

    /// Returns the minimum prefix length of this authorization.
    pub fn address_length(self) -> u8 {
        self.prefix.address_length()
    }

    /// Returns the maximum prefix length of this authorization.
    pub fn max_length(self) -> u8 {
        self.max_length
    }

    /// Returns an RTR payload value for this route origin.
    pub fn to_payload(self) -> Payload {
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
}


//--- PartialOrd and Ord

impl PartialOrd for RouteOrigin {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RouteOrigin {
    fn cmp(&self, other: &Self) -> Ordering {
        // The sort order attempts to avoid races in consumers that don’t
        // apply changes atomically. It keeps more specifics first and the
        // same prefixes together.
        //
        // XXX This could probably be improved.
        match self.max_length.cmp(&other.max_length) {
            Ordering::Less => return Ordering::Greater,
            Ordering::Greater => return Ordering::Less,
            Ordering::Equal => { }
        }
        match self.prefix.cmp(&other.prefix) {
            Ordering::Less => return Ordering::Less,
            Ordering::Greater => return Ordering::Greater,
            Ordering::Equal => { }
        }
        self.as_id.cmp(&other.as_id)
    }
}


//------------ AddressPrefix -------------------------------------------------

/// An IP address prefix: an IP address and a prefix length.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
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


//--- From

impl From<FriendlyRoaIpAddress> for AddressPrefix {
    fn from(addr: FriendlyRoaIpAddress) -> Self {
        AddressPrefix {
            addr: addr.address(),
            len: addr.address_length(),
        }
    }
}

impl From<AddressPrefix> for IpBlock {
    fn from(src: AddressPrefix) -> Self {
        Prefix::new(src.addr, src.len).into()
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


//============ Part Three. Payload Source Information ========================
//
// Some output formats need information about the source of the information
// presented. This part contains the types for that.


//------------ OriginInfo ----------------------------------------------------

/// Information about the source of a route origin authorization.
#[derive(Clone, Debug)]
pub struct OriginInfo {
    /// The head of a linked list of origin infos.
    ///
    /// We are abusing `Result` here to distinguish between origins from ROAs
    /// and from local exceptions. If you squint real hard, this even kind of
    /// makes sense.
    head: Result<Arc<RoaInfo>, Arc<ExceptionInfo>>,

    /// The tail of the linked list.
    tail: Option<Box<OriginInfo>>,
}


impl OriginInfo {
    fn add_roa(&mut self, info: Arc<RoaInfo>) {
        self.tail = Some(Box::new(OriginInfo {
            head: Ok(info),
            tail: self.tail.take()
        }));
    }

    fn add_local(&mut self, info: Arc<ExceptionInfo>) {
        self.tail = Some(Box::new(OriginInfo {
            head: Err(info),
            tail: self.tail.take()
        }));
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
        self.head.as_ref().map(|info| info.validity).ok()
    }
}

impl From<Arc<RoaInfo>> for OriginInfo {
    fn from(src: Arc<RoaInfo>) -> Self {
        OriginInfo { head: Ok(src), tail: None }
    }
}

impl From<Arc<ExceptionInfo>> for OriginInfo {
    fn from(src: Arc<ExceptionInfo>) -> Self {
        OriginInfo { head: Err(src), tail: None }
    }
}


//------------ RoaInfo -------------------------------------------------------

/// Information about the ROA an origin came from.
#[derive(Clone, Debug)]
pub struct RoaInfo {
    /// The TAL the ROA is derived from.
    pub tal: Arc<TalInfo>,

    /// The rsync URI identifying the ROA.
    pub uri: Option<uri::Rsync>,

    /// The validity of the ROA.
    pub validity: Validity,
}

impl RoaInfo {
    /// Creates a new origin info from the EE certificate of a ROA
    fn new(cert: &ResourceCert, ca_validity: Validity) -> Self {
        RoaInfo {
            tal: cert.tal().clone(),
            uri: cert.signed_object().cloned().map(|mut uri| {
                uri.unshare(); uri
            }),
            validity: cert.validity().trim(ca_validity),
        }
    }
}


//============ Part Four. The Attic ==========================================

/// Returns the difference in keys between the two hash maps as a vec.
fn key_difference<K: Copy + Hash + Eq, V>(
    current: &HashMap<K, V>, next: &HashMap<K, V>
) -> Vec<K> {
    current.keys().filter(|key| next.contains_key(key)).cloned().collect()
}


//============ Appendix One. The Tests =======================================

#[cfg(test)]
mod test {
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

