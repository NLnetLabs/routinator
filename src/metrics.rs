//! Monitoring metrics.
//!
//! This module contains all types expressing metrics collected during a
//! validation run. For each such run, there is an associated value of type
//! [`Metrics`] that collects all metrics gathered during the run. Additional
//! types contain the metrics related to specific processed entities.

use std::{io, ops, process};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{
    AtomicU32, AtomicI64, AtomicU64, AtomicUsize, Ordering,
};
use std::sync::atomic::Ordering::Relaxed;
use std::time::{Duration, SystemTimeError};
use arc_swap::ArcSwap;
use chrono::{DateTime, TimeZone, Utc};
use rpki::uri;
use rpki::repository::tal::TalInfo;
use rpki::rtr::state::Serial;
use uuid::Uuid;
use crate::collector::{HttpStatus, SnapshotReason};
use crate::utils::sync::Mutex;


//------------ Metrics -------------------------------------------------------

/// The metrics collected during a validation run.
#[derive(Debug)]
pub struct Metrics {
    /// Time when these metrics have been collected.
    pub time: DateTime<Utc>,

    /// Rsync metrics.
    pub rsync: Vec<RsyncModuleMetrics>,

    /// RRDP metrics.
    pub rrdp: Vec<RrdpRepositoryMetrics>,

    /// Per-TAL metrics.
    pub tals: Vec<TalMetrics>,

    /// Per-repository metrics.
    pub repositories: Vec<RepositoryMetrics>,

    /// Overall publication metrics.
    pub publication: PublicationMetrics,

    /// Payload metrics for local exceptions.
    pub local: PayloadMetrics,

    /// Overall payload metrics.
    pub snapshot: SnapshotMetrics,
}

impl Metrics {
    /// Creates a new metrics value with default metrics.
    pub fn new() -> Self {
        Metrics {
            time: Utc::now(),
            rsync: Vec::new(),
            rrdp: Vec::new(),
            tals: Vec::new(),
            repositories: Vec::new(),
            publication: Default::default(),
            local: Default::default(),
            snapshot: Default::default(),
        }
    }

    /// Finalizes the metrics.
    pub fn finalize(&mut self) {
        for metric in &mut self.tals {
            metric.finalize();
        }
        for metric in &mut self.repositories {
            metric.finalize();
        }
        self.local.finalize();
        self.snapshot.finalize();
    }

    /// Returns the time the metrics were created as a Unix timestamp.
    pub fn timestamp(&self) -> i64 {
        self.time.timestamp()
    }

    /// Returns whether all rsync processes have completed successfully.
    pub fn rsync_complete(&self) -> bool {
        for metrics in &self.rsync {
            match metrics.status {
                Ok(status) if !status.success() => return false,
                Err(_) => return false,
                _ => { }
            }
        }
        true
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl AsRef<Self> for Metrics {
    fn as_ref(&self) -> &Self {
        self
    }
}


//------------ RrdpRepositoryMetrics -----------------------------------------

/// Metrics collected while updating an RRDP repository.
#[derive(Clone, Debug)]
pub struct RrdpRepositoryMetrics {
    /// The rpkiNotify URI of the RRDP repository.
    pub notify_uri: uri::Https,

    /// The status of requesting the notification file.
    pub notify_status: HttpStatus,

    /// The session ID of the last update.
    pub session: Option<Uuid>,

    /// The serial number of the last update.
    pub serial: Option<u64>,

    /// Was there a reason to fall back to using a snapshot?
    pub snapshot_reason: Option<SnapshotReason>,

    /// The status of requesting the last payload file.
    ///
    /// If multiple payload files had to be requested, for instance because
    /// multiple deltas needed applying, all the other ones had to have ended
    /// in a response with a 200 status code.
    ///
    /// A value of `None` means that no payload was requested because the
    /// repository was up-to-date.
    pub payload_status: Option<HttpStatus>,

    /// The duration of the last update.
    pub duration: Result<Duration, SystemTimeError>,
}

impl RrdpRepositoryMetrics {
    pub fn new(notify_uri: uri::Https) -> Self {
        RrdpRepositoryMetrics {
            notify_uri,
            notify_status: HttpStatus::Error,
            session: None,
            serial: None,
            snapshot_reason: None,
            payload_status: None,
            duration: Ok(Duration::from_secs(0))
        }
    }

    pub fn status(&self) -> HttpStatus {
        if self.notify_status.is_success() {
            if let Some(status) = self.payload_status {
                status
            }
            else {
                self.notify_status
            }
        }
        else {
            self.notify_status
        }
    }
}


//------------ RsyncModuleMetrics --------------------------------------------

/// Metrics collected while updating an rsync module.
#[derive(Debug)]
pub struct RsyncModuleMetrics {
    pub module: uri::Rsync,
    pub status: Result<process::ExitStatus, io::Error>,
    pub duration: Result<Duration, SystemTimeError>,
}


//------------ TalMetrics ----------------------------------------------------

/// Metrics for all publication points under a TAL.
#[derive(Clone, Debug)]
pub struct TalMetrics {
    /// The TAL.
    pub tal: Arc<TalInfo>,

    /// Publication metrics.
    pub publication: PublicationMetrics,

    /// The VRP metrics.
    pub payload: PayloadMetrics,
}

impl TalMetrics {
    pub fn new(tal: Arc<TalInfo>) -> Self {
        TalMetrics {
            tal,
            publication: Default::default(),
            payload: Default::default(),
        }
    }

    pub fn finalize(&mut self) {
        self.payload.finalize();
    }

    pub fn name(&self) -> &str {
        self.tal.name()
    }
}


//------------ RepositoryMetrics ---------------------------------------------

/// Metrics for all publication points in a repository.
#[derive(Clone, Debug)]
pub struct RepositoryMetrics {
    /// The repository URI as a string.
    pub uri: String,

    /// The publication metrics.
    pub publication: PublicationMetrics,

    /// The VRP metrics.
    pub payload: PayloadMetrics,
}

impl RepositoryMetrics {
    pub fn new(uri: String) -> Self {
        RepositoryMetrics {
            uri,
            publication: Default::default(),
            payload: Default::default(),
        }
    }

    pub fn finalize(&mut self) {
        self.payload.finalize();
    }
}


//------------ PublicationMetrics --------------------------------------------

/// Metrics regarding publication points and published objects.
#[derive(Clone, Debug, Default)]
pub struct PublicationMetrics {
    /// The number of valid publication points.
    pub valid_points: u32,

    /// The number of rejected publication points.
    pub rejected_points: u32,

    /// The number of valid manifests.
    pub valid_manifests: u32,

    /// The number of invalid manifests.
    pub invalid_manifests: u32,

    /// The number of premature manifests.
    pub premature_manifests: u32,

    /// The number of stale manifests.
    pub stale_manifests: u32,

    /// The number of missing manifests.
    pub missing_manifests: u32,

    /// The number of valid CRLs.
    pub valid_crls: u32,

    /// The number of invalid CRLs.
    pub invalid_crls: u32,

    /// The number of stale CRLs.
    pub stale_crls: u32,

    /// The number of stray CRLs.
    ///
    /// Stray CRLs are CRL objects appearing in publication points that are
    /// not referenced by the manifest’s EE certificate. They make a
    /// publication point invalid.
    pub stray_crls: u32,

    /// The number of valid CA certificates.
    pub valid_ca_certs: u32,

    /// The number of valid router certificates.
    pub valid_router_certs: u32,

    /// The number of invalid certificates.
    pub invalid_certs: u32,

    /// The number of valid ROAs.
    pub valid_roas: u32,

    /// The number of invalid ROAs.
    pub invalid_roas: u32,

    /// The number of valid GBRs.
    pub valid_gbrs: u32,

    /// The number of invald GBRs.
    pub invalid_gbrs: u32,

    /// The number of valid ASPA objects.
    pub valid_aspas: u32,

    /// The number of invalid ASPA objects.
    pub invalid_aspas: u32,

    /// The number of other objects.
    pub others: u32,
}

impl PublicationMetrics {
    /// Returns the number of stale objects.
    pub fn stale_objects(&self) -> u32 {
        self.stale_manifests + self.stale_crls
    }
}

impl ops::Add for PublicationMetrics {
    type Output = Self;

    fn add(mut self, other: Self) -> Self::Output {
        self += other;
        self
    }
}

impl<'a> ops::AddAssign<&'a Self> for PublicationMetrics {
    fn add_assign(&mut self, other: &'a Self) {
        self.valid_points += other.valid_points;
        self.rejected_points += other.rejected_points;

        self.valid_manifests += other.valid_manifests;
        self.invalid_manifests += other.invalid_manifests;
        self.premature_manifests += other.premature_manifests;
        self.stale_manifests += other.stale_manifests;
        self.missing_manifests += other.missing_manifests;
        self.valid_crls += other.valid_crls;
        self.invalid_crls += other.invalid_crls;
        self.stale_crls += other.stale_crls;
        self.stray_crls += other.stray_crls;

        self.valid_ca_certs += other.valid_ca_certs;
        self.valid_router_certs += other.valid_router_certs;
        self.invalid_certs += other.invalid_certs;
        self.valid_roas += other.valid_roas;
        self.invalid_roas += other.invalid_roas;
        self.valid_gbrs += other.valid_gbrs;
        self.invalid_gbrs += other.invalid_gbrs;
        self.valid_aspas += other.valid_aspas;
        self.invalid_aspas += other.invalid_aspas;
        self.others += other.others;
    }
}

impl ops::AddAssign for PublicationMetrics {
    fn add_assign(&mut self, other: Self) {
        self.add_assign(&other)
    }
}


//------------ SnapshotMetrics -----------------------------------------------

/// Metrics regarding the full payload set.
#[derive(Clone, Debug, Default)]
pub struct SnapshotMetrics {
    /// Payload metrics portion.
    pub payload: PayloadMetrics,

    /// The number of ASPA customer ASNs that had too large ASPAs.
    ///
    /// This number is subtracted from `payload.aspa.valid` through the
    /// `finalize` method, so you don’t have to do that yourself.
    pub large_aspas: u32,
}

impl SnapshotMetrics {
    /// Finalizes the metrics by summing up the generated attributes.
    pub fn finalize(&mut self) {
        self.payload.finalize();
        self.payload.aspas.valid =
            self.payload.aspas.valid.saturating_sub(self.large_aspas);
    }
}


//------------ PayloadMetrics ------------------------------------------------

/// Metrics regarding the generated payload set.
#[derive(Clone, Debug, Default)]
pub struct PayloadMetrics {
    /// The metrics for IPv4 prefix origins.
    pub v4_origins: VrpMetrics,

    /// The metrics for IPv6 prefix origins.
    pub v6_origins: VrpMetrics,

    /// The metrics for all prefix origins.
    pub origins: VrpMetrics,

    /// The metrics for router keys.
    pub router_keys: VrpMetrics,

    /// The metrics for ASPA payload.
    pub aspas: VrpMetrics,

    /// The number of ASPA payload that was too large.
    pub large_aspas: u32,

    /// The metrics for all payload items.
    pub all: VrpMetrics,
}

impl PayloadMetrics {
    /// Finalizes the metrics by summing up the generated attributes.
    pub fn finalize(&mut self) {
        self.origins = self.v4_origins.clone();
        self.origins += &self.v6_origins;
        self.all = self.origins.clone();
        self.all += &self.router_keys;
        self.all += &self.aspas;
    }

    /// Returns the metrics for VRPs.
    ///
    /// There’s a method for this because we aren’t quite sure whether it
    /// is supposed to refer to `self.origins` or `self.all`. This way, we
    /// can easily switch.
    ///
    /// Currently, the method returns the metrics for origins.
    pub fn vrps(&self) -> &VrpMetrics {
        &self.origins
    }
}

impl ops::Add for PayloadMetrics {
    type Output = Self;

    fn add(mut self, other: Self) -> Self::Output {
        self += other;
        self
    }
}

impl<'a> ops::AddAssign<&'a Self> for PayloadMetrics {
    fn add_assign(&mut self, other: &'a Self) {
        self.v4_origins += &other.v4_origins;
        self.v6_origins += &other.v6_origins;
        self.origins += &other.origins;
        self.router_keys += &other.router_keys;
        self.aspas += &other.aspas;
        self.all += &other.all;
    }
}

impl ops::AddAssign for PayloadMetrics {
    fn add_assign(&mut self, other: Self) {
        self.add_assign(&other)
    }
}


//------------ VrpMetrics ----------------------------------------------------

/// Individual metrics regarding the generated payload.
///
/// Despite its name, this type is used for both VRPs and router keys.
#[derive(Clone, Debug, Default)]
pub struct VrpMetrics {
    /// The total number of valid VRPs.
    pub valid: u32,

    /// The number of VRPs overlapping with rejected publication points.
    pub marked_unsafe: u32,

    /// The number of VRPs filtered due to local exceptions.
    pub locally_filtered: u32,

    /// The number of duplicate VRPs.
    ///
    /// This number is only calculated after local filtering. If duplicates
    /// come from different publication points, the decision which are
    /// counted as valid and which are counted as duplicate depends on the
    /// order of processing. This number therefore has to be taken with a
    /// grain of salt.
    pub duplicate: u32,

    /// The total number of VRPs contributed to the final set.
    ///
    /// See the note on `duplicate_vrps` for caveats.
    pub contributed: u32,
}

impl ops::Add for VrpMetrics {
    type Output = Self;

    fn add(mut self, other: Self) -> Self::Output {
        self += other;
        self
    }
}

impl<'a> ops::AddAssign<&'a Self> for VrpMetrics {
    fn add_assign(&mut self, other: &'a Self) {
        self.valid += other.valid;
        self.marked_unsafe += other.marked_unsafe;
        self.locally_filtered += other.locally_filtered;
        self.duplicate += other.duplicate;
        self.contributed += other.contributed;
    }
}

impl ops::AddAssign for VrpMetrics {
    fn add_assign(&mut self, other: Self) {
        self.add_assign(&other)
    }
}


//------------ HttpServerMetrics ---------------------------------------------

#[derive(Debug, Default)]
pub struct HttpServerMetrics {
    conn_open: AtomicU64,
    conn_close: AtomicU64,
    bytes_read: AtomicU64,
    bytes_written: AtomicU64,
    requests: AtomicU64,
}

impl HttpServerMetrics {
    pub fn conn_open(&self) -> u64 {
        self.conn_open.load(Ordering::Relaxed)
    }

    pub fn inc_conn_open(&self) {
        self.conn_open.fetch_add(1, Ordering::Relaxed);
    }

    pub fn conn_close(&self) -> u64 {
        self.conn_close.load(Ordering::Relaxed)
    }

    pub fn inc_conn_close(&self) {
        self.conn_close.fetch_add(1, Ordering::Relaxed);
    }

    pub fn bytes_read(&self) -> u64 {
        self.bytes_read.load(Ordering::Relaxed)
    }

    pub fn inc_bytes_read(&self, count: u64) {
        self.bytes_read.fetch_add(count, Ordering::Relaxed);
    }

    pub fn bytes_written(&self) -> u64 {
        self.bytes_written.load(Ordering::Relaxed)
    }

    pub fn inc_bytes_written(&self, count: u64) {
        self.bytes_written.fetch_add(count, Ordering::Relaxed);
    }

    pub fn requests(&self) -> u64 {
        self.requests.load(Ordering::Relaxed)
    }

    pub fn inc_requests(&self) {
        self.requests.fetch_add(1, Ordering::Relaxed);
    }
}


//------------ RtrServerMetrics ----------------------------------------------

/// The metrics for the RTR server.
pub struct RtrServerMetrics {
    /// The global metrics over all connections.
    global: Arc<RtrMetricsData>,

    /// The per-client address metrics.
    ///
    /// If this is `None`, per-client metrics are disabled.
    client: Option<RtrPerAddrMetrics>,
}

impl RtrServerMetrics {
    /// Creates a new RTR server metrics value.
    ///
    /// If `detailed` is `true` per-client statistics should be produced when
    /// presenting the metrics.
    pub fn new(detailed: bool) -> Self {
        Self {
            global: Default::default(),
            client: detailed.then(|| Default::default())
        }
    }

    /// Returns a client metrics value for the given address.
    pub fn get_client(&self, addr: IpAddr) -> RtrClientMetrics {
        RtrClientMetrics {
            global: self.global.clone(),
            client: self.client.as_ref().map(|client| client.get(addr)),
        }
    }

    /// Returns the global metrics.
    pub fn global(&self) -> Arc<RtrMetricsData> {
        self.global.clone()
    }

    /// Returns an iterator over the per-client metrics if enabled.
    pub fn clients(
        &self
    ) -> Option<Arc<Vec<(IpAddr, Arc<RtrMetricsData>)>>> {
        self.client.as_ref().map(|client| client.addrs.load().clone())
    }
}


//------------ RtrPerAddrMetrics ---------------------------------------------

/// A map of metrics per client address.
#[derive(Default)]
pub struct RtrPerAddrMetrics {
    addrs: ArcSwap<Vec<(IpAddr, Arc<RtrMetricsData>)>>,
    write: Mutex<()>,
}

impl RtrPerAddrMetrics {
    /// Returns the metrics data for the given address.
    fn get(&self, addr: IpAddr) -> Arc<RtrMetricsData> {
        // See if we have that address already.
        let addrs = self.addrs.load();
        if let Ok(idx) = addrs.binary_search_by(|x| x.0.cmp(&addr)) {
            return addrs[idx].1.clone()
        }

        // We don’t. Create a new slice with the address included.
        let _write = self.write.lock();

        // Re-load self.addrs, it may have changed since.
        let addrs = self.addrs.load();
        let idx = match addrs.binary_search_by(|x| x.0.cmp(&addr)) {
            Ok(idx) => return addrs[idx].1.clone(),
            Err(idx) => idx,
        };

        // Make a new self.addrs, by placing the new item in the right spot,
        // it’ll be automatically sorted.
        let mut new_addrs = Vec::with_capacity(addrs.len() + 1);
        new_addrs.extend_from_slice(&addrs[..idx]);
        new_addrs.push((addr, Default::default()));
        new_addrs.extend_from_slice(&addrs[idx..]);
        let res = new_addrs[idx].1.clone();
        self.addrs.store(new_addrs.into());
        res
    }
}


//------------ RtrClientMetrics ----------------------------------------------

/// The metrics held by a connection.
#[derive(Debug)]
pub struct RtrClientMetrics {
    global: Arc<RtrMetricsData>,
    client: Option<Arc<RtrMetricsData>>,
}

impl RtrClientMetrics {
    /// Updates the client metrics.
    ///
    /// The method takes a closure that is run either once or twice, depending
    /// on whether per-client address metrics are enabled.
    pub fn update(&self, op: impl Fn(&RtrMetricsData)) {
        op(&self.global);
        if let Some(client) = self.client.as_ref() {
            op(client)
        }
    }
}


//------------ RtrMetricsData ------------------------------------------------

#[derive(Debug)]
pub struct RtrMetricsData {
    /// The number of currently open connections.
    open: AtomicUsize,

    /// The serial number of the last successful update.
    ///
    /// This is actually an option with the value of `u32::MAX` serving as
    /// `None`.
    serial: AtomicU32,

    /// The time the last successful update finished.
    ///
    /// This is an option of the unix timestamp. The value of `i64::MIN`
    /// serves as a `None`.
    updated: AtomicI64,

    /// The time the last successful cache reset finished.
    ///
    /// This is an option of the unix timestamp. The value of `i64::MIN`
    /// serves as a `None`.
    last_reset: AtomicI64,

    /// The number of successful reset queries.
    reset_queries: AtomicU32,

    /// The number of successful serial queries.
    serial_queries: AtomicU32,

    /// The number of bytes read.
    bytes_read: AtomicU64,

    /// The number of bytes written.
    bytes_written: AtomicU64,
}

impl Default for RtrMetricsData {
    fn default() -> Self {
        Self {
            open: AtomicUsize::new(0),
            serial: AtomicU32::new(u32::MAX),
            updated: AtomicI64::new(i64::MIN),
            last_reset: AtomicI64::new(i64::MIN),
            reset_queries: AtomicU32::new(0),
            serial_queries: AtomicU32::new(0),
            bytes_read: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
        }
    }
}

impl RtrMetricsData {
    /// Return the number of currently open connections.
    pub fn open(&self) -> usize {
        self.open.load(Relaxed)
    }

    /// Increases the count of open connections.
    pub fn inc_open(&self) {
        self.open.fetch_add(1, Relaxed);
    }

    /// Decreases the count of open connections.
    pub fn dec_open(&self) {
        self.open.fetch_sub(1, Relaxed);
    }

    /// Returns the serial number last seen.
    ///
    /// Returns `None` if no client has yet successfully retrieved data.
    pub fn serial(&self) -> Option<u32> {
        match self.serial.load(Relaxed) {
            u32::MAX => None,
            other => Some(other),
        }
    }

    /// A successful update with the given serial number has finished now.
    ///
    /// Updates the serial number and update time accordingly.
    pub fn update_now(&self, serial: Serial, reset: bool) {
        self.serial.store(serial.into(), Relaxed);
        self.updated.store(Utc::now().timestamp(), Relaxed);
        if reset {
            self.last_reset.store(Utc::now().timestamp(), Relaxed);
            self.reset_queries.fetch_add(1, Relaxed);
        }
        else {
            self.serial_queries.fetch_add(1, Relaxed);
        }
    }

    /// Returns the time of the last successful update.
    ///
    /// Returns `None` if there never was a successful update.
    pub fn updated(&self) -> Option<DateTime<Utc>> {
        match self.updated.load(Relaxed) {
            i64::MIN => None,
            other => Utc.timestamp_opt(other, 0).single()
        }
    }

    /// Returns the time of the last successful reset update.
    ///
    /// Returns `None` if there never was a successful update.
    pub fn last_reset(&self) -> Option<DateTime<Utc>> {
        match self.last_reset.load(Relaxed) {
            i64::MIN => None,
            other => Utc.timestamp_opt(other, 0).single()
        }
    }

    /// Returns the number of successful reset queries.
    pub fn reset_queries(&self) -> u32 {
        self.reset_queries.load(Relaxed)
    }

    /// Returns the number of successful serial queries.
    pub fn serial_queries(&self) -> u32 {
        self.serial_queries.load(Relaxed)
    }

    /// Returns the total number of bytes read from this client.
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read.load(Relaxed)
    }

    /// Increases the number of bytes read from this client.
    pub fn inc_bytes_read(&self, count: u64) {
        self.bytes_read.fetch_add(count, Relaxed);
    }

    /// Returns the total number of bytes written to this client.
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written.load(Relaxed)
    }

    /// Increases the number of bytes written to this client.
    pub fn inc_bytes_written(&self, count: u64) {
        self.bytes_written.fetch_add(count, Relaxed);
    }
}

