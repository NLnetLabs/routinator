//! Monitoring metrics.
//!
//! This module contains all types expressing metrics collected during a
//! validation run. For each such run, there is an associated value of type
//! [`Metrics`] that collects all metrics gathered during the run. Additional
//! types contain the metrics related to specific processed entities.

use std::{io, ops, process};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTimeError};
use chrono::{DateTime, Utc};
use rpki::uri;
use rpki::repository::tal::TalInfo;
use uuid::Uuid;


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

    /// VRP metrics for local exceptions.
    pub local: VrpMetrics,

    /// Overall VRP metrics.
    pub vrps: VrpMetrics,
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
            vrps: Default::default(),
        }
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

    /// The status code of requesting the notification file.
    pub notify_status: Option<reqwest::StatusCode>,

    /// The session ID of the last update.
    pub session: Option<Uuid>,

    /// The serial number of the last update.
    pub serial: Option<u64>,

    /// Was the last update attempt from a delta?
    pub delta: bool,

    /// The duration of the last update.
    pub duration: Result<Duration, SystemTimeError>,
}

impl RrdpRepositoryMetrics {
    pub fn new(notify_uri: uri::Https) -> Self {
        RrdpRepositoryMetrics {
            notify_uri,
            notify_status: None,
            session: None,
            serial: None,
            delta: false,
            duration: Ok(Duration::from_secs(0))
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
    pub vrps: VrpMetrics,
}

impl TalMetrics {
    pub fn new(tal: Arc<TalInfo>) -> Self {
        TalMetrics {
            tal,
            publication: Default::default(),
            vrps: Default::default(),
        }
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
    pub vrps: VrpMetrics,
}

impl RepositoryMetrics {
    pub fn new(uri: String) -> Self {
        RepositoryMetrics {
            uri,
            publication: Default::default(),
            vrps: Default::default(),
        }
    }
}


//------------ PublicationMetrics --------------------------------------------

/// Metrics regarding publication points and published objects.
#[derive(Clone, Debug, Default)]
pub struct PublicationMetrics {
    /// The number of publication points.
    pub valid_points: u32,

    /// The number of rejected publication points.
    pub rejected_points: u32,

    /// The number of valid manifests.
    pub valid_manifests: u32,

    /// The number of invalid manifests.
    pub invalid_manifests: u32,

    /// The number of stale manifest.
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

    /// The number of valid EE certificates.
    pub valid_ee_certs: u32,

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
        self.stale_manifests += other.stale_manifests;
        self.missing_manifests += other.missing_manifests;
        self.valid_crls += other.valid_crls;
        self.invalid_crls += other.invalid_crls;
        self.stale_crls += other.stale_crls;
        self.stray_crls += other.stray_crls;

        self.valid_ca_certs += other.valid_ca_certs;
        self.valid_ee_certs += other.valid_ee_certs;
        self.invalid_certs += other.invalid_certs;
        self.valid_roas += other.valid_roas;
        self.invalid_roas += other.invalid_roas;
        self.valid_gbrs += other.valid_gbrs;
        self.invalid_gbrs += other.invalid_gbrs;
        self.others += other.others;
    }
}

impl ops::AddAssign for PublicationMetrics {
    fn add_assign(&mut self, other: Self) {
        self.add_assign(&other)
    }
}


//------------ VrpMetrics ----------------------------------------------------

/// Metrics regarding the generated VRP set.
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
    /// come from different entitites, who get’s to contribute their VRP and
    /// whose gets filtered depends on the order of processing. This number
    /// therefore has to be taken with a grain of salt.
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


//------------ ServerMetrics -------------------------------------------------

#[derive(Debug, Default)]
pub struct ServerMetrics {
    rtr_conn_open: AtomicU64,
    rtr_conn_close: AtomicU64,
    rtr_bytes_read: AtomicU64,
    rtr_bytes_written: AtomicU64,

    http_conn_open: AtomicU64,
    http_conn_close: AtomicU64,
    http_bytes_read: AtomicU64,
    http_bytes_written: AtomicU64,
    http_requests: AtomicU64,
}

impl ServerMetrics {
    pub fn rtr_conn_open(&self) -> u64 {
        self.rtr_conn_open.load(Ordering::Relaxed)
    }

    pub fn inc_rtr_conn_open(&self) {
        self.rtr_conn_open.fetch_add(1, Ordering::Relaxed);
    }

    pub fn rtr_conn_close(&self) -> u64 {
        self.rtr_conn_close.load(Ordering::Relaxed)
    }

    pub fn inc_rtr_conn_close(&self) {
        self.rtr_conn_close.fetch_add(1, Ordering::Relaxed);
    }

    pub fn rtr_bytes_read(&self) -> u64 {
        self.rtr_bytes_read.load(Ordering::Relaxed)
    }

    pub fn inc_rtr_bytes_read(&self, count: u64) {
        self.rtr_bytes_read.fetch_add(count, Ordering::Relaxed);
    }

    pub fn rtr_bytes_written(&self) -> u64 {
        self.rtr_bytes_written.load(Ordering::Relaxed)
    }

    pub fn inc_rtr_bytes_written(&self, count: u64) {
        self.rtr_bytes_written.fetch_add(count, Ordering::Relaxed);
    }

    pub fn http_conn_open(&self) -> u64 {
        self.http_conn_open.load(Ordering::Relaxed)
    }

    pub fn inc_http_conn_open(&self) {
        self.http_conn_open.fetch_add(1, Ordering::Relaxed);
    }

    pub fn http_conn_close(&self) -> u64 {
        self.http_conn_close.load(Ordering::Relaxed)
    }

    pub fn inc_http_conn_close(&self) {
        self.http_conn_close.fetch_add(1, Ordering::Relaxed);
    }

    pub fn http_bytes_read(&self) -> u64 {
        self.http_bytes_read.load(Ordering::Relaxed)
    }

    pub fn inc_http_bytes_read(&self, count: u64) {
        self.http_bytes_read.fetch_add(count, Ordering::Relaxed);
    }

    pub fn http_bytes_written(&self) -> u64 {
        self.http_bytes_written.load(Ordering::Relaxed)
    }

    pub fn inc_http_bytes_written(&self, count: u64) {
        self.http_bytes_written.fetch_add(count, Ordering::Relaxed);
    }

    pub fn http_requests(&self) -> u64 {
        self.http_requests.load(Ordering::Relaxed)
    }

    pub fn inc_http_requests(&self) {
        self.http_requests.fetch_add(1, Ordering::Relaxed);
    }
}

