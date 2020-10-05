//! Monitoring metrics.

use std::{io, process};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTimeError};
use chrono::{DateTime, Utc};
use rpki::uri;
use rpki::tal::TalInfo;


//------------ Metrics -------------------------------------------------------

#[derive(Debug)]
pub struct Metrics {
    /// Time when these metrics have been collected.
    time: DateTime<Utc>,

    /// Per-TAL metrics.
    tals: Vec<TalMetrics>,

    /// Rsync metrics.
    rsync: Vec<RsyncModuleMetrics>,

    /// RRDP metrics.
    rrdp: Vec<RrdpServerMetrics>,

    /// Number of stale objects.
    stale_count: AtomicU64,

    /// Number of VRPs added from local exceptions.
    local_vrps: u32,

    /// Final number of VRPs.
    final_vrps: u32,
}

impl Metrics {
    pub fn new() -> Self {
        Metrics {
            time: Utc::now(),
            tals: Vec::new(),
            rsync: Vec::new(),
            rrdp: Vec::new(),
            stale_count: AtomicU64::new(0),
            local_vrps: 0,
            final_vrps: 0,
        }
    }

    pub fn stale_count(&self) -> u64 {
        self.stale_count.load(Ordering::Relaxed)
    }

    pub fn inc_stale_count(&self) {
        self.stale_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn push_tal(&mut self, tal: TalMetrics) {
        self.tals.push(tal)
    }

    pub fn set_rsync(
        &mut self,
        rsync: Vec<RsyncModuleMetrics>
    ) {
        self.rsync = rsync
    }

    pub fn set_rrdp(
        &mut self,
        rrdp: Vec<RrdpServerMetrics>
    ) {
        self.rrdp = rrdp
    }

    pub fn time(&self) -> DateTime<Utc> {
        self.time
    }

    pub fn timestamp(&self) -> i64 {
        self.time.timestamp()
    }

    pub fn set_tals(&mut self, tals: Vec<TalMetrics>) {
        self.tals = tals
    }

    pub fn tals(&self) -> &[TalMetrics] {
        &self.tals
    }

    pub fn rsync(&self) -> &[RsyncModuleMetrics] {
        &self.rsync
    }

    pub fn rrdp(&self) -> &[RrdpServerMetrics] {
        &self.rrdp
    }

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

    pub fn local_vrps(&self) -> u32 {
        self.local_vrps
    }

    pub fn inc_local_vrps(&mut self) {
        self.local_vrps += 1
    }

    pub fn final_vrps(&self) -> u32 {
        self.final_vrps
    }

    pub fn set_final_vrps(&mut self, count: u32) {
        self.final_vrps = count
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


//------------ TalMetrics ----------------------------------------------------

#[derive(Clone, Debug)]
pub struct TalMetrics {
    /// The TAL.
    pub tal: Arc<TalInfo>,

    /// Number of valid ROAs.
    pub roas: u32,

    /// Total number of valid VRPs.
    ///
    /// This is the total number of VRPs resulting from the validation run
    /// before any filtering is done. In particular, this number includes
    /// duplicate VRPs.
    pub total_valid_vrps: u32,

    /// Number of VRPs overlapping with rejected CAs.
    pub unsafe_vrps: u32,

    /// Number of VRPs filtered due to local exceptions.
    pub locally_filtered_vrps: u32,

    /// Number of duplicate VRPs.
    ///
    /// This number is only calculated after all filtering is done.
    pub duplicate_vrps: u32,

    /// Total number of VRPs in the final set.
    ///
    /// This is the number of unique valid VRPs minus filtered VRPs.
    pub final_vrps: u32,
}

impl TalMetrics {
    pub fn new(tal: Arc<TalInfo>) -> Self {
        TalMetrics {
            tal,
            roas: 0,
            total_valid_vrps: 0,
            unsafe_vrps: 0,
            locally_filtered_vrps: 0,
            duplicate_vrps: 0,
            final_vrps: 0,
        }
    }
}


//------------ RrdpServerMetrics ---------------------------------------------

#[derive(Clone, Debug)]
pub struct RrdpServerMetrics {
    pub notify_uri: uri::Https,
    pub notify_status: Option<reqwest::StatusCode>,
    pub serial: Option<u64>,
    pub duration: Result<Duration, SystemTimeError>,
}

impl RrdpServerMetrics {
    pub fn new(notify_uri: uri::Https) -> Self {
        RrdpServerMetrics {
            notify_uri,
            notify_status: None,
            serial: None,
            duration: Ok(Duration::from_secs(0))
        }
    }
}


//------------ RsyncModuleMetrics --------------------------------------------

#[derive(Debug)]
pub struct RsyncModuleMetrics {
    pub module: uri::RsyncModule,
    pub status: Result<process::ExitStatus, io::Error>,
    pub duration: Result<Duration, SystemTimeError>,
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
