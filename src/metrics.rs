//! Monitoring metrics.

use std::{io, process};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTimeError};
use chrono::{DateTime, Utc};
use log::info;
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
}

impl Metrics {
    pub fn new() -> Self {
        Metrics {
            time: Utc::now(),
            tals: Vec::new(),
            rsync: Vec::new(),
            rrdp: Vec::new(),
            stale_count: AtomicU64::new(0),
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

    pub fn log(&self) {
        info!("Summary:");
        for tal in &self.tals {
            info!(
                "{}: {} valid ROAs, {} VRPs.",
                tal.tal.name(), tal.roas, tal.vrps
            )
        }
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

    /// Number of ROAs.
    pub roas: u32,

    /// Number of VRPs.
    pub vrps: u32,
}

impl TalMetrics {
    pub fn new(tal: Arc<TalInfo>) -> Self {
        TalMetrics {
            tal,
            roas: 0,
            vrps: 0
        }
    }
}


//------------ RrdpServerMetrics ---------------------------------------------

#[derive(Clone, Debug)]
pub struct RrdpServerMetrics {
    pub notify_uri: uri::Https,
    pub notify_status: Option<reqwest::StatusCode>,
    pub serial: Option<usize>,
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
