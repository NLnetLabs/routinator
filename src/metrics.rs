//! Monitoring metrics.

use std::sync::Arc;
use chrono::{DateTime, Utc};
use log::info;
use rpki::tal::TalInfo;
use rpki::uri::RsyncModule;
use crate::repository::RsyncMetrics;


//------------ Metrics -------------------------------------------------------

#[derive(Debug)]
pub struct Metrics {
    /// Time when these metrics have been collected.
    time: DateTime<Utc>,

    /// Per-TAL metrics.
    tals: Vec<TalMetrics>,

    /// Rsync metrics.
    rsync: Vec<(RsyncModule, RsyncMetrics)>,
}

impl Metrics {
    pub fn new() -> Self {
        Metrics {
            time: Utc::now(),
            tals: Vec::new(),
            rsync: Vec::new(),
        }
    }

    pub fn push_tal(&mut self, tal: TalMetrics) {
        self.tals.push(tal)
    }

    pub fn set_rsync(&mut self, rsync: Vec<(RsyncModule, RsyncMetrics)>) {
        self.rsync = rsync
    }

    pub fn time(&self) -> DateTime<Utc> {
        self.time
    }

    pub fn timestamp(&self) -> i64 {
        self.time.timestamp()
    }

    pub fn tals(&self) -> &[TalMetrics] {
        &self.tals
    }

    pub fn rsync(&self) -> &[(RsyncModule, RsyncMetrics)] {
        &self.rsync
    }

    pub fn rsync_complete(&self) -> bool {
        for (_, metrics) in &self.rsync {
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

