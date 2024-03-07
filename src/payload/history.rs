//! The collection of data used to serve our clients.
//!
//! This is a private module. Its public types are re-exported by the parent
//! as needed.

use std::{cmp, ops};
use std::collections::VecDeque;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};
use chrono::{DateTime, Utc};
use log::info;
use rpki::rtr::{Serial, State, Timing};
use rpki::rtr::server::PayloadSource;
use crate::config::{Config, FilterPolicy};
use crate::metrics::Metrics;
use crate::slurm::LocalExceptions;
use super::delta::{DeltaArcIter, PayloadDelta};
use super::snapshot::{PayloadSnapshot, SnapshotArcIter};
use super::validation::ValidationReport;


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
        let snapshot = report.into_snapshot(
            exceptions, &mut metrics,
        );

        let (current, serial) = {
            let read = self.read();
            (read.current(), read.serial())
        };

        let delta = current.as_ref().and_then(|current| {
            PayloadDelta::construct(current, &snapshot, serial)
        });

        let mut history = self.write();
        history.metrics = Some(metrics.into());
        let res = if let Some(delta) = delta {
            // Data has changed.
            info!(
                "Delta with {} announced and {} withdrawn items.",
                delta.announce_len(),
                delta.withdraw_len(),
            );
            history.push_delta(delta);
            true
        }
        else if current.is_none() {
            // This is the first snapshot ever.
            true
        }
        else {
            // Nothing has changed.
            false
        };
        // Update the snapshot. The refresh time and object information may
        // have changed.
        history.current = Some(snapshot.into());
        res
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
    type Set = SnapshotArcIter;
    type Diff = DeltaArcIter;

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
            read.current.clone().unwrap_or_default().arc_iter(),
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
                delta.arc_iter(),
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
    /// The newest delta will be at the front of the queue. This delta will
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
    /// The history becomes active once the first validation has finished.
    pub fn is_active(&self) -> bool {
        self.current.is_some()
    }

    /// Returns a shareable reference to the current payload snapshot.
    ///
    /// If the history isn't active yet, returns `None`.
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
    /// The serial is what the requester has last seen. The method produces
    /// a delta from that version to the current version if it can. If it
    /// can't, this is either because it doesn't have enough history data or
    /// because the serial is actually in the future.
    ///
    /// The method returns an arc'd delta so it can return the delta from the
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

        let mut res = match iter.next() {
            Some(delta) => delta.clone(),
            None => return Some(Arc::new(PayloadDelta::empty(serial))),
        };
        for delta in iter {
            res = Arc::new(res.merge(delta));
        }

        Some(res)
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

    /// Returns the session and serial number of the current data set.
    pub fn session_and_serial(&self) -> (u64, Serial) {
        (self.session(), self.serial())
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

    /// Returns the unsafe VRP policy.
    pub fn unsafe_vrps(&self) -> FilterPolicy {
        self.unsafe_vrps
    }
}

