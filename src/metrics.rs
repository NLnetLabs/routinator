//! Monitoring metrics.
//!
//! This module contains all types expressing metrics collected during a
//! validation run. For each such run, there is an associated value of type
//! [`Metrics`] that collects all metrics gathered during the run. Additional
//! types contain the metrics related to specific processed entities.

use std::{cmp, io, ops, process, slice};
use std::iter::Peekable;
use std::net::IpAddr;
use std::sync::{Arc};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, SystemTimeError};
use chrono::{DateTime, TimeZone, Utc};
use rpki::uri;
use rpki::repository::tal::TalInfo;
use rpki::rtr::payload::Payload;
use rpki::rtr::state::Serial;
use tokio::sync::Mutex;
use uuid::Uuid;
use crate::collector::{HttpStatus, SnapshotReason};


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
    pub payload: PayloadMetrics,
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
            payload: Default::default(),
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
        self.payload.finalize();
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
        self.premature_manifests += other.premature_manifests;
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

    /// Returns a mutable reference to the metrics for the given payload.
    pub fn for_payload(&mut self, payload: &Payload) -> &mut VrpMetrics {
        match payload {
            Payload::Origin(ref origin) if origin.prefix.addr().is_ipv4() => {
                &mut self.v4_origins
            }
            Payload::Origin(_) => &mut self.v6_origins,
            Payload::RouterKey(_) => &mut self.router_keys,
        }
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


//------------ SharedRtrServerMetrics ----------------------------------------

/// A shareable wrapper around RTR server metrics.
///
/// This type provides access to a [`RtrServerMetrics`] object via a
/// reference counter and lock for concurrent access.
#[derive(Clone, Debug)]
pub struct SharedRtrServerMetrics {
    /// The actual metrics behind a thick, safe wall.
    metrics: Arc<Mutex<RtrServerMetrics>>,

    /// Do we want to publish detailed metrics?
    detailed: bool,
}

impl SharedRtrServerMetrics {
    /// Creates a new shareable value.
    ///
    /// If `detailed` is `true` per-client statistics should be produced when
    /// presenting the metrics.
    pub fn new(detailed: bool) -> Self {
        SharedRtrServerMetrics {
            metrics: Default::default(),
            detailed
        }
    }

    /// Add a new client to the metrics.
    ///
    /// This method locks the underlying metrics. The lock is acquired
    /// asynchronously. The method can thus be spawned as a new task.
    pub async fn add_client(&self, client: Arc<RtrClientMetrics>) {
        let mut metrics = self.metrics.lock().await;
        metrics.insert_client(client);
    }

    /// Returns whether detailed per-client statistics should be presented.
    pub fn detailed(&self) -> bool {
        self.detailed
    }

    /// Provides read access to the underlying server metrics.
    ///
    /// This method acquires the lock asynchronously.
    pub async fn read(
        &self
    ) -> impl ops::Deref<Target = RtrServerMetrics> + '_ {
        self.metrics.lock().await
    }
}


//------------ RtrServerMetrics ----------------------------------------------

/// Metrics regarding the operation of the RTR server.
///
/// This keeps a list of [`RtrClientMetrics`]. There is one element for each
/// currently open connection and at least one element for each address for
/// which there previously was a connection. Elements for recently closed
/// connections are only collected into single items for each address when a
/// new item is added (typically, when a new connection is opened), so there
/// may be multiple ‘closed’ elements for an address. There may be multiple
/// open elements for an address if there are multiple open connections from
/// the address.
///
/// The list is always ordered by address. Thus, if you iterate over the
/// list via [`iter_clients`][Self::iter_clients], all elements with the same
/// address will appear in an uninterrupted sequence. The
/// [`fold_clients`][Self::fold_clients] method can be used to produce an
/// iterator that walks over all addresses and creates a collated value for
/// each.
#[derive(Clone, Debug, Default)]
pub struct RtrServerMetrics {
    /// A list of client metrics.
    ///
    /// The vec will always be sorted by socket address. Each new connection
    /// inserts a new value. Closed connections (the `open` flag is `false`)
    /// will be collapsed into a single value ever so often.
    clients: Vec<Arc<RtrClientMetrics>>,
}

impl RtrServerMetrics {
    /// Returns the number of current connections.
    pub fn current_connections(&self) -> usize {
        self.clients.iter().filter(|client| client.is_open()).count()
    }

    /// Returns the total number of bytes read.
    pub fn bytes_read(&self) -> u64 {
        self.clients.iter().map(|client| client.bytes_read()).sum()
    }

    /// Returns the total number of bytes written.
    pub fn bytes_written(&self) -> u64 {
        self.clients.iter().map(|client| client.bytes_written()).sum()
    }

    /// Returns an iterator over all clients.
    ///
    /// There can be multiple elements for an address. However, these are
    /// guaranteed to be clustered together.
    pub fn iter_clients(
        &self
    ) -> impl Iterator<Item = &RtrClientMetrics> + '_ {
        self.clients.iter().map(AsRef::as_ref)
    }

    /// Returns an iterator over folded values for clients with same address.
    ///
    /// For each group of clients with the same address, the closure `fold`
    /// is run providing access to the client and the result of type `B`
    /// which will initialized with `init` for each group.
    pub fn fold_clients<'a, B, F>(
        &'a self, init: B, fold: F
    ) -> impl Iterator<Item = (IpAddr, B)> + 'a
    where
        B: Clone + 'a,
        F: FnMut(&mut B, &RtrClientMetrics) + 'a
    {
        FoldedRtrClientsIter::new(self, init, fold)
    }

    /// Inserts a new client into the metrics.
    ///
    /// Collapses multiple closed client metrics into a single one and
    /// inserts the new client metrics at the right place to keep the
    /// client list sorted.
    fn insert_client(&mut self, client: Arc<RtrClientMetrics>) {
        // XXX This can be optimised within the same vec. But this is a bit
        //     scary and I rather get it right for now.

        // See if we need to collapse the vec. This is true if there is more
        // than one closed item for an address.
        let mut collapse = false;
        let mut slice = self.clients.as_slice();
        while let Some((first, tail)) = slice.split_first() {
            slice = tail;
            if first.open.load(Ordering::Relaxed) {
                continue
            }
            for item in tail {
                if item.addr != first.addr {
                    break
                }
                if !item.open.load(Ordering::Relaxed) {
                    collapse = true;
                    break;
                }
            }
            if collapse {
                break
            }
        }

        if collapse {
            // Construct a new vec. Simply move all open clients over. For
            // closed clients, only keep one item with a sum. This item is
            // `pending` below. It is kept through the loop and moved to the
            // new vec whenever a new addr is encountered.
            // The new client is inserted when we encounter the first client
            // with an addr larger than the new client’s.
            let mut new_clients = Vec::new();
            let mut pending: Option<Arc<RtrClientMetrics>> = None;
            let mut client = Some(client);
            for item in self.clients.drain(..) {
                // Insert the new client the first time we see a larger addr.
                if let Some(addr) = client.as_ref().map(|c| c.addr) {
                    if addr < item.addr {
                        if let Some(client) = client.take() {
                            new_clients.push(client)
                        }
                    }
                }

                // Always keep open items.
                if item.open.load(Ordering::Relaxed) {
                    new_clients.push(item);
                    continue;
                }

                if let Some(pending_item) = pending.take() {
                    if pending_item.addr == item.addr {
                        pending = Some(
                            Arc::new(pending_item.collapse_closed(&item))
                        );
                    }
                    else {
                        new_clients.push(pending_item);
                        pending = Some(item);
                    }
                }
                else {
                    pending = Some(item);
                }
            }
            if let Some(pending) = pending.take() {
                new_clients.push(pending)
            }
            self.clients = new_clients;
        }
        else {
            // Insert the new client at the right point to keep the vec
            // ordered.
            let index = match self.clients.binary_search_by(|item| {
                item.addr.cmp(&client.addr)
            }) {
                Ok(index) => index + 1,
                Err(index) => index
            };
            self.clients.insert(index, client);
        }
    }
}


//------------ RtrClientMetrics ----------------------------------------------

/// Metrics about a single RTR client.
///
/// We consider all connections from a single IP address as a single client.
/// This may not always be strictly correct (think NAT), but seems a good way
/// to present information.
///
/// All information is stored in atomic values, so you can keep the metrics
/// behind an arc. All load and store operations are done with relaxed
/// ordering. This should be fine because in practice there is exactly one
/// writer (the RTR connection) and possibly many readers that present
/// information to the user only so there is no bad consequences if their
/// value is a bit behind.
#[derive(Debug)]
pub struct RtrClientMetrics {
    /// The socket address of the client.
    addr: IpAddr,

    /// Is this client currently connected?
    open: AtomicBool,

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

impl RtrClientMetrics {
    /// Create a new RTR client metrics value for the given address.
    pub fn new(addr: IpAddr) -> Self {
        RtrClientMetrics {
            addr,
            open: AtomicBool::new(true),
            serial: AtomicU32::new(u32::MAX),
            updated: AtomicI64::new(i64::MIN),
            last_reset: AtomicI64::new(i64::MIN),
            reset_queries: AtomicU32::new(0),
            serial_queries: AtomicU32::new(0),
            bytes_read: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
        }
    }

    /// Returns whether this client is currently open.
    pub fn is_open(&self) -> bool {
        self.open.load(Ordering::Relaxed)
    }

    /// Closes the client.
    pub fn close(&self) {
        self.open.store(false, Ordering::Relaxed)
    }

    /// Returns the total number of bytes read from this client.
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read.load(Ordering::Relaxed)
    }

    /// Increases the number of bytes read from this client.
    pub fn inc_bytes_read(&self, count: u64) {
        self.bytes_read.fetch_add(count, Ordering::Relaxed);
    }

    /// Returns the total number of bytes written to this client.
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written.load(Ordering::Relaxed)
    }

    /// Increases the number of bytes written to this client.
    pub fn inc_bytes_written(&self, count: u64) {
        self.bytes_written.fetch_add(count, Ordering::Relaxed);
    }

    /// Returns the serial number of the last successful update.
    ///
    /// Returns `None` if there never was a successful update.
    pub fn serial(&self) -> Option<Serial> {
        let serial = self.serial.load(Ordering::Relaxed);
        if serial == u32::MAX {
            None
        }
        else {
            Some(serial.into())
        }
    }

    /// Returns the time of the last successful update.
    ///
    /// Returns `None` if there never was a successful update.
    pub fn updated(&self) -> Option<DateTime<Utc>> {
        let updated = self.updated.load(Ordering::Relaxed);
        if updated == i64::MIN {
            None
        }
        else {
            Some(Utc.timestamp(updated, 0))
        }
    }

    /// Returns the time of the last successful reset update.
    ///
    /// Returns `None` if there never was a successful update.
    pub fn last_reset(&self) -> Option<DateTime<Utc>> {
        let updated = self.last_reset.load(Ordering::Relaxed);
        if updated == i64::MIN {
            None
        }
        else {
            Some(Utc.timestamp(updated, 0))
        }
    }

    /// Returns the number of successful reset queries.
    pub fn reset_queries(&self) -> u32 {
        self.reset_queries.load(Ordering::Relaxed)
    }

    /// Returns the number of successful serial queries.
    pub fn serial_queries(&self) -> u32 {
        self.serial_queries.load(Ordering::Relaxed)
    }

    /// A successful update with the given serial number has finished now.
    ///
    /// Updates the serial number and update time accordingly.
    pub fn update_now(&self, serial: Serial, reset: bool) {
        self.serial.store(serial.into(), Ordering::Relaxed);
        self.updated.store(Utc::now().timestamp(), Ordering::Relaxed);
        if reset {
            self.last_reset.store(Utc::now().timestamp(), Ordering::Relaxed);
            self.reset_queries.fetch_add(1, Ordering::Relaxed);
        }
        else {
            self.serial_queries.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Collapses the metrics of two values into a new one.
    ///
    /// The returned value will use the addr of `self` and will always be
    /// closed.
    fn collapse_closed(&self, other: &Self) -> Self {
        let left_serial = self.serial.load(Ordering::Relaxed);
        let right_serial = other.serial.load(Ordering::Relaxed);
        RtrClientMetrics {
            addr: self.addr,
            open: AtomicBool::new(false),
            serial: AtomicU32::new(
                if left_serial == u32::MAX {
                    right_serial
                }
                else if right_serial == u32::MAX {
                    left_serial
                }
                else {
                    cmp::max(left_serial, right_serial)
                }
            ),
            updated: AtomicI64::new(
                cmp::max(
                    self.updated.load(Ordering::Relaxed),
                    other.updated.load(Ordering::Relaxed)
                )
            ),
            last_reset: AtomicI64::new(
                cmp::max(
                    self.last_reset.load(Ordering::Relaxed),
                    other.last_reset.load(Ordering::Relaxed)
                )
            ),
            reset_queries: AtomicU32::new(
                self.reset_queries.load(Ordering::Relaxed)
                + other.reset_queries.load(Ordering::Relaxed)
            ),
            serial_queries: AtomicU32::new(
                self.serial_queries.load(Ordering::Relaxed)
                + other.serial_queries.load(Ordering::Relaxed)
            ),
            bytes_read: AtomicU64::new(
                self.bytes_read.load(Ordering::Relaxed)
                + other.bytes_read.load(Ordering::Relaxed)
            ),
            bytes_written: AtomicU64::new(
                self.bytes_written.load(Ordering::Relaxed)
                + other.bytes_written.load(Ordering::Relaxed)
            ),
        }
    }
}


//------------ FoldedRtrClientsIter ------------------------------------------

/// An iterator over groups of RTR clients in RTR server metrics.
///
/// A value to this type can be obtained via
/// [`RtrServerMetrics::fold_clients`].
struct FoldedRtrClientsIter<'a, B, F> {
    /// An iterator over the clients.
    clients: Peekable<slice::Iter<'a, Arc<RtrClientMetrics>>>,

    /// The initial value to use for each group.
    init: B,

    /// The fold function run for each client.
    fold_fn: F
}

impl<'a, B, F> FoldedRtrClientsIter<'a, B, F> {
    /// Creates a new value.
    fn new(metrics: &'a RtrServerMetrics, init: B, fold_fn: F) -> Self {
        FoldedRtrClientsIter {
            clients: metrics.clients.iter().peekable(),
            init,
            fold_fn
        }
    }
}

impl<'a, B, F> Iterator for FoldedRtrClientsIter<'a, B, F>
where
    B: Clone + 'a,
    F: FnMut(&mut B, &RtrClientMetrics) + 'a
{
    type Item = (IpAddr, B);

    fn next(&mut self) -> Option<Self::Item> {
        let first = self.clients.next()?;
        let addr = first.addr;
        let mut value = self.init.clone();
        (self.fold_fn)(&mut value, first);
        loop {
            match self.clients.peek() {
                Some(client) if client.addr == addr => {
                    let client = match self.clients.next() {
                        Some(client) => client,
                        None => break,
                    };
                    (self.fold_fn)(&mut value, client);
                }
                _ => break
            }
        }
        Some((addr, value))
    }
}


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn insert_rtr_metrics() {
        let addr1 = IpAddr::from_str("10.0.0.1").unwrap();
        let addr2 = IpAddr::from_str("10.0.0.2").unwrap();
        let addr3 = IpAddr::from_str("10.0.0.3").unwrap();
        let addr4 = IpAddr::from_str("10.0.0.4").unwrap();
        assert!(addr1 < addr2);
        assert!(addr2 < addr3);
        assert!(addr3 < addr4);

        fn client(addr: IpAddr) -> Arc<RtrClientMetrics> {
            RtrClientMetrics::new(addr).into()
        }

        fn assert_sequence(metrics: &RtrServerMetrics, addrs: &[IpAddr]) {
            assert_eq!(metrics.clients.len(), addrs.len());
            metrics.clients.iter().zip(addrs.iter()).for_each(|(m, a)| {
                assert_eq!(m.addr, *a);
            });
        }

        let mut metrics = RtrServerMetrics::default();
        metrics.insert_client(client(addr4));
        metrics.insert_client(client(addr2));
        metrics.insert_client(client(addr4));
        metrics.insert_client(client(addr3));
        assert_sequence(&metrics, &[addr2, addr3, addr4, addr4]);
        metrics.insert_client(client(addr3));
        metrics.insert_client(client(addr3));
        assert_sequence(&metrics, &[addr2, addr3, addr3, addr3, addr4, addr4]);
        metrics.clients[1].inc_bytes_read(10);
        metrics.clients[1].close();
        metrics.clients[1].inc_bytes_read(40);
        metrics.clients[3].close();
        metrics.clients[4].close();
        metrics.clients[5].close();
        metrics.insert_client(client(addr1));
        assert_sequence(&metrics, &[addr1, addr2, addr3, addr3, addr4]);
        let (open3, closed3) = if metrics.clients[2].is_open() {
            (&metrics.clients[2], &metrics.clients[3])
        }
        else {
            (&metrics.clients[3], &metrics.clients[2])
        };
        assert!(open3.is_open());
        assert!(!closed3.is_open());
        assert_eq!(open3.bytes_read(), 0);
        assert_eq!(closed3.bytes_read(), 50);
    }
}

