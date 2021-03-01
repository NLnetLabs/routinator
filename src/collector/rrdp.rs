/// Local repository copy synchronized with RRDP.

use std::{cmp, error, fmt, fs, io, mem};
use std::collections::{HashSet, HashMap};
use std::convert::{TryFrom, TryInto};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use bytes::Bytes;
use chrono::{DateTime, Utc, TimeZone};
use log::{debug, error, info, warn};
use reqwest::{Certificate, Proxy, StatusCode};
use reqwest::blocking::{Client, ClientBuilder, Response};
use ring::digest;
use ring::constant_time::verify_slices_are_equal;
use rpki::{rrdp, uri};
use rpki::rrdp::{NotificationFile, ProcessDelta, ProcessSnapshot, UriAndHash};
use sled::IVec;
use sled::transaction::{ConflictableTransactionError, TransactionError};
use uuid::Uuid;
use crate::config::Config;
use crate::error::Failed;
use crate::metrics::{Metrics, RrdpServerMetrics};
use crate::utils::UriExt;


///----------- Configuration Constants ---------------------------------------

/// The maximum size of a HTTP response for a trust anchor certificate.
const MAX_TA_SIZE: u64 = 64 * 1024;

/// The default timeout for RRDP requests.
///
/// This is mentioned in the man page. If you change it, also change it there.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);


//------------ Collector -----------------------------------------------------

/// The local copy of RPKI repositories synchronized via RRDP.
#[derive(Debug)]
pub struct Collector {
    /// The file tree of the database.
    object_tree: sled::Tree,

    /// A HTTP client.
    ///
    /// If this is `None`, we don’t actually do updates.
    http: Option<HttpClient>,

    /// Whether to filter dubious authorities in notify URIs.
    filter_dubious: bool,

    /// RRDP repository fallback timeout.
    ///
    /// This is the time since last an RRDP repository was last update 
    fallback_time: Duration,
}

impl Collector {
    /// Initializes the RRDP collector without creating a value.
    ///
    /// This function is called implicitely by [`new`][Self::new].
    pub fn init(_config: &Config) -> Result<(), Failed> {
        Ok(())
    }

    /// Creates a new RRDP collector.
    pub fn new(
        config: &Config, db: &sled::Db, update: bool
    ) -> Result<Option<Self>, Failed> {
        if config.disable_rrdp {
            return Ok(None)
        }

        Self::init(config)?;
        Ok(Some(Collector {
            object_tree: match db.open_tree("rrdp-objects") {
                Ok(tree) => tree,
                Err(err) => {
                    error!(
                        "Database error: \
                        failed to open RRDP data tree, {}",
                        err
                    );
                    return Err(Failed)
                }
            },
            http: if update {
                Some(HttpClient::new(config)?)
            }
            else {
                None
            },
            filter_dubious: !config.allow_dubious_hosts,
            fallback_time: config.rrdp_fallback_time,
        }))
    }

    /// Ignites the collector.
    pub fn ignite(&mut self) -> Result<(), Failed> {
        self.http.as_mut().map_or(Ok(()), HttpClient::ignite)
    }

    /// Starts a validation run using the collector.
    pub fn start(&self) -> Run {
        Run::new(self)
    }

    #[allow(clippy::mutable_key_type)]
    pub fn cleanup(&self, _retain: &HashSet<uri::Https>) {
        unimplemented!()
    }
}


//------------ Run -----------------------------------------------------------

/// Using the collector for a single validation run.
#[derive(Debug)]
pub struct Run<'a> {
    /// A reference to the underlying collector.
    collector: &'a Collector,

    /// A set of the repositories we have updated already.
    ///
    /// The value of the map is whether we consider the repository current.
    updated: RwLock<HashMap<uri::Https, bool>>,

    /// The modules that are currently being updated.
    ///
    /// The value in the map is a mutex that is used to synchronize competing
    /// attempts to update the module. Only the thread that has the mutex is
    /// allowed to actually run rsync.
    running: RwLock<HashMap<uri::Https, Arc<Mutex<()>>>>,
}

impl<'a> Run<'a> {
    /// Creates a new runner.
    fn new(collector: &'a Collector) -> Self {
        Run {
            collector,
            updated: Default::default(),
            running: Default::default(),
        }
    }

    /// Loads a trust anchor certificate identified by an HTTPS URI.
    pub fn load_ta(&self, uri: &uri::Https) -> Option<Bytes> {
        let http = match self.collector.http {
            Some(ref http) => http,
            None => return None,
        };
        let mut response = match http.response(uri) {
            Ok(response) => response,
            Err(_) => return None,
        };
        if response.content_length() > Some(MAX_TA_SIZE) {
            warn!(
                "Trust anchor certificate {} exceeds size limit of {} bytes. \
                 Ignoring.",
                uri, MAX_TA_SIZE
            );
            return None
        }
        let mut bytes = Vec::new();
        if let Err(err) = response.copy_to(&mut bytes) {
            info!("Failed to get trust anchor {}: {}", uri, err);
            return None
        }
        Some(Bytes::from(bytes))
    }

    /// Returns whether an RRDP repository has been updated already.
    ///
    /// This does not mean the repository is actually up-to-date or even
    /// available
    /// as an update may have failed.
    pub fn is_current(&self, notify_uri: &uri::Https) -> bool {
        // If updating is disabled, everything is already current.
        if self.collector.http.is_none() {
            return true
        }
        self.updated.read().unwrap().get(notify_uri).is_some()
    }

    /// Accesses an RRDP repository.
    ///
    /// This method blocks if the repository is deemed to need updating until
    /// the update has finished.
    ///
    /// Returns whether the repository can be used..
    pub fn load_repository(
        &self, rpki_notify: &uri::Https
    ) -> Result<bool, Failed> {
        // If we don’t update, just return whether we have a current copy.
        let http = match self.collector.http.as_ref() {
            Some(http) => http,
            None => return self.is_repository_current(rpki_notify)
        };

        // If we already tried updating, we can return already.
        if let Some(current) = self.updated.read().unwrap().get(rpki_notify) {
            return Ok(*current)
        }
        //
        // Get a clone of the (arc-ed) mutex. Make a new one if there isn’t
        // yet.
        let mutex = {
            self.running.write().unwrap()
            .entry(rpki_notify.clone()).or_default()
            .clone()
        };
        //
        // Acquire the mutex. Once we have it, see if the repository is
        // up-to-date which happens if someone else had it first.
        let _lock = mutex.lock().unwrap();
        if let Some(res) = self.updated.read().unwrap().get(rpki_notify) {
            return Ok(*res)
        }

        // Check if the repository URI is dubious. If so, skip updating and
        // reject the repository.
        let updated = if
            self.collector.filter_dubious
            && rpki_notify.has_dubious_authority()
        {
            warn!(
                "{}: Dubious host name. Not using the repository.",
                rpki_notify
            );
            false
        }
        else {
            let mut update = RepositoryUpdate::new(
                self.collector, http, rpki_notify
            );
            update.update()?
        };

        // If we have updated successfully, we are current. Otherwise it
        // depends if we (a) have a copy at all and (b) whether it is new
        // enough.
        let current = if updated {
            true
        }
        else {
            match self.collector.object_tree.get(rpki_notify)? {
                Some(data) => {
                    let duration = Utc::now().signed_duration_since(
                        RepositoryState::try_from(data)?.updated
                    );
                    match duration.to_std() {
                        Ok(duration) => {
                            duration < self.collector.fallback_time
                        }
                        Err(_) => false
                    }
                }
                None => false
            }
        };

        // Remove from running.
        self.running.write().unwrap().remove(rpki_notify);

        // Insert into updated map and also return.
        self.updated.write().unwrap().insert(rpki_notify.clone(), current);
        Ok(current)
    }

    fn is_repository_current(
        &self, _rpki_notify: &uri::Https
    ) -> Result<bool, Failed> {
        unimplemented!()
    }

    /// Loads the file for the given URI from the given repository.
    ///
    /// Does _not_ attempt to update the repository first but rather just
    /// returns whatever it has.
    pub fn load_file(
        &self,
        rpki_notify: &uri::Https,
        uri: &uri::Rsync,
    ) -> Result<Option<Bytes>, Failed> {
        match self.collector.object_tree.get(
            &ObjectKey::new(rpki_notify, uri).into_key()
        )? {
            Some(value) => {
                StoredObject::try_from(value).map(|obj| {
                    Some(obj.content)
                }).map_err(|_| {
                    error!("Encountered invalid object in RRDP database.");
                    Failed
                })
            }
            None => Ok(None)
        }
    }

    /// Finishes the validation run.
    ///
    /// Updates `metrics` with the collector run’s metrics.
    ///
    /// If you are not interested in the metrics, you can simple drop the
    /// value, instead.
    pub fn done(self, _metrics: &mut Metrics) {
        unimplemented!()
    }
}


//------------ RepositoryUpdate ----------------------------------------------

struct RepositoryUpdate<'a> {
    collector: &'a Collector,
    http: &'a HttpClient,
    rpki_notify: &'a uri::Https,
    metrics: RrdpServerMetrics,
}

impl<'a> RepositoryUpdate<'a> {
    fn new(
        collector: &'a Collector,
        http: &'a HttpClient,
        rpki_notify: &'a uri::Https,
    ) -> Self {
        RepositoryUpdate {
            collector, http, rpki_notify,
            metrics: RrdpServerMetrics::new(rpki_notify.clone())
        }
    }

    fn update(&mut self) -> Result<bool, Failed> {
        debug!("RRDP {}: Updating repository", self.rpki_notify);
        self.metrics.serial = None;
        let notify = self.http.notification_file(
            &self.rpki_notify, &mut self.metrics.notify_status
        )?;
        if self.delta_update(&notify)? {
            return Ok(true)
        }
        self.snapshot_update(&notify)
    }

    fn snapshot_update(
        &self,
        notify: &NotificationFile,
    ) -> Result<bool, Failed> {
        // We wipe the old repository data first. This may leave us with no
        // data at all, but that doesn’t matter since we have the last good
        // data in the store.
        for key in self.collector.object_tree.scan_prefix(
            ObjectKey::prefix(self.rpki_notify).into_key()
        ).keys() {
            let key = key?;
            self.collector.object_tree.remove(key)?;
        }

        let res = self.collector.object_tree.transaction(|tree| {
            self.snapshot_update_tran(notify, tree)?;
            Ok(())
        });

        match res {
            Ok(()) => Ok(true),
            Err(TransactionError::Abort(err)) => {
                warn!(
                    "RRDP {}: failed to process snapshot file {}: {}",
                    self.rpki_notify, notify.snapshot.uri(), err
                );
                Ok(false)
            }
            Err(TransactionError::Storage(err)) => {
                Err(err.into())
            }
        }
    }

    fn snapshot_update_tran(
        &self,
        notify: &NotificationFile,
        tree: &sled::transaction::TransactionalTree
    ) -> Result<(), SnapshotError> {
        debug!("RRDP {}: updating from snapshot.", self.rpki_notify);
        
        let mut processor = SnapshotProcessor::new(
            &notify, self.rpki_notify, tree
        );
        let mut reader = io::BufReader::new(HashRead::new(
            self.http.response(notify.snapshot.uri())?
        ));
        processor.process(&mut reader)?;
        let hash = reader.into_inner().into_hash();
        if verify_slices_are_equal(
            hash.as_ref(),
            notify.snapshot.hash().as_ref()
        ).is_err() {
            return Err(SnapshotError::HashMismatch)
        }

        tree.insert(
            self.rpki_notify.as_str(),
            &RepositoryState::from_notify(notify),
        )?;

        Ok(())
    }

    fn delta_update(
        &self,
        notify: &NotificationFile,
    ) -> Result<bool, Failed> {
        let state = match self.collector.object_tree.get(
            self.rpki_notify.as_str()
        )? {
            Some(state) => match RepositoryState::try_from(state) {
                Ok(state) => state,
                Err(_) => {
                    error!(
                        "RRDP Database error: \
                        cannot decode repository state for {}",
                        self.rpki_notify
                    );
                    return Err(Failed)
                }
            }
            None => return Ok(false)
        };

        let deltas = match Self::calc_deltas(notify, &state) {
            Some([]) => return Ok(true),
            Some(deltas) => deltas,
            None => return Ok(false),
        };

        for (serial, uri_and_hash) in deltas {
            if !self.delta_update_step(
                notify, *serial, uri_and_hash.uri(), uri_and_hash.hash()
            )? {
                info!(
                    "RRDP {}: Delta update failed, falling back to snapshot.",
                    self.rpki_notify
                );
                return Ok(false)
            }
        }

        debug!("RRDP {}: Delta update succeeded.", self.rpki_notify);
        Ok(true)
    }

    /// Calculates the slice of deltas to follow for updating.
    ///
    /// Returns an empty slice if no update is necessary.
    /// Returns a non-empty slice of the sequence of deltas to be applied.
    /// Returns `None` if updating via deltas is not possible.
    fn calc_deltas<'b>(
        notify: &'b NotificationFile,
        state: &RepositoryState
    ) -> Option<&'b [(u64, UriAndHash)]> {
        if notify.session_id != state.session {
            debug!("New session. Need to get snapshot.");
            return None
        }
        debug!("Serials: us {}, them {}", state.serial, notify.serial);
        if notify.serial == state.serial {
            return Some(&[]);
        }

        // If there is no last delta (remember, we have a different
        // serial than the notification file) or if the last delta’s
        // serial differs from that noted in the notification file,
        // bail out.
        if notify.deltas.last().map(|delta| delta.0) != Some(notify.serial) {
            debug!("Last delta serial differs from current serial.");
            return None
        }

        let mut deltas = notify.deltas.as_slice();
        let serial = match state.serial.checked_add(1) {
            Some(serial) => serial,
            None => return None
        };
        loop {
            let first = match deltas.first() {
                Some(first) => first,
                None => {
                    debug!("Ran out of deltas.");
                    return None
                }
            };
            match first.0.cmp(&serial) {
                cmp::Ordering::Greater => {
                    debug!("First delta is too new ({})", first.0);
                    return None
                }
                cmp::Ordering::Equal => break,
                cmp::Ordering::Less => deltas = &deltas[1..]
            }
        }
        Some(deltas)
    }

    /// Performs the update for a single delta.
    ///
    /// Returns `Ok(true)` if the update step succeeded, `Ok(false)` if the
    /// delta was faulty, and `Err(Failed)` if things have gone badly.
    fn delta_update_step(
        &self,
        notify: &NotificationFile,
        serial: u64,
        uri: &uri::Https,
        hash: rrdp::Hash,
    ) -> Result<bool, Failed> {
        let res = self.collector.object_tree.transaction(|tree| {
            self.delta_update_tran(notify, serial, uri, hash, tree)?;
            Ok(())
        });

        match res {
            Ok(()) => Ok(true),
            Err(TransactionError::Abort(err)) => {
                warn!(
                    "RRDP {}: failed to process delta: {}",
                    self.rpki_notify, err
                );
                Ok(false)
            }
            Err(TransactionError::Storage(err)) => {
                Err(err.into())
            }
        }
        
    }

    fn delta_update_tran(
        &self,
        notify: &NotificationFile,
        serial: u64,
        uri: &uri::Https,
        hash: rrdp::Hash,
        tree: &'a sled::transaction::TransactionalTree,
    ) -> Result<(), DeltaError> {
        let mut processor = DeltaProcessor::new(
            self.rpki_notify, notify.session_id, serial, tree
        );
        let mut reader = io::BufReader::new(HashRead::new(
            self.http.response(uri)?
        ));
        processor.process(&mut reader)?;
        let remote_hash = reader.into_inner().into_hash();
        if verify_slices_are_equal(
            remote_hash.as_ref(),
            hash.as_ref()
        ).is_err() {
            return Err(DeltaError::DeltaHashMismatch)
        }

        tree.insert(
            self.rpki_notify.as_str(),
            &RepositoryState::new(notify.session_id, serial),
        )?;

        Ok(())
    }
}


//------------ HttpClient ----------------------------------------------------

#[derive(Debug)]
struct HttpClient {
    client: Result<Client, Option<ClientBuilder>>,
}

impl HttpClient {
    pub fn new(config: &Config) -> Result<Self, Failed> {
        let mut builder = Client::builder();
        builder = builder.user_agent(&config.rrdp_user_agent);
        builder = builder.gzip(true);
        match config.rrdp_timeout {
            Some(Some(timeout)) => {
                builder = builder.timeout(timeout);
            }
            Some(None) => { /* keep no timeout */ }
            None => {
                builder = builder.timeout(DEFAULT_TIMEOUT);
            }
        }
        if let Some(timeout) = config.rrdp_connect_timeout {
            builder = builder.connect_timeout(timeout);
        }
        if let Some(addr) = config.rrdp_local_addr {
            builder = builder.local_address(addr)
        }
        for path in &config.rrdp_root_certs {
            builder = builder.add_root_certificate(
                Self::load_cert(path)?
            );
        }
        for proxy in &config.rrdp_proxies {
            let proxy = match Proxy::all(proxy) {
                Ok(proxy) => proxy,
                Err(err) => {
                    error!(
                        "Invalid rrdp-proxy '{}': {}", proxy, err
                    );
                    return Err(Failed)
                }
            };
            builder = builder.proxy(proxy);
        }
        Ok(HttpClient {
            client: Err(Some(builder)),
        })
    }

    pub fn ignite(&mut self) -> Result<(), Failed> {
        let builder = match self.client.as_mut() {
            Ok(_) => return Ok(()),
            Err(builder) => match builder.take() {
                Some(builder) => builder,
                None => {
                    error!("Previously failed to initialize HTTP client.");
                    return Err(Failed)
                }
            }
        };
        let client = match builder.build() {
            Ok(client) => client,
            Err(err) => {
                error!("Failed to initialize HTTP client: {}.", err);
                return Err(Failed)
            }
        };
        self.client = Ok(client);
        Ok(())
    }

    fn client(&self) -> &Client {
        self.client.as_ref().unwrap()
    }

    fn load_cert(path: &Path) -> Result<Certificate, Failed> {
        let mut file = match fs::File::open(path) {
            Ok(file) => file,
            Err(err) => {
                error!(
                    "Cannot open rrdp-root-cert file '{}': {}'",
                    path.display(), err
                );
                return Err(Failed);
            }
        };
        let mut data = Vec::new();
        if let Err(err) = io::Read::read_to_end(&mut file, &mut data) {
            error!(
                "Cannot read rrdp-root-cert file '{}': {}'",
                path.display(), err
            );
            return Err(Failed);
        }
        Certificate::from_pem(&data).map_err(|err| {
            error!(
                "Cannot decode rrdp-root-cert file '{}': {}'",
                path.display(), err
            );
            Failed
        })
    }

    pub fn response(
        &self,
        uri: &uri::Https
    ) -> Result<Response, reqwest::Error> {
        self.client().get(uri.as_str()).send()
    }

    pub fn notification_file(
        &self,
        uri: &uri::Https,
        status: &mut Option<StatusCode>,
    ) -> Result<NotificationFile, Failed> {
        let response = match self.response(uri) {
            Ok(response) => {
                *status = Some(response.status());
                response
            }
            Err(err) => {
                warn!("RRDP {}: {}", uri, err);
                *status = None;
                return Err(Failed);
            }
        };
        if !response.status().is_success() {
            warn!(
                "RRDP {}: Getting notification file failed with status {}",
                uri, response.status()
            );
            return Err(Failed);
        }
        match NotificationFile::parse(io::BufReader::new(response)) {
            Ok(mut res) => {
                res.deltas.sort_by_key(|delta| delta.0);
                Ok(res)
            }
            Err(err) => {
                warn!("RRDP {}: {}", uri, err);
                Err(Failed)
            }
        }
    }
}


//------------ SnapshotProcessor ---------------------------------------------

struct SnapshotProcessor<'a> {
    notify: &'a NotificationFile,
    rpki_notify: &'a uri::Https,
    tree: &'a sled::transaction::TransactionalTree,
}

impl<'a> SnapshotProcessor<'a> {
    fn new(
        notify: &'a NotificationFile,
        rpki_notify: &'a uri::Https,
        tree: &'a sled::transaction::TransactionalTree,
    ) -> Self {
        SnapshotProcessor { notify, rpki_notify, tree }
    }
}

impl<'a> ProcessSnapshot for SnapshotProcessor<'a> {
    type Err = SnapshotError;

    fn meta(
        &mut self,
        session_id: Uuid,
        serial: u64,
    ) -> Result<(), Self::Err> {
        if session_id != self.notify.session_id {
            return Err(SnapshotError::SessionMismatch {
                expected: self.notify.session_id,
                received: session_id
            })
        }
        if serial != self.notify.serial {
            return Err(SnapshotError::SerialMismatch {
                expected: self.notify.serial,
                received: serial
            })
        }
        Ok(())
    }

    fn publish(
        &mut self,
        uri: uri::Rsync,
        data: &mut rrdp::ObjectReader,
    ) -> Result<(), Self::Err> {
        let data = StoredObject::read_into_ivec(data)?;
        self.tree.insert(
            ObjectKey::new(self.rpki_notify, &uri).into_key(),
            data
        )?;
        Ok(())
    }
}


//------------ DeltaProcessor ------------------------------------------------

struct DeltaProcessor<'a> {
    rpki_notify: &'a uri::Https,
    session_id: Uuid,
    serial: u64,
    tree: &'a sled::transaction::TransactionalTree,
}

impl<'a> DeltaProcessor<'a> {
    fn new(
        rpki_notify: &'a uri::Https,
        session_id: Uuid,
        serial: u64,
        tree: &'a sled::transaction::TransactionalTree,
    ) -> Self {
        DeltaProcessor { rpki_notify, session_id, serial, tree }
    }

    fn check_hash(
        &self,
        uri: &uri::Rsync,
        hash: rrdp::Hash,
    ) -> Result<(), DeltaError> {
        let data = match self.tree.get(
            ObjectKey::new(self.rpki_notify, uri).into_key()
        )? {
            Some(data) => data,
            None => {
                return Err(DeltaError::MissingObject { uri: uri.clone() })
            }
        };
        let stored_hash = StoredObject::decode_hash(&data)?;
        if stored_hash != hash {
            Err(DeltaError::ObjectHashMismatch { uri: uri.clone() })
        }
        else {
            Ok(())
        }
    }

    fn check_new(
        &self,
        uri: &uri::Rsync
    ) -> Result<(), DeltaError> {
        if self.tree.get(
            ObjectKey::new(self.rpki_notify, uri).into_key()
        )?.is_some() {
            Err(DeltaError::ObjectAlreadyPresent { uri: uri.clone() })
        }
        else {
            Ok(())
        }
    }
}

impl<'a> ProcessDelta for DeltaProcessor<'a> {
    type Err = DeltaError;

    fn meta(
        &mut self, session_id: Uuid, serial: u64
    ) -> Result<(), Self::Err> {
        if session_id != self.session_id {
            return Err(DeltaError::SessionMismatch {
                expected: self.session_id,
                received: session_id
            })
        }
        if serial != self.serial {
            return Err(DeltaError::SerialMismatch {
                expected: self.serial,
                received: serial
            })
        }
        Ok(())
    }

    fn publish(
        &mut self,
        uri: uri::Rsync,
        hash: Option<rrdp::Hash>,
        data: &mut rrdp::ObjectReader<'_>
    ) -> Result<(), Self::Err> {
        // XXX We could also look at the result of the insert instead of
        //     runnning check_new if there is no hash. However, then we do
        //     all the decoding stuff which I think is more expensive than
        //     a quick lookup. Might be wrong, though.
        match hash {
            Some(hash) => self.check_hash(&uri, hash)?,
            None => self.check_new(&uri)?
        }
        let data = StoredObject::read_into_ivec(data)?;
        self.tree.insert(
            ObjectKey::new(self.rpki_notify, &uri).into_key(),
            data
        )?;
        Ok(())
    }

    fn withdraw(
        &mut self,
        uri: uri::Rsync,
        hash: rrdp::Hash
    ) -> Result<(), Self::Err> {
        self.check_hash(&uri, hash)?;
        self.tree.remove(
            ObjectKey::new(self.rpki_notify, &uri).into_key()
        )?;
        Ok(())
    }
}


//------------ RepositoryState -----------------------------------------------

#[derive(Clone, Debug)]
struct RepositoryState {
    /// The UUID of the current session of repository.
    pub session: Uuid,

    /// The serial number within the current session.
    pub serial: u64,

    /// The time of last update of the server.
    pub updated: DateTime<Utc>,
}

impl RepositoryState {
    pub fn from_notify(notify: &NotificationFile) -> Self {
        Self::new(notify.session_id, notify.serial)
    }

    pub fn new(session: Uuid, serial: u64) -> Self {
        RepositoryState {
            session, serial,
            updated: Utc::now()
        }
    }
}


//--- From and TryFrom

impl<'a> From<&'a RepositoryState> for IVec {
    fn from(state: &'a RepositoryState) -> IVec {
        let mut vec = Vec::new();

        // Version. 0u8
        vec.push(0u8);

        // The session as its bytes.
        vec.extend_from_slice(state.session.as_bytes());

        // The serial in network byte order.
        vec.extend_from_slice(&state.serial.to_be_bytes());

        // The update time as the i64 timestamp in network byte order.
        vec.extend_from_slice(&state.updated.timestamp().to_be_bytes());

        vec.into()
    }
}

impl TryFrom<IVec> for RepositoryState {
    type Error = StateError;

    fn try_from(stored: IVec) -> Result<Self, Self::Error> {
        const ENCODING_LEN: usize = {
            mem::size_of::<u8>() +
            mem::size_of::<uuid::Bytes>() +
            mem::size_of::<u64>() +
            mem::size_of::<i64>()
        };

        if stored.len() != ENCODING_LEN {
            return Err(StateError)
        }

        // Version. Must be 0u8.
        let (field, stored) = stored.split_at(mem::size_of::<u8>());
        if field != b"\0" {
            return Err(StateError)
        }

        // Session.
        let (field, stored) = stored.split_at(mem::size_of::<uuid::Bytes>());
        let session = Uuid::from_slice(field).unwrap();

        // Serial.
        let (field, stored) = stored.split_at(mem::size_of::<u64>());
        let serial = u64::from_be_bytes(field.try_into().unwrap());

        // Updated.
        let field = stored;
        let updated = Utc.timestamp(
            i64::from_be_bytes(field.try_into().unwrap()), 0
        );
        
        Ok(RepositoryState { session, serial, updated })
    }
}


//------------ ObjectKey -----------------------------------------------------

#[derive(Clone, Copy, Debug)]
struct ObjectKey<'a> {
    rpki_notify: &'a str,
    uri: &'a str
}

impl<'a> ObjectKey<'a> {
    fn new(rpki_notify: &'a uri::Https, uri: &'a uri::Rsync) -> Self {
        ObjectKey {
            rpki_notify: rpki_notify.as_str(),
            uri: uri.as_str()
        }
    }

    fn prefix(rpki_notify: &'a uri::Https) -> Self {
        ObjectKey {
            rpki_notify: rpki_notify.as_str(),
            uri: ""
        }
    }

    fn into_key(self) -> Vec<u8> {
        format!("{}\0{}", self.rpki_notify, self.uri).into()
    }
}


//------------ StoredObject --------------------------------------------------

#[derive(Clone, Debug)]
struct StoredObject<Octets> {
    /// The RRDP hash of the object.
    hash: rrdp::Hash,

    /// The content of the object.
    content: Octets,
}

impl StoredObject<()> {
    pub fn read_into_ivec(
        reader: &mut impl io::Read
    ) -> Result<IVec, io::Error> {
        let mut reader = HashRead::new(reader);
        let mut res = vec![0; mem::size_of::<rrdp::Hash>()];
        io::copy(&mut reader, &mut res)?;
        let hash = reader.into_hash();
        res[..hash.as_slice().len()].copy_from_slice(hash.as_slice());
        Ok(res.into())
    }

    pub fn decode_hash(stored: &[u8]) -> Result<rrdp::Hash, ObjectError> {
        const MIN_LEN: usize = {
            mem::size_of::<u8>() + mem::size_of::<rrdp::Hash>()
        };

        if stored.len() < MIN_LEN {
            return Err(ObjectError)
        }

        // Version. Must be 0u8.
        let (field, stored) = stored.split_at(mem::size_of::<u8>());
        if field != b"\0" {
            return Err(ObjectError)
        }

        // Hash
        let (field, _) = stored.split_at(mem::size_of::<rrdp::Hash>());
        let hash = rrdp::Hash::try_from(field).unwrap();

        Ok(hash)
    }
}


//--- From and TryFrom

impl<'a, Octets: AsRef<[u8]>> From<&'a StoredObject<Octets>> for IVec {
    fn from(src: &'a StoredObject<Octets>) -> Self {
        let mut vec = Vec::new();

        // Version. 0u8
        vec.push(0u8);
        
        // The hash as its bytes
        vec.extend_from_slice(src.hash.as_ref());

        // The content as its bytes.
        vec.extend_from_slice(src.content.as_ref());

        vec.into()
    }
}

impl TryFrom<IVec> for StoredObject<Bytes> {
    type Error = ObjectError;

    fn try_from(stored: IVec) -> Result<Self, Self::Error> {
        const MIN_LEN: usize = {
            mem::size_of::<u8>() + mem::size_of::<rrdp::Hash>()
        };

        if stored.len() < MIN_LEN {
            return Err(ObjectError)
        }

        // Version. Must be 0u8.
        let (field, stored) = stored.split_at(mem::size_of::<u8>());
        if field != b"\0" {
            return Err(ObjectError)
        }

        // Hash
        let (field, stored) = stored.split_at(mem::size_of::<rrdp::Hash>());
        let hash = rrdp::Hash::try_from(field).unwrap();

        // Content
        let content = Bytes::copy_from_slice(stored);

        Ok(StoredObject { hash, content })
    }
}


//------------ HashRead ------------------------------------------------------

pub struct HashRead<R> {
    reader: R,
    context: digest::Context,
}

impl<R> HashRead<R> {
    pub fn new(reader: R) -> Self {
        HashRead {
            reader,
            context: digest::Context::new(&digest::SHA256)
        }
    }

    pub fn into_hash(self) -> rrdp::Hash {
        rrdp::Hash::try_from(self.context.finish()).unwrap()
    }

    /*
    pub fn read_all(mut self) -> Result<rrdp::Hash, io::Error>
    where R: io::Read {
        let mut buf = [0u8; 4096];
        while io::Read::read(&mut self, &mut buf)? > 0 { }
        Ok(self.into_hash())
    }
    */
}


impl<R: io::Read> io::Read for HashRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        let res = self.reader.read(buf)?;
        self.context.update(&buf[..res]);
        Ok(res)
    }
}


//============ Errors ========================================================

//------------ SnapshotError -------------------------------------------------

#[derive(Debug)]
enum SnapshotError {
    Http(reqwest::Error),
    Rrdp(rrdp::ProcessError),
    SessionMismatch {
        expected: Uuid,
        received: Uuid
    },
    SerialMismatch {
        expected: u64,
        received: u64,
    },
    HashMismatch,
    Db(sled::transaction::UnabortableTransactionError),
}

impl From<reqwest::Error> for SnapshotError {
    fn from(err: reqwest::Error) -> Self {
        SnapshotError::Http(err)
    }
}

impl From<rrdp::ProcessError> for SnapshotError {
    fn from(err: rrdp::ProcessError) -> Self {
        SnapshotError::Rrdp(err)
    }
}

impl From<io::Error> for SnapshotError {
    fn from(err: io::Error) -> Self {
        SnapshotError::Rrdp(err.into())
    }
}

impl From<sled::transaction::UnabortableTransactionError> for SnapshotError {
    fn from(err: sled::transaction::UnabortableTransactionError) -> Self {
        SnapshotError::Db(err)
    }
}

impl From<SnapshotError> for ConflictableTransactionError<SnapshotError> {
    fn from(
        err: SnapshotError
    ) -> ConflictableTransactionError<SnapshotError> {
        match err {
            SnapshotError::Db(err) => err.into(),
            _ => ConflictableTransactionError::Abort(err),
        }
    }
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SnapshotError::Http(ref err) => err.fmt(f),
            SnapshotError::Rrdp(ref err) => err.fmt(f),
            SnapshotError::SessionMismatch { ref expected, ref received } => {
                write!(
                    f,
                    "session ID mismatch (notification_file: {}, \
                     snapshot file: {}",
                     expected, received
                )
            }
            SnapshotError::SerialMismatch { ref expected, ref received } => {
                write!(
                    f,
                    "serial number mismatch (notification_file: {}, \
                     snapshot file: {}",
                     expected, received
                )
            }
            SnapshotError::HashMismatch => {
                write!(f, "hash value mismatch")
            }
            SnapshotError::Db(ref err) => err.fmt(f),
        }
    }
}

impl error::Error for SnapshotError { }


//------------ DeltaError ----------------------------------------------------

#[derive(Debug)]
enum DeltaError {
    Http(reqwest::Error),
    Rrdp(rrdp::ProcessError),
    SessionMismatch {
        expected: Uuid,
        received: Uuid
    },
    SerialMismatch {
        expected: u64,
        received: u64,
    },
    MissingObject {
        uri: uri::Rsync,
    },
    ObjectAlreadyPresent {
        uri: uri::Rsync,
    },
    ObjectHashMismatch {
        uri: uri::Rsync,
    },
    DeltaHashMismatch,
    ObjectError,
    Db(sled::transaction::UnabortableTransactionError),
}

impl From<reqwest::Error> for DeltaError {
    fn from(err: reqwest::Error) -> Self {
        DeltaError::Http(err)
    }
}

impl From<rrdp::ProcessError> for DeltaError {
    fn from(err: rrdp::ProcessError) -> Self {
        DeltaError::Rrdp(err)
    }
}

impl From<io::Error> for DeltaError {
    fn from(err: io::Error) -> Self {
        DeltaError::Rrdp(err.into())
    }
}

impl From<ObjectError> for DeltaError {
    fn from(_: ObjectError) -> Self {
        DeltaError::ObjectError
    }
}

impl From<sled::transaction::UnabortableTransactionError> for DeltaError {
    fn from(err: sled::transaction::UnabortableTransactionError) -> Self {
        DeltaError::Db(err)
    }
}

impl From<DeltaError> for ConflictableTransactionError<DeltaError> {
    fn from(
        err: DeltaError
    ) -> ConflictableTransactionError<DeltaError> {
        match err {
            DeltaError::Db(err) => err.into(),
            _ => ConflictableTransactionError::Abort(err),
        }
    }
}

impl fmt::Display for DeltaError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DeltaError::Http(ref err) => err.fmt(f),
            DeltaError::Rrdp(ref err) => err.fmt(f),
            DeltaError::SessionMismatch { ref expected, ref received } => {
                write!(
                    f,
                    "session ID mismatch (notification_file: {}, \
                     snapshot file: {}",
                     expected, received
                )
            }
            DeltaError::SerialMismatch { ref expected, ref received } => {
                write!(
                    f,
                    "serial number mismatch (notification_file: {}, \
                     snapshot file: {}",
                     expected, received
                )
            }
            DeltaError::MissingObject { ref uri } => {
                write!(
                    f,
                    "reference to missing object {}",
                    uri
                )
            }
            DeltaError::ObjectAlreadyPresent { ref uri } => {
                write!(
                    f,
                    "attempt to add already present object {}",
                    uri
                )
            }
            DeltaError::ObjectHashMismatch { ref uri } => {
                write!(
                    f,
                    "local object {} has different hash",
                    uri
                )
            }
            DeltaError::DeltaHashMismatch => {
                write!(f, "delta file hash value mismatch")
            }
            DeltaError::ObjectError => {
                write!(f, "database error: failed to decode object")
            }
            DeltaError::Db(ref err) => err.fmt(f),
        }
    }
}

impl error::Error for DeltaError { }


//------------ StateError ----------------------------------------------------

/// Repository state cannot be decoded correctly.
#[derive(Clone, Copy, Debug)]
pub struct StateError;

impl From<StateError> for Failed {
    fn from(_: StateError) -> Self {
        error!("Database error: failed to decode object.");
        Failed
    }
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("repository state cannot be decoded")
    }
}

impl error::Error for StateError { }



//------------ ObjectError ---------------------------------------------------

/// A cached object cannot be decoded correctly.
#[derive(Clone, Copy, Debug)]
struct ObjectError;

impl fmt::Display for ObjectError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("cached object cannot be decoded")
    }
}

impl error::Error for ObjectError { }

