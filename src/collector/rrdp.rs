//! Local repository copy synchronized with RRDP.
//!
//! The RRDP collector works as follows:
//!
//! Data is kept in a sled database. This is normally the same database that
//! is used by the store. Each RRDP repository has one tree in that database whose
//! name is the repository’s rpkiNotify URI prefixed by `"rrdp:"`. The items
//! in that tree are the objects currently published keyed by their rsync URI.
//! The stored values contain both the raw content as well as the SHA-256
//! hash of the object so that we can quickly check the hash on update or
//! deletion.
//!
//! In addition, the current state of the repository is stored under the empty
//! key in its tree.

use std::{cmp, error, fmt, fs, io, mem};
use std::collections::{HashSet, HashMap};
use std::convert::{TryFrom, TryInto};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};
use bytes::Bytes;
use chrono::{DateTime, Utc, TimeZone};
use log::{debug, error, info, warn};
use reqwest::{Certificate, Proxy, StatusCode};
use reqwest::blocking::{Client, ClientBuilder, Response};
use rand::Rng;
use ring::digest;
use ring::constant_time::verify_slices_are_equal;
use rpki::{rrdp, uri};
use rpki::rrdp::{NotificationFile, ProcessDelta, ProcessSnapshot, UriAndHash};
use sled::IVec;
use uuid::Uuid;
use crate::config::Config;
use crate::error::Failed;
use crate::metrics::{Metrics, RrdpRepositoryMetrics};
use crate::utils::{JsonBuilder, UriExt};


///----------- Configuration Constants ---------------------------------------

/// The maximum size of a HTTP response for a trust anchor certificate.
const MAX_TA_SIZE: u64 = 64 * 1024;

/// The default timeout for RRDP requests.
///
/// This is mentioned in the man page. If you change it, also change it there.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// The key to store the repository state under.
const REPOSITORY_STATE_KEY: &[u8] = b"";


//------------ Collector -----------------------------------------------------

/// The local copy of RPKI repositories synchronized via RRDP.
#[derive(Debug)]
pub struct Collector {
    /// The database.
    db: sled::Db,

    /// The HTTP client.
    ///
    /// If this is `None`, we don’t actually do updates.
    http: Option<HttpClient>,

    /// Whether to filter dubious authorities in notify URIs.
    filter_dubious: bool,

    /// RRDP repository fallback timeout.
    ///
    /// This is the time since the last known update of an RRDP repository
    /// before it is considered non-existant.
    fallback_time: FallbackTime,
}

impl Collector {
    /// Creates a new RRDP collector.
    pub fn new(
        config: &Config, db: &sled::Db, update: bool
    ) -> Result<Option<Self>, Failed> {
        if config.disable_rrdp {
            return Ok(None)
        }

        Ok(Some(Collector {
            db: db.clone(),
            http: if update {
                Some(HttpClient::new(config)?)
            }
            else {
                None
            },
            filter_dubious: !config.allow_dubious_hosts,
            fallback_time: FallbackTime::from_config(config),
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

    /// Cleans up the RRDP collector.
    ///
    /// Deletes all RRDP repository trees that are not included in `retain`.
    #[allow(clippy::mutable_key_type)]
    pub fn cleanup(&self, retain: &HashSet<uri::Https>) -> Result<(), Failed> {
        for tree_name in self.db.tree_names() {
            if let Some(tree_uri) = Repository::tree_uri(&tree_name) {
                if !retain.contains(&tree_uri) {
                    debug!(
                        "RRDP {}: dropping tree.",
                        String::from_utf8_lossy(&tree_name)
                    ); 
                    self.db.drop_tree(tree_name)?;
                }
                else {
                    debug!(
                        "RRDP {}: keeping tree.",
                        String::from_utf8_lossy(&tree_name)
                    ); 
                }
            }
        }
        Ok(())
    }

    /// Dumps the content of the RRDP collector.
    pub fn dump(&self, dir: &Path) -> Result<(), Failed> {
        let dir = dir.join("rrdp");

        if let Err(err)  = fs::remove_dir_all(&dir) {
            if err.kind() != io::ErrorKind::NotFound {
                error!(
                    "Failed to delete directory {}: {}",
                    dir.display(), err
                );
                return Err(Failed)
            }
        }

        let mut repos = HashMap::new();

        for name in self.db.tree_names() {
            if !name.starts_with(b"rrdp:") {
                continue
            }

            let uri = match uri::Https::from_slice(&name[5..]) {
                Ok(uri) => uri,
                Err(_) => {
                    warn!(
                        "Invalid RRDP collector tree {}. Skipping.",
                        String::from_utf8_lossy(&name)
                    );
                    return Err(Failed);
                }
            };

            let repository = Repository::new(self, &uri)?;

            let state = repository.tree.get(
                REPOSITORY_STATE_KEY
            )?.and_then(|data| {
                match RepositoryState::try_from(data) {
                    Ok(state) => Some(state),
                    Err(_) => {
                        warn!(
                            "Failed to decode RRDP repository state for {}",
                            uri
                        );
                        None
                    }
                }
            });

            // Use the URI’s authority as the directory name, possibly
            // append a number to make it unique.
            let repo_dir_name = if !repos.contains_key(uri.authority()) {
                String::from(uri.authority())
            }
            else {
                let mut i = 1;
                loop {
                    let name = format!("{}-{}", uri.authority(), i);
                    if !repos.contains_key(&name) {
                        break name
                    }
                    i += 1
                }
            };
            let repo_dir = dir.join(&repo_dir_name);
            repos.insert(repo_dir_name, (uri, state));

            if let Err(err) = fs::create_dir_all(&repo_dir) {
                error!(
                    "Failed to create directory {}: {}",
                    repo_dir.display(),
                    err
                );
                return Err(Failed)
            }

            for (uri, content) in repository.iter_files() {
                self.dump_object(&repo_dir, &uri, &content)?;
            }
        }

        let mut repos: Vec<_> = repos.into_iter().collect();
        repos.sort_by(|left, right| left.0.cmp(&right.0));

        let json_path = dir.join("repositories.json");
        if let Err(err) = fs::write(
            &json_path, 
            &JsonBuilder::build(|builder| {
                builder.member_array("repositories", |builder| {
                    for (key, (uri, state)) in repos.iter() {
                        builder.array_object(|builder| {
                            builder.member_str(
                                "path",
                                key
                            );
                            builder.member_str("rpkiNotify", uri);
                            if let Some(state) = state {
                                builder.member_raw("serial", state.serial);
                                builder.member_str("session", state.session);
                                builder.member_str(
                                    "updated",
                                    state.updated.to_rfc3339()
                                );
                            }
                        })
                    }
                })
            })
        ) {
            error!( "Failed to write {}: {}", json_path.display(), err);
            return Err(Failed)
        }

        Ok(())
    }

    fn dump_object(
        &self, base_dir: &Path, uri: &uri::Rsync, data: &[u8]
    ) -> Result<(), Failed> {
        let path = base_dir.join(
            uri.canonical_authority().as_ref()
        ).join(uri.module_name()).join(uri.path());
        if let Some(path) = path.parent() {
            if let Err(err) = fs::create_dir_all(path) {
                error!(
                    "Failed to create directory {}: {}",
                    path.display(),
                    err
                );
                return Err(Failed)
            }
        }
        if let Err(err) = fs::write(&path, data) {
            error!(
                "Failed to write file {}: {}",
                path.display(),
                err
            );
            return Err(Failed)
        }
        Ok(())
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
    /// If there is some value for a repository, it is available and current.
    /// If there is a `None`, the repository is not available or outdated.
    updated: RwLock<HashMap<uri::Https, Option<Repository>>>,

    /// The modules that are currently being updated.
    ///
    /// The value in the map is a mutex that is used to synchronize competing
    /// attempts to update the module. Only the thread that has the mutex is
    /// allowed to actually run rsync.
    running: RwLock<HashMap<uri::Https, Arc<Mutex<()>>>>,

    /// The server metrics.
    metrics: Mutex<Vec<RrdpRepositoryMetrics>>,
}

impl<'a> Run<'a> {
    /// Creates a new runner.
    fn new(collector: &'a Collector) -> Self {
        Run {
            collector,
            updated: Default::default(),
            running: Default::default(),
            metrics: Mutex::new(Vec::new()),
        }
    }

    /// Loads a trust anchor certificate identified by an HTTPS URI.
    ///
    /// This just downloads the file. It is not cached since that is done
    /// by the store anyway.
    pub fn load_ta(&self, uri: &uri::Https) -> Option<Bytes> {
        let http = match self.collector.http {
            Some(ref http) => http,
            None => return None,
        };
        let mut response = match http.response(uri, false) {
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
    /// available as an update may have failed.
    pub fn was_updated(&self, notify_uri: &uri::Https) -> bool {
        // If updating is disabled, everything is considered as updated.
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
    /// If a repository is has been successfully updated during this run,
    /// returns it. Otherwise returns it if it is cached and that cached data
    /// is newer than the fallback time. Thus, if the method returns
    /// `Ok(None)`, you can fall back to rsync.
    pub fn load_repository(
        &self, rpki_notify: &uri::Https
    ) -> Result<Option<Repository>, Failed> {
        match self.collector.http.as_ref() {
            Some(http) => self.load_repository_updated(http, rpki_notify),
            None => self.load_repository_no_update(rpki_notify)
        }
    }

    /// Accesses an RRDP repository if updates are enabled.
    fn load_repository_updated(
        &self, http: &HttpClient, rpki_notify: &uri::Https
    ) -> Result<Option<Repository>, Failed> {
        // If we already tried updating, we can return already.
        if let Some(repo) = self.updated.read().unwrap().get(rpki_notify) {
            return Ok(repo.clone())
        }

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
            return Ok(res.clone())
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
            let updated = update.update()?;
            self.metrics.lock().unwrap().push(update.metrics);
            updated
        };

        // If we have updated successfully, we are current. Otherwise it
        // depends if we (a) have a copy at all and (b) whether it is new
        // enough.
        let current = if updated {
            true
        }
        else {
            self.is_repository_current(rpki_notify)?
        };

        // Remove from running.
        self.running.write().unwrap().remove(rpki_notify);

        let repository = if current {
            Some(Repository::new(
                self.collector, rpki_notify
            )?)
        }
        else {
            None
        };
        
        // Insert into updated map and also return.
        self.updated.write().unwrap().insert(
            rpki_notify.clone(), repository.clone()
        );
        Ok(repository)
    }

    /// Accesses an RRDP repository if updates are disabled.
    fn load_repository_no_update(
        &self, rpki_notify: &uri::Https
    ) -> Result<Option<Repository>, Failed> {
        if let Some(repo) = self.updated.read().unwrap().get(rpki_notify) {
            return Ok(repo.clone())
        }
        let repository = if self.is_repository_current(rpki_notify)? {
            Some(Repository::new(
                self.collector, rpki_notify
            )?)
        }
        else {
            None
        };
        
        // Insert into updated map and also return.
        self.updated.write().unwrap().insert(
            rpki_notify.clone(), repository.clone()
        );
        Ok(repository)
    }

    /// Returns whether a repository should be considered current.
    ///
    /// It is current if we have a copy of the repository and that copy has
    /// not yet expired.
    fn is_repository_current(
        &self, rpki_notify: &uri::Https
    ) -> Result<bool, Failed> {
        let tree = self.collector.db.open_tree(
            Repository::tree_name(rpki_notify)
        )?;
        match tree.get(REPOSITORY_STATE_KEY)? {
            Some(data) => Ok(!RepositoryState::try_from(data)?.is_expired()),
            None => Ok(false)
        }
    }

    /// Finishes the validation run.
    ///
    /// Updates `metrics` with the collector run’s metrics.
    ///
    /// If you are not interested in the metrics, you can simple drop the
    /// value, instead.
    pub fn done(self, metrics: &mut Metrics) {
        metrics.rrdp = self.metrics.into_inner().unwrap()
    }
}


//------------ Repository ----------------------------------------------------

/// Access to a single RRDP repository.
#[derive(Clone, Debug)]
pub struct Repository {
    /// The sled tree for the repository.
    tree: sled::Tree,
}

impl Repository {
    /// Creates a new value for the given rpkiNotify URI.
    fn new(
        collector: &Collector, rpki_notify: &uri::Https
    ) -> Result<Self, Failed> {
        Ok(Repository {
            tree: collector.db.open_tree(Repository::tree_name(rpki_notify))?
        })
    }

    /// Returns the tree name for the given rpkiNotify URI.
    fn tree_name(rpki_notify: &uri::Https) -> Vec<u8> {
        format!("rrdp:{}", rpki_notify).into()
    }

    /// Returns the rpkiNotify for a given RRDP tree name.
    ///
    /// If the tree name isn’t actually for an RRDP collector tree, returns
    /// `None`.
    fn tree_uri(tree_name: &[u8]) -> Option<uri::Https> {
        if tree_name.starts_with(b"rrdp:") {
            uri::Https::from_slice(&tree_name[5..]).ok()
        }
        else {
            None
        }
    }

    /// Loads an object from the repository.
    ///
    /// The object is identified by its rsync URI. If the object doesn’t
    /// exist, returns `None`.
    pub fn load_file(
        &self,
        uri: &uri::Rsync
    ) -> Result<Option<Bytes>, Failed> {
        match self.tree.get(uri.as_str())? {
            Some(value) => {
                RepositoryObject::try_from(value).map(|obj| {
                    Some(obj.content)
                }).map_err(|_| {
                    error!("Encountered invalid object in RRDP database.");
                    Failed
                })
            }
            None => Ok(None)
        }
    }

    /// Iterators over all the objects in the repository.
    ///
    /// Warns about broken objects but continues.
    pub fn iter_files(
        &self
    ) -> impl Iterator<Item = (uri::Rsync, Bytes)> {
        let mut failed = false;
        self.tree.iter().map(move |item| {
            let (key, value) = match item {
                Ok(item) => item,
                Err(err) => {
                    if !failed { 
                        warn!("Database error: {}", err);
                        failed = true;
                    }
                    return None
                }
            };
            if key == REPOSITORY_STATE_KEY {
                return None
            }
            let uri = match uri::Rsync::from_slice(&key) {
                Ok(uri) => uri,
                Err(_) => {
                    warn!(
                        "Object with bad URI '{}' in RRDP collector.",
                        String::from_utf8_lossy(&key)
                    );
                    return None
                }
            };
            let object = match RepositoryObject::try_from(value) {
                Ok(object) => object,
                Err(_) => {
                    warn!(
                        "Broken object for URI {} in RRDP collector.",
                        uri
                    );
                    return None
                }
            };
            Some((uri, object.content))
        }).filter_map(|item| item)
    }
}


//------------ RepositoryUpdate ----------------------------------------------

/// Updating an RRDP repository.
///
/// This type collects all the data necessary for updating a repository and
/// provides all the methods that actually do it.
struct RepositoryUpdate<'a> {
    /// A reference to the RRDP collector the update is done on.
    collector: &'a Collector,

    /// The HTTP client to use for downloading things.
    http: &'a HttpClient,

    /// The rpkiNotify URI identifying the repository.
    rpki_notify: &'a uri::Https,

    /// The update metrics.
    metrics: RrdpRepositoryMetrics,
}

impl<'a> RepositoryUpdate<'a> {
    /// Creates a new update.
    fn new(
        collector: &'a Collector,
        http: &'a HttpClient,
        rpki_notify: &'a uri::Https,
    ) -> Self {
        RepositoryUpdate {
            collector, http, rpki_notify,
            metrics: RrdpRepositoryMetrics::new(rpki_notify.clone())
        }
    }

    /// Performs an update and returns whether that succeeeded.
    ///
    /// This method wraps `_update` and times how long that takes.
    fn update(&mut self) -> Result<bool, Failed> {
        let start_time = SystemTime::now();
        let res = self._update();
        self.metrics.duration = SystemTime::now().duration_since(start_time);
        res
    }

    /// Actually performs an update and returns whether that succeeded.
    fn _update(&mut self) -> Result<bool, Failed> {
        let notify = match self.http.notification_file(
            &self.rpki_notify, &mut self.metrics.notify_status
        ) {
            Some(notify) => notify,
            None => return Ok(false)
        };
        self.metrics.serial = Some(notify.serial);
        self.metrics.session = Some(notify.session_id);
        match self.delta_update(&notify)? {
            None => {
                return Ok(true)
            }
            Some(reason) => {
                self.metrics.snapshot_reason = Some(reason)
            }
        }
        self.snapshot_update(&notify)
    }


    //--- Snapshot Update

    /// Performs a snapshot update and returns whether that succeeded.
    ///
    /// The URI and expected meta-data of the snapshot file are taken from
    /// `notify`.
    fn snapshot_update(
        &mut self,
        notify: &NotificationFile,
    ) -> Result<bool, Failed> {
        match self.try_snapshot_update(
            notify,
        ) {
            Ok(()) => Ok(true),
            Err(SnapshotError::Db(err)) => {
                Err(err.into())
            }
            Err(err) => {
                warn!(
                    "RRDP {}: failed to process snapshot file {}: {}",
                    self.rpki_notify, notify.snapshot.uri(), err
                );
                Ok(false)
            }
        }
    }

    /// Try performing a snapshot update.
    ///
    /// This is basically the snapshot update except that it returns an error
    /// whenever anything goes wrong whether that is fatal or not.
    fn try_snapshot_update(
        &mut self,
        notify: &NotificationFile,
    ) -> Result<(), SnapshotError> {
        debug!("RRDP {}: updating from snapshot.", self.rpki_notify);

        let response = match self.http.response(
            notify.snapshot.uri(), false
        ) {
            Ok(response) => {
                self.metrics.payload_status = Some(response.status().into());
                response
            }
            Err(err) => {
                self.metrics.payload_status = Some(HttpStatus::Error);
                return Err(err.into())
            }
        };
        let mut processor = SnapshotProcessor::new(&notify);
        let mut reader = io::BufReader::new(HashRead::new(response));
        processor.process(&mut reader)?;
        let hash = reader.into_inner().into_hash();
        if verify_slices_are_equal(
            hash.as_ref(),
            notify.snapshot.hash().as_ref()
        ).is_err() {
            return Err(SnapshotError::HashMismatch)
        }

        self.collector.db.drop_tree(Repository::tree_name(self.rpki_notify))?;

        let tree = self.collector.db.open_tree(
            Repository::tree_name(self.rpki_notify)
        )?;

        tree.apply_batch(processor.batch)?;
        tree.insert(
            REPOSITORY_STATE_KEY,
            &RepositoryState::from_notify(notify, self.collector.fallback_time)
        )?;
        tree.flush()?;

        debug!("RRDP {}: snapshot update completed.", self.rpki_notify);

        Ok(())
    }


    //--- Delta Update

    /// Performs a delta update of the RRDP repository.
    ///
    /// Takes information of the available deltas from `notify`. May not do
    /// anything at all if the repository is up-to-date. Returns whether the
    /// update succeeded. If `Ok(Some(reason))` is returned, a snapshot update
    /// should be tried next because of the reason given.
    fn delta_update(
        &mut self,
        notify: &NotificationFile,
    ) -> Result<Option<SnapshotReason>, Failed> {
        let tree = self.collector.db.open_tree(
            Repository::tree_name(self.rpki_notify)
        )?;

        debug!("RRDP {}: Tree has {} entries.", self.rpki_notify, tree.len());

        let state = match tree.get("")? {
            Some(state) => {
                match RepositoryState::try_from(state) {
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
            }
            None => return Ok(Some(SnapshotReason::NewRepository)),
        };

        let deltas = match Self::calc_deltas(notify, &state) {
            Ok([]) => return Ok(None),
            Ok(deltas) => deltas,
            Err(reason) => return Ok(Some(reason)),
        };

        let count = deltas.len();
        for (i, (serial, uri_and_hash)) in deltas.iter().enumerate() {
            debug!(
                "RRDP {}: Delta update step ({}/{}).",
                uri_and_hash.uri(), i + 1, count
            );
            if let Some(reason) = self.delta_update_step(
                &tree, notify, *serial,
                uri_and_hash.uri(), uri_and_hash.hash()
            )? {
                info!(
                    "RRDP {}: Delta update failed, falling back to snapshot.",
                    self.rpki_notify
                );
                return Ok(Some(reason))
            }
        }

        tree.flush()?;

        debug!("RRDP {}: Delta update completed.", self.rpki_notify);
        Ok(None)
    }

    /// Calculates the slice of deltas to follow for updating.
    ///
    /// Returns an empty slice if no update is necessary.
    /// Returns a non-empty slice of the sequence of deltas to be applied.
    /// Returns `None` if updating via deltas is not possible.
    fn calc_deltas<'b>(
        notify: &'b NotificationFile,
        state: &RepositoryState
    ) -> Result<&'b [(u64, UriAndHash)], SnapshotReason> {
        if notify.session_id != state.session {
            debug!("New session. Need to get snapshot.");
            return Err(SnapshotReason::NewSession)
        }
        debug!("Serials: us {}, them {}", state.serial, notify.serial);
        if notify.serial == state.serial {
            return Ok(&[]);
        }

        // If there is no last delta (remember, we have a different
        // serial than the notification file) or if the last delta’s
        // serial differs from that noted in the notification file,
        // bail out.
        if notify.deltas.last().map(|delta| delta.0) != Some(notify.serial) {
            debug!("Last delta serial differs from current serial.");
            return Err(SnapshotReason::BadDeltaSet)
        }

        let mut deltas = notify.deltas.as_slice();
        let serial = match state.serial.checked_add(1) {
            Some(serial) => serial,
            None => return Err(SnapshotReason::LargeSerial)
        };
        loop {
            let first = match deltas.first() {
                Some(first) => first,
                None => {
                    debug!("Ran out of deltas.");
                    return Err(SnapshotReason::BadDeltaSet)
                }
            };
            match first.0.cmp(&serial) {
                cmp::Ordering::Greater => {
                    debug!("First delta is too new ({})", first.0);
                    return Err(SnapshotReason::OutdatedLocal)
                }
                cmp::Ordering::Equal => break,
                cmp::Ordering::Less => deltas = &deltas[1..]
            }
        }
        Ok(deltas)
    }

    /// Performs the update for a single delta.
    ///
    /// Returns `Ok(None)` if the update step succeeded, `Ok(Some(reason))`
    /// if the delta was faulty, and `Err(Failed)` if things have gone badly.
    fn delta_update_step(
        &mut self,
        tree: &sled::Tree,
        notify: &NotificationFile,
        serial: u64,
        uri: &uri::Https,
        hash: rrdp::Hash,
    ) -> Result<Option<SnapshotReason>, Failed> {
        let batch = match self.collect_delta_update_step(
            tree, notify, serial, uri, hash
        ) {
            Ok(batch) => batch, 
            Err(DeltaError::Db(err)) => {
                return Err(err.into())
            }
            Err(err) => {
                warn!(
                    "RRDP {}: failed to process delta: {}",
                    self.rpki_notify, err
                );
                return Ok(Some(SnapshotReason::ConflictingDelta))
            }
        };
        tree.apply_batch(batch)?;
        Ok(None)
    }

    /// Collects the changes to be done for a delta update step.
    ///
    /// Upon success, returns a batch with the changes. 
    fn collect_delta_update_step(
        &mut self,
        tree: &sled::Tree,
        notify: &NotificationFile,
        serial: u64,
        uri: &uri::Https,
        hash: rrdp::Hash,
    ) -> Result<sled::Batch, DeltaError> {
        let response = match self.http.response(uri, false) {
            Ok(response) => {
                self.metrics.payload_status = Some(response.status().into());
                response
            }
            Err(err) => {
                self.metrics.payload_status = Some(HttpStatus::Error);
                return Err(err.into())
            }
        };
        let mut processor = DeltaProcessor::new(
            notify.session_id, serial, tree
        );
        let mut reader = io::BufReader::new(HashRead::new(response));

        processor.process(&mut reader)?;
        
        let remote_hash = reader.into_inner().into_hash();
        if verify_slices_are_equal(
            remote_hash.as_ref(),
            hash.as_ref()
        ).is_err() {
            return Err(DeltaError::DeltaHashMismatch)
        }

        processor.batch.insert(
            REPOSITORY_STATE_KEY,
            &RepositoryState::new(
                notify.session_id, serial, self.collector.fallback_time
            ),
        );

        Ok(processor.batch)
    }
}


//------------ HttpClient ----------------------------------------------------

/// The HTTP client for updating RRDP repositories.
#[derive(Debug)]
struct HttpClient {
    /// The (blocking) reqwest client.
    ///
    /// This will be of the error variant until `ignite` has been called. Yes,
    /// that is not ideal but 
    client: Result<Client, Option<ClientBuilder>>,

    /// The base directory for storing copies of responses if that is enabled.
    response_dir: Option<PathBuf>,
}

impl HttpClient {
    /// Creates a new, not-yet-ignited client based on the config.
    pub fn new(config: &Config) -> Result<Self, Failed> {

        // Deal with the reqwest’s TLS features by defining a creator
        // function for the two cases.
        #[cfg(not(feature = "native-tls"))]
        fn create_builder() -> ClientBuilder {
            Client::builder().use_rustls_tls()
        }

        #[cfg(feature = "native-tls")]
        fn create_builder() -> ClientBuilder {
            Client::builder().use_native_tls()
        }

        let mut builder = create_builder();
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
            response_dir: config.rrdp_keep_responses.clone(),
        })
    }

    /// Ignites the client.
    ///
    /// This _must_ be called before any other methods can be called. It must
    /// be called after any potential fork on Unix systems because it spawns
    /// threads.
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

    /// Loads a WebPKI trusted certificate.
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

    /// Returns a reference to the reqwest client.
    ///
    /// # Panics
    ///
    /// The method panics if the client hasn’t been ignited yet.
    fn client(&self) -> &Client {
        self.client.as_ref().unwrap()
    }

    /// Performs an HTTP GET request for the given URI.
    ///
    /// If keeping responses is enabled, the response is written to a file
    /// corresponding to the URI. If the resource behind the URI changes over
    /// time and this change should be tracked, set `multi` to `true` to
    /// include the current time in the file name.
    pub fn response(
        &self,
        uri: &uri::Https,
        multi: bool,
    ) -> Result<HttpResponse, reqwest::Error> {
        self.client().get(uri.as_str()).send().map(|response| {
            HttpResponse::create(response, uri, &self.response_dir, multi)
        })
    }

    /// Requests, parses, and returns the given RRDP notification file.
    ///
    /// The value referred to by `status` will be updated to the received
    /// status code or `None` if the request failed for other reasons.
    ///
    /// Returns the notification file on success.
    pub fn notification_file(
        &self,
        uri: &uri::Https,
        status: &mut HttpStatus,
    ) -> Option<NotificationFile> {
        let response = match self.response(uri, true) {
            Ok(response) => {
                *status = response.status().into();
                response
            }
            Err(err) => {
                warn!("RRDP {}: {}", uri, err);
                *status = HttpStatus::Error;
                return None;
            }
        };
        if !response.status().is_success() {
            warn!(
                "RRDP {}: Getting notification file failed with status {}",
                uri, response.status()
            );
            return None;
        }
        match NotificationFile::parse(io::BufReader::new(response)) {
            Ok(mut res) => {
                res.deltas.sort_by_key(|delta| delta.0);
                Some(res)
            }
            Err(err) => {
                warn!("RRDP {}: {}", uri, err);
                None
            }
        }
    }
}


//------------ HttpResponse --------------------------------------------------

/// Wraps a reqwest response for added features.
struct HttpResponse {
    /// The wrapped reqwest response.
    response: Response,

    /// A file to also store read data into.
    file: Option<fs::File>,
}

impl HttpResponse {
    /// Creates a new response wrapping a reqwest reponse.
    ///
    /// If `response_dir` is some path, the response will also be written to
    /// a file under this directory based on `uri`. Each URI component
    /// starting with the authority will be a directory name. If `multi` is
    /// `false` the last component will be the file name. If `multi` is
    /// `true` the last component will be a directory, too, and the file name
    /// will be the ISO timestamp of the current time.
    pub fn create(
        response: Response,
        uri: &uri::Https,
        response_dir: &Option<PathBuf>,
        multi: bool
    ) -> Self {
        HttpResponse {
            response,
            file: response_dir.as_ref().and_then(|base| {
                Self::open_file(base, uri, multi).ok()
            })
        }
    }

    /// Opens the file mirroring file.
    ///
    /// See [`create`][Self::create] for the rules.
    fn open_file(
        base: &Path, uri: &uri::Https, multi: bool
    ) -> Result<fs::File, Failed> {
        let path = base.join(&uri.as_str()[8..]);
        let path = if multi {
            path.join(Utc::now().to_rfc3339())
        }
        else {
            path
        };

        let parent = match path.parent() {
            Some(parent) => parent,
            None => {
                warn!(
                    "Cannot keep HTTP response; \
                    URI translated into a bad path '{}'",
                    path.display()
                );
                return Err(Failed)
            }
        };
        if let Err(err) = fs::create_dir_all(&parent) {
            warn!(
                "Cannot keep HTTP response; \
                creating director {} failed: {}",
                parent.display(), err
            );
            return Err(Failed)
        }
        fs::File::create(&path).map_err(|err| {
            warn!(
                "Cannot keep HTTP response; \
                creating file {} failed: {}",
                path.display(), err
            );
            Failed
        })
    }

    /// Returns the value of the content length header if present.
    pub fn content_length(&self) -> Option<u64> {
        self.response.content_length()
    }

    /// Copies the full content of the response to the given writer.
    pub fn copy_to<W: io::Write + ?Sized>(
        &mut self, w: &mut W
    ) -> Result<u64, io::Error> {
        // We cannot use the reqwest response’s `copy_to` impl because we need
        // to use our own `io::Read` impl which sneaks in the copying to file
        // if necessary.
        io::copy(self, w)
    }

    /// Returns the status code of the response.
    pub fn status(&self) -> StatusCode {
        self.response.status()
    }
}


//--- Read

impl io::Read for HttpResponse {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        let res = self.response.read(buf)?;
        if let Some(file) = self.file.as_mut() {
            file.write_all(&buf[..res])?;
        }
        Ok(res)
    }
}


//------------ SnapshotProcessor ---------------------------------------------

/// The processor for an RRDP snapshot.
struct SnapshotProcessor<'a> {
    /// A reference to the notification file pointing to the snapshot.
    notify: &'a NotificationFile,

    /// The batch to add all objects to.
    batch: sled::Batch,
}

impl<'a> SnapshotProcessor<'a> {
    /// Creates a new processor.
    fn new(
        notify: &'a NotificationFile,
    ) -> Self {
        SnapshotProcessor {
            notify,
            batch: sled::Batch::default()
        }
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
        let data = RepositoryObject::read_into_ivec(data)?;
        self.batch.insert(uri.as_str(), data);
        Ok(())
    }
}


//------------ DeltaProcessor ------------------------------------------------

/// The processor for RRDP delta updates.
struct DeltaProcessor<'a> {
    /// The session ID of the RRDP session.
    session_id: Uuid,

    /// The expected serial number of the delta.
    serial: u64,

    /// The database tree of the RRDP repository.
    tree: &'a sled::Tree,

    /// The batch to add all updates to.
    batch: sled::Batch,
}

impl<'a> DeltaProcessor<'a> {
    /// Creates a new processor.
    fn new(
        session_id: Uuid,
        serial: u64,
        tree: &'a sled::Tree,
    ) -> Self {
        DeltaProcessor {
            session_id, serial, tree,
            batch: sled::Batch::default(),
        }
    }

    /// Checks the hash of an object that should be present.
    fn check_hash(
        &self,
        uri: &uri::Rsync,
        hash: rrdp::Hash,
    ) -> Result<(), DeltaError> {
        let data = match self.tree.get(&uri)? {
            Some(data) => data,
            None => {
                return Err(DeltaError::MissingObject { uri: uri.clone() })
            }
        };
        let stored_hash = RepositoryObject::decode_hash(&data)?;
        if stored_hash != hash {
            Err(DeltaError::ObjectHashMismatch { uri: uri.clone() })
        }
        else {
            Ok(())
        }
    }

    /// Checks that a new object isn’t present yet.
    fn check_new(
        &self,
        uri: &uri::Rsync
    ) -> Result<(), DeltaError> {
        if self.tree.get(&uri)?.is_some() {
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
        let data = RepositoryObject::read_into_ivec(data)?;
        self.batch.insert(uri.as_slice(), data);
        Ok(())
    }

    fn withdraw(
        &mut self,
        uri: uri::Rsync,
        hash: rrdp::Hash
    ) -> Result<(), Self::Err> {
        self.check_hash(&uri, hash)?;
        self.batch.remove(uri.as_slice());
        Ok(())
    }
}


//------------ RepositoryState -----------------------------------------------

/// The current state of an RRDP repository.
///
/// A value of this type is stored under the empty key with each repository
/// and is updated on each … update.
#[derive(Clone, Debug)]
struct RepositoryState {
    /// The UUID of the current session of repository.
    pub session: Uuid,

    /// The serial number within the current session.
    pub serial: u64,

    /// The time of last update of the server.
    pub updated: DateTime<Utc>,

    /// The time when we consider the stored data to be expired.
    pub best_before: DateTime<Utc>,
}

impl RepositoryState {
    /// Create the state based on the notification file.
    pub fn from_notify(
        notify: &NotificationFile,
        fallback: FallbackTime,
    ) -> Self {
        Self::new(notify.session_id, notify.serial, fallback)
    }

    /// Create new state with given values.
    pub fn new(session: Uuid, serial: u64, fallback: FallbackTime) -> Self {
        RepositoryState {
            session, serial,
            updated: Utc::now(),
            best_before: fallback.best_before(),
        }
    }

    /// Returns whether this repository should be considered expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.best_before
    }
}


//--- From and TryFrom

impl<'a> From<&'a RepositoryState> for IVec {
    fn from(state: &'a RepositoryState) -> IVec {
        let mut vec = Vec::with_capacity(state.session.as_bytes().len() + 17);

        // Version. 0u8
        vec.push(0u8);

        // The session as its bytes.
        vec.extend_from_slice(state.session.as_bytes());

        // The serial in network byte order.
        vec.extend_from_slice(&state.serial.to_be_bytes());

        // The update time as the i64 timestamp in network byte order.
        vec.extend_from_slice(&state.updated.timestamp().to_be_bytes());

        // The best-before time as the i64 timestamp in network byte order.
        vec.extend_from_slice(&state.best_before.timestamp().to_be_bytes());

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
            mem::size_of::<i64>() +
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
        let (field, stored) = stored.split_at(
            mem::size_of::<DateTime<Utc>>()
        );
        let updated = Utc.timestamp(
            i64::from_be_bytes(field.try_into().unwrap()), 0
        );

        // Best-before.
        let field = stored;
        let best_before = Utc.timestamp(
            i64::from_be_bytes(field.try_into().unwrap()), 0
        );
        
        Ok(RepositoryState { session, serial, updated, best_before })
    }
}


//------------ RepositoryObject ----------------------------------------------

/// A repository object stored in the database.
#[derive(Clone, Debug)]
struct RepositoryObject<Octets> {
    /// The RRDP hash of the object.
    hash: rrdp::Hash,

    /// The content of the object.
    content: Octets,
}

impl RepositoryObject<()> {
    /// Reads an object’s content directly into a database vec.
    pub fn read_into_ivec(
        reader: &mut impl io::Read
    ) -> Result<IVec, io::Error> {
        let mut reader = HashRead::new(reader);
        let mut res = vec![0; mem::size_of::<rrdp::Hash>() + 1];
        io::copy(&mut reader, &mut res)?;
        let hash = reader.into_hash();
        res[1..hash.as_slice().len() + 1].copy_from_slice(hash.as_slice());
        Ok(res.into())
    }

    /// Decodes only the object hash from the database representation.
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

impl<'a, Octets: AsRef<[u8]>> From<&'a RepositoryObject<Octets>> for IVec {
    fn from(src: &'a RepositoryObject<Octets>) -> Self {
        let mut vec = Vec::with_capacity(
            src.hash.as_ref().len() + src.content.as_ref().len() + 1
        );

        // Version. 0u8
        vec.push(0u8);
        
        // The hash as its bytes
        vec.extend_from_slice(src.hash.as_ref());

        // The content as its bytes.
        vec.extend_from_slice(src.content.as_ref());

        vec.into()
    }
}

impl TryFrom<IVec> for RepositoryObject<Bytes> {
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

        Ok(RepositoryObject { hash, content })
    }
}


//------------ FallbackTime --------------------------------------------------

/// Parameters for calculating the best-before time of repositories.
#[derive(Clone, Copy, Debug)]
struct FallbackTime {
    min: Duration,
    max: Duration,
}

impl FallbackTime {
    /// Creates a new value from the configuration.
    pub fn from_config(config: &Config) -> Self {
        FallbackTime {
            min: config.refresh,
            max: cmp::max(2 * config.refresh, config.rrdp_fallback_time)
        }
    }

    /// Picks a best-before date for a repository updated around now.
    pub fn best_before(self) -> DateTime<Utc> {
        // Saturating conversion between std’s and chrono’s Duration types.
        Utc::now() + chrono::Duration::from_std(
            rand::thread_rng().gen_range(self.min..self.max)
        ).unwrap_or_else(|_| chrono::Duration::milliseconds(i64::MAX))
    }
}


//------------ HashRead ------------------------------------------------------

/// A reader wrapper that calculates the SHA-256 hash of all read data.
struct HashRead<R> {
    /// The wrapped reader.
    reader: R,

    /// The context for hash calculation.
    context: digest::Context,
}

impl<R> HashRead<R> {
    /// Creates a new hash reader.
    pub fn new(reader: R) -> Self {
        HashRead {
            reader,
            context: digest::Context::new(&digest::SHA256)
        }
    }

    /// Converts the reader into the hash.
    pub fn into_hash(self) -> rrdp::Hash {
        rrdp::Hash::try_from(self.context.finish()).unwrap()
    }
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

/// An error happened during snapshot processing.
///
/// This is an internal error type only necessary for error handling during
/// RRDP processing. Values will be logged and converted into failures or
/// negative results as necessary.
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
    Db(sled::Error),
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

impl From<sled::Error> for SnapshotError {
    fn from(err: sled::Error) -> Self {
        SnapshotError::Db(err)
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

/// An error happened during delta processing.
///
/// This is an internal error type only necessary for error handling during
/// RRDP processing. Values will be logged and converted into failures or
/// negative results as necessary.
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
    Db(sled::Error),
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

impl From<sled::Error> for DeltaError {
    fn from(err: sled::Error) -> Self {
        DeltaError::Db(err)
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
///
/// This is treated as a database error leading to a failure.
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

/// A repository object cannot be decoded correctly.
///
/// This is treated as a database error leading to a failure.
#[derive(Clone, Copy, Debug)]
struct ObjectError;

impl fmt::Display for ObjectError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("cached object cannot be decoded")
    }
}

impl error::Error for ObjectError { }


//------------ SnapshotReason ------------------------------------------------

/// The reason why a snapshot was used.
#[derive(Clone, Copy, Debug)]
pub enum SnapshotReason {
    /// The respository is new.
    NewRepository,

    /// A new session was encountered.
    NewSession,

    /// The delta set in the notification file is inconsistent.
    BadDeltaSet,

    /// A larger-than-supported serial number was encountered.
    LargeSerial,

    /// The local copy is outdated and cannot be updated via deltas.
    OutdatedLocal,

    /// A delta file was conflicting with locally stored data.
    ConflictingDelta,
}

impl SnapshotReason {
    /// Returns a shorthand code for the reason.
    pub fn code(self) -> &'static str {
        use SnapshotReason::*;

        match self {
            NewRepository => "new-repository",
            NewSession => "new-session",
            BadDeltaSet => "inconsistent-delta-set",
            LargeSerial => "large-serial",
            OutdatedLocal => "outdate-local",
            ConflictingDelta => "conflicting-delta",
        }
    }
}


//------------ HttpStatus ----------------------------------------------------

/// The result of an HTTP request.
#[derive(Clone, Copy, Debug)]
pub enum HttpStatus {
    /// A response was received with the given status code.
    Response(StatusCode),

    /// An error happened.
    Error
}

impl HttpStatus {
    pub fn into_i16(self) -> i16 {
        match self {
            HttpStatus::Response(code) => code.as_u16() as i16,
            HttpStatus::Error => -1
        }
    }

    pub fn is_success(self) -> bool {
        matches!(
            self,
            HttpStatus::Response(code) if code.is_success()
        )
    }
}

impl From<StatusCode> for HttpStatus {
    fn from(code: StatusCode) -> Self {
        HttpStatus::Response(code)
    }
}


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;
    use rpki::repository::crypto::digest::DigestAlgorithm;

    #[test]
    fn encoded_repository_object() {
        let data = b"foobar".as_ref();
        let expected_hash =
            "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2";
        let digest = DigestAlgorithm::sha256().digest(data);
        let encoded = RepositoryObject::read_into_ivec(
            &mut data.clone()
        ).unwrap();

        let hash = RepositoryObject::decode_hash(
            encoded.as_ref()
        ).unwrap();
        assert_eq!(hash.as_slice(), digest.as_ref());
        assert_eq!(format!("{}", hash), expected_hash);

        let decoded = RepositoryObject::try_from(encoded).unwrap();
        assert_eq!(decoded.content.as_ref(), data);
        assert_eq!(decoded.hash.as_slice(), digest.as_ref());
    }
}

