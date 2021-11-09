//! Local repository copies synchronized with RRDP.
//!
//! The RRDP collector uses the file system to store its data.  For each
//! hostname serving an RRDP repository, there is directory. Within these
//! directories, each repository has its own directory based on the SHA-256
//! hash of the full rpkiNotify URI. Within this directory, all objects
//! published by the RRDP server are stored in a (relative) path constructed
//! from all the components of their rsync URI. The first of these is indeed
//! `rsync`.
//!
//! During updates, all newly published objects are stored in a temporary
//! tree alongside the actual object tree. The files are also stored in paths
//! build from their rsync URI, but the first component `rsync` is replaced
//! by `tmp`.
//!
//! For each repository, the state at last update is stored in a file named
//! `state.bin` place in the repository directory. This file is removed before
//! any update is attempted to mark the repository as ‘in flux.’ Similarly,
//! if this file is not found before an update is started, the repository is
//! considered not present even if there are actually files.

use std::{cmp, error, fmt, fs, io};
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};
use bytes::Bytes;
use chrono::{DateTime, TimeZone, Utc};
use log::{debug, error, info, warn};
use rand::Rng;
use ring::digest;
use ring::constant_time::verify_slices_are_equal;
use reqwest::header;
use reqwest::{Certificate, Proxy, StatusCode};
use reqwest::blocking::{Client, ClientBuilder, RequestBuilder, Response};
use rpki::{rrdp, uri};
use rpki::repository::crypto::DigestAlgorithm;
use rpki::rrdp::{DeltaInfo, NotificationFile, ProcessDelta, ProcessSnapshot};
use uuid::Uuid;
use crate::config::Config;
use crate::error::Failed;
use crate::metrics::{Metrics, RrdpRepositoryMetrics};
use crate::utils::fatal;
use crate::utils::binio::{Compose, Parse};
use crate::utils::date::{parse_http_date, format_http_date};
use crate::utils::dump::DumpRegistry;
use crate::utils::json::JsonBuilder;
use crate::utils::uri::UriExt;


//------------ Collector -----------------------------------------------------

/// The local copy of RPKI repositories synchronized via RRDP.
#[derive(Debug)]
pub struct Collector {
    /// The path of the directory we store all our data in.
    working_dir: PathBuf,

    /// The HTTP client.
    http: HttpClient,

    /// Whether to filter dubious authorities in notify URIs.
    filter_dubious: bool,

    /// RRDP repository fallback timeout.
    ///
    /// This is the time since the last known update of an RRDP repository
    /// before it is considered non-existant.
    fallback_time: FallbackTime,

    /// The maximum allowed size for published objects.
    max_object_size: Option<u64>,

    /// The maximum number of deltas we process before using a snapshot.
    max_delta_count: usize,
}

impl Collector {
    /// Initializes the RRDP collector without creating a value.
    ///
    /// This function is called implicitely by [`new`][Collector::new].
    pub fn init(config: &Config) -> Result<(), Failed> {
        let _ = Self::create_working_dir(config)?;
        Ok(())
    }

    /// Creates the working dir and returns its path.
    fn create_working_dir(config: &Config) -> Result<PathBuf, Failed> {
        let working_dir = config.cache_dir.join("rrdp");

        if config.fresh {
            if let Err(err) = fs::remove_dir_all(&working_dir) {
                if err.kind() != io::ErrorKind::NotFound {
                    error!(
                        "Failed to delete RRDP working directory at {}: {}",
                        working_dir.display(), err
                    );
                    return Err(Failed)
                }
            }
        }

        if let Err(err) = fs::create_dir_all(&working_dir) {
            error!(
                "Failed to create RRDP working directory {}: {}.",
                working_dir.display(), err
            );
            return Err(Failed);
        }
        Ok(working_dir)
    }
    /// Creates a new RRDP collector.
    pub fn new(config: &Config) -> Result<Option<Self>, Failed> {
        if config.disable_rrdp {
            return Ok(None)
        }
        Ok(Some(Collector {
            working_dir: Self::create_working_dir(config)?,
            http: HttpClient::new(config)?,
            filter_dubious: !config.allow_dubious_hosts,
            fallback_time: FallbackTime::from_config(config),
            max_object_size: config.max_object_size,
            max_delta_count: config.rrdp_max_delta_count,
        }))
    }

    /// Ignites the collector.
    pub fn ignite(&mut self) -> Result<(), Failed> {
        self.http.ignite()
    }

    /// Starts a validation run using the collector.
    pub fn start(&self) -> Run {
        Run::new(self)
    }

    /// Dumps the content of the RRDP collector.
    #[allow(clippy::mutable_key_type)]
    pub fn dump(&self, dir: &Path) -> Result<(), Failed> {
        let dir = dir.join("rrdp");
        debug!("Dumping RRDP collector content to {}", dir.display());
        let mut registry = DumpRegistry::new(dir);
        let mut states = HashMap::new();
        for entry in fatal::read_dir(&self.working_dir)? {
            let entry = entry?;
            if !entry.is_dir() {
                continue;
            }
            for entry in fatal::read_dir(entry.path())? {
                let entry = entry?;
                if entry.is_dir() {
                    self.dump_repository(
                        entry.path(), &mut registry, &mut states
                    )?;
                }
            }
        }
        self.dump_repository_json(registry, states)?;
        debug!("RRDP collector dump complete.");
        Ok(())
    }

    /// Dumps the content of an RRDP repository.
    #[allow(clippy::mutable_key_type)]
    fn dump_repository(
        &self,
        repo_path: &Path,
        registry: &mut DumpRegistry,
        state_registry: &mut HashMap<uri::Https, RepositoryState>,
    ) -> Result<(), Failed> {
        let state_path = repo_path.join(RepositoryState::FILE_NAME);
        let state = match RepositoryState::load_path(&state_path)? {
            Some(state) => state,
            None => return Ok(())
        };
        let target_path = registry.get_repo_path(Some(&state.rpki_notify));

        fatal::create_dir_all(&target_path)?;

        Self::dump_tree(&repo_path.join("rsync"), &target_path)?;

        state_registry.insert(state.rpki_notify.clone(), state);

        Ok(())
    }

    /// Dumps a tree.
    fn dump_tree(
        source_path: &Path,
        target_path: &Path,
    ) -> Result<(), Failed> {
        for entry in fatal::read_dir(source_path)? {
            let entry = entry?;
            if entry.is_dir() {
                Self::dump_tree(
                    entry.path(), &target_path.join(entry.file_name())
                )?;
            }
            else if entry.is_file() {
                let target_path = target_path.join(entry.file_name());
                fatal::create_parent_all(&target_path)?;
                if let Err(err) = fs::copy(entry.path(), &target_path) {
                    error!(
                        "Fatal: failed to copy {} to {}: {}",
                        entry.path().display(),
                        target_path.display(),
                        err
                    );
                    return Err(Failed)
                }
            }
        }
        Ok(())
    }

    /// Dumps the repositories.json.
    #[allow(clippy::mutable_key_type)]
    fn dump_repository_json(
        &self,
        repos: DumpRegistry,
        states: HashMap<uri::Https, RepositoryState>,
    ) -> Result<(), Failed> {
        let path = repos.base_dir().join("repositories.json");
        if let Err(err) = fs::write(
            &path, 
            &JsonBuilder::build(|builder| {
                builder.member_array("repositories", |builder| {
                    for (key, value) in repos.rrdp_uris() {
                        builder.array_object(|builder| {
                            builder.member_str(
                                "path", value
                            );
                            builder.member_str("type", "rrdp");
                            builder.member_str(
                                "rpkiNotify",
                                key
                            );

                            if let Some(state) = states.get(key) {
                                builder.member_raw("serial", state.serial);
                                builder.member_str("session", state.session);
                                builder.member_str(
                                    "updated",
                                    state.updated().to_rfc3339()
                                );
                            }
                        })
                    }
                    builder.array_object(|builder| {
                        builder.member_str("path", "rsync");
                        builder.member_str("type", "rsync");
                    });
                })
            })
        ) {
            error!( "Failed to write {}: {}", path.display(), err);
            return Err(Failed)
        }

        Ok(())
    }

    /// Returns the path for a repository.
    fn repository_path(&self, rpki_notify: &uri::Https) -> PathBuf {
        let authority = rpki_notify.canonical_authority();
        let alg = DigestAlgorithm::sha256();
        let mut dir = String::with_capacity(
            authority.len()
            + alg.digest_len()
            + 1 // one slash
        );
        dir.push_str(&authority);
        dir.push('/');
        crate::utils::str::append_hex(
            alg.digest(rpki_notify.as_slice()).as_ref(),
            &mut dir
        );
        self.working_dir.join(dir)
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
    /// allowed to actually update.
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
        let mut response = match self.collector.http.response(uri, false) {
            Ok(response) => response,
            Err(_) => return None,
        };
        if response.content_length() > self.collector.max_object_size {
            warn!(
                "Trust anchor certificate {} exceeds size limit. \
                 Ignoring.",
                uri
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
        self.updated.read().unwrap().get(notify_uri).is_some()
    }

    /// Accesses an RRDP repository.
    ///
    /// This method blocks if the repository is deemed to need updating until
    /// the update has finished.
    ///
    /// If a repository has been successfully updated during this run,
    /// returns it. Otherwise returns it if it is cached and that cached data
    /// is newer than the fallback time. Thus, if the method returns
    /// `Ok(None)`, you can fall back to rsync.
    pub fn load_repository(
        &self, rpki_notify: &uri::Https
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

        // Acquire the mutex. Once we have it, see if the repository is
        // up-to-date which happens if someone else had the mutex first.
        let _lock = mutex.lock().unwrap();
        if let Some(res) = self.updated.read().unwrap().get(rpki_notify) {
            return Ok(res.clone())
        }

        // Now we can update the repository.
        let repository = Repository::try_update(self, rpki_notify.clone())?;

        // Remove from running.
        self.running.write().unwrap().remove(rpki_notify);

        // Insert into updated map and also return.
        self.updated.write().unwrap().insert(
            rpki_notify.clone(), repository.clone()
        );
        Ok(repository)
    }

    /// Cleans up the RRDP collector.
    ///
    /// Deletes all RRDP repository trees that are not included in `retain`.
    #[allow(clippy::mutable_key_type)]
    pub fn cleanup(
        &self,
        retain: &mut HashSet<uri::Https>
    ) -> Result<(), Failed> {
        // Add all the RRDP repositories we’ve tried during this run to be
        // kept.
        for uri in self.updated.read().unwrap().keys() {
            retain.insert(uri.clone());
        }

        for entry in fatal::read_dir(&self.collector.working_dir)? {
            let entry = entry?;
            if entry.is_file() {
                // This isn’t supposed to be here. Make it go away.
                if let Err(err) = fs::remove_file(entry.path()) {
                    error!(
                        "Fatal: failed to delete stray file {}: {}",
                        entry.path().display(), err
                    );
                    return Err(Failed)
                }
            }
            else if entry.is_dir() {
                self.cleanup_authority(entry.path(), retain)?;
            }
        }
        Ok(())
    }

    /// Cleans up an authority directory.
    #[allow(clippy::mutable_key_type)]
    pub fn cleanup_authority(
        &self,
        path: &Path,
        retain: &HashSet<uri::Https>
    ) -> Result<(), Failed> {
        for entry in fatal::read_dir(path)? {
            let entry = entry?;
            if entry.is_file() {
                // This isn’t supposed to be here. Make it go away.
                if let Err(err) = fs::remove_file(entry.path()) {
                    error!(
                        "Fatal: failed to delete stray file {}: {}",
                        entry.path().display(), err
                    );
                    return Err(Failed)
                }
            }
            else if entry.is_dir() {
                self.cleanup_repository(entry.path(), retain)?;
            }
        }
        Ok(())
    }

    /// Cleans up a repository directory.
    #[allow(clippy::mutable_key_type)]
    pub fn cleanup_repository(
        &self,
        path: &Path,
        retain: &HashSet<uri::Https>
    ) -> Result<(), Failed> {
        let state_path = path.join(RepositoryState::FILE_NAME);
        let keep = match RepositoryState::load_path(&state_path)? {
            Some(state) => {
                retain.contains(&state.rpki_notify)
            }
            None => false,
        };

        if !keep {
            debug!("Deleting unused RRDP tree {}.", path.display());
            if let Err(err) = fs::remove_dir_all(path) {
                error!(
                    "Fatal: failed to delete tree {}: {}.",
                    path.display(), err
                );
                return Err(Failed)
            }
        }

        Ok(())
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
    /// The rpkiNotify URI of the repository.
    rpki_notify: uri::Https,

    /// The path where everything from this repository lives.
    path: PathBuf,
}

impl Repository {
    /// Loads an object from the repository.
    ///
    /// The object is identified by its rsync URI. If the object doesn’t
    /// exist, returns `None`.
    pub fn load_object(
        &self,
        uri: &uri::Rsync
    ) -> Result<Option<Bytes>, Failed> {
        RepositoryObject::load(&self.object_path(uri)).map(|maybe_obj| {
            maybe_obj.map(|obj| obj.content)
        })
    }

    /// Returns the path where all the objects live.
    fn object_base(&self) -> PathBuf {
        self.path.join("rsync")
    }

    /// Returns the path for a given rsync URI.
    fn object_path(&self, uri: &uri::Rsync) -> PathBuf {
        self.path.join(
            format!(
                "rsync/{}/{}/{}",
                uri.canonical_authority(),
                uri.module_name(),
                uri.path()
            )
        )
    }

    /// Returns the path where all the objects live.
    fn tmp_base(&self) -> PathBuf {
        self.path.join("tmp")
    }

    /// Returns the path for a given rsync URI.
    fn tmp_object_path(&self, uri: &uri::Rsync) -> PathBuf {
        self.path.join(
            format!(
                "tmp/{}/{}/{}",
                uri.canonical_authority(),
                uri.module_name(),
                uri.path()
            )
        )
    }
}

/// # Update
///
impl Repository {
    /// Creates the repository by trying to update it.
    ///
    /// Returns `Ok(None)` if the update fails and there is no already
    /// downloaded version that hasn’t expired yet.
    fn try_update(
        run: &Run, rpki_notify: uri::Https
    ) -> Result<Option<Self>, Failed> {
        // Check if the repository URI is dubious and return early if so.
        if run.collector.filter_dubious && rpki_notify.has_dubious_authority() {
            warn!(
                "{}: Dubious host name. Not using the repository.",
                rpki_notify
            );
            return Ok(None)
        }

        let path = run.collector.repository_path(&rpki_notify);
        let repo = Repository { rpki_notify: rpki_notify.clone(), path };
        let state = match RepositoryState::load(&repo) {
            Ok(state) => {
                state
            }
            Err(_) => {
                // Try to recover by removing the repository directory and
                // starting from scratch.
                if let Err(err) = fs::remove_dir_all(&repo.path) {
                    error!(
                        "Fatal: failed to delete corrupted repository \
                         directory {}: {}",
                         repo.path.display(), err
                    );
                    return Err(Failed)
                }
                None
            }
        };

        let is_current = match state.as_ref() {
            Some(state) => !state.is_expired(),
            None => false,
        };
        let best_before = state.as_ref().map(|state| state.best_before());

        let start_time = SystemTime::now();
        let mut metrics = RrdpRepositoryMetrics::new(rpki_notify.clone());
        let is_updated = repo._update(run, state, &mut metrics)?;
        metrics.duration = SystemTime::now().duration_since(start_time);
        run.metrics.lock().unwrap().push(metrics);

        if is_updated || is_current {
            Ok(Some(repo))
        }
        else {
            match best_before {
                Some(date) => {
                    info!(
                        "RRDP {}: Update failed and \
                        current copy is expired since {}.",
                        rpki_notify, date
                    );
                },
                None => {
                    info!(
                        "RRDP {}: Update failed and there is no current copy.",
                        rpki_notify
                    );
                }
            }
            Ok(None)
        }
    }

    /// Performs the actual update.
    ///
    /// Returns `Ok(false)` if the update failed.
    fn _update(
        &self,
        run: &Run,
        mut state: Option<RepositoryState>,
        metrics: &mut RrdpRepositoryMetrics,
    ) -> Result<bool, Failed> {
        let notify = match run.collector.http.notification_file(
            &self.rpki_notify,
            state.as_ref(),
            &mut metrics.notify_status
        ) {
            Ok(Some(notify)) => notify,
            Ok(None) => {
                self.not_modified(run, state.as_mut())?;
                return Ok(true)
            }
            Err(Failed) => {
                return Ok(false)
            }
        };

        metrics.serial = Some(notify.content.serial());
        metrics.session = Some(notify.content.session_id());
        match self.delta_update(run, state.as_ref(), &notify, metrics)? {
            None => {
                return Ok(true)
            }
            Some(reason) => {
                metrics.snapshot_reason = Some(reason)
            }
        }
        self.snapshot_update(run, &notify, metrics)
    }

    /// Handle the case of a Not Modified response.
    fn not_modified(
        &self,
        run: &Run,
        state: Option<&mut RepositoryState>,
    ) -> Result<(), Failed> {
        debug!("RRDP {}: Not modified.", self.rpki_notify);
        if let Some(state) = state {
            state.touch(run.collector.fallback_time);
            state.write(self)?
        }
        Ok(())
    }

    /// Performs a snapshot update and returns whether that succeeded.
    ///
    /// The URI and expected meta-data of the snapshot file are taken from
    /// `notify`.
    fn snapshot_update(
        &self,
        run: &Run,
        notify: &Notification,
        metrics: &mut RrdpRepositoryMetrics,
    ) -> Result<bool, Failed> {
        debug!("RRDP {}: updating from snapshot.", self.rpki_notify);
        match SnapshotUpdate::new(
            run.collector, self, notify, metrics
        ).try_update() {
            Ok(()) => {
                debug!(
                    "RRDP {}: snapshot update completed.",
                    self.rpki_notify
                );
                Ok(true)
            }
            Err(SnapshotError::Fatal) => Err(Failed),
            Err(err) => {
                warn!(
                    "RRDP {}: failed to process snapshot file {}: {}",
                    self.rpki_notify, notify.content.snapshot().uri(), err
                );
                Ok(false)
            }
        }
    }

    /// Performs a delta update of the RRDP repository.
    ///
    /// Takes information of the available deltas from `notify`. May not do
    /// anything at all if the repository is up-to-date. Returns whether the
    /// update succeeded. If `Ok(Some(reason))` is returned, a snapshot update
    /// should be tried next because of the reason given.
    fn delta_update(
        &self,
        run: &Run,
        state: Option<&RepositoryState>,
        notify: &Notification,
        metrics: &mut RrdpRepositoryMetrics,
    ) -> Result<Option<SnapshotReason>, Failed> {
        let state = match state {
            Some(state) => state,
            None => return Ok(Some(SnapshotReason::NewRepository)),
        };

        let deltas = match self.calc_deltas(&notify.content, state) {
            Ok(deltas) => deltas,
            Err(reason) => return Ok(Some(reason)),
        };

        if deltas.len() > run.collector.max_delta_count {
            debug!(
                "RRDP: {}: Too many delta steps required ({})",
                self.rpki_notify, deltas.len()
            );
            return Ok(Some(SnapshotReason::TooManyDeltas))
        }

        if !deltas.is_empty() {
            let count = deltas.len();
            for (i, info) in deltas.iter().enumerate() {
                debug!(
                    "RRDP {}: Delta update step ({}/{}).",
                    self.rpki_notify, i + 1, count
                );
                if let Some(reason) = DeltaUpdate::new(
                    run.collector, self, notify.content.session_id(),
                    info, metrics
                ).try_update()? {
                    info!(
                        "RRDP {}: Delta update failed, \
                        trying snapshot instead.",
                        self.rpki_notify
                    );
                    return Ok(Some(reason))
                }
            }
        }

        // We are up-to-date now, so we can replace the state file with one
        // reflecting the notification we’ve got originally. This will update
        // the etag and last-modified data.
        RepositoryState::from_notify(
            self.rpki_notify.clone(),
            notify,
            run.collector.fallback_time
        ).write(self)?;

        debug!("RRDP {}: Delta update completed.", self.rpki_notify);
        Ok(None)
    }

    /// Calculates the slice of deltas to follow for updating.
    ///
    /// Returns an empty slice if no update is necessary.
    /// Returns a non-empty slice of the sequence of deltas to be applied.
    /// Returns `None` if updating via deltas is not possible.
    fn calc_deltas<'b>(
        &self,
        notify: &'b NotificationFile,
        state: &RepositoryState
    ) -> Result<&'b [rrdp::DeltaInfo], SnapshotReason> {
        if notify.session_id() != state.session {
            debug!("New session. Need to get snapshot.");
            return Err(SnapshotReason::NewSession)
        }
        debug!("{}: Serials: us {}, them {}.",
            self.rpki_notify, state.serial, notify.serial()
        );
        if notify.serial() == state.serial {
            return Ok(&[]);
        }

        // If there is no last delta (remember, we have a different
        // serial than the notification file) or if the last delta’s
        // serial differs from that noted in the notification file,
        // bail out.
        if notify.deltas().last().map(|delta| delta.serial())
            != Some(notify.serial())
        {
            debug!("Last delta serial differs from current serial.");
            return Err(SnapshotReason::BadDeltaSet)
        }

        let mut deltas = notify.deltas();
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
            match first.serial().cmp(&serial) {
                cmp::Ordering::Greater => {
                    debug!("First delta is too new ({})", first.serial());
                    return Err(SnapshotReason::OutdatedLocal)
                }
                cmp::Ordering::Equal => break,
                cmp::Ordering::Less => deltas = &deltas[1..]
            }
        }
        Ok(deltas)
    }
}


//------------ SnapshotUpdate ------------------------------------------------

/// An update to a repository performed from a snapshot file.
///
/// For this type of update, we collect all the published objects in the
/// repository’s temp directory and move it over to the object directory upon
/// success.
struct SnapshotUpdate<'a> {
    /// The collector.
    collector: &'a Collector,

    /// The repository.
    repository: &'a Repository,

    /// The notification file pointing to the snapshot.
    notify: &'a Notification,

    /// The metrics for the update.
    metrics: &'a mut RrdpRepositoryMetrics,
}

impl<'a> SnapshotUpdate<'a> {
    pub fn new(
        collector: &'a Collector,
        repository: &'a Repository,
        notify: &'a Notification,
        metrics: &'a mut RrdpRepositoryMetrics,
    ) -> Self {
        SnapshotUpdate { collector, repository, notify, metrics }
    }
    
    pub fn try_update(mut self) -> Result<(), SnapshotError> {
        let response = match self.collector.http.response(
            self.notify.content.snapshot().uri(), false
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

        let tmp_base = self.repository.tmp_base();
        if let Err(err) = fs::create_dir_all(&tmp_base) {
            error!(
                "Fatal: failed to create RRDP temporary directory {}: {}",
                tmp_base.display(), err
            );
            return Err(SnapshotError::Fatal)
        }

        match self.try_process(response) {
            Ok(()) => {
                // Remove the state file to signal we are messing with the
                // directory.
                RepositoryState::remove(self.repository)?;

                // Delete the old object base and move the tmp base over.
                // Note that the old object base may actually be missing.
                let object_base = self.repository.object_base();
                if let Err(err) = fs::remove_dir_all(&object_base) {
                    if err.kind() != io::ErrorKind::NotFound {
                        error!(
                            "Fatal: failed to delete RRDP object \
                            directory {}: {}",
                            object_base.display(), err
                        );
                        return Err(SnapshotError::Fatal)
                    }
                }
                // We don’t need to ensure presence of the repository directory
                // since the tmp_base lives there, too. So this really is
                // just a rename.
                if let Err(err) = fs::rename(&tmp_base, &object_base) {
                    error!(
                        "Fatal: failed to rename {} to {}: {}",
                        tmp_base.display(), object_base.display(), err
                    );
                    return Err(SnapshotError::Fatal)
                }

                // Write the new state.
                RepositoryState::from_notify(
                    self.repository.rpki_notify.clone(),
                    self.notify,
                    self.collector.fallback_time
                ).write(self.repository)?;

                Ok(())
            }
            Err(err) => {
                if let Err(err) = fs::remove_dir_all(&tmp_base) {
                    error!(
                        "Fatal: failed to delete RRDP temporary \
                        directory {}:{}",
                        tmp_base.display(), err
                    );
                    return Err(SnapshotError::Fatal)
                }
                Err(err)
            }
        }
    }

    pub fn try_process(
        &mut self,
        response: HttpResponse
    ) -> Result<(), SnapshotError> {
        let mut reader = io::BufReader::new(HashRead::new(response));
        self.process(&mut reader)?;
        let hash = reader.into_inner().into_hash();
        if verify_slices_are_equal(
            hash.as_ref(),
            self.notify.content.snapshot().hash().as_ref()
        ).is_err() {
            return Err(SnapshotError::HashMismatch)
        }
        Ok(())
    }
}

impl<'a> ProcessSnapshot for SnapshotUpdate<'a> {
    type Err = SnapshotError;

    fn meta(
        &mut self,
        session_id: Uuid,
        serial: u64,
    ) -> Result<(), Self::Err> {
        if session_id != self.notify.content.session_id() {
            return Err(SnapshotError::SessionMismatch {
                expected: self.notify.content.session_id(),
                received: session_id
            })
        }
        if serial != self.notify.content.serial() {
            return Err(SnapshotError::SerialMismatch {
                expected: self.notify.content.serial(),
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
        let path = self.repository.tmp_object_path(&uri);
        let mut data = MaxSizeRead::new(data, self.collector.max_object_size);
        if RepositoryObject::create(&path, &mut data).is_err() {
            if data.was_triggered() {
                Err(SnapshotError::LargeObject(uri))
            }
            else {
                Err(SnapshotError::Fatal)
            }
        }
        else {
            Ok(())
        }
    }
}


//------------ DeltaUpdate ---------------------------------------------------

/// An update to a repository performed from a delta file.
///
/// For this kind of update, we collect newly published and updated objects in
/// the repository’s temp directory and remember them as well as all deleted
/// objects and if everything is okay, copy files over to and delete files in
/// the object directory.
struct DeltaUpdate<'a> {
    /// The collector.
    collector: &'a Collector,

    /// The repository.
    repository: &'a Repository,

    /// The session ID of the RRDP session.
    session_id: Uuid,

    /// Information about the delta file.
    info: &'a DeltaInfo,

    /// The metrics for the update.
    metrics: &'a mut RrdpRepositoryMetrics,

    /// The URIs of objects to be copied from the temp to the object directory.
    publish: HashSet<uri::Rsync>,

    /// The URIs of objects to be deleted.
    withdraw: HashSet<uri::Rsync>,
}

impl<'a> DeltaUpdate<'a> {
    /// Creates a new delta update.
    pub fn new(
        collector: &'a Collector,
        repository: &'a Repository,
        session_id: Uuid,
        info: &'a DeltaInfo,
        metrics: &'a mut RrdpRepositoryMetrics,
    ) -> Self {
        DeltaUpdate {
            collector, repository, session_id, info, metrics,
            publish: Default::default(), withdraw: Default::default(),
        }
    }

    /// Tries to perform the delta update.
    pub fn try_update(
        mut self
    ) -> Result<Option<SnapshotReason>, Failed> {
        if let Err(err) = self.collect_changes() {
            warn!(
                "RRDP {}: failed to process delta: {}",
                self.repository.rpki_notify, err
            );
            return Ok(Some(SnapshotReason::ConflictingDelta))
        }
        self.apply_changes()?;
        Ok(None)
    }

    fn collect_changes(&mut self) -> Result<(), DeltaError> {
        let response = match self.collector.http.response(
            self.info.uri(), false
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
        self.try_process(response)?;
        if let Some(uri) = self.publish.intersection(&self.withdraw).next() {
            return Err(DeltaError::ObjectRepeated { uri: uri.clone() })
        }
        Ok(())
    }

    /// Applies the collected changes.
    ///
    /// If anything goes wrong here, we will have to wipe the repository as it
    /// will be in an inconsistent state.
    fn apply_changes(self) -> Result<(), Failed> {
        // First, delete the state file to mark the repository as being in
        // flux.
        RepositoryState::remove(self.repository)?;

        if self._apply_changes().is_err() {
            if let Err(err) = fs::remove_dir_all(&self.repository.path) {
                error!(
                    "Fatal: failed to delete repository directory {}: {}",
                    self.repository.path.display(), err
                );
            }
            return Err(Failed)
        }

        // Write a state file to reflect how far we’ve come.
        RepositoryState::new_for_delta(
            self.repository.rpki_notify.clone(),
            self.session_id,
            self.info.serial(),
            self.collector.fallback_time
        ).write(self.repository)?;
        Ok(())
    }

    /// Actually applies the changes, not dealing with errors.
    fn _apply_changes(&self) -> Result<(), Failed> {
        for uri in &self.publish {
            let tmp_path = self.repository.tmp_object_path(uri);
            let obj_path = self.repository.object_path(uri);
            if let Err(err) = fs::remove_file(&obj_path) {
                if err.kind() != io::ErrorKind::NotFound {
                    error!(
                        "Fatal: failed to delete {}: {}",
                        obj_path.display(), err
                    );
                    return Err(Failed)
                }
            }
            if let Some(parent) = obj_path.parent() {
                if let Err(err) = fs::create_dir_all(&parent) {
                    error!(
                        "Fatal: failed to create directory {}: {}",
                        parent.display(), err
                    );
                    return Err(Failed)
                }
            }
            if let Err(err) = fs::rename(&tmp_path, &obj_path) {
                error!(
                    "Fatal: failed to move {} to {}: {}",
                    tmp_path.display(), obj_path.display(), err
                );
                return Err(Failed)
            }
        }
        for uri in &self.withdraw {
            let obj_path = self.repository.object_path(uri);
            if let Err(err) = fs::remove_file(&obj_path) {
                if err.kind() != io::ErrorKind::NotFound {
                    error!(
                        "Fatal: failed to delete {}: {}",
                        obj_path.display(), err
                    );
                    return Err(Failed)
                }
            }
        }
        Ok(())
    }

    pub fn try_process(
        &mut self,
        response: HttpResponse
    ) -> Result<(), DeltaError> {
        let mut reader = io::BufReader::new(HashRead::new(response));
        self.process(&mut reader)?;
        let hash = reader.into_inner().into_hash();
        if verify_slices_are_equal(
            hash.as_ref(),
            self.info.hash().as_ref()
        ).is_err() {
            return Err(DeltaError::DeltaHashMismatch)
        }
        Ok(())
    }

    /// Checks whether the object has the given hash.
    ///
    /// If the hash is `None`, actually checks that the object doesn’t
    /// exist.
    fn check_hash(
        &self, uri: &uri::Rsync, expected: Option<rrdp::Hash>
    ) -> Result<(), DeltaError> {
        let current = RepositoryObject::load_hash(
            &self.repository.object_path(uri)
        )?;
        if current == expected {
            Ok(())
        }
        else if expected.is_none() {
            Err(DeltaError::ObjectAlreadyPresent { uri: uri.clone() })
        }
        else if current.is_none() {
            Err(DeltaError::MissingObject { uri: uri.clone() })
        }
        else {
            Err(DeltaError::ObjectHashMismatch { uri: uri.clone() })
        }
    }
}

impl<'a> ProcessDelta for DeltaUpdate<'a> {
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
        if serial != self.info.serial() {
            return Err(DeltaError::SerialMismatch {
                expected: self.info.serial(),
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
        self.check_hash(&uri, hash)?;
        let mut data = MaxSizeRead::new(data, self.collector.max_object_size);
        let path = self.repository.tmp_object_path(&uri);
        if RepositoryObject::create(&path, &mut data).is_err() {
            if data.was_triggered() {
                return Err(DeltaError::LargeObject(uri))
            }
            else {
                return Err(DeltaError::Fatal)
            }
        }
        if !self.publish.insert(uri.clone()) {
            return Err(DeltaError::ObjectRepeated { uri })
        }
        Ok(())
    }

    fn withdraw(
        &mut self,
        uri: uri::Rsync,
        hash: rrdp::Hash
    ) -> Result<(), Self::Err> {
        self.check_hash(&uri, Some(hash))?;
        if !self.withdraw.insert(uri.clone()) {
            return Err(DeltaError::ObjectRepeated { uri })
        }
        Ok(())
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

    /// The timeout for requests.
    timeout: Option<Duration>,
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
        builder = builder.timeout(None); // Set per request.
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
            timeout: config.rrdp_timeout,
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
        self._response(uri, self.client().get(uri.as_str()), multi)
    }

    /// Creates a response from a request builder.
    fn _response(
        &self,
        uri: &uri::Https,
        mut request: RequestBuilder,
        multi: bool
    ) -> Result<HttpResponse, reqwest::Error> {
        if let Some(timeout) = self.timeout {
            request = request.timeout(timeout);
        }
        request.send().map(|response| {
            HttpResponse::create(response, uri, &self.response_dir, multi)
        })
    }

    /// Requests, parses, and returns the given RRDP notification file.
    ///
    /// The value referred to by `status` will be updated to the received
    /// status code or `HttpStatus::Error` if the request failed.
    ///
    /// Returns the notification file on success.
    pub fn notification_file(
        &self,
        uri: &uri::Https,
        state: Option<&RepositoryState>,
        status: &mut HttpStatus,
    ) -> Result<Option<Notification>, Failed> {
        let mut request = self.client().get(uri.as_str());
        if let Some(state) = state {
            if let Some(etag) = state.etag.as_ref() {
                request = request.header(
                    header::IF_NONE_MATCH, etag.as_ref()
                );
            }
            if let Some(ts) = state.last_modified_ts {
                request = request.header(
                    header::IF_MODIFIED_SINCE,
                    format_http_date(Utc.timestamp(ts, 0))
                );
            }
        }
        let response = match self._response(uri, request, true) {
            Ok(response) => {
                *status = response.status().into();
                response
            }
            Err(err) => {
                warn!("RRDP {}: {}", uri, err);
                *status = HttpStatus::Error;
                return Err(Failed)
            }
        };

        if response.status() == StatusCode::NOT_MODIFIED {
            Ok(None)
        }
        else if !response.status().is_success() {
            warn!(
                "RRDP {}: Getting notification file failed with status {}",
                uri, response.status()
            );
            Err(Failed)
        }
        else {
            Notification::from_response(uri, response).map(Some)
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
                creating directory {} failed: {}",
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

    /// Returns the value of the ETag header if present.
    ///
    /// The returned value is the complete content. That is, it includes the
    /// quotation marks and a possible `W/` prefix.
    ///
    /// The method quietly returns `None` if the content of a header is
    /// malformed or if there is more than one occurence of the header.
    ///
    /// The method returns a `Bytes` value as there is a good chance the
    /// tag is short enough to be be inlined.
    pub fn etag(&self) -> Option<Bytes> {
        let mut etags = self.response.headers()
            .get_all(header::ETAG)
            .into_iter();
        let etag = etags.next()?;
        if etags.next().is_some() {
            return None
        }
        Self::parse_etag(etag.as_bytes())
    }

    /// Parses the ETag value.
    ///
    /// This is a separate function to make testing easier.
    fn parse_etag(etag: &[u8]) -> Option<Bytes> {
        // The tag starts with an optional case-sensitive `W/` followed by
        // `"`. Let’s remember where the actual tag starts.
        let start = if etag.starts_with(b"W/\"") {
            3
        }
        else if etag.get(0) == Some(&b'"') {
            1
        }
        else {
            return None
        };

        // We need at least one more character. Empty tags are allowed.
        if etag.len() <= start {
            return None
        }

        // The tag ends with a `"`.
        if etag.last() != Some(&b'"') {
            return None
        }

        Some(Bytes::copy_from_slice(etag))
    }

    /// Returns the value of the Last-Modified header if present.
    ///
    /// The method quietly returns `None` if the content of a header is
    /// malformed or if there is more than one occurence of the header.
    pub fn last_modified(&self) -> Option<DateTime<Utc>> {
        let mut iter = self.response.headers()
            .get_all(header::LAST_MODIFIED)
            .into_iter();
        let value = iter.next()?;
        if iter.next().is_some() {
            return None
        }
        parse_http_date(value.to_str().ok()?)
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


//------------ Notification --------------------------------------------------

/// The notification file of an RRDP repository.
struct Notification {
    /// The content of the file.
    content: NotificationFile,

    /// The Etag value if provided.
    etag: Option<Bytes>,

    /// The Last-Modified value if provided,
    last_modified: Option<DateTime<Utc>>,
}

impl Notification {
    /// Creates a new notification from a successful HTTP response.
    ///
    /// Assumes that the response status was 200 OK.
    fn from_response(
        uri: &uri::Https, response: HttpResponse
    ) -> Result<Self, Failed> {
        let etag = response.etag();
        let last_modified = response.last_modified();
        let mut content = NotificationFile::parse(
            io::BufReader::new(response)
        ).map_err(|err| {
            warn!("RRDP {}: {}", uri, err);
            Failed
        })?;
        content.sort_deltas();
        Ok(Notification { content, etag, last_modified })
    }
}


//------------ RepositoryState -----------------------------------------------

/// The current state of an RRDP repository.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct RepositoryState {
    /// The rpkiNotify URI of the repository.
    pub rpki_notify: uri::Https,

    /// The UUID of the current session of repository.
    pub session: Uuid,

    /// The serial number within the current session.
    pub serial: u64,

    /// Unix timestamp in seconds of the time of last update of the server.
    ///
    /// We are not using `DateTime<Utc>` here since we don’t need sub-second
    /// precision and converting on the fly makes a value change when cycled
    /// through the database as its sub-second portion is forced to zero.
    pub updated_ts: i64,

    /// The time when we consider the stored data to be expired.
    pub best_before_ts: i64,

    /// The value of the date header of the notification file if present.
    ///
    /// Given as the Unix timestamp in seconds.
    pub last_modified_ts: Option<i64>,

    /// The value of the ETag header of the notification file if present.
    ///
    /// This is the complete tag including the quotation marks and possibly
    /// the weak prefix.
    pub etag: Option<Bytes>,
}

impl RepositoryState {
    /// Create the state for a delta update.
    pub fn new_for_delta(
        rpki_notify: uri::Https,
        session: Uuid,
        serial: u64,
        fallback: FallbackTime,
    ) -> Self {
        RepositoryState {
            rpki_notify,
            session,
            serial,
            updated_ts: Utc::now().timestamp(),
            best_before_ts: fallback.best_before().timestamp(),
            last_modified_ts: None,
            etag: None
        }
    }

    /// Create the state based on the notification file.
    pub fn from_notify(
        rpki_notify: uri::Https,
        notify: &Notification,
        fallback: FallbackTime,
    ) -> Self {
        RepositoryState {
            rpki_notify,
            session: notify.content.session_id(),
            serial: notify.content.serial(),
            updated_ts: Utc::now().timestamp(),
            best_before_ts: fallback.best_before().timestamp(),
            last_modified_ts: notify.last_modified.map(|x| x.timestamp()),
            etag: notify.etag.clone(),
        }
    }

    /// Returns the last update time as proper timestamp.
    pub fn updated(&self) -> DateTime<Utc> {
        Utc.timestamp(self.updated_ts, 0)
    }

    /// Returns the best before time as a proper timestamp.
    pub fn best_before(&self) -> DateTime<Utc> {
        Utc.timestamp(self.best_before_ts, 0)
    }

    /// Sets the update time to now.
    pub fn touch(&mut self, fallback: FallbackTime) {
        self.updated_ts = Utc::now().timestamp();
        self.best_before_ts = fallback.best_before().timestamp();
    }

    /// Returns whether this repository should be considered expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.best_before()
    }

    /// Reads the state file of a repository.
    pub fn load(repo: &Repository) -> Result<Option<Self>, Failed> {
        Self::load_path(&Self::file_path(repo))
    }

    /// Reads the state file at a path.
    pub fn load_path(path: &Path) -> Result<Option<Self>, Failed> {
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Ok(None)
            }
            Err(err) => {
                warn!(
                    "Failed to open repository state file {}: {}",
                    path.display(), err
                );
                return Err(Failed)
            }
        };
        Self::_read(&mut file)
        .map(Some)
        .map_err(|err| {
            warn!(
                "Failed to read repository state file {}: {}",
                path.display(), err
            );
            Failed
        })
    }

    /// Deletes the state file of a repository.
    pub fn remove(repo: &Repository) -> Result<(), Failed> {
        fatal::remove_file(&Self::file_path(repo))
    }


    /// Reads the state from an IO reader.
    fn _read(reader: &mut impl io::Read) -> Result<Self, io::Error> {
        // Version number. Must be 0u8.
        let version = u8::parse(reader)?;
        if version != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("unexpected version {}", version)
            ))
        }

        Ok(RepositoryState {
            rpki_notify: Parse::parse(reader)?,
            session: Parse::parse(reader)?,
            serial: Parse::parse(reader)?,
            updated_ts: Parse::parse(reader)?,
            best_before_ts: Parse::parse(reader)?,
            last_modified_ts: Parse::parse(reader)?,
            etag: Parse::parse(reader)?,
        })
    }

    /// Writes the state file of a repository.
    pub fn write(&self, repo: &Repository) -> Result<(), Failed> {
        let path = Self::file_path(repo);
        let mut file = match File::create(&path) {
            Ok(file) => file,
            Err(err) => {
                error!(
                    "Fatal: Failed to open repository state file {}: {}",
                    path.display(), err
                );
                return Err(Failed)
            }
        };
        self._write(&mut file).map_err(|err| {
            error!(
                "Fatal: Failed to write repository state file {}: {}",
                path.display(), err
            );
            Failed
        })
    }

    /// Writes the state to an IO writer.
    fn _write(
        &self, writer: &mut impl io::Write
    ) -> Result<(), io::Error> {
        0u8.compose(writer)?; // version
        self.rpki_notify.compose(writer)?;
        self.session.compose(writer)?;
        self.serial.compose(writer)?;
        self.updated_ts.compose(writer)?;
        self.best_before_ts.compose(writer)?;
        self.last_modified_ts.compose(writer)?;
        self.etag.compose(writer)?;
        Ok(())
    }

    pub const FILE_NAME: &'static str = "state.bin";

    pub fn file_path(repo: &Repository) -> PathBuf {
        repo.path.join(Self::FILE_NAME)
    }
}


//------------ RepositoryObject ----------------------------------------------

/// A repository object stored locally.
///
/// In order to speed up updates, we store the RRDP hash of a file before its
/// content, if we understand it.
#[derive(Clone, Debug)]
struct RepositoryObject {
    /// The RRDP hash of the object.
    #[allow(dead_code)]
    hash: rrdp::Hash,

    /// The content of the object.
    content: Bytes,
}

impl RepositoryObject {
    /// Loads a repository object from the given path.
    pub fn load(path: &Path) -> Result<Option<Self>, Failed> {
        let mut file = match Self::open(path)? {
            Some(file) => file,
            None => return Ok(None)
        };
        Self::read(&mut file).map(Some).map_err(|err| {
            error!("Fatal: failed to read {}: {}", path.display(), err);
            Failed
        })
    }

    /// Checks the hash of the objects.
    pub fn load_hash(path: &Path) -> Result<Option<rrdp::Hash>, Failed> {
        let mut file = match Self::open(path)? {
            Some(file) => file,
            None => return Ok(None)
        };
        rrdp::Hash::parse(&mut file).map(Some).map_err(|err| {
            error!("Fatal: failed to read {}: {}", path.display(), err);
            Failed
        })
    }

    /// Opens the file for a repository object.
    fn open(path: &Path) -> Result<Option<File>, Failed> {
        match File::open(path) {
            Ok(file) => Ok(Some(file)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                Ok(None)
            }
            Err(err) => {
                error!("Fatal: failed to open {}: {}", path.display(), err);
                Err(Failed)
            }
        }
    }

    /// Reads the object from a reader.
    fn read(source: &mut impl io::Read) -> Result<Self, io::Error> {
        let hash = rrdp::Hash::parse(source)?;
        let mut content = Vec::new();
        source.read_to_end(&mut content)?;
        Ok(RepositoryObject {
            hash,
            content: content.into(),
        })
    }

    /// Writes a new object using everything from reader.
    pub fn create(
        path: &Path, data: &mut impl io::Read
    ) -> Result<(), Failed> {
        if let Some(parent) = path.parent() {
            if let Err(err) = fs::create_dir_all(parent) {
                error!(
                    "Fatal: failed to create directory {}: {}.",
                    parent.display(), err
                );
                return Err(Failed)
            }
        }
        let mut target = match File::create(&path) {
            Ok(target) => target,
            Err(err) => {
                error!(
                    "Fatal: failed to open file {}: {}", path.display(), err
                );
                return Err(Failed)
            }
        };
        Self::_create(data, &mut target).map_err(|err| {
            error!(
                "Fatal: failed to write file {}: {}", path.display(), err
            );
            Failed
        })
    }

    fn _create(
        data: &mut impl io::Read, target: &mut File
    ) -> Result<(), io::Error> {
        rrdp::Hash::from([0u8; 32]).compose(target)?;
        let mut reader = HashRead::new(data);
        io::copy(&mut reader, target)?;
        target.seek(SeekFrom::Start(0))?;
        reader.into_hash().compose(target)?;
        Ok(())
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
        // Unwrap should be safe: This can only fail if the slice has the
        // wrong length.
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


//------------ MaxSizeRead ---------------------------------------------------

/// A reader that reads until a certain limit is exceeded.
struct MaxSizeRead<R> {
    /// The wrapped reader.
    reader: R,

    /// The number of bytes left to read.
    ///
    /// If this is `None` we are allowed to read an unlimited amount.
    left: Option<u64>,

    /// Did we trigger?
    triggered: bool,
}

impl<R> MaxSizeRead<R> {
    pub fn new(reader: R, max_size: Option<u64>) -> Self {
        MaxSizeRead { reader, left: max_size, triggered: false }
    }

    pub fn was_triggered(&self) -> bool {
        self.triggered
    }
}

impl<R: io::Read> io::Read for MaxSizeRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        let res = self.reader.read(buf)?;
        if let Some(left) = self.left {
            let res64 = match u64::try_from(res) {
                Ok(res) => res,
                Err(_) => {
                    // If the usize doesn’t fit into a u64, things are
                    // definitely way too big.
                    self.left = Some(0);
                    self.triggered = true;
                    return Err(io::Error::new(
                        io::ErrorKind::Other, "size limit exceeded"
                    ))
                }
            };
            if res64 > left {
                self.left = Some(0);
                self.triggered = true;
                Err(io::Error::new(
                    io::ErrorKind::Other, "size limit exceeded")
                )
            }
            else {
                self.left = Some(left - res64);
                Ok(res)
            }
        }
        else {
            Ok(res)
        }
    }
}


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

    /// There were too many deltas to process.
    TooManyDeltas,
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
            TooManyDeltas => "too-many-deltas",
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

    pub fn is_not_modified(self) -> bool {
        matches!(
            self,
            HttpStatus::Response(code) if code == StatusCode::NOT_MODIFIED
        )
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
    LargeObject(uri::Rsync),
    Fatal,
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

impl From<Failed> for SnapshotError {
    fn from(_: Failed) -> Self {
        SnapshotError::Fatal
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
            SnapshotError::LargeObject(ref uri) => {
                write!(f, "object exceeds size limit: {}", uri)
            }
            SnapshotError::Fatal => Ok(())
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
    ObjectRepeated {
        uri: uri::Rsync,
    },
    DeltaHashMismatch,
    LargeObject(uri::Rsync),
    Fatal,
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

impl From<Failed> for DeltaError {
    fn from(_: Failed) -> Self {
        DeltaError::Fatal
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
            DeltaError::ObjectRepeated { ref uri } => {
                write!(f, "object appears multiple times: {}", uri)
            }
            DeltaError::LargeObject(ref uri) => {
                write!(f, "object exceeds size limit: {}", uri)
            }
            DeltaError::DeltaHashMismatch => {
                write!(f, "delta file hash value mismatch")
            }
            DeltaError::Fatal => {
                Ok(())
            }
        }
    }
}

impl error::Error for DeltaError { }


//============ Testing =======================================================

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn write_read_repository_state() {
        let orig = RepositoryState {
            rpki_notify: uri::Https::from_str(
                "https://foo.bar/bla/blubb"
            ).unwrap(),
            session: Uuid::nil(),
            serial: 12,
            updated_ts: 28,
            best_before_ts: 892,
            last_modified_ts: Some(23),
            etag: Some(Bytes::copy_from_slice(b"23890"))
        };
        let mut written = Vec::new();
        orig._write(&mut written).unwrap();
        let mut slice = written.as_slice();
        let decoded = RepositoryState::_read(&mut slice).unwrap();
        assert!(slice.is_empty());
        assert_eq!(orig, decoded);
    }
}

