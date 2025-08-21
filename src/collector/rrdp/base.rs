use std::error::Error;
use std::{cmp, fs, io};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};
use std::time::SystemTime;
use bytes::Bytes;
use log::{debug, error, info, warn};
use rpki::uri;
use rpki::crypto::DigestAlgorithm;
use rpki::rrdp::{DeltaInfo, DeltaListError, NotificationFile};
use tempfile::NamedTempFile;
use crate::config::Config;
use crate::error::{Fatal, RunFailed};
use crate::log::LogBookWriter;
use crate::metrics::{Metrics, RrdpRepositoryMetrics};
use crate::utils::fatal;
use crate::utils::archive::{ArchiveError, OpenError};
use crate::utils::dump::DumpRegistry;
use crate::utils::json::JsonBuilder;
use crate::utils::sync::{Mutex, RwLock};
use crate::utils::uri::UriExt;
use super::archive::{
    FallbackTime, RrdpArchive, RepositoryState, SnapshotRrdpArchive,
};
use super::http::{HttpClient, HttpStatus};
use super::update::{
    DeltaUpdate, Notification, SnapshotError, SnapshotReason, SnapshotUpdate
};


//------------ Collector -----------------------------------------------------

/// The local copy of RPKI repositories synchronized via RRDP.
#[derive(Debug)]
pub struct Collector {
    /// The path of the directory we store all our data in.
    working_dir: PathBuf,

    /// The HTTP client.
    http: HttpClient,

    /// Various configuration options.
    config: RrdpConfig,
}

impl Collector {
    /// Initializes the RRDP collector without creating a value.
    ///
    /// This function is called implicitely by [`new`][Collector::new].
    pub fn init(config: &Config) -> Result<(), Fatal> {
        let _ = Self::create_working_dir(config)?;
        Ok(())
    }

    /// Creates the working dir and returns its path.
    fn create_working_dir(config: &Config) -> Result<PathBuf, Fatal> {
        let working_dir = config.cache_dir.join("rrdp");

        if config.fresh {
            if let Err(err) = fs::remove_dir_all(&working_dir) {
                if err.kind() != io::ErrorKind::NotFound {
                    error!(
                        "Failed to delete RRDP working directory at {}: {}",
                        working_dir.display(), err
                    );
                    return Err(Fatal)
                }
            }
        }

        if let Err(err) = fs::create_dir_all(&working_dir) {
            error!(
                "Failed to create RRDP working directory {}: {}.",
                working_dir.display(), err
            );
            return Err(Fatal);
        }
        Ok(working_dir)
    }

    /// Creates a new RRDP collector.
    ///
    /// Returns `Ok(None)` if RRDP was disabled.
    pub fn new(config: &Config) -> Result<Option<Self>, Fatal> {
        if config.disable_rrdp {
            return Ok(None)
        }
        Ok(Some(Self {
            working_dir: Self::create_working_dir(config)?,
            http: HttpClient::new(config)?,
            config: config.into(),
        }))
    }

    pub fn ignite(&mut self) -> Result<(), Fatal> {
        self.http.ignite()
    }

    /// Sanitizes the stored data.
    ///
    /// Validates all repository archives and deletes those that are corrupt.
    pub fn sanitize(&self) -> Result<(), Fatal> {
        for entry in fatal::read_dir(&self.working_dir)? {
            let entry = entry?;
            if !entry.is_dir() || entry.file_name() == "tmp" {
                continue;
            }
            for entry in fatal::read_dir(entry.path())? {
                let entry = entry?;
                if !entry.is_file() {
                    continue;
                }
                match RrdpArchive::verify(entry.path()) {
                    Ok(_) | Err(OpenError::NotFound) => { }
                    Err(OpenError::Archive(ArchiveError::Io(err))) => {
                        error!(
                            "Fatal: Failed to read RRDP repository archive\
                             {}: {}",
                             entry.path().display(), err
                        );
                        return Err(Fatal)
                    }
                    Err(OpenError::Archive(ArchiveError::Corrupt(_))) => {
                        match fs::remove_file(entry.path()) {
                            Ok(()) => {
                                info!(
                                    "Deleting corrupt RRDP repository \
                                     archive {}.",
                                    entry.path().display()
                                );
                            }
                            Err(err) => {
                                error!(
                                    "Fatal: Failed to delete corrupt RRDP \
                                    repository archive {}: {}.",
                                    entry.path().display(), err
                                );
                                return Err(Fatal)
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub fn start(&self) -> Run<'_> {
        Run::new(self)
    }

    #[allow(clippy::mutable_key_type)]
    pub fn dump(&self, dir: &Path) -> Result<(), Fatal> {
        let dir = dir.join("rrdp");
        debug!("Dumping RRDP collector content from {} to {}", 
            self.working_dir.display(), 
            dir.display()
        );
        let mut registry = DumpRegistry::new(dir);
        let mut states = HashMap::new();
        for entry in fatal::read_dir(&self.working_dir)? {
            let entry = entry?;
            if !entry.is_dir() || entry.file_name() == "tmp" {
                continue;
            }
            for entry in fatal::read_dir(entry.path())? {
                let entry = entry?;
                if entry.is_file() {
                    if let Err(err) = self.dump_repository(
                        entry.into_path().into(), &mut registry, &mut states
                    ) {
                        if err.is_fatal() {
                            return Err(Fatal)
                        }
                    }
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
        repo_path: Arc<PathBuf>,
        registry: &mut DumpRegistry,
        state_registry: &mut HashMap<uri::Https, RepositoryState>,
    ) -> Result<(), RunFailed> {
        let archive = RrdpArchive::open(repo_path.clone())?;
        let state = archive.load_state()?;
        let target_path = registry.get_repo_path(Some(&state.rpki_notify));
        let object_path = target_path.join("rsync");
        
        for item in archive.objects()? {
            let (uri, data) = item?;
            let path = object_path.join(
                uri.canonical_module().as_ref()
            ).join(uri.path());
            fatal::create_parent_all(&path)?;
            fatal::write_file(&path, &data)?;
        }

        state_registry.insert(state.rpki_notify.clone(), state);
        Ok(())
    }

    /// Dumps the repositories.json.
    #[allow(clippy::mutable_key_type)]
    fn dump_repository_json(
        &self,
        repos: DumpRegistry,
        states: HashMap<uri::Https, RepositoryState>,
    ) -> Result<(), Fatal> {
        fatal::create_dir_all(repos.base_dir())?;
        let path = repos.base_dir().join("repositories.json");
        if let Err(err) = fs::write(
            &path, 
            JsonBuilder::build(|builder| {
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
                                if let Some(updated) = state.updated() {
                                    builder.member_str(
                                        "updated",
                                        updated.to_rfc3339()
                                    );
                                }
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
            return Err(Fatal)
        }

        Ok(())
    }
}

impl Collector {
    /// Returns the path for a repository.
    fn repository_path(
        &self, rpki_notify: &uri::Https
    ) -> Result<PathBuf, Fatal> {
        let mut path = self.working_dir.clone();
        path.push(rpki_notify.canonical_authority().as_ref());
        if let Err(err) = fs::create_dir_all(&path) {
            error!(
                "Failed to create RRDP archive directory {}: {}",
                path.display(), err
            );
            return Err(Fatal)
        }

        let alg = DigestAlgorithm::sha256();
        let mut dir = String::with_capacity(
              alg.digest_len()
              + 4 // ".bin"
        );
        crate::utils::str::append_hex(
            alg.digest(rpki_notify.as_slice()).as_ref(),
            &mut dir
        );
        dir.push_str(".bin");
        path.push(&dir);
        Ok(path)
    }

    fn temp_file(
        &self
    ) -> Result<(fs::File, Arc<PathBuf>), Fatal> {
        let base = self.working_dir.join("tmp");
        if let Err(err) = fs::create_dir_all(&base) {
            error!(
                "Failed to create RRDP temporary directory {}: {}",
                base.display(), err
            );
            return Err(Fatal)
        }
        let file = match NamedTempFile::new_in(&base) {
            Ok(file) => file,
            Err(err) => {
                error!(
                    "Failed to create temporary RRDP file in {}: {}",
                    base.display(), err
                );
                return Err(Fatal)
            }
        };
        let (file, path) = file.keep().map_err(|err| {
            error!(
                "Failed to create temporary RRDP file {}: {}",
                err.file.path().display(), err.error
            );
            Fatal
        })?;
        Ok((file, path.into()))
    }

    pub(super) fn http(&self) -> &HttpClient {
        &self.http
    }

    pub(super) fn config(&self) -> &RrdpConfig {
        &self.config
    }
}


//------------ Run -----------------------------------------------------------

/// Using the collector for a single validation run.
#[derive(Debug)]
pub struct Run<'a> {
    /// A reference to the underlying collector.
    collector: &'a Collector,

    /// A set of the repositories we have updated already.
    updated: RwLock<HashMap<uri::Https, LoadResult<Repository>>>,

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
        Self {
            collector,
            updated: Default::default(),
            running: Default::default(),
            metrics: Default::default(),
        }
    }

    /// Loads a trust anchor certificate identified by an HTTPS URI.
    ///
    /// This just downloads the file. It is not cached since that is done
    /// by the store anyway.
    pub fn load_ta(&self, uri: &uri::Https) -> Option<Bytes> {
        let mut response = match self.collector.http.response(uri) {
            Ok(response) => response,
            Err(_) => return None,
        };
        if response.content_length() > self.collector.config().max_object_size {
            warn!(
                "Trust anchor certificate {uri} exceeds size limit. \
                 Ignoring."
            );
            return None
        }
        let mut bytes = Vec::new();
        if let Err(err) = response.copy_to(&mut bytes) {
            info!("Failed to get trust anchor {uri}: {err}");
            return None
        }
        Some(Bytes::from(bytes))
    }

    /// Returns whether an RRDP repository has been updated already.
    ///
    /// This does not mean the repository is actually up-to-date or even
    /// available as an update may have failed.
    pub fn was_updated(&self, rpki_notify: &uri::Https) -> bool {
        self.updated.read().contains_key(rpki_notify)
    }

    /// Accesses an RRDP repository.
    ///
    /// This method blocks if the repository is deemed to need updating until
    /// the update has finished.
    ///
    /// Returns the result of the update of the repository and whether this
    /// is the first attempt at updating the repository.
    pub fn load_repository(
        &self, rpki_notify: &uri::Https
    ) -> Result<LoadResult, RunFailed> {
        // If we already tried updating, we can return already.
        if let Some(repo) = self.updated.read().get(rpki_notify) {
            return repo.read()
        }

        // Get a clone of the (arc-ed) mutex. Make a new one if there isn’t
        // yet.
        let mutex = {
            self.running.write()
            .entry(rpki_notify.clone()).or_default()
            .clone()
        };

        // Acquire the mutex. Once we have it, see if the repository is
        // up-to-date which happens if someone else had the mutex first.
        let _lock = mutex.lock();
        if let Some(repo) = self.updated.read().get(rpki_notify) {
            self.running.write().remove(rpki_notify);
            return repo.read()
        }

        let mut log = LogBookWriter::new(
            self.collector.config.log_repository_issues.then(|| {
                format!("RRDP {}: ", rpki_notify)
            })
        );

        // Now we can update the repository. But we only do this if we like
        // the URI.
        let (repo, mut metrics) = if
            self.collector.config().filter_dubious
            && rpki_notify.has_dubious_authority()
        {
            let mut metrics = RrdpRepositoryMetrics::new(rpki_notify.clone());
            metrics.notify_status = HttpStatus::Rejected;
            log.warn(format_args!(
                "Dubious host name. Not using the repository."
            ));
            (LoadResult::Unavailable, metrics)
        }
        else {
            RepositoryUpdate::new(
                self.collector, rpki_notify, &mut log,
            )?.try_update()?
        };

        let log = log.into_book();
        if !log.is_empty() {
            metrics.log_book = Some(log);
        }

        // Insert metrics.
        self.metrics.lock().push(metrics);

        let res = repo.read()?;

        // Insert into updated map.
        self.updated.write().insert(rpki_notify.clone(), repo);

        // Remove from running.
        self.running.write().remove(rpki_notify);

        Ok(res)
    }

    #[allow(clippy::mutable_key_type)]
    pub fn cleanup(
        &self,
        retain: &mut HashSet<uri::Https>
    ) -> Result<(), Fatal> {
        // Add all the RRDP repositories we’ve tried during this run to be
        // kept.
        for uri in self.updated.read().keys() {
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
                    return Err(Fatal)
                }
            }
            else if entry.is_dir() {
                if entry.file_name() == "tmp" {
                    self.cleanup_tmp(entry.path())?
                }
                else {
                    self.cleanup_authority(entry.path(), retain)?;
                }
            }
        }

        Ok(())
    }

    /// Cleans up an authority directory.
    pub fn cleanup_tmp(
        &self,
        path: &Path,
    ) -> Result<(), Fatal> {
        for entry in fatal::read_dir(path)? {
            let entry = entry?;
            if entry.is_file() {
                if let Err(err) = fs::remove_file(entry.path()) {
                    error!(
                        "Fatal: failed to delete file {}: {}",
                        entry.path().display(), err
                    );
                    return Err(Fatal)
                }
            }
            else if let Err(err) = fs::remove_dir_all(entry.path()) {
                error!(
                    "Fatal: failed to delete directory {}: {}",
                    entry.path().display(), err
                );
                return Err(Fatal)
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
    ) -> Result<(), Fatal> {
        for entry in fatal::read_dir(path)? {
            let entry = entry?;
            if entry.is_file() {
                let entry_path = Arc::new(entry.into_path());
                let keep = match self.keep_repository(
                    entry_path.clone(), retain
                ) {
                    Ok(some) => some,
                    Err(err) if err.should_retry() => {
                        // The RrdpArchive code has deleted the file already
                        // in this case, so we mustn’t do it again, so we
                        // pretend we want to keep it.
                        true
                    }
                    Err(_) => return Err(Fatal),
                };
                if !keep {
                    if let Err(err) = fs::remove_file(entry_path.as_ref()) {
                        error!(
                            "Fatal: failed to delete file {}: {}",
                            entry_path.display(), err
                        );
                        return Err(Fatal)
                    }
                }
            }
            else {
                // This isn’t supposed to be here. Make it go away.
                if let Err(err) = fs::remove_dir_all(entry.path()) {
                    error!(
                        "Fatal: failed to delete stray directory {}: {}",
                        entry.path().display(), err
                    );
                    return Err(Fatal)
                }
            }
        }
        Ok(())
    }

    /// Returns whether we should keep a repository.
    #[allow(clippy::mutable_key_type)]
    pub fn keep_repository(
        &self,
        path: Arc<PathBuf>,
        retain: &HashSet<uri::Https>
    ) -> Result<bool, RunFailed> {
        let archive = RrdpArchive::open(path)?;
        let state = archive.load_state()?;
        Ok(retain.contains(&state.rpki_notify))
    }

    pub fn done(self, metrics: &mut Metrics) {
        metrics.rrdp = self.metrics.into_inner()
    }
}


//------------ RrdpConfig ----------------------------------------------------

/// The configuration of the RRDP collector.
#[derive(Clone, Debug)]
pub struct RrdpConfig {
    /// Whether to filter dubious authorities in notify URIs.
    pub filter_dubious: bool,

    /// RRDP repository fallback timeout.
    ///
    /// This is the time since the last known update of an RRDP repository
    /// before it is considered non-existant.
    pub fallback_time: FallbackTime,

    /// The maximum allowed size for published objects.
    pub max_object_size: Option<u64>,

    /// The maximum number of deltas we process before using a snapshot.
    pub max_delta_count: usize,

    /// The maximum length of the delta list in a notification file.
    pub max_delta_list_len: usize,

    /// Log issues also to the process log?
    pub log_repository_issues: bool,
}

impl<'a> From<&'a Config> for RrdpConfig {
    fn from(config: &'a Config) -> Self {
        Self {
            filter_dubious: !config.allow_dubious_hosts,
            fallback_time: FallbackTime::from_config(config),
            max_object_size: config.max_object_size,
            max_delta_count: config.rrdp_max_delta_count,
            max_delta_list_len: config.rrdp_max_delta_list_len,
            log_repository_issues: config.log_repository_issues,
        }
    }
}


//------------ LoadResult ----------------------------------------------------

/// The result of trying to load a repository.
#[derive(Clone, Debug)]
pub enum LoadResult<Repo = Arc<ReadRepository>> {
    /// The update failed and there is no local copy.
    Unavailable,

    /// The update failed and any content should now be considered stale.
    Stale,

    /// The update failed but content should not be considered stale yet.
    Current,

    /// The repository was successfully updated.
    Updated(Repo),
}

impl LoadResult<Repository> {
    fn read(&self) -> Result<LoadResult, RunFailed> {
        match self {
            Self::Unavailable => Ok(LoadResult::Unavailable),
            Self::Stale => Ok(LoadResult::Stale),
            Self::Current => Ok(LoadResult::Current),
            Self::Updated(repo) => Ok(LoadResult::Updated(repo.read()?)),
        }
    }
}


//------------ ReadRepository ------------------------------------------------

/// Read access to a single RRDP repository.
#[derive(Debug)]
pub struct ReadRepository {
    /// The archive for the repository.
    archive: RrdpArchive,
}

impl ReadRepository {
    fn new(repository: &Repository) -> Result<Self, RunFailed> {
        Ok(Self {
            archive: RrdpArchive::open(repository.path.clone())?,
        })
    }

    /// Loads an object from the repository.
    ///
    /// The object is identified by its rsync URI. If the object doesn’t
    /// exist, returns `None`.
    pub fn load_object(
        &self,
        uri: &uri::Rsync
    ) -> Result<Option<Bytes>, RunFailed> {
        self.archive.load_object(uri)
    }
}


//------------ Repository ----------------------------------------------------

/// A single RRDP repository.
#[derive(Debug)]
struct Repository {
    /// The path where everything from this repository lives.
    path: Arc<PathBuf>,

    /// A reader for the repository.
    ///
    /// This is a weak arc so it gets dropped if nobody is using it any more.
    read: Mutex<Weak<ReadRepository>>,
}

impl Repository {
    fn new(path: impl Into<Arc<PathBuf>>) -> Self {
        Self {
            path: path.into(),
            read: Mutex::new(Weak::new())
        }
    }

    pub fn read(&self) -> Result<Arc<ReadRepository>, RunFailed> {
        let mut read = self.read.lock();
        if let Some(res) = read.upgrade() {
            return Ok(res)
        }
        let res = Arc::new(ReadRepository::new(self)?);
        *read = Arc::downgrade(&res);
        Ok(res)
    }
}


//------------ RepositoryUpdate ----------------------------------------------

/// All the state necessary to update a repository.
struct RepositoryUpdate<'a> {
    collector: &'a Collector,
    path: Arc<PathBuf>,
    rpki_notify: &'a uri::Https,
    metrics: RrdpRepositoryMetrics,
    log: &'a mut LogBookWriter,
}

impl<'a> RepositoryUpdate<'a> {
    fn new(
        collector: &'a Collector,
        rpki_notify: &'a uri::Https,
        log: &'a mut LogBookWriter,
    ) -> Result<Self, RunFailed> {
        Ok(Self {
            collector,
            path: Arc::new(collector.repository_path(rpki_notify)?),
            rpki_notify,
            metrics: RrdpRepositoryMetrics::new(rpki_notify.clone()),
            log,
        })
    }

    /// Creates the repository by trying to update it.
    fn try_update(
        mut self
    ) -> Result<(LoadResult<Repository>, RrdpRepositoryMetrics), RunFailed> {
        let current = match RrdpArchive::try_open(self.path.clone()) {
            Ok(Some(archive)) => {
                let state = archive.load_state()?;
                Some((archive, state))
            }
            Ok(None) => None,
            Err(err) => {
                if err.should_retry() {
                    // RrdpArchive::try_open should already have deleted the
                    // file, so we can happily pretend it never existed.
                    None
                }
                else {
                    return Err(err)
                }
            }
        };

        let start_time = SystemTime::now();
        let is_current = match current.as_ref() {
            Some(current) => !current.1.is_expired(),
            None => false,
        };
        let best_before = current.as_ref().and_then(|current|
            current.1.best_before()
        );

        let is_updated = self.update(current)?;

        self.metrics.duration = SystemTime::now().duration_since(start_time);

        let res = if is_updated {
            LoadResult::Updated(Repository::new(self.path))
        }
        else if is_current {
            LoadResult::Current
        }
        else if let Some(date) = best_before {
            self.log.info(format_args!(
                "Update failed and current copy is expired since {date}.",
            ));
            LoadResult::Stale
        }
        else {
            self.log.info(format_args!(
                "Update failed and there is no current copy."
            ));
            LoadResult::Unavailable
        };
        Ok((res, self.metrics))
    }

    /// Performs the actual update.
    ///
    /// Returns `Ok(false)` if the update failed.
    fn update(
        &mut self,
        current: Option<(RrdpArchive, RepositoryState)>,
    ) -> Result<bool, RunFailed> {
        let notify = match Notification::get(
            &self.collector.http, self.rpki_notify,
            current.as_ref().map(|x| &x.1),
            &mut self.metrics.notify_status,
            self.collector.config.max_delta_list_len,
            self.log,
        ) {
            Ok(Some(notify)) => notify,
            Ok(None) => {
                self.not_modified(current)?;
                return Ok(true)
            }
            Err(_) => return Ok(false)
        };

        self.metrics.serial = Some(notify.content().serial());
        self.metrics.session = Some(notify.content().session_id());

        if let Some((archive, state)) = current {
            match self.delta_update(&notify, archive, state)? {
                None => {
                    return Ok(true)
                }
                Some(reason) => {
                    self.metrics.snapshot_reason = Some(reason)
                }
            }
        }
        else {
            self.metrics.snapshot_reason = Some(SnapshotReason::NewRepository);
        }
        self.snapshot_update(&notify)
    }

    /// Handle the case of a Not Modified response.
    fn not_modified(
        &mut self,
        current: Option<(RrdpArchive, RepositoryState)>,
    ) -> Result<(), RunFailed> {
        self.log.info(format_args!("Not modified."));
        if let Some((mut archive, mut state)) = current {
            // Copy serial and session to the metrics so they will still be
            // present.
            self.metrics.serial = Some(state.serial);
            self.metrics.session = Some(state.session);
            state.touch(self.collector.config().fallback_time);
            archive.update_state(&state)?;
        }
        Ok(())
    }

    /// Performs a snapshot update and returns whether that succeeded.
    ///
    /// The URI and expected meta-data of the snapshot file are taken from
    /// `notify`.
    fn snapshot_update(
        &mut self,
        notify: &Notification,
    ) -> Result<bool, RunFailed> {
        self.log.debug(format_args!("updating from snapshot."));
        let (file, path) = self.collector.temp_file()?;
        let mut archive = SnapshotRrdpArchive::create_with_file(
            file, path.clone()
        )?;
        if let Err(err) = SnapshotUpdate::new(
            self.collector, &mut archive, notify, &mut self.metrics,
        ).try_update() {
            // XXX This should probably be done nicer. The problem is that I
            // cannot peek into the response stream to see if it has a chance
            // of being processable (e.g. is empty). This means that it will
            // end up as an XML error, which whilst technically true is not
            // really helpful in the case of a broken/timed out HTTP stream.
            if let SnapshotError::RunFailed(err) = err {
                self.log.debug(format_args!("snapshot update failed."));
                return Err(err)
            }
            else if let SnapshotError::Http(err) = err {
                if let Some(source) = err.source() {
                    warn!(
                        "RRDP {}: Failed to process snapshot file {}: {} ({})",
                        self.rpki_notify, notify.content().snapshot().uri(), 
                        err, source
                    );
                } else {
                    warn!(
                        "RRDP {}: Failed to process snapshot file {}: {}",
                        self.rpki_notify, notify.content().snapshot().uri(), 
                        err
                    );
                }
                return Ok(false)
            } 
            else if let SnapshotError::Rrdp(err) = err {

                let mut err: &dyn Error = &err;
                while let Some(e) = err.source() {
                    err = e;
                }
                warn!("RRDP {}: Failed to process snapshot file XML {}: {}", 
                    self.rpki_notify, notify.content().snapshot().uri(), err);
                return Ok(false);
            }
            else {
                self.log.warn(format_args!(
                    "failed to process snapshot file {}: {}",
                    notify.content().snapshot().uri(), err
                ));
                return Ok(false)
            }
        }
        
        // XXX There is a possible issue here: Someone could unlink the
        //     temp file and replace it with something new and we will now
        //     copy that to the final location.

        if let Err(err) = fs::remove_file(self.path.as_ref()) {
            if !matches!(err.kind(), io::ErrorKind::NotFound) {
                error!(
                    "Fatal: Failed to delete outdated RRDP repository file \
                     {}: {}",
                    self.path.display(), err
                );
                return Err(RunFailed::fatal())
            }
        }
        drop(archive);
        if let Err(err) = fs::rename(path.as_ref(), self.path.as_ref()) {
            error!(
                "Fatal: Failed to move new RRDP repository file {} to {}: {}",
                path.display(), self.path.display(), err
            );
            return Err(RunFailed::fatal())
        }

        self.log.debug(format_args!("snapshot update completed."));
        Ok(true)
    }

    /// Performs a delta update of the RRDP repository.
    ///
    /// Takes information of the available deltas from `notify`. May not do
    /// anything at all if the repository is up-to-date. Returns whether the
    /// update succeeded. If `Ok(Some(reason))` is returned, a snapshot update
    /// should be tried next because of the reason given.
    fn delta_update(
        &mut self,
        notify: &Notification,
        mut archive: RrdpArchive,
        state: RepositoryState,
    ) -> Result<Option<SnapshotReason>, RunFailed> {
        if let Err(err) = notify.content().delta_status() {
            match err {
                DeltaListError::Oversized => {
                    self.log.info(format_args!(
                        "Overly large delta set in notification file",
                    ));
                    return Ok(Some(SnapshotReason::LargeDeltaSet));
                }
            }
        }

        if let Err(reason) = notify.check_deltas(&state) {
            return Ok(Some(reason))
        }

        let deltas = match self.calc_deltas(notify.content(), &state) {
            Ok(deltas) => deltas,
            Err(reason) => return Ok(Some(reason)),
        };

        if !deltas.is_empty() {
            let count = deltas.len();
            for (i, info) in deltas.iter().enumerate() {
                self.log.debug(format_args!(
                    "Delta update step ({}/{}).", i + 1, count
                ));
                if let Err(err) = DeltaUpdate::new(
                    self.collector, &mut archive,
                    notify.content().session_id(),
                    info, &mut self.metrics
                ).try_update() {
                    self.log.warn(format_args!(
                        "failed to process delta: {}", err,
                    ));
                    return Ok(Some(SnapshotReason::ConflictingDelta))
                }
            }
        }

        // We are up-to-date now, so we can replace the state file with one
        // reflecting the notification we’ve got originally. This will update
        // the etag and last-modified data.
        if let Err(err) = archive.update_state(
            &notify.to_repository_state(self.collector.config.fallback_time)
        ) {
            if err.should_retry() {
                return Ok(Some(SnapshotReason::CorruptArchive))
            }
            else {
                return Err(err)
            }
        }

        self.log.debug(format_args!("Delta update completed."));
        Ok(None)
    }

    /// Calculates the slice of deltas to follow for updating.
    ///
    /// Returns an empty slice if no update is necessary.
    /// Returns a non-empty slice of the sequence of deltas to be applied.
    fn calc_deltas<'b>(
        &mut self,
        notify: &'b NotificationFile,
        state: &RepositoryState
    ) -> Result<&'b [DeltaInfo], SnapshotReason> {
        if notify.session_id() != state.session {
            self.log.debug(format_args!(
                "New session. Need to get snapshot."
            ));
            return Err(SnapshotReason::NewSession)
        }
        self.log.debug(format_args!(
            "Serials: us {}, them {}.", state.serial, notify.serial()
        ));
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
            self.log.debug(format_args!(
                "Last delta serial differs from current serial."
            ));
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
                    self.log.debug(format_args!("Ran out of deltas."));
                    return Err(SnapshotReason::BadDeltaSet)
                }
            };
            match first.serial().cmp(&serial) {
                cmp::Ordering::Greater => {
                    self.log.debug(format_args!(
                        "First delta is too new ({})", first.serial()
                    ));
                    return Err(SnapshotReason::OutdatedLocal)
                }
                cmp::Ordering::Equal => break,
                cmp::Ordering::Less => deltas = &deltas[1..]
            }
        }

        if deltas.len() > self.collector.config.max_delta_count {
            self.log.debug(format_args!(
                "Too many delta steps required ({})", deltas.len()
            ));
            return Err(SnapshotReason::TooManyDeltas)
        }

        Ok(deltas)
    }
}

