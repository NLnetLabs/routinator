//! The local copy of the RPKI repository.
//!
//! This module contains [`Repository`] representing the local copy of the
//! RPKI repository. It knows how to update the content and also how to
//! process it into a list of address origins.
//!
//! [`Repository`]: struct.Repository.html

use std::{fmt, fs, io, ops};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use bytes::Bytes;
use crossbeam_utils::thread;
use crossbeam_queue::{ArrayQueue, SegQueue};
use log::{debug, error, info, warn};
use rpki::uri;
use rpki::cert::{Cert, KeyUsage, ResourceCert, TbsCert};
use rpki::crl::{Crl, CrlStore};
use rpki::crypto::KeyIdentifier;
use rpki::manifest::{Manifest, ManifestContent, ManifestHash};
use rpki::roa::{Roa, RoaStatus};
use rpki::tal::{Tal, TalInfo, TalUri};
use rpki::x509::ValidationError;
use crate::{rrdp, rsync};
use crate::config::{Config, StalePolicy};
use crate::metrics::Metrics;
use crate::operation::Error;
use crate::origins::{OriginsReport, RouteOrigins};


//------------ Configuration -------------------------------------------------

/// The minimum number of manifest entries that triggers CRL serial caching.
///
/// The value has been determined exprimentally with the RPKI repository at
/// a certain state so may or may not be a good one, really.
const CRL_CACHE_LIMIT: usize = 50;


//------------ Repository ----------------------------------------------------

/// The local copy of the RPKI repository.
#[derive(Debug)]
pub struct Repository {
    /// The base directory of the local cache.
    cache_dir: PathBuf,

    /// The list of our TALs. 
    tals: Vec<Tal>,

    /// Should we be strict when decoding data?
    strict: bool,

    /// How do we deal with stale objects?
    stale: StalePolicy,

    /// Number of validation threads.
    validation_threads: usize,

    /// The RRDP cache.
    ///
    /// If this is `None`, use of RRDP has been disable entirely.
    rrdp: Option<rrdp::Cache>,

    /// The rsync cache.
    ///
    /// If this is `None`, use of RRDP has been disable entirely.
    rsync: Option<rsync::Cache>,

    /// Should we leave the repository dirty after a valiation run.
    dirty_repository: bool,
}

impl Repository {
    /// Initializes the repository.
    pub fn init(config: &Config) -> Result<(), Error> {
        let rsync_dir = config.cache_dir.join("rsync");
        if let Err(err) = fs::create_dir_all(&rsync_dir) {
            error!(
                "Failed to create rsync cache directory {}: {}.",
                rsync_dir.display(), err
            );
            return Err(Error);
        }
        rsync::Cache::init(config)?;
        rrdp::Cache::init(config)?;
        Ok(())
    }

    /// Creates a new repository.
    ///
    /// Takes all necessary information from `config`. If `update` is `false`,
    /// updating the local cache will not be updated from upstream.
    pub fn new(
        config: &Config,
        update: bool
    ) -> Result<Self, Error> {
        if let Err(err) = fs::read_dir(&config.cache_dir) {
            if err.kind() == io::ErrorKind::NotFound {
                error!(
                    "Missing repository directory {}.\n\
                     You may have to initialize it via \
                     \'routinator init\'.",
                     config.cache_dir.display()
                );
            }
            else {
                error!(
                    "Failed to open repository directory {}: {}",
                    config.cache_dir.display(), err
                );
            }
            return Err(Error)
        }

        Ok(Repository {
            cache_dir: config.cache_dir.clone(),
            tals: Self::load_tals(config)?,
            strict: config.strict,
            stale: config.stale,
            validation_threads: config.validation_threads,
            rrdp: rrdp::Cache::new(config, update)?,
            rsync: rsync::Cache::new( config, update)?,
            dirty_repository: config.dirty_repository,
        })
    }

    /// Reloads the TAL files based on the config object.
    pub fn reload_tals(&mut self, config: &Config) -> Result<(), Error> {
        self.tals = Self::load_tals(config)?;
        Ok(())
    }

    /// Loads the TAL files from the given directory.
    fn load_tals(config: &Config) -> Result<Vec<Tal>, Error> {
        let mut res = Vec::new();
        let dir = match fs::read_dir(&config.tal_dir) {
            Ok(dir) => dir,
            Err(err) => {
                if err.kind() == io::ErrorKind::NotFound {
                    error!(
                        "Missing TAL directory {}.\n\
                         You may have to initialize it via \
                         \'routinator init\'.",
                         config.tal_dir.display()
                    );
                }
                else {
                    error!("Failed to open TAL directory: {}.", err);
                }
                return Err(Error)
            }
        };
        for entry in dir {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    error!(
                        "Failed to iterate over tal directory: {}",
                        err
                    );
                    return Err(Error)
                }
            };

            if !entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
                continue
            }

            let path = entry.path();
            if path.extension().map(|ext| ext != "tal").unwrap_or(true) {
                continue
            }

            let mut file = match File::open(&path) {
                Ok(file) => {
                    file
                }
                Err(err) => {
                    error!(
                        "Failed to open TAL {}: {}. \n\
                         Aborting.",
                         path.display(), err
                    );
                    return Err(Error)
                }
            };
            let tal = match Tal::read_named(
                Self::path_to_label(&path, config),
                &mut file
            ) {
                Ok(tal) => tal,
                Err(err) => {
                    error!(
                        "Failed to read TAL {}: {}. \n\
                         Aborting.",
                        path.display(), err
                    );
                    return Err(Error)
                }
            };
            res.push(tal);
        }
        if res.is_empty() {
            error!(
                "No TALs found in TAL directory. Starting anyway."
            );
        }
        Ok(res)
    }

    /// Converts a path into a TAL label.
    fn path_to_label(path: &Path, config: &Config) -> String {
        if let Some(name) = path.file_name().unwrap().to_str() {
            if let Some(label) = config.tal_labels.get(name) {
                return label.clone()
            }
        }
        path.file_stem().unwrap().to_string_lossy().into_owned()
    }

    /// Performs a complete validation run on the repository.
    pub fn process(
        &mut self,
    ) -> Result<(OriginsReport, Metrics), Error> {
        self.ignite()?;
        let run = Run::new(self)?;
        let report = run.process()?;
        let metrics = run.into_metrics();
        Ok((report, metrics))
    }

    /// Starts the caches.
    ///
    /// This needs to be done after a possible fork as the caches may use
    /// their own threads.
    fn ignite(&mut self) -> Result<(), Error> {
        self.rsync.as_mut().map_or(Ok(()), rsync::Cache::ignite)?;
        self.rrdp.as_mut().map_or(Ok(()), rrdp::Cache::ignite)
    }
}


//------------ Run -----------------------------------------------------------

/// A single validation run of the repository.
#[derive(Debug)]
pub struct Run<'a> {
    repository: &'a Repository,
    rsync: Option<rsync::Run<'a>>,
    rrdp: Option<rrdp::Run<'a>>,
}

impl<'a> Run<'a> {
    pub fn new(repository: &'a Repository) -> Result<Self, Error> {
        Ok(Run {
            repository,
            rsync: if let Some(ref rsync) = repository.rsync {
                Some(rsync.start()?)
            }
            else {
                None
            },
            rrdp: if let Some(ref rrdp) = repository.rrdp { 
                Some(rrdp.start()?)
            }
            else {
                None
            },
        })
    }

    /// Performs a complete validation run on the repository.
    pub fn process(
        &self,
    ) -> Result<OriginsReport, Error> {
        // If we don’t have any TALs, we just return an empty report.
        if self.repository.tals.is_empty() {
            return Ok(OriginsReport::new())
        }

        // Stick all TALs into a queue. The worker threads will take one after
        // out of the queue so that the thread first to finish gets a second
        // TAL if there is more TALs than threads.
        let tasks = SegQueue::new();
        for (index, tal) in self.repository.tals.iter().enumerate() {
            tasks.push(ValidationTask::Tal { tal, index });
        }

        // Prepare another queue for the threads to put the results in.
        let origins_queue = ArrayQueue::new(self.repository.validation_threads);

        // Now work.
        let res = thread::scope(|scope| {
            for _ in 0..self.repository.validation_threads {
                scope.spawn(|_| {
                    let mut origins = RouteOrigins::new();
                    while let Ok(task) = tasks.pop() {
                        match task {
                            ValidationTask::Tal { tal, index } => {
                                self.process_tal(
                                    tal, index, &mut origins, &tasks
                                );
                            }
                            ValidationTask::Ca { cert, uri } => {
                                self.process_ca(
                                    cert, &uri, &mut origins, &tasks
                                )
                            }
                        }
                    }
                    origins_queue.push(origins).unwrap();
                });
            }
        });
        if res.is_err() {
            // One of the workers has panicked. Well gosh darn.
            error!(
                "Validation failed after a worker thread has panicked. \
                 This is most assuredly a bug."
            );
            return Err(Error);
        }

        let mut res = OriginsReport::with_capacity(
            self.repository.validation_threads,
            self.repository.tals.iter().map(|tal| {
                tal.info().clone()
            }).collect()
        );
        while let Ok(item) = origins_queue.pop() {
            // If item is an Err, something went wrong fatally in the worker
            // and we should bail instead.
            res.push_origins(item);
        }
        Ok(res)
    }

    /// Processes all data for the given trust anchor.
    ///
    /// This fails if the next file in `entry` looks like a trust anchor
    /// locator but fails to parse. If the next `entry` isn’t a trust anchor
    /// at all or if none of the URIs in the TAL file lead to anything,
    /// Ok-returns an empty list of route origins.
    fn process_tal(
        &self,
        tal: &Tal,
        index: usize,
        origins: &mut RouteOrigins,
        tasks: &SegQueue<ValidationTask>,
    ) {
        for uri in tal.uris() {
            let cert = match self.load_ta(&uri, tal.info()) {
                Some(cert) => cert,
                _ => continue,
            };
            if cert.subject_public_key_info() != tal.key_info() {
                info!(
                    "Trust anchor {}: key doesn’t match TAL.",
                    uri
                );
                continue;
            }
            let cert = match cert.validate_ta(tal.info().clone(),
                                              self.repository.strict) {
                Ok(cert) => cert,
                Err(_) => {
                    info!(
                        "Trust anchor {}: doesn’t validate.",
                        uri
                    );
                    continue;
                }
            };
            info!("Found valid trust anchor {}. Processing.", uri);
            self.process_ca(CaCert::root(cert, index), &uri, origins, tasks);
            return
        }
        warn!("No valid trust anchor for TAL {}", tal.info().name());
    }

    /// Loads a trust anchor certificate from the given URI.
    fn load_ta(
        &self,
        uri: &TalUri,
        info: &TalInfo,
    ) -> Option<Cert> {
        match *uri {
            TalUri::Rsync(ref uri) => {
                self.rsync.as_ref().and_then(|rsync| {
                    rsync.load_module(uri);
                    self.load_file(None, uri)
                })
            }
            TalUri::Https(ref uri) => {
                self.rrdp.as_ref().and_then(|rrdp| rrdp.load_ta(uri, info))
            }
        }.and_then(|bytes| Cert::decode(bytes).ok())
    }

    /// Loads the content of a file from the given URI.
    fn load_file(
        &self,
        rrdp_server: Option<rrdp::ServerId>,
        uri: &uri::Rsync,
    ) -> Option<Bytes> {
        if let Some(id) = rrdp_server {
            if let Some(rrdp) = self.rrdp.as_ref() {
                if let Ok(res) = rrdp.load_file(id, uri) {
                    return res
                }
            }
        }
        self.rsync.as_ref().and_then(|rsync| rsync.load_file(uri))
    }

    /// Processes all data for the given trust CA.
    /// 
    /// The CA cert is given through `cert`. It is located at `uri`, this
    /// is only needed for composing error messages. Any route origins found
    /// in the objects issued directly or transitively by this CA are added
    /// to `routes`.
    fn process_ca<U: fmt::Display>(
        &self,
        cert: Arc<CaCert>,
        uri: &U,
        routes: &mut RouteOrigins,
        tasks: &SegQueue<ValidationTask>,
    ) {
        let mut store = CrlStore::new();
        let repo_uri = match cert.ca_repository() {
            Some(uri) => uri,
            None => {
                info!("CA cert {} has no repository URI. Ignoring.", uri);
                return
            }
        };
        let rrdp_server = cert.rpki_notify().and_then(|uri| {
            self.rrdp.as_ref().and_then(|rrdp| rrdp.load_server(uri))
        });
        if rrdp_server.is_none() {
            if let Some(ref rsync) = self.rsync {
                rsync.load_module(repo_uri)
            }
        }
        let manifest = match self.get_manifest(
            rrdp_server, &cert, uri, &mut store, routes,
        ) {
            Some(some) => some,
            None => return,
        };

        for (uri, hash) in manifest.iter_uris(repo_uri) {
            self.process_object(
                rrdp_server, uri, hash, &cert, &mut store, routes, tasks
            );
        }
    }

    /// Reads, parses, and returns the manifest for a CA.
    ///
    /// The manifest for the CA referenced via `issuer` is determined, read,
    /// and parsed. In particular, the first manifest that is referenced in
    /// the certificate and that turns out to be valid is returned.
    ///
    /// If no manifest can be found, `None` is returned.
    fn get_manifest<U: fmt::Display>(
        &self,
        rrdp_server: Option<rrdp::ServerId>,
        issuer: &ResourceCert,
        issuer_uri: &U,
        store: &mut CrlStore,
        routes: &mut RouteOrigins
    ) -> Option<ManifestContent> {
        let uri = match issuer.rpki_manifest() {
            Some(uri) => uri,
            None => {
                info!("{}: No valid manifest found. Ignoring.", issuer_uri);
                return None
            }
        };
        let bytes = match self.load_file(rrdp_server, &uri) {
            Some(bytes) => bytes,
            None => {
                info!("{}: failed to load.", uri);
                return None;
            }
        };
        let manifest = match Manifest::decode(bytes, self.repository.strict) {
            Ok(manifest) => manifest,
            Err(_) => {
                info!("{}: failed to decode", uri);
                return None;
            }
        };
        let (cert, manifest) = match manifest.validate(
            issuer, self.repository.strict
        ) {
            Ok(manifest) => manifest,
            Err(_) => {
                info!("{}: failed to validate", uri);
                return None;
            }
        };
        if manifest.is_stale() {
            match self.repository.stale {
                StalePolicy::Refuse => {
                    info!("{}: stale manifest", uri);
                    return None;
                }
                StalePolicy::Warn => {
                    warn!("{}: stale manifest", uri);
                }
                StalePolicy::Accept => { }
            }
        }
        if manifest.len() > CRL_CACHE_LIMIT {
            store.enable_serial_caching();
        }
        if self.check_crl(rrdp_server, &cert, issuer, store).is_err() {
            info!("{}: certificate has been revoked", uri);
            return None
        }
        routes.update_refresh(&cert);
        Some(manifest)
    }

    /// Processes an RPKI object and, if necessary, all its dependent objects.
    ///
    /// The object is referenced by `uri`. Its hash is compared to `hash`
    /// and its own certificate is expected to be issued by `cert`. The
    /// CRL store `crl` is used to access the CRLs this object’s certificate
    /// should not be listed on.
    ///
    /// Any route orgins resulting from the object or any of its dependent
    /// objects are added to `routes`.
    ///
    /// This method logs all its messages.
    #[allow(clippy::too_many_arguments)]
    fn process_object(
        &self,
        rrdp_server: Option<rrdp::ServerId>,
        uri: uri::Rsync,
        hash: ManifestHash,
        issuer: &Arc<CaCert>,
        crl: &mut CrlStore,
        routes: &mut RouteOrigins,
        tasks: &SegQueue<ValidationTask>,
    ) {
        if uri.ends_with(".cer") {
            self.process_cer(
                rrdp_server, uri, hash, issuer, crl, routes, tasks
            )
        }
        else if uri.ends_with(".roa") {
            self.process_roa(
                rrdp_server, uri, hash, issuer, crl, routes,
            )
        }
        else if uri.ends_with(".crl") {
            // CRLs are read on demand.
        }
        else if uri.ends_with(".gbr") {
            info!("{}: Unsupported file type", uri)
        }
        else {
            info!("{}: Unknown file type.", uri);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn process_cer(
        &self,
        rrdp_server: Option<rrdp::ServerId>,
        uri: uri::Rsync,
        hash: ManifestHash,
        issuer: &Arc<CaCert>,
        crl: &mut CrlStore,
        routes: &mut RouteOrigins,
        tasks: &SegQueue<ValidationTask>,
    ) {
        let bytes = match self.load_file(rrdp_server, &uri) {
            Some(bytes) => bytes,
            None => {
                info!("{}: failed to load.", uri);
                return
            }
        };
        if hash.verify(&bytes).is_err() {
            info!("{}: file has wrong hash.", uri);
            return
        }
        let cert = match Cert::decode(bytes) {
            Ok(cert) => cert,
            Err(_) => {
                info!("{}: failed to decode.", uri);
                return
            }
        };
        if cert.key_usage() != KeyUsage::Ca {
            info!(
                "{}: probably a router key. Ignoring.",
                uri
            );
            return
        }
        if issuer.check_loop(&cert).is_err() {
            warn!(
                "{}: certificate loop detected. Ignoring this CA.",
                uri
            );
            return
        }
        let cert = match cert.validate_ca(issuer, self.repository.strict) {
            Ok(cert) => cert,
            Err(_) => {
                info!("{}: failed to validate.", uri);
                return
            }
        };
        if self.check_crl(rrdp_server, &cert, issuer, crl).is_err() {
            info!("{}: certificate has been revoked", uri);
            return
        }
        routes.update_refresh(&cert);

        let repo_uri = match cert.ca_repository() {
            Some(uri) => uri,
            None => {
                info!("CA cert {} has no repository URI. Ignoring.", uri);
                return
            }
        };

        // Defer operation if we need to update the repository part where
        // the CA lives.
        let defer = match (self.rrdp.as_ref(), cert.rpki_notify()) {
            (Some(rrdp), Some(rrdp_uri)) => !rrdp.is_current(rrdp_uri),
            _ => match self.rsync.as_ref() {
                Some(rsync) => !rsync.is_current(repo_uri),
                None => false
            }
        };

        let cert = CaCert::chain(issuer, cert);

        if defer {
            debug!("Queueing CA {} for later processing.", uri);
            tasks.push(ValidationTask::Ca { cert, uri });
        }
        else {
            self.process_ca( cert, &uri, routes, tasks)
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn process_roa(
        &self,
        rrdp_server: Option<rrdp::ServerId>,
        uri: uri::Rsync,
        hash: ManifestHash,
        issuer: &Arc<CaCert>,
        crl: &mut CrlStore,
        routes: &mut RouteOrigins,
    ) {
        let bytes = match self.load_file(rrdp_server, &uri) {
            Some(bytes) => bytes,
            None => {
                info!("{}: failed to load.", uri);
                return
            }
        };
        if hash.verify(&bytes).is_err() {
            info!("{}: file has wrong hash.", uri);
            return
        }
        let roa = match Roa::decode(bytes, self.repository.strict) {
            Ok(roa) => roa,
            Err(_) => {
                info!("{}: decoding failed.", uri);
                return
            }
        };
        let mut extra = None;
        let route = roa.process(issuer, self.repository.strict, |cert| {
            self.check_crl(rrdp_server, cert, issuer, crl)?;
            extra = Some(8u8);
            Ok(())
        });
        match route {
            Ok(route) => {
                if let RoaStatus::Valid { ref cert } = *route.status() {
                    routes.update_refresh(cert);
                }
                routes.push(route, issuer.tal);
            }
            Err(_) => {
                info!("{}: processing failed.", uri);
            }
        }
    }

    /// Checks wheter a certificate is listed on its CRL.
    fn check_crl(
        &self,
        rrdp_server: Option<rrdp::ServerId>,
        cert: &TbsCert,
        issuer: &ResourceCert,
        store: &mut CrlStore,
    ) -> Result<(), ValidationError> {
        let uri = match cert.crl_uri() {
            Some(some) => some,
            None => return Ok(())
        };

        // If we already have that CRL, use it.
        if let Some(crl) = store.get(&uri) {
            if crl.contains(cert.serial_number()) {
                return Err(ValidationError)
            }
            else {
                return Ok(())
            }
        }

        // Otherwise, try to load it, use it, and then store it.
        let bytes = match self.load_file(rrdp_server, &uri) {
            Some(bytes) => bytes,
            _ => return Err(ValidationError),
        };
        let crl = match Crl::decode(bytes) {
            Ok(crl) => crl,
            Err(_) => return Err(ValidationError)
        };
        if crl.validate(issuer.subject_public_key_info()).is_err() {
            return Err(ValidationError)
        }
        if crl.is_stale() {
            match self.repository.stale {
                StalePolicy::Refuse => {
                    info!("{}: stale CRL.", uri);
                    return Err(ValidationError)
                }
                StalePolicy::Warn => {
                    warn!("{}: stale CRL.", uri);
                }
                StalePolicy::Accept => { }
            }
        }
        let revoked = crl.contains(cert.serial_number());
        store.push(uri.clone(), crl);
        if revoked {
            Err(ValidationError)
        }
        else {
            Ok(())
        }
    }

    pub fn cleanup(&self) {
        if self.repository.dirty_repository {
            return
        }
        if let Some(ref rsync) = self.rsync {
            rsync.cleanup();
        }
        if let Some(ref rrdp) = self.rrdp {
            rrdp.cleanup();
        }
        Self::cleanup_base(&self.repository.cache_dir);
    }

    fn cleanup_base(cache_dir: &Path) {
        let dir = match fs::read_dir(cache_dir) {
            Ok(dir) => dir,
            Err(err) => {
                warn!("Failed to read repository directory: {}", err);
                return
            }
        };
        for entry in dir {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    warn!(
                        "Failed to iterate over repository directory: {}", err
                    );
                    return
                }
            };
            match entry.file_name().to_str() {
                Some("http") => continue,
                Some("rsync") => continue,
                Some("rrdp") => continue,
                Some("tmp") => continue,
                _ => { }
            }
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                if let Err(err) = fs::remove_dir_all(entry.path()) {
                    warn!(
                        "Failed to delete unused repository directory {}:{}",
                        entry.path().display(),
                        err
                    );
                }
            }
            else if let Err(err) = fs::remove_file(entry.path()) {
                warn!(
                    "Failed to delete unused repository entry {}:{}",
                    entry.path().display(),
                    err
                );
            }
        }
    }

    pub fn into_metrics(self) -> Metrics {
        let mut res = Metrics::new();
        if let Some(rrdp) = self.rrdp {
            res.set_rrdp(rrdp.into_metrics());
        }
        if let Some(rsync) = self.rsync {
            res.set_rsync(rsync.into_metrics());
        }
        res
    }
}


//------------ CaCert --------------------------------------------------------

/// A CA certificate plus references to all its parents.
struct CaCert {
    /// The CA certificate of this CA.
    cert: ResourceCert,

    /// The parent CA.
    /// 
    /// This will be none for a trust anchor.
    parent: Option<Arc<CaCert>>,

    /// The index of the TAL.
    tal: usize,
}

impl CaCert {
    /// Creates a new CA cert for a trust anchor.
    pub fn root(cert: ResourceCert, tal: usize) -> Arc<Self> {
        Arc::new(CaCert {
            cert,
            parent: None,
            tal
        })
    }

    pub fn chain(this: &Arc<Self>, cert: ResourceCert) -> Arc<Self> {
        Arc::new(CaCert {
            cert,
            parent: Some(this.clone()),
            tal: this.tal
        })
    }

    /// Checks whether a child cert has appeared in chain already.
    pub fn check_loop(&self, cert: &Cert) -> Result<(), Error> {
        self._check_loop(cert.subject_key_identifier())
    }

    /// The actual recursive loop test.
    ///
    /// We are comparing certificates by comparing their subject key
    /// identifiers.
    fn _check_loop(&self, key_id: KeyIdentifier) -> Result<(), Error> {
        if self.cert.subject_key_identifier() == key_id {
            Err(Error)
        }
        else if let Some(ref parent) = self.parent {
            parent._check_loop(key_id)
        }
        else {
            Ok(())
        }
    }
} 

impl ops::Deref for CaCert {
    type Target = ResourceCert;

    fn deref(&self) -> &Self::Target {
        &self.cert
    }
}


//------------ ValidationTask ------------------------------------------------

/// A task for a validation worker thread.
enum ValidationTask<'a> {
    /// Process the given TAL.
    Tal { tal: &'a Tal, index: usize },

    /// Process the given CA.
    Ca { cert: Arc<CaCert>, uri: uri::Rsync },
}

