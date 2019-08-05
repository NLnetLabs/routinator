//! The local copy of the RPKI repository.
//!
//! This module contains [`Repository`] representing the local copy of the
//! RPKI repository. It knows how to update the content and also how to
//! process it into a list of address origins.
//!
//! [`Repository`]: struct.Repository.html

use std::{fmt, fs, io};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use bytes::Bytes;
use derive_more::Display;
use futures::future;
use futures::Future;
use futures_cpupool::CpuPool;
use log::{debug, error, info, warn};
use rpki::uri;
use rpki::cert::{Cert, ResourceCert, TbsCert};
use rpki::crl::{Crl, CrlStore};
use rpki::manifest::{Manifest, ManifestContent, ManifestHash};
use rpki::roa::Roa;
use rpki::tal::{Tal, TalInfo, TalUri};
use rpki::x509::ValidationError;
//use unwrap::unwrap;
use crate::{rrdp, rsync};
use crate::metrics::Metrics;
use crate::config::Config;
use crate::operation::Error;
use crate::origins::RouteOrigins;
use crate::slurm::LocalExceptions;


//------------ Configuration -------------------------------------------------

/// The minimum number of manifest entries that triggers CRL serial caching.
///
/// The value has been determined exprimentally with the RPKI repository at
/// a certain state so may or may not be a good one, really.
const CRL_CACHE_LIMIT: usize = 50;


//------------ Repository ----------------------------------------------------

/// A reference to the local copy of the RPKI repository.
///
/// This type wraps all the configuration necessary for finding and working
/// with the local copy. The actual data is stored in the file system.
///
/// You create a repository by calling the `new` function, providing a small
/// amount of configuration information. Next, you can update the content via
/// the `update` method. Finally, the `process` method produces a list of
/// validated route origins.
///
/// The actual data of the value is stored in an arc, so clones of values are
/// cheap.
#[derive(Clone, Debug)]
pub struct Repository(Arc<RepoInner>);

#[derive(Debug)]
struct RepoInner {
    /// The base directory of the local cache.
    cache_dir: PathBuf,

    /// The list of our TALs. 
    tals: Vec<Tal>,

    /// Should we be strict when decoding data?
    strict: bool,

    /// Should we keep extended information about ROAs?
    extra_output: bool,

    /// Number of validation threads.
    validation_threads: usize,

    /// The RRDP cache.
    rrdp: Option<rrdp::Cache>,

    /// The rsync cache.
    rsync: rsync::Cache,

    /// Should we leave the repository dirty after a valiation run.
    dirty_repository: bool,
}

impl Repository {
    /// Creates a new repository.
    ///
    /// Takes all necessary information from `config`. If `update` is `false`,
    /// updating the local cache will not be updated from upstream.
    pub fn new(
        config: &Config,
        extra_output: bool,
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

        Ok(Repository(Arc::new(RepoInner {
            cache_dir: config.cache_dir.clone(),
            tals: Self::load_tals(&config.tal_dir)?,
            strict: config.strict,
            extra_output,
            validation_threads: config.validation_threads,
            rrdp: rrdp::Cache::new(config, update).ok(),
            rsync: rsync::Cache::new(
                config, config.cache_dir.join("rsync"), update
            
            )?,
            dirty_repository: config.dirty_repository,
        })))
    }

    pub fn init(config: &Config) -> Result<(), Error> {
        let rsync_dir = config.cache_dir.join("rsync");
        if let Err(err) = fs::create_dir_all(&rsync_dir) {
            error!(
                "Failed to create rsync cache directory {}: {}.",
                rsync_dir.display(), err
            );
            return Err(Error);
        }
        rrdp::Cache::init(config)?;
        Ok(())
    }

    /// Loads the TAL files from the given directory.
    fn load_tals(tal_dir: &Path) -> Result<Vec<Tal>, Error> {
        let mut res = Vec::new();
        let dir = match fs::read_dir(tal_dir) {
            Ok(dir) => dir,
            Err(err) => {
                if err.kind() == io::ErrorKind::NotFound {
                    error!(
                        "Missing TAL directory {}.\n\
                         You may have to initialize it via \
                         \'routinator init\'.",
                         tal_dir.display()
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
            let tal = match Tal::read(&path, &mut file) {
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
        Ok(res)
    }

    /// Starts a validation run.
    ///
    /// This resets the update cache that lists the rsync modules we have
    /// already tried updating. It is therefore really important to call this
    /// method before doing any new update.
    pub fn start(&self) -> Result<(), Error> {
        self.0.rsync.start()?;
        if let Some(ref rrdp) = self.0.rrdp {
            rrdp.start()?;
        }
        Ok(())
    }

    /// Process the local repository and produce a list of route origins.
    ///
    /// Starts with the trust anchors and makes its way down through
    /// certificates and manifests and such. If it encounters new publication
    /// points, it will try to fetch them unless rsync has been disabled.
    ///
    /// The method logs all error messages.
    pub fn process_async(
        &self
    ) -> impl Future<Item=Vec<RouteOrigins>, Error=Error> {
        let pool = CpuPool::new(self.0.validation_threads);
        let repo = self.clone();
        let clean_repo = self.clone();
        future::join_all((0..self.0.tals.len()).map(move |idx| {
            let repo = repo.clone();
            let pool = pool.clone();
            pool.spawn(future::lazy(move || repo.process_tal(idx)))
        })).and_then(move |res| {
            clean_repo.cleanup();
            Ok(res)
        })
    }

    /// Process the local repository and produce a list of route origins.
    ///
    /// This is the synchronous version of `process_async`.
    pub fn process(&self) -> Result<Vec<RouteOrigins>, Error> {
        self.process_async().wait()
    }

    /// Loads the exceptions.
    pub fn load_exceptions(
        &self,
        config: &Config
    ) -> Result<LocalExceptions, Error> {
        config.load_exceptions(self.0.extra_output)
    }

    /// Update metrics for this validation run.
    pub fn update_metrics(&self, metrics: &mut Metrics) {
        self.0.rsync.update_metrics(metrics);
    }
}


/// # Repository Access
///
impl Repository {
    /// Loads a trust anchor certificate from the given URI.
    fn load_ta(
        &self,
        uri: &TalUri,
        info: &TalInfo,
    ) -> Option<Cert> {
        match *uri {
            TalUri::Rsync(ref uri) => {
                self.load_file(None, uri, true)
                .and_then(|bytes| Cert::decode(bytes).ok())
            }
            TalUri::Https(ref uri) => {
                self.0.rrdp.as_ref().and_then(|rrdp| rrdp.load_ta(uri, info))
            }
        }
    }

    /// Loads the content of a file from the given URI.
    ///
    /// If `create` is `true`, it will try to rsync missing files.
    ///
    /// If loading the file fails, logs a warning and returns `None`.
    fn load_file(
        &self,
        rrdp_server: Option<rrdp::ServerId>,
        uri: &uri::Rsync,
        create: bool
    ) -> Option<Bytes> {
        if let Some(id) = rrdp_server {
            if let Some(rrdp) = self.0.rrdp.as_ref() {
                if let Ok(res) = rrdp.load_file(id, uri) {
                    return res
                }
            }
        }
        self.0.rsync.load_file(uri, create)
    }
}


/// # Processing
///
impl Repository {
    /// Processes all data for the given trust anchor.
    ///
    /// This fails if the next file in `entry` looks like a trust anchor
    /// locator but fails to parse. If the next `entry` isn’t a trust anchor
    /// at all or if none of the URIs in the TAL file lead to anything,
    /// Ok-returns an empty list of route origins.
    ///
    /// This method logs all its error messages.
    pub fn process_tal(
        self,
        //entry: DirEntry
        idx: usize
    ) -> Result<RouteOrigins, Error> {
        let tal = &self.0.tals[idx];
        let mut res = RouteOrigins::new(tal.info().clone());
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
                                              self.0.strict) {
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
            self.process_ca(cert, &uri, &mut res);
            // We stop once we have had the first working URI.
            return Ok(res)
        }
        warn!("No valid trust anchor for TAL {}", tal.info().name());
        Ok(res)
    }

    /// Processes all data for the given trust CA.
    /// 
    /// The CA cert is given through `cert`. It is located at `uri`, this
    /// is only needed for composing error messages. Any route origins found
    /// in the objects issued directly or transitively by this CA are added
    /// to `routes`.
    fn process_ca<U: fmt::Display>(
        &self,
        cert: ResourceCert,
        uri: &U,
        routes: &mut RouteOrigins
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
            self.0.rrdp.as_ref().and_then(|rrdp| rrdp.load_server(uri))
        });
        let mft = match self.get_manifest(rrdp_server, &cert, uri, &mut store) {
            Some(manifest) => manifest,
            None => {
                info!("No valid manifest for CA {}. Ignoring.", uri);
                return
            }
        };

        for (uri, hash) in mft.iter_uris(repo_uri) {
            self.process_object(
                rrdp_server, uri, hash, &cert, &mut store, routes
            );
        }
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
    fn process_object(
        &self,
        rrdp_server: Option<rrdp::ServerId>,
        uri: uri::Rsync,
        hash: ManifestHash,
        issuer: &ResourceCert,
        crl: &mut CrlStore,
        routes: &mut RouteOrigins,
    ) {
        // XXX We should have the directory already from fetching the
        //     manifest. So we should be fine calling load_file without
        //     request for file creation.
        if uri.ends_with(".cer") {
            let bytes = match self.load_file(rrdp_server, &uri, false) {
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
            let cert = match cert.validate_ca(issuer, self.0.strict) {
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
            self.process_ca(cert, &uri, routes)
        }
        else if uri.ends_with(".roa") {
            let bytes = match self.load_file(rrdp_server, &uri, false) {
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
            let roa = match Roa::decode(bytes, self.0.strict) {
                Ok(roa) => roa,
                Err(_) => {
                    info!("{}: decoding failed.", uri);
                    return
                }
            };
            let mut extra = None;
            let route = roa.process(issuer, self.0.strict, |cert| {
                self.check_crl(rrdp_server, cert, issuer, crl)?;
                extra = Some(8u8);
                Ok(())
            });
            match route {
                Ok(route) => routes.push(route),
                Err(_) => {
                    info!("{}: processing failed.", uri);
                }
            }
        }
        else if uri.ends_with(".crl") {
            // CRLs are read on demand.
        }
        else if uri.ends_with(".gbr") {
            info!("{}: Not gonna call ...", uri)
        }
        else {
            warn!("{}: Unknown file type", uri);
        }
    }

    /// Reads, parses, and returns the manifest for a CA.
    ///
    /// The manifest for the CA referenced via `issuer` is determined, read,
    /// and parsed. In particular, the first manifest that is referenced in
    /// the certificate and that turns out to be valid is returned.
    ///
    /// If no manifest can be found, `None` is returned.
    ///
    /// Note that currently we happily accept stale manifests, i.e., manifests
    /// whose certificate is still valid but the next_update time has passed.
    /// The RFC says we need to decide what to do, so this is fine.
    fn get_manifest<U: fmt::Display>(
        &self,
        rrdp_server: Option<rrdp::ServerId>,
        issuer: &ResourceCert,
        issuer_uri: &U,
        store: &mut CrlStore,
    ) -> Option<ManifestContent> {
        let uri = match issuer.rpki_manifest() {
            Some(uri) => uri,
            None => {
                info!("{}: No valid manifest found. Ignoring.", issuer_uri);
                return None
            }
        };
        let bytes = match self.load_file(rrdp_server, &uri, true) {
            Some(bytes) => bytes,
            None => {
                info!("{}: failed to load.", uri);
                return None;
            }
        };
        let manifest = match Manifest::decode(bytes, self.0.strict) {
            Ok(manifest) => manifest,
            Err(_) => {
                info!("{}: failed to decode", uri);
                return None;
            }
        };
        let (cert, manifest) = match manifest.validate(issuer,
                                                       self.0.strict) {
            Ok(manifest) => manifest,
            Err(_) => {
                info!("{}: failed to validate", uri);
                return None;
            }
        };
        if manifest.is_stale() {
            warn!("{}: stale manifest", uri);
        }
        if manifest.len() > CRL_CACHE_LIMIT {
            debug!(
                "{}: Manifest with {} entries: enabling serial caching",
                uri,
                manifest.len()
            );
            store.enable_serial_caching();
        }
        if self.check_crl(rrdp_server, cert, issuer, store).is_err() {
            info!("{}: certificate has been revoked", uri);
            return None
        }
        Some(manifest)
    }

    /// Checks wheter a certificate is listed on its CRL.
    fn check_crl<C: AsRef<TbsCert>>(
        &self,
        rrdp_server: Option<rrdp::ServerId>,
        cert: C,
        issuer: &ResourceCert,
        store: &mut CrlStore,
    ) -> Result<(), ValidationError> {
        let cert = cert.as_ref();
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
        let bytes = match self.load_file(rrdp_server, &uri, true) {
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
            warn!("{}: stale CRL.", uri);
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
}


/// # Cleanup
///
impl Repository {
    fn cleanup(&self) {
        if self.0.dirty_repository {
            return
        }
        self.0.rsync.cleanup();
        if let Some(ref rrdp) = self.0.rrdp {
            rrdp.cleanup()
        }
        self.cleanup_base();
    }

    fn cleanup_base(&self) {
        let dir = match fs::read_dir(&self.0.cache_dir) {
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
            else {
                if let Err(err) = fs::remove_file(entry.path()) {
                    warn!(
                        "Failed to delete unused repository entry {}:{}",
                        entry.path().display(),
                        err
                    );
                }
            }
        }
    }
}


//------------ RsyncError ---------------------------------------------------

#[derive(Debug, Display)]
pub enum RsyncError {
    #[display(fmt="unable to run rsync:\n{}", _0)]
    Command(io::Error),

    #[display(fmt="unable to run rsync:\n{}", _0)]
    Output(String),
}

impl From<io::Error> for RsyncError {
    fn from(err: io::Error) -> RsyncError {
        RsyncError::Command(err)
    }
}

