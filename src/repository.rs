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
use std::sync::atomic::{AtomicBool, Ordering};
use bytes::Bytes;
use crossbeam_utils::thread;
use crossbeam_queue::SegQueue;
use log::{debug, error, info, warn};
use rpki::uri;
use rpki::repository::cert::{Cert, KeyUsage, ResourceCert, TbsCert};
use rpki::repository::crl::Crl;
use rpki::repository::crypto::KeyIdentifier;
use rpki::repository::manifest::{Manifest, ManifestContent, ManifestHash};
use rpki::repository::roa::{Roa, RouteOriginAttestation};
use rpki::repository::sigobj::SignedObject;
use rpki::repository::tal::{Tal, TalInfo, TalUri};
use rpki::repository::x509::{Time, ValidationError};
use crate::{rrdp, rsync};
use crate::config::{Config, FilterPolicy};
use crate::metrics::Metrics;
use crate::operation::Error;
use crate::origins::OriginsReport;


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
    stale: FilterPolicy,

    /// How do we deal with unknown object types?
    unknown_objects: FilterPolicy,

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
            unknown_objects: config.unknown_objects,
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
            let mut tal = match Tal::read_named(
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
            tal.prefer_https();
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

    pub fn process_origins(
        &mut self
    ) -> Result<(OriginsReport, Metrics), Error> {
        let report = OriginsReport::new();
        let metrics = self.process(&report)?;
        Ok((report, metrics))
    }

    pub fn process<P: ProcessRun>(
        &mut self,
        processor: P
    ) -> Result<Metrics, Error> {
        self.ignite()?;
        let run = Run::new(self, processor)?;
        run.process()?;
        Ok(run.into_metrics())
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
pub struct Run<'a, P> {
    repository: &'a Repository,
    processor: P,
    rsync: Option<rsync::Run<'a>>,
    rrdp: Option<rrdp::Run<'a>>,
    metrics: Metrics,
}

impl<'a, P> Run<'a, P> {
    pub fn new(
        repository: &'a Repository,
        processor: P
    ) -> Result<Self, Error> {
        Ok(Run {
            repository,
            processor,
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
            metrics: Metrics::new(),
        })
    }

    pub fn into_metrics(self) -> Metrics {
        let mut res = self.metrics;
        if let Some(rrdp) = self.rrdp {
            res.set_rrdp(rrdp.into_metrics());
        }
        if let Some(rsync) = self.rsync {
            res.set_rsync(rsync.into_metrics());
        }
        res
    }
}

impl<'a, P: ProcessRun> Run<'a, P> {
    /// Performs a complete validation run on the repository.
    pub fn process(&self) -> Result<(), Error> {
        // If we don’t have any TALs, we ain’t got nothing to do.
        if self.repository.tals.is_empty() {
            return Ok(())
        }

        // Initialize our task queue with all the TALs.
        let tasks = SegQueue::new();
        for (index, tal) in self.repository.tals.iter().enumerate() {
            tasks.push(ValidationTask::Tal { tal, index });
        }

        // And off we trot.
        let had_err = AtomicBool::new(false);
        let res = thread::scope(|scope| {
            for _ in 0..self.repository.validation_threads {
                scope.spawn(|_| {
                    while let Ok(task) = tasks.pop() {
                        let err = match task {
                            ValidationTask::Tal { tal, index } => {
                                self.process_tal(
                                    tal, index, &tasks
                                )
                            }
                            ValidationTask::Ca(task) => {
                                self.process_ca(
                                    task.cert, &task.uri, task.process, &tasks
                                )
                            }
                        };
                        if err.is_err() {
                            had_err.store(true, Ordering::Relaxed);
                            break;
                        }
                        else if had_err.load(Ordering::Relaxed) {
                            break;
                        }
                    }
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

        Ok(())
    }

    /// Processes all data for the given trust anchor.
    fn process_tal(
        &self,
        tal: &Tal,
        index: usize,
        tasks: &SegQueue<ValidationTask<P::ProcessCa>>,
    ) -> Result<(), Error> {
        for uri in tal.uris() {
            let cert = match self.load_ta(&uri, tal.info()) {
                Some(cert) => cert,
                _ => continue,
            };
            if cert.subject_public_key_info() != tal.key_info() {
                warn!(
                    "Trust anchor {}: key doesn’t match TAL.",
                    uri
                );
                continue;
            }
            let cert = match cert.validate_ta(tal.info().clone(),
                                              self.repository.strict) {
                Ok(cert) => CaCert::root(cert, index),
                Err(_) => {
                    warn!(
                        "Trust anchor {}: doesn’t validate.",
                        uri
                    );
                    continue;
                }
            };
            debug!("Found valid trust anchor {}. Processing.", uri);

            match self.processor.process_ta(tal, uri, &cert.cert)? {
                Some(processor) => {
                    return self.process_ca(cert, uri, processor, tasks)
                }
                None => {
                    debug!("Skipping trust anchor {}.", uri);
                    return Ok(())
                }
            }
        }
        warn!("No valid trust anchor for TAL {}", tal.info().name());
        Ok(())
    }

    /// Processes all data for the given trust CA.
    fn process_ca(
        &self,
        cert: Arc<CaCert>,
        uri: &impl fmt::Display,
        mut process: P::ProcessCa,
        tasks: &SegQueue<ValidationTask<P::ProcessCa>>,
    ) -> Result<(), Error> {
        let repo_uri = match cert.ca_repository() {
            Some(uri) => uri,
            None => {
                // This is actually checked during certificate validation,
                // so this should never happen.
                error!(
                    "CA cert {} has no repository URI. \
                     Why has it not been rejected yet?",
                    uri
                );
                return Ok(())
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
        let (store, manifest) = match self.get_manifest(
            rrdp_server, &cert, uri, &repo_uri, &mut process,
        ) {
            Some(some) => some,
            None => {
                process.cancel(&cert.cert);
                return Ok(())
            }
        };

        let mut child_cas = Vec::new();
        for (uri, hash) in manifest.iter_uris(repo_uri) {
            if !self.process_object(
                rrdp_server, uri, hash, &cert, &store, &mut process,
                &mut child_cas
            )? {
                process.cancel(&cert.cert);
                return Ok(())
            }
        }

        process.commit();

        for ca in child_cas {
            if ca.defer {
                tasks.push(ValidationTask::Ca(ca));
            }
            else {
                self.process_ca(ca.cert, &ca.uri, ca.process, tasks)?;
            }
        }

        Ok(())
    }

    fn get_manifest<U: fmt::Display>(
        &self,
        rrdp_server: Option<rrdp::ServerId>,
        issuer: &ResourceCert,
        issuer_uri: &U,
        repo_uri: &uri::Rsync,
        process: &mut P::ProcessCa,
    ) -> Option<(CrlStore, ManifestContent)> {
        let uri = match issuer.rpki_manifest() {
            Some(uri) => uri,
            None => {
                warn!("{}: No valid manifest found.", issuer_uri);
                return None
            }
        };
        let bytes = match self.load_file(rrdp_server, &uri) {
            Some(bytes) => bytes,
            None => {
                warn!("{}: failed to load.", uri);
                return None;
            }
        };
        let manifest = match Manifest::decode(bytes, self.repository.strict) {
            Ok(manifest) => manifest,
            Err(_) => {
                warn!("{}: failed to decode", uri);
                return None;
            }
        };
        let (cert, manifest) = match manifest.validate(
            issuer, self.repository.strict
        ) {
            Ok(manifest) => manifest,
            Err(_) => {
                warn!("{}: failed to validate", uri);
                return None;
            }
        };
        if manifest.is_stale() {
            self.metrics.inc_stale_count();
            match self.repository.stale {
                FilterPolicy::Reject => {
                    warn!("{}: stale manifest", uri);
                    return None;
                }
                FilterPolicy::Warn => {
                    warn!("{}: stale manifest", uri);
                }
                FilterPolicy::Accept => { }
            }
        }
        let store = match self.check_manifest_crl(
            rrdp_server, issuer, &uri, &cert, &manifest, repo_uri
        ) {
            Ok(some) => some,
            Err(_) => {
                return None
            }
        };

        process.update_refresh(cert.validity().not_after());
        process.update_refresh(manifest.next_update());
        Some((store, manifest))
    }

    /// Processes an RPKI object and, if necessary, all its dependent objects.
    ///
    /// The object is referenced by `uri`. Its hash is compared to `hash`
    /// and its own certificate is expected to be issued by `cert`. The
    /// CRL store `crl` is used to access the CRLs this object’s certificate
    /// should not be listed on.
    #[allow(clippy::too_many_arguments)]
    fn process_object(
        &self,
        rrdp_server: Option<rrdp::ServerId>,
        uri: uri::Rsync,
        hash: ManifestHash,
        issuer: &Arc<CaCert>,
        crl: &CrlStore,
        process: &mut P::ProcessCa,
        child_cas: &mut Vec<CaValidationTask<P::ProcessCa>>,
    ) -> Result<bool, Error> {
        let bytes = match self.load_file(rrdp_server, &uri) {
            Some(bytes) => bytes,
            None => {
                warn!("{}: failed to load.", uri);
                return Ok(false)
            }
        };
        if hash.verify(&bytes).is_err() {
            warn!("{}: file has wrong manifest hash.", uri);
            return Ok(false)
        }
        if !process.want(&uri)? {
            return Ok(true)
        }

        let res = if uri.ends_with(".cer") {
            self.process_cer(bytes, uri, issuer, crl, process, child_cas)
        }
        else if uri.ends_with(".roa") {
            self.process_roa( bytes, uri, issuer, crl, process)
        }
        else if uri.ends_with(".crl") {
            // CRLs have already been processed.
            Ok(true)
        }
        else if uri.ends_with(".gbr") {
            self.process_gbr(bytes, uri, issuer, crl, process)
        }
        else {
            self.process_other(bytes, uri, issuer, crl, process)
        };

        // XXX Invalid objects should not lead to a CA being rejected for now
        //     pending progress of draft-ietf-sidrops-6486bis
        let _ = res?;
        Ok(true)
    }

    /// Processes a certificate object.
    ///
    /// Returns whether processing of this CA should continue.
    #[allow(clippy::too_many_arguments)]
    fn process_cer(
        &self,
        bytes: Bytes,
        uri: uri::Rsync,
        issuer: &Arc<CaCert>,
        crl: &CrlStore,
        process: &mut P::ProcessCa,
        child_cas: &mut Vec<CaValidationTask<P::ProcessCa>>,
    ) -> Result<bool, Error> {
        let cert = match Cert::decode(bytes) {
            Ok(cert) => cert,
            Err(_) => {
                warn!("{}: failed to decode.", uri);
                return Ok(false)
            }
        };

        if cert.key_usage() == KeyUsage::Ca {
            self.process_ca_cer(
                cert, uri, issuer, crl, process, child_cas
            )
        }
        else {
            self.process_ee_cer(
                cert, uri, issuer, crl, process
            )
        }
    }

    /// Processes a CA certificate.
    ///
    /// Returns whether processing of this CA should continue.
    #[allow(clippy::too_many_arguments)]
    fn process_ca_cer(
        &self,
        cert: Cert,
        uri: uri::Rsync,
        issuer: &Arc<CaCert>,
        crl_store: &CrlStore,
        process: &mut P::ProcessCa,
        child_cas: &mut Vec<CaValidationTask<P::ProcessCa>>,
    ) -> Result<bool, Error> {
        if issuer.check_loop(&cert).is_err() {
            warn!(
                "{}: certificate loop detected.",
                uri
            );
            return Ok(true)
        }
        let cert = match cert.validate_ca(issuer, self.repository.strict) {
            Ok(cert) => cert,
            Err(_) => {
                warn!("{}: CA certificate failed to validate.", uri);
                return Ok(false)
            }
        };
        if self.check_crl(&cert, crl_store).is_err() {
            warn!("{}: certificate has been revoked", uri);
            return Ok(false)
        }
        let repo_uri = match cert.ca_repository() {
            Some(uri) => uri,
            None => {
                warn!("CA cert {} has no repository URI. Ignoring.", uri);
                return Ok(true)
            }
        };

        let mut child_process = match process.process_ca(&uri, &cert)? {
            Some(process) => process,
            None => {
                return Ok(true)
            }
        };
        child_process.update_refresh(cert.validity().not_after());


        // Defer operation if we need to update the repository part where
        // the CA lives.
        let defer = match (self.rrdp.as_ref(), cert.rpki_notify()) {
            (Some(rrdp), Some(rrdp_uri)) => !rrdp.is_current(rrdp_uri),
            _ => match self.rsync.as_ref() {
                Some(rsync) => !rsync.is_current(repo_uri),
                None => false
            }
        };
        child_cas.push(CaValidationTask {
            cert: CaCert::chain(issuer, cert),
            uri,
            process: child_process,
            defer
        });
        Ok(true)
    }

    /// Processes an EE certificate.
    ///
    /// Returns whether processing of this CA should continue.
    #[allow(clippy::too_many_arguments)]
    fn process_ee_cer(
        &self,
        cert: Cert,
        uri: uri::Rsync,
        issuer: &Arc<CaCert>,
        crl_store: &CrlStore,
        process: &mut P::ProcessCa,
    ) -> Result<bool, Error> {
        if cert.validate_router(issuer, self.repository.strict).is_err() {
            warn!("{}: router certificate failed to validate.", uri);
            return Ok(false)
        };
        if self.check_crl(&cert, crl_store).is_err() {
            warn!("{}: certificate has been revoked", uri);
            return Ok(false)
        }

        process.process_ee_cert(&uri, cert)?;

        Ok(true)
    }

    /// Processes a ROA object.
    ///
    /// Returns whether processing of this CA should continue.
    fn process_roa(
        &self,
        bytes: Bytes,
        uri: uri::Rsync,
        issuer: &Arc<CaCert>,
        crl: &CrlStore,
        process: &mut P::ProcessCa,
    ) -> Result<bool, Error> {
        let roa = match Roa::decode(bytes, self.repository.strict) {
            Ok(roa) => roa,
            Err(_) => {
                warn!("{}: decoding failed.", uri);
                return Ok(false)
            }
        };
        let route = roa.process(issuer, self.repository.strict, |cert| {
            self.check_crl(&cert, crl)
        });
        match route {
            Ok(route) => {
                process.process_roa(&uri, route)?;
                Ok(true)
            }
            Err(_) => {
                warn!("{}: validation failed.", uri);
                Ok(false)
            }
        }
    }

    /// Processes a Ghostbuster Record.
    ///
    /// Returns whether processing of this CA should continue.
    fn process_gbr(
        &self,
        bytes: Bytes,
        uri: uri::Rsync,
        issuer: &Arc<CaCert>,
        crl: &CrlStore,
        process: &mut P::ProcessCa,
    ) -> Result<bool, Error> {
        let obj = match SignedObject::decode(bytes, self.repository.strict) {
            Ok(obj) => obj,
            Err(_) => {
                warn!("{}: decoding failed.", uri);
                return Ok(false)
            }
        };
        match obj.process(issuer, self.repository.strict, |cert| {
            self.check_crl(&cert, crl)
        }) {
            Ok(content) => {
                process.process_gbr(&uri, content)?;
                Ok(true)
            }
            Err(_) => {
                warn!("{}: validation failed.", uri);
                Ok(false)
            }
        }
    }

    /// Processes an RPKI object of some other type.
    ///
    /// Returns whether processing of this CA should continue.
    fn process_other(
        &self,
        _bytes: Bytes,
        uri: uri::Rsync,
        _issuer: &Arc<CaCert>,
        _crl: &CrlStore,
        _process: &mut P::ProcessCa,
    ) -> Result<bool, Error> {
        match self.repository.unknown_objects {
            FilterPolicy::Reject => {
                warn!("{}: unknown object; rejecting CA.", uri);
                Ok(false)
            }
            FilterPolicy::Warn => {
                warn!("{}: unknown object; ignoring.", uri);
                Ok(true)
            }
            FilterPolicy::Accept => {
                Ok(true)
            }
        }
    }


    //--- Loading

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


    //--- CRL Handling

    /// Checks wheter a certificate is listed on its CRL.
    fn check_crl(
        &self,
        cert: &TbsCert,
        store: &CrlStore,
    ) -> Result<(), ValidationError> {
        let uri = match cert.crl_uri() {
            Some(some) => some,
            None => return Ok(())
        };

        if store.uri != *uri || store.crl.contains(cert.serial_number()) {
            Err(ValidationError)
        }
        else {
            Ok(())
        }
    }

    /// Check the manifest CRL.
    ///
    /// Checks that there is exactly one CRL on the manifest, that it matches
    /// the CRL mentioned in the manifest’s EE certificate, that it matches
    /// its manifest hash, that it is a valid CRL for the CA, and that it does
    /// not revoke the manifest’s EE certificate.
    ///
    /// If all that is true, returns a `CrlStore` containing that CRL so other
    /// objects can be checked.
    fn check_manifest_crl(
        &self,
        rrdp_server: Option<rrdp::ServerId>,
        issuer: &ResourceCert,
        manifest_uri: &uri::Rsync,
        manifest_cert: &TbsCert,
        manifest: &ManifestContent,
        repo_uri: &uri::Rsync,
    ) -> Result<CrlStore, ValidationError> {
        // Let’s first get the manifest CRL’s name relative to repo_uri. If
        // it ain’t relative at all, this is already invalid.
        let crl_uri = match manifest_cert.crl_uri() {
            // RFC 6481: MUST end in .crl.
            Some(some) if some.ends_with(".crl") => some.clone(),
            _ => {
                warn!("{}: invalid CRL URI.", manifest_uri);
                return Err(ValidationError)
            }
        };
        let crl_name = match uri_relative_to(&crl_uri, repo_uri) {
            Some(name) => name,
            None => {
                warn!(
                    "{}: CRL URI outside repository directory.",
                    manifest_uri
                );
                return Err(ValidationError)
            }
        };

        // Now we go over the manifest and try to find an entry matching
        // crl_name.
        let mut res = None;
        for item in manifest.iter() {
            let (file, hash) = item.into_pair();
            if file == crl_name {
                let (bytes, crl) = self.load_crl(
                    rrdp_server, &crl_uri, issuer
                )?;
                let hash = ManifestHash::new(hash, manifest.file_hash_alg());
                if hash.verify(&bytes).is_err() {
                    warn!("{}: file has wrong hash.", crl_uri);
                    return Err(ValidationError)
                }
                res = Some(crl);
            }
            else if file.ends_with(b".crl") {
                warn!("{}: manifest contains unexpected CRLs.", manifest_uri);
                return Err(ValidationError)
            }
        }
        
        // Now we should have our CRL in res or it wasn’t on the manifest.
        let mut res = match res {
            Some(res) => CrlStore::new(crl_uri, res),
            None => {
                warn!("{}: manifest contains no CRLs.", manifest_uri);
                return Err(ValidationError)
            }
        };

        // Turn on serial caching before looking for the first serial.
        if manifest.len() > CRL_CACHE_LIMIT {
            res.crl.cache_serials()
        }

        // Finally: has the manifest’s cert been revoked?
        if res.crl.contains(manifest_cert.serial_number()) {
            warn!("{}: certificate has been revoked.", manifest_uri);
            return Err(ValidationError)
        }

        // Phew: All good.
        Ok(res)
    }

    /// Loads and validates the given CRL.
    fn load_crl(
        &self,
        rrdp_server: Option<rrdp::ServerId>,
        uri: &uri::Rsync,
        issuer: &ResourceCert,
    ) -> Result<(Bytes, Crl), ValidationError> {
        let bytes = match self.load_file(rrdp_server, &uri) {
            Some(bytes) => bytes,
            _ => return Err(ValidationError),
        };
        let crl = match Crl::decode(bytes.clone()) {
            Ok(crl) => crl,
            Err(_) => return Err(ValidationError)
        };
        if crl.validate(issuer.subject_public_key_info()).is_err() {
            return Err(ValidationError)
        }
        if crl.is_stale() {
            self.metrics.inc_stale_count();
            match self.repository.stale {
                FilterPolicy::Reject => {
                    info!("{}: stale CRL.", uri);
                    return Err(ValidationError)
                }
                FilterPolicy::Warn => {
                    warn!("{}: stale CRL.", uri);
                }
                FilterPolicy::Accept => { }
            }
        }
        Ok((bytes, crl))
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


//------------ CrlStore ------------------------------------------------------

/// The CRL of a CA.
struct CrlStore {
    uri: uri::Rsync,
    crl: Crl,
}

impl CrlStore {
    fn new(uri: uri::Rsync, crl: Crl) -> Self {
        CrlStore { uri, crl }
    }
}


//------------ ValidationTask & CaValidationTask -----------------------------

/// A task for a validation worker thread.
enum ValidationTask<'a, P> {
    /// Process the given TAL.
    Tal { tal: &'a Tal, index: usize },

    /// Process the given CA.
    Ca(CaValidationTask<P>),
}

struct CaValidationTask<P> {
    cert: Arc<CaCert>,
    uri: uri::Rsync,
    process: P,
    defer: bool,
}


//------------ ProcessRun ----------------------------------------------------

pub trait ProcessRun: Send + Sync {
    type ProcessCa: ProcessCa;

    /// Process the given trust anchor.
    ///
    /// If the method wants the content of this trust anchor to be validated
    /// and processed, it returns a processor for it as some success value.
    /// If it rather wishes to skip this trust anchor, it returns `Ok(None)`.
    /// If it wishes to abort processing, it returns an error.
    fn process_ta(
        &self, tal: &Tal, uri: &TalUri, cert: &ResourceCert
    ) -> Result<Option<Self::ProcessCa>, Error>;
}


//------------ ProcessCa -----------------------------------------------------

pub trait ProcessCa: Sized + Send + Sync {
    /// Updates the refresh time for this CA.
    fn update_refresh(&mut self, _not_after: Time) { }

    /// Determines whether an object with the given URI should be processed.
    ///
    /// The object will only be processed if the method returns `Ok(true)`.
    /// If it returns `Ok(false)`, the object will be skipped quietly. If it
    /// returns an error, the entire processing run will be aborted.
    fn want(&self, uri: &uri::Rsync) -> Result<bool, Error>;
   
    /// Process the content of a validated CA.
    ///
    /// The method can choose how to proceed. If it chooses to process the CA,
    /// it returns `Ok(Some(value))` with a new processor to be used for this
    /// CA. If it wishes to skip this CA, it returns `Ok(None)`. And if it
    /// wishes to abort processing, it returns an error.
    fn process_ca(
        &mut self, uri: &uri::Rsync, cert: &ResourceCert
    ) -> Result<Option<Self>, Error>;

    /// Process the content of a validated EE certificate.
    ///
    /// The method is given both the URI and the certificate. If it
    /// returns an error, the entire processing run will be aborted.
    fn process_ee_cert(
        &mut self, uri: &uri::Rsync, cert: Cert
    ) -> Result<(), Error> {
        let _ = (uri, cert);
        Ok(())
    }
 
    /// Process the content of a validated ROA.
    ///
    /// The method is given both the URI and the content of the ROA. If it
    /// returns an error, the entire processing run will be aborted.
    fn process_roa(
        &mut self, uri: &uri::Rsync, route: RouteOriginAttestation
    ) -> Result<(), Error> {
        let _ = (uri, route);
        Ok(())
    }
 
    /// Process the content of a Ghostbuster Record.
    ///
    /// The method is given both the URI and the raw content of the object
    /// as we currently don’t support parsing of these records.
    ///
    /// If the method returns an error, the entire processing run will be
    /// aborted.
    fn process_gbr(
        &mut self, uri: &uri::Rsync, content: Bytes
    ) -> Result<(), Error> {
        let _ = (uri, content);
        Ok(())
    }

    /// Completes processing of the CA.
    ///
    /// The method is called when all objects of the CA have been processed
    /// successfully or have been actively ignored and no error has happend.
    fn commit(self);

    /// Completes processing of an invalid CA.
    ///
    /// The method is called when at least one of the objects published by the
    /// CA is invalid.
    ///
    /// The default implementation does nothing at all.
    fn cancel(self, _cert: &ResourceCert) {
    }
}


//------------ Helper Functions ----------------------------------------------

#[allow(clippy::manual_strip)] // str::strip_prefix not in 1.42
fn uri_relative_to<'a>(
    uri: &'a uri::Rsync,
    other: &uri::Rsync
) -> Option<&'a [u8]> {
    if uri.module() != other.module() {
        return None
    }
    if uri.path() == other.path() {
        Some(b"")
    }
    else if other.path().is_empty() {
        Some(uri.path().as_bytes())
    }
    else if !uri.path().starts_with(other.path()) {
        None
    }
    else {
        let (left, right) = uri.path().split_at(other.path().len());
        if left.ends_with('/') {
            Some(right.as_bytes())
        }
        else if right.starts_with('/') {
            Some(right[1..].as_bytes())
        }
        else {
            None
        }
    }
}


//============ Tests =========================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uri_relative_to() {
        use std::str::FromStr;

        let aa      = uri::Rsync::from_str("rsync://l/m/aa").unwrap();
        let aaa     = uri::Rsync::from_str("rsync://l/m/aaa").unwrap();
        let aa_s    = uri::Rsync::from_str("rsync://l/m/aa/").unwrap();
        let aa_s_bb = uri::Rsync::from_str("rsync://l/m/aa/bb").unwrap();
        let cc      = uri::Rsync::from_str("rsync://l/m/cc").unwrap();
        let cc_s    = uri::Rsync::from_str("rsync://l/m/cc/").unwrap();
        let dl      = uri::Rsync::from_str("rsync://d/m/aa/").unwrap();
        let dm      = uri::Rsync::from_str("rsync://l/d/aa/").unwrap();
        let dlm     = uri::Rsync::from_str("rsync://d/d/aa/").unwrap();
        let n       = uri::Rsync::from_str("rsync://d/d/").unwrap();
        let n_bb    = uri::Rsync::from_str("rsync://d/d/bb").unwrap();

        assert_eq!(uri_relative_to(&aa, &aa), Some(b"".as_ref()));
        assert_eq!(uri_relative_to(&aaa, &aa), None);
        assert_eq!(uri_relative_to(&aa_s_bb, &aa), Some(b"bb".as_ref()));
        assert_eq!(uri_relative_to(&aa_s_bb, &aa_s), Some(b"bb".as_ref()));
        assert_eq!(uri_relative_to(&aa_s_bb, &cc), None);
        assert_eq!(uri_relative_to(&aa_s_bb, &cc_s), None);
        assert_eq!(uri_relative_to(&aa_s_bb, &dl), None);
        assert_eq!(uri_relative_to(&aa_s_bb, &dm), None);
        assert_eq!(uri_relative_to(&aa_s_bb, &dlm), None);
        assert_eq!(uri_relative_to(&n_bb, &n), Some(b"bb".as_ref()));
    }
}

