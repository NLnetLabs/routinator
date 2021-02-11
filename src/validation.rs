/// Validation of RPKI data.

use std::{fs, io};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use bytes::Bytes;
use crossbeam_queue::SegQueue;
use crossbeam_utils::thread;
use log::{debug, error, warn};
use rpki::repository::cert::{Cert, KeyUsage, ResourceCert};
use rpki::repository::crl::Crl;
use rpki::repository::crypto::keys::KeyIdentifier;
use rpki::repository::manifest::{Manifest, ManifestContent, ManifestHash};
use rpki::repository::roa::{Roa, RouteOriginAttestation};
use rpki::repository::sigobj::SignedObject;
use rpki::repository::tal::{Tal, TalInfo, TalUri};
use rpki::repository::x509::{Time, ValidationError};
use rpki::uri;
use crate::{cache, store};
use crate::cache::Cache;
use crate::config::{Config, FilterPolicy};
use crate::metrics::Metrics;
use crate::operation::Error;
use crate::origins::OriginsReport;
use crate::store::{Store, StoredManifest};


//------------ Configuration -------------------------------------------------

/// The minimum number of manifest entries that triggers CRL serial caching.
///
/// The value has been determined exprimentally with the RPKI repository at
/// a certain state so may or may not be a good one, really.
const CRL_CACHE_LIMIT: usize = 50;


//------------ Validation ----------------------------------------------------

/// Information on the trust anchors and rules for validation.
#[derive(Debug)]
pub struct Validation {
    /// The directory to load TALs from.
    tal_dir: PathBuf,

    /// A mapping of TAL file names to TAL labels.
    tal_labels: HashMap<String, String>,

    /// The list of our TALs. 
    tals: Vec<Tal>,

    /// The cache to load updated data from.
    cache: Cache,

    /// The store to load stored data from.
    store: Store,

    /// Should we be strict when decoding data?
    strict: bool,

    /// How do we deal with stale objects?
    stale: FilterPolicy,

    /// How do we deal with unknown object types?
    unknown_objects: FilterPolicy,

    /// Number of validation threads.
    validation_threads: usize,

    /// Should we leave the repository dirty after a valiation run.
    dirty_repository: bool,
}

impl Validation {
    /// Initializes whatever needs initializing.
    pub fn init(config: &Config) -> Result<(), Error> {
        if let Err(err) = fs::read_dir(&config.tal_dir) {
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

    /// Creates a new set of validation rules from the configuration.
    pub fn new(
        config: &Config,
        cache: Cache,
        store: Store,
    ) -> Result<Self, Error> {
        Self::init(config)?;
        let mut res = Validation {
            tal_dir: config.tal_dir.clone(),
            tal_labels: config.tal_labels.clone(),
            tals: Vec::new(),
            cache,
            store,
            strict: config.strict,
            stale: config.stale,
            unknown_objects: config.unknown_objects,
            validation_threads: config.validation_threads,
            dirty_repository: config.dirty_repository,
        };
        res.reload_tals()?;
        Ok(res)
    }

    /// Reloads the TAL files based on the config object.
    pub fn reload_tals(&mut self) -> Result<(), Error> {
        let mut res = Vec::new();
        let dir = match fs::read_dir(&self.tal_dir) {
            Ok(dir) => dir,
            Err(err) => {
                if err.kind() == io::ErrorKind::NotFound {
                    error!(
                        "Missing TAL directory {}.\n\
                         You may have to initialize it via \
                         \'routinator init\'.",
                         self.tal_dir.display()
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
                self.path_to_tal_label(&path),
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
        self.tals = res;
        Ok(())
    }

    /// Converts a path into a TAL label.
    fn path_to_tal_label(&self, path: &Path) -> String {
        if let Some(name) = path.file_name().unwrap().to_str() {
            if let Some(label) = self.tal_labels.get(name) {
                return label.clone()
            }
        }
        path.file_stem().unwrap().to_string_lossy().into_owned()
    }

    /// Ignites validation processing.
    ///
    /// This spawns of threads and therefore needs to be done after a
    /// possible fork.
    pub fn ignite(&mut self) -> Result<(), Error> {
        self.cache.ignite()
    }

    /// Starts a validation run.
    pub fn start<P>(&self, processor: P) -> Result<Run<P>, Error> {
        Ok(Run::new(self, self.cache.start()?, self.store.start(), processor))
    }

    pub fn process_origins(
        &self
    ) -> Result<(OriginsReport, Metrics), Error> {
        let report = OriginsReport::new();
        let run = self.start(&report)?;
        run.process()?;
        let metrics = run.done();
        Ok((report, metrics))
    }

    pub fn cleanup(&self) -> Result<(), Error> {
        self.store.cleanup(self.cache.cleanup())
    }
}



//------------ Run -----------------------------------------------------------

/// A single validation run.
#[derive(Debug)]
pub struct Run<'a, P> {
    validation: &'a Validation,
    cache: cache::Run<'a>,
    store: store::Run<'a>,
    processor: P,
    metrics: Metrics,
}

impl<'a, P> Run<'a, P> {
    fn new(
        validation: &'a Validation,
        cache: cache::Run<'a>,
        store: store::Run<'a>,
        processor: P,
    ) -> Self {
        Run {
            validation, cache, store, processor,
            metrics: Metrics::new()
        }
    }

    pub fn done(mut self) -> Metrics {
        self.cache.done(&mut self.metrics);
        self.store.done(&mut self.metrics);
        self.metrics
    }
}

impl<'a, P: ProcessRun> Run<'a, P> {
    /// Performs the validation run.
    pub fn process(&self) -> Result<(), Error> {
        // If we don’t have any TALs, we ain’t got nothing to do.
        if self.validation.tals.is_empty() {
            return Ok(())
        }

        // Initialize our task queue with all the TALs.
        let tasks = SegQueue::new();
        for (index, tal) in self.validation.tals.iter().enumerate() {
            tasks.push(Task::Tal(TalTask { tal, index }));
        }

        // And off we trot.
        let had_err = AtomicBool::new(false);
        let res = thread::scope(|scope| {
            for _ in 0..self.validation.validation_threads {
                scope.spawn(|_| {
                    while let Some(task) = tasks.pop() {
                        if self.process_task(task, &tasks).is_err() {
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

    /// Process a task. Any task.
    fn process_task(
        &self, task: Task<P::ProcessCa>, tasks: &SegQueue<Task<P::ProcessCa>>
    ) -> Result<(), Error> {
        match task {
            Task::Tal(task) => self.process_tal_task(task, tasks),
            Task::Ca(task) => self.process_ca_task(task, tasks)
        }
    }

    /// Processes a trust anchor.
    fn process_tal_task(
        &self, task: TalTask, tasks: &SegQueue<Task<P::ProcessCa>>
    ) -> Result<(), Error> {
        for uri in task.tal.uris() {
            let cert = match self.load_ta(uri, task.tal.info())? {
                Some(cert) => cert,
                _ => continue,
            };
            if cert.subject_public_key_info() != task.tal.key_info() {
                warn!(
                    "Trust anchor {}: key doesn’t match TAL.",
                    uri
                );
                continue;
            }
            let cert = match cert.validate_ta(
                task.tal.info().clone(), self.validation.strict
            ) {
                Ok(cert) => CaCert::root(cert, uri.clone(), task.index),
                Err(_) => {
                    warn!("Trust anchor {}: doesn’t validate.", uri);
                    continue;
                }
            };
            let cert = match cert {
                Ok(cert) => cert,
                Err(_) => continue,
            };
            debug!("Found valid trust anchor {}. Processing.", uri);

            match self.processor.process_ta(task.tal, uri, cert.cert())? {
                Some(processor) => {
                    return self.process_ca_task(
                        CaTask { cert, processor, defer: false, }, tasks
                    )
                }
                None => {
                    debug!("Skipping trust anchor {}.", uri);
                    return Ok(())
                }
            }
        }
        warn!("No valid trust anchor for TAL {}", task.tal.info().name());
        Ok(())
    }

    /// Loads a trust anchor certificate with the given URI.
    ///
    /// Attempts to download the certificate from upstream but falls back to
    /// the version in the store if available.
    fn load_ta(
        &self,
        uri: &TalUri,
        _info: &TalInfo,
    ) -> Result<Option<Cert>, Error> {
        // Get the new version, store and return it if it decodes.
        if let Some(bytes) = self.cache.load_ta(uri) {
            if let Ok(cert) = Cert::decode(bytes.clone()) {
                self.store.update_ta(uri, &bytes)?;
                return Ok(Some(cert))
            }
        }

        // Get what we have in store.
        self.store.load_ta(uri).map(|bytes| {
            bytes.and_then(|bytes| Cert::decode(bytes).ok())
        })
    }

    /// Processes a CA.
    fn process_ca_task(
        &self,
        task: CaTask<P::ProcessCa>,
        tasks: &SegQueue<Task<P::ProcessCa>>,
    ) -> Result<(), Error> {
        let more_tasks = PubPoint::new(
            self, &task.cert, task.processor
        )?.process()?;
        for task in more_tasks {
            if task.defer {
                tasks.push(Task::Ca(task))
            }
            else {
                self.process_ca_task(task, tasks)?;
            }
        }
        Ok(())
    }
}


//------------ PubPoint ------------------------------------------------------

struct PubPoint<'a, P: ProcessRun> {
    run: &'a Run<'a, P>,
    cert: &'a Arc<CaCert>,
    processor: P::ProcessCa,
    cache: Option<cache::Repository<'a>>,
    store: store::Repository,
}

impl<'a, P: ProcessRun> PubPoint<'a, P> {
    pub fn new(
        run: &'a Run<'a, P>,
        cert: &'a Arc<CaCert>,
        processor: P::ProcessCa,
    ) -> Result<Self, Error> {
        let cache = run.cache.repository(cert);
        let store = run.store.repository(cert, cache.as_ref())?;
        Ok(PubPoint { run, cert, processor, cache, store })
    }

    pub fn process(self) -> Result<Vec<CaTask<P::ProcessCa>>, Error> {
        let manifest = match self.update_stored()? {
            PointManifest::Valid(manifest) => manifest,
            PointManifest::Unverified(stored) => {
                match self.validate_stored_manifest(stored) {
                    Ok(manifest) => manifest,
                    Err(_) => return Ok(Vec::new())
                }
            }
            PointManifest::NotFound => {
                warn!(
                    "{}: No valid manifest found.",
                    self.cert.rpki_manifest()
                );
                return Ok(Vec::new())
            }
        };

        ValidPubPoint::new(self, manifest).process()
    }

    // Clippy false positive: We are using HashSet<Bytes> here -- Bytes is
    // not a mutable type.
    #[allow(clippy::mutable_key_type)]
    fn update_stored(&self) -> Result<PointManifest, Error> {
        // If we don’t have a cache, we just use the stored publication point.
        let cache = match self.cache {
            Some(ref cache) => cache,
            None => {
                return self.store.load_manifest(
                    self.cert.rpki_manifest()
                ).map(Into::into)
            }
        };

        // Try to load the manifest both from store and cache.
        let cached = cache.load_object(self.cert.rpki_manifest());
        let stored = self.store.load_manifest(self.cert.rpki_manifest())?;

        // If the manifest is not in the cache, we can abort already.
        let cached = match cached {
            Some(mft) => mft,
            None => return Ok(stored.into())
        };

        // If the stored and cached manifests are the same, nothing has
        // changed and we can abort the update. However, we need to check that
        // the stored manifest refers to the same CA repository URI, just to
        // be sure.
        let same = if let Some(mft) = stored.as_ref() {
            mft.manifest() == &cached
                && mft.ca_repository() == self.cert.ca_repository()
        }
        else {
            false
        };
        if same {
            return Ok(stored.into())
        }

        // Validate the cached manifest.
        let cached = match self.validate_cached_manifest(cached, cache) {
            Ok(cached) => cached,
            Err(_) => {
                return Ok(stored.into())
            }
        };

        // The manifest is fine. Now we can update the cache. We do this in a
        // transaction and rollback if anything is wrong.
        let files = self.store.update_point(
            self.cert.rpki_manifest(),

            |update| {
                // Store all files on the cached manifest. Abort if they can’t
                // be loaded or if their hash doesn’t match.
                //
                // We also stick all file names into a set so we can delete
                // everything that isn’t on the manifest.
                let mut files = HashSet::new();
                for item in cached.content.iter() {
                    let uri = match self.cert.ca_repository().join(
                        item.file()
                    ) {
                        Ok(uri) => uri,
                        Err(_) => {
                            warn!("{}: illegal file name '{}'.",
                                self.cert.rpki_manifest(),
                                String::from_utf8_lossy(item.file())
                            );
                            return Err(store::UpdateError::abort())
                        }
                    };
                    let hash = ManifestHash::new(
                        item.hash().clone(), cached.content.file_hash_alg()
                    );

                    let content = match cache.load_object(&uri) {
                        Some(content) => content,
                        None => {
                            warn!("{}: failed to load.", uri);
                            return Err(store::UpdateError::abort());
                        }
                    };

                    if hash.verify(&content).is_err() {
                        warn!("{}: file has wrong manifest hash.", uri);
                        return Err(store::UpdateError::abort());
                    }

                    update.insert_object(
                        item.file(),
                        &store::StoredObject::new(content, Some(hash), None)
                    )?;

                    files.insert(item.file().clone());
                }

                update.update_manifest(
                    &store::StoredManifest::new(
                        self.cert.cert.validity().not_after(),
                        self.cert.ca_repository().clone(),
                        cached.manifest_bytes.clone(),
                        cached.crl_bytes.clone(),
                    )
                )?;
                Ok(files)
            }
        );

        let files = match files {
            Ok(files) => files,
            Err(err) => {
                if err.was_aborted() {
                    warn!(
                        "{}: Invalid manifest or content. \
                        Using previously stored version.",
                        self.cert.rpki_manifest()
                    );
                    return Ok(stored.into())
                }
                else {
                    return Err(Error)
                }
            }
        };

        // Delete everything in the store that is not in files.
        self.store.drain_point(
            self.cert.rpki_manifest(),
            |file| files.contains(file)
        )?;

        Ok(cached.into())
    }

    fn validate_cached_manifest(
        &self, manifest_bytes: Bytes, cache: &cache::Repository
    ) -> Result<ValidPointManifest, ValidationError> {
        let manifest = match Manifest::decode(
            manifest_bytes.clone(), self.run.validation.strict
        ) {
            Ok(manifest) => manifest,
            Err(_) => {
                warn!("{}: failed to decode", self.cert.rpki_manifest());
                return Err(ValidationError);
            }
        };
        let (ee_cert, content) = match manifest.validate(
            self.cert.cert(), self.run.validation.strict
        ) {
            Ok(some) => some,
            Err(_) => {
                warn!("{}: failed to validate", self.cert.rpki_manifest());
                return Err(ValidationError);
            }
        };
        if content.is_stale() {
            //self.metrics.inc_stale_count();
            match self.run.validation.stale {
                FilterPolicy::Reject => {
                    warn!("{}: stale manifest", self.cert.rpki_manifest());
                    return Err(ValidationError);
                }
                FilterPolicy::Warn => {
                    warn!("{}: stale manifest", self.cert.rpki_manifest());
                }
                FilterPolicy::Accept => { }
            }
        }

        let (crl_uri, crl, crl_bytes) = self.validate_cached_crl(
            &ee_cert, &content, cache
        )?;

        Ok(ValidPointManifest {
            ee_cert, content, crl_uri, crl, manifest_bytes, crl_bytes
        })
    }

    /// Check the manifest CRL.
    ///
    /// Checks that there is exactly one CRL on the manifest, that it matches
    /// the CRL mentioned in the manifest’s EE certificate, that it matches
    /// its manifest hash, that it is a valid CRL for the CA, and that it does
    /// not revoke the manifest’s EE certificate.
    ///
    /// If all that is true, returns the decoded CRL.
    fn validate_cached_crl(
        &self,
        ee_cert: &ResourceCert,
        manifest: &ManifestContent,
        cache: &cache::Repository
    ) -> Result<(uri::Rsync, Crl, Bytes), ValidationError> {
        // Let’s first get the manifest CRL’s name relative to repo_uri. If
        // it ain’t relative at all, this is already invalid.
        let crl_uri = match ee_cert.crl_uri() {
            // RFC 6481: MUST end in .crl.
            Some(some) if some.ends_with(".crl") => some.clone(),
            _ => {
                warn!("{}: invalid CRL URI.", self.cert.rpki_manifest());
                return Err(ValidationError)
            }
        };
        let crl_name = match crl_uri.relative_to(&self.cert.ca_repository()) {
            Some(name) => name,
            None => {
                warn!(
                    "{}: CRL URI outside repository directory.",
                    self.cert.rpki_manifest()
                );
                return Err(ValidationError)
            }
        };

        // Now we go over the manifest and try to find an entry matching
        // crl_name.
        let mut crl_bytes = None;
        for item in manifest.iter() {
            let (file, hash) = item.into_pair();
            if file == crl_name {
                let bytes = match cache.load_object(&crl_uri) {
                    Some(bytes) => bytes,
                    None => {
                        warn!("{}: failed to load.", crl_uri);
                        return Err(ValidationError);
                    }
                };
                let hash = ManifestHash::new(hash, manifest.file_hash_alg());
                if hash.verify(&bytes).is_err() {
                    warn!("{}: file has wrong hash.", crl_uri);
                    return Err(ValidationError)
                }
                crl_bytes = Some(bytes);
            }
            else if file.ends_with(b".crl") {
                warn!(
                    "{}: manifest contains unexpected CRLs.",
                    self.cert.rpki_manifest()
                );
                return Err(ValidationError)
            }
        }
        let crl_bytes = match crl_bytes {
            Some(some) => some,
            None => {
                warn!(
                    "{}: CRL not listed on manifest.",
                    self.cert.rpki_manifest()
                );
                return Err(ValidationError);
            }
        };

        // Decode and validate the CRL.
        let mut crl = match Crl::decode(crl_bytes.clone()) {
            Ok(crl) => crl,
            Err(_) => {
                warn!("{}: failed to decode.", crl_uri);
                return Err(ValidationError)
            }
        };
        if crl.validate(self.cert.cert().subject_public_key_info()).is_err() {
            warn!("{}: failed to validate.", crl_uri);
            return Err(ValidationError)
        }
        if crl.is_stale() {
            //self.metrics.inc_stale_count();
            match self.run.validation.stale {
                FilterPolicy::Reject => {
                    warn!("{}: stale CRL.", crl_uri);
                    return Err(ValidationError)
                }
                FilterPolicy::Warn => {
                    warn!("{}: stale CRL.", crl_uri);
                }
                FilterPolicy::Accept => { }
            }
        }

        // Turn on serial caching before looking for the first serial.
        if manifest.len() > CRL_CACHE_LIMIT {
            crl.cache_serials()
        }

        // Finally: has the manifest’s cert been revoked?
        if crl.contains(ee_cert.serial_number()) {
            warn!(
                "{}: certificate has been revoked.",
                self.cert.rpki_manifest()
            );
            return Err(ValidationError)
        }

        // Phew: All good.
        Ok((crl_uri, crl, crl_bytes))
    }

    fn validate_stored_manifest(
        &self, stored_manifest: StoredManifest
    ) -> Result<ValidPointManifest, ValidationError> {
        // Decode and validate the manifest.
        let manifest = match Manifest::decode(
            stored_manifest.manifest().clone(), self.run.validation.strict
        ) {
            Ok(manifest) => manifest,
            Err(_) => {
                warn!("{}: failed to decode", self.cert.rpki_manifest());
                return Err(ValidationError);
            }
        };
        let (ee_cert, content) = match manifest.validate(
            self.cert.cert(), self.run.validation.strict
        ) {
            Ok(some) => some,
            Err(_) => {
                warn!("{}: failed to validate", self.cert.rpki_manifest());
                return Err(ValidationError);
            }
        };
        if content.is_stale() {
            //self.metrics.inc_stale_count();
            match self.run.validation.stale {
                FilterPolicy::Reject => {
                    warn!("{}: stale manifest", self.cert.rpki_manifest());
                    return Err(ValidationError);
                }
                FilterPolicy::Warn => {
                    warn!("{}: stale manifest", self.cert.rpki_manifest());
                }
                FilterPolicy::Accept => { }
            }
        }

        // Get the CRL URI. We actually only need this for error reporting.
        let crl_uri = match ee_cert.crl_uri() {
            Some(uri) => uri.clone(),
            None => {
                // This should have been ruled out in manifest validation.
                warn!(
                    "{}: manifest without CRL URI.",
                    self.cert.rpki_manifest()
                );
                return Err(ValidationError)
            }
        };

        // Decode and validate the CRL.
        let mut crl = match Crl::decode(stored_manifest.crl().clone()) {
            Ok(crl) => crl,
            Err(_) => {
                warn!("{}: failed to decode.", crl_uri);
                return Err(ValidationError)
            }
        };
        if crl.validate(self.cert.cert().subject_public_key_info()).is_err() {
            warn!("{}: failed to validate.", crl_uri);
            return Err(ValidationError)
        }
        if crl.is_stale() {
            //self.metrics.inc_stale_count();
            match self.run.validation.stale {
                FilterPolicy::Reject => {
                    warn!("{}: stale CRL.", crl_uri);
                    return Err(ValidationError)
                }
                FilterPolicy::Warn => {
                    warn!("{}: stale CRL.", crl_uri);
                }
                FilterPolicy::Accept => { }
            }
        }

        // Turn on serial caching before looking for the first serial.
        if content.len() > CRL_CACHE_LIMIT {
            crl.cache_serials()
        }

        // Finally: has the manifest’s cert been revoked?
        //
        // XXX This shouldn’t really happen because if it were we would never
        //     have stored this manifest.
        if crl.contains(ee_cert.serial_number()) {
            warn!(
                "{}: certificate has been revoked.",
                self.cert.rpki_manifest()
            );
            return Err(ValidationError)
        }

        Ok(ValidPointManifest {
            ee_cert, content, crl_uri, crl,
            manifest_bytes: stored_manifest.manifest().clone(),
            crl_bytes: stored_manifest.crl().clone()
        })
    }
}


//------------ ValidPubPoint -------------------------------------------------

struct ValidPubPoint<'a, P: ProcessRun> {
    point: PubPoint<'a, P>,
    manifest: ValidPointManifest,
    child_cas: Vec<CaTask<P::ProcessCa>>,
}

impl<'a, P: ProcessRun> ValidPubPoint<'a, P> {
    pub fn new(point: PubPoint<'a, P>, manifest: ValidPointManifest) -> Self {
        ValidPubPoint {
            point, manifest,
            child_cas: Vec::new()
        }
    }

    pub fn process(mut self) -> Result<Vec<CaTask<P::ProcessCa>>, Error> {
        if self._process()? {
            self.point.processor.commit();
            Ok(self.child_cas)
        }
        else {
            self.point.processor.cancel(&self.point.cert.cert());
            Ok(Vec::new())
        }
    }

    pub fn _process(&mut self) -> Result<bool, Error> {
        for item in self.manifest.content.iter() {
            let (file, hash) = item.into_pair();
            let uri = match self.point.cert.ca_repository().join(&file) {
                Ok(uri) => uri,
                Err(_) => {
                    warn!(
                        "{}: illegal file name {} in manifest.",
                        self.point.cert.rpki_manifest(),
                        String::from_utf8_lossy(&file)
                    );
                    return Ok(false)
                }
            };
            let hash = ManifestHash::new(
                hash, self.manifest.content.file_hash_alg()
            );
            if !self.process_object(uri, &file, hash)? {
                return Ok(false)
            }
        }

        Ok(true)
    }

    /// Processes a single object on the manifest.
    ///
    /// Returns whether processing of the manifest should continue or whether
    /// the entire (!) manifest should be disregarded.
    fn process_object(
        &mut self, uri: uri::Rsync, file: &[u8], hash: ManifestHash,
    ) -> Result<bool, Error> {
        let object = match self.point.store.load_object(
            self.point.cert.rpki_manifest(), file
        )? {
            Some(bytes) => bytes,
            None => {
                warn!("{}: failed to load.", uri);
                return Ok(false)
            }
        };

        if object.verify_hash(&hash).is_err() {
            warn!("{}: file has wrong manifest hash.", uri);
            return Ok(false)
        }

        if !self.point.processor.want(&uri)? {
            return Ok(true)
        }

        if uri.ends_with(".cer") {
            self.process_cer(uri, object)?;
        }
        else if uri.ends_with(".roa") {
            self.process_roa(uri, object)?;
        }
        else if uri.ends_with(".crl") {
            // CRLs have already been processed.
        }
        else if uri.ends_with(".gbr") {
            self.process_gbr(uri, object)?;
        }
        else {
            warn!("{}: unknown object type.", uri);
        }
        Ok(true)
    }

    /// Processes a certificate object.
    fn process_cer(
        &mut self, uri: uri::Rsync, object: store::StoredObject,
    ) -> Result<(), Error> {
        let cert = match Cert::decode(object.into_content()) {
            Ok(cert) => cert,
            Err(_) => {
                warn!("{}: failed to decode.", uri);
                return Ok(())
            }
        };

        if cert.key_usage() == KeyUsage::Ca {
            self.process_ca_cer(uri, cert)
        }
        else {
            self.process_ee_cer(uri, cert)
        }
    }

    /// Processes a CA certificate.
    #[allow(clippy::too_many_arguments)]
    fn process_ca_cer(
        &mut self, uri: uri::Rsync, cert: Cert,
    ) -> Result<(), Error> {
        if self.point.cert.check_loop(&cert).is_err() {
            warn!("{}: certificate loop detected.", uri);
            return Ok(())
        }
        let cert = match cert.validate_ca(
            self.point.cert.cert(), self.point.run.validation.strict
        ) {
            Ok(cert) => cert,
            Err(_) => {
                warn!("{}: CA certificate failed to validate.", uri);
                return Ok(())
            }
        };
        if self.check_crl(&uri, &cert).is_err() {
            return Ok(())
        }

        let cert = match CaCert::chain(
            &self.point.cert, uri.clone(), cert
        ) {
            Ok(cert) => cert,
            Err(_) => return Ok(())
        };

        let mut processor = match self.point.processor.process_ca(
            &uri, &cert.cert
        )? {
            Some(processor) => processor,
            None => return Ok(())
        };
        processor.update_refresh(cert.cert.validity().not_after());

        // Defer operation if we need to update the repository part where
        // the CA lives.
        let defer = self.point.run.cache.is_current(&cert);

        self.child_cas.push(CaTask { cert, processor, defer });
        Ok(())
    }

    /// Processes an EE certificate.
    fn process_ee_cer(
        &mut self, uri: uri::Rsync, cert: Cert,
    ) -> Result<(), Error> {
        if cert.validate_router(
            &self.point.cert.cert, self.point.run.validation.strict
        ).is_err() {
            warn!("{}: router certificate failed to validate.", uri);
            return Ok(())
        };
        if self.check_crl(&uri, &cert).is_err() {
            return Ok(())
        }
        self.point.processor.process_ee_cert(&uri, cert)?;
        Ok(())
    }

    /// Processes a ROA object.
    fn process_roa(
        &mut self, uri: uri::Rsync, object: store::StoredObject,
    ) -> Result<(), Error> {
        let roa = match Roa::decode(
            object.into_content(), self.point.run.validation.strict
        ) {
            Ok(roa) => roa,
            Err(_) => {
                warn!("{}: decoding failed.", uri);
                return Ok(())
            }
        };
        match roa.process(
            &self.point.cert.cert,
            self.point.run.validation.strict,
            |cert| self.check_crl(&uri, &cert)
        ) {
            Ok(route) => self.point.processor.process_roa(&uri, route)?,
            Err(_) => warn!("{}: validation failed.", uri)
        }
        Ok(())
    }

    /// Processes a Ghostbuster Record.
    fn process_gbr(
        &mut self, uri: uri::Rsync, object: store::StoredObject,
    ) -> Result<(), Error> {
        let obj = match SignedObject::decode(
            object.into_content(), self.point.run.validation.strict
        ) {
            Ok(obj) => obj,
            Err(_) => {
                warn!("{}: decoding failed.", uri);
                return Ok(())
            }
        };
        match obj.process(
            &self.point.cert.cert,
            self.point.run.validation.strict,
            |cert| self.check_crl(&uri, &cert)
        ) {
            Ok(content) => self.point.processor.process_gbr(&uri, content)?,
            Err(_) => warn!("{}: validation failed.", uri),
        }
        Ok(())
    }

    fn check_crl(
        &self, uri: &uri::Rsync, cert: &Cert
    ) -> Result<(), ValidationError> {
        let crl_uri = match cert.crl_uri() {
            Some(some) => some,
            None => {
                warn!("{}: certificate has no CRL URI", uri);
                return Err(ValidationError)
            }
        };

        if *crl_uri != self.manifest.crl_uri {
            warn!("{}: certifacte's CRL differs from manifest's.", uri);
            return Err(ValidationError)
        }

        if self.manifest.crl.contains(cert.serial_number()) {
            warn!("{}: certificate has been revoked.", uri);
            return Err(ValidationError)
        }

        Ok(())
    }
}


//------------ Task ----------------------------------------------------------

/// Any task that can be queued for delayed processing.
enum Task<'a, P> {
    Tal(TalTask<'a>),
    Ca(CaTask<P>),
}


//------------ TalTask ------------------------------------------------------

/// A task for processing a single TAL.
struct TalTask<'a> {
    /// A reference to the actual tal.
    tal: &'a Tal,

    /// The index of this TAL in the metrics.
    index: usize,
}


//------------ CaTask --------------------------------------------------------

/// A task for processing a single CA.
struct CaTask<P> {
    /// The CA certificate of the CA.
    cert: Arc<CaCert>,

    /// The processor for this CA.
    processor: P,

    /// Defer processing?
    defer: bool,
}


//------------ CaCert --------------------------------------------------------

/// A CA certificate plus references to all its parents.
#[derive(Clone, Debug)]
pub struct CaCert {
    /// The CA certificate of this CA.
    cert: ResourceCert,

    /// The certificate’s location.
    uri: TalUri,

    /// The CA repository URI of the certificate.
    ca_repository: uri::Rsync,

    /// The manifest URI of the certificate.
    rpki_manifest: uri::Rsync,

    /// The parent CA.
    /// 
    /// This will be none for a trust anchor.
    parent: Option<Arc<CaCert>>,

    /// The index of the TAL.
    tal: usize,
}

impl CaCert {
    /// Creates a new CA cert for a trust anchor.
    pub fn root(
        cert: ResourceCert, uri: TalUri, tal: usize
    ) -> Result<Arc<Self>, Error> {
        Self::new(cert, uri, None, tal)
    }

    pub fn chain(
        this: &Arc<Self>,
        uri: uri::Rsync,
        cert: ResourceCert
    ) -> Result<Arc<Self>, Error> {
        Self::new(cert, TalUri::Rsync(uri), Some(this.clone()), this.tal)
    }

    fn new(
        cert: ResourceCert,
        uri: TalUri, 
        parent: Option<Arc<Self>>,
        tal: usize
    ) -> Result<Arc<Self>, Error> {
        let ca_repository = match cert.ca_repository() {
            Some(uri) => uri.clone(),
            None => {
                // This is actually checked during certificate validation,
                // so this should never happen.
                error!(
                    "CA cert {} has no repository URI. \
                     Why has it not been rejected yet?",
                    uri
                );
                return Err(Error)
            }
        };
        
        let rpki_manifest = match cert.rpki_manifest() {
            Some(uri) => uri.clone(),
            None => {
                // This is actually checked during certificate validation,
                // so this should never happen.
                error!(
                    "CA cert {} has no manifest URI. \
                     Why has it not been rejected yet?",
                    uri
                );
                return Err(Error)
            }
        };
        Ok(Arc::new(CaCert {
            cert, uri, ca_repository, rpki_manifest, parent, tal
        }))
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

    pub fn cert(&self) -> &ResourceCert {
        &self.cert
    }

    pub fn ca_repository(&self) -> &uri::Rsync {
        &self.ca_repository
    }

    pub fn rpki_manifest(&self) -> &uri::Rsync {
        &self.rpki_manifest
    }

    pub fn rpki_notify(&self) -> Option<&uri::Https> {
        self.cert.rpki_notify()
    }
} 


//------------ PointManinfest ------------------------------------------------

// XXX Clippy complains that ValidPointManifest is 1160 bytes. I _think_ this
//     is fine here as PointManifest is just a helper type to make things
//     easier and everything eventually turns into a ValidPointManifest, but
//     perhaps some restructuring might be good, anyway.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
enum PointManifest {
    Unverified(StoredManifest),
    Valid(ValidPointManifest),
    NotFound,
}

impl From<StoredManifest> for PointManifest {
    fn from(src: StoredManifest) -> Self {
        PointManifest::Unverified(src)
    }
}

impl From<Option<StoredManifest>> for PointManifest {
    fn from(src: Option<StoredManifest>) -> Self {
        match src {
            Some(manifest) => PointManifest::Unverified(manifest),
            None => PointManifest::NotFound
        }
    }
}

impl From<ValidPointManifest> for PointManifest {
    fn from(src: ValidPointManifest) -> PointManifest {
        PointManifest::Valid(src)
    }
}


//------------ ValidPointManifest --------------------------------------------

#[derive(Clone, Debug)]
struct ValidPointManifest {
    ee_cert: ResourceCert,
    content: ManifestContent,
    crl_uri: uri::Rsync,
    crl: Crl,
    manifest_bytes: Bytes,
    crl_bytes: Bytes,
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


