/// Updating and processing of RPKI data.
///
/// This module provides types and traits implementing validation of RPKI data
/// from a set of trust anchor locators to some output data.
///
/// Data validation is configured through [`Engine`] so that the
/// configuration can be used for multiple validation runs. This includes both
/// a [collector][crate::collector::Collector] and
/// [store][crate::store::Store] to use for validation.
///
/// Individual validation runs are managed through [`Run`]. Such a runner can
/// be obtained from validation via its [`start`][Engine::start] method.
/// It in turn provides the [`process`][Run::process] method which drives the
/// actual validation.
///
/// Engine runs are generic over what exactly should be done with valid
/// RPKI data. The trait [`ProcessRun`] represents a full validation run with
/// the accompanying trait [`ProcessPubPoint`] dealing with individual
/// publication points.

use std::{fmt, fs, io, str};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use bytes::Bytes;
use crossbeam_queue::{ArrayQueue, SegQueue};
use crossbeam_utils::thread;
use log::{debug, error, warn};
use rpki::repository::cert::{Cert, KeyUsage, ResourceCert};
use rpki::repository::crl::Crl;
use rpki::repository::crypto::keys::KeyIdentifier;
use rpki::repository::manifest::{Manifest, ManifestContent, ManifestHash};
use rpki::repository::roa::{Roa, RouteOriginAttestation};
use rpki::repository::sigobj::SignedObject;
use rpki::repository::tal::{Tal, TalInfo, TalUri};
use rpki::repository::x509::{Time, Validity, ValidationError};
use rpki::uri;
use crate::{collector, store};
use crate::collector::Collector;
use crate::config::{Config, FilterPolicy};
use crate::error::Failed;
use crate::metrics::{
    Metrics, PublicationMetrics, RepositoryMetrics, TalMetrics
};
use crate::payload::ValidationReport;
use crate::store::{Store, StoredManifest};
use crate::utils::str_from_ascii;


//------------ Configuration -------------------------------------------------

/// The minimum number of manifest entries that triggers CRL serial caching.
///
/// The value has been determined experimentally with the RPKI repository at
/// a certain state so may or may not be a good one, really.
const CRL_CACHE_LIMIT: usize = 50;


//------------ Engine --------------------------------------------------------

/// The mechanism to update and process RPKI data.
///
/// A validation value can be created from the configuration via
/// [`Engine::new`]. If you don’t actually want to perform a validation run
/// but just initialize everything, [`Engine::init`] will suffice.
///
/// When created, the set of TALs is loaded and kept around. It will only be
/// refreshed explicitly through the [`reload_tals`][Self::reload_tals]
/// method.
///
/// Before starting the very first validation run, you need to call
/// [`ignite`][Self::ignite] at least once. As this may spawn threads, this
/// must happen after a possible fork.
///
/// A run is started via the [`start`][Self::start] method, providing a
/// processor that handles valid data. The method returns a [Run] value that
/// drives the validation run. For route origin validation, a shortcut is
/// available through [`process_origins`][Self::process_origins].
///
/// Finally, the method [`cleanup`][Self::cleanup] can be used to perform
/// cleanup on both the store and collector owned by the validation.
#[derive(Debug)]
pub struct Engine {
    /// The directory to load TALs from.
    tal_dir: PathBuf,

    /// A mapping of TAL file names to TAL labels.
    tal_labels: HashMap<String, String>,

    /// The list of our TALs. 
    tals: Vec<Tal>,

    /// The sled database.
    db: sled::Db,

    /// The collector to load updated data from.
    collector: Collector,

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

impl Engine {
    /// Attempts to create the sled database under the given cache dir.
    ///
    /// NB: The database will be opened below the given directory. I,e., the
    /// provided path is `cache_dir` from the
    /// [`Config`][crate::config::Config].
    fn open_db(cache_dir: &Path, fresh: bool) -> Result<sled::Db, Failed> {
        if let Err(err) = fs::read_dir(cache_dir) {
            if err.kind() == io::ErrorKind::NotFound {
                error!(
                    "Missing repository directory {}.\n\
                     You may have to initialize it via \
                     \'routinator init\'.",
                     cache_dir.display()
                );
            }
            else {
                error!(
                    "Failed to open repository directory {}: {}",
                    cache_dir.display(), err
                );
            }
            return Err(Failed)
        }

        let db_path = cache_dir.join("store");

        if fresh {
            if let Err(err) = fs::remove_dir_all(&db_path) {
                if err.kind() != io::ErrorKind::NotFound {
                    error!(
                        "Failed to delete store database at {}: {}",
                        db_path.display(), err
                    );
                    return Err(Failed)
                }
            }
        }

        sled::open(&db_path).map_err(|err| {
            error!(
                "Failed to open store database at {}: {}",
                db_path.display(),
                err
            );
            Failed
        })
    }

    /// Initializes the engine without creating a value.
    ///
    /// This ensures that the TAL directory is present and logs a hint how
    /// to achieve that if not.
    ///
    /// The function is called implicitly by [`new`][Self::new].
    pub fn init(config: &Config) -> Result<(), Failed> {
        Collector::init(config)?;
        Self::open_db(&config.cache_dir, config.fresh).map(|_| ())
    }

    /// Creates a new engine.
    ///
    /// Takes all necessary information from `config`.
    /// It also takes over the provided cache and store for use during
    /// validation.
    ///
    /// Loads the initial set of TALs and errors out if that fails.
    pub fn new(
        config: &Config,
        update: bool,
    ) -> Result<Self, Failed> {
        let db = Self::open_db(&config.cache_dir, config.fresh)?;
        let collector = Collector::new(config, &db, update)?;
        let store = Store::new(db.clone());
        let mut res = Engine {
            tal_dir: config.tal_dir.clone(),
            tal_labels: config.tal_labels.clone(),
            tals: Vec::new(),
            db,
            collector,
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

    /// Reloads the set of TALs.
    ///
    /// Assumes that all regular files with an extension of `tal` in the
    /// TAL directory specified during object creation are TAL files and
    /// tries to load and decode them. Fails if that fails for at least one
    /// of those files.
    ///
    /// It is not considered an error if there are no TAL files in the TAL
    /// directory. However, a warning will be logged in this case.
    pub fn reload_tals(&mut self) -> Result<(), Failed> {
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
                return Err(Failed)
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
                    return Err(Failed)
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
                    return Err(Failed)
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
                    return Err(Failed)
                }
            };
            tal.prefer_https();
            res.push(tal);
        }
        if res.is_empty() {
            warn!(
                "No TALs found in TAL directory. Starting anyway."
            );
        }
        self.tals = res;
        Ok(())
    }

    /// Converts a path into a TAL label.
    ///
    /// This will be an explicitly configured TAL label if the file name
    /// portion of the path is registered in `self.tal_labels` or the file
    /// name without the `tal` extension otherwise.
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
    /// This spawns threads and therefore needs to be done after a
    /// possible fork.
    pub fn ignite(&mut self) -> Result<(), Failed> {
        self.collector.ignite()
    }

    /// Starts a validation run.
    ///
    /// During the run, `processor` will be responsible for dealing with
    /// valid objects. It must implement the [`ProcessRun`] trait.
    ///
    /// The method returns a [`Run`] that drives the validation run.
    pub fn start<P: ProcessRun>(
        &self, processor: P
    ) -> Result<Run<P>, Failed> {
        Ok(Run::new(
            self, self.collector.start(), self.store.start(), processor
        ))
    }

    /// Performs a route origin validation run.
    ///
    /// Returns the result of the run and the run’s metrics.
    pub fn process_origins(
        &self
    ) -> Result<(ValidationReport, Metrics), Failed> {
        let report = ValidationReport::new();
        let mut run = self.start(&report)?;
        run.process()?;
        let metrics = run.done();
        Ok((report, metrics))
    }

    /// Cleans the collector and store owned by the engine.
    pub fn cleanup(&self) -> Result<(), Failed> {
        self.store.cleanup(self.collector.cleanup())
    }

    /// Dumps the content of the collector and store owned by the engine.
    pub fn dump(&self, dir: &Path) -> Result<(), Failed> {
        self.store.dump(dir)?;
        self.collector.dump(dir)?;
        Ok(())
    }
}


//------------ Run -----------------------------------------------------------

/// A single validation run.
///
/// The runner is generic over the processor of valid data which must
/// implement the [`ProcessRun`] trait. The actual run is triggered by the
/// [`process`][Self::process] method. Upon completion, metrics of the run
/// can be extracted through [`done`][Self::done].
pub struct Run<'a, P> {
    /// A reference to the underlying validation.
    validation: &'a Engine,

    /// The runner for the collector.
    collector: collector::Run<'a>,

    /// The runner for the store.
    store: store::Run<'a>,

    /// The processor for valid data.
    processor: P,

    /// The metrics collected during the run.
    metrics: Metrics,
}

impl<'a, P> Run<'a, P> {
    /// Creates a new runner from all the parts.
    fn new(
        validation: &'a Engine,
        collector: collector::Run<'a>,
        store: store::Run<'a>,
        processor: P,
    ) -> Self {
        Run {
            validation, collector, store, processor,
            metrics: Default::default()
        }
    }

    /// Finishes the validation run and returns the metrics.
    ///
    /// If you are not interested in the metrics, you can simple drop the
    /// value, instead.
    pub fn done(self) -> Metrics {
        let mut metrics = self.metrics;
        self.collector.done(&mut metrics);
        self.store.done(&mut metrics);
        metrics
    }
}

impl<'a, P: ProcessRun> Run<'a, P> {
    /// Performs the validation run.
    pub fn process(&mut self) -> Result<(), Failed> {
        // If we don’t have any TALs, we ain’t got nothing to do.
        if self.validation.tals.is_empty() {
            return Ok(())
        }

        // Initialize our task queue with all the TALs.
        let metrics = RunMetrics::default();
        let tasks = SegQueue::new();
        for (index, tal) in self.validation.tals.iter().enumerate() {
            tasks.push(Task::Tal(TalTask { tal, index }));
            self.metrics.tals.push(TalMetrics::new(tal.info().clone()));
        }

        // And off we trot.

        // Keep a flag to cancel everything if something goes wrong.
        let had_err = AtomicBool::new(false);
        let thread_metrics = ArrayQueue::new(
            self.validation.validation_threads
        );
        let res = thread::scope(|scope| {
            for _ in 0 .. self.validation.validation_threads {
                scope.spawn(|_| {
                    let mut metrics = metrics.fork();
                    while let Some(task) = tasks.pop() {
                        if self.process_task(
                            task, &tasks, &mut metrics, &had_err,
                        ).is_err() {
                            break;
                        }
                    }
                    thread_metrics.push(metrics).unwrap();
                });
            }
        });

        if res.is_err() {
            // One of the workers has panicked. Well gosh darn.
            error!(
                "Engine failed after a worker thread has panicked. \
                 This is most assuredly a bug."
            );
            return Err(Failed);
        }

        if had_err.load(Ordering::Relaxed) {
            return Err(Failed);
        }

        metrics.prepare_final(&mut self.metrics);
        while let Some(metrics) = thread_metrics.pop() {
            metrics.collapse(&mut self.metrics);
        }

        Ok(())
    }

    /// Process a task. Any task.
    fn process_task(
        &self,
        task: Task<P::PubPoint>,
        tasks: &SegQueue<Task<P::PubPoint>>,
        metrics: &mut RunMetrics,
        had_err: &AtomicBool,
    ) -> Result<(), Failed> {
        match task {
            Task::Tal(task) => {
                self.process_tal_task(task, tasks, metrics, had_err)
            }
            Task::Ca(task) => {
                self.process_ca_task(task, tasks, metrics, had_err)
            }
        }
    }

    /// Processes a trust anchor.
    fn process_tal_task(
        &self, task: TalTask,
        tasks: &SegQueue<Task<P::PubPoint>>,
        metrics: &mut RunMetrics,
        had_err: &AtomicBool,
    ) -> Result<(), Failed> {
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

            match self.processor.process_ta(
                task.tal, uri, &cert, cert.tal
            )? {
                Some(processor) => {
                    return self.process_ca_task(
                        CaTask {
                            cert, processor,
                            repository_index: None,
                            defer: false,
                        },
                        tasks, metrics, had_err
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
    ) -> Result<Option<Cert>, Failed> {
        // Get the new version, store and return it if it decodes.
        if let Some(bytes) = self.collector.load_ta(uri) {
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
        task: CaTask<P::PubPoint>,
        tasks: &SegQueue<Task<P::PubPoint>>,
        metrics: &mut RunMetrics,
        had_err: &AtomicBool,
    ) -> Result<(), Failed> {
        let more_tasks = PubPoint::new(
            self, &task.cert, task.processor, task.repository_index,
        ).and_then(|point| {
            point.process(metrics)
        }).map_err(|_| {
            had_err.store(true, Ordering::Relaxed);
            Failed
        })?;
        for task in more_tasks {
            if had_err.load(Ordering::Relaxed) {
                return Err(Failed)
            }
            if task.defer {
                tasks.push(Task::Ca(task))
            }
            else {
                self.process_ca_task(task, tasks, metrics, had_err)?;
            }
        }
        Ok(())
    }
}


//------------ PubPoint ------------------------------------------------------

/// Validation of a single publication point.
struct PubPoint<'a, P: ProcessRun> {
    /// A reference to the runner.
    run: &'a Run<'a, P>,

    /// A reference to the CA certificate of the publication point.
    cert: &'a Arc<CaCert>,

    /// The processor for valid data at this publication point.
    processor: P::PubPoint,

    /// The point’s repository in the collector if available.
    collector: Option<collector::Repository<'a>>,

    /// The point’s repository in the store.
    store: store::Repository,

    /// The index of this point’s repository in the run’s metrics.
    repository_index: Option<usize>,

    /// The publication metrics for this publication point.
    metrics: PublicationMetrics,
}

impl<'a, P: ProcessRun> PubPoint<'a, P> {
    /// Creates a new publication point validator based on a CA certificate.
    pub fn new(
        run: &'a Run<'a, P>,
        cert: &'a Arc<CaCert>,
        processor: P::PubPoint,
        repository_index: Option<usize>,
    ) -> Result<Self, Failed> {
        let collector = run.collector.repository(cert)?;
        let store = run.store.repository(cert)?;
        Ok(PubPoint {
            run, cert, processor, collector, store,
            repository_index,
            metrics: Default::default(),
        })
    }

    /// Performs validation of the publication point.
    ///
    /// Upon success, returns a list of all the child CAs of this publication
    /// point as CA processing tasks.
    pub fn process(
        mut self,
        metrics: &mut RunMetrics,
    ) -> Result<Vec<CaTask<P::PubPoint>>, Failed> {
        let manifest = match self.update_stored()? {
            PointManifest::Valid(manifest) => {
                self.metrics.valid_manifests += 1;
                self.metrics.valid_crls += 1;
                manifest
            }
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
                self.metrics.missing_manifests += 1;
                return Ok(Vec::new())
            }
        };

        ValidPubPoint::new(self, manifest).process(metrics)
    }

    /// Tries to update the stored data for the publication point.
    ///
    /// Tries to fetch the updated manifest from the collector. If it differs
    /// from the stored manifest, updates the stored manifest and objects if
    /// the manifest is valid and all the objects are present and match their
    /// hashes.
    ///
    /// Depending on how far it gets, returns either a validated or raw
    /// manifest or that the publication point can’t be found at all.
    // Clippy false positive: We are using HashSet<Bytes> here -- Bytes is
    // not a mutable type.
    #[allow(clippy::mutable_key_type)]
    fn update_stored(&self) -> Result<PointManifest, Failed> {
        // If we don’t have a collector, we just use the stored publication
        // point.
        let collector = match self.collector {
            Some(ref collector) => collector,
            None => {
                return self.store.load_manifest(
                    self.cert.rpki_manifest()
                ).map(Into::into)
            }
        };

        // Try to load the manifest both from store and collector.
        let collected = collector.load_object(self.cert.rpki_manifest())?;
        let stored = self.store.load_manifest(self.cert.rpki_manifest())?;

        // If the manifest is not in the collector, we can abort already.
        let collected = match collected {
            Some(mft) => mft,
            None => return Ok(stored.into())
        };

        // If the stored and collected manifests are the same, nothing has
        // changed and we can abort the update. However, we need to check that
        // the stored manifest refers to the same CA repository URI, just to
        // be sure.
        let same = if let Some(mft) = stored.as_ref() {
            mft.manifest() == &collected
                && mft.ca_repository() == self.cert.ca_repository()
        }
        else {
            false
        };
        if same {
            return Ok(stored.into())
        }

        // Validate the collected manifest.
        let collected = match self.validate_collected_manifest(
            collected, collector
        )? {
            Some(collected) => collected,
            None => {
                return Ok(stored.into())
            }
        };

        // The manifest is fine. Now we can update the store. We do this in a
        // transaction and rollback if anything is wrong.
        let files = self.store.update_point(
            self.cert.rpki_manifest(),

            |update| {
                // Store all files on the collected manifest. Abort if they
                // can’t be loaded or if their hash doesn’t match.
                //
                // We also stick all file names into a set so we can delete
                // everything that isn’t on the manifest.
                let mut files = HashSet::new();
                for item in collected.content.iter() {
                    let file = match str_from_ascii(item.file()) {
                        Ok(file) => file,
                        Err(_) => {
                            warn!("{}: illegal file name '{}'.",
                                self.cert.rpki_manifest(),
                                String::from_utf8_lossy(item.file())
                            );
                            return Err(store::UpdateError::abort())
                        }
                    };
                    let uri = self.cert.ca_repository().join(
                        file.as_ref()
                    ).unwrap();

                    let hash = ManifestHash::new(
                        item.hash().clone(), collected.content.file_hash_alg()
                    );

                    let content = match collector.load_object(&uri)? {
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
                        file,
                        &store::StoredObject::new(content, Some(hash))
                    );

                    files.insert(item.file().clone());
                }

                update.update_manifest(
                    store::StoredManifest::new(
                        self.cert.cert.validity().not_after(),
                        self.cert.ca_repository().clone(),
                        collected.manifest_bytes.clone(),
                        collected.crl_bytes.clone(),
                    )
                );
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
                    return Err(Failed)
                }
            }
        };

        // Delete everything in the store that is not in files.
        self.store.retain_objects(
            self.cert.rpki_manifest(),
            |file| files.contains(file.as_bytes())
        )?;

        Ok(collected.into())
    }

    /// Tries to validate a manifest acquired from the collector.
    ///
    /// Checks that the manifest is correct itself and has been signed by the
    /// publication point’s CA. Tries to load the associated CRL from the
    /// collector, validates that against the CA and checks that the manifest
    /// has not been revoked.
    fn validate_collected_manifest(
        &self,
        manifest_bytes: Bytes,
        repository: &collector::Repository,
    ) -> Result<Option<ValidPointManifest>, Failed> {
        let manifest = match Manifest::decode(
            manifest_bytes.clone(), self.run.validation.strict
        ) {
            Ok(manifest) => manifest,
            Err(_) => {
                warn!("{}: failed to decode", self.cert.rpki_manifest());
                return Ok(None)
            }
        };
        let (ee_cert, content) = match manifest.validate(
            self.cert.cert(), self.run.validation.strict
        ) {
            Ok(some) => some,
            Err(_) => {
                warn!("{}: failed to validate", self.cert.rpki_manifest());
                return Ok(None)
            }
        };
        if content.is_stale() {
            //self.metrics.inc_stale_count();
            match self.run.validation.stale {
                FilterPolicy::Reject => {
                    warn!("{}: stale manifest", self.cert.rpki_manifest());
                    return Ok(None)
                }
                FilterPolicy::Warn => {
                    warn!("{}: stale manifest", self.cert.rpki_manifest());
                }
                FilterPolicy::Accept => { }
            }
        }

        let (crl_uri, crl, crl_bytes) = match self.validate_collected_crl(
            &ee_cert, &content, repository
        )? {
            Some(some) => some,
            None => return Ok(None)
        };

        Ok(Some(ValidPointManifest {
            ee_cert, content, crl_uri, crl, manifest_bytes, crl_bytes
        }))
    }

    /// Check the manifest CRL.
    ///
    /// Checks that there is exactly one CRL on the manifest, that it matches
    /// the CRL mentioned in the manifest’s EE certificate, that it matches
    /// its manifest hash, that it is a valid CRL for the CA, and that it does
    /// not revoke the manifest’s EE certificate.
    ///
    /// If all that is true, returns the decoded CRL.
    fn validate_collected_crl(
        &self,
        ee_cert: &ResourceCert,
        manifest: &ManifestContent,
        repository: &collector::Repository
    ) -> Result<Option<(uri::Rsync, Crl, Bytes)>, Failed> {
        // Let’s first get the manifest CRL’s name relative to repo_uri. If
        // it ain’t relative at all, this is already invalid.
        let crl_uri = match ee_cert.crl_uri() {
            // RFC 6481: MUST end in .crl.
            Some(some) if some.ends_with(".crl") => some.clone(),
            _ => {
                warn!("{}: invalid CRL URI.", self.cert.rpki_manifest());
                return Ok(None)
            }
        };
        let crl_name = match crl_uri.relative_to(&self.cert.ca_repository()) {
            Some(name) => name,
            None => {
                warn!(
                    "{}: CRL URI outside repository directory.",
                    self.cert.rpki_manifest()
                );
                return Ok(None)
            }
        };

        // Now we go over the manifest and try to find an entry matching
        // crl_name.
        let mut crl_bytes = None;
        for item in manifest.iter() {
            let (file, hash) = item.into_pair();
            if file == crl_name {
                let bytes = match repository.load_object(&crl_uri)? {
                    Some(bytes) => bytes,
                    None => {
                        warn!("{}: failed to load.", crl_uri);
                        return Ok(None)
                    }
                };
                let hash = ManifestHash::new(hash, manifest.file_hash_alg());
                if hash.verify(&bytes).is_err() {
                    warn!("{}: file has wrong hash.", crl_uri);
                    return Ok(None)
                }
                crl_bytes = Some(bytes);
            }
            else if file.ends_with(b".crl") {
                warn!(
                    "{}: manifest contains unexpected CRLs.",
                    self.cert.rpki_manifest()
                );
                return Ok(None)
            }
        }
        let crl_bytes = match crl_bytes {
            Some(some) => some,
            None => {
                warn!(
                    "{}: CRL not listed on manifest.",
                    self.cert.rpki_manifest()
                );
                return Ok(None)
            }
        };

        // Decode and validate the CRL.
        let mut crl = match Crl::decode(crl_bytes.clone()) {
            Ok(crl) => crl,
            Err(_) => {
                warn!("{}: failed to decode.", crl_uri);
                return Ok(None)
            }
        };
        if crl.validate(self.cert.cert().subject_public_key_info()).is_err() {
            warn!("{}: failed to validate.", crl_uri);
            return Ok(None)
        }
        if crl.is_stale() {
            //self.metrics.inc_stale_count();
            match self.run.validation.stale {
                FilterPolicy::Reject => {
                    warn!("{}: stale CRL.", crl_uri);
                    return Ok(None)
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
            return Ok(None)
        }

        // Phew: All good.
        Ok(Some((crl_uri, crl, crl_bytes)))
    }

    /// Tries to validate a stored manifest.
    ///
    /// This is similar to
    /// [`validate_collecteded_manifest`][Self::validate_collected_manifest]
    /// but has less hassle with the CRL because that is actually included in
    /// the stored manifest.
    fn validate_stored_manifest(
        &mut self,
        stored_manifest: StoredManifest,
    ) -> Result<ValidPointManifest, ValidationError> {
        // Decode and validate the manifest.
        let manifest = match Manifest::decode(
            stored_manifest.manifest().clone(), self.run.validation.strict
        ) {
            Ok(manifest) => manifest,
            Err(_) => {
                warn!("{}: failed to decode", self.cert.rpki_manifest());
                self.metrics.invalid_manifests += 1;
                return Err(ValidationError);
            }
        };
        let (ee_cert, content) = match manifest.validate(
            self.cert.cert(), self.run.validation.strict
        ) {
            Ok(some) => some,
            Err(_) => {
                warn!("{}: failed to validate", self.cert.rpki_manifest());
                self.metrics.invalid_manifests += 1;
                return Err(ValidationError);
            }
        };
        if content.is_stale() {
            self.metrics.stale_manifests += 1;
            match self.run.validation.stale {
                FilterPolicy::Reject => {
                    warn!("{}: stale manifest", self.cert.rpki_manifest());
                    self.metrics.invalid_manifests += 1;
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
                self.metrics.invalid_manifests += 1;
                return Err(ValidationError)
            }
        };

        // Decode and validate the CRL.
        let mut crl = match Crl::decode(stored_manifest.crl().clone()) {
            Ok(crl) => crl,
            Err(_) => {
                warn!("{}: failed to decode.", crl_uri);
                self.metrics.invalid_manifests += 1;
                self.metrics.invalid_crls += 1;
                return Err(ValidationError)
            }
        };
        if crl.validate(self.cert.cert().subject_public_key_info()).is_err() {
            warn!("{}: failed to validate.", crl_uri);
            self.metrics.invalid_manifests += 1;
            self.metrics.invalid_crls += 1;
            return Err(ValidationError)
        }
        if crl.is_stale() {
            self.metrics.stale_crls += 1;
            match self.run.validation.stale {
                FilterPolicy::Reject => {
                    warn!("{}: stale CRL.", crl_uri);
                    self.metrics.invalid_manifests += 1;
                    self.metrics.invalid_crls += 1;
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
            self.metrics.invalid_manifests += 1;
            return Err(ValidationError)
        }

        self.metrics.valid_manifests += 1;
        self.metrics.valid_crls += 1;
        Ok(ValidPointManifest {
            ee_cert, content, crl_uri, crl,
            manifest_bytes: stored_manifest.manifest().clone(),
            crl_bytes: stored_manifest.crl().clone()
        })
    }
}


//------------ ValidPubPoint -------------------------------------------------

/// Processing of a publication point that is known to be valid.
struct ValidPubPoint<'a, P: ProcessRun> {
    /// A reference to the publication point.
    point: PubPoint<'a, P>,

    /// The valid manifest of the point.
    manifest: ValidPointManifest,

    /// The list of child CA processing tasks we want to return eventually.
    child_cas: Vec<CaTask<P::PubPoint>>,
}

impl<'a, P: ProcessRun> ValidPubPoint<'a, P> {
    /// Creates a new valid publication point from point and manifest.
    pub fn new(point: PubPoint<'a, P>, manifest: ValidPointManifest) -> Self {
        ValidPubPoint {
            point, manifest,
            child_cas: Vec::new()
        }
    }

    /// Processes the point returning the child CAs.
    pub fn process(
        mut self,
        metrics: &mut RunMetrics,
    ) -> Result<Vec<CaTask<P::PubPoint>>, Failed> {
        let repository_index = match self.point.repository_index {
            Some(index) => index,
            None => {
                let index = metrics.repository_index(
                    self.point.cert, self.point.store.is_rrdp()
                );
                self.point.repository_index = Some(index);
                index
            }
        };
        self.point.processor.repository_index(repository_index);
        if self._process()? {
            metrics.apply(
                &self.point.metrics, repository_index, self.point.cert.tal
            );
            self.point.processor.commit();
            Ok(self.child_cas)
        }
        else {
            self.point.processor.cancel(&self.point.cert);
            Ok(Vec::new())
        }
    }

    /// Processes the point returning whether the point was accepted.
    ///
    /// If the processor votes to abort processing of the entire point, this
    /// will return `Ok(false)`.
    pub fn _process(
        &mut self,
    ) -> Result<bool, Failed> {
        for item in self.manifest.content.iter() {
            let (file, hash) = item.into_pair();
            let file = match str_from_ascii(&file) {
                Ok(file) => file,
                Err(_) => {
                    warn!(
                        "{}: illegal file name {} in manifest.",
                        self.point.cert.rpki_manifest(),
                        String::from_utf8_lossy(&file)
                    );
                    return Ok(false)
                }
            };
            let uri = match self.point.cert.ca_repository().join(
                file.as_ref()
            ) {
                Ok(uri) => uri,
                Err(_) => {
                    warn!(
                        "{}: illegal file name {} in manifest.",
                        self.point.cert.rpki_manifest(),
                        file
                    );
                    return Ok(false)
                }
            };
            let hash = ManifestHash::new(
                hash, self.manifest.content.file_hash_alg()
            );
            if !self.process_object(uri, file, hash)? {
                return Ok(false)
            }
        }

        Ok(true)
    }

    /// Processes a single object.
    ///
    /// Returns whether processing should continue or whether the entire (!)
    /// publication point should be disregarded.
    fn process_object(
        &mut self,
        uri: uri::Rsync, file: &str, hash: ManifestHash,
    ) -> Result<bool, Failed> {
        let object = match self.point.store.load_object(
            self.point.cert.rpki_manifest(), file
        )? {
            Some(bytes) => bytes,
            None => {
                warn!("{}: failed to load.", uri);
                return Ok(false)
            }
        };

        // This shouldn’t actually happen?
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
            if uri != self.manifest.crl_uri {
                warn!("{}: stray CRL.", uri);
                self.point.metrics.stray_crls += 1;
            }
        }
        else if uri.ends_with(".gbr") {
            self.process_gbr(uri, object)?;
        }
        else {
            self.point.metrics.others += 1;
            warn!("{}: unknown object type.", uri);
        }
        Ok(true)
    }

    /// Processes a certificate object.
    fn process_cer(
        &mut self, uri: uri::Rsync, object: store::StoredObject,
    ) -> Result<(), Failed> {
        let cert = match Cert::decode(object.into_content()) {
            Ok(cert) => cert,
            Err(_) => {
                warn!("{}: failed to decode.", uri);
                self.point.metrics.invalid_certs += 1;
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
    ) -> Result<(), Failed> {
        if self.point.cert.check_loop(&cert).is_err() {
            warn!("{}: certificate loop detected.", uri);
            self.point.metrics.invalid_certs += 1;
            return Ok(())
        }
        let cert = match cert.validate_ca(
            self.point.cert.cert(), self.point.run.validation.strict
        ) {
            Ok(cert) => cert,
            Err(_) => {
                warn!("{}: CA certificate failed to validate.", uri);
                self.point.metrics.invalid_certs += 1;
                return Ok(())
            }
        };
        if self.check_crl(&uri, &cert).is_err() {
            self.point.metrics.invalid_certs += 1;
            return Ok(())
        }

        let cert = match CaCert::chain(
            &self.point.cert, uri.clone(), cert
        ) {
            Ok(cert) => cert,
            Err(_) => {
                self.point.metrics.invalid_certs += 1;
                return Ok(())
            }
        };

        self.point.metrics.valid_ca_certs += 1;

        let mut processor = match self.point.processor.process_ca(
            &uri, &cert
        )? {
            Some(processor) => processor,
            None => return Ok(())
        };
        processor.update_refresh(cert.cert.validity().not_after());

        // Defer operation if we need to update the repository part where
        // the CA lives.
        let defer = !self.point.run.collector.was_updated(&cert);

        // If we switch repositories, we need to apply our metrics.
        let repository_index = if cert.repository_switch() {
            None
        }
        else {
            self.point.repository_index
        };

        self.child_cas.push(CaTask {
            cert, processor, repository_index, defer
        });
        Ok(())
    }

    /// Processes an EE certificate.
    fn process_ee_cer(
        &mut self, uri: uri::Rsync, cert: Cert,
    ) -> Result<(), Failed> {
        if cert.validate_router(
            &self.point.cert.cert, self.point.run.validation.strict
        ).is_err() {
            warn!("{}: router certificate failed to validate.", uri);
            self.point.metrics.invalid_certs += 1;
            return Ok(())
        };
        if self.check_crl(&uri, &cert).is_err() {
            self.point.metrics.invalid_certs += 1;
            return Ok(())
        }
        self.point.metrics.valid_ee_certs += 1;
        self.point.processor.process_ee_cert(&uri, cert)?;
        Ok(())
    }

    /// Processes a ROA object.
    fn process_roa(
        &mut self, uri: uri::Rsync, object: store::StoredObject,
    ) -> Result<(), Failed> {
        let roa = match Roa::decode(
            object.into_content(), self.point.run.validation.strict
        ) {
            Ok(roa) => roa,
            Err(_) => {
                warn!("{}: decoding failed.", uri);
                self.point.metrics.invalid_roas += 1;
                return Ok(())
            }
        };
        match roa.process(
            &self.point.cert.cert,
            self.point.run.validation.strict,
            |cert| self.check_crl(&uri, &cert)
        ) {
            Ok((cert, route)) => {
                self.point.metrics.valid_roas += 1;
                self.point.processor.process_roa(&uri, cert, route)?
            }
            Err(_) => {
                self.point.metrics.invalid_roas += 1;
                warn!("{}: validation failed.", uri)
            }
        }
        Ok(())
    }

    /// Processes a Ghostbuster Record.
    fn process_gbr(
        &mut self, uri: uri::Rsync, object: store::StoredObject,
    ) -> Result<(), Failed> {
        let obj = match SignedObject::decode(
            object.into_content(), self.point.run.validation.strict
        ) {
            Ok(obj) => obj,
            Err(_) => {
                warn!("{}: decoding failed.", uri);
                self.point.metrics.invalid_gbrs += 1;
                return Ok(())
            }
        };
        match obj.process(
            &self.point.cert.cert,
            self.point.run.validation.strict,
            |cert| self.check_crl(&uri, &cert)
        ) {
            Ok((cert, content)) => {
                self.point.metrics.valid_gbrs += 1;
                self.point.processor.process_gbr(&uri, cert, content)?
            }
            Err(_) => {
                self.point.metrics.invalid_gbrs += 1;
                warn!("{}: validation failed.", uri)
            }
        }
        Ok(())
    }

    /// Checks whether `cert` has been revoked.
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
    /// The task is to process a trust anchor locator.
    Tal(TalTask<'a>),

    /// The task is to process a CA.
    Ca(CaTask<P>),
}

impl<'a, P> fmt::Debug for Task<'a, P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Task::Tal(ref inner) => {
                write!(f, "TalTask {{ tal: {} }}", inner.tal.info().name())
            }
            Task::Ca(ref inner) => {
                write!(
                    f, "CaTask {{ ca_repository: {} }}",
                    inner.cert.ca_repository
                )
            }
        }
    }
}


//------------ TalTask ------------------------------------------------------

/// A task for processing a single trust anchor locator.
struct TalTask<'a> {
    /// A reference to the actual TAL.
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

    /// The repository index of we know it already.
    repository_index: Option<usize>,

    /// Defer processing?
    ///
    /// Processing is deferred if the CA lives in a different repository than
    /// its issuing CA:
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
    /// This will be `None` for a trust anchor certificate.
    parent: Option<Arc<CaCert>>,

    /// The index of the TAL in the metrics.
    tal: usize,

    /// The combined validity of the certificate.
    ///
    /// This is derived from the validity of all the parents and the
    /// certificate itself.
    combined_validity: Validity,
}

impl CaCert {
    /// Creates a new CA cert for a trust anchor.
    pub fn root(
        cert: ResourceCert, uri: TalUri, tal: usize
    ) -> Result<Arc<Self>, Failed> {
        Self::new(cert, uri, None, tal)
    }

    /// Creates a new CA cert for an issued CA.
    pub fn chain(
        issuer: &Arc<Self>,
        uri: uri::Rsync,
        cert: ResourceCert
    ) -> Result<Arc<Self>, Failed> {
        Self::new(cert, TalUri::Rsync(uri), Some(issuer.clone()), issuer.tal)
    }

    /// Creates a new CA cert from its various parts.
    fn new(
        cert: ResourceCert,
        uri: TalUri, 
        parent: Option<Arc<Self>>,
        tal: usize,
    ) -> Result<Arc<Self>, Failed> {
        let combined_validity = match parent.as_ref() {
            Some(ca) => cert.validity().trim(ca.combined_validity()),
            None => cert.validity()
        };
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
                return Err(Failed)
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
                return Err(Failed)
            }
        };
        Ok(Arc::new(CaCert {
            cert, uri, ca_repository, rpki_manifest, parent, tal,
            combined_validity,
        }))
    }

    /// Checks whether a child cert has appeared in the chain already.
    pub fn check_loop(&self, cert: &Cert) -> Result<(), Failed> {
        self._check_loop(cert.subject_key_identifier())
    }

    /// The actual recursive loop test.
    ///
    /// We are comparing certificates by comparing their subject key
    /// identifiers.
    fn _check_loop(&self, key_id: KeyIdentifier) -> Result<(), Failed> {
        if self.cert.subject_key_identifier() == key_id {
            Err(Failed)
        }
        else if let Some(ref parent) = self.parent {
            parent._check_loop(key_id)
        }
        else {
            Ok(())
        }
    }

    /// Returns a reference to the resource certificate.
    pub fn cert(&self) -> &ResourceCert {
        &self.cert
    }

    /// Returns a reference the caRepository URI of the certificate.
    pub fn ca_repository(&self) -> &uri::Rsync {
        &self.ca_repository
    }

    /// Returns a reference to the rpkiManifest URI of the certificate.
    pub fn rpki_manifest(&self) -> &uri::Rsync {
        &self.rpki_manifest
    }

    /// Returns a reference to the rpkiNotify URI of the certificate.
    pub fn rpki_notify(&self) -> Option<&uri::Https> {
        self.cert.rpki_notify()
    }

    /// Returns the combined validaty of the whole CA.
    pub fn combined_validity(&self) -> Validity {
        self.combined_validity
    }

    /// Returns whether the CA is in a different repository from its parent.
    ///
    /// This is just a quick check and may report a switch when in fact there
    /// isn’t one.
    fn repository_switch(&self) -> bool {
        let parent = match self.parent.as_ref() {
            Some(parent) => parent,
            None => return true,
        };

        match self.rpki_notify() {
            Some(rpki_notify) => {
                Some(rpki_notify) != parent.rpki_notify()
            }
            None => {
                self.ca_repository.module() != parent.ca_repository.module()
            }
        }
    }
} 


//------------ PointManifest -------------------------------------------------

/// The various results of getting manifest from collector and store.
// XXX Clippy complains that ValidPointManifest is 1160 bytes. I _think_ this
//     is fine here as PointManifest is just a helper type to make things
//     easier and everything eventually turns into a ValidPointManifest, but
//     perhaps some restructuring might be good, anyway.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
enum PointManifest {
    /// The manifest has been loaded from store but has not been verified.
    Unverified(StoredManifest),

    /// The manifest has been loaded and has been validated.
    Valid(ValidPointManifest),

    /// The manifest has not been found anywhere.
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

/// All information from a validated manifest.
#[derive(Clone, Debug)]
struct ValidPointManifest {
    /// The EE certificate the manifest was signed with.
    ee_cert: ResourceCert,

    /// The payload of the manifest.
    content: ManifestContent,

    /// The CRL distribution point URI of the manifest.
    ///
    /// This is here separately because it may be `None` in a `ResourceCert`
    /// but can’t be in a valid CA cert.
    crl_uri: uri::Rsync,

    /// The CRL.
    crl: Crl,

    /// The raw bytes of the manifest.
    manifest_bytes: Bytes,

    /// The raw bytes of the CRL.
    crl_bytes: Bytes,
}


//------------ RunMetrics ----------------------------------------------------

/// The metrics collected during a engine run.
#[derive(Debug, Default)]
struct RunMetrics {
    /// The per-TAL metrics.
    tals: Vec<PublicationMetrics>,

    /// The per-repository metrics.
    repositories: Vec<PublicationMetrics>,

    /// The overall metrics.
    publication: PublicationMetrics,

    /// The indexes of repositories in the repository metrics vec.
    ///
    /// The key is the string representation of the rpkiNotify or rsync
    /// module URI.
    repository_indexes: Arc<Mutex<HashMap<String, usize>>>,
}

impl RunMetrics {
    /// Creates a new value that shares indexes with the current one.
    pub fn fork(&self) -> Self {
        RunMetrics {
            tals: Default::default(),
            repositories: Default::default(),
            publication: Default::default(),
            repository_indexes: self.repository_indexes.clone(),
        }
    }

    /// Returns the index of a repository in the metrics.
    ///
    /// Adds a new repository if necessary.
    pub fn repository_index(&self, cert: &CaCert, rrdp: bool) -> usize {
        let uri = cert.rpki_notify().and_then(|uri| {
            if rrdp {
                Some(Cow::Borrowed(uri.as_str()))
            }
            else {
                None
            }
        }).unwrap_or_else(|| cert.ca_repository.canonical_module());

        let mut repository_indexes = self.repository_indexes.lock().unwrap();
        if let Some(index) = repository_indexes.get(uri.as_ref()) {
            return *index
        }

        let index = repository_indexes.len();
        repository_indexes.insert(uri.into_owned(), index);
        index
    }

    /// Apply publication metrics.
    pub fn apply(
        &mut self, metrics: &PublicationMetrics,
        repository_index: usize, tal_index: usize
    ) {
        while self.repositories.len() <= repository_index {
            self.repositories.push(Default::default())
        }
        self.repositories[repository_index] += metrics;

        while self.tals.len() <= tal_index {
            self.tals.push(Default::default())
        }
        self.tals[tal_index] += metrics;

        self.publication += metrics;
    }

    /// Prepares the final metrics.
    pub fn prepare_final(&self, target: &mut Metrics) {
        let mut indexes: Vec<_>
            = self.repository_indexes.lock().unwrap().iter().map(|item| {
                (item.0.clone(), *item.1)
            }).collect();
        indexes.sort_by_key(|(_, idx)| *idx);
        target.repositories = indexes.into_iter().map(|(uri, _)| {
            RepositoryMetrics::new(uri)
        }).collect();
    }

    /// Collapse into the final metrics.
    ///
    /// Assumes that the target has been extended to fit all TALs and
    /// repositories.
    ///
    /// This only collapses the publication metrics since those are the ones
    /// collected by the engine.
    pub fn collapse(self, target: &mut Metrics) {
        for (target, metric) in target.tals.iter_mut().zip(
            self.tals.into_iter()
        ) {
            target.publication += metric
        }
        for (target, metric) in target.repositories.iter_mut().zip(
            self.repositories.into_iter()
        ) {
            target.publication += metric
        }
        target.publication += self.publication;
    }
}


//------------ ProcessRun ----------------------------------------------------

/// A type that can process the valid data from the RPKI.
pub trait ProcessRun: Send + Sync {
    /// The type processing the valid data of a single publication point.
    type PubPoint: ProcessPubPoint;

    /// Processes the given trust anchor.
    ///
    /// If the method wants the content of this trust anchor to be validated
    /// and processed, it returns a processor for it as some success value.
    /// If it rather wishes to skip this trust anchor, it returns `Ok(None)`.
    /// If it wishes to abort processing, it returns an error.
    ///
    /// The `tal_index` argument indicates the index of the TAL in the
    /// metrics produced by the processing run. Similarly, the
    /// `repository_index` argument refers to the index of the repository 
    /// publishing the trust anchor CA’s publication point in the metrics.
    fn process_ta(
        &self, tal: &Tal, uri: &TalUri, cert: &CaCert, tal_index: usize
    ) -> Result<Option<Self::PubPoint>, Failed>;
}


//------------ ProcessPubPoint -----------------------------------------------

/// A type that can process the valid data from an RPKI publication point.
pub trait ProcessPubPoint: Sized + Send + Sync {
    /// Sets the index of repository in the processing run metrics.
    fn repository_index(&mut self, repository_index: usize) {
        let _ = repository_index;
    }

    /// Updates the refresh time for this publication poont.
    fn update_refresh(&mut self, not_after: Time) {
        let _ = not_after;
    }

    /// Determines whether an object with the given URI should be processed.
    ///
    /// The object will only be processed if the method returns `Ok(true)`.
    /// If it returns `Ok(false)`, the object will be skipped quietly. If it
    /// returns an error, the entire processing run will be aborted.
    fn want(&self, uri: &uri::Rsync) -> Result<bool, Failed>;
   
    /// Process the content of a validated CA.
    ///
    /// The method can choose how to proceed. If it chooses to process the CA,
    /// it returns `Ok(Some(value))` with a new processor to be used for this
    /// CA. If it wishes to skip this CA, it returns `Ok(None)`. And if it
    /// wishes to abort processing, it returns an error.
    ///
    /// The `repository_index` argument indicates the index of the repository
    /// publishing the CA’s publication point in the metrics produced by the
    /// processing run.
    fn process_ca(
        &mut self, uri: &uri::Rsync, cert: &CaCert,
    ) -> Result<Option<Self>, Failed>;

    /// Process the content of a validated EE certificate.
    ///
    /// The method is given both the URI and the certificate. If it
    /// returns an error, the entire processing run will be aborted.
    fn process_ee_cert(
        &mut self, uri: &uri::Rsync, cert: Cert
    ) -> Result<(), Failed> {
        let _ = (uri, cert);
        Ok(())
    }
 
    /// Process the content of a validated ROA.
    ///
    /// The method is given both the URI and the content of the ROA. If it
    /// returns an error, the entire processing run will be aborted.
    fn process_roa(
        &mut self,
        uri: &uri::Rsync,
        cert: ResourceCert,
        route: RouteOriginAttestation
    ) -> Result<(), Failed> {
        let _ = (uri, cert, route);
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
        &mut self,
        uri: &uri::Rsync,
        cert: ResourceCert,
        content: Bytes
    ) -> Result<(), Failed> {
        let _ = (uri, cert, content);
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
    fn cancel(self, _cert: &CaCert) {
    }
}

