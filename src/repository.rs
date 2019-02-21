//! The local copy of the RPKI repository.
//!
//! This module contains [`Repository`] representing the local copy of the
//! RPKI repository. It knows how to update the content and also how to
//! process it into a list of address origins.
//!
//! [`Repository`]: struct.Repository.html

use std::{fs, io, process};
use std::fs::{DirEntry, File, create_dir_all};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Output};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;
use bytes::Bytes;
use futures::future;
use futures::{Future, IntoFuture};
use futures_cpupool::CpuPool;
use rpki::uri;
use rpki::cert::{Cert, ResourceCert};
use rpki::crl::{Crl, CrlStore};
use rpki::manifest::{Manifest, ManifestContent, ManifestHash};
use rpki::roa::Roa;
use rpki::tal::Tal;
use rpki::x509::ValidationError;
use tokio::timer::Timeout;
use tokio_process::CommandExt;
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
    /// The directory our local copy of the respository lives in.
    cache_dir: PathBuf, 

    /// The list of our TALs. 
    tals: Vec<Tal>,

    /// Should we be strict when decoding data?
    strict: bool,

    /// Should we keep extended information about ROAs?
    extra_output: bool,

    /// Number of rsync commands.
    rsync_threads: usize,

    /// Number of validation threads.
    validation_threads: usize,

    /// Information for running rsync.
    ///
    /// If this is `None`, we don’t rsync.
    rsync: Option<(Mutex<RsyncState>, RsyncCommand)>,
}

impl Repository {
    /// Creates a new repository.
    ///
    /// Takes all necessary information from `config`. If `rsync` is `false`,
    /// rsyncing is disabled.
    ///
    /// This function writes error messages to stderr.
    pub fn new(
        config: &Config,
        extra_output: bool,
        rsync: bool
    ) -> Result<Self, Error> {
        if let Err(err) = fs::read_dir(&config.cache_dir) {
            eprintln!(
                "Failed to open repository directory {}: {}",
                config.cache_dir.display(), err
            );
            return Err(Error)
        }

        Ok(Repository(Arc::new(RepoInner {
            cache_dir: config.cache_dir.clone(),
            tals: Self::load_tals(&config.tal_dir)?,
            strict: config.strict,
            extra_output,
            rsync_threads: config.rsync_count,
            validation_threads: config.validation_threads,
            rsync: if rsync {
                Some((
                    Mutex::new(RsyncState::new()),
                    RsyncCommand::detect(config)?
                ))
            }
            else {
                None
            },
        })))
    }

    /// Loads the TAL files from the given directory.
    fn load_tals(tal_dir: &Path) -> Result<Vec<Tal>, Error> {
        let mut res = Vec::new();
        let dir = match fs::read_dir(tal_dir) {
            Ok(dir) => dir,
            Err(err) => {
                error!("Failed to open TAL directory: {}", err);
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
            let path = entry.path();
            if !entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
                warn!("{}: garbage in TAL directory.", path.display());
                continue
            }
            let mut file = match File::open(&path) {
                Ok(file) => {
                    info!("Processing TAL {}", path.display());
                    file
                }
                Err(err) => {
                    error!(
                        "Failed to open TAL {}: {}. \
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
                        "Failed to read TAL {}: {}. \
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
    pub fn start(&self) {
        if let Some(ref rsync) = self.0.rsync {
            rsync.0.lock().unwrap().clear_seen();
        }
    }

    /// Asynchronously updates the content of the local repository.
    ///
    /// This goes over all the known repository publication points and runs
    /// rsync on them to update.
    ///
    /// The method logs all error messages.
    pub fn update_async(&self) -> impl Future<Item=(), Error=Error> {
        let repo = self.clone();
        let pool = CpuPool::new(self.0.rsync_threads);
        fs::read_dir(&self.0.cache_dir).map_err(|err| {
            error!(
                "Failed to read repository directory: {}",
                err
            );
            Error
        }).into_future()
        .and_then(|dir| {
            future::join_all(dir.map(move |entry| {
                let repo = repo.clone();
                let pool = pool.clone();
                entry.map_err(|err| {
                    error!(
                        "Failed to iterate over repository directory: {}",
                        err
                    );
                    Error
                }).into_future()
                .and_then(move |entry| {
                    pool.spawn(future::lazy(|| {
                        repo.update_host(entry);
                        Ok(())
                    }))
                })
            })).map(|_| ())
        })
    }

    /// Updates the content of the local repository.
    ///
    /// This is the synchronous version of `update_async`.
    pub fn update(&self) -> Result<(), Error> {
        self.update_async().wait()
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
    ) -> impl Future<Item=RouteOrigins, Error=Error> {
        let pool = CpuPool::new(self.0.validation_threads);
        let repo = self.clone();
        future::join_all((0..self.0.tals.len()).map(move |idx| {
            let repo = repo.clone();
            let pool = pool.clone();
            pool.spawn(future::lazy(move || repo.process_tal(idx)))
        })).and_then(|x| {
            let mut res = RouteOrigins::new();
            x.into_iter().for_each(|item| res.merge(item));
            Ok(res)
        })
    }

    /// Process the local repository and produce a list of route origins.
    ///
    /// This is the synchronous version of `process_async`.
    pub fn process(&self) -> Result<RouteOrigins, Error> {
        self.process_async().wait()
    }

    /// Loads the exceptions.
    pub fn load_exceptions(
        &self,
        config: &Config
    ) -> Result<LocalExceptions, Error> {
        config.load_exceptions(self.0.extra_output)
    }
}


/// # Repository Access
///
impl Repository {
    /// Loads a trust anchor certificate from the given URI.
    fn load_ta(
        &self,
        uri: &uri::Rsync
    ) -> Result<Option<Cert>, Error> {
        Ok(
            self.load_file(uri, true)
            .and_then(|bytes| Cert::decode(bytes).ok())
        )
    }

    /// Loads the content of a file from the given URI.
    ///
    /// If `create` is `true`, it will try to rsync missing files.
    ///
    /// If loading the file fails, logs a warning and returns `None`.
    fn load_file(
        &self,
        uri: &uri::Rsync,
        create: bool
    ) -> Option<Bytes> {
        match File::open(self.uri_to_path(uri)) {
            Ok(mut file) => {
                let mut data = Vec::new();
                if let Err(err) = file.read_to_end(&mut data) {
                    warn!(
                        "Failed to read file '{}': {}",
                        self.uri_to_path(uri).display(),
                        err
                    );
                    return None
                }
                Some(data.into())
            }
            Err(ref err) if err.kind() == io::ErrorKind::NotFound => {
                if create {
                    self.rsync_module(uri.module());
                    self.load_file(uri, false)
                }
                else {
                    info!("{}: not found in local repository", uri);
                    None
                }
            }
            Err(err) => {
                warn!(
                    "Failed to open file '{}': {}",
                    self.uri_to_path(uri).display(), err
                );
                None
            }
        }
    }

    /// Converts an rsync module URI into a path.
    fn module_to_path(&self, module: &uri::RsyncModule) -> PathBuf {
        let mut res = self.0.cache_dir.clone();
        res.push(module.authority());
        res.push(module.module());
        res
    }

    /// Converts an rsync URI into a path.
    fn uri_to_path(&self, uri: &uri::Rsync) -> PathBuf {
        let mut res = self.module_to_path(uri.module());
        res.push(uri.path());
        res
    }
}


/// # Updating
///
impl Repository {
    /// Updates content of the host-specific directory of the local copy.
    ///
    /// If something goes wrong, logs a message.
    fn update_host(self, entry: DirEntry) {
        if !entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
            return
        }
        match entry_to_uri_component(&entry) {
            Some(host) => self.update_module(host, entry.path()),
            None => {
                warn!(
                    "{}: illegal host directory. Skipping.",
                    entry.path().display()
                );
            }
        }
    }

    /// Updates content of the module-specific directory of the local copy.
    ///
    /// If something goes wrong, logs a message.
    fn update_module(&self, host: Bytes, path: PathBuf) {
        let dir = match fs::read_dir(&path) {
            Ok(dir) => dir,
            Err(err) => {
                warn!(
                    "Failed to read directory {}: {}.",
                    path.display(), err
                );
                return
            }
        };
        for entry in dir {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    warn!(
                        "Failed to iterate over directory {}: {}",
                        path.display(), err
                    );
                    // XXX Or continue?
                    return
                }
            };
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                warn!(
                    "{}: unexpected file. Skipping.",
                    entry.path().display()
                );
                continue
            }
            match entry_to_uri_component(&entry) {
                Some(module) => {
                    self.rsync_module(
                        &uri::RsyncModule::new(host.clone(), module)
                    )
                }
                None => {
                    warn!(
                        "{}: illegal module directory. Skipping",
                        entry.path().display()
                    )
                }
            }
        }
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
        let mut res = RouteOrigins::new();
        let tal = &self.0.tals[idx];
        for uri in tal.uris() {
            let cert = match self.load_ta(&uri) {
                Ok(Some(cert)) => cert,
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
    fn process_ca(
        &self,
        cert: ResourceCert,
        uri: &uri::Rsync,
        routes: &mut RouteOrigins
    ) {
        let mut store = CrlStore::new();
        let repo_uri = match cert.repository_uri() {
            Some(uri) => uri,
            None => {
                info!("CA cert {} has no repository URI. Ignoring.", uri);
                return
            }
        };
        let manifest = match self.get_manifest(&cert, uri, &mut store) {
            Some(manifest) => manifest,
            None => {
                info!("No valid manifest for CA {}. Ignoring.", uri);
                return
            }
        };

        for item in manifest.iter_uris(repo_uri) {
            let (uri, hash) = match item {
                Ok(item) => item,
                Err(_) => continue,
            };
            self.process_object(uri, hash, &cert, &mut store, routes);
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
            let bytes = match self.load_file(&uri, false) {
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
            if self.check_crl(&cert, issuer, crl).is_err() {
                info!("{}: certificate has been revoked", uri);
                return
            }
            self.process_ca(cert, &uri, routes)
        }
        else if uri.ends_with(".roa") {
            let bytes = match self.load_file(&uri, false) {
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
                self.check_crl(cert, issuer, crl)?;
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
    fn get_manifest(
        &self,
        issuer: &ResourceCert,
        issuer_uri: &uri::Rsync,
        store: &mut CrlStore,
    ) -> Option<ManifestContent> {
        for uri in issuer.manifest_uris() {
            let uri = match uri.into_rsync_uri() {
                Some(uri) => uri,
                None => {
                    continue
                }
            };
            let bytes = match self.load_file(&uri, true) {
                Some(bytes) => bytes,
                None => {
                    info!("{}: failed to load.", uri);
                    continue
                }
            };
            let manifest = match Manifest::decode(bytes, self.0.strict) {
                Ok(manifest) => manifest,
                Err(_) => {
                    info!("{}: failed to decode", uri);
                    continue
                }
            };
            let (cert, manifest) = match manifest.validate(issuer,
                                                           self.0.strict) {
                Ok(manifest) => manifest,
                Err(_) => {
                    info!("{}: failed to validate", uri);
                    continue
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
            if self.check_crl(cert, issuer, store).is_err() {
                info!("{}: certificate has been revoked", uri);
                continue
            }
            return Some(manifest)
        }
        info!("{}: No valid manifest found. Ignoring.", issuer_uri);
        None
    }

    /// Checks wheter a certificate is listen on its CRL.
    fn check_crl<C: AsRef<Cert>>(
        &self,
        cert: C,
        issuer: &ResourceCert,
        store: &mut CrlStore,
    ) -> Result<(), ValidationError> {
        let cert = cert.as_ref();
        let uri_list = match cert.crl_distribution() {
            Some(some) => some,
            None => return Ok(())
        };
        for uri in uri_list.iter() {
            let uri = match uri.into_rsync_uri() {
                Some(uri) => uri,
                None => continue
            };

            // If we already have that CRL, use it.
            if let Some(crl) = store.get(&uri) {
                if crl.contains(&cert.serial_number()) {
                    return Err(ValidationError)
                }
                else {
                    return Ok(())
                }
            }

            // Otherwise, try to load it, use it, and then store it.
            let bytes = match self.load_file(&uri, true) {
                Some(bytes) => bytes,
                _ => continue
            };
            let crl = match Crl::decode(bytes) {
                Ok(crl) => crl,
                Err(_) => continue
            };
            if crl.validate(issuer.as_ref().subject_public_key_info()).is_err() {
                continue
            }
            if crl.is_stale() {
                warn!("{}: stale CRL.", uri);
            }

            let revoked = crl.contains(&cert.serial_number());
            store.push(uri, crl);
            if revoked {
                return Err(ValidationError)
            }
            else {
                return Ok(())
            }
        }
        Err(ValidationError)
    }
}


/// # Rsyncing
///
impl Repository {
    #[allow(mutex_atomic)] // XXX Double check maybe they are right?
    fn rsync_module(&self, module: &uri::RsyncModule) {
        if let Some((ref state, ref command)) = self.0.rsync {
            if state.lock().unwrap().have_seen(module) {
                return
            }
            let path = self.module_to_path(module);

            let cvar = state.lock().unwrap().get_running(module);
            match cvar {
                Ok(cvar) => {
                    let mut finished = cvar.0.lock().unwrap();
                    while !*finished {
                        finished = cvar.1.wait(finished).unwrap();
                    }
                }
                Err(cvar) => {
                    let mut finished = cvar.0.lock().unwrap();
                    let _ = command.update(module, path);
                    {
                        let mut state = state.lock().unwrap();
                        state.remove_running(module);
                        state.add_seen(module);
                    }
                    *finished = true;
                    cvar.1.notify_all();
                }
            }
        }
    }
}


//------------ RsyncState ----------------------------------------------------

#[derive(Clone, Debug)]
struct RsyncState {
    /// Rsync processes currently running.
    ///
    /// The first element of each list item is the module for which the
    /// process runs, the second is a conditional variable that is going
    /// to be triggered when the process finishes.
    #[allow(type_complexity)]
    running: Vec<(uri::RsyncModule, Arc<(Mutex<bool>, Condvar)>)>,

    /// The rsync modules we already tried in this iteration.
    seen: Vec<uri::RsyncModule>,
}

impl RsyncState {
    fn new() -> Self {
        RsyncState {
            running: Vec::new(),
            seen: Vec::new(),
        }
    }

    #[allow(type_complexity, mutex_atomic)]
    fn get_running(
        &mut self,
        module: &uri::RsyncModule
    ) -> Result<Arc<(Mutex<bool>, Condvar)>, Arc<(Mutex<bool>, Condvar)>> {
        for item in &self.running {
            if item.0.eq(module) {
                return Ok(item.1.clone())
            }
        }
        let res = Arc::new((Mutex::new(false), Condvar::new()));
        self.running.push((module.clone(), res.clone()));
        Err(res)
    }

    fn remove_running(&mut self, module: &uri::RsyncModule) {
        self.running.retain(|item| !item.0.eq(module))
    }

    fn add_seen(&mut self, module: &uri::RsyncModule) {
        self.seen.push(module.clone());
    }

    fn have_seen(&self, module: &uri::RsyncModule) -> bool {
        self.seen.contains(module)
    }

    fn clear_seen(&mut self) {
        self.seen.clear()
    }
}


//------------ RsyncCommand --------------------------------------------------

#[derive(Clone, Debug)]
pub struct RsyncCommand {
    command: String,
    args: Vec<String>,
    timeout: Duration,

}

impl RsyncCommand {
    pub fn detect(config: &Config) -> Result<Self, Error> {
        let command = config.rsync_command.clone();
        let output = match process::Command::new(&command).arg("-h").output() {
            Ok(output) => output,
            Err(err) => {
                eprintln!(
                    "Failed to run rsync: {}",
                    err
                );
                return Err(Error)
            }
        };
        if !output.status.success() {
            eprintln!(
                "Running rsync failed with output: \n{}",
                String::from_utf8_lossy(&output.stderr)
            );
            return Err(Error);
        }
        let args = match config.rsync_args {
            Some(ref args) => args.clone(),
            None => {
                let has_contimeout =
                   output.stdout.windows(12)
                   .any(|window| window == b"--contimeout");
                if has_contimeout {
                    vec!["--contimeout=10".into()]
                }
                else {
                    Vec::new()
                }
            }
        };
        Ok(RsyncCommand {
            command,
            args,
            timeout: config.rsync_timeout
        })
    }

    pub fn update<P: AsRef<Path>>(
        &self,
        source: &uri::RsyncModule,
        destination: P
    ) -> Result<(), io::Error> {
        let output = self.command(source, destination)?.output()?;
        let status = Self::log_output(source, output);
        if status.success() {
            return Err(io::Error::new(io::ErrorKind::Other, "rsync failed"))
        }
        Ok(())
    }

    pub fn update_async<P: AsRef<Path>>(
        &self,
        source: &uri::RsyncModule,
        destination: P
    ) -> impl Future<Item=(), Error=io::Error> {
        let cmd = self.command(source, destination);
        let source = source.clone();
        let timeout = self.timeout.clone();
        future::lazy(|| cmd)
        .and_then(move |mut cmd| {
            Timeout::new(cmd.output_async(), timeout)
            .map_err(|err| {
                err.into_inner().unwrap_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "rsync command took too long"
                    )
                })
            })
        })
        .and_then(move |output| {
            let status = Self::log_output(&source, output);
            if status.success() {
                Ok(())
            }
            else {
                Err(io::Error::new(io::ErrorKind::Other, "rsync failed"))
            }
        })
    }

    fn command<P: AsRef<Path>>(
        &self,
        source: &uri::RsyncModule,
        destination: P
    ) -> Result<process::Command, io::Error> {
        info!("rsyncing from {}.", source);
        let destination = destination.as_ref();
        create_dir_all(destination)?;
        let destination = match Self::format_destination(destination) {
            Ok(some) => some,
            Err(_) => {
                error!(
                    "rsync: illegal destination path {}.",
                    destination.display()
                );
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "illegal destination path"
                ));
            }
        };
        let mut cmd = process::Command::new(&self.command);
        for item in &self.args {
            cmd.arg(item);
        }
        cmd.arg("-rltz")
           .arg("--delete")
           .arg(source.to_string())
           .arg(destination);
        debug!("Running command {:?}", cmd);
        Ok(cmd)
    }

    #[cfg(not(windows))]
    fn format_destination(path: &Path) -> Result<String, Error> {
        let mut destination = format!("{}", path.display());
        if !destination.ends_with('/') {
            destination.push('/')
        }
        Ok(destination)
    }

    #[cfg(windows)]
    fn format_destination(path: &Path) -> Result<String, Error> {
        // On Windows we are using Cygwin rsync which requires Unix-style
        // paths. In particular, the drive parameter needs to be turned
        // from e.g. `C:` into `/cygdrive/c` and all backslashes should
        // become slashes.
        use std::path::{Component, Prefix};

        let mut destination = String::new();
        for component in path.components() {
            match component {
                Component::Prefix(prefix) => {
                    // We only accept UNC and Disk prefixes. Everything else
                    // causes an error.
                    match prefix.kind() {
                        Prefix::UNC(server, share) => {
                            let (server, share) = match (server.to_str(),
                                                         share.to_str()) {
                                (Some(srv), Some(shr)) => (srv, shr),
                                _ => return Err(Error)
                            };
                            destination.push_str(server);
                            destination.push('/');
                            destination.push_str(share);
                        }
                        Prefix::Disk(disk) => {
                            let disk = if disk.is_ascii() {
                                (disk as char).to_ascii_lowercase()
                            }
                            else {
                                return Err(Error)
                            };
                            destination.push_str("/cygdrive/");
                            destination.push(disk);
                        }
                        _ => return Err(Error)
                    }
                }
                Component::CurDir | Component::RootDir => {
                    continue
                }
                Component::ParentDir => {
                    destination.push_str("..");
                }
                Component::Normal(s) => {
                    match s.to_str() {
                        Some(s) => destination.push_str(s),
                        None => return Err(Error)
                    }
                }
            }
            destination.push_str("/");
        }
        Ok(destination)
    }

    fn log_output(source: &uri::RsyncModule, output: Output) -> ExitStatus {
        if !output.status.success() {
            warn!(
                "rsync {}/{}: failed with status {}",
                source.authority(), source.module(), output.status
            );
        }
        if !output.stderr.is_empty() {
            String::from_utf8_lossy(&output.stderr).lines().for_each(|l| {
                warn!(
                    "rsync {}/{}: {}", source.authority(), source.module(), l
                );
            })
        }
        if !output.stdout.is_empty() {
            String::from_utf8_lossy(&output.stdout).lines().for_each(|l| {
                info!(
                    "rsync {}/{}: {}", source.authority(), source.module(), l
                )
            })
        }
        output.status
    }
}


//------------ Helper Functions ----------------------------------------------

fn entry_to_uri_component(entry: &DirEntry) -> Option<Bytes> {
    let name = entry.file_name();
    name.to_str().and_then(|name| {
        if uri::is_uri_ascii(name) {
            Some(Bytes::from(name.as_bytes()))
        }
        else {
            None
        }
    })
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

