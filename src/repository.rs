//! The local copy of the RPKI repository.
//!
//! This module contains [`Repository`] representing the local copy of the
//! RPKI repository. It knows how to update the content and also how to
//! process it into a list of route origins.
//!
//! [`Repository`]: struct.Repository.html

use std::{fs, io, process};
use std::fs::{DirEntry, File, create_dir_all};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Output};
use std::sync::{Arc, Condvar, Mutex};
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
use tokio_process::CommandExt;
use super::config::Config;
use super::origins::RouteOrigins;


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
/// with the local copy.
///
/// You create a repository by calling the `new` function, providing a small
/// amount of configuration information. Next, you can update the content via
/// the `update` method. Finally, the `process` method produces a list of
/// validated route origins.
#[derive(Clone, Debug)]
pub struct Repository(Arc<RepoInner>);

#[derive(Debug)]
struct RepoInner {
    /// The directory our local copy of the respository lives in.
    cache_dir: PathBuf, 

    /// The directory the TALs live in.
    tal_dir: PathBuf,

    /// Should we be strict when decoding data?
    strict: bool,

    /// Number of threads.
    threads: usize,

    /// Information for running rsync.
    ///
    /// If this is `None`, we don’t rsync.
    rsync: Option<(Mutex<RsyncState>, RsyncCommand)>,
}

impl Repository {
    /// Creates a new repository.
    pub fn new(config: &Config, rsync: bool) -> Result<Self, ProcessingError> {
        if let Err(err) = fs::read_dir(&config.cache_dir) {
            return Err(ProcessingError::BadCacheDirectory(
                format!("{}", config.cache_dir.display()),
                err
            ))
        }
        if let Err(err) = fs::read_dir(&config.tal_dir) {
            return Err(ProcessingError::BadTalDirectory(
                format!("{}", config.tal_dir.display()),
                err
            ))
        }

        // Let’s quickly go over the TALs to break as early as possible if
        // they aren’t good.
        for _ in Tal::read_dir(&config.tal_dir)? { }

        Ok(Repository(Arc::new(RepoInner {
            cache_dir: config.cache_dir.clone(),
            tal_dir: config.tal_dir.clone(),
            strict: config.strict,
            threads: config.validation_threads,
            rsync: if rsync {
                Some((
                    Mutex::new(RsyncState::new()),
                    RsyncCommand::detect()?
                ))
            }
            else {
                None
            }
        })))
    }

    /// Starts a validation run.
    pub fn start(&self) {
        if let Some(ref rsync) = self.0.rsync {
            rsync.0.lock().unwrap().clear_seen();
        }
    }

    /// Updates the content of the local copy.
    ///
    /// This will go out and do a bunch of rsync requests (unless that was
    /// disabled explicitely).
    pub fn update(&self) -> Result<(), ProcessingError> {
        self.update_async().wait()
    }

    pub fn update_async(
        &self
    ) -> impl Future<Item=(), Error=ProcessingError> {
        let repo = self.clone();
        let pool = CpuPool::new(self.0.threads);
        fs::read_dir(&self.0.cache_dir).map_err(Into::into).into_future()
        .and_then(|dir| {
            future::join_all(dir.map(move |entry| {
                let repo = repo.clone();
                pool.spawn(future::lazy(|| repo.update_host(entry)))
            })).map(|_| ())
        })
    }

    /// Process the local copy and produce a list of validated route origins.
    ///
    /// Note that the method may also do some rsync if it encounters new
    /// modules it hasn’t seen before. This means that if you start out on a
    /// new copy, it will go out and fetch everything it needs.
    pub fn process(&self) -> Result<RouteOrigins, ProcessingError> {
        self.process_async().wait()
    }

    pub fn process_async(
        &self
    ) -> impl Future<Item=RouteOrigins, Error=ProcessingError> {
        let pool = CpuPool::new(self.0.threads);
        let repo = self.clone();
        fs::read_dir(&self.0.tal_dir).map_err(Into::into).into_future()
        .and_then(|dir| {
            future::join_all(dir.map(move |entry| {
                let repo = repo.clone();
                pool.spawn(future::lazy(|| repo.process_tal(entry)))
            })).and_then(|x| {
                let mut res = RouteOrigins::new();
                x.into_iter().for_each(|item| res.merge(item));
                Ok(res)
            })
        })
    }
}


/// # Repository Access
///
impl Repository {
    /// Loads a trust anchor certificate from the given URI.
    fn load_ta(
        &self,
        uri: &uri::Rsync
    ) -> Result<Option<Cert>, ProcessingError> {
        Ok(
            self.load_file(uri, true)?
            .and_then(|bytes| Cert::decode(bytes).ok())
        )
    }

    /// Loads the content of a file from the given URI.
    ///
    /// If `create` is `true`, it will try to rsync missing files.
    fn load_file(
        &self,
        uri: &uri::Rsync,
        create: bool
    ) -> Result<Option<Bytes>, ProcessingError> {
        match File::open(self.uri_to_path(uri)) {
            Ok(mut file) => {
                let mut data = Vec::new();
                file.read_to_end(&mut data)?;
                Ok(Some(data.into()))
            }
            Err(ref err) if err.kind() == io::ErrorKind::NotFound => {
                if create {
                    self.rsync_module(uri.module());
                    self.load_file(uri, false)
                }
                else {
                    debug!("{}: not found; ignoring", uri);
                    Ok(None)
                }
            }
            Err(err) => Err(err.into()),
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
    fn update_host(
        self,
        entry: Result<DirEntry, io::Error>
    ) -> Result<(), ProcessingError> {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            return Ok(())
        }
        match entry_to_uri_component(&entry) {
            Some(host) => self.update_module(host, entry.path()),
            None => {
                warn!(
                    "{}: illegal host directory. Skipping.",
                    entry.path().display()
                );
                Ok(())
            }
        }
    }

    /// Updates content of the module-specific directory of the local copy.
    fn update_module(
        &self,
        host: Bytes,
        path: PathBuf
    ) -> Result<(), ProcessingError> {
        for entry in fs::read_dir(&path)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                warn!("{}: unexpected file. Skipping", entry.path().display());
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
        Ok(())
    }
}


/// # Processing
///
impl Repository {
    /// Processes all data for the given trust anchor.
    pub fn process_tal(
        self,
        entry: Result<DirEntry, io::Error>
    ) -> Result<RouteOrigins, ProcessingError> {
        let entry = entry?;
        let path = entry.path();
        let mut res = RouteOrigins::new();
        if !entry.file_type()?.is_file() {
            warn!("{}: garbage in TAL directory.", path.display());
            return Ok(res)
        }
        let mut file = match File::open(&path) {
            Ok(file) => {
                debug!("Processing TAL {}", path.display());
                file
            }
            Err(err) => {
                error!("{}: {}. Aborting.", path.display(), err);
                return Err(err.into())
            }
        };
        let tal = match Tal::read(&path, &mut file) {
            Ok(tal) => tal,
            Err(err) => {
                error!("{}: {}. Aborting.", path.display(), err);
                return Err(ProcessingError::Other)
            }
        };
        for uri in tal.uris() {
                let cert = match self.load_ta(&uri) {
                    Ok(Some(cert)) => cert,
                    _ => continue,
                };
                if cert.subject_public_key_info() != tal.key_info() {
                    continue;
                }
                let cert = match cert.validate_ta(tal.info().clone(),
                                                  self.0.strict) {
                    Ok(cert) => cert,
                    Err(_) => {
                        continue;
                    }
                };
                debug!("processing {}", uri);
                let _ = self.process_ca(cert, &mut res);
                // We stop once we have had the first working URI.
                break;
        }
        Ok(res)
    }

    /// Processes all data for the given trust CA.
    fn process_ca(
        &self,
        cert: ResourceCert,
        routes: &mut RouteOrigins
    ) -> Result<(), ProcessingError> {
        let mut store = CrlStore::new();

        let repo_uri = match cert.repository_uri() {
            Some(uri) => uri,
            None => return Ok(())
        };
        let manifest = match self.get_manifest(&cert, &mut store)? {
            Some(manifest) => manifest,
            None => return Ok(())
        };

        for item in manifest.iter_uris(repo_uri) {
            let (uri, hash) = match item {
                Ok(item) => item,
                Err(_) => continue,
            };
            self.process_object(uri, hash, &cert, &mut store, routes)?;
        }
        Ok(())
    }

    /// Processes all an object.
    fn process_object(
        &self,
        uri: uri::Rsync,
        hash: ManifestHash,
        issuer: &ResourceCert,
        crl: &mut CrlStore,
        routes: &mut RouteOrigins,
    ) -> Result<(), ProcessingError> {
        // XXX We should have the directory already from the fetching the
        //     manifest. So we should be fine calling load_file without
        //     request for file creation.
        if uri.ends_with(".cer") {
            let bytes = match self.load_file(&uri, false)? {
                Some(bytes) => bytes,
                None => {
                    info!("{}: failed to load.", uri);
                    return Ok(())
                }
            };
            if let Err(_) = hash.verify(&bytes) {
                info!("{}: file has wrong hash.", uri);
                return Ok(())
            }
            let cert = match Cert::decode(bytes) {
                Ok(cert) => cert,
                Err(_) => {
                    info!("{}: failed to decode.", uri);
                    return Ok(())
                }
            };
            let cert = match cert.validate_ca(issuer, self.0.strict) {
                Ok(cert) => cert,
                Err(_) => {
                    info!("{}: failed to validate.", uri);
                    return Ok(())
                }
            };
            if let Err(_) = self.check_crl(&cert, issuer, crl) {
                info!("{}: certificate has been revoked", uri);
                return Ok(())
            }
            self.process_ca(cert, routes)
        }
        else if uri.ends_with(".roa") {
            let bytes = match self.load_file(&uri, false)? {
                Some(bytes) => bytes,
                None => return Ok(())
            };
            if let Err(_) = hash.verify(&bytes) {
                return Ok(())
            }
            let roa = match Roa::decode(bytes, self.0.strict) {
                Ok(roa) => roa,
                Err(_) => {
                    info!("Decoding failed for {}", uri);
                    return Ok(())
                }
            };
            let route = roa.process(issuer, self.0.strict, |cert| {
                self.check_crl(cert, issuer, crl)
            });
            if let Ok(route) = route {
                routes.push(route)
            }
            Ok(())
        }
        else if uri.ends_with(".crl") {
            Ok(())
        }
        else {
            info!("skipping unknown file {}", uri);
            Ok(())
        }
    }

    fn get_manifest(
        &self,
        issuer: &ResourceCert,
        store: &mut CrlStore,
    ) -> Result<Option<ManifestContent>, ProcessingError> {
        for uri in issuer.manifest_uris() {
            let uri = match uri.into_rsync_uri() {
                Some(uri) => uri,
                None => continue,
            };
            let bytes = match self.load_file(&uri, true)? {
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
            if manifest.len() > CRL_CACHE_LIMIT {
                debug!(
                    "Manifest with {} entries: enabling serial caching",
                    manifest.len()
                );
                store.enable_serial_caching();
            }
            if let Err(_) = self.check_crl(cert, issuer, store) {
                info!("{}: certificate has been revoked", uri);
                continue
            }
            return Ok(Some(manifest))
        }
        debug!("No valid manifests");
        Ok(None)
    }

    fn check_crl<C: AsRef<Cert>>(
        &self,
        cert: C,
        issuer: &ResourceCert,
        store: &mut CrlStore,
    ) -> Result<(), ValidationError> {
        let uri_list = match cert.as_ref().crl_distribution() {
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
                if crl.contains(&cert.as_ref().serial_number()) {
                    return Err(ValidationError)
                }
                else {
                    return Ok(())
                }
            }

            // Otherwise, try to load it, use it, and then store it.
            let bytes = match self.load_file(&uri, true) {
                Ok(Some(bytes)) => bytes,
                _ => continue
            };
            let crl = match Crl::decode(bytes) {
                Ok(crl) => crl,
                Err(_) => continue
            };
            if let Err(_) = crl.validate(issuer) {
                continue
            }

            let revoked = crl.contains(&cert.as_ref().serial_number());
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
    has_contimeout: bool
}

impl RsyncCommand {
    pub fn detect() -> Result<Self, RsyncError> {
        let output = process::Command::new("rsync").arg("-h").output()?;
        if !output.status.success() {
            return Err(RsyncError::Output(
                String::from_utf8_lossy(&output.stderr).into()
            ))
        }
        Ok(RsyncCommand {
            has_contimeout:
                output.stdout.windows(12)
                             .any(|window| window == b"--contimeout")
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
        future::lazy(|| cmd)
        .and_then(|mut cmd| {
            cmd.output_async()
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
        let mut destination = format!("{}", destination.display());
        if !destination.ends_with("/") {
            destination.push('/')
        }
        let mut cmd = process::Command::new("rsync");
        cmd.arg("-rltz")
           .arg("--delete");
        if self.has_contimeout {
            cmd.arg("--contimeout=10");
        }
        cmd.arg(source.to_string())
           .arg(destination);
        debug!("Running command {:?}", cmd);
        Ok(cmd)
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


//------------ ProcessingError -----------------------------------------------

#[derive(Debug, Fail)]
pub enum ProcessingError {
    #[fail(display="failed to open cache directory {}: {}", _0, _1)]
    BadCacheDirectory(String, io::Error),

    #[fail(display="failed to open trust anchor directory {}: {}", _0, _1)]
    BadTalDirectory(String, io::Error),

    #[fail(display="{}", _0)]
    Rsync(RsyncError),

    #[fail(display="IO error: {}", _0)]
    Io(io::Error),

    #[fail(display="fatal processing error")]
    Other
}

impl From<RsyncError> for ProcessingError {
    fn from(err: RsyncError) -> Self {
        ProcessingError::Rsync(err)
    }
}

impl From<io::Error> for ProcessingError {
    fn from(err: io::Error) -> Self {
        ProcessingError::Io(err)
    }
}


//------------ RsyncError ---------------------------------------------------

#[derive(Debug, Fail)]
pub enum RsyncError {
    #[fail(display="unable to run rsync:\n{}", _0)]
    Command(io::Error),

    #[fail(display="unable to run rsync:\n{}", _0)]
    Output(String),
}

impl From<io::Error> for RsyncError {
    fn from(err: io::Error) -> RsyncError {
        RsyncError::Command(err)
    }
}

