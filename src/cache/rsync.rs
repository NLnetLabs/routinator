/// Local repository copy synchronized with rsync.
//
//  The rsync cache works as follows:
//
//  Data is kept in the directory given via the cache_dir attribute using the
//  rsync URI without the scheme as the path. We assume that data is published
//  in rsync modules identified by the first two components of this path. This
//  corresponds with the way the rsync daemon works.
//
//  During a valiation run, we keep track of the modules we already have
//  updated. When access to a module that has not yet been updated is
//  requested, we spawn rsync and block until it returns. If during that time
//  another thread requests access to the same module, that thread is blocked,
//  too.

use std::{fmt, fs, io, ops, process};
use std::borrow::{Borrow, Cow, ToOwned};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;
use bytes::Bytes;
use log::{debug, error, info, warn};
use rpki::uri;
use crate::config::Config;
use crate::metrics::{Metrics, RsyncModuleMetrics};
use crate::operation::Error;
use crate::utils::UriExt;


//------------ Cache ---------------------------------------------------------

/// A local copy of repositories synchronized via rsync.
#[derive(Debug)]
pub struct Cache {
    /// The base directory of the cache.
    cache_dir: CacheDir,

    /// The command for running rsync.
    ///
    /// If this is `None` actual rsyncing has been disabled and data
    /// present will be used as is.
    command: Option<Command>,

    /// Whether to filter dubious authorities in rsync URIs.
    filter_dubious: bool,
}
 

impl Cache {
    /// Initializes the rsync cache without creating a value.
    ///
    /// This function is called implicitely by [`new`][Cache::new].
    pub fn init(config: &Config) -> Result<(), Error> {
        let _ = Self::create_cache_dir(config)?;
        Ok(())
    }

    /// Creates the cache dir and returns its path.
    fn create_cache_dir(config: &Config) -> Result<PathBuf, Error> {
        let cache_dir = config.cache_dir.join("rsync");
        if let Err(err) = fs::create_dir_all(&cache_dir) {
            error!(
                "Failed to create RRDP cache directory {}: {}.",
                cache_dir.display(), err
            );
            return Err(Error);
        }
        Ok(cache_dir)
    }

    /// Creates a new rsync cache.
    ///
    /// If use of rsync is disabled via the config, returns `Ok(None)`.
    ///
    /// The cache will not actually run rsync but use whatever files are
    /// present already in the cache directory if `update` is `false`.
    pub fn new(config: &Config, update: bool) -> Result<Option<Self>, Error> {
        if config.disable_rsync {
            Ok(None)
        }
        else {
            Ok(Some(Cache {
                cache_dir: CacheDir::new(Self::create_cache_dir(config)?),
                command: if update {
                    Some(Command::new(config)?)
                }
                else { None },
                filter_dubious: !config.allow_dubious_hosts
            }))
        }
    }

    /// Prepares the cache for use in a validation run.
    pub fn ignite(&mut self) -> Result<(), Error> {
        // We don’t need to do anything. But just in case we later will,
        // let’s keep the method around.
        Ok(())
    }

    /// Start a validation run on the cache.
    pub fn start(&self) -> Run {
        Run::new(self)
    }
}


//------------ Run -----------------------------------------------------------

/// Using the rsync cache during a validation run.
#[derive(Debug)]
pub struct Run<'a> {
    /// A reference to the underlying cache.
    cache: &'a Cache,

    /// The set of modules that has been updated already.
    updated: RwLock<HashSet<OwnedModule>>,

    /// The modules that are currently being updated.
    ///
    /// The value in the map is a mutex that is used to synchronize competing
    /// attempts to update the module. Only the thread that has the mutex is
    /// allowed to actually run rsync.
    running: RwLock<HashMap<OwnedModule, Arc<Mutex<()>>>>,

    /// The metrics for updated rsync modules.
    metrics: Mutex<Vec<RsyncModuleMetrics>>,
}


impl<'a> Run<'a> {
    /// Creates a new runner from a cache.
    fn new(cache: &'a Cache) -> Self {
        Run {
            cache,
            updated: Default::default(),
            running: Default::default(),
            metrics: Default::default(),
        }
    }

    /// Returns whether the module for the given URI has been updated yet.
    ///
    /// This does not mean the module is actually up-to-date or even available
    /// as an update may have failed.
    pub fn is_current(&self, uri: &uri::Rsync) -> bool {
        self.updated.read().unwrap().contains(Module::from_uri(uri).as_ref())
    }

    /// Tries to update the module for the given URI.
    ///
    /// If the module has not yet been updated, may block until an update
    /// finished. This update may not be successful and files in the module
    /// may be outdated or missing completely.
    pub fn load_module(&self, uri: &uri::Rsync) {
        let command = match self.cache.command.as_ref() {
            Some(command) => command,
            None => return,
        };
        let module = Module::from_uri(uri);

        // If it is already up-to-date, return.
        if self.updated.read().unwrap().contains(module.as_ref()) {
            return
        }

        // Get a clone of the (arc-ed) mutex. Make a new one if there isn’t
        // yet.
        let mutex = {
            self.running.write().unwrap()
            .entry(module.clone().into_owned()).or_default()
            .clone()
        };
        
        // Acquire the mutex. Once we have it, see if the module is up-to-date
        // which happens if someone else had it first.
        let _lock = mutex.lock().unwrap();
        if self.updated.read().unwrap().contains(module.as_ref()) {
            return
        }

        // Check if the module name is dubious. If so, skip updating.
        if self.cache.filter_dubious && uri.has_dubious_authority() {
            warn!(
                "{}: Dubious host name. Skipping update.",
                module
            )
        }
        else {
            // Run the actual update.
            let metrics = command.update(
                module.as_ref(),
                &self.cache.cache_dir.module_path(module.as_ref())
            );

            // Insert into updated map and metrics.
            self.metrics.lock().unwrap().push(metrics);
        }

        // Remove from running.
        self.running.write().unwrap().remove(module.as_ref());

        // Insert into updated map no matter what.
        self.updated.write().unwrap().insert(module.into_owned());
    }

    /// Loads the file for the given URI.
    ///
    /// Does _not_ attempt to update the corresponding module first. You need
    /// to explicitely call [`load_module`][Run::load_module] for that.
    ///
    /// If the file is missing, returns `None`.
    pub fn load_file(
        &self,
        uri: &uri::Rsync,
    ) -> Option<Bytes> {
        let path = self.cache.cache_dir.uri_path(uri);
        match fs::File::open(&path) {
            Ok(mut file) => {
                let mut data = Vec::new();
                if let Err(err) = io::Read::read_to_end(&mut file, &mut data) {
                    error!(
                        "Failed to read file '{}': {}",
                        path.display(),
                        err
                    );
                    None
                }
                else {
                    Some(data.into())
                }
            }
            Err(err) => {
                if err.kind() == io::ErrorKind::NotFound {
                    info!("{}: not found in local repository", uri);
                } else {
                    error!(
                        "Failed to open file '{}': {}",
                        path.display(), err
                    );
                }
                None
            }
        }
    }

    /*
    pub fn cleanup(&self) {
        if self.cache.command.is_none() {
            return
        }
        let modules = self.updated.read().unwrap();
        let dir = match fs::read_dir(&self.cache.cache_dir.base) {
            Ok(dir) => dir,
            Err(err) => {
                error!(
                    "Failed to read rsync cache directory: {}",
                    err
                );
                return
            }
        };
        for entry in dir {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    error!(
                        "Failed to iterate over rsync cache directory: {}",
                        err
                    );
                    return
                }
            };
            Self::cleanup_host(entry, &modules);
        }
    }

    #[allow(clippy::mutable_key_type)] // XXX False positive, I think
    fn cleanup_host(entry: fs::DirEntry, modules: &HashSet<OwnedModule>) {
        if !entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
            return
        }
        let path = entry.path();
        let host = match entry_to_uri_component(&entry) {
            Some(host) => host,
            None => {
                info!(
                    "{}: illegal rsync host directory. Skipping.",
                    path.display()
                );
                return
            }
        };
        let dir = match fs::read_dir(&path) {
            Ok(dir) => dir,
            Err(err) => {
                info!(
                    "Failed to read directory {}: {}. Skipping.",
                    path.display(), err
                );
                return
            }
        };
        let mut keep = false;
        for entry in dir {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    info!(
                        "Failed to iterate over directory {}: {}",
                        path.display(), err
                    );
                    return
                }
            };
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                info!(
                    "{}: unexpected file. Skipping.",
                    entry.path().display()
                );
                continue
            }
            let deleted = match entry_to_uri_component(&entry) {
                Some(module) => {
                    let module = match OwnedModule::new(&host, &module) {
                        Ok(module) => module,
                        Err(_) => continue,
                    };
                    Self::cleanup_module(&module, entry.path(), modules)
                }
                None => {
                    info!(
                        "{}: illegal module directory. Skipping",
                        entry.path().display()
                    );
                    continue
                }
            };
            if !deleted {
                keep = true
            }
        }
        if !keep {
            let _ = fs::remove_dir_all(path);
        }
    }

    /// Return if module has been removed.
    #[allow(clippy::mutable_key_type)] // XXX False positive, I think
    fn cleanup_module(
        module: &Module,
        path: PathBuf,
        modules: &HashSet<OwnedModule>
    ) -> bool {
        if !modules.contains(module) {
            if let Err(err) = fs::remove_dir_all(&path) {
                error!(
                    "Failed to delete rsync module directory {}: {}",
                    path.display(),
                    err
                );
            }
            true
        }
        else {
            false
        }
    }
    */

    /// Finishes the validation run.
    ///
    /// Updates `metrics` with the cache run’s metrics.
    ///
    /// If you are not interested in the metrics, you can simple drop the
    /// value, instead.
    pub fn done(self, metrics: &mut Metrics) {
        metrics.set_rsync(self.metrics.into_inner().unwrap())
    }
}


//------------ Command -------------------------------------------------------

/// The command to run rsync.
#[derive(Debug)]
struct Command {
    /// The actual command.
    command: String,

    /// The list of additional arguments.
    ///
    /// We will always add a few more when actually running.
    args: Vec<String>,
}

impl Command {
    /// Creates a new rsync command from the config.
    pub fn new(config: &Config) -> Result<Self, Error> {
        let command = config.rsync_command.clone();
        let output = match process::Command::new(&command).arg("-h").output() {
            Ok(output) => output,
            Err(err) => {
                error!(
                    "Failed to run rsync: {}",
                    err
                );
                return Err(Error)
            }
        };
        if !output.status.success() {
            error!(
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
                let timeout = format!(
                    "--timeout={}",
                    config.rsync_timeout.as_secs()
                );
                if has_contimeout {
                    vec!["--contimeout=10".into(), timeout]
                }
                else {
                    vec![timeout]
                }
            }
        };
        Ok(Command {
            command,
            args,
        })
    }

    /// Updates a module by running rsync.
    pub fn update(
        &self,
        source: &Module,
        destination: &Path
    ) -> RsyncModuleMetrics {
        let start = SystemTime::now();
        let status = {
            match self.command(source, destination) {
                Ok(mut command) => match command.output() {
                    Ok(output) => Ok(Self::log_output(source, output)),
                    Err(err) => Err(err)
                }
                Err(err) => Err(err)
            }
        };
        RsyncModuleMetrics {
            module: source.to_uri(),
            status,
            duration: SystemTime::now().duration_since(start),
        }
    }

    /// Actually runs rsync.
    fn command(
        &self,
        source: &Module,
        destination: &Path
    ) -> Result<process::Command, io::Error> {
        info!("rsyncing from {}.", source);
        fs::create_dir_all(destination)?;
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
        debug!("{}: Running command {:?}", source, cmd);
        Ok(cmd)
    }

    /// Formats the destination path for inclusion in the command.
    #[cfg(not(windows))]
    #[allow(clippy::unnecessary_wraps)]
    fn format_destination(path: &Path) -> Result<String, Error> {
        // Make sure the path ends in a slash or strange things happen.
        let mut destination = format!("{}", path.display());
        if !destination.ends_with('/') {
            destination.push('/')
        }
        Ok(destination)
    }

    /// Formats the destination path for inclusion in the command.
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
            destination.push('/');
        }
        Ok(destination)
    }

    /// Logs the output from the rsync command.
    fn log_output(
        source: &Module,
        output: process::Output
    ) -> process::ExitStatus {
        if !output.status.success() {
            warn!("{}: failed with status {}", source, output.status);
        }
        else {
            info!("{}: successfully completed.", source);
        }
        if !output.stderr.is_empty() {
            String::from_utf8_lossy(&output.stderr).lines().for_each(|l| {
                warn!("{}: {}", source, l);
            })
        }
        if !output.stdout.is_empty() {
            String::from_utf8_lossy(&output.stdout).lines().for_each(|l| {
                info!("{}: {}", source, l)
            })
        }
        output.status
    }
}


//------------ CacheDir ------------------------------------------------------

/// The cache directory of the rsync cache.
#[derive(Clone, Debug)]
struct CacheDir {
    /// The base path.
    base: PathBuf
}

impl CacheDir {
    /// Creates a new cache directory.
    ///
    /// Does not actually create the directory on disk.
    pub fn new(base: PathBuf) -> Self {
        CacheDir { base }
    }

    /// Returns the absolute path for the given module.
    pub fn module_path(&self, module: &Module) -> PathBuf {
        let mut res = self.base.clone();
        res.push(&module.0[8..]);
        res
    }

    /// Returns the absolute path for the given URI.
    fn uri_path(&self, uri: &uri::Rsync) -> PathBuf {
        let mut res = self.base.clone();
        res.push(uri.canonical_authority().as_ref());
        res.push(uri.module_name());
        res.push(uri.path());
        res
    }
}


//------------ Module --------------------------------------------------------

/// The module portion of an rsync URI.
///
/// This is an unsized object – essentially a wrapped `str`.
#[derive(Debug, Eq, Hash, PartialEq)]
pub struct Module(str);

impl Module {
    /// Creates a new module without checking the underlying string.
    unsafe fn from_str(s: &str) -> &Module {
        &*(s as *const str as *const Module)
    }

    /// Returns a module reference for a reference to an rsync URI.
    ///
    /// Because the authority portion of a URI is case insensitive, the
    /// function may have to convert upper ASCII case letters into lower case
    /// to create a canonical value. If this has to happen, an [`OwnedModule`]
    /// is returned via the cow.
    pub fn from_uri(uri: &uri::Rsync) -> Cow<Module> {
        match uri.canonical_module() {
            Cow::Borrowed(s) => {
                Cow::Borrowed(unsafe { Module::from_str(s) })
            }
            Cow::Owned(s) => Cow::Owned(OwnedModule(s))
        }
    }

    /// Converts a module reference into its rsync URI.
    pub fn to_uri(&self) -> uri::Rsync {
        uri::Rsync::from_str(&self.0).unwrap()
    }
}


//--- ToOwned

impl ToOwned for Module {
    type Owned = OwnedModule;

    fn to_owned(&self) -> Self::Owned {
        OwnedModule(self.0.to_owned())
    }
}


//--- Display

impl fmt::Display for Module {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        self.0.fmt(f)
    }
}


//------------ OwnedModule ---------------------------------------------------

/// An owned version of the module portion of an rsync URI.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct OwnedModule(String);

/*
impl OwnedModule {
    fn new(authority: &str, module: &str) -> Result<Self, uri::Error> {
        uri::Rsync::from_string(
            format!("rsync://{}/{}/", authority, module)
        ).map(|uri| OwnedModule(uri.canonical_module().into_owned()))
    }
}
*/


//--- Deref, AsRef, Borrow

impl ops::Deref for OwnedModule {
    type Target = Module;

    fn deref(&self) -> &Module {
        self.as_ref()
    }
}

impl AsRef<Module> for OwnedModule {
    fn as_ref(&self) -> &Module {
        unsafe { Module::from_str(self.0.as_str()) }
    }
}

impl Borrow<Module> for OwnedModule {
    fn borrow(&self) -> &Module {
        self.as_ref()
    }
}


//--- Display

impl fmt::Display for OwnedModule {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        self.0.fmt(f)
    }
}


//------------ Helper Functions ----------------------------------------------

/*
fn entry_to_uri_component(entry: &fs::DirEntry) -> Option<String> {
    let name = entry.file_name();
    name.into_string().ok().and_then(|name| {
        if uri::check_uri_ascii(name.as_bytes()).is_ok() {
            Some(name)
        }
        else {
            None
        }
    })
}
*/

