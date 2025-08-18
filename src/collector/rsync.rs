//! Local repository copy synchronized with rsync.
//!
//! The rsync collector works as follows:
//!
//! Data is kept in the directory given via the cache_dir attribute using the
//! rsync URI without the scheme as the path. We assume that data is published
//! in rsync modules identified by the first two components of this path. This
//! corresponds to the way the rsync daemon works.
//!
//! During a valiation run, we keep track of the modules we already have
//! updated. When access to a module that has not yet been updated is
//! requested, we spawn rsync and block until it returns. If during that time
//! another thread requests access to the same module, that thread is blocked,
//! too.

use std::{fmt, fs, io, ops};
use std::borrow::{Borrow, Cow};
use std::collections::{HashMap, HashSet};
use std::marker::Unpin;
use std::path::{Path, PathBuf};
use std::process::{Command as StdCommand, ExitStatus, Stdio};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use bytes::Bytes;
use futures::{FutureExt, TryFutureExt};
use futures::future::Either;
use log::{debug, error, warn};
use rpki::uri;
use tokio::io::AsyncBufReadExt;
use tokio::process::Command as AsyncCommand;
use crate::config::Config;
use crate::error::{Failed, Fatal};
use crate::log::LogBookWriter;
use crate::metrics::{Metrics, RsyncModuleMetrics};
use crate::utils::fatal;
use crate::utils::sync::{Mutex, RwLock};
use crate::utils::uri::UriExt;


//------------ Collector -----------------------------------------------------

/// A local copy of repositories synchronized via rsync.
#[derive(Debug)]
pub struct Collector {
    /// The base directory of the collector.
    working_dir: WorkingDir,

    /// The command for running rsync.
    ///
    /// If this is `None` actual rsyncing has been disabled and data
    /// present will be used as is.
    command: Option<RsyncCommand>,

    /// Whether to filter dubious authorities in rsync URIs.
    filter_dubious: bool,

    /// Whether to log issues also to the process log?
    log_repository_issues: bool,
}
 

impl Collector {
    /// Initializes the rsync collector without creating a value.
    ///
    /// This function is called implicitely by [`new`][Collector::new].
    pub fn init(config: &Config) -> Result<(), Failed> {
        let _ = Self::create_working_dir(config)?;
        Ok(())
    }

    /// Creates the working dir and returns its path.
    fn create_working_dir(config: &Config) -> Result<PathBuf, Failed> {
        let working_dir = config.cache_dir.join("rsync");

        if config.fresh {
            if let Err(err) = fs::remove_dir_all(&working_dir) {
                if err.kind() != io::ErrorKind::NotFound {
                    error!(
                        "Failed to delete rsync working directory at {}: {}",
                        working_dir.display(), err
                    );
                    return Err(Failed)
                }
            }
        }

        if let Err(err) = fs::create_dir_all(&working_dir) {
            error!(
                "Failed to create rsync working directory {}: {}.",
                working_dir.display(), err
            );
            return Err(Failed);
        }
        Ok(working_dir)
    }

    /// Creates a new rsync collector.
    ///
    /// If use of rsync is disabled via the config, returns `Ok(None)`.
    pub fn new(config: &Config) -> Result<Option<Self>, Failed> {
        if config.disable_rsync {
            Ok(None)
        }
        else {
            Ok(Some(Collector {
                working_dir: WorkingDir::new(
                    Self::create_working_dir(config)?
                ),
                command: Some(RsyncCommand::new(config)?),
                filter_dubious: !config.allow_dubious_hosts,
                log_repository_issues: config.log_repository_issues,
            }))
        }
    }

    /// Prepares the collector for use in a validation run.
    pub fn ignite(&mut self) -> Result<(), Failed> {
        // We don’t need to do anything. But just in case we later will,
        // let’s keep the method around.
        Ok(())
    }

    /// Sanitizes the stored data.
    ///
    /// Currently doesn’t do anything.
    pub fn sanitize(&self) -> Result<(), Fatal> {
        Ok(())
    }

    /// Start a validation run on the collector.
    pub fn start(&self) -> Run<'_> {
        Run::new(self)
    }

    /// Dumps the content of the rsync collector.
    pub fn dump(&self, dir: &Path) -> Result<(), Failed> {
        let target = dir.join("rsync");
        debug!("Dumping rsync collector content from {} to {}", 
            self.working_dir.base.display(), 
            target.display()
        );

        if let Err(err) = fs::remove_dir_all(&target) {
            if err.kind() != io::ErrorKind::NotFound {
                error!(
                    "Failed to delete directory {}: {}",
                    dir.display(), err
                );
                return Err(Failed)
            }
        }
        Self::dump_dir(&self.working_dir.base, &target)?;
        debug!("Rsync collector dump complete.");
        Ok(())
    }

    /// Recursively copies the content of `source` to `target`.
    fn dump_dir(source: &Path, target: &Path) -> Result<(), Failed> {
        let read_dir = match fs::read_dir(source) {
            Ok(read_dir) => read_dir,
            Err(err) => {
                error!(
                    "Failed to open directory {}: {}", source.display(), err
                );
                return Err(Failed)
            }
        };
        for item in read_dir {
            let item = match item {
                Ok(item) => item,
                Err(err) => {
                    error!(
                        "Failed to read directory {}: {}",
                        source.display(), err
                    );
                    return Err(Failed)
                }
            };
            let file_type = match item.file_type() {
                Ok(file_type) => file_type,
                Err(err) => {
                    error!(
                        "Failed to file type for {}: {}",
                        item.path().display(), err
                    );
                    return Err(Failed)
                }
            };

            if file_type.is_dir() {
                let target = target.join(item.file_name());
                if let Err(err) = fs::create_dir_all(&target) {
                    error!(
                        "Failed to create directory {}: {}",
                        target.display(), err
                    );
                    return Err(Failed);
                }
                Self::dump_dir(&item.path(), &target)?;
            }
            else if file_type.is_file() {
                let target = target.join(item.file_name());
                if let Err(err) = fs::copy(item.path(), &target) {
                    error!(
                        "Failed to copy {} to {}: {}",
                        item.path().display(), target.display(), err
                    );
                    return Err(Failed)
                }
            }
        }
        Ok(())
    }
}


//------------ Run -----------------------------------------------------------

/// Using the rsync collector during a validation run.
#[derive(Debug)]
pub struct Run<'a> {
    /// A reference to the underlying collector.
    collector: &'a Collector,

    /// The set of modules that have been updated already.
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
    /// Creates a new runner from a collector.
    fn new(collector: &'a Collector) -> Self {
        Run {
            collector,
            updated: Default::default(),
            running: Default::default(),
            metrics: Default::default(),
        }
    }

    /// Returns whether the module for the given URI has been updated yet.
    ///
    /// This does not mean the module is actually up-to-date or even available
    /// as an update may have failed.
    pub fn was_updated(&self, uri: &uri::Rsync) -> bool {
        self.updated.read().contains(Module::from_uri(uri).as_ref())
    }

    /// Tries to update the module for the given URI.
    ///
    /// If the module has not yet been updated, may block until an update
    /// finished. This update may not be successful and files in the module
    /// may be outdated or missing completely.
    pub fn load_module(&self, uri: &uri::Rsync) {
        let command = match self.collector.command.as_ref() {
            Some(command) => command,
            None => return,
        };
        let module = Module::from_uri(uri);

        // If it is already up-to-date, return.
        if self.updated.read().contains(module.as_ref()) {
            return
        }

        // Get a clone of the (arc-ed) mutex. Make a new one if there isn’t
        // yet.
        let mutex = {
            self.running.write()
            .entry(module.clone().into_owned()).or_default()
            .clone()
        };
        
        // Acquire the mutex. Once we have it, see if the module is up-to-date
        // which happens if someone else had it first.
        let _lock = mutex.lock();
        if self.updated.read().contains(module.as_ref()) {
            return
        }

        let mut log = LogBookWriter::new(
            self.collector.log_repository_issues.then(|| {
                format!("rsync {}: ", module)
            })
        );

        // Check if the module name is dubious. If so, skip updating.
        if self.collector.filter_dubious && uri.has_dubious_authority() {
            log.warn(format_args!(
                "Dubious host name. Skipping update."
            ))
        }
        else {
            // Run the actual update.
            let metrics = command.update(
                module.as_ref(),
                &self.collector.working_dir.module_path(module.as_ref()),
                log
            );

            // Insert into updated map and metrics.
            self.metrics.lock().push(metrics);
        }

        // Remove from running.
        self.running.write().remove(module.as_ref());

        // Insert into updated map no matter what.
        self.updated.write().insert(module.into_owned());
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
        let path = self.collector.working_dir.uri_path(uri);
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
                if err.kind() != io::ErrorKind::NotFound {
                    error!(
                        "Failed to open file '{}': {}",
                        path.display(), err
                    );
                }
                None
            }
        }
    }

    /// Cleans the collector only keeping the modules included in `retain`.
    //
    //  This currently is super agressive, deleting everyting that it doesn’t
    //  like.
    pub fn cleanup(&self, retain: &mut ModuleSet) -> Result<(), Failed> {
        if self.collector.command.is_none() {
            return Ok(())
        }

        // Add all modules we’ve used during this run to retain.
        for module in self.updated.read().iter() {
            retain.add_from_uri(&module.to_uri());
        }

        for entry in fatal::read_dir(
            &self.collector.working_dir.base
        )? {
            let entry = entry?;
            let keep = match entry.file_name().to_str() {
                Some(name) => {
                    match retain.authorities.get(name) {
                        Some(modules) => self.cleanup_host(&entry, modules)?,
                        None => false,
                    }
                }
                None => false
            };

            if !keep {
                fatal::remove_all(entry.path())?;
            }
        }

        Ok(())
    }

    /// Removes all modules from the directory that are not in `retain`.
    ///
    /// Returns whether the host directory should be kept or can be deleted,
    /// too.
    fn cleanup_host(
        &self, entry: &fatal::DirEntry, retain: &HashSet<String>
    ) -> Result<bool, Failed> {
        if entry.is_file() {
            fatal::remove_file(entry.path())?;
            return Ok(false)
        }
        else if !entry.is_dir() {
            return Ok(false)
        }

        let mut keep_host = false;
        for entry in fatal::read_dir(entry.path())? {
            let entry = entry?;
            let keep = match entry.file_name().to_str() {
                Some(name) => retain.contains(name),
                None => false
            };

            if !keep {
                fatal::remove_all(entry.path())?;
            }
            else {
                keep_host = true;
            }
        }

        Ok(keep_host)
    }

    /// Finishes the validation run.
    ///
    /// Updates `metrics` with the collector run’s metrics.
    ///
    /// If you are not interested in the metrics, you can simple drop the
    /// value, instead.
    pub fn done(self, metrics: &mut Metrics) {
        metrics.rsync = self.metrics.into_inner();
    }
}


//------------ RsyncCommand --------------------------------------------------

/// The command to run rsync.
#[derive(Debug)]
struct RsyncCommand {
    /// The actual command.
    command: String,

    /// The list of additional arguments.
    ///
    /// We will always add a few more when actually running.
    args: Vec<String>,

    /// The rsync timeout.
    timeout: Option<Duration>,
}

impl RsyncCommand {
    /// Creates a new rsync command from the config.
    pub fn new(config: &Config) -> Result<Self, Failed> {
        let command = config.rsync_command.clone();
        let output = match StdCommand::new(&command).arg("-h").output() {
            Ok(output) => output,
            Err(err) => {
                error!(
                    "Failed to run rsync: {err}"
                );
                return Err(Failed)
            }
        };
        if !output.status.success() {
            error!(
                "Running rsync failed with output: \n{}",
                String::from_utf8_lossy(&output.stderr)
            );
            return Err(Failed);
        }
        let args = match config.rsync_args {
            Some(ref args) => args.clone(),
            None => {
                let mut args = Vec::new();
                args.push("--no-motd".into());
                args.push("-z".into());
                let has_contimeout =
                   output.stdout.windows(12)
                   .any(|window| window == b"--contimeout");
                if has_contimeout {
                    args.push("--contimeout=10".into());
                }
                if let Some(max_size) = config.max_object_size {
                    args.push(format!("--max-size={max_size}"));
                }
                args
            }
        };
        Ok(RsyncCommand {
            command,
            args,
            timeout: config.rsync_timeout,
        })
    }

    /// Updates a module by running rsync.
    pub fn update(
        &self,
        source: &Module,
        destination: &Path,
        mut log: LogBookWriter,
    ) -> RsyncModuleMetrics {
        let start = SystemTime::now();
        let status = self.command(
            source, destination, &mut log,
        ).and_then(|cmd| self.run(source, cmd, &mut log));
        let log = log.into_book();
        RsyncModuleMetrics {
            module: source.to_uri(),
            status,
            duration: SystemTime::now().duration_since(start),
            log_book: (!log.is_empty()).then(|| log),
        }
    }

    /// Actually runs the rsync command.
    fn run(
        &self,
        source: &Module,
        mut command: AsyncCommand,
        log: &mut LogBookWriter,
    ) -> Result<ExitStatus, io::Error> {
        // Because we can’t have a timeout on a child process with just std,
        // we resort to Tokio here: We fire up a current-thread runtime and
        // use Tokio’s async process handling.

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()?;
        let mut stdout = log.clone();
        let mut stderr = log.clone();

        runtime.block_on(async {
            command.stdout(Stdio::piped());
            command.stderr(Stdio::piped());
            command.kill_on_drop(true);
            let mut child = command.spawn()?;
            let stdout_pipe = child.stdout.take().map(
                tokio::io::BufReader::new
            );
            let stderr_pipe = child.stderr.take().map(
                tokio::io::BufReader::new
            );
            let res = tokio::try_join!(
                match self.timeout {
                    None => Either::Left(child.wait().map(Ok)),
                    Some(timeout) => {
                        Either::Right(
                            tokio::time::timeout(
                                timeout, child.wait()
                            ).map_err(|_| {
                                io::Error::new(
                                    io::ErrorKind::TimedOut,
                                    "rsync process reached time out"
                                )
                            })
                        )
                    }
                },
                Self::process_output(
                    stdout_pipe, &mut stdout, log::Level::Info,
                ),
                Self::process_output(
                    stderr_pipe, &mut stderr, log::Level::Warn,
                ),
            );
            let status = match res {
                Ok((Ok(status), _, _)) => {
                    // Child has exited successfully with status.
                    Ok(status)
                }
                Ok((Err(err), _, _)) => {
                    // Waiting for child has failed with err.
                    Err(err)
                }
                Err(err) => {
                    if let Err(kill_err) = child.kill().await {
                        warn!(
                            "{source}: Failed to kill rsync process: {kill_err}"
                        );
                    }
                    Err(err)
                }
            };

            log.append(stdout);
            log.append(stderr);
            log.sort();
            if let Err(ref err) = status {
                log.warn(format_args!("{err}"));
            }
            status
        })
    }

    /// Creates the rsync command.
    fn command(
        &self,
        source: &Module,
        destination: &Path,
        log: &mut LogBookWriter,
    ) -> Result<AsyncCommand, io::Error> {
        fs::create_dir_all(destination)?;
        let destination = match Self::format_destination(destination) {
            Ok(some) => some,
            Err(_) => {
                log.error(format_args!(
                    "illegal destination path {}.",
                    destination.display()
                ));
                return Err(io::Error::other("illegal destination path"));
            }
        };
        let mut cmd = AsyncCommand::new(&self.command);
        for item in &self.args {
            cmd.arg(item);
        }
        cmd.arg("-rtO")
           .arg("--delete")
           .arg(source.to_string())
           .arg(destination);
        log.debug(format_args!("running command {cmd:?}"));
        Ok(cmd)
    }

    /// Formats the destination path for inclusion in the command.
    #[cfg(not(windows))]
    #[allow(clippy::unnecessary_wraps)]
    fn format_destination(path: &Path) -> Result<String, Failed> {
        // Make sure the path ends in a slash or strange things happen.
        let mut destination = format!("{}", path.display());
        if !destination.ends_with('/') {
            destination.push('/')
        }
        Ok(destination)
    }

    /// Formats the destination path for inclusion in the command.
    #[cfg(windows)]
    fn format_destination(path: &Path) -> Result<String, Failed> {
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
                                _ => return Err(Failed)
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
                                return Err(Failed)
                            };
                            destination.push_str("/cygdrive/");
                            destination.push(disk);
                        }
                        _ => return Err(Failed)
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
                        None => return Err(Failed)
                    }
                }
            }
            destination.push('/');
        }
        Ok(destination)
    }

    /// Logs the line in the buffer.
    async fn process_output(
        pipe: Option<impl AsyncBufReadExt + Unpin>,
        target: &mut LogBookWriter,
        level: log::Level,
    ) -> Result<(), io::Error> {
        let Some(mut pipe) = pipe else { return Ok(()) };
        let mut line = Vec::new();
        while pipe.read_until(b'\n', &mut line).await? != 0 {
            let mut len = line.len();
            if len > 0 && line[len - 1] == b'\n' {
                len -= 1;
            }

            // On Windows, we may now have a \r at the end.
            #[cfg(windows)]
            if len > 0 && line[len - 1] == b'\r' {
                len -= 1;
            }

            if len > 0 {
                target.log(level, format_args!("{}",
                    String::from_utf8_lossy(&line[..len])
                ));
            }

            line.clear();
        }
        Ok(())
    }
}


//------------ WorkingDir ----------------------------------------------------

/// The working directory of the rsync collector.
#[derive(Clone, Debug)]
struct WorkingDir {
    /// The base path.
    base: PathBuf
}

impl WorkingDir {
    /// Creates a new value.
    ///
    /// Does not actually create the directory on disk.
    pub fn new(base: PathBuf) -> Self {
        WorkingDir { base }
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
    pub fn from_uri(uri: &uri::Rsync) -> Cow<'_, Module> {
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


//------------ ModuleSet -----------------------------------------------------

/// A set of rsync modules.
///
/// This is used in cleanup.
#[derive(Clone, Debug, Default)]
pub struct ModuleSet {
    /// The modules under each authority.
    authorities: HashMap<String, HashSet<String>>,
}

impl ModuleSet {
    /// Adds a the module from a URI to the set.
    ///
    /// Returns whether the module was new to the set.
    pub fn add_from_uri(&mut self, uri: &uri::Rsync) -> bool {
        self.with_authority(uri, |auth| {
            let module_name = uri.module_name();
            if auth.contains(module_name) {
                false
            }
            else {
                auth.insert(module_name.to_string());
                true
            }
        })
    }

    fn with_authority<F: FnOnce(&mut HashSet<String>) -> R, R>(
        &mut self, uri: &uri::Rsync, op: F,
    ) -> R {
        // If uri.canonical_authority returns a borrowed str, we avoid an
        // allocation at the price of a double lookup for a missing
        // authority. Given that the map should be relatively small, this
        // should be faster.
        let auth = uri.canonical_authority();
        if let Cow::Borrowed(auth) = auth {
            if let Some(value) = self.authorities.get_mut(auth) {
                return op(value)
            }
        }
        op(self.authorities.entry(auth.into_owned()).or_default())
    }
}

