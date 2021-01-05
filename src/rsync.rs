/// Local repository copy synchronized with rsync.

use std::{fs, io, process};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;
use bytes::Bytes;
use log::{debug, error, info, warn};
use rpki::uri;
use crate::config::Config;
use crate::metrics::RsyncModuleMetrics;
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
    /// If this is `None` actual rsyncing has been disabled.
    command: Option<Command>,

    /// Whether to filter dubious authorities in rsync URIs.
    filter_dubious: bool,
}
 

impl Cache {
    pub fn init(config: &Config) -> Result<(), Error> {
        let rsync_dir = Self::cache_dir(config);
        if let Err(err) = fs::create_dir_all(&rsync_dir) {
            error!(
                "Failed to create RRDP cache directory {}: {}.",
                rsync_dir.display(), err
            );
            return Err(Error);
        }
        Ok(())
    }

    pub fn new(config: &Config, update: bool) -> Result<Option<Self>, Error> {
        if config.disable_rsync {
            Ok(None)
        }
        else {
            Self::init(config)?;
            Ok(Some(Cache {
                cache_dir: CacheDir::new(Self::cache_dir(config)),
                command: if update {
                    Some(Command::new(config)?)
                }
                else { None },
                filter_dubious: !config.allow_dubious_hosts
            }))
        }
    }

    pub fn ignite(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn cache_dir(config: &Config) -> PathBuf {
        config.cache_dir.join("rsync")
    }

    pub fn start(&self) -> Result<Run, Error> {
        Run::new(self)
    }
}


//------------ Run -----------------------------------------------------------

/// Information for a validation run.
#[derive(Debug)]
pub struct Run<'a> {
    /// A reference to the underlying cache.
    cache: &'a Cache,

    updated: RwLock<HashSet<uri::RsyncModule>>,

    running: RwLock<HashMap<uri::RsyncModule, Arc<Mutex<()>>>>,

    metrics: Mutex<Vec<RsyncModuleMetrics>>,
}


impl<'a> Run<'a> {
    pub fn new(cache: &'a Cache) -> Result<Self, Error> {
        Ok(Run {
            cache,
            updated: Default::default(),
            running: Default::default(),
            metrics: Default::default(),
        })
    }

    pub fn is_current(&self, uri: &uri::Rsync) -> bool {
        self.updated.read().unwrap().contains(uri.module())
    }

    pub fn load_module(&self, uri: &uri::Rsync) {
        let command = match self.cache.command.as_ref() {
            Some(command) => command,
            None => return,
        };
        let module = uri.module();

        // If it is already up-to-date, return.
        if self.updated.read().unwrap().contains(module) {
            return
        }

        // Get a clone of the (arc-ed) mutex. Make a new one if there isn’t
        // yet.
        let mutex = {
            self.running.write().unwrap()
            .entry(module.clone()).or_default()
            .clone()
        };
        
        // Acquire the mutex. Once we have it, see if the module is up-to-date
        // which happens if someone else had it first.
        let _lock = mutex.lock().unwrap();
        if self.updated.read().unwrap().contains(module) {
            return
        }

        // Check if the module name is dubious. If so, skip updating.
        if self.cache.filter_dubious && module.has_dubious_authority() {
            warn!(
                "{}: Dubious host name. Skipping update.",
                module
            )
        }
        else {
            // Run the actual update.
            let metrics = command.update(
                module, &self.cache.cache_dir.module_path(module)
            );

            // Insert into updated map and metrics.
            self.metrics.lock().unwrap().push(metrics);
        }

        // Insert into updated map no matter what.
        self.updated.write().unwrap().insert(module.clone());

        // Remove from running.
        self.running.write().unwrap().remove(module);
    }

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
    fn cleanup_host(entry: fs::DirEntry, modules: &HashSet<uri::RsyncModule>) {
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
                    Self::cleanup_module(
                        uri::RsyncModule::new(host.clone(), module),
                        entry.path(),
                        modules,
                    )
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
        module: uri::RsyncModule,
        path: PathBuf,
        modules: &HashSet<uri::RsyncModule>
    ) -> bool {
        if !modules.contains(&module) {
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

    pub fn into_metrics(self) -> Vec<RsyncModuleMetrics> {
        self.metrics.into_inner().unwrap()
    }
}


//------------ Command -------------------------------------------------------

/// The command to run rsync.
#[derive(Debug)]
struct Command {
    command: String,
    args: Vec<String>,
}

/// # External Interface
///
impl Command {
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

    pub fn update(
        &self,
        source: &uri::RsyncModule,
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
            module: source.clone(),
            status,
            duration: SystemTime::now().duration_since(start),
        }
    }

    fn command(
        &self,
        source: &uri::RsyncModule,
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
        debug!(
            "rsync://{}/{}: Running command {:?}",
            source.authority(), source.module(), cmd
        );
        Ok(cmd)
    }

    #[cfg(not(windows))]
    #[allow(clippy::unnecessary_wraps)]
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
            destination.push('/');
        }
        Ok(destination)
    }

    fn log_output(
        source: &uri::RsyncModule,
        output: process::Output
    ) -> process::ExitStatus {
        if !output.status.success() {
            warn!(
                "rsync://{}/{}: failed with status {}",
                source.authority(), source.module(), output.status
            );
        }
        else {
            info!(
                "rsync://{}/{}: successfully completed.",
                source.authority(), source.module(),
            );
        }
        if !output.stderr.is_empty() {
            String::from_utf8_lossy(&output.stderr).lines().for_each(|l| {
                warn!(
                    "rsync://{}/{}: {}", source.authority(), source.module(), l
                );
            })
        }
        if !output.stdout.is_empty() {
            String::from_utf8_lossy(&output.stdout).lines().for_each(|l| {
                info!(
                    "rsync://{}/{}: {}", source.authority(), source.module(), l
                )
            })
        }
        output.status
    }
}


//------------ CacheDir ------------------------------------------------------

#[derive(Clone, Debug)]
struct CacheDir {
    base: PathBuf
}

impl CacheDir {
    fn new(base: PathBuf) -> Self {
        CacheDir { base }
    }

    fn module_path(&self, module: &uri::RsyncModule) -> PathBuf {
        let mut res = self.base.clone();
        res.push(module.authority());
        res.push(module.module());
        res
    }

    fn uri_path(&self, uri: &uri::Rsync) -> PathBuf {
        let mut res = self.module_path(uri.module());
        res.push(uri.path());
        res
    }
}


//------------ Helper Functions ----------------------------------------------

fn entry_to_uri_component(entry: &fs::DirEntry) -> Option<Bytes> {
    let name = entry.file_name();
    name.to_str().and_then(|name| {
        if uri::is_uri_ascii(name) {
            Some(Bytes::copy_from_slice(name.as_bytes()))
        }
        else {
            None
        }
    })
}

