//! Synchronizing repositories via rsync.

use std::{fs, io, mem, process};
use std::collections::HashMap;
use std::fs::{DirEntry, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, SystemTime, SystemTimeError};
use bytes::Bytes;
use log::{debug, error, info, warn};
use rpki::uri;
use unwrap::unwrap;
use crate::metrics::Metrics;
use crate::config::Config;
use crate::operation::Error;


///----------- Cache ---------------------------------------------------------

/// Access to local copies of repositories synchronized via rsync.
#[derive(Debug)]
pub struct Cache {
    /// The base directory of the cache.
    cache_dir: CacheDir,

    /// Running rsync.
    ///
    /// If this is `None` actual rsyncing has been disabled.
    command: Option<Command>,
}

impl Cache {
    /// Creates a new rsync cache.
    pub fn new(
        config: &Config,
        cache_dir: PathBuf,
        update: bool
    ) -> Result<Self, Error> {
        Ok(Cache {
            cache_dir: CacheDir::new(cache_dir),
            command: if update {
                Some(Command::detect(config)?)
            }
            else { None }
        })
    }

    /// Start a new validation run.
    pub fn start(&self) -> Result<(), Error> {
        // XXX Check for existing directory here.
        self.command.as_ref().map(Command::start);
        Ok(())
    }

    /// Loads the content of a file from the given URI.
    ///
    /// If `create` is `true`, it will try to rsync missing files.
    ///
    /// If loading the file fails, logs a warning and returns `None`.
    pub fn load_file(
        &self,
        uri: &uri::Rsync,
        create: bool
    ) -> Option<Bytes> {
        let command = self.command.as_ref().and_then(|command| {
            if create { Some(command) }
            else { None }
        });
        if let Some(command) = command {
            command.rsync_module(uri.module(), &self.cache_dir)
        }
        let path = self.cache_dir.uri_path(uri);
        match File::open(&path) {
            Ok(mut file) => {
                let mut data = Vec::new();
                if let Err(err) = file.read_to_end(&mut data) {
                    warn!(
                        "Failed to read file '{}': {}",
                        path.display(),
                        err
                    );
                    return None
                }
                Some(data.into())
            }
            Err(err) => {
                if err.kind() == io::ErrorKind::NotFound {
                    info!("{}: not found in local repository", uri);
                } else {
                    warn!(
                        "Failed to open file '{}': {}",
                        path.display(), err
                    );
                }
                None
            }
        }
    }

    pub fn cleanup(&self) {
        if let Some(ref command) = self.command {
            command.cleanup(self.cache_dir.base());
        }
    }

    pub fn update_metrics(&self, metrics: &mut Metrics) {
        if let Some(ref command) = self.command {
            command.update_metrics(metrics)
        }
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

    fn base(&self) -> &Path {
        &self.base
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


//------------ Command -------------------------------------------------------

/// The command to run rsync.
#[derive(Debug)]
struct Command {
    command: String,
    args: Vec<String>,

    /// The rsync state.
    state: Mutex<State>,

}

/// # External Interface
///
impl Command {
    fn detect(config: &Config) -> Result<Self, Error> {
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
            state: Mutex::new(State::new())
        })
    }

    fn start(&self) {
        unwrap!(self.state.lock()).clear_seen();
    }

    #[allow(clippy::mutex_atomic)] // XXX Double check maybe they are right?
    fn rsync_module(
        &self,
        module: &uri::RsyncModule,
        cache_dir: &CacheDir
    ) {
        if unwrap!(self.state.lock()).have_seen(module) {
            return
        }
        let path = cache_dir.module_path(module);

        let cvar = unwrap!(self.state.lock()).get_running(module);
        match cvar {
            Ok(cvar) => {
                let mut finished = unwrap!(cvar.0.lock());
                while !*finished {
                    finished = unwrap!(cvar.1.wait(finished));
                }
            }
            Err(cvar) => {
                let mut finished = unwrap!(cvar.0.lock());
                let metrics = self.update(module, path);
                {
                    let mut state = unwrap!(self.state.lock());
                    state.remove_running(module);
                    state.add_seen(module.clone(), metrics);
                }
                *finished = true;
                cvar.1.notify_all();
            }
        }
    }

    fn update<P: AsRef<Path>>(
        &self,
        source: &uri::RsyncModule,
        destination: P
    ) -> ModuleMetrics {
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
        ModuleMetrics {
            status,
            duration: SystemTime::now().duration_since(start),
        }
    }

    pub fn cleanup(&self, cache_dir: &Path) {
        let _ = unwrap!(self.state.lock()).cleanup(cache_dir);
    }

    pub fn update_metrics(&self, metrics: &mut Metrics) {
        metrics.set_rsync(unwrap!(self.state.lock()).take_seen())
    }

}

/// # Internal Helper Methods
///
impl Command {
    fn command<P: AsRef<Path>>(
        &self,
        source: &uri::RsyncModule,
        destination: P
    ) -> Result<process::Command, io::Error> {
        info!("rsyncing from {}.", source);
        let destination = destination.as_ref();
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
            debug!(
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


//------------ State ---------------------------------------------------------

#[derive(Debug)]
struct State {
    /// Rsync processes currently running.
    ///
    /// The first element of each list item is the module for which the
    /// process runs, the second is a conditional variable that is going
    /// to be triggered when the process finishes.
    #[allow(clippy::type_complexity)]
    running: Vec<(uri::RsyncModule, Arc<(Mutex<bool>, Condvar)>)>,

    /// The rsync modules we already tried in this iteration.
    seen: HashMap<uri::RsyncModule, ModuleMetrics>,
}

impl State {
    fn new() -> Self {
        State {
            running: Vec::new(),
            seen: HashMap::new(),
        }
    }

    #[allow(clippy::type_complexity, clippy::mutex_atomic)]
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

    fn add_seen(&mut self, module: uri::RsyncModule, metrics: ModuleMetrics) {
        let _ = self.seen.insert(module, metrics);
    }

    fn have_seen(&self, module: &uri::RsyncModule) -> bool {
        self.seen.contains_key(module)
    }

    fn clear_seen(&mut self) {
        self.seen.clear()
    }

    fn take_seen(&mut self) -> Vec<(uri::RsyncModule, ModuleMetrics)> {
        mem::replace(&mut self.seen, HashMap::new()).into_iter().collect()
    }
}

impl State {
    pub fn cleanup(&self, cache_dir: &Path) -> Result<(), Error> {
        let dir = fs::read_dir(cache_dir).map_err(|err| {
            warn!(
                "Failed to read rsync cache directory: {}",
                err
            );
            Error
        })?;
        for entry in dir {
            let entry = entry.map_err(|err| {
                warn!(
                    "Failed to iterate over rsync cache directory: {}",
                    err
                );
                Error
            })?;
            self.cleanup_host(entry);
        }
        Ok(())
    }

    fn cleanup_host(&self, entry: DirEntry) {
        if !entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
            return
        }
        let path = entry.path();
        let host = match entry_to_uri_component(&entry) {
            Some(host) => host,
            None => {
                warn!(
                    "{}: illegal rsync host directory. Skipping.",
                    path.display()
                );
                return
            }
        };
        let dir = match fs::read_dir(&path) {
            Ok(dir) => dir,
            Err(err) => {
                warn!(
                    "Failed to read directory {}: {}. Skipping.",
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
            match entry_to_uri_component(&entry) {
                Some(module) => {
                    self.cleanup_module(
                        uri::RsyncModule::new(host.clone(), module),
                        entry.path(),
                    )
                }
                None => {
                    info!(
                        "{}: illegal module directory. Skipping",
                        entry.path().display()
                    )
                }
            }
        }
        // Now we just try to delete the whole host directory which fails
        // if there are still modules left.
        let _ = fs::remove_dir(path);
    }

    fn cleanup_module(
        &self,
        module: uri::RsyncModule,
        path: PathBuf,
    ) {
        if !self.have_seen(&module) {
            debug!("Cleanup: trying to delete {}.", path.display());
            if let Err(err) = fs::remove_dir_all(&path) {
                error!(
                    "Failed to delete rsync module directory {}: {}",
                    path.display(),
                    err
                );
            }
        }
        else {
            debug!("Cleanup: keeping {}.", path.display());
        }
    }
}


//------------ ModuleMetrics -------------------------------------------------

#[derive(Debug)]
pub struct ModuleMetrics {
    pub status: Result<process::ExitStatus, io::Error>,
    pub duration: Result<Duration, SystemTimeError>,
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

