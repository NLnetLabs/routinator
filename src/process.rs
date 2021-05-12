//! Managing the process Routinator runs in.

use std::{fs, io};
use std::future::Future;
use std::path::Path;
use std::sync::mpsc;
use std::sync::{Mutex, RwLock};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use log::{error, LevelFilter};
use tokio::runtime::Runtime;
use crate::config::{Config, LogTarget};
use crate::error::Failed;


//------------ Process -------------------------------------------------------

/// A representation of the process Routinator runs in.
///
/// This type provides access to the configuration and the environment in a
/// platform independent way.
pub struct Process {
    config: Config,
    service: Option<ServiceImpl>,
}

impl Process {
    pub fn init() -> Result<(), Failed> {
        Self::init_logging()?;

        Ok(())
    }

    /// Creates a new process object.
    ///
    pub fn new(config: Config) -> Self {
        Process { 
            service: Some(ServiceImpl::new(&config)),
            config
        }
    }

    /// Returns a reference to the config.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Returns an exclusive reference to the config.
    pub fn config_mut(&mut self) -> &mut Config {
        &mut self.config
    }
}

/// # Logging
///
impl Process {
    /// Initialize logging.
    ///
    /// All diagnostic output of Routinator is done via logging, never to
    /// stderr directly. Thus, it is important to initalize logging before
    /// doing anything else that may result in such output. This function
    /// does exactly that. It sets a maximum log level of `warn`, leading
    /// only printing important information, and directs all logging to
    /// stderr.
    fn init_logging() -> Result<(), Failed> {
        log::set_max_level(LevelFilter::Warn);
        if let Err(err) = log_reroute::init() {
            eprintln!("Failed to initialize logger: {}.\nAborting.", err);
            return Err(Failed)
        };
        let dispatch = fern::Dispatch::new()
            .level(LevelFilter::Error)
            .chain(io::stderr())
            .into_log().1;
        log_reroute::reroute_boxed(dispatch);
        Ok(())
    }

    /// Switches logging to the configured target.
    ///
    /// Once the configuration has been successfully loaded, logging should
    /// be switched to whatever the user asked for via this method.
    #[allow(unused_variables)] // for cfg(not(unix))
    pub fn switch_logging(
        &self,
        daemon: bool,
        with_output: bool
    ) -> Result<Option<LogOutput>, Failed> {
        let logger = match self.config.log_target {
            #[cfg(unix)]
            LogTarget::Default(fac) => {
                if daemon {
                    self.syslog_logger(fac)?
                }
                else {
                    self.stderr_logger(false)
                }
            }
            #[cfg(unix)]
            LogTarget::Syslog(fac) => {
                self.syslog_logger(fac)?
            }
            LogTarget::Stderr => {
                self.stderr_logger(daemon)
            }
            LogTarget::File(ref path) => {
                self.file_logger(path)?
            }
        };
        let (logger, res) = if with_output {
            let (tx, res) = LogOutput::new();
            let logger = logger.chain(tx);
            (logger, Some(res))
        }
        else {
            (logger, None)
        };

        log_reroute::reroute_boxed(logger.into_log().1);
        log::set_max_level(self.config.log_level);
        Ok(res)
    }

    /// Creates a syslog logger and configures correctly.
    #[cfg(unix)]
    fn syslog_logger(
        &self,
        facility: syslog::Facility
    ) -> Result<fern::Dispatch, Failed> {
        let process = std::env::current_exe().ok().and_then(|path|
            path.file_name()
                .and_then(std::ffi::OsStr::to_str)
                .map(ToString::to_string)
        ).unwrap_or_else(|| String::from("routinator"));
        let formatter = syslog::Formatter3164 {
            facility,
            hostname: None,
            process,
            pid: nix::unistd::getpid().as_raw()
        };
        let logger = syslog::unix(formatter.clone()).or_else(|_| {
            syslog::tcp(formatter.clone(), ("127.0.0.1", 601))
        }).or_else(|_| {
            syslog::udp(formatter, ("127.0.0.1", 0), ("127.0.0.1", 514))
        });
        match logger {
            Ok(logger) => {
                Ok(self.fern_logger(false).chain(
                    Box::new(syslog::BasicLogger::new(logger))
                    as Box::<dyn log::Log>
                ))
            }
            Err(err) => {
                error!("Cannot connect to syslog: {}", err);
                Err(Failed)
            }
        }
    }

    /// Creates a stderr logger.
    ///
    /// If we are in daemon mode, we add a timestamp to the output.
    fn stderr_logger(&self, daemon: bool) -> fern::Dispatch {
        self.fern_logger(daemon).chain(io::stderr())
    }

    /// Creates a file logger using the file provided by `path`.
    fn file_logger(&self, path: &Path) -> Result<fern::Dispatch, Failed> {
        let file = match fern::log_file(path) {
            Ok(file) => file,
            Err(err) => {
                error!(
                    "Failed to open log file '{}': {}",
                    path.display(), err
                );
                return Err(Failed)
            }
        };
        Ok(self.fern_logger(true).chain(file))
    }

    /// Creates and returns a fern logger.
    fn fern_logger(&self, timestamp: bool) -> fern::Dispatch {
        let mut res = fern::Dispatch::new();
        if timestamp {
            res = res.format(|out, message, _record| {
                out.finish(format_args!(
                    "{} {} {}",
                    chrono::Local::now().format("[%Y-%m-%d %H:%M:%S]"),
                    _record.module_path().unwrap_or(""),
                    message
                ))
            });
        }
        res = res
            .level(self.config.log_level)
            .level_for("rustls", LevelFilter::Error);
        if self.config.log_level == LevelFilter::Debug {
            res = res
                .level_for("tokio_reactor", LevelFilter::Info)
                .level_for("hyper", LevelFilter::Info)
                .level_for("reqwest", LevelFilter::Info)
                .level_for("h2", LevelFilter::Info)
                .level_for("sled", LevelFilter::Info);
        }
        res
    }
}


/// # System Service
///
impl Process {
    /// Sets up the system service.
    ///
    /// If `detach` is `true`, the service will detach from the current
    /// process and keep running in the background.
    ///
    /// After the method returns, we will be running in the final process
    /// but still have the same privileges as when we were initially started.
    /// Whether there is still a terminal and standard stream available
    /// depends on the config.
    ///
    /// This method may encounter and log errors after detaching. You should
    /// therefore call `switch_logging` before this method.
    pub fn setup_service(&mut self, detach: bool) -> Result<(), Failed> {
        self.service.as_mut().unwrap().setup_service(&self.config, detach)
    }

    /// Drops privileges.
    ///
    /// If requested via the config, this method will drop all potentially
    /// elevated privileges. This may include loosing root or system
    /// administrator permissions and change the file system root.
    pub fn drop_privileges(&mut self) -> Result<(), Failed> {
        self.service.take().unwrap().drop_privileges(&mut self.config)
    }
}


/// # Directory Management
///
impl Process {
    /// Creates the cache directory.
    ///
    /// This will also change ownership of the directory if necessary.
    pub fn create_cache_dir(&self) -> Result<(), Failed> {
        if let Err(err) = fs::create_dir_all(&self.config.cache_dir) {
            error!("Fatal: failed to create cache directory {}: {}",
                self.config.cache_dir.display(), err
            );
            return Err(Failed)
        }
        ServiceImpl::prepare_cache_dir(&self.config)
    }
}


/// # Tokio Runtime
///
impl Process {
    /// Returns a Tokio runtime based on the configuration.
    pub fn runtime(&self) -> Result<Runtime, Failed> {
        Runtime::new().map_err(|err| {
            error!("Failed to create runtime: {}", err);
            Failed
        })
    }

    /// Runs a future to completion atop a Tokio runtime.
    pub fn block_on<F: Future>(&self, future: F) -> Result<F::Output, Failed> {
        Ok(self.runtime()?.block_on(future))
    }
}


//------------ LogOutput -----------------------------------------------------

#[derive(Debug)]
pub struct LogOutput {
    queue: Mutex<mpsc::Receiver<String>>,
    current: RwLock<(Bytes, DateTime<Utc>)>,
}

impl LogOutput {
    fn new() -> (mpsc::Sender<String>, Self) {
        let (tx, rx) = mpsc::channel();
        let res = LogOutput {
            queue: Mutex::new(rx),
            current: RwLock::new((
                "Initial validation ongoing. Please wait.".into(),
                Utc::now()
            ))
        };
        (tx, res)
    }

    pub fn start(&self) {
        self.current.write().expect("Log lock got poisoned").1 = Utc::now();
    }

    pub fn flush(&self) {
        let queue = self.queue.lock().expect("Log queue lock got poisoned");
        let started = self.current.read().expect("Log lock got poisoned").1;

        let mut content = format!(
            "Log from validation run started at {}\n\n", started
        );
        for item in queue.try_iter() {
            content.push_str(&item)
        }
        self.current.write().expect("Log lock got poisoned").0 = content.into();
    }

    pub fn get_output(&self) -> Bytes {
        self.current.read().expect("Log lock got poisoned").0.clone()
    }
}


//------------ Platform-dependent Service Implementation ---------------------

#[cfg(unix)]
use self::unix::ServiceImpl;

#[cfg(not(unix))]
use self::noop::ServiceImpl;


/// Unix “Service.”
///
/// This implementation is based on the _daemonize_ crate. See
/// https://github.com/knsd/daemonize for more information.
///
#[cfg(unix)]
mod unix {
    use std::env::set_current_dir;
    use std::ffi::CString;
    use std::os::unix::io::RawFd;
    use std::path::Path;
    use log::error;
    use nix::libc;
    use nix::fcntl::{flock, open, FlockArg, OFlag};
    use nix::unistd::{
        chown, chroot, fork, getpid, setgid, setuid, write, Gid, Uid
    };
    use nix::sys::stat::Mode;
    use crate::config::Config;
    use crate::error::Failed;

    #[derive(Debug, Default)]
    pub struct ServiceImpl {
        pid_file: Option<RawFd>,
        uid: Option<Uid>,
        gid: Option<Gid>,
    }

    impl ServiceImpl {
        pub fn new(_config: &Config) -> Self {
            ServiceImpl::default()
        }

        pub fn setup_service(
            &mut self, config: &Config, detach: bool
        ) -> Result<(), Failed> {
            if let Some(pid_file) = config.pid_file.as_ref() {
                self.create_pid_file(pid_file)?
            }
            if detach {
                self.perform_fork()?
            }
            if let Some(path) = config.working_dir.as_ref() {
                if let Err(err) = set_current_dir(&path) {
                    error!("Fatal: failed to set working directory {}: {}",
                        path.display(), err
                    );
                    return Err(Failed)
                }
            }
            // set_sid 
            // umask
            if detach {
                self.perform_fork()?
            }
            // redirect_standard_streams
            self.uid = Self::get_user(config)?;
            self.gid = Self::get_group(config)?;
            // chown_pid_file
            
            Ok(())
        }

        pub fn drop_privileges(
            self, config: &mut Config
        ) -> Result<(), Failed> {
            config.adjust_chroot_paths()?;
            if let Some(path) = config.chroot.as_ref() {
                if let Err(err) = chroot(path) {
                    error!("Fatal: cannot chroot to '{}': {}'",
                        path.display(), err
                    );
                    return Err(Failed)
                }
            }
            if let Some(gid) = self.gid {
                if let Err(err) = setgid(gid) {
                    error!("Fatal: failed to set group: {}", err);
                    return Err(Failed)
                }
            }
            if let Some(uid) = self.uid {
                if let Err(err) = setuid(uid) {
                    error!("Fatal: failed to set user: {}", err);
                    return Err(Failed)
                }
            }
            self.write_pid_file()?;

            Ok(())
        }

        fn create_pid_file(&mut self, path: &Path) -> Result<(), Failed> {
            let fd = match open(
                path,
                OFlag::O_WRONLY | OFlag::O_CREAT,
                Mode::from_bits_truncate(0o666)
            ) {
                Ok(fd) => fd,
                Err(err) => {
                    error!("Fatal: failed to create PID file {}: {}",
                        path.display(), err
                    );
                    return Err(Failed)
                }
            };
            if let Err(err) = flock(fd, FlockArg::LockExclusiveNonblock) {
                error!("Fatal: cannot lock PID file {}: {}",
                    path.display(), err
                );
                return Err(Failed)
            }
            self.pid_file = Some(fd);
            Ok(())
        }

        fn write_pid_file(&self) -> Result<(), Failed> {
            if let Some(pid_file) = self.pid_file {
                let pid = format!("{}", getpid());
                match write(pid_file, pid.as_bytes()) {
                    Ok(len) if len == pid.len() => {}
                    Ok(_) => {
                        error!(
                            "Fatal: failed to write PID to PID file: \
                             short write"
                        );
                        return Err(Failed)
                    }
                    Err(err) => {
                        error!(
                            "Fatal: failed to write PID to PID file: {}", err
                        );
                        return Err(Failed)
                    }
                }
            }
            Ok(())
        }

        fn perform_fork(&self) -> Result<(), Failed> {
            match unsafe { fork() } {
                Ok(res) => {
                    if res.is_parent() {
                        std::process::exit(0)
                    }
                    Ok(())
                }
                Err(err) => {
                    error!("Fatal: failed to detach: {}", err);
                    Err(Failed)
                }
            }
        }

        fn get_user(config: &Config) -> Result<Option<Uid>, Failed> {
            let name = match config.user.as_ref() {
                Some(name) => name,
                None => return Ok(None)
            };
            let cname = match CString::new(name.clone()) {
                Ok(name) => name,
                Err(_) => {
                    error!("Fatal: invalid user ID '{}'", name);
                    return Err(Failed)
                }
            };

            let uid = unsafe {
                let ptr = libc::getpwnam(cname.as_ptr() as *const libc::c_char);
                if ptr.is_null() {
                    None
                }
                else {
                    let s = &*ptr;
                    Some(s.pw_uid)
                }
            };
            match uid {
                Some(uid) => Ok(Some(Uid::from_raw(uid))),
                None => {
                    error!("Fatal: unknown user ID '{}'", name);
                    Err(Failed)
                }
            }
        }

        fn get_group(config: &Config) -> Result<Option<Gid>, Failed> {
            let name = match config.group.as_ref() {
                Some(name) => name,
                None => return Ok(None)
            };
            let cname = match CString::new(name.clone()) {
                Ok(name) => name,
                Err(_) => {
                    error!("Fatal: invalid user ID '{}'", name);
                    return Err(Failed)
                }
            };

            let gid = unsafe {
                let ptr = libc::getgrnam(cname.as_ptr() as *const libc::c_char);
                if ptr.is_null() {
                    None
                }
                else {
                    let s = &*ptr;
                    Some(s.gr_gid)
                }
            };
            match gid {
                Some(gid) => Ok(Some(Gid::from_raw(gid))),
                None => {
                    error!("Fatal: unknown group ID '{}'", name);
                    Err(Failed)
                }
            }
        }
     
        pub fn prepare_cache_dir(config: &Config) -> Result<(), Failed> {
            let uid = Self::get_user(config)?;
            let gid = Self::get_group(config)?;
            if uid.is_some() || gid.is_some() {
                if let Err(err) = chown(&config.cache_dir, uid, gid) {
                    error!(
                        "Fatal: failed to change ownership of cache dir \
                         {}: {}",
                        config.cache_dir.display(),
                        err
                    );
                    return Err(Failed)
                }
            }
            Ok(())
        }
    }
}

#[cfg(not(unix))]
mod noop {
    use crate::error::Failed;
    use crate::config::Config;

    pub struct ServiceImpl;

    impl ServiceImpl {
        pub fn new(_config: &Config) -> Self {
            ServiceImpl
        }

        pub fn setup_service(
            &mut self, _config: &Config, _detach: bool
        ) -> Result<(), Failed> {
            Ok(())
        }

        pub fn drop_privileges(
            self, _config: &mut Config
        ) -> Result<(), Failed> {
            Ok(())
        }
 
        pub fn prepare_cache_dir(_config: &Config) -> Result<(), Failed> {
            Ok(())
        }
    }
}
