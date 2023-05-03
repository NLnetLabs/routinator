//! Managing the process Routinator runs in.

use std::{fs, io, mem, process};
use std::future::Future;
use std::io::Write;
use std::net::TcpListener;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::sync::Arc;
use bytes::Bytes;
use chrono::Utc;
use log::{error, LevelFilter};
use once_cell::sync::OnceCell;
use tokio::runtime::Runtime;
use crate::config::{Config, LogTarget};
use crate::error::Failed;
use crate::utils::fmt::WriteOrPanic;
use crate::utils::sync::{Mutex, RwLock};


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
        if let Err(err) = log::set_logger(&GLOBAL_LOGGER) {
            eprintln!("Failed to initialize logger: {}.\nAborting.", err);
            return Err(Failed)
        }
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
        let (output, res) = if with_output {
            let output = LogOutput::new();
            (Some(output.0), Some(output.1))
        }
        else {
            (None, None)
        };
        let logger = Logger::new(&self.config, daemon, output)?;
        GLOBAL_LOGGER.switch(logger);
        log::set_max_level(self.config.log_level);
        Ok(res)
    }

    /// Rotates the log file if necessary.
    pub fn rotate_log(&self) -> Result<(), Failed> {
        GLOBAL_LOGGER.rotate()
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

    /// Returns the first listen socket passed into the process if available.
    pub fn get_listen_fd(&self) -> Result<Option<TcpListener>, Failed> {
        if self.config.systemd_listen {
            match listenfd::ListenFd::from_env().take_tcp_listener(0) {
                Ok(Some(res)) => Ok(Some(res)),
                Ok(None) => {
                    error!(
                        "Fatal: systemd_listen enabled \
                         but no socket available."
                    );
                    Err(Failed)
                }
                Err(err) => {
                    error!(
                        "Fatal: failed to get systemd_listen socket:  {}",
                        err
                    );
                    Err(Failed)
                }
            }
        }
        else {
            Ok(None)
        }
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


//------------ Logger --------------------------------------------------------

/// Format and write log messages.
struct Logger {
    /// Where to write messages to.
    target: Mutex<LogBackend>,

    /// An additional target for showing the log in the HTTP server.
    output: Option<Arc<Mutex<String>>>,

    /// The maximum log level.
    log_level: log::LevelFilter,
}

/// The actual target for logging
enum LogBackend {
    #[cfg(unix)]
    Syslog(SyslogLogger),
    File {
        file: fs::File,
        path: PathBuf,
    },
    Stderr {
        stderr: io::Stderr,
        timestamp: bool,
    }
}

impl Logger {
    /// Creates a new logger from config and additional information.
    fn new(
        config: &Config, daemon: bool, output: Option<Arc<Mutex<String>>>
    ) -> Result<Self, Failed> {
        let target = match config.log_target {
            #[cfg(unix)]
            LogTarget::Default(facility) => {
                if daemon { 
                    Self::new_syslog_target(facility)?
                }
                else {
                    Self::new_stderr_target(false)
                }
            }
            #[cfg(unix)]
            LogTarget::Syslog(facility) => {
                Self::new_syslog_target(facility)?
            }
            LogTarget::File(ref path) => {
                Self::new_file_target(path.clone())?
            }
            LogTarget::Stderr => {
                Self::new_stderr_target(daemon)
            }
        };
        Ok(Self {
            target: Mutex::new(target),
            output,
            log_level: config.log_level,
        })
    }

    /// Creates a syslog target.
    #[cfg(unix)]
    fn new_syslog_target(
        facility: syslog::Facility
    ) -> Result<LogBackend, Failed> {
        SyslogLogger::new(facility).map(LogBackend::Syslog)
    }

    fn new_file_target(path: PathBuf) -> Result<LogBackend, Failed> {
        Ok(LogBackend::File {
            file: match Self::open_log_file(&path) {
                Ok(file) => file,
                Err(err) => {
                    error!(
                        "Failed to open log file '{}': {}",
                        path.display(), err
                    );
                    return Err(Failed)
                }
            },
            path
        })
    }

    /// Opens a log file.
    fn open_log_file(path: &PathBuf) -> Result<fs::File, io::Error> {
        fs::OpenOptions::new().create(true).append(true).open(path)
    }

    /// Configures the stederr target.
    fn new_stderr_target(timestamp: bool) -> LogBackend {
        LogBackend::Stderr {
            stderr: io::stderr(),
            timestamp,
        }
    }

    /// Logs a message.
    ///
    /// This method may exit the whole process if logging fails.
    fn log(&self, record: &log::Record) {
        if self.should_ignore(record) {
            return;
        }

        if let Some(output) = self.output.as_ref() {
            writeln!(output.lock(), "{}", record.args());
        }

        if let Err(err) = self.try_log(record) {
            self.log_failure(err);
        }
    }

    /// Tries logging a message and returns an error if there is one.
    fn try_log(&self, record: &log::Record) -> Result<(), io::Error> {
        match self.target.lock().deref_mut() {
            #[cfg(unix)]
            LogBackend::Syslog(ref mut logger) => logger.log(record),
            LogBackend::File { ref mut file, .. } => {
                writeln!(
                    file, "{} [{}] {}",
                    chrono::Local::now().format("[%Y-%m-%d %H:%M:%S]"),
                    record.level(),
                    record.args()
                )
            }
            LogBackend::Stderr{ ref mut stderr, timestamp } => {
                // We never fail when writing to stderr.
                if *timestamp {
                    let _ = write!(stderr, "{}",
                        chrono::Local::now().format("[%Y-%m-%d %H:%M:%S]")
                    );
                }
                let _ = writeln!(
                    stderr, "[{}] {}", record.level(), record.args()
                );
                Ok(())
            }
        }
    }

    /// Handles an error that happened during logging.
    fn log_failure(&self, err: io::Error) -> ! {
        // We try to write a meaningful message to stderr and then abort.
        match self.target.lock().deref() {
            #[cfg(unix)]
            LogBackend::Syslog(_) => {
                eprintln!("Logging to syslog failed: {}. Exiting.", err);
            }
            LogBackend::File { ref path, .. } => {
                eprintln!(
                    "Logging to file {} failed: {}. Exiting.",
                    path.display(),
                    err
                );
            }
            LogBackend::Stderr { ..  } => {
                // We never fail when writing to stderr.
            }
        }
        process::exit(1)
    }

    /// Flushes the logging backend.
    fn flush(&self) {
        match self.target.lock().deref_mut() {
            #[cfg(unix)]
            LogBackend::Syslog(ref mut logger) => logger.flush(),
            LogBackend::File { ref mut file, .. } => {
                let _ = file.flush();
            }
            LogBackend::Stderr { ref mut stderr, .. } => {
                let _  = stderr.lock().flush();
            }
        }
    }

    /// Determines whether a log record should be ignored.
    ///
    /// This filters out messages by libraries that we don’t really want to
    /// see.
    fn should_ignore(&self, record: &log::Record) -> bool {
        let module = match record.module_path() {
            Some(module) => module,
            None => return false,
        };

        if record.level() > log::Level::Error {
            // Only log errors from rustls.
            if module.starts_with("rustls") {
                return true
            }
        }
        if self.log_level >= log::LevelFilter::Debug {
            // Don’t filter anything else if we are in debug or worse.
            return false
        }

        // Ignore these modules unless INFO or better.
        record.level() > log::Level::Info && (
               module.starts_with("tokio_reactor")
            || module.starts_with("hyper")
            || module.starts_with("reqwest")
            || module.starts_with("h2")
        )
    }

    /// Rotates the log target if necessary.
    ///
    /// This method exits the whole process when rotating fails.
    fn rotate(&self) -> Result<(), Failed> {
        if let LogBackend::File {
            ref mut file, ref path
        } = self.target.lock().deref_mut() {
            // This tries to open the file. If this fails, it writes a
            // message to both the old file and stderr and then exits.
            *file = match Self::open_log_file(path) {
                Ok(file) => file,
                Err(err) => {
                    let _ = writeln!(file,
                        "Re-opening log file {} failed: {}. Exiting.",
                        path.display(), err
                    );
                    eprintln!(
                        "Re-opening log file {} failed: {}. Exiting.",
                        path.display(), err
                    );
                    return Err(Failed)
                }
            }
        }
        Ok(())
    }
}


//------------ SyslogLogger --------------------------------------------------

/// A syslog logger.
///
/// This is essentially [`syslog::BasicLogger`] but that one keeps the logger
/// behind a mutex – which we already do – and doesn’t return error – which
/// we do want to see.
#[cfg(unix)]
struct SyslogLogger(
    syslog::Logger<syslog::LoggerBackend, syslog::Formatter3164>
);

#[cfg(unix)]
impl SyslogLogger {
    /// Creates a new syslog logger.
    fn new(facility: syslog::Facility) -> Result<Self, Failed> {
        let process = std::env::current_exe().ok().and_then(|path|
            path.file_name()
                .and_then(std::ffi::OsStr::to_str)
                .map(ToString::to_string)
        ).unwrap_or_else(|| String::from("routinator"));
        let formatter = syslog::Formatter3164 {
            facility,
            hostname: None,
            process,
            pid: std::process::id(),
        };
        let logger = syslog::unix(formatter.clone()).or_else(|_| {
            syslog::tcp(formatter.clone(), ("127.0.0.1", 601))
        }).or_else(|_| {
            syslog::udp(formatter, ("127.0.0.1", 0), ("127.0.0.1", 514))
        });
        match logger {
            Ok(logger) => Ok(Self(logger)),
            Err(err) => {
                error!("Cannot connect to syslog: {}", err);
                Err(Failed)
            }
        }
    }

    /// Tries logging.
    fn log(&mut self, record: &log::Record) -> Result<(), io::Error> {
        match record.level() {
            log::Level::Error => self.0.err(record.args()),
            log::Level::Warn => self.0.warning(record.args()),
            log::Level::Info => self.0.info(record.args()),
            log::Level::Debug => self.0.debug(record.args()),
            log::Level::Trace => self.0.debug(record.args()),
        }.map_err(|err| {
            match err.0 {
                syslog::ErrorKind::Io(err) => err,
                syslog::ErrorKind::Msg(err) => {
                    io::Error::new(io::ErrorKind::Other, err)
                }
                err => {
                    io::Error::new(io::ErrorKind::Other, format!("{}", err))
                }
            }
        })
    }

    /// Flushes the logger.
    ///
    /// Ignores any errors.
    fn flush(&mut self) {
        let _ = self.0.backend.flush();
    }
}


//------------ GlobalLogger --------------------------------------------------

/// The global logger.
///
/// A value of this type can go into a static. Until a proper logger is
/// installed, it just writes all log output to stderr.
struct GlobalLogger {
    /// The real logger. Can only be set once.
    inner: OnceCell<Logger>,
}

/// The static for the log crate.
static GLOBAL_LOGGER: GlobalLogger = GlobalLogger::new();

impl GlobalLogger {
    /// Creates a new provisional logger.
    const fn new() -> Self {
        GlobalLogger { inner: OnceCell::new() }
    }

    /// Switches to the proper logger.
    fn switch(&self, logger: Logger) {
        if self.inner.set(logger).is_err() {
            panic!("Tried to switch logger more than once.")
        }
    }

    /// Performs a log rotation.
    fn rotate(&self) -> Result<(), Failed> {
        match self.inner.get() {
            Some(logger) => logger.rotate(),
            None => Ok(()),
        }
    }
}


impl log::Log for GlobalLogger {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &log::Record<'_>) {
        match self.inner.get() {
            Some(logger) => logger.log(record),
            None => {
                let _ = writeln!(
                    io::stderr().lock(), "[{}] {}",
                    record.level(), record.args()
                );
            }
        }
    }

    fn flush(&self) {
        if let Some(logger) = self.inner.get() {
            logger.flush()
        }
    }
}


//------------ LogOutput -----------------------------------------------------

#[derive(Debug)]
pub struct LogOutput {
    queue: Arc<Mutex<String>>,
    current: RwLock<Bytes>,
}

impl LogOutput {
    fn new() -> (Arc<Mutex<String>>, Self) {
        let queue = Arc::new(Mutex::new(String::new()));
        let res = LogOutput {
            queue: queue.clone(),
            current: RwLock::new(
                "Initial validation ongoing. Please wait.".into(),
            )
        };
        (queue, res)
    }

    pub fn start(&self) {
        let new_string = format!(
            "Log from validation run started at {}\n\n", Utc::now()
        );
        let _ = mem::replace(self.queue.lock().deref_mut(), new_string);
    }

    pub fn flush(&self) {
        let content = mem::take(self.queue.lock().deref_mut());
        *self.current.write() = content.into();
    }

    pub fn get_output(&self) -> Bytes {
        self.current.read().clone()
    }
}


//------------ Platform-dependent Service Implementation ---------------------

#[cfg(unix)]
use self::unix::ServiceImpl;

#[cfg(not(unix))]
use self::noop::ServiceImpl;


/// Unix “Service.”
///
/// This implementation is based on the 
/// [daemonize](https://github.com/knsd/daemonize) crate.
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

            if let Some(path) = config.working_dir.as_ref().or(
                config.chroot.as_ref()
            ) {
                if let Err(err) = set_current_dir(path) {
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
                OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_TRUNC,
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
