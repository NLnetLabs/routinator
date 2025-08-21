//! Logging.

use std::{fmt, fs, io, mem, process, slice};
use std::io::Write;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use log::{LevelFilter, Record, error};
use crate::config::{Config, LogTarget};
use crate::error::Failed;
use crate::utils::date::{format_iso_date, format_local_iso_date};
use crate::utils::fmt::WriteOrPanic;
use crate::utils::sync::{Mutex, RwLock};

//------------ LogMessage ----------------------------------------------------

/// The data of a single logged item.
#[derive(Clone, Debug)]
pub struct LogMessage {
    pub when: DateTime<Utc>,
    pub level: log::Level,
    pub content: String,
}

impl LogMessage {
    fn from_record(record: &Record<'_>) -> Self {
        Self {
            when: Utc::now(),
            level: record.level(),
            content: record.args().to_string(),
        }
    }
}


//------------ LogBook -------------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct LogBook {
    /// The messages logged into this log book.
    messages: Vec<LogMessage>,
}

impl LogBook {
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
}

impl<'a> IntoIterator for &'a LogBook {
    type Item = &'a LogMessage;
    type IntoIter = slice::Iter<'a, LogMessage>;

    fn into_iter(self) -> Self::IntoIter {
        self.messages.iter()
    }
}


//------------ LogBookWriter -------------------------------------------------

#[derive(Clone, Debug)]
pub struct LogBookWriter {
    /// The book to write messages to.
    book: LogBook,

    /// The prefix for writing messages to the process log.
    ///
    /// If this is `None`, we don’t write to the process log.
    process_prefix: Option<String>,
}

impl LogBookWriter {
    /// Creates a new log book writer.
    ///
    /// If `process_prefix` is not `None`, the writer will also write to the
    /// process log, prefixing every line with the given format output. This
    /// is the prefix exactly, i.e., there will not be white space or
    /// characters separating the prefix from the actual log output. Such
    /// a separator has to be part of the prefix.
    pub fn new(process_prefix: Option<String>) -> Self {
        Self {
            book: Default::default(),
            process_prefix,
        }
    }

    pub fn append(&mut self, mut other: LogBookWriter) {
        self.book.messages.append(&mut other.book.messages);
    }

    pub fn sort(&mut self) {
        self.book.messages.sort_unstable_by_key(|message| message.when);
    }

    /// Converts the writer into the final log book.
    pub fn into_book(self) -> LogBook {
        self.book
    }

    pub fn log(&mut self, level: log::Level, args: fmt::Arguments<'_>) {
        self.log_record(
            &log::Record::builder().level(level).args(args).build()
        )
    }

    pub fn trace(&mut self, args: fmt::Arguments<'_>) {
        self.log(log::Level::Trace, args);
    }

    pub fn debug(&mut self, args: fmt::Arguments<'_>) {
        self.log(log::Level::Debug, args);
    }

    pub fn info(&mut self, args: fmt::Arguments<'_>) {
        self.log(log::Level::Info, args);
    }

    pub fn warn(&mut self, args: fmt::Arguments<'_>) {
        self.log(log::Level::Info, args);
    }

    pub fn error(&mut self, args: fmt::Arguments<'_>) {
        self.log(log::Level::Error, args);
    }

    /// Writes a log record.
    pub fn log_record(&mut self, record: &Record<'_>) {
        let logger = log::logger();

        // We use the level filter from the global log which should be set
        // up correctly according to our configuration.
        if !logger.enabled(record.metadata()) {
            return
        }
        self.book.messages.push(LogMessage::from_record(record));
        if let Some(prefix) = self.process_prefix.as_ref() {
            logger.log(
                &log::Record::builder()
                    .args(format_args!("{}{}", prefix, record.args()))
                    .metadata(record.metadata().clone())
                    .module_path(record.module_path())
                    .file(record.file())
                    .line(record.line())
                    .build()
            );
        }
    }
}


//------------ Logger --------------------------------------------------------

/// Format and write log messages.
pub struct Logger {
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
    /// Initialize logging.
    ///
    /// All diagnostic output of Routinator is done via logging, never to
    /// stderr directly. Thus, it is important to initialize logging before
    /// doing anything else that may result in such output. This function
    /// does exactly that. It sets a maximum log level of `warn`, leading
    /// only printing important information, and directs all logging to
    /// stderr.
    pub fn init() -> Result<(), Failed> {
        log::set_max_level(LevelFilter::Warn);
        if let Err(err) = log::set_logger(&GLOBAL_LOGGER) {
            eprintln!("Failed to initialize logger: {err}.\nAborting.");
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
        config: &Config,
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
        let logger = Logger::new(config, daemon, output)?;
        GLOBAL_LOGGER.switch(logger);
        log::set_max_level(config.log_level);
        Ok(res)
    }

    /// Rotates the log file if necessary.
    pub fn rotate_log() -> Result<(), Failed> {
        GLOBAL_LOGGER.rotate()
    }

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

    /// Configures the stderr target.
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
                    file, "[{}] [{}] {}",
                    format_local_iso_date(chrono::Local::now()),
                    record.level(),
                    record.args()
                )
            }
            LogBackend::Stderr{ ref mut stderr, timestamp } => {
                // We never fail when writing to stderr.
                if *timestamp {
                    let _ = write!(stderr, "[{}] ",
                        format_local_iso_date(chrono::Local::now()),
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
                eprintln!("Logging to syslog failed: {err}. Exiting.");
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

        // log::Level sorts more important first.

        if record.level() > log::Level::Error {
            // From rustls, only log errors.
            if module.starts_with("rustls") {
                return true
            }
        }
        if self.log_level >= log::LevelFilter::Trace {
            // Don’t filter anything else if we are in trace.
            return false
        }

        // Ignore these modules unless INFO or more important.
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
                error!("Cannot connect to syslog: {err}");
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
            log::Level::Trace => {
                // Syslog doesn’t have trace, use debug instead.
                self.0.debug(record.args())
            }
        }.map_err(|err| {
            match err {
                syslog::Error::Io(err) => err,
                err => io::Error::other(err),
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
    inner: OnceLock<Logger>,
}

/// The static for the log crate.
static GLOBAL_LOGGER: GlobalLogger = GlobalLogger::new();

impl GlobalLogger {
    /// Creates a new provisional logger.
    const fn new() -> Self {
        GlobalLogger { inner: OnceLock::new() }
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
            "Log from validation run started at {}\n\n",
            format_iso_date(Utc::now())
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

