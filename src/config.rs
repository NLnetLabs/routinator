//! Configuration.
//!
//! This module primarily contains the type [`Config`] that holds the
//! configuration for how Routinator keeps and updates the local repository
//! as well as for the RTR server.

use std::{env, fmt, fs, io};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
use clap::{App, Arg, ArgMatches};
#[cfg(unix)] use daemonize::Daemonize;
use dirs::home_dir;
use fern;
use log::LevelFilter;
#[cfg(unix)] use syslog::Facility;
use toml;
use crate::operation::Error;
use crate::repository::Repository;
use crate::slurm::LocalExceptions;


//------------ Defaults for Some Values --------------------------------------

/// Are we doing strict validation by default?
const DEFAULT_STRICT: bool = false;

/// The default number of rsync commands run in parallel.
const DEFAULT_RSYNC_COUNT: usize = 4;

/// The default refresh interval in seconds.
const DEFAULT_REFRESH: u64 = 3600;

/// The default RTR retry interval in seconds.
const DEFAULT_RETRY: u64 = 600;

/// The default RTR expire interval in seconds.
const DEFAULT_EXPIRE: u64 = 7200;

/// The default number of VRP diffs to keep.
const DEFAULT_HISTORY_SIZE: usize = 10;


//------------ Config --------------------------------------------------------  

/// Routinator configuration.
///
/// This type contains both the basic configuration of Routinator, such as
/// where to keep the repository and how to update it, and the configuration
/// for the RTR server.
///
/// All values are public and can be accessed directly.
///
/// The two functions [`config_args`] and [`rtrd_args`] can be used to create
/// the clap application. Its matches can then be used to create the basic
/// config via [`from_arg_matches`]. If the RTR server configuration is
/// necessary, it can be added via [`apply_rtrd_arg_matches`] from the RTR
/// server subcommand matches.
///
/// A few methods are provided that do mundane tasks that heavily depend on
/// the configuration.
///
/// [`config_args`]: #method.config_args
/// [`rtrd_args`]: #method.rtrd_args
/// [`from_arg_matches`]: #method.from_arg_matches
/// [`apply_rtrd_arg_matches`]: #method.apply_rtrd_arg_matches
#[derive(Clone, Debug)]
pub struct Config {
    /// Path to the directory that contains the repository cache.
    pub cache_dir: PathBuf,

    /// Path to the directory that contains the trust anchor locators.
    pub tal_dir: PathBuf,

    /// Paths to the local exceptions files.
    pub exceptions: Vec<PathBuf>,

    /// Should we do strict validation?
    pub strict: bool,

    /// The command to run for rsync.
    pub rsync_command: String,

    /// Arguments passed to rsync.
    pub rsync_args: Option<Vec<String>>,

    /// Number of parallel rsync commands.
    pub rsync_count: usize,

    /// Number of parallel validations.
    pub validation_threads: usize,

    /// The refresh interval for repository validation.
    pub refresh: Duration,

    /// The RTR retry inverval to be announced to a client.
    pub retry: Duration,

    /// The RTR expire time to be announced to a client.
    pub expire: Duration,

    /// How many diffs to keep in the history.
    pub history_size: usize,

    /// Addresses to listen on for RTR TCP transport connections.
    pub tcp_listen: Vec<SocketAddr>,

    /// Addresses to listen on for HTTP monitoring connectsion.
    pub http_listen: Vec<SocketAddr>,

    /// The log levels to be logged.
    pub log_level: LevelFilter,

    /// Should we log to stderr?
    pub log_target: LogTarget,

    /// The optional PID file for daemon mode.
    pub pid_file: Option<PathBuf>,

    /// The optional working directory for daemon mode.
    pub working_dir: Option<PathBuf>,

    /// The optional directory to chroot to in daemon mode.
    pub chroot: Option<PathBuf>,
}


impl Config {
    /// Adds the basic arguments to a clapp app.
    ///
    /// The function follows clap’s builder pattern: it takes an app,
    /// adds a bunch of arguments to it and returns it at the end.
    pub fn config_args<'a: 'b, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        app
        .arg(Arg::with_name("config")
             .short("c")
             .long("config")
             .takes_value(true)
             .value_name("PATH")
             .help("read base configuration from this file")
        )
        .arg(Arg::with_name("base-dir")
             .short("b")
             .long("base-dir")
             .value_name("DIR")
             .help("sets the base directory for cache and TALs")
             .takes_value(true)
        )
        .arg(Arg::with_name("repository-dir")
             .short("r")
             .long("repository-dir")
             .value_name("DIR")
             .help("sets the repository cache directory")
             .takes_value(true)
        )
        .arg(Arg::with_name("tal-dir")
             .short("t")
             .long("tal-dir")
             .value_name("DIR")
             .help("sets the TAL directory")
             .takes_value(true)
        )
        .arg(Arg::with_name("exceptions")
             .short("x")
             .long("exceptions")
             .value_name("FILE")
             .help("file with local exceptions (see RFC 8416 for format)")
             .takes_value(true)
             .multiple(true)
             .number_of_values(1)
        )
        .arg(Arg::with_name("strict")
             .long("strict")
             .help("parse RPKI data in strict mode")
        )
        .arg(Arg::with_name("rsync-command")
             .long("rsync-command")
             .value_name("COMMAND")
             .help("the command to run for rsync")
             .takes_value(true)
        )
        .arg(Arg::with_name("rsync-count")
             .long("rsync-count")
             .value_name("COUNT")
             .help("number of parallel rsync commands")
             .takes_value(true)
        )
        .arg(Arg::with_name("validation-threads")
             .long("validation-threads")
             .value_name("COUNT")
             .help("number of threads for validation")
             .takes_value(true)
        )
        .arg(Arg::with_name("verbose")
             .short("v")
             .long("verbose")
             .multiple(true)
             .help("log more information, twice for even more")
        )
        .arg(Arg::with_name("quiet")
             .short("q")
             .long("quiet")
             .multiple(true)
             .conflicts_with("verbose")
             .help("log less informatio, twice for no information")
        )
        .arg(Arg::with_name("syslog")
             .long("syslog")
             .help("log to syslog")
        )
        .arg(Arg::with_name("syslog-facility")
             .long("syslog-facility")
             .takes_value(true)
             .default_value("daemon")
             .help("facility to use for syslog logging")
        )
        .arg(Arg::with_name("logfile")
             .long("logfile")
             .takes_value(true)
             .value_name("PATH")
             .help("log to this file")
        )
    }

    /// Adds the relevant config args to the rtrd subcommand.
    ///
    /// Some of the options in the config only makes sense to have for the
    /// RTR server. Having them in the global part of the clap command line
    /// is confusing, so we stick to defaults unless we actually run the
    /// server. This function adds the relevant args to the subcommand.
    ///
    /// It follows clap’s builder pattern: It takes an app, adds a bunch of
    /// arguments to it, and returns it in the end.
    pub fn rtrd_args<'a: 'b, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        app
        .arg(Arg::with_name("refresh")
            .long("refresh")
            .value_name("SECONDS")
            .default_value("3600")
            .help("refresh interval in seconds")
        )
        .arg(Arg::with_name("retry")
            .long("retry")
            .value_name("SECONDS")
            .default_value("600")
            .help("RTR retry interval in seconds")
        )
        .arg(Arg::with_name("expire")
            .long("expire")
            .value_name("SECONDS")
            .default_value("600")
            .help("RTR expire interval in seconds")
        )
        .arg(Arg::with_name("history")
            .long("history")
            .value_name("COUNT")
            .default_value("10")
            .help("number of history items to keep in repeat mode")
        )
        .arg(Arg::with_name("listen")
            .short("l")
            .long("listen")
            .value_name("ADDR:PORT")
            .help("listen addr:port for RTR")
            .takes_value(true)
            .multiple(true)
            .number_of_values(1)
        )
        .arg(Arg::with_name("listen-http")
            .long("listen-http")
            .value_name("ADDR:PORT")
            .help("listen addr:port for monitoring")
            .takes_value(true)
            .multiple(true)
            .number_of_values(1)
        )
        .arg(Arg::with_name("pid-file")
            .long("pid-file")
            .value_name("PATH")
            .help("the file for keep the daemon process's PID in")
            .takes_value(true)
        )
        .arg(Arg::with_name("working-dir")
            .long("working-dir")
            .value_name("PATH")
            .help("the working directory of the daemon process")
            .takes_value(true)
        )
        .arg(Arg::with_name("chroot")
            .long("chroot")
            .value_name("PATH")
            .help("root directory for the daemon process")
            .takes_value(true)
        )
    }

    /// Creates a configuration from the command line arguments.
    ///
    /// The function will try to read a config file, either the one provided
    /// via the command line or the default, and apply all basic command line
    /// options to it.
    ///
    /// If you are trying to run the RTR server, you need to also apply the
    /// RTR server arguments via [`apply_rtrd_arg_matches`].
    ///
    /// This functions prints all its error messages directly to stderr.
    ///
    /// [`apply_rtrd_arg_matches`]: #method.apply_rtrd_arg_matches
    pub fn from_arg_matches(
        matches: &ArgMatches,
        cur_dir: &Path,
    ) -> Result<Self, Error> {
        let mut res = Self::create_base_config(
            Self::path_value_of(matches, "config", &cur_dir)
                .as_ref().map(AsRef::as_ref)
        )?;

        res.apply_arg_matches(matches, &cur_dir)?;

        Ok(res)
    }

    /// Applies the basic command line arguments to a configuration.
    ///
    /// The path arguments in `matches` will be interpreted relative to
    /// `cur_dir`.
    ///
    /// This functions prints all its error messages directly to stderr.
    fn apply_arg_matches(
        &mut self,
        matches: &ArgMatches,
        cur_dir: &Path,
    ) -> Result<(), Error> {
        // cache_dir
        if let Some(dir) = matches.value_of("repository-dir") {
            self.cache_dir = cur_dir.join(dir)
        }
        else if let Some(dir) = matches.value_of("base-dir") {
            self.cache_dir = cur_dir.join(dir).join("repository")
        }
        if self.cache_dir == Path::new("") {
            eprintln!(
                "Couldn’t determine default repository directory: \
                 no home directory.\n\
                 Please specify the repository directory with the -r option."
            );
            return Err(Error)
        }

        // tal_dir
        if let Some(dir) = matches.value_of("tal-dir") {
            self.tal_dir = cur_dir.join(dir)
        }
        else if let Some(dir) = matches.value_of("base-dir") {
            self.tal_dir = cur_dir.join(dir).join("tals")
        }
        if self.tal_dir == Path::new("") {
            eprintln!(
                "Couldn’t determine default TAL directory: \
                 no home directory.\n\
                 Please specify the repository directory with the -t option."
            );
            return Err(Error)
        }

        // expceptions
        if let Some(list) = matches.values_of("exceptions") {
            self.exceptions = list.map(|path| cur_dir.join(path)).collect()
        }

        // strict
        if matches.is_present("strict") {
            self.strict = true
        }

        // rsync_command
        if let Some(value) = matches.value_of("rsync-command") {
            self.rsync_command = value.into()
        }

        // rsync_count
        if let Some(value) = from_str_value_of(matches, "rsync-count")? {
            self.rsync_count = value
        }

        // validation_threads
        if let Some(value) = from_str_value_of(matches, "validation-threads")? {
            self.validation_threads = value
        }

        // log_level
        match (matches.occurrences_of("verbose"),
                                            matches.occurrences_of("quiet")) {
            // This assumes that -v and -q are conflicting.
            (0, 0) => { }
            (1, 0) => self.log_level = LevelFilter::Info,
            (_, 0) => self.log_level = LevelFilter::Debug,
            (0, 1) => self.log_level = LevelFilter::Error,
            (0, _) => self.log_level = LevelFilter::Off,
            _ => { }
        }

        // log_target
        self.apply_log_matches(matches, cur_dir)?;

        Ok(())
    }

    #[cfg(unix)]
    fn apply_log_matches(
        &mut self,
        matches: &ArgMatches,
        cur_dir: &Path,
    ) -> Result<(), Error> {
        if matches.is_present("syslog") {
            self.log_target = LogTarget::Syslog(
                match Facility::from_str(
                               matches.value_of("syslog-facility").unwrap()) {
                    Ok(value) => value,
                    Err(_) => {
                        eprintln!("Invalid value for syslog-facility.");
                        return Err(Error);
                    }
                }
            )
        }
        else if let Some(file) = matches.value_of("logfile") {
            if file == "-" {
                self.log_target = LogTarget::Stderr
            }
            else {
                self.log_target = LogTarget::File(cur_dir.join(file))
            }
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn apply_log_matches(
        &mut self,
        matches: &ArgMatches,
        cur_dir: &Path,
    ) -> Result<(), Error> {
        if let Some(file) = matches.value_of("logfile") {
            if file == "-" {
                self.log_target = LogTarget::Stderr
            }
            else {
                self.log_target = LogTarget::File(cur_dir.join(file))
            }
        }
        Ok(())
    }


    /// Applies the RTR server command line arguments to a config.
    ///
    /// This functions prints all its error messages directly to stderr.
    pub fn apply_rtrd_arg_matches(
        &mut self,
        matches: &ArgMatches,
        cur_dir: &Path,
    ) -> Result<(), Error> {
        // refresh
        if let Some(value) = from_str_value_of(matches, "refresh")? {
            self.refresh = Duration::from_secs(value)
        }

        // retry
        if let Some(value) = from_str_value_of(matches, "retry")? {
            self.retry = Duration::from_secs(value)
        }

        // expire
        if let Some(value) = from_str_value_of(matches, "expire")? {
            self.expire = Duration::from_secs(value)
        }

        // history_size
        if let Some(value) = from_str_value_of(matches, "history")? {
            self.history_size = value
        }

        // tcp_listen
        if let Some(list) = matches.values_of("listen") {
            self.tcp_listen = Vec::new();
            for value in list.into_iter() {
                match SocketAddr::from_str(value) {
                    Ok(some) => self.tcp_listen.push(some),
                    Err(_) => {
                        eprintln!("Invalid value for listen: {}", value);
                        return Err(Error);
                    }
                }
            }
        }

        // http_listen
        if let Some(list) = matches.values_of("listen-http") {
            self.http_listen = Vec::new();
            for value in list.into_iter() {
                match SocketAddr::from_str(value) {
                    Ok(some) => self.http_listen.push(some),
                    Err(_) => {
                        eprintln!("Invalid value for listen-http: {}", value);
                        return Err(Error);
                    }
                }
            }
        }


        // pid_file
        if let Some(pid_file) = matches.value_of("pid-file") {
            self.pid_file = Some(cur_dir.join(pid_file))
        }

        // working_dir
        if let Some(working_dir) = matches.value_of("working-dir") {
            self.working_dir = Some(cur_dir.join(working_dir))
        }

        // chroot
        if let Some(chroot) = matches.value_of("chroot") {
            self.chroot = Some(cur_dir.join(chroot))
        }

        Ok(())
    }

    /// Creates and returns the repository for this configuration.
    ///
    /// This will create the cache and TAL directories if they don’t exist
    /// and, in this case, populate the TAL directoy with the default set
    /// of TALS.
    ///
    /// If `update` is `false`, all updates in the respository are disabled.
    ///
    /// This functions prints all its error messages directly to stderr.
    pub fn create_repository(
        &self,
        extra_output: bool,
        update: bool,
    ) -> Result<Repository, Error> {
        self.prepare_dirs()?;
        Repository::new(self, extra_output, update)
    }

    /// Loads the local exceptions for this configuration.
    ///
    /// This function logs its error messages.
    pub fn load_exceptions(
        &self,
        extra_info: bool
    ) -> Result<LocalExceptions, Error> {
        let mut res = LocalExceptions::empty();
        let mut ok = true;
        for path in &self.exceptions {
            if let Err(err) = res.extend_from_file(path, extra_info) {
                error!(
                    "Failed to load exceptions file {}: {}",
                    path.display(), err
                );
                ok = false;
            }
        }
        if ok {
            Ok(res)
        }
        else {
            Err(Error)
        }
    }

    /// Switches logging to the configured target.
    ///
    /// If `daemon` is `true`, the default target is syslog, otherwise it is
    /// stderr.
    ///
    /// This functions prints all its error messages directly to stderr.
    #[allow(unused_variables)] // for cfg(not(unix))
    pub fn switch_logging(&self, daemon: bool) -> Result<(), Error> {
        match self.log_target {
            #[cfg(unix)]
            LogTarget::Default(fac) => {
                if daemon {
                    if let Err(err) = syslog::init(fac, self.log_level, None) {
                        eprintln!("Failed to init syslog: {}", err);
                        return Err(Error)
                    }
                }
                else {
                    self.switch_stderr_logging()?;
                }
            }
            #[cfg(unix)]
            LogTarget::Syslog(fac) => {
                if let Err(err) = syslog::init(fac, self.log_level, None) {
                    eprintln!("Failed to init syslog: {}", err);
                    return Err(Error)
                }
            }
            LogTarget::Stderr => {
                self.switch_stderr_logging()?;
            }
            LogTarget::File(ref path) => {
                let file = match fern::log_file(path) {
                    Ok(file) => file,
                    Err(err) => {
                        eprintln!(
                            "Failed to open log file '{}': {}",
                            path.display(), err
                        );
                        return Err(Error)
                    }
                };
                let dispatch = fern::Dispatch::new()
                    .level(self.log_level)
                    .chain(file);
                if let Err(err) = dispatch.apply() {
                    eprintln!("Failed to init file logging: {}", err);
                    return Err(Error)
                }
            }
        }
        Ok(())
    }

    /// Switches to stderr logging.
    fn switch_stderr_logging(&self) -> Result<(), Error> {
        let dispatch = fern::Dispatch::new()
            .level(self.log_level)
            .chain(io::stderr());
        if let Err(err) = dispatch.apply() {
            eprintln!("Failed to init stderr logging: {}", err);
            return Err(Error)
        }
        Ok(())
    }

    /// Returns a path value in arg matches.
    ///
    /// This expands a relative path based on the given directory.
    fn path_value_of(
        matches: &ArgMatches,
        key: &str,
        dir: &Path
    ) -> Option<PathBuf> {
        matches.value_of(key).map(|path| dir.join(path))
    }

    /// Creates the correct base configuration for the given config file.
    /// 
    /// If no config path is given, tries to read the default config in
    /// `$HOME/.routinator.conf`. If that doesn’t exist, creates a default
    /// config.
    ///
    /// This functions prints all its error messages directly to stderr.
    fn create_base_config(path: Option<&Path>) -> Result<Self, Error> {
        let file = match path {
            Some(path) => {
                match ConfigFile::read(&path)? {
                    Some(file) => file,
                    None => {
                        eprintln!(
                            "Cannot read config file {}", path.display()
                        );
                        return Err(Error);
                    }
                }
            }
            None => {
                match home_dir() {
                    Some(dir) => match ConfigFile::read(
                                            &dir.join(".routinator.conf"))? {
                        Some(file) => file,
                        None => return Ok(Self::default()),
                    }
                    None => return Ok(Self::default())
                }
            }
        };
        Self::from_config_file(file)
    }

    /// Creates a base config from a config file.
    ///
    /// This functions prints all its error messages directly to stderr.
    fn from_config_file(mut file: ConfigFile) -> Result<Self, Error> {
        let log_target = Self::log_target_from_config_file(&mut file)?;
        let res = Config {
            cache_dir: file.take_mandatory_path("repository-dir")?,
            tal_dir: file.take_mandatory_path("tal-dir")?,
            exceptions: file.take_path_array("exceptions")?,
            strict: file.take_bool("strict")?.unwrap_or(false),
            rsync_command: {
                file.take_string("rsync-command")?
                    .unwrap_or_else(|| "rsync".into())
            },
            rsync_args: file.take_opt_string_array("rsync-args")?,
            rsync_count: {
                file.take_small_usize("rsync-count")?
                    .unwrap_or(DEFAULT_RSYNC_COUNT)
            },
            validation_threads: {
                file.take_small_usize("validation-threads")?
                    .unwrap_or(::num_cpus::get())
            },
            refresh: {
                Duration::from_secs(
                    file.take_u64("refresh")?.unwrap_or(DEFAULT_REFRESH)
                )
            },
            retry: {
                Duration::from_secs(
                    file.take_u64("retry")?.unwrap_or(DEFAULT_REFRESH)
                )
            },
            expire: {
                Duration::from_secs(
                    file.take_u64("expire")?.unwrap_or(DEFAULT_REFRESH)
                )
            },
            history_size: {
                file.take_small_usize("history-size")?
                    .unwrap_or(DEFAULT_HISTORY_SIZE)
            },
            tcp_listen: file.take_from_str_array("listen-tcp")?,
            http_listen: file.take_from_str_array("listen-http")?,
            log_level: {
                file.take_from_str("log-level")?.unwrap_or(LevelFilter::Warn)
            },
            log_target,
            pid_file: file.take_path("pid-file")?,
            working_dir: file.take_path("working-dir")?,
            chroot: file.take_path("chroot")?,
        };
        file.check_exhausted()?;
        Ok(res)
    }

    /// Determines the logging target from the config file.
    #[cfg(unix)]
    fn log_target_from_config_file(
        file: &mut ConfigFile
    ) -> Result<LogTarget, Error> {
        let facility = file.take_string("syslog-facility")?;
        let facility = facility.as_ref().map(AsRef::as_ref)
                               .unwrap_or("daemon");
        let facility = match Facility::from_str(facility) {
            Ok(value) => value,
            Err(_) => {
                eprintln!(
                    "Error in config file {}: \
                     invalid syslog-facility.",
                     file.path.display()
                );
                return Err(Error);
            }
        };
        let log_target = file.take_string("log")?;
        let log_file = file.take_path("log-file")?;
        match log_target.as_ref().map(AsRef::as_ref) {
            Some("default") | None => Ok(LogTarget::Default(facility)),
            Some("syslog") => Ok(LogTarget::Syslog(facility)),
            Some("stderr") =>  Ok(LogTarget::Stderr),
            Some("file") => {
                match log_file {
                    Some(file) => Ok(LogTarget::File(file)),
                    None => {
                        eprintln!(
                            "Error in config file {}: \
                             log target \"file\" requires 'log-file' value.",
                             file.path.display()
                        );
                        Err(Error)
                    }
                }
            }
            Some(value) => {
                eprintln!(
                    "Error in config file {}: \
                     invalid log target '{}'",
                     file.path.display(),
                     value
                );
                Err(Error)
            }
        }
    }

    /// Determines the logging target from the config file.
    #[cfg(not(unix))]
    fn log_target_from_config_file(
        file: &mut ConfigFile
    ) -> Result<LogTarget, Error> {
        let log_target = file.take_string("log")?;
        let log_file = file.take_path("log-file")?;
        match log_target.as_ref().map(AsRef::as_ref) {
            Some("default") | Some("stderr") | None => Ok(LogTarget::Stderr),
            Some("file") => {
                match log_file {
                    Some(file) => Ok(LogTarget::File(file)),
                    None => {
                        eprintln!(
                            "Error in config file {}: \
                             log target \"file\" requires 'log-file' value.",
                             file.path.display()
                        );
                        Err(Error)
                    }
                }
            }
            Some(value) => {
                eprintln!(
                    "Error in config file {}: \
                     invalid log target '{}'",
                     file.path.display(),
                     value
                );
                Err(Error)
            }
        }
    }

    /// Creates a default config with the given paths.
    fn default_with_paths(cache_dir: PathBuf, tal_dir: PathBuf) -> Self {
        Config {
            cache_dir,
            tal_dir,
            exceptions: Vec::new(),
            strict: DEFAULT_STRICT,
            rsync_command: "rsync".into(),
            rsync_args: None,
            rsync_count: DEFAULT_RSYNC_COUNT,
            validation_threads: ::num_cpus::get(),
            refresh: Duration::from_secs(DEFAULT_REFRESH),
            retry: Duration::from_secs(DEFAULT_RETRY),
            expire: Duration::from_secs(DEFAULT_EXPIRE),
            history_size: DEFAULT_HISTORY_SIZE,
            tcp_listen: vec![
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 3323)
            ],
            http_listen: Vec::new(),
            log_level: LevelFilter::Warn,
            log_target: LogTarget::default(),
            pid_file: None,
            working_dir: None,
            chroot: None
        }
    }


    /// Prepares and returns the cache dir and tal dir.
    ///
    /// If the cache dir doesn’t exist, tries to create it. If the tal dir
    /// doesn’t exist, tries to create it and populate it with the default
    /// set of TALs.
    ///
    /// This method prints all its error messages directly to stderr.
    fn prepare_dirs(&self) -> Result<(), Error> {
        if let Err(err) = fs::create_dir_all(&self.cache_dir) {
            eprintln!(
                "Can't create repository directory {}: {}.\nAborting.",
                self.cache_dir.display(), err
            );
            return Err(Error);
        }
        if fs::read_dir(&self.tal_dir).is_err() {
            if let Err(err) = fs::create_dir_all(&self.tal_dir) {
                eprintln!(
                    "Can't create TAL directory {}: {}.\nAborting.",
                    self.tal_dir.display(), err
                );
                return Err(Error);
            }
            for (name, content) in &DEFAULT_TALS {
                let mut file = match fs::File::create(self.tal_dir.join(name)) {
                    Ok(file) => file,
                    Err(err) => {
                        eprintln!(
                            "Can't create TAL file {}: {}.\n Aborting.",
                            self.tal_dir.join(name).display(), err
                        );
                        return Err(Error);
                    }
                };
                if let Err(err) = file.write_all(content) {
                    eprintln!(
                        "Can't create TAL file {}: {}.\n Aborting.",
                        self.tal_dir.join(name).display(), err
                    );
                    return Err(Error);
                }
            }
        }
        Ok(())
    }

    /// Returns a daemonizer based on the configuration.
    ///
    /// This also changes the paths in the configuration if `chroot` is set.
    /// As this may fail, this whole method may fail.
    ///
    /// The method prints any error messages to stderr.
    #[cfg(unix)]
    pub fn daemonize(&mut self) -> Result<Daemonize<()>, Error> {
        if let Some(ref chroot) = self.chroot {
            self.cache_dir = match self.cache_dir.strip_prefix(chroot) {
                Ok(dir) => dir.into(),
                Err(_) => {
                    eprintln!(
                        "Fatal: Repository directory {} \
                         not under chroot {}.",
                         self.cache_dir.display(), chroot.display()
                    );
                    return Err(Error)
                }
            };
            self.tal_dir = match self.tal_dir.strip_prefix(chroot) {
                Ok(dir) => dir.into(),
                Err(_) => {
                    eprintln!(
                        "Fatal: TAL directory {} not under chroot {}.",
                         self.tal_dir.display(), chroot.display()
                    );
                    return Err(Error)
                }
            };
            for item in &mut self.exceptions {
                *item = match item.strip_prefix(chroot) {
                    Ok(path) => path.into(),
                    Err(_) => {
                        eprintln!(
                            "Fatal: Exception file {} not under chroot {}.",
                             item.display(), chroot.display()
                        );
                        return Err(Error)
                    }
                }
            }
            if let LogTarget::File(ref mut file) = self.log_target {
                *file = match file.strip_prefix(chroot) {
                    Ok(path) => path.into(),
                    Err(_) => {
                        eprintln!(
                            "Fatal: Log file {} not under chroot {}.",
                             file.display(), chroot.display()
                        );
                        return Err(Error)
                    }
                };
            }
            // XXX I _think_ the pid_file remains where it is outside the
            //     chroot?
            if let Some(ref mut dir) = self.working_dir {
                *dir = match dir.strip_prefix(chroot) {
                    Ok(path) => path.into(),
                    Err(_) => {
                        eprintln!(
                            "Fatal: working directory {} not under chroot {}.",
                             dir.display(), chroot.display()
                        );
                        return Err(Error)
                    }
                }
            }
        }
        let mut res = Daemonize::new();
        if let Some(ref pid_file) = self.pid_file {
            res = res.pid_file(pid_file)
        }
        if let Some(ref dir) = self.working_dir {
            res = res.working_directory(dir)
        }
        if let Some(ref chroot) = self.chroot {
            res = res.chroot(chroot)
        }
        Ok(res)
    }

    /// Returns a TOML representation of the config.
    pub fn to_toml(&self) -> toml::Value {
        let mut res = toml::value::Table::new();
        res.insert(
            "repository-dir".into(),
            self.cache_dir.display().to_string().into()
        );
        res.insert(
            "tal-dir".into(),
            self.tal_dir.display().to_string().into()
        );
        res.insert(
            "exceptions".into(),
            toml::Value::Array(
                self.exceptions.iter()
                    .map(|p| p.display().to_string().into())
                    .collect()
            )
        );
        res.insert("strict".into(), self.strict.into());
        res.insert("rsync-command".into(), self.rsync_command.clone().into());
        if let Some(ref args) = self.rsync_args {
            res.insert(
                "rsync-args".into(),
                toml::Value::Array(
                    args.iter().map(|a| a.clone().into()).collect()
                )
            );
        }
        res.insert("rsync-count".into(), (self.rsync_count as i64).into());
        res.insert(
            "validation-threads".into(),
            (self.validation_threads as i64).into()
        );
        res.insert("refresh".into(), (self.refresh.as_secs() as i64).into());
        res.insert("retry".into(), (self.retry.as_secs() as i64).into());
        res.insert("expire".into(), (self.expire.as_secs() as i64).into());
        res.insert("history-size".into(), (self.history_size as i64).into());
        res.insert(
            "listen-tcp".into(),
            toml::Value::Array(
                self.tcp_listen.iter().map(|a| a.to_string().into()).collect()
            )
        );
        res.insert("log-level".into(), self.log_level.to_string().into());
        match self.log_target {
            #[cfg(unix)]
            LogTarget::Default(facility) => {
                res.insert("log".into(), "default".into());
                res.insert(
                    "syslog-facility".into(),
                    facility_to_string(facility).into()
                );
            }
            #[cfg(unix)]
            LogTarget::Syslog(facility) => {
                res.insert("log".into(), "syslog".into());
                res.insert(
                    "syslog-facility".into(),
                    facility_to_string(facility).into()
                );
            }
            LogTarget::Stderr => {
                res.insert("log".into(), "stderr".into());
            }
            LogTarget::File(ref file) => {
                res.insert("log".into(), "file".into());
                res.insert(
                    "log-file".into(),
                    file.display().to_string().into()
                );
            }
        }
        if let Some(ref file) = self.pid_file {
            res.insert("pid-file".into(), file.display().to_string().into());
        }
        if let Some(ref dir) = self.working_dir {
            res.insert("working-dir".into(), dir.display().to_string().into());
        }
        if let Some(ref dir) = self.chroot {
            res.insert("chroot".into(), dir.display().to_string().into());
        }
        res.into()
    }
}


//--- Default

impl Default for Config {
    fn default() -> Self {
        match home_dir() {
            Some(dir) => {
                let base = dir.join(".rpki-cache");
                Config::default_with_paths(
                    base.join("repository"), 
                    base.join("tals")
                )
            }
            None => {
                Config::default_with_paths(
                    PathBuf::from(""), PathBuf::from("")
                )
            }
        }
    }
}


//--- Display

impl fmt::Display for Config {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_toml())
    }
}


//------------ LogTarget -----------------------------------------------------

/// The target to log to.
#[derive(Clone, Debug)]
pub enum LogTarget {
    /// Default.
    ///
    /// Logs to `Syslog(facility)` in daemon mode and `Stderr` otherwise.
    #[cfg(unix)]
    Default(Facility),

    /// Syslog.
    ///
    /// The argument is the syslog facility to use.
    #[cfg(unix)]
    Syslog(Facility),

    /// Stderr.
    Stderr,

    /// A file.
    ///
    /// The argument is the file name.
    File(PathBuf)
}


//--- Default

#[cfg(unix)]
impl Default for LogTarget {
    fn default() -> Self {
        LogTarget::Default(Facility::LOG_DAEMON)
    }
}

#[cfg(not(unix))]
impl Default for LogTarget {
    fn default() -> Self {
        LogTarget::Stderr
    }
}


//--- PartialEq and Eq

impl PartialEq for LogTarget {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            #[cfg(unix)]
            (&LogTarget::Default(s), &LogTarget::Default(o)) => {
                (s as usize) == (o as usize)
            }
            #[cfg(unix)]
            (&LogTarget::Syslog(s), &LogTarget::Syslog(o)) => {
                (s as usize) == (o as usize)
            }
            (&LogTarget::Stderr, &LogTarget::Stderr) => true,
            (&LogTarget::File(ref s), &LogTarget::File(ref o)) => {
                s == o
            }
            _ => false
        }
    }
}

impl Eq for LogTarget { }


//------------ ConfigFile ----------------------------------------------------

/// The content of a config file.
///
/// This is a thin wrapper around `toml::Table` to make dealing with it more
/// convenient.
///
/// All functions and methods that can return an `Error` print their error
/// messages to stderr.
#[derive(Clone, Debug)]
struct ConfigFile {
    /// The content of the file.
    content: toml::value::Table,

    /// The path to the config file.
    path: PathBuf,

    /// The directory we found the file in.
    ///
    /// This is used in relative paths.
    dir: PathBuf,
}

impl ConfigFile {
    /// Reads the config file at the given path.
    ///
    /// If there is no such file, returns `None`. If there is a file but it
    /// is broken, aborts.
    fn read(path: &Path) -> Result<Option<Self>, Error> {
        let mut file = match fs::File::open(path) {
            Ok(file) => file,
            Err(_) => return Ok(None)
        };
        let mut config = String::new();
        if let Err(err) = file.read_to_string(&mut config) {
            eprintln!(
                "Failed to read config file {}: {}",
                path.display(), err
            );
            return Err(Error);
        }
        Self::parse(&config, path).map(Some)
    }

    /// Parses the content of the file from a string.
    fn parse(content: &str, path: &Path) -> Result<Self, Error> {
        let content = match toml::from_str(content) {
            Ok(toml::Value::Table(content)) => content,
            Ok(_) => {
                eprintln!(
                    "Failed to parse config file {}: Not a mapping.",
                    path.display()
                );
                return Err(Error);
            }
            Err(err) => {
                eprintln!(
                    "Failed to parse config file {}: {}",
                    path.display(), err
                );
                return Err(Error);
            }
        };
        let dir = if path.is_relative() {
            path.join(match env::current_dir() {
                Ok(dir) => dir,
                Err(err) => {
                    eprintln!(
                        "Fatal: Can't determine current directory: {}.",
                        err
                    );
                    return Err(Error);
                }
            }).parent().unwrap().into() // a file always has a parent
        }
        else {
            path.parent().unwrap().into()
        };
        Ok(ConfigFile {
            content,
            path: path.into(),
            dir: dir
        })
    }

    fn take_bool(&mut self, key: &str) -> Result<Option<bool>, Error> {
        match self.content.remove(key) {
            Some(value) => {
                if let toml::Value::Boolean(res) = value {
                    Ok(Some(res))
                }
                else {
                    eprintln!(
                        "Error in config file {}: \
                         '{}' expected to be a boolean.",
                        self.path.display(), key
                    );
                    Err(Error)
                }
            }
            None => Ok(None)
        }
    }
    
    fn take_u64(&mut self, key: &str) -> Result<Option<u64>, Error> {
        match self.content.remove(key) {
            Some(value) => {
                if let toml::Value::Integer(res) = value {
                    if res < 0 {
                        eprintln!(
                            "Error in config file {}: \
                            '{}' expected to be a positive integer.",
                            self.path.display(), key
                        );
                        Err(Error)
                    }
                    else {
                        Ok(Some(res as u64))
                    }
                }
                else {
                    eprintln!(
                        "Error in config file {}: \
                         '{}' expected to be an integer.",
                        self.path.display(), key
                    );
                    Err(Error)
                }
            }
            None => Ok(None)
        }
    }

    fn take_small_usize(&mut self, key: &str) -> Result<Option<usize>, Error> {
        match self.content.remove(key) {
            Some(value) => {
                if let toml::Value::Integer(res) = value {
                    if res < 0 {
                        eprintln!(
                            "Error in config file {}: \
                            '{}' expected to be a positive integer.",
                            self.path.display(), key
                        );
                        Err(Error)
                    }
                    else if res > ::std::u16::MAX.into() {
                        eprintln!(
                            "Error in config file {}: \
                            value for '{}' is too large.",
                            self.path.display(), key
                        );
                        Err(Error)
                    }
                    else {
                        Ok(Some(res as usize))
                    }
                }
                else {
                    eprintln!(
                        "Error in config file {}: \
                         '{}' expected to be a integer.",
                        self.path.display(), key
                    );
                    Err(Error)
                }
            }
            None => Ok(None)
        }
    }

    fn take_string(&mut self, key: &str) -> Result<Option<String>, Error> {
        match self.content.remove(key) {
            Some(value) => {
                if let toml::Value::String(res) = value {
                    Ok(Some(res))
                }
                else {
                    eprintln!(
                        "Error in config file {}: \
                         '{}' expected to be a string.",
                        self.path.display(), key
                    );
                    Err(Error)
                }
            }
            None => Ok(None)
        }
    }

    fn take_from_str<T>(&mut self, key: &str) -> Result<Option<T>, Error>
    where T: FromStr, T::Err: fmt::Display {
        match self.take_string(key)? {
            Some(value) => {
                match T::from_str(&value) {
                    Ok(some) => Ok(Some(some)),
                    Err(err) => {
                        eprintln!(
                            "Error in config file {}: \
                             illegal value in '{}': {}.",
                            self.path.display(), key, err
                        );
                        Err(Error)
                    }
                }
            }
            None => Ok(None)
        }
    }

    fn take_path(&mut self, key: &str) -> Result<Option<PathBuf>, Error> {
        self.take_string(key).map(|opt| opt.map(|path| self.dir.join(path)))
    }

    fn take_mandatory_path(&mut self, key: &str) -> Result<PathBuf, Error> {
        match self.take_path(key)? {
            Some(res) => Ok(res),
            None => {
                eprintln!(
                    "Error in config file {}: missing required '{}'.",
                    self.path.display(), key
                );
                Err(Error)
            }
        }
    }

    fn take_path_array(&mut self, key: &str) -> Result<Vec<PathBuf>, Error> {
        match self.content.remove(key) {
            Some(::toml::Value::Array(vec)) => {
                let mut res = Vec::new();
                for value in vec.into_iter() {
                    if let ::toml::Value::String(value) = value {
                        res.push(self.dir.join(value))
                    }
                    else {
                        eprintln!(
                            "Error in config file {}: \
                            '{}' expected to be a array of paths.",
                            self.path.display(),
                            key
                        );
                        return Err(Error);
                    }
                }
                Ok(res)
            }
            Some(_) => {
                eprintln!(
                    "Error in config file {}: \
                     '{}' expected to be a array of paths.",
                    self.path.display(), key
                );
                Err(Error)
            }
            None => Ok(Vec::new())
        }
    }

    fn take_opt_string_array(
        &mut self,
        key: &str
    ) -> Result<Option<Vec<String>>, Error> {
        match self.content.remove(key) {
            Some(::toml::Value::Array(vec)) => {
                let mut res = Vec::new();
                for value in vec.into_iter() {
                    if let ::toml::Value::String(value) = value {
                        res.push(value)
                    }
                    else {
                        eprintln!(
                            "Error in config file {}: \
                            '{}' expected to be a array of strings.",
                            self.path.display(),
                            key
                        );
                        return Err(Error);
                    }
                }
                Ok(Some(res))
            }
            Some(_) => {
                eprintln!(
                    "Error in config file {}: \
                     '{}' expected to be a array of strings.",
                    self.path.display(), key
                );
                Err(Error)
            }
            None => Ok(None)
        }
    }

    fn take_from_str_array<T>(&mut self, key: &str) -> Result<Vec<T>, Error>
    where T: FromStr, T::Err: fmt::Display {
        match self.content.remove(key) {
            Some(::toml::Value::Array(vec)) => {
                let mut res = Vec::new();
                for value in vec.into_iter() {
                    if let ::toml::Value::String(value) = value {
                        match T::from_str(&value) {
                            Ok(value) => res.push(value),
                            Err(err) => {
                                eprintln!(
                                    "Error in config file {}: \
                                     Invalid value in '{}': {}",
                                    self.path.display(), key, err
                                );
                                return Err(Error)
                            }
                        }
                    }
                    else {
                        eprintln!(
                            "Error in config file {}: \
                            '{}' expected to be a array of strings.",
                            self.path.display(),
                            key
                        );
                        return Err(Error)
                    }
                }
                Ok(res)
            }
            Some(_) => {
                eprintln!(
                    "Error in config file {}: \
                     '{}' expected to be a array of strings.",
                    self.path.display(), key
                );
                Err(Error)
            }
            None => Ok(Vec::new())
        }
    }

    fn check_exhausted(&self) -> Result<(), Error> {
        if !self.content.is_empty() {
            print!(
                "Error in config file {}: Unknown settings ",
                self.path.display()
            );
            let mut first = true;
            for key in self.content.keys() {
                if !first {
                    print!(",");
                }
                else {
                    first = false
                }
                print!("{}", key);
            }
            eprintln!(".");
            Err(Error)
        }
        else {
            Ok(())
        }
    }
}


//------------ Helpers -------------------------------------------------------

fn from_str_value_of<T>(
    matches: &ArgMatches,
    key: &str
) -> Result<Option<T>, Error>
where T: FromStr, T::Err: fmt::Display {
    match matches.value_of(key) {
        Some(value) => {
            match T::from_str(value) {
                Ok(value) => Ok(Some(value)),
                Err(err) => {
                    eprintln!(
                        "Invalid value for {}: {}.", 
                        key, err
                    );
                    Err(Error)
                }
            }
        }
        None => Ok(None)
    }
}

#[cfg(unix)]
fn facility_to_string(facility: Facility) -> String {
    use syslog::Facility::*;

    match facility {
        LOG_KERN => "kern",
        LOG_USER => "user",
        LOG_MAIL => "mail",
        LOG_DAEMON => "daemon",
        LOG_AUTH => "auth",
        LOG_SYSLOG => "syslog",
        LOG_LPR => "lpr",
        LOG_NEWS => "news",
        LOG_UUCP => "uucp",
        LOG_CRON => "cron",
        LOG_AUTHPRIV => "authpriv",
        LOG_FTP => "ftp",
        LOG_LOCAL0 => "local0",
        LOG_LOCAL1 => "local1",
        LOG_LOCAL2 => "local2",
        LOG_LOCAL3 => "local3",
        LOG_LOCAL4 => "local4",
        LOG_LOCAL5 => "local5",
        LOG_LOCAL6 => "local6",
        LOG_LOCAL7 => "local7",
    }.into()
}


//------------ DEFAULT_TALS --------------------------------------------------

const DEFAULT_TALS: [(&str, &[u8]); 5] = [
    ("afrinic.tal", include_bytes!("../tals/afrinic.tal")),
    ("apnic.tal", include_bytes!("../tals/apnic.tal")),
    ("arin.tal", include_bytes!("../tals/arin.tal")),
    ("lacnic.tal", include_bytes!("../tals/lacnic.tal")),
    ("ripe.tal", include_bytes!("../tals/ripe.tal")),
];


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;

    fn get_default_config() -> Config {
        // Set $HOME so that home_dir always succeeds.
        ::std::env::set_var("HOME", "/home/test");
        Config::default()
    }

    fn process_basic_args(args: &[&str]) -> Config {
        let mut config = get_default_config();
        config.apply_arg_matches(
            &Config::config_args(App::new("routinator"))
                .get_matches_from_safe(args).unwrap(),
            Path::new("/test")
        ).unwrap();
        config
    }

    fn process_rtrd_args(args: &[&str]) -> Config {
        let mut config = get_default_config();
        let matches = Config::rtrd_args(Config::config_args(
                App::new("routinator"))
        ).get_matches_from_safe(args).unwrap();
        config.apply_arg_matches(&matches, Path::new("/test")).unwrap();
        config.apply_rtrd_arg_matches(&matches, Path::new("/test")).unwrap();
        config
    }

    #[test]
    #[cfg(unix)]
    fn default_config() {
        let config = get_default_config();
        assert_eq!(
            config.cache_dir,
            home_dir().unwrap().join(".rpki-cache").join("repository")
        );
        assert_eq!(
            config.tal_dir,
            home_dir().unwrap().join(".rpki-cache").join("tals")
        );
        assert!(config.exceptions.is_empty());
        assert_eq!(config.strict, DEFAULT_STRICT);
        assert_eq!(config.rsync_count, DEFAULT_RSYNC_COUNT);
        assert_eq!(config.validation_threads, ::num_cpus::get());
        assert_eq!(config.refresh, Duration::from_secs(DEFAULT_REFRESH));
        assert_eq!(config.retry, Duration::from_secs(DEFAULT_RETRY));
        assert_eq!(config.expire, Duration::from_secs(DEFAULT_EXPIRE));
        assert_eq!(config.history_size, DEFAULT_HISTORY_SIZE);
        assert_eq!(
            config.tcp_listen,
            vec![SocketAddr::from_str("127.0.0.1:3323").unwrap()]
        );
        assert_eq!(config.log_level, LevelFilter::Warn);
        assert_eq!(config.log_target, LogTarget::Default(Facility::LOG_DAEMON));
    }

    #[test]
    #[cfg(unix)]
    fn good_file_config() {
        let config = ConfigFile::parse(
            "repository-dir = \"/repodir\"\n\
             tal-dir = \"taldir\"\n\
             exceptions = [\"ex1\", \"/ex2\"]\n\
             strict = true\n\
             rsync-count = 12\n\
             validation-threads = 1000\n\
             refresh = 6\n\
             retry = 7\n\
             expire = 8\n\
             history-size = 5000\n\
             listen-tcp = [\"[2001:db8::4]:323\", \"192.0.2.4:323\"]\n\
             log-level = \"info\"\n\
             log = \"file\"\n\
             log-file = \"foo.log\"",
            &Path::new("/test/routinator.conf")
        ).unwrap();
        let config = Config::from_config_file(config).unwrap();
        assert_eq!(config.cache_dir.to_str().unwrap(), "/repodir");
        assert_eq!(config.tal_dir.to_str().unwrap(), "/test/taldir");
        assert_eq!(
            config.exceptions,
            vec![PathBuf::from("/test/ex1"), PathBuf::from("/ex2")]
        );
        assert_eq!(config.strict, true);
        assert_eq!(config.rsync_count, 12);
        assert_eq!(config.validation_threads, 1000);
        assert_eq!(config.refresh, Duration::from_secs(6));
        assert_eq!(config.retry, Duration::from_secs(7));
        assert_eq!(config.expire, Duration::from_secs(8));
        assert_eq!(config.history_size, 5000);
        assert_eq!(
            config.tcp_listen,
            vec![
                SocketAddr::from_str("[2001:db8::4]:323").unwrap(),
                SocketAddr::from_str("192.0.2.4:323").unwrap(),
            ]
        );
        assert_eq!(config.log_level, LevelFilter::Info);
        assert_eq!(
            config.log_target,
            LogTarget::File(PathBuf::from("/test/foo.log"))
        );
    }

    #[test]
    fn bad_config_file() {
        let config = ConfigFile::parse(
            "", Path::new("/test/routinator.conf")
        ).unwrap();
        assert!(Config::from_config_file(config).is_err());
        let config = ConfigFile::parse(
            "repository-dir=\"bla\"",
            Path::new("/test/routinator.conf")
        ).unwrap();
        assert!(Config::from_config_file(config).is_err());
        let config = ConfigFile::parse(
            "tal-dir=\"bla\"",
            Path::new("/test/routinator.conf")
        ).unwrap();
        assert!(Config::from_config_file(config).is_err());
    }

    #[test]
    #[cfg(unix)]
    fn basic_args() {
        let config = process_basic_args(&[
            "routinator", "-r", "/repository", "-t", "tals",
            "-x", "/x1", "--exceptions", "x2", "--strict",
            "--rsync-count", "1000", "--validation-threads", "2000",
            "--syslog", "--syslog-facility", "auth"
        ]);
        assert_eq!(config.cache_dir, Path::new("/repository"));
        assert_eq!(config.tal_dir, Path::new("/test/tals"));
        assert_eq!(
            config.exceptions, [Path::new("/x1"), Path::new("/test/x2")]
        );
        assert_eq!(config.strict, true);
        assert_eq!(config.rsync_count, 1000);
        assert_eq!(config.validation_threads, 2000);
        assert_eq!(config.log_target, LogTarget::Syslog(Facility::LOG_AUTH));
    }

    #[test]
    fn verbosity() {
        let config = process_basic_args(&["routinator"]);
        assert_eq!(config.log_level, LevelFilter::Warn);
        let config = process_basic_args(&["routinator", "-v"]);
        assert_eq!(config.log_level, LevelFilter::Info);
        let config = process_basic_args(&["routinator", "-vv"]);
        assert_eq!(config.log_level, LevelFilter::Debug);
        let config = process_basic_args(&["routinator", "-q"]);
        assert_eq!(config.log_level, LevelFilter::Error);
        let config = process_basic_args(&["routinator", "-qq"]);
        assert_eq!(config.log_level, LevelFilter::Off);
    }

    #[test]
    fn rtrd_args() {
        let config = process_rtrd_args(&[
            "routinator", "--refresh", "7", "--retry", "8", "--expire", "9",
            "--history", "1000", "-l", "[2001:db8::4]:323",
            "--listen", "192.0.2.4:323"
        ]);
        assert_eq!(config.refresh, Duration::from_secs(7));
        assert_eq!(config.retry, Duration::from_secs(8));
        assert_eq!(config.expire, Duration::from_secs(9));
        assert_eq!(config.history_size, 1000);
        assert_eq!(
            config.tcp_listen,
            vec![
                SocketAddr::from_str("[2001:db8::4]:323").unwrap(),
                SocketAddr::from_str("192.0.2.4:323").unwrap(),
            ]
        );
    }
}

