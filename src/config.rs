//! Configuration.
//!
//! This module primarily contains the type [`Config`] that holds all the
//! configuration used by Routinator. It can be loaded both from a TOML
//! formatted config file and command line options.
//!
//! [`Config`]: struct.Config.html

use std::{env, fmt, fs, io};
use std::collections::HashMap;
use std::future::Future;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
use clap::{App, Arg, ArgMatches};
#[cfg(unix)] use daemonize::Daemonize;
use dirs::home_dir;
use log::{LevelFilter, Log, error};
#[cfg(unix)] use syslog::Facility;
use tokio::runtime::Runtime;
use crate::operation::Error;


//------------ Defaults for Some Values --------------------------------------

/// Are we doing strict validation by default?
const DEFAULT_STRICT: bool = false;

/// The default timeout for running rsync commands in seconds.
const DEFAULT_RSYNC_TIMEOUT: u64 = 300;

/// Are we leaving the repository dirty by default?
const DEFAULT_DIRTY_REPOSITORY: bool = false;

/// The default refresh interval in seconds.
const DEFAULT_REFRESH: u64 = 600;

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
/// where to keep the repository and how to update it, as well as the
/// configuration for server mode.
///
/// All values are public and can be accessed directly.
///
/// The two functions [`config_args`] and [`server_args`] can be used to
/// create the clap application. Its matches can then be used to create the
/// basic config via [`from_arg_matches`]. If the RTR server configuration is
/// necessary, it can be added via [`apply_server_arg_matches`] from the
/// server subcommand matches.
///
/// The methods [`init_logging`] and [`switch_logging`] can be used to
/// configure logging according to the strategy provided by the configuration.
/// On Unix systems only, the method [`daemonize`] creates a correctly
/// configured `Daemonizer`. Finally, [`to_toml`] can be used to produce a
/// TOML value that contains a configuration file content representing the
/// current configuration.
///
/// [`config_args`]: #method.config_args
/// [`server_args`]: #method.server_args
/// [`from_arg_matches`]: #method.from_arg_matches
/// [`apply_server_arg_matches`]: #method.apply_server_arg_matches
/// [`init_logging`]: #method.init_logging
/// [`switch_logging`]: #method.switch_logging
/// [`daemonize`]: #method.daemonize
/// [`to_toml`]: #method.to_toml
#[derive(Clone, Debug)]
pub struct Config {
    /// Path to the directory that contains the repository cache.
    pub cache_dir: PathBuf,

    /// Path to the directory that contains the trust anchor locators.
    pub tal_dir: PathBuf,

    /// Paths to the local exceptions files.
    pub exceptions: Vec<PathBuf>,

    /// Should we do strict validation?
    ///
    /// See [the relevant RPKI crate documentation](https://github.com/NLnetLabs/rpki-rs/blob/master/doc/relaxed-validation.md)
    /// for more information.
    pub strict: bool,

    /// How should we deal with stale objects?
    ///
    /// See the [`StalePolicy`] type for a description of the available
    /// options.
    ///
    /// [`StalePolicy`]: enum.StalePolicy.html
    pub stale: StalePolicy,

    /// Allow dubious host names.
    pub allow_dubious_hosts: bool,

    /// Whether to disable rsync.
    pub disable_rsync: bool,

    /// The command to run for rsync.
    pub rsync_command: String,

    /// Optional arguments passed to rsync.
    ///
    /// If these are present, they overide the arguments automatically
    /// determined otherwise. Thus, `Some<Vec::new()>` will supress all
    /// arguments.
    pub rsync_args: Option<Vec<String>>,

    /// Timeout for rsync commands.
    pub rsync_timeout: Duration,

    /// Wether to disable RRDP.
    pub disable_rrdp: bool,

    /// Optional RRDP timeout in seconds.
    ///
    /// If this is not set, the default timeouts of the `reqwest` crate are
    /// used. Use `Some(None)` for no timeout.
    #[allow(clippy::option_option)]
    pub rrdp_timeout: Option<Option<Duration>>,

    /// Optional RRDP connect timeout in seconds.
    pub rrdp_connect_timeout: Option<Duration>,

    /// Optional RRDP local address to bind to when doing requests.
    pub rrdp_local_addr: Option<IpAddr>,

    /// RRDP additional root certificates for HTTPS.
    ///
    /// These do not overide the default system root certififcates.
    pub rrdp_root_certs: Vec<PathBuf>,

    /// RRDP HTTP proxies.
    pub rrdp_proxies: Vec<String>,

    /// Wether to not cleanup the repository directory after a validation run.
    ///
    /// If this is `false` and update has not been disabled otherwise, all
    /// data for rsync modules (if rsync is enabled) and RRDP servers (if
    /// RRDP is enabled) that have not been used during validation will be
    /// deleted.
    pub dirty_repository: bool,

    /// Number of threads used during validation.
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
    pub rtr_listen: Vec<SocketAddr>,

    /// Addresses to listen on for HTTP monitoring connectsion.
    pub http_listen: Vec<SocketAddr>,

    /// Whether to get the listening sockets from systemd.
    pub systemd_listen: bool,

    /// The log levels to be logged.
    pub log_level: LevelFilter,

    /// The target to log to.
    pub log_target: LogTarget,

    /// The optional PID file for daemon mode.
    pub pid_file: Option<PathBuf>,

    /// The optional working directory for daemon mode.
    pub working_dir: Option<PathBuf>,

    /// The optional directory to chroot to in daemon mode.
    pub chroot: Option<PathBuf>,

    /// The name of the user to change to in daemon mode.
    pub user: Option<String>,

    /// The name of the group to change to in daemon mode.
    pub group: Option<String>,

    /// A mapping of TAL file names to TAL labels.
    pub tal_labels: HashMap<String, String>,
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
             .help("Read base configuration from this file")
        )
        .arg(Arg::with_name("base-dir")
             .short("b")
             .long("base-dir")
             .value_name("DIR")
             .help("Sets the base directory for cache and TALs")
             .takes_value(true)
        )
        .arg(Arg::with_name("repository-dir")
             .short("r")
             .long("repository-dir")
             .value_name("DIR")
             .help("Sets the repository cache directory")
             .takes_value(true)
        )
        .arg(Arg::with_name("tal-dir")
             .short("t")
             .long("tal-dir")
             .value_name("DIR")
             .help("Sets the TAL directory")
             .takes_value(true)
        )
        .arg(Arg::with_name("exceptions")
             .short("x")
             .long("exceptions")
             .value_name("FILE")
             .help("File with local exceptions (see RFC 8416 for format)")
             .takes_value(true)
             .multiple(true)
             .number_of_values(1)
        )
        .arg(Arg::with_name("strict")
             .long("strict")
             .help("Parse RPKI data in strict mode")
        )
        .arg(Arg::with_name("stale")
             .long("stale")
             .value_name("POLICY")
             .help("The policy for handling stale objects")
             .takes_value(true)
        )
        .arg(Arg::with_name("allow-dubious-hosts")
             .long("allow-dubios-hosts")
             .help("Allow dubious host names in rsycn and HTTPS URIs")
        )
        .arg(Arg::with_name("disable-rsync")
            .long("disable-rsync")
            .help("Disable rsync and only use RRDP")
        )
        .arg(Arg::with_name("rsync-command")
             .long("rsync-command")
             .value_name("COMMAND")
             .help("The command to run for rsync")
             .takes_value(true)
        )
        .arg(Arg::with_name("rsync-timeout")
            .long("rsync-timeout")
            .value_name("SECONDS")
            .help("Timeout for rsync commands")
            .takes_value(true)
        )
        .arg(Arg::with_name("disable-rrdp")
            .long("disable-rrdp")
            .help("Disable RRDP and only use rsync")
        )
        .arg(Arg::with_name("rrdp-timeout")
            .long("rrdp-timeout")
            .value_name("SECONDS")
            .help("Timeout of network operation for RRDP (0 for none)")
            .takes_value(true)
        )
        .arg(Arg::with_name("rrdp-connect-timeout")
            .long("rrdp-connect-timeout")
            .value_name("SECONDS")
            .help("Timeout for connecting to an RRDP server")
            .takes_value(true)
        )
        .arg(Arg::with_name("rrdp-local-addr")
            .long("rrdp-local-addr")
            .value_name("ADDR")
            .help("Local address for outgoing RRDP connections")
            .takes_value(true)
        )
        .arg(Arg::with_name("rrdp-root-cert")
            .long("rrdp-root-cert")
            .value_name("PATH")
            .help("Path to trusted PEM certificate for RRDP HTTPS")
            .takes_value(true)
            .multiple(true)
            .number_of_values(1)
        )
        .arg(Arg::with_name("rrdp-proxy")
            .long("rrdp-proxy")
            .value_name("URI")
            .help("Proxy server for RRDP (HTTP or SOCKS5)")
            .takes_value(true)
            .multiple(true)
            .number_of_values(1)
        )
        .arg(Arg::with_name("dirty-repository")
            .long("dirty")
            .help("Do not clean up repository directory after validation")
        )
        .arg(Arg::with_name("validation-threads")
             .long("validation-threads")
             .value_name("COUNT")
             .help("Number of threads for validation")
             .takes_value(true)
        )
        .arg(Arg::with_name("verbose")
             .short("v")
             .long("verbose")
             .multiple(true)
             .help("Log more information, twice for even more")
        )
        .arg(Arg::with_name("quiet")
             .short("q")
             .long("quiet")
             .multiple(true)
             .conflicts_with("verbose")
             .help("Log less information, twice for no information")
        )
        .arg(Arg::with_name("syslog")
             .long("syslog")
             .help("Log to syslog")
        )
        .arg(Arg::with_name("syslog-facility")
             .long("syslog-facility")
             .takes_value(true)
             .default_value("daemon")
             .help("Facility to use for syslog logging")
        )
        .arg(Arg::with_name("logfile")
             .long("logfile")
             .takes_value(true)
             .value_name("PATH")
             .help("Log to this file")
        )
    }

    /// Adds the relevant config args to the server subcommand.
    ///
    /// Some of the options in the config only make sense for the
    /// RTR server. Having them in the global part of the clap command line
    /// is confusing, so we stick to defaults unless we actually run the
    /// server. This function adds the relevant arguments to the subcommand
    /// provided via `app`.
    ///
    /// It follows clap’s builder pattern and returns the app with all
    /// arguments added.
    pub fn server_args<'a: 'b, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        app
        .arg(Arg::with_name("refresh")
            .long("refresh")
            .value_name("SECONDS")
            .help("Refresh interval in seconds [default 3600]")
        )
        .arg(Arg::with_name("retry")
            .long("retry")
            .value_name("SECONDS")
            .help("RTR retry interval in seconds [default 600]")
        )
        .arg(Arg::with_name("expire")
            .long("expire")
            .value_name("SECONDS")
            .help("RTR expire interval in seconds [default 600]")
        )
        .arg(Arg::with_name("history")
            .long("history")
            .value_name("COUNT")
            .help("Number of history items to keep [default 10]")
        )
        .arg(Arg::with_name("rtr-listen")
            .long("rtr")
            .value_name("ADDR:PORT")
            .help("Listen on address/port for RTR")
            .takes_value(true)
            .multiple(true)
            .number_of_values(1)
        )
        .arg(Arg::with_name("http-listen")
            .long("http")
            .value_name("ADDR:PORT")
            .help("Listen on address/port for HTTP")
            .takes_value(true)
            .multiple(true)
            .number_of_values(1)
        )
        .arg(Arg::with_name("systemd-listen")
            .long("systemd-listen")
            .help("Acquire listening sockets from systemd")
        )
        .arg(Arg::with_name("pid-file")
            .long("pid-file")
            .value_name("PATH")
            .help("The file for keep the daemon process's PID in")
            .takes_value(true)
        )
        .arg(Arg::with_name("working-dir")
            .long("working-dir")
            .value_name("PATH")
            .help("The working directory of the daemon process")
            .takes_value(true)
        )
        .arg(Arg::with_name("chroot")
            .long("chroot")
            .value_name("PATH")
            .help("Root directory for the daemon process")
            .takes_value(true)
        )
        .arg(Arg::with_name("user")
            .long("user")
            .value_name("USER")
            .help("User for the daemon process")
            .takes_value(true)
        )
        .arg(Arg::with_name("group")
            .long("group")
            .value_name("GROUP")
            .help("Group for the daemon process")
            .takes_value(true)
        )
    }

    /// Creates a configuration from command line matches.
    ///
    /// The function attempts to create configuration from the command line
    /// arguments provided via `matches`. It will try to read a config file
    /// if provided via the config file option (`-c` or `--config`) or a
    /// file in `$HOME/.routinator.conf` otherwise. If the latter doesn’t
    /// exist either, starts with a default configuration.
    ///
    /// All relative paths given in command line arguments will be interpreted
    /// relative to `cur_dir`. Conversely, paths in the config file are
    /// treated as relative to the config file’s directory.
    ///
    /// If you are runming in server mode, you need to also apply the server
    /// arguments via [`apply_server_arg_matches`].
    ///
    /// [`apply_server_arg_matches`]: #method.apply_server_arg_matches
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
    #[allow(clippy::cognitive_complexity)]
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
            error!(
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
            error!(
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

        // stale
        if let Some(value) = from_str_value_of(matches, "stale")? {
            self.stale = value
        }

        // allow_dubious_hosts
        if matches.is_present("allow-dubious-hosts") {
            self.allow_dubious_hosts = true
        }

        // disable_rsync
        if matches.is_present("disable-rsync") {
            self.disable_rsync = true
        }

        // rsync_command
        if let Some(value) = matches.value_of("rsync-command") {
            self.rsync_command = value.into()
        }

        // rsync_timeout
        if let Some(value) = from_str_value_of(matches, "rsync-timeout")? {
            self.rsync_timeout = Duration::from_secs(value)
        }

        // disable_rrdp
        if matches.is_present("disable-rrdp") {
            self.disable_rrdp = true
        }

        // rrdp_timeout
        if let Some(value) = from_str_value_of(matches, "rrdp-timeout")? {
            self.rrdp_timeout = match value {
                0 => Some(None),
                value => Some(Some(Duration::from_secs(value))),
            }
        }

        // rrdp_connect_timeout
        if let Some(value) = from_str_value_of(matches, "rrdp-timeout")? {
            self.rrdp_connect_timeout = Some(Duration::from_secs(value))
        }

        // rrdp_local_addr
        if let Some(value) = from_str_value_of(matches, "rrdp-local-addr")? {
            self.rrdp_local_addr = Some(value)
        }

        // rrdp_root_certs
        if let Some(list) = matches.values_of("rrdp-root-cert") {
            self.rrdp_root_certs = Vec::new();
            for value in list {
                match PathBuf::from_str(value) {
                    Ok(path) => self.rrdp_root_certs.push(path),
                    Err(_) => {
                        error!("Invalid path for rrdp-root-cert '{}'", value);
                        return Err(Error)
                    }
                };
            }
        }

        // rrdp_proxies
        if let Some(list) = matches.values_of("rrdp-proxy") {
            self.rrdp_proxies = list.map(Into::into).collect();
        }

        // dirty_repository
        if matches.is_present("dirty-repository") {
            self.dirty_repository = true
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

    /// Applies the logging-specific command line arguments to the config.
    ///
    /// This is the Unix version that also considers syslog as a valid
    /// target.
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
                        error!("Invalid value for syslog-facility.");
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

    /// Applies the logging-specific command line arguments to the config.
    ///
    /// This is the non-Unix version that does not use syslog.
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


    /// Applies the RTR server command line arguments to an existing config.
    ///
    /// All paths used in arguments are interpreted relative to `cur_dir`.
    pub fn apply_server_arg_matches(
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

        // rtr_listen
        if let Some(list) = matches.values_of("rtr-listen") {
            self.rtr_listen = Vec::new();
            for value in list {
                match SocketAddr::from_str(value) {
                    Ok(some) => self.rtr_listen.push(some),
                    Err(_) => {
                        error!("Invalid value for rtr: {}", value);
                        return Err(Error);
                    }
                }
            }
        }

        // http_listen
        if let Some(list) = matches.values_of("http-listen") {
            self.http_listen = Vec::new();
            for value in list {
                match SocketAddr::from_str(value) {
                    Ok(some) => self.http_listen.push(some),
                    Err(_) => {
                        error!("Invalid value for http: {}", value);
                        return Err(Error);
                    }
                }
            }
        }

        // systemd_listen
        if matches.is_present("systemd-listen") {
            self.systemd_listen = true
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

        // user
        if let Some(user) = matches.value_of("user") {
            self.user = Some(user.into())
        }

        // group
        if let Some(group) = matches.value_of("group") {
            self.group = Some(group.into())
        }

        Ok(())
    }

    /// Initialize logging.
    ///
    /// All diagnostic output of Routinator is done via logging, never to
    /// stderr directly. Thus, it is important to initalize logging before
    /// doing anything else that may result in such output. This function
    /// does exactly that. It sets a maximum log level of `warn`, leading
    /// only printing important information, and directs all logging to
    /// stderr.
    pub fn init_logging() -> Result<(), Error> {
        log::set_max_level(LevelFilter::Warn);
        if let Err(err) = log_reroute::init() {
            eprintln!("Failed to initialize logger: {}.\nAborting.", err);
            return Err(Error)
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
    pub fn switch_logging(&self, daemon: bool) -> Result<(), Error> {
        let logger = match self.log_target {
            #[cfg(unix)]
            LogTarget::Default(fac) => {
                if daemon {
                    self.syslog_logger(fac)?
                }
                else {
                    self.stderr_logger(false)?
                }
            }
            #[cfg(unix)]
            LogTarget::Syslog(fac) => {
                self.syslog_logger(fac)?
            }
            LogTarget::Stderr => {
                self.stderr_logger(daemon)?
            }
            LogTarget::File(ref path) => {
                self.file_logger(path)?
            }
        };
        log_reroute::reroute_boxed(logger);
        log::set_max_level(self.log_level);
        Ok(())
    }

    /// Creates a syslog logger and configures correctly.
    #[cfg(unix)]
    fn syslog_logger(
        &self,
        facility: syslog::Facility
    ) -> Result<Box<dyn Log>, Error> {
        let process = env::current_exe().ok().and_then(|path|
            path.file_name()
                .and_then(std::ffi::OsStr::to_str)
                .map(ToString::to_string)
        ).unwrap_or_else(|| String::from("routinator"));
        let pid = unsafe { libc::getpid() };
        let formatter = syslog::Formatter3164 {
            facility,
            hostname: None,
            process,
            pid
        };
        let logger = syslog::unix(formatter.clone()).or_else(|_| {
            syslog::tcp(formatter.clone(), ("127.0.0.1", 601))
        }).or_else(|_| {
            syslog::udp(formatter, ("127.0.0.1", 0), ("127.0.0.1", 514))
        });
        match logger {
            Ok(logger) => Ok(Box::new(syslog::BasicLogger::new(logger))),
            Err(err) => {
                error!("Cannot connect to syslog: {}", err);
                Err(Error)
            }
        }
    }

    /// Creates a stderr logger.
    ///
    /// If we are in daemon mode, we add a timestamp to the output.
    fn stderr_logger(&self, daemon: bool) -> Result<Box<dyn Log>, Error> {
        Ok(self.fern_logger(daemon).chain(io::stderr()).into_log().1)
    }

    /// Creates a file logger using the file provided by `path`.
    fn file_logger(&self, path: &Path) -> Result<Box<dyn Log>, Error> {
        let file = match fern::log_file(path) {
            Ok(file) => file,
            Err(err) => {
                error!(
                    "Failed to open log file '{}': {}",
                    path.display(), err
                );
                return Err(Error)
            }
        };
        Ok(self.fern_logger(true).chain(file).into_log().1)
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
            .level(self.log_level)
            .level_for("rustls", LevelFilter::Error);
        if self.log_level == LevelFilter::Debug {
            res = res
                .level_for("tokio_reactor", LevelFilter::Info)
                .level_for("hyper", LevelFilter::Info)
                .level_for("reqwest", LevelFilter::Info)
                .level_for("h2", LevelFilter::Info);
        }
        res
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

    /// Creates the correct base configuration for the given config file path.
    /// 
    /// If no config path is given, tries to read the default config in
    /// `$HOME/.routinator.conf`. If that doesn’t exist, creates a default
    /// config.
    fn create_base_config(path: Option<&Path>) -> Result<Self, Error> {
        let file = match path {
            Some(path) => {
                match ConfigFile::read(&path)? {
                    Some(file) => file,
                    None => {
                        error!("Cannot read config file {}", path.display());
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
    fn from_config_file(mut file: ConfigFile) -> Result<Self, Error> {
        let log_target = Self::log_target_from_config_file(&mut file)?;
        let res = Config {
            cache_dir: file.take_mandatory_path("repository-dir")?,
            tal_dir: file.take_mandatory_path("tal-dir")?,
            exceptions: {
                file.take_path_array("exceptions")?.unwrap_or_else(Vec::new)
            },
            strict: file.take_bool("strict")?.unwrap_or(false),
            stale: file.take_from_str("stale")?.unwrap_or_default(),
            allow_dubious_hosts:
                file.take_bool("allow-dubious-hosts")?.unwrap_or(false),
            disable_rsync: file.take_bool("disable-rsync")?.unwrap_or(false),
            rsync_command: {
                file.take_string("rsync-command")?
                    .unwrap_or_else(|| "rsync".into())
            },
            rsync_args: file.take_string_array("rsync-args")?,
            rsync_timeout: {
                Duration::from_secs(
                    file.take_u64("rsync-timeout")?
                        .unwrap_or(DEFAULT_RSYNC_TIMEOUT)
                )
            },
            disable_rrdp: file.take_bool("disable-rrdp")?.unwrap_or(false),
            rrdp_timeout: {
                file.take_u64("rrdp-timeout")?
                .map(|secs| {
                    if secs == 0 {
                        None
                    }
                    else {
                        Some(Duration::from_secs(secs))
                    }
                })
            },
            rrdp_connect_timeout: {
                file.take_u64("rrdp-connect-timeout")?.map(Duration::from_secs)
            },
            rrdp_local_addr: file.take_from_str("rrdp-local-addr")?,
            rrdp_root_certs: {
                file.take_from_str_array("rrdp-root-certs")?
                    .unwrap_or_else(Vec::new)
            },
            rrdp_proxies: {
                file.take_string_array("rrdp-proxies")?.unwrap_or_else(
                    Vec::new
                )
            },
            dirty_repository: file.take_bool("dirty")?.unwrap_or(false),
            validation_threads: {
                file.take_small_usize("validation-threads")?
                    .unwrap_or_else(::num_cpus::get)
            },
            refresh: {
                Duration::from_secs(
                    file.take_u64("refresh")?.unwrap_or(DEFAULT_REFRESH)
                )
            },
            retry: {
                Duration::from_secs(
                    file.take_u64("retry")?.unwrap_or(DEFAULT_RETRY)
                )
            },
            expire: {
                Duration::from_secs(
                    file.take_u64("expire")?.unwrap_or(DEFAULT_EXPIRE)
                )
            },
            history_size: {
                file.take_small_usize("history-size")?
                    .unwrap_or(DEFAULT_HISTORY_SIZE)
            },
            rtr_listen: {
                file.take_from_str_array("rtr-listen")?
                    .unwrap_or_else(Vec::new)
            },
            http_listen: {
                file.take_from_str_array("http-listen")?
                    .unwrap_or_else(Vec::new)
            },
            systemd_listen: file.take_bool("systemd-listen")?.unwrap_or(false),
            log_level: {
                file.take_from_str("log-level")?.unwrap_or(LevelFilter::Warn)
            },
            log_target,
            pid_file: file.take_path("pid-file")?,
            working_dir: file.take_path("working-dir")?,
            chroot: file.take_path("chroot")?,
            user: file.take_string("user")?,
            group: file.take_string("group")?,
            tal_labels: file.take_string_map("tal-labels")?.unwrap_or_default(),
        };
        file.check_exhausted()?;
        Ok(res)
    }

    /// Determines the logging target from the config file.
    ///
    /// This is the Unix version that also deals with syslog.
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
                error!(
                    "Error in config file {}: invalid syslog-facility.",
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
                        error!(
                            "Error in config file {}: \
                             log target \"file\" requires 'log-file' value.",
                            file.path.display()
                        );
                        Err(Error)
                    }
                }
            }
            Some(value) => {
                error!(
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
    ///
    /// This is the non-Unix version that only logs to stderr or a file.
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
                        error!(
                            "Error in config file {}: \
                             log target \"file\" requires 'log-file' value.",
                            file.path.display()
                        );
                        Err(Error)
                    }
                }
            }
            Some(value) => {
                error!(
                    "Error in config file {}: \
                     invalid log target '{}'",
                    file.path.display(), value
                );
                Err(Error)
            }
        }
    }

    /// Creates a default config with the given paths.
    ///
    /// Uses default values for everything except for the cache and TAL
    /// directories which are provided.
    fn default_with_paths(cache_dir: PathBuf, tal_dir: PathBuf) -> Self {
        Config {
            cache_dir,
            tal_dir,
            exceptions: Vec::new(),
            strict: DEFAULT_STRICT,
            stale: Default::default(),
            allow_dubious_hosts: false,
            disable_rsync: false,
            rsync_command: "rsync".into(),
            rsync_args: None,
            rsync_timeout: Duration::from_secs(DEFAULT_RSYNC_TIMEOUT),
            disable_rrdp: false,
            rrdp_timeout: None,
            rrdp_connect_timeout: None,
            rrdp_local_addr: None,
            rrdp_root_certs: Vec::new(),
            rrdp_proxies: Vec::new(),
            dirty_repository: DEFAULT_DIRTY_REPOSITORY,
            validation_threads: ::num_cpus::get(),
            refresh: Duration::from_secs(DEFAULT_REFRESH),
            retry: Duration::from_secs(DEFAULT_RETRY),
            expire: Duration::from_secs(DEFAULT_EXPIRE),
            history_size: DEFAULT_HISTORY_SIZE,
            rtr_listen: Vec::new(),
            http_listen: Vec::new(),
            systemd_listen: false,
            log_level: LevelFilter::Warn,
            log_target: LogTarget::default(),
            pid_file: None,
            working_dir: None,
            chroot: None,
            user: None,
            group: None,
            tal_labels: HashMap::new(),
        }
    }

    /// Returns a Tokio runtime based on the configuration.
    pub fn runtime(&self) -> Result<Runtime, Error> {
        Runtime::new().map_err(|err| {
            error!("Failed to create runtime: {}", err);
            Error
        })
    }

    /// Runs a future to completion atop a Tokio runtime.
    pub fn block_on<F: Future>(&self, future: F) -> Result<F::Output, Error> {
        Ok(self.runtime()?.block_on(future))
    }

    /// Returns a daemonizer based on the configuration.
    ///
    /// This also changes the paths in the configuration if `chroot` is set.
    /// As this may fail, this whole method may fail.
    #[cfg(unix)]
    pub fn daemonize(&mut self) -> Result<Daemonize<()>, Error> {
        if let Some(ref chroot) = self.chroot {
            self.cache_dir = match self.cache_dir.strip_prefix(chroot) {
                Ok(dir) => dir.into(),
                Err(_) => {
                    error!(
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
                    error!(
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
                        error!(
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
                        error!(
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
                        error!(
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
        if let Some(ref user) = self.user {
            res = res.user(user.as_str())
        }
        if let Some(ref group) = self.group {
            res = res.group(group.as_str())
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
        res.insert("stale".into(), format!("{}", self.stale).into());
        res.insert(
            "allow-dubious-hosts".into(), self.allow_dubious_hosts.into()
        );
        res.insert("disable-rsync".into(), self.disable_rsync.into());
        res.insert("rsync-command".into(), self.rsync_command.clone().into());
        if let Some(ref args) = self.rsync_args {
            res.insert(
                "rsync-args".into(),
                toml::Value::Array(
                    args.iter().map(|a| a.clone().into()).collect()
                )
            );
        }
        res.insert(
            "rsync-timeout".into(),
            (self.rsync_timeout.as_secs() as i64).into()
        );
        res.insert("disable-rrdp".into(), self.disable_rrdp.into());
        if let Some(timeout) = self.rrdp_timeout {
            res.insert(
                "rrdp-timeout".into(),
                ((timeout.map(|d| d.as_secs()).unwrap_or(0)) as i64).into()
            );
        }
        if let Some(timeout) = self.rrdp_connect_timeout {
            res.insert(
                "rrdp-connect-timeout".into(),
                (timeout.as_secs() as i64).into()
            );
        }
        if let Some(addr) = self.rrdp_local_addr {
            res.insert("rrdp-local-addr".into(), addr.to_string().into());
        }
        res.insert(
            "rrdp-root-certs".into(),
            toml::Value::Array(
                self.rrdp_root_certs.iter()
                    .map(|p| p.display().to_string().into())
                    .collect()
            )
        );
        res.insert(
            "rrdp-proxies".into(),
            toml::Value::Array(
                self.rrdp_proxies.iter().map(|s| s.clone().into()).collect()
            )
        );
        res.insert("dirty".into(), self.dirty_repository.into());
        res.insert(
            "validation-threads".into(),
            (self.validation_threads as i64).into()
        );
        res.insert("refresh".into(), (self.refresh.as_secs() as i64).into());
        res.insert("retry".into(), (self.retry.as_secs() as i64).into());
        res.insert("expire".into(), (self.expire.as_secs() as i64).into());
        res.insert("history-size".into(), (self.history_size as i64).into());
        res.insert(
            "rtr-listen".into(),
            toml::Value::Array(
                self.rtr_listen.iter().map(|a| a.to_string().into()).collect()
            )
        );
        res.insert(
            "http-listen".into(),
            toml::Value::Array(
                self.http_listen.iter().map(|a| a.to_string().into()).collect()
            )
        );
        res.insert("systemd-listen".into(), self.systemd_listen.into());
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
        if let Some(ref user) = self.user {
            res.insert("user".into(), user.clone().into());
        }
        if let Some(ref group) = self.group {
            res.insert("group".into(), group.clone().into());
        }
        if !self.tal_labels.is_empty() {
            res.insert(
                "tal-labels".into(),
                toml::Value::Array(
                    self.tal_labels.iter().map(|(left, right)| {
                        toml::Value::Array(vec![
                            left.clone().into(), right.clone().into()
                        ])
                    }).collect()
                )
            );
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


//------------ StalePolicy ---------------------------------------------------

/// The local policy for handling of stale objects.
///
/// Stale objects are manifests and CRLs that have a `next_update` field in
/// the past. The protocol leaves the decision how to interpret stale
/// objects to local policy. This type defines the options for this local
/// policy.
#[derive(Clone, Copy, Debug)]
pub enum StalePolicy {
    /// Refuse to accept a stale objects.
    ///
    /// A stale objects and, transitively, all objects that depend on the
    /// stale objects are considered invalid.
    Refuse,

    /// Accept the stale object but log a warning.
    ///
    /// A stale object and, transitively, all objects that depend on the
    /// stale object are considered valid. A warning is logged about the
    /// fact that the object is stale.
    ///
    /// This is the default policy.
    Warn,

    /// Quietly accept the stale object.
    ///
    /// A stale object and, transitively, all objects that depend on the
    /// stale object are considered valid.
    Accept
}

impl Default for StalePolicy {
    fn default() -> Self {
        StalePolicy::Warn
    }
}

impl FromStr for StalePolicy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "refuse" => Ok(StalePolicy::Refuse),
            "warn" => Ok(StalePolicy::Warn),
            "accept" => Ok(StalePolicy::Accept),
            _ => Err(format!("invalid policy '{}'", s))
        }
    }
}

impl fmt::Display for StalePolicy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match *self {
            StalePolicy::Refuse => "refuse",
            StalePolicy::Warn => "warn",
            StalePolicy::Accept => "accept",
        })
    }
}


//------------ ConfigFile ----------------------------------------------------

/// The content of a config file.
///
/// This is a thin wrapper around `toml::Table` to make dealing with it more
/// convenient.
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
    #[allow(clippy::verbose_file_reads)]
    fn read(path: &Path) -> Result<Option<Self>, Error> {
        let mut file = match fs::File::open(path) {
            Ok(file) => file,
            Err(_) => return Ok(None)
        };
        let mut config = String::new();
        if let Err(err) = file.read_to_string(&mut config) {
            error!(
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
                error!(
                    "Failed to parse config file {}: Not a mapping.",
                    path.display()
                );
                return Err(Error);
            }
            Err(err) => {
                error!(
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
                    error!(
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
            dir
        })
    }

    /// Takes a boolean value from the config file.
    ///
    /// The value is taken from the given `key`. Returns `Ok(None)` if there
    /// is no such key. Returns an error if the key exists but the value
    /// isn’t a booelan.
    fn take_bool(&mut self, key: &str) -> Result<Option<bool>, Error> {
        match self.content.remove(key) {
            Some(value) => {
                if let toml::Value::Boolean(res) = value {
                    Ok(Some(res))
                }
                else {
                    error!(
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
    
    /// Takes an unsigned integer value from the config file.
    ///
    /// The value is taken from the given `key`. Returns `Ok(None)` if there
    /// is no such key. Returns an error if the key exists but the value
    /// isn’t an integer or if it is negative.
    fn take_u64(&mut self, key: &str) -> Result<Option<u64>, Error> {
        match self.content.remove(key) {
            Some(value) => {
                if let toml::Value::Integer(res) = value {
                    if res < 0 {
                        error!(
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
                    error!(
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

    /// Takes a small unsigned integer value from the config file.
    ///
    /// While the result is returned as an `usize`, it musn’t be in the
    /// range of a `u16`.
    ///
    /// The value is taken from the given `key`. Returns `Ok(None)` if there
    /// is no such key. Returns an error if the key exists but the value
    /// isn’t an integer or if it is out of bounds.
    fn take_small_usize(&mut self, key: &str) -> Result<Option<usize>, Error> {
        match self.content.remove(key) {
            Some(value) => {
                if let toml::Value::Integer(res) = value {
                    if res < 0 {
                        error!(
                            "Error in config file {}: \
                            '{}' expected to be a positive integer.",
                            self.path.display(), key
                        );
                        Err(Error)
                    }
                    else if res > ::std::u16::MAX.into() {
                        error!(
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
                    error!(
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

    /// Takes a string value from the config file.
    ///
    /// The value is taken from the given `key`. Returns `Ok(None)` if there
    /// is no such key. Returns an error if the key exists but the value
    /// isn’t a string.
    fn take_string(&mut self, key: &str) -> Result<Option<String>, Error> {
        match self.content.remove(key) {
            Some(value) => {
                if let toml::Value::String(res) = value {
                    Ok(Some(res))
                }
                else {
                    error!(
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

    /// Takes a string encoded value from the config file.
    ///
    /// The value is taken from the given `key`. It is expected to be a
    /// string and will be converted to the final type via `FromStr::from_str`.
    ///
    /// Returns `Ok(None)` if the key doesn’t exist. Returns an error if the
    /// key exists but the value isn’t a string or conversion fails.
    fn take_from_str<T>(&mut self, key: &str) -> Result<Option<T>, Error>
    where T: FromStr, T::Err: fmt::Display {
        match self.take_string(key)? {
            Some(value) => {
                match T::from_str(&value) {
                    Ok(some) => Ok(Some(some)),
                    Err(err) => {
                        error!(
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

    /// Takes a path value from the config file.
    ///
    /// The path is taken from the given `key`. It must be a string value.
    /// It is treated as relative to the directory of the config file. If it
    /// is indeed a relative path, it is expanded accordingly and an absolute
    /// path is returned.
    ///
    /// Returns `Ok(None)` if the key does not exist. Returns an error if the
    /// key exists but the value isn’t a string.
    fn take_path(&mut self, key: &str) -> Result<Option<PathBuf>, Error> {
        self.take_string(key).map(|opt| opt.map(|path| self.dir.join(path)))
    }

    /// Takes a mandatory path value from the config file.
    ///
    /// This is the pretty much the same as [`take_path`] but also returns
    /// an error if the key does not exist.
    ///
    /// [`take_path`]: #method.take_path
    fn take_mandatory_path(&mut self, key: &str) -> Result<PathBuf, Error> {
        match self.take_path(key)? {
            Some(res) => Ok(res),
            None => {
                error!(
                    "Error in config file {}: missing required '{}'.",
                    self.path.display(), key
                );
                Err(Error)
            }
        }
    }

    /// Takes an array of strings from the config file.
    ///
    /// The value is taken from the entry with the given `key` and, if
    /// present, the entry is removed. The value must be an array of strings.
    /// If the key is not present, returns `Ok(None)`. If the entry is present
    /// but not an array of strings, returns an error.
    fn take_string_array(
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
                        error!(
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
                error!(
                    "Error in config file {}: \
                     '{}' expected to be a array of strings.",
                    self.path.display(), key
                );
                Err(Error)
            }
            None => Ok(None)
        }
    }

    /// Takes an array of string encoded values from the config file.
    ///
    /// The value is taken from the entry with the given `key` and, if
    /// present, the entry is removed. The value must be an array of strings.
    /// Each string is converted to the output type via `FromStr::from_str`.
    ///
    /// If the key is not present, returns `Ok(None)`. If the entry is present
    /// but not an array of strings or if converting any of the strings fails,
    /// returns an error.
    fn take_from_str_array<T>(
        &mut self,
        key: &str
    ) -> Result<Option<Vec<T>>, Error>
    where T: FromStr, T::Err: fmt::Display {
        match self.content.remove(key) {
            Some(::toml::Value::Array(vec)) => {
                let mut res = Vec::new();
                for value in vec.into_iter() {
                    if let ::toml::Value::String(value) = value {
                        match T::from_str(&value) {
                            Ok(value) => res.push(value),
                            Err(err) => {
                                error!(
                                    "Error in config file {}: \
                                     Invalid value in '{}': {}",
                                    self.path.display(), key, err
                                );
                                return Err(Error)
                            }
                        }
                    }
                    else {
                        error!(
                            "Error in config file {}: \
                            '{}' expected to be a array of strings.",
                            self.path.display(),
                            key
                        );
                        return Err(Error)
                    }
                }
                Ok(Some(res))
            }
            Some(_) => {
                error!(
                    "Error in config file {}: \
                     '{}' expected to be a array of strings.",
                    self.path.display(), key
                );
                Err(Error)
            }
            None => Ok(None)
        }
    }

    /// Takes an array of paths from the config file.
    ///
    /// The values are taken from the given `key` which must be an array of
    /// strings. Each path is treated as relative to the directory of the
    /// config file. All paths are expanded if necessary and are returned as
    /// absolute paths.
    ///
    /// Returns `Ok(None)` if the key does not exist. Returns an error if the
    /// key exists but the value isn’t an array of string.
    fn take_path_array(
        &mut self,
        key: &str
    ) -> Result<Option<Vec<PathBuf>>, Error> {
        match self.content.remove(key) {
            Some(::toml::Value::Array(vec)) => {
                let mut res = Vec::new();
                for value in vec.into_iter() {
                    if let ::toml::Value::String(value) = value {
                        res.push(self.dir.join(value))
                    }
                    else {
                        error!(
                            "Error in config file {}: \
                            '{}' expected to be a array of paths.",
                            self.path.display(),
                            key
                        );
                        return Err(Error);
                    }
                }
                Ok(Some(res))
            }
            Some(_) => {
                error!(
                    "Error in config file {}: \
                     '{}' expected to be a array of paths.",
                    self.path.display(), key
                );
                Err(Error)
            }
            None => Ok(None)
        }
    }

    /// Takes a string-to-string hashmap from the config file.
    fn take_string_map(
        &mut self,
        key: &str
    ) -> Result<Option<HashMap<String, String>>, Error> {
        match self.content.remove(key) {
            Some(::toml::Value::Array(vec)) => {
                let mut res = HashMap::new();
                for value in vec.into_iter() {
                    let mut pair = match value {
                        ::toml::Value::Array(pair) => pair.into_iter(),
                        _ => {
                            error!(
                                "Error in config file {}: \
                                '{}' expected to be a array of string pairs.",
                                self.path.display(),
                                key
                            );
                            return Err(Error);
                        }
                    };
                    let left = match pair.next() {
                        Some(::toml::Value::String(value)) => value,
                        _ => {
                            error!(
                                "Error in config file {}: \
                                '{}' expected to be a array of string pairs.",
                                self.path.display(),
                                key
                            );
                            return Err(Error);
                        }
                    };
                    let right = match pair.next() {
                        Some(::toml::Value::String(value)) => value,
                        _ => {
                            error!(
                                "Error in config file {}: \
                                '{}' expected to be a array of string pairs.",
                                self.path.display(),
                                key
                            );
                            return Err(Error);
                        }
                    };
                    if pair.next().is_some() {
                        error!(
                            "Error in config file {}: \
                            '{}' expected to be a array of string pairs.",
                            self.path.display(),
                            key
                        );
                        return Err(Error);
                    }
                    if res.insert(left, right).is_some() {
                        error!(
                            "Error in config file {}: \
                            'duplicate item in '{}'.",
                            self.path.display(),
                            key
                        );
                        return Err(Error);
                    }
                }
                Ok(Some(res))
            }
            Some(_) => {
                error!(
                    "Error in config file {}: \
                     '{}' expected to be a array of string pairs.",
                    self.path.display(), key
                );
                Err(Error)
            }
            None => Ok(None)
        }
    }

    /// Checks whether the config file is now empty.
    ///
    /// If it isn’t, logs a complaint and returns an error.
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
            error!(".");
            Err(Error)
        }
        else {
            Ok(())
        }
    }
}


//------------ Helpers -------------------------------------------------------

/// Try to convert a string encoded value.
///
/// This helper function just changes error handling. Instead of returning
/// the actual conversion error, it logs it as an invalid value for entry
/// `key` and returns the standard error.
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
                    error!(
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

/// Converts the syslog facility name to the facility type.
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

    fn process_server_args(args: &[&str]) -> Config {
        let mut config = get_default_config();
        let matches = Config::server_args(Config::config_args(
                App::new("routinator"))
        ).get_matches_from_safe(args).unwrap();
        config.apply_arg_matches(&matches, Path::new("/test")).unwrap();
        config.apply_server_arg_matches(&matches, Path::new("/test")).unwrap();
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
        assert_eq!(config.validation_threads, ::num_cpus::get());
        assert_eq!(config.refresh, Duration::from_secs(DEFAULT_REFRESH));
        assert_eq!(config.retry, Duration::from_secs(DEFAULT_RETRY));
        assert_eq!(config.expire, Duration::from_secs(DEFAULT_EXPIRE));
        assert_eq!(config.history_size, DEFAULT_HISTORY_SIZE);
        assert!(config.rtr_listen.is_empty());
        assert!(config.http_listen.is_empty());
        assert_eq!(config.systemd_listen, false);
        assert_eq!(config.log_level, LevelFilter::Warn);
        assert_eq!(config.log_target, LogTarget::Default(Facility::LOG_DAEMON));
    }

    #[test]
    #[cfg(unix)] // ... because of drive letters in absolute paths on Windows.
    fn good_config_file() {
        let config = ConfigFile::parse(
            "repository-dir = \"/repodir\"\n\
             tal-dir = \"taldir\"\n\
             exceptions = [\"ex1\", \"/ex2\"]\n\
             strict = true\n\
             validation-threads = 1000\n\
             refresh = 6\n\
             retry = 7\n\
             expire = 8\n\
             history-size = 5000\n\
             rtr-listen = [\"[2001:db8::4]:323\", \"192.0.2.4:323\"]\n\
             http-listen = [\"192.0.2.4:8080\"]\n\
             systemd-listen = true\n\
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
        assert_eq!(config.validation_threads, 1000);
        assert_eq!(config.refresh, Duration::from_secs(6));
        assert_eq!(config.retry, Duration::from_secs(7));
        assert_eq!(config.expire, Duration::from_secs(8));
        assert_eq!(config.history_size, 5000);
        assert_eq!(
            config.rtr_listen,
            vec![
                SocketAddr::from_str("[2001:db8::4]:323").unwrap(),
                SocketAddr::from_str("192.0.2.4:323").unwrap(),
            ]
        );
        assert_eq!(
            config.http_listen,
            vec![SocketAddr::from_str("192.0.2.4:8080").unwrap()]
        );
        assert_eq!(config.systemd_listen, true);
        assert_eq!(config.log_level, LevelFilter::Info);
        assert_eq!(
            config.log_target,
            LogTarget::File(PathBuf::from("/test/foo.log"))
        );
    }

    #[test]
    #[cfg(unix)] // ... because of drive letters in absolute paths on Windows.
    fn minimal_config_file() {
        let config = ConfigFile::parse(
            "repository-dir = \"/repodir\"\n\
             tal-dir = \"taldir\"",
            &Path::new("/test/routinator.conf")
        ).unwrap();
        let config = Config::from_config_file(config).unwrap();
        assert_eq!(config.cache_dir.to_str().unwrap(), "/repodir");
        assert_eq!(config.tal_dir.to_str().unwrap(), "/test/taldir");
        assert!(config.exceptions.is_empty());
        assert_eq!(config.strict, false);
        assert_eq!(config.validation_threads, ::num_cpus::get());
        assert_eq!(config.refresh, Duration::from_secs(DEFAULT_REFRESH));
        assert_eq!(config.retry, Duration::from_secs(DEFAULT_RETRY));
        assert_eq!(config.expire, Duration::from_secs(DEFAULT_EXPIRE));
        assert_eq!(config.history_size, DEFAULT_HISTORY_SIZE);
        assert!(config.rtr_listen.is_empty());
        assert!(config.http_listen.is_empty());
        assert_eq!(config.systemd_listen, false);
        assert!(config.http_listen.is_empty());
        assert_eq!(config.log_level, LevelFilter::Warn);
        assert_eq!(
            config.log_target,
            LogTarget::default()
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
            "--validation-threads", "2000",
            "--syslog", "--syslog-facility", "auth"
        ]);
        assert_eq!(config.cache_dir, Path::new("/repository"));
        assert_eq!(config.tal_dir, Path::new("/test/tals"));
        assert_eq!(
            config.exceptions, [Path::new("/x1"), Path::new("/test/x2")]
        );
        assert_eq!(config.strict, true);
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
    fn server_args() {
        let config = process_server_args(&[
            "routinator", "--refresh", "7", "--retry", "8", "--expire", "9",
            "--history", "1000",
            "--rtr", "[2001:db8::4]:323",
            "--rtr", "192.0.2.4:323",
            "--http", "192.0.2.4:8080",
            "--systemd-listen",
        ]);
        assert_eq!(config.refresh, Duration::from_secs(7));
        assert_eq!(config.retry, Duration::from_secs(8));
        assert_eq!(config.expire, Duration::from_secs(9));
        assert_eq!(config.history_size, 1000);
        assert_eq!(
            config.rtr_listen,
            vec![
                SocketAddr::from_str("[2001:db8::4]:323").unwrap(),
                SocketAddr::from_str("192.0.2.4:323").unwrap(),
            ]
        );
        assert_eq!(
            config.http_listen,
            vec![SocketAddr::from_str("192.0.2.4:8080").unwrap()]
        );
        assert_eq!(config.systemd_listen, true);
    }
}

