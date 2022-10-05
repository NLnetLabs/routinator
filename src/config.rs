//! Configuration.
//!
//! This module primarily contains the type [`Config`] that holds all the
//! configuration used by Routinator. It can be loaded both from a TOML
//! formatted config file and command line options.
//!
//! [`Config`]: struct.Config.html

use std::{env, fmt, fs};
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
use clap::{
    Command, Args, ArgAction, ArgMatches, FromArgMatches, Parser,
    crate_version,
};
use dirs::home_dir;
use log::{LevelFilter, error};
#[cfg(unix)] use syslog::Facility;
use crate::error::Failed;


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

/// The default for the RRDP timeout.
const DEFAULT_RRDP_TIMEOUT: Duration = Duration::from_secs(300);

/// The default for the RRDP fallback time.
const DEFAULT_RRDP_FALLBACK_TIME: Duration = Duration::from_secs(3600);

/// The default for the maximum number of deltas.
const DEFAULT_RRDP_MAX_DELTA_COUNT: usize = 100;

/// The default RRDP HTTP User Agent header value to send.
const DEFAULT_RRDP_USER_AGENT: &str = concat!("Routinator/", crate_version!());

/// The default RTR TCP keepalive.
const DEFAULT_RTR_TCP_KEEPALIVE: Option<Duration>
    = Some(Duration::from_secs(60));

/// The default stale policy.
const DEFAULT_STALE_POLICY: FilterPolicy = FilterPolicy::Reject;

/// The default unsafe-vrps policy.
const DEFAULT_UNSAFE_VRPS_POLICY: FilterPolicy = FilterPolicy::Accept;

/// The default unknown-objects policy.
const DEFAULT_UNKNOWN_OBJECTS_POLICY: FilterPolicy = FilterPolicy::Warn;

/// The default maximum object size.
const DEFAULT_MAX_OBJECT_SIZE: u64 = 20_000_000;

/// The default maximum CA depth.
const DEFAULT_MAX_CA_DEPTH: usize = 32;

/// The default syslog facility.
#[cfg(unix)]
const DEFAULT_SYSLOG_FACILITY: Facility = Facility::LOG_DAEMON;


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
#[derive(Clone, Debug, Eq, PartialEq)]
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
    /// Stale objects are manifests and CRLs that have a `next_update` field
    /// in the past. The current version of the protocol leaves the decision
    /// how to interpret stale objects to local policy. This configuration
    /// value configures this policy.
    ///
    /// Since the upcoming version of the protocol clarifies that these
    /// objects should be rejected, this is the default policy.
    pub stale: FilterPolicy,

    /// How should we deal with unsafe VRPs?
    ///
    /// Unsafe VRPs have their prefix intersect with a prefix held by a
    /// rejected CA. Allowing such VRPs may lead to legitimate routes being
    /// flagged as RPKI invalid. To avoid this, these can VRPs can be
    /// filtered.
    ///
    /// The default for now is to warn about them.
    pub unsafe_vrps: FilterPolicy,

    /// How to deal with unknown RPKI object types.
    pub unknown_objects: FilterPolicy,

    /// Allow dubious host names.
    pub allow_dubious_hosts: bool,

    /// Should we wipe the cache before starting?
    ///
    /// (This option is only available on command line.)
    pub fresh: bool,

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

    /// Whether to disable RRDP.
    pub disable_rrdp: bool,

    /// Time since last update of an RRDP repository before fallback to rsync.
    pub rrdp_fallback_time: Duration,

    /// The maxmimm number of deltas we allow before using snapshot.
    pub rrdp_max_delta_count: usize,

    /// RRDP timeout in seconds.
    ///
    /// If this is None, no timeout is set.
    pub rrdp_timeout: Option<Duration>,

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

    /// RRDP HTTP User Agent.
    pub rrdp_user_agent: String,

    /// Should we keep RRDP responses and if so where?
    pub rrdp_keep_responses: Option<PathBuf>,

    /// Optional size limit for objects.
    pub max_object_size: Option<u64>,

    /// Maxium length of the CA chain.
    pub max_ca_depth: usize,

    /// Whether to process BGPsec router keys.
    pub enable_bgpsec: bool,

    /// Whether to not cleanup the repository directory after a validation run.
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

    /// Addresses to listen on for RTR TLS transport connections.
    pub rtr_tls_listen: Vec<SocketAddr>,

    /// Addresses to listen on for HTTP connections.
    pub http_listen: Vec<SocketAddr>,

    /// Addresses to listen on for HTTP TLS connections.
    pub http_tls_listen: Vec<SocketAddr>,

    /// Whether to get the listening sockets from systemd.
    pub systemd_listen: bool,

    /// The length of the TCP keep-alive timeout for RTR TCP sockets.
    ///
    /// If this is `None`, TCP keep-alive will not be enabled.
    pub rtr_tcp_keepalive: Option<Duration>,

    /// Should we publish detailed RTR client statistics?
    pub rtr_client_metrics: bool,

    /// Path to the RTR TLS private key.
    pub rtr_tls_key: Option<PathBuf>,

    /// Path to the RTR TLS server certificate.
    pub rtr_tls_cert: Option<PathBuf>,

    /// Path to the HTTP TLS private key.
    pub http_tls_key: Option<PathBuf>,

    /// Path to the HTTP TLS server certificate.
    pub http_tls_cert: Option<PathBuf>,

    /// The log levels to be logged.
    pub log_level: LevelFilter,

    /// The target to log to.
    pub log_target: LogTarget,

    /// The optional PID file for server mode.
    pub pid_file: Option<PathBuf>,

    /// The optional working directory for server mode.
    pub working_dir: Option<PathBuf>,

    /// The optional directory to chroot to in server mode.
    pub chroot: Option<PathBuf>,

    /// The name of the user to change to in server mode.
    pub user: Option<String>,

    /// The name of the group to change to in server mode.
    pub group: Option<String>,

    /// A mapping of TAL file names to TAL labels.
    pub tal_labels: HashMap<String, String>,
}


impl Config {
    /// Adds the basic arguments to a clapp app.
    ///
    /// The function follows clap’s builder pattern: it takes an app,
    /// adds a bunch of arguments to it and returns it at the end.
    pub fn config_args(app: Command) -> Command {
        GlobalArgs::augment_args(app)
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
    pub fn server_args(app: Command) -> Command {
        ServerArgs::augment_args(app)
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
    ) -> Result<Self, Failed> {
        let mut res = Self::create_base_config(
            Self::path_value_of(matches, "config", cur_dir)
                .as_ref().map(AsRef::as_ref)
        )?;

        res.apply_arg_matches(matches, cur_dir)?;

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
    ) -> Result<(), Failed> {
        let args = GlobalArgs::from_arg_matches(
            matches
        ).expect("bug in command line arguments parser");


        // log_target - Goes first so we can move things out of args later.
        self.apply_log_matches(&args, cur_dir)?;

        // cache_dir
        if let Some(dir) = args.repository_dir {
            self.cache_dir = cur_dir.join(dir)
        }
        else if let Some(dir) = args.base_dir.as_ref() {
            self.cache_dir = cur_dir.join(dir).join("repository")
        }
        if self.cache_dir == Path::new("") {
            error!(
                "Couldn’t determine default repository directory: \
                 no home directory.\n\
                 Please specify the repository directory with the -r option."
            );
            return Err(Failed)
        }

        // tal_dir
        if let Some(dir) = args.tal_dir {
            self.tal_dir = cur_dir.join(dir)
        }
        else if let Some(dir) = args.base_dir.as_ref() {
            self.tal_dir = cur_dir.join(dir).join("tals")
        }
        if self.tal_dir == Path::new("") {
            error!(
                "Couldn’t determine default TAL directory: \
                 no home directory.\n\
                 Please specify the repository directory with the -t option."
            );
            return Err(Failed)
        }

        // exceptions
        if let Some(list) = args.exceptions {
            self.exceptions = list.into_iter().map(|path| {
                cur_dir.join(path)
            }).collect()
        }

        // strict
        if args.strict {
            self.strict = true
        }

        // stale
        if let Some(value) = args.stale {
            self.stale = value
        }

        // unsafe_vrps
        if let Some(value) = args.unsafe_vrps {
            self.unsafe_vrps = value
        }

        // unknown_objects
        if let Some(value) = args.unknown_objects {
            self.unknown_objects = value
        }

        // allow_dubious_hosts
        if args.allow_dubious_hosts {
            self.allow_dubious_hosts = true
        }

        // fresh
        if args.fresh {
            self.fresh = true
        }

        // disable_rsync
        if args.disable_rsync {
            self.disable_rsync = true
        }

        // rsync_command
        if let Some(value) = args.rsync_command {
            self.rsync_command = value
        }

        // rsync_timeout
        if let Some(value) = args.rsync_timeout {
            self.rsync_timeout = Duration::from_secs(value)
        }

        // disable_rrdp
        if args.disable_rrdp {
            self.disable_rrdp = true
        }

        // rrdp_fallback_time
        if let Some(value) = args.rrdp_fallback_time {
            self.rrdp_fallback_time = Duration::from_secs(value)
        }

        // rrdp_max_delta_count
        if let Some(value) = args.rrdp_max_delta_count {
            self.rrdp_max_delta_count = value
        }

        // rrdp_timeout
        if let Some(value) = args.rrdp_timeout {
            self.rrdp_timeout = if value == 0 {
                None
            }
            else {
                Some(Duration::from_secs(value))
            };
        }

        // rrdp_connect_timeout
        if let Some(value) = args.rrdp_connect_timeout {
            self.rrdp_connect_timeout = Some(Duration::from_secs(value))
        }

        // rrdp_local_addr
        if let Some(value) = args.rrdp_local_addr {
            self.rrdp_local_addr = Some(value)
        }

        // rrdp_root_certs
        if let Some(list) = args.rrdp_root_cert {
            self.rrdp_root_certs = list.into_iter().map(|path| {
                cur_dir.join(path)
            }).collect()
        }

        // rrdp_proxies
        if let Some(list) = args.rrdp_proxy {
            self.rrdp_proxies = list
        }

        // rrdp_keep_responses
        if let Some(path) = args.rrdp_keep_responses {
            self.rrdp_keep_responses = Some(path)
        }

        // max_object_size
        if let Some(value) = args.max_object_size {
            if value == 0 {
                self.max_object_size = None
            }
            else {
                self.max_object_size = Some(value)
            }
        }

        // max_ca_depth
        if let Some(value) = args.max_ca_depth {
            self.max_ca_depth = value;
        }

        // enable_bgpsec
        if args.enable_bgpsec {
            self.enable_bgpsec = true
        }

        // dirty_repository
        if args.dirty_repository {
            self.dirty_repository = true
        }

        // validation_threads
        if let Some(value) = args.validation_threads {
            self.validation_threads = value
        }

        // log_level
        if args.verbose > 1 {
            self.log_level = LevelFilter::Debug
        }
        else if args.verbose == 1 {
            self.log_level = LevelFilter::Info
        }
        else if args.quiet > 1 {
            self.log_level = LevelFilter::Off
        }
        else if args.quiet == 1 {
            self.log_level = LevelFilter::Error
        }

        Ok(())
    }

    /// Applies the logging-specific command line arguments to the config.
    ///
    /// This is the Unix version that also considers syslog as a valid
    /// target.
    #[cfg(unix)]
    fn apply_log_matches(
        &mut self,
        args: &GlobalArgs,
        cur_dir: &Path,
    ) -> Result<(), Failed> {
        if args.syslog {
            if let Some(facility) = args.syslog_facility.as_ref() {
                self.log_target = LogTarget::Syslog(
                    match Facility::from_str(facility) {
                        Ok(value) => value,
                        Err(_) => {
                            error!("Invalid value for syslog-facility.");
                            return Err(Failed);
                        }
                    }
                )
            }
            else if !matches!(self.log_target, LogTarget::Syslog(_)) {
                // If we don’t have a syslog facility already from the config
                // file, we use the default.
                self.log_target = LogTarget::Syslog(DEFAULT_SYSLOG_FACILITY)
            }
        }
        else if let Some(file) = args.logfile.as_ref() {
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
    #[allow(clippy::unnecessary_wraps)]
    fn apply_log_matches(
        &mut self,
        matches: &ArgMatches,
        cur_dir: &Path,
    ) -> Result<(), Failed> {
        if let Some(file) = args.logfile.as_ref() {
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
    ) -> Result<(), Failed> {
        let args = ServerArgs::from_arg_matches(
            matches
        ).expect("bug in command line arguments parser");

        // refresh
        if let Some(value) = args.refresh {
            self.refresh = Duration::from_secs(value)
        }

        // retry
        if let Some(value) = args.retry {
            self.retry = Duration::from_secs(value)
        }

        // expire
        if let Some(value) = args.expire {
            self.expire = Duration::from_secs(value)
        }

        // history_size
        if let Some(value) = args.history {
            self.history_size = value
        }

        // rtr_listen
        if let Some(list) = args.rtr_listen {
            self.rtr_listen = list
        }

        // rtr_tls_listen
        if let Some(list) = args.rtr_tls_listen {
            self.rtr_tls_listen = list
        }

        // http_listen
        if let Some(list) = args.http_listen {
            self.http_listen = list
        }

        // http_tls_listen
        if let Some(list) = args.http_tls_listen {
            self.http_tls_listen = list
        }

        // systemd_listen
        if args.systemd_listen {
            self.systemd_listen = true
        }

        // rtr_tcp_keepalive
        if let Some(keep) = args.rtr_tcp_keepalive {
            self.rtr_tcp_keepalive = if keep == 0 {
                None
            }
            else {
                Some(Duration::from_secs(keep))
            }
        }

        // rtr_client_metrics
        if args.rtr_client_metrics {
            self.rtr_client_metrics = true
        }

        // rtr_tls_key
        if let Some(path) = args.rtr_tls_key {
            self.rtr_tls_key = Some(cur_dir.join(path))
        }

        // rtr_tls_cert
        if let Some(path) = args.rtr_tls_cert {
            self.rtr_tls_cert = Some(cur_dir.join(path))
        }

        // http_tls_key
        if let Some(path) = args.http_tls_key {
            self.http_tls_key = Some(cur_dir.join(path))
        }

        // http_tls_cert
        if let Some(path) = args.http_tls_cert {
            self.http_tls_cert = Some(cur_dir.join(path))
        }

        // pid_file
        if let Some(pid_file) = args.pid_file {
            self.pid_file = Some(cur_dir.join(pid_file))
        }

        // working_dir
        if let Some(working_dir) = args.working_dir {
            self.working_dir = Some(cur_dir.join(working_dir))
        }

        // chroot
        if let Some(chroot) = args.chroot {
            self.chroot = Some(cur_dir.join(chroot))
        }

        // user
        if let Some(user) = args.user {
            self.user = Some(user)
        }

        // group
        if let Some(group) = args.group {
            self.group = Some(group)
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
        matches.get_one::<PathBuf>(key).map(|path| dir.join(path))
    }

    /// Creates the correct base configuration for the given config file path.
    /// 
    /// If no config path is given, tries to read the default config in
    /// `$HOME/.routinator.conf`. If that doesn’t exist, creates a default
    /// config.
    fn create_base_config(path: Option<&Path>) -> Result<Self, Failed> {
        let file = match path {
            Some(path) => {
                match ConfigFile::read(path)? {
                    Some(file) => file,
                    None => {
                        error!("Cannot read config file {}", path.display());
                        return Err(Failed);
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
    fn from_config_file(mut file: ConfigFile) -> Result<Self, Failed> {
        let log_target = Self::log_target_from_config_file(&mut file)?;
        let res = Config {
            cache_dir: file.take_mandatory_path("repository-dir")?,
            tal_dir: file.take_mandatory_path("tal-dir")?,
            exceptions: {
                file.take_path_array("exceptions")?.unwrap_or_default()
            },
            strict: file.take_bool("strict")?.unwrap_or(false),
            stale: {
                file.take_from_str("stale")?.unwrap_or(DEFAULT_STALE_POLICY)
            },
            unsafe_vrps: {
                file.take_from_str("unsafe-vrps")?
                    .unwrap_or(DEFAULT_UNSAFE_VRPS_POLICY)
            },
            unknown_objects: {
                file.take_from_str("unknown-objects")?
                    .unwrap_or(DEFAULT_UNKNOWN_OBJECTS_POLICY)
            },
            allow_dubious_hosts:
                file.take_bool("allow-dubious-hosts")?.unwrap_or(false),
            fresh: false,
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
            rrdp_fallback_time: {
                file.take_u64("rrdp-fallback-time")?
                .map(Duration::from_secs)
                .unwrap_or(DEFAULT_RRDP_FALLBACK_TIME)
            },
            rrdp_max_delta_count: {
                file.take_usize("rrdp-max-delta-count")?
                .unwrap_or(DEFAULT_RRDP_MAX_DELTA_COUNT)
            },
            rrdp_timeout: {
                match file.take_u64("rrdp-timeout")? {
                    Some(0) => None,
                    Some(value) => Some(Duration::from_secs(value)),
                    None => Some(DEFAULT_RRDP_TIMEOUT)
                }
            },
            rrdp_connect_timeout: {
                file.take_u64("rrdp-connect-timeout")?.map(Duration::from_secs)
            },
            rrdp_local_addr: file.take_from_str("rrdp-local-addr")?,
            rrdp_root_certs: {
                file.take_from_str_array("rrdp-root-certs")?
                    .unwrap_or_default()
            },
            rrdp_proxies: {
                file.take_string_array("rrdp-proxies")?.unwrap_or_default()
            },
            rrdp_user_agent: DEFAULT_RRDP_USER_AGENT.to_string(),
            rrdp_keep_responses: file.take_path("rrdp-keep-responses")?,
            max_object_size: {
                match file.take_u64("max-object-size")? {
                    Some(0) => None,
                    Some(value) => Some(value),
                    None => Some(DEFAULT_MAX_OBJECT_SIZE),
                }
            },
            max_ca_depth: {
                file.take_usize("max-ca-depth")?
                    .unwrap_or(DEFAULT_MAX_CA_DEPTH)
            },
            enable_bgpsec: file.take_bool("enable-bgpsec")?.unwrap_or(false),
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
                file.take_from_str_array("rtr-listen")?.unwrap_or_default()
            },
            rtr_tls_listen: {
                file.take_from_str_array("rtr-tls-listen")?
                    .unwrap_or_default()
            },
            http_listen: {
                file.take_from_str_array("http-listen")?.unwrap_or_default()
            },
            http_tls_listen: {
                file.take_from_str_array("http-tls-listen")?
                    .unwrap_or_default()
            },
            systemd_listen: file.take_bool("systemd-listen")?.unwrap_or(false),
            rtr_tcp_keepalive: {
                match file.take_u64("rtr-tcp-keepalive")? {
                    Some(0) => None,
                    Some(keep) => Some(Duration::from_secs(keep)),
                    None => DEFAULT_RTR_TCP_KEEPALIVE,
                }
            },
            rtr_client_metrics: {
                file.take_bool("rtr-client-metrics")?.unwrap_or(false)
            },
            rtr_tls_key: file.take_path("rtr-tls-key")?,
            rtr_tls_cert: file.take_path("rtr-tls-cert")?,
            http_tls_key: file.take_path("http-tls-key")?,
            http_tls_cert: file.take_path("http-tls-cert")?,
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
    ) -> Result<LogTarget, Failed> {
        let facility = file.take_string("syslog-facility")?;
        let facility = facility.as_ref().map(AsRef::as_ref)
                               .unwrap_or("daemon");
        let facility = match Facility::from_str(facility) {
            Ok(value) => value,
            Err(_) => {
                error!(
                    "Failed in config file {}: invalid syslog-facility.",
                    file.path.display()
                );
                return Err(Failed);
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
                            "Failed in config file {}: \
                             log target \"file\" requires 'log-file' value.",
                            file.path.display()
                        );
                        Err(Failed)
                    }
                }
            }
            Some(value) => {
                error!(
                    "Failed in config file {}: \
                     invalid log target '{}'",
                     file.path.display(),
                     value
                );
                Err(Failed)
            }
        }
    }

    /// Determines the logging target from the config file.
    ///
    /// This is the non-Unix version that only logs to stderr or a file.
    #[cfg(not(unix))]
    fn log_target_from_config_file(
        file: &mut ConfigFile
    ) -> Result<LogTarget, Failed> {
        let log_target = file.take_string("log")?;
        let log_file = file.take_path("log-file")?;
        match log_target.as_ref().map(AsRef::as_ref) {
            Some("default") | Some("stderr") | None => Ok(LogTarget::Stderr),
            Some("file") => {
                match log_file {
                    Some(file) => Ok(LogTarget::File(file)),
                    None => {
                        error!(
                            "Failed in config file {}: \
                             log target \"file\" requires 'log-file' value.",
                            file.path.display()
                        );
                        Err(Failed)
                    }
                }
            }
            Some(value) => {
                error!(
                    "Failed in config file {}: \
                     invalid log target '{}'",
                    file.path.display(), value
                );
                Err(Failed)
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
            stale: DEFAULT_STALE_POLICY,
            unsafe_vrps: DEFAULT_UNSAFE_VRPS_POLICY,
            unknown_objects: DEFAULT_UNKNOWN_OBJECTS_POLICY,
            allow_dubious_hosts: false,
            fresh: false,
            disable_rsync: false,
            rsync_command: "rsync".into(),
            rsync_args: None,
            rsync_timeout: Duration::from_secs(DEFAULT_RSYNC_TIMEOUT),
            disable_rrdp: false,
            rrdp_fallback_time: DEFAULT_RRDP_FALLBACK_TIME,
            rrdp_max_delta_count: DEFAULT_RRDP_MAX_DELTA_COUNT,
            rrdp_timeout: Some(DEFAULT_RRDP_TIMEOUT), 
            rrdp_connect_timeout: None,
            rrdp_local_addr: None,
            rrdp_root_certs: Vec::new(),
            rrdp_proxies: Vec::new(),
            rrdp_user_agent: DEFAULT_RRDP_USER_AGENT.to_string(),
            rrdp_keep_responses: None,
            max_object_size: Some(DEFAULT_MAX_OBJECT_SIZE),
            max_ca_depth: DEFAULT_MAX_CA_DEPTH,
            enable_bgpsec: false,
            dirty_repository: DEFAULT_DIRTY_REPOSITORY,
            validation_threads: ::num_cpus::get(),
            refresh: Duration::from_secs(DEFAULT_REFRESH),
            retry: Duration::from_secs(DEFAULT_RETRY),
            expire: Duration::from_secs(DEFAULT_EXPIRE),
            history_size: DEFAULT_HISTORY_SIZE,
            rtr_listen: Vec::new(),
            rtr_tls_listen: Vec::new(),
            http_listen: Vec::new(),
            http_tls_listen: Vec::new(),
            systemd_listen: false,
            rtr_tcp_keepalive: DEFAULT_RTR_TCP_KEEPALIVE,
            rtr_client_metrics: false,
            rtr_tls_key: None,
            rtr_tls_cert: None,
            http_tls_key: None,
            http_tls_cert: None,
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

    /// Alters paths so that they are relative to a possible chroot.
    pub fn adjust_chroot_paths(&mut self) -> Result<(), Failed> {
        if let Some(ref chroot) = self.chroot {
            self.cache_dir = match self.cache_dir.strip_prefix(chroot) {
                Ok(dir) => dir.into(),
                Err(_) => {
                    error!(
                        "Fatal: Repository directory {} \
                         not under chroot {}.",
                         self.cache_dir.display(), chroot.display()
                    );
                    return Err(Failed)
                }
            };
            self.tal_dir = match self.tal_dir.strip_prefix(chroot) {
                Ok(dir) => dir.into(),
                Err(_) => {
                    error!(
                        "Fatal: TAL directory {} not under chroot {}.",
                         self.tal_dir.display(), chroot.display()
                    );
                    return Err(Failed)
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
                        return Err(Failed)
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
                        return Err(Failed)
                    }
                };
            }
            if let Some(ref mut dir) = self.working_dir {
                *dir = match dir.strip_prefix(chroot) {
                    Ok(path) => path.into(),
                    Err(_) => {
                        error!(
                            "Fatal: working directory {} not under chroot {}.",
                             dir.display(), chroot.display()
                        );
                        return Err(Failed)
                    }
                }
            }
        }
        Ok(())
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
            "unsafe-vrps".into(), format!("{}", self.unsafe_vrps).into()
        );
        res.insert(
            "unknown-objects".into(), format!("{}", self.unknown_objects).into()
        );
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
        res.insert(
            "rrdp-fallback-time".into(),
            (self.rrdp_fallback_time.as_secs() as i64).into()
        );
        res.insert(
            "rrdp-max-delta-count".into(),
            i64::try_from(self.rrdp_max_delta_count).unwrap_or(i64::MAX).into()
        );
        res.insert(
            "rrdp-timeout".into(),
            match self.rrdp_timeout {
                None => 0.into(),
                Some(value) => {
                    value.as_secs().try_into().unwrap_or(i64::MAX).into()
                }
            }
        );
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
        if let Some(path) = self.rrdp_keep_responses.as_ref() {
            res.insert(
                "rrdp-keep-responses".into(),
                format!("{}", path.display()).into()
            );
        }
        res.insert("max-object-size".into(),
            match self.max_object_size {
                Some(value) => value as i64,
                None => 0,
            }.into()
        );
        res.insert("max-ca-depth".into(),
            (self.max_ca_depth as i64).into()
        );
        res.insert("enable-bgpsec".into(), self.enable_bgpsec.into());
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
            "rtr-tls-listen".into(),
            toml::Value::Array(
                self.rtr_tls_listen.iter().map(|a| {
                    a.to_string().into()
                }).collect()
            )
        );
        res.insert(
            "http-listen".into(),
            toml::Value::Array(
                self.http_listen.iter().map(|a| a.to_string().into()).collect()
            )
        );
        res.insert(
            "http-tls-listen".into(),
            toml::Value::Array(
                self.http_tls_listen.iter().map(|a| {
                    a.to_string().into()
                }).collect()
            )
        );
        res.insert("systemd-listen".into(), self.systemd_listen.into());
        res.insert("rtr-tcp-keepalive".into(),
            match self.rtr_tcp_keepalive {
                Some(keep) => (keep.as_secs() as i64).into(),
                None => 0.into(),
            }
        );
        res.insert(
            "rtr-client-metrics".into(),
            self.rtr_client_metrics.into()
        );
        if let Some(ref path) = self.rtr_tls_key {
            res.insert(
                "rtr-tls-key".into(),
                path.display().to_string().into()
            );
        }
        if let Some(ref path) = self.rtr_tls_cert {
            res.insert(
                "rtr-tls-cert".into(),
                path.display().to_string().into()
            );
        }
        if let Some(ref path) = self.http_tls_key {
            res.insert(
                "http-tls-key".into(),
                path.display().to_string().into()
            );
        }
        if let Some(ref path) = self.http_tls_cert {
            res.insert(
                "http-tls-cert".into(),
                path.display().to_string().into()
            );
        }
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


//------------ FilterPolicy ---------------------------------------------------

/// The policy for filtering.
///
/// Various filters can be configured via this policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilterPolicy {
    /// Reject objects matched by the filter.
    Reject,

    /// Accept objects matched by the filter but log a warning.
    Warn,

    /// Quietly accept objects matched by the filter.
    Accept
}

impl FilterPolicy {
    /// Does the filter policy require logging?
    ///
    /// This is true for reject and warn.
    pub fn log(self) -> bool {
        matches!(self, FilterPolicy::Reject | FilterPolicy::Warn)
    }
}

impl FromStr for FilterPolicy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "reject" => Ok(FilterPolicy::Reject),
            "warn" => Ok(FilterPolicy::Warn),
            "accept" => Ok(FilterPolicy::Accept),
            _ => Err(format!("invalid policy '{}'", s))
        }
    }
}

impl fmt::Display for FilterPolicy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match *self {
            FilterPolicy::Reject => "reject",
            FilterPolicy::Warn => "warn",
            FilterPolicy::Accept => "accept",
        })
    }
}


//------------ GlobalArgs ----------------------------------------------------

/// The global command line arguments.
#[derive(Clone, Debug, Parser)]
struct GlobalArgs {
    /// Read base configuration from this file
    #[arg(short, long, value_name="PATH")]
    config: Option<PathBuf>,

    /// Sets the base directory for cache and TALs
    #[arg(short, long, value_name="PATH")]
    base_dir: Option<PathBuf>,

    /// Sets the repository cache directory
    #[arg(short, long, value_name="PATH")]
    repository_dir: Option<PathBuf>,

    /// Sets the TAL directory
    #[arg(short, long, value_name="PATH")]
    tal_dir: Option<PathBuf>,

    /// File with local exceptions (see RFC 8416 for format)
    #[arg(short, long, value_name="PATH")]
    exceptions: Option<Vec<PathBuf>>,

    /// Parse RPKI data in strict mode
    #[arg(long)]
    strict: bool,

    /// The policy for handling stale objects
    #[arg(long, value_name = "POLICY")]
    stale: Option<FilterPolicy>,

    /// The policy for handling unsafe VRPs
    #[arg(long, value_name = "POLICY")]
    unsafe_vrps: Option<FilterPolicy>,

    /// The policy for handling unknown object types
    #[arg(long, value_name = "POLICY")]
    unknown_objects: Option<FilterPolicy>,

    /// Allow dubious host names in rsync and HTTPS URIs
    #[arg(long)]
    allow_dubious_hosts: bool,

    /// Delete cached data, download everything again
    #[arg(long)]
    fresh: bool,

    /// Disable rsync and only use RRDP
    #[arg(long)]
    disable_rsync: bool,

    /// The command to run for rsync
    #[arg(long, value_name="COMMAND")]
    rsync_command: Option<String>,

    /// Timeout for rsync commands
    #[arg(long, value_name = "SECONDS")]
    rsync_timeout: Option<u64>,

    /// Disable RRDP and only use rsync
    #[arg(long)]
    disable_rrdp: bool,

    /// Maximum number of RRDP deltas before using snapshot
    #[arg(long, value_name = "COUNT")]
    rrdp_max_delta_count: Option<usize>,

    /// Maximum time since last update before fallback to rsync
    #[arg(long, value_name = "SECONDS")]
    rrdp_fallback_time: Option<u64>,

    /// Timeout of network operation for RRDP (0 for none)
    #[arg(long, value_name = "SECONDS")]
    rrdp_timeout: Option<u64>,

    /// Timeout for connecting to an RRDP server
    #[arg(long, value_name = "SECONDS")]
    rrdp_connect_timeout: Option<u64>,

    /// Local address for outgoing RRDP connections
    #[arg(long, value_name = "ADDR")]
    rrdp_local_addr: Option<IpAddr>,

    /// Path to trusted PEM certificate for RRDP HTTPS
    #[arg(long, value_name = "PATH")]
    rrdp_root_cert: Option<Vec<PathBuf>>,

    /// Proxy server for RRDP (HTTP or SOCKS5)
    #[arg(long, value_name = "URI")]
    rrdp_proxy: Option<Vec<String>>,

    /// Keep RRDP responses in the given directory
    #[arg(long, value_name = "PATH")]
    rrdp_keep_responses: Option<PathBuf>,

    /// Maximum size of downloaded objects (0 for no limit)
    #[arg(long, value_name = "BYTES")]
    max_object_size: Option<u64>,

    /// Maximum distance of a CA from a trust anchor
    #[arg(long, value_name = "COUNT")]
    max_ca_depth: Option<usize>,

    /// Include BGPsec router keys in the data set
    #[arg(long)]
    enable_bgpsec: bool,

    /// Do not clean up repository directory after validation
    #[arg(long)]
    dirty_repository: bool,

    /// Number of threads for validation
    #[arg(long, value_name = "COUNT")]
    validation_threads: Option<usize>,

    /// Log more information, twice for even more
    #[arg(short, long, action = ArgAction::Count)]
    verbose: u8,

    /// Log less information, twice for no information
    #[arg(short, long, action = ArgAction::Count, conflicts_with = "verbose")]
    quiet: u8,

    /// Log to syslog
    #[cfg(unix)]
    #[arg(long)]
    syslog: bool,

    /// Facility to use for syslog logging
    #[cfg(unix)]
    #[arg(long, value_name = "FACILITY")]
    syslog_facility: Option<String>,

    /// Log to this file
    #[arg(long, value_name = "PATH")]
    logfile: Option<String>,
}


//------------ ServerArgs ----------------------------------------------------

/// The server-related command line arguments.
#[derive(Clone, Debug, Parser)]
struct ServerArgs {
    /// Refresh interval in seconds [default 3600]
    #[arg(long, value_name = "SECONDS")]
    refresh: Option<u64>,

    /// RTR retry interval in seconds [default 600]
    #[arg(long, value_name = "SECONDS")]
    retry: Option<u64>,

    /// RTR expire interval in seconds [default 600]
    #[arg(long, value_name = "SECONDS")]
    expire: Option<u64>,

    /// Number of history items to keep [default 10]
    #[arg(long, value_name = "COUNT")]
    history: Option<usize>,

    /// Listen on address/port for RTR
    #[arg(long = "rtr", value_name = "ADDR:PORT")]
    rtr_listen: Option<Vec<SocketAddr>>,

    /// Listen on address/port for RTR over TLS
    #[arg(long = "rtr-tls", value_name = "ADDR:PORT")]
    rtr_tls_listen: Option<Vec<SocketAddr>>,

    /// Listen on address/port for HTTP
    #[arg(long = "http", value_name = "ADDR:PORT")]
    http_listen: Option<Vec<SocketAddr>>,

    /// Listen on address/port for HTTP over TLS
    #[arg(long = "http-tls", value_name = "ADDR:PORT")]
    http_tls_listen: Option<Vec<SocketAddr>>,

    /// Acquire listening sockets from systemd
    #[arg(long)]
    systemd_listen: bool,

    /// TCP keep-alive timeout on RTR [default 60, 0 for off]
    #[arg(long, value_name = "SECONDS")]
    rtr_tcp_keepalive: Option<u64>,

    /// Include RTR client information in metrics
    #[arg(long)]
    rtr_client_metrics: bool,

    /// The private key to use for RTR over TLS
    #[arg(long, value_name = "PATH")]
    rtr_tls_key: Option<PathBuf>,

    /// The certificate to use for RTR over TLS
    #[arg(long, value_name = "PATH")]
    rtr_tls_cert: Option<PathBuf>,

    /// The private key to use for HTTP over TLS
    #[arg(long, value_name = "PATH")]
    http_tls_key: Option<PathBuf>,

    /// The certificate to use for HTTP over TLS
    #[arg(long, value_name = "PATH")]
    http_tls_cert: Option<PathBuf>,

    /// The file for keep the daemon process's PID in
    #[arg(long, value_name = "PATH")]
    pid_file: Option<PathBuf>,

    /// The working directory of the daemon process
    #[arg(long, value_name = "PATH")]
    working_dir: Option<PathBuf>,

    /// Root directory for the daemon process
    #[arg(long, value_name = "PATH")]
    chroot: Option<PathBuf>,

    /// User for the daemon process
    #[arg(long, value_name = "UID")]
    user: Option<String>,

    /// Group for the daemon process
    #[arg(long, value_name = "GID")]
    group: Option<String>,
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
    fn read(path: &Path) -> Result<Option<Self>, Failed> {
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
            return Err(Failed);
        }
        Self::parse(&config, path).map(Some)
    }

    /// Parses the content of the file from a string.
    fn parse(content: &str, path: &Path) -> Result<Self, Failed> {
        let content = match toml::from_str(content) {
            Ok(toml::Value::Table(content)) => content,
            Ok(_) => {
                error!(
                    "Failed to parse config file {}: Not a mapping.",
                    path.display()
                );
                return Err(Failed);
            }
            Err(err) => {
                error!(
                    "Failed to parse config file {}: {}",
                    path.display(), err
                );
                return Err(Failed);
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
                    return Err(Failed);
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
    fn take_bool(&mut self, key: &str) -> Result<Option<bool>, Failed> {
        match self.content.remove(key) {
            Some(value) => {
                if let toml::Value::Boolean(res) = value {
                    Ok(Some(res))
                }
                else {
                    error!(
                        "Failed in config file {}: \
                         '{}' expected to be a boolean.",
                        self.path.display(), key
                    );
                    Err(Failed)
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
    fn take_u64(&mut self, key: &str) -> Result<Option<u64>, Failed> {
        match self.content.remove(key) {
            Some(value) => {
                if let toml::Value::Integer(res) = value {
                    if res < 0 {
                        error!(
                            "Failed in config file {}: \
                            '{}' expected to be a positive integer.",
                            self.path.display(), key
                        );
                        Err(Failed)
                    }
                    else {
                        Ok(Some(res as u64))
                    }
                }
                else {
                    error!(
                        "Failed in config file {}: \
                         '{}' expected to be an integer.",
                        self.path.display(), key
                    );
                    Err(Failed)
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
    fn take_usize(&mut self, key: &str) -> Result<Option<usize>, Failed> {
        match self.content.remove(key) {
            Some(value) => {
                if let toml::Value::Integer(res) = value {
                    usize::try_from(res).map(Some).map_err(|_| {
                        error!(
                            "Failed in config file {}: \
                            '{}' expected to be a positive integer.",
                            self.path.display(), key
                        );
                        Failed
                    })
                }
                else {
                    error!(
                        "Failed in config file {}: \
                         '{}' expected to be an integer.",
                        self.path.display(), key
                    );
                    Err(Failed)
                }
            }
            None => Ok(None)
        }
    }

    /// Takes a small unsigned integer value from the config file.
    ///
    /// While the result is returned as an `usize`, it must be in the
    /// range of a `u16`.
    ///
    /// The value is taken from the given `key`. Returns `Ok(None)` if there
    /// is no such key. Returns an error if the key exists but the value
    /// isn’t an integer or if it is out of bounds.
    fn take_small_usize(&mut self, key: &str) -> Result<Option<usize>, Failed> {
        match self.content.remove(key) {
            Some(value) => {
                if let toml::Value::Integer(res) = value {
                    if res < 0 {
                        error!(
                            "Failed in config file {}: \
                            '{}' expected to be a positive integer.",
                            self.path.display(), key
                        );
                        Err(Failed)
                    }
                    else if res > ::std::u16::MAX.into() {
                        error!(
                            "Failed in config file {}: \
                            value for '{}' is too large.",
                            self.path.display(), key
                        );
                        Err(Failed)
                    }
                    else {
                        Ok(Some(res as usize))
                    }
                }
                else {
                    error!(
                        "Failed in config file {}: \
                         '{}' expected to be a integer.",
                        self.path.display(), key
                    );
                    Err(Failed)
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
    fn take_string(&mut self, key: &str) -> Result<Option<String>, Failed> {
        match self.content.remove(key) {
            Some(value) => {
                if let toml::Value::String(res) = value {
                    Ok(Some(res))
                }
                else {
                    error!(
                        "Failed in config file {}: \
                         '{}' expected to be a string.",
                        self.path.display(), key
                    );
                    Err(Failed)
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
    fn take_from_str<T>(&mut self, key: &str) -> Result<Option<T>, Failed>
    where T: FromStr, T::Err: fmt::Display {
        match self.take_string(key)? {
            Some(value) => {
                match T::from_str(&value) {
                    Ok(some) => Ok(Some(some)),
                    Err(err) => {
                        error!(
                            "Failed in config file {}: \
                             illegal value in '{}': {}.",
                            self.path.display(), key, err
                        );
                        Err(Failed)
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
    fn take_path(&mut self, key: &str) -> Result<Option<PathBuf>, Failed> {
        self.take_string(key).map(|opt| opt.map(|path| self.dir.join(path)))
    }

    /// Takes a mandatory path value from the config file.
    ///
    /// This is the pretty much the same as [`take_path`] but also returns
    /// an error if the key does not exist.
    ///
    /// [`take_path`]: #method.take_path
    fn take_mandatory_path(&mut self, key: &str) -> Result<PathBuf, Failed> {
        match self.take_path(key)? {
            Some(res) => Ok(res),
            None => {
                error!(
                    "Failed in config file {}: missing required '{}'.",
                    self.path.display(), key
                );
                Err(Failed)
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
    ) -> Result<Option<Vec<String>>, Failed> {
        match self.content.remove(key) {
            Some(toml::Value::Array(vec)) => {
                let mut res = Vec::new();
                for value in vec.into_iter() {
                    if let toml::Value::String(value) = value {
                        res.push(value)
                    }
                    else {
                        error!(
                            "Failed in config file {}: \
                            '{}' expected to be a array of strings.",
                            self.path.display(),
                            key
                        );
                        return Err(Failed);
                    }
                }
                Ok(Some(res))
            }
            Some(_) => {
                error!(
                    "Failed in config file {}: \
                     '{}' expected to be a array of strings.",
                    self.path.display(), key
                );
                Err(Failed)
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
    ) -> Result<Option<Vec<T>>, Failed>
    where T: FromStr, T::Err: fmt::Display {
        match self.content.remove(key) {
            Some(toml::Value::Array(vec)) => {
                let mut res = Vec::new();
                for value in vec.into_iter() {
                    if let toml::Value::String(value) = value {
                        match T::from_str(&value) {
                            Ok(value) => res.push(value),
                            Err(err) => {
                                error!(
                                    "Failed in config file {}: \
                                     Invalid value in '{}': {}",
                                    self.path.display(), key, err
                                );
                                return Err(Failed)
                            }
                        }
                    }
                    else {
                        error!(
                            "Failed in config file {}: \
                            '{}' expected to be a array of strings.",
                            self.path.display(),
                            key
                        );
                        return Err(Failed)
                    }
                }
                Ok(Some(res))
            }
            Some(_) => {
                error!(
                    "Failed in config file {}: \
                     '{}' expected to be a array of strings.",
                    self.path.display(), key
                );
                Err(Failed)
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
    ) -> Result<Option<Vec<PathBuf>>, Failed> {
        match self.content.remove(key) {
            Some(toml::Value::String(value)) => {
                Ok(Some(vec![self.dir.join(value)]))
            }
            Some(toml::Value::Array(vec)) => {
                let mut res = Vec::new();
                for value in vec.into_iter() {
                    if let toml::Value::String(value) = value {
                        res.push(self.dir.join(value))
                    }
                    else {
                        error!(
                            "Failed in config file {}: \
                            '{}' expected to be a array of paths.",
                            self.path.display(),
                            key
                        );
                        return Err(Failed);
                    }
                }
                Ok(Some(res))
            }
            Some(_) => {
                error!(
                    "Failed in config file {}: \
                     '{}' expected to be a array of paths.",
                    self.path.display(), key
                );
                Err(Failed)
            }
            None => Ok(None)
        }
    }

    /// Takes a string-to-string hashmap from the config file.
    fn take_string_map(
        &mut self,
        key: &str
    ) -> Result<Option<HashMap<String, String>>, Failed> {
        match self.content.remove(key) {
            Some(toml::Value::Array(vec)) => {
                let mut res = HashMap::new();
                for value in vec.into_iter() {
                    let mut pair = match value {
                        toml::Value::Array(pair) => pair.into_iter(),
                        _ => {
                            error!(
                                "Failed in config file {}: \
                                '{}' expected to be a array of string pairs.",
                                self.path.display(),
                                key
                            );
                            return Err(Failed);
                        }
                    };
                    let left = match pair.next() {
                        Some(toml::Value::String(value)) => value,
                        _ => {
                            error!(
                                "Failed in config file {}: \
                                '{}' expected to be a array of string pairs.",
                                self.path.display(),
                                key
                            );
                            return Err(Failed);
                        }
                    };
                    let right = match pair.next() {
                        Some(toml::Value::String(value)) => value,
                        _ => {
                            error!(
                                "Failed in config file {}: \
                                '{}' expected to be a array of string pairs.",
                                self.path.display(),
                                key
                            );
                            return Err(Failed);
                        }
                    };
                    if pair.next().is_some() {
                        error!(
                            "Failed in config file {}: \
                            '{}' expected to be a array of string pairs.",
                            self.path.display(),
                            key
                        );
                        return Err(Failed);
                    }
                    if res.insert(left, right).is_some() {
                        error!(
                            "Failed in config file {}: \
                            'duplicate item in '{}'.",
                            self.path.display(),
                            key
                        );
                        return Err(Failed);
                    }
                }
                Ok(Some(res))
            }
            Some(_) => {
                error!(
                    "Failed in config file {}: \
                     '{}' expected to be a array of string pairs.",
                    self.path.display(), key
                );
                Err(Failed)
            }
            None => Ok(None)
        }
    }

    /// Checks whether the config file is now empty.
    ///
    /// If it isn’t, logs a complaint and returns an error.
    fn check_exhausted(&self) -> Result<(), Failed> {
        if !self.content.is_empty() {
            print!(
                "Failed in config file {}: Unknown settings ",
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
            Err(Failed)
        }
        else {
            Ok(())
        }
    }
}


//------------ Helpers -------------------------------------------------------

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
            &Config::config_args(Command::new("routinator"))
                .get_matches_from(args),
            Path::new("/test")
        ).unwrap();
        config
    }

    fn process_server_args(args: &[&str]) -> Config {
        let mut config = get_default_config();
        let matches = Config::server_args(Config::config_args(
                Command::new("routinator"))
        ).get_matches_from(args);
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
        assert!(!config.systemd_listen);
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
            Path::new("/test/routinator.conf")
        ).unwrap();
        let config = Config::from_config_file(config).unwrap();
        assert_eq!(config.cache_dir.to_str().unwrap(), "/repodir");
        assert_eq!(config.tal_dir.to_str().unwrap(), "/test/taldir");
        assert_eq!(
            config.exceptions,
            vec![PathBuf::from("/test/ex1"), PathBuf::from("/ex2")]
        );
        assert!(config.strict);
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
        assert!(config.systemd_listen);
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
            Path::new("/test/routinator.conf")
        ).unwrap();
        let config = Config::from_config_file(config).unwrap();
        assert_eq!(config.cache_dir.to_str().unwrap(), "/repodir");
        assert_eq!(config.tal_dir.to_str().unwrap(), "/test/taldir");
        assert!(config.exceptions.is_empty());
        assert!(!config.strict);
        assert_eq!(config.validation_threads, ::num_cpus::get());
        assert_eq!(config.refresh, Duration::from_secs(DEFAULT_REFRESH));
        assert_eq!(config.retry, Duration::from_secs(DEFAULT_RETRY));
        assert_eq!(config.expire, Duration::from_secs(DEFAULT_EXPIRE));
        assert_eq!(config.history_size, DEFAULT_HISTORY_SIZE);
        assert!(config.rtr_listen.is_empty());
        assert!(config.http_listen.is_empty());
        assert!(!config.systemd_listen);
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
    fn read_your_own_config() {
        let out_config = get_default_config();
        let out_file = format!("{}", out_config.to_toml());
        let in_file = ConfigFile::parse(
            &out_file, Path::new("/test/routinator.conf")
        ).unwrap();
        let in_config = Config::from_config_file(in_file).unwrap();
        assert_eq!(out_config, in_config);
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
        assert!(config.strict);
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
        assert!(config.systemd_listen);
    }
    
    #[test]
    fn check_args() {
        crate::operation::Operation::config_args(
            GlobalArgs::augment_args(Command::new("test"))
        ).debug_assert();
    }
}

