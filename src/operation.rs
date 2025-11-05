//! What Routinator can do for you.
//!
//! This module implements all the commands users can ask Routinator to
//! perform. They are encapsulated in the type [`Operation`] which can
//! determine the command from the command line argumments and then execute
//! it.
//!
//! [`Operation`]: enum.Operation.html

// Some functions here have unnecessarily wrapped return types for
// consisitency.
#![allow(clippy::unnecessary_wraps)]

use std::{fs, io, thread};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, Instant, SystemTime};
use bytes::Bytes;
use clap::{Arg, Args, ArgAction, ArgMatches, FromArgMatches, Parser};
use log::{error, info, warn};
use rpki::repository::Rsc;
use rpki::repository::rsc::FileNameAndHash;
use rpki::resources::{Asn, Prefix};
#[cfg(feature = "rta")] use rpki::repository::rta::Rta;
use rpki::rtr::server::NotifySender;
use tempfile::NamedTempFile;
use tokio::sync::oneshot;
#[cfg(feature = "rta")] use crate::rta;
use crate::{output, rsc, validity};
use crate::config::Config;
use crate::error::{ExitError, Failed, RunFailed};
use crate::http::http_listener;
use crate::metrics::RtrServerMetrics;
use crate::output::{Output, OutputFormat};
use crate::payload::{PayloadSnapshot, SharedHistory, ValidationReport};
use crate::process::Process;
use crate::engine::Engine;
use crate::rtr::{rtr_listener};
use crate::slurm::LocalExceptions;

#[cfg(unix)] use tokio::signal::unix::{Signal, SignalKind, signal};
#[cfg(not(unix))] use futures::future::pending;


//------------ Operation -----------------------------------------------------

/// The command to execute.
///
/// This type collects all the commands we have defined plus any possible
/// extra configuration they support.
///
/// You can create a value from the command line arguments. First, you add
/// all necessary sub-commands and arguments to a clap `Command` via
/// [`config_args`] and then process the argument matches into a value in
/// [`from_arg_matches`]. Finally, you can execute the created command
/// through the [`run`] method.
///
/// [`config_args`]: #method.config_args
/// [`from_arg_matches`]: #method.from_arg_matches
/// [`run`]: #method.run
pub enum Operation {
    Server(Server),
    Vrps(Vrps),
    Validate(Validate),
    #[cfg(feature = "rta")]
    ValidateDocument(ValidateDocument),
    ValidateRsc(ValidateRsc),
    Update(Update),
    PrintConfig(PrintConfig),
    Dump(Dump),
    ArchiveStats(ArchiveStats),
    Man(Man),
}

impl Operation {
    /// Prepares everything.
    ///
    /// Call this before doing anything else.
    pub fn prepare() -> Result<(), Failed> {
        Process::init()
    }

    /// Adds the command configuration to a clap app.
    pub fn config_args<'a: 'b, 'b>(app: clap::Command) -> clap::Command {
        let app = Server::config_args(app);
        let app = Vrps::config_args(app);
        let app = Validate::config_args(app);

        #[cfg(feature = "rta")]
        let app = ValidateDocument::config_args(app);

        let app = ValidateRsc::config_args(app);
        let app = Update::config_args(app);
        let app = PrintConfig::config_args(app);
        let app = Dump::config_args(app);
        let app = ArchiveStats::config_args(app);
        Man::config_args(app)
    }

    /// Creates a command from clap matches.
    pub fn from_arg_matches(
        matches: &ArgMatches,
        cur_dir: &Path,
        config: &mut Config
    ) -> Result<Self, Failed> {
        Ok(match matches.subcommand() {
            Some(("server", matches)) => {
                Operation::Server(
                    Server::from_arg_matches(matches, cur_dir, config)?
                )
            }
            Some(("vrps", matches)) => {
                Operation::Vrps(Vrps::from_arg_matches(matches)?)
            }
            Some(("validate", matches)) => {
                Operation::Validate(Validate::from_arg_matches(matches)?)
            }
            #[cfg(feature = "rta")]
            Some(("rta", matches)) => {
                Operation::ValidateDocument(
                    ValidateDocument::from_arg_matches(matches)?
                )
            }
            Some(("rsc", matches)) => {
                Operation::ValidateRsc(ValidateRsc::from_arg_matches(matches)?)
            }
            Some(("update", matches)) => {
                Operation::Update(Update::from_arg_matches(matches)?)
            }
            Some(("config", matches)) => {
                Operation::PrintConfig(
                    PrintConfig::from_arg_matches(matches, cur_dir, config)?
                )
            }
            Some(("dump", matches)) => {
                Operation::Dump( Dump::from_arg_matches(matches, cur_dir)?)
            }
            Some(("archive-stats", matches)) => {
                Operation::ArchiveStats(
                    ArchiveStats::from_arg_matches(matches)?
                )
            }
            Some(("man", matches)) => {
                Operation::Man(Man::from_arg_matches(matches)?)
            }
            _ => {
                error!(
                    "Failed: a command is required.\n\
                     \nCommonly used commands are:\
                     \n   vrps      Produces a list of validated ROA payload\
                     \n   validate  Perform origin validation for an \
                                    annoucement\
                     \n   server    Start the RTR server\
                     \n   man       Show the manual page\
                     \n\
                     \nSee routinator -h for a usage summary or \
                       routinator man for detailed help."
                );
                return Err(Failed)
            }
        })
    }

    /// Runs the command.
    ///
    /// Depending on the command, this method may switch to logging at some
    /// point.
    pub fn run(self, config: Config) -> Result<(), ExitError> {
        let process = Process::new(config);
        match self {
            Operation::Server(cmd) => cmd.run(process),
            Operation::Vrps(cmd) => cmd.run(process),
            Operation::Validate(cmd) => cmd.run(process),
            #[cfg(feature = "rta")]
            Operation::ValidateDocument(cmd) => cmd.run(process),
            Operation::ValidateRsc(cmd) => cmd.run(process),
            Operation::Update(cmd) => cmd.run(process),
            Operation::PrintConfig(cmd) => cmd.run(process),
            Operation::Dump(cmd) => cmd.run(process),
            Operation::ArchiveStats(cmd) => cmd.run(process),
            Operation::Man(cmd) => cmd.run(process),
        }
    }
}


//------------ Server --------------------------------------------------------

/// Run as server.
#[derive(Clone, Debug, Parser)]
pub struct Server {
    /// Detach from the terminal
    //
    // If this is `false`, we just start the server and keep going. If
    // this is `true`, we detach from the terminal into daemon mode
    // which has a few extra consequences.
    #[arg(short, long)]
    detach: bool,
}

impl Server {
    /// Adds the command configuration to a clap app.
    pub fn config_args(app: clap::Command) -> clap::Command {
        app.subcommand(
            Config::server_args(
                Server::augment_args(
                    clap::Command::new("server")
                    .about("Starts as a server")
                    .after_help(AFTER_HELP)
                )
            )
       )
    }

    /// Creates a command from clap matches.
    pub fn from_arg_matches(
        matches: &ArgMatches,
        cur_dir: &Path,
        config: &mut Config
    ) -> Result<Self, Failed> {
        config.apply_server_arg_matches(matches, cur_dir)?;
        Ok(<Server as FromArgMatches>::from_arg_matches(matches).unwrap())
    }

    /// Starts Routinator in server mode.
    ///
    /// If `detach` is `true`, will fork the server and exit. Otherwise
    /// just runs the server forever.
    pub fn run(self, mut process: Process) -> Result<(), ExitError> {
        let log = process.switch_logging(
            self.detach,
            !process.config().http_listen.is_empty()
        )?;
        warn!("Using config file {}.", process.config().config_file.display());
        process.setup_service(self.detach)?;
        let log = log.map(Arc::new);
        let rtr_metrics = Arc::new(RtrServerMetrics::new(
            process.config().rtr_client_metrics
        ));

        let history = SharedHistory::from_config(process.config());
        let mut notify = NotifySender::new();
        let rtr = rtr_listener(
            history.clone(), rtr_metrics.clone(), process.config(),
            notify.clone(), process.get_listen_fd()?
        )?;
        let http = http_listener(
            history.clone(), rtr_metrics, log.clone(), process.config(),
            notify.clone(),
        )?;

        process.drop_privileges()?;

        // Load exceptions and quit if they are broken.
        let Ok(mut exceptions) = LocalExceptions::load(
            process.config(), true
        ) else {
            error!("Exiting.");
            return Err(ExitError::Generic)
        };

        let mut validation = Engine::new(process.config(), true)?;
        let runtime = process.runtime()?;
        let mut rtr = runtime.spawn(rtr);
        let mut http = runtime.spawn(http);
        let (sig_tx, sig_rx) = mpsc::channel();
        let (err_tx, mut err_rx) = oneshot::channel();

        validation.ignite()?;

        let join = thread::spawn(move || {
            let mut initial = true;
            let mut can_retry = true;
            let err = loop {
                if let Some(log) = log.as_ref() {
                    log.start();
                }

                match LocalExceptions::load(process.config(), true) {
                    Ok(new_exceptions) => {
                        exceptions = new_exceptions;
                    }
                    Err(_) => {
                        warn!("Using previously loaded local exceptions.");
                    }
                }

                let initial_run = initial;
                initial = false;
                let timeout = match Self::process_once(
                    process.config(), &validation, &history,
                    &mut notify, &exceptions, initial_run,
                ) {
                    Ok(()) => {
                        // Immediately start a new run after the
                        // initial run.
                        if initial_run {
                            info!(
                                "Initial run complete, now starting \
                                 normal run."
                            );
                            Duration::from_secs(0)
                        }
                        else {
                            history.read().refresh_wait()
                        }
                    }
                    Err(err) => {
                        if err.should_retry() {
                            if initial_run {
                                info!(
                                    "Retrying full validation run."
                                );
                                Duration::from_secs(0)
                            }
                            else if can_retry {
                                if validation.sanitize().is_err() {
                                    break Err(Failed)
                                }
                                info!(
                                    "Validation failed but \
                                     can be retried."
                                );
                                can_retry = false;
                                Duration::from_secs(0)
                            }
                            else {
                                error!(
                                    "Retried validation failed again."
                                );
                                break Err(Failed);
                            }
                        }
                        else {
                            break Err(Failed);
                        }
                    }
                };

                if let Some(log) = log.as_ref() {
                    log.flush();
                }

                // Because we don’t want to restart validation upon
                // log rotation, we need to loop here. But then we need
                // to recalculate timeout.
                let deadline = Instant::now() + timeout;

                info!(
                    "Next validation run scheduled in {} seconds",
                    timeout.as_secs()
                );

                let end = loop {
                    let timeout = deadline.saturating_duration_since(
                        Instant::now()
                    );
                    match sig_rx.recv_timeout(timeout) {
                        Ok(UserSignal::ReloadTals) => {
                            match validation.reload_tals() {
                                Ok(_) => {
                                    info!("Reloaded TALs at user request.");
                                    break None;
                                },
                                Err(_) => {
                                    error!(
                                        "Fatal: Reloading TALs failed, \
                                         shutting down."
                                    );
                                    break Some(Err(Failed));
                                }
                            }
                        }
                        Ok(UserSignal::RotateLog) => {
                            if process.rotate_log().is_err() {
                                break Some(Err(Failed));
                            }
                        }
                        Err(RecvTimeoutError::Timeout) => {
                            break None;
                        }
                        Err(RecvTimeoutError::Disconnected) => {
                            break Some(Ok(()));
                        }
                    }
                };
                if let Some(end) = end {
                    break end;
                }
            };
            // An error here means the receiver is gone which is fine.
            let _ = err_tx.send(err);
        });

        let res: Result<(), Failed> = runtime.block_on(async move {
            let mut signal = SignalListener::new()?;
            let res = loop {
                tokio::select! {
                    sig = signal.next() => {
                        if sig_tx.send(sig).is_err() {
                            break Err(Failed);
                        }
                    }
                    res = &mut err_rx => {
                        match res {
                            Ok(res) => break res,
                            Err(_) => break Err(Failed)
                        }
                    }
                    _ = &mut rtr => break Err(Failed),
                    _ = &mut http => break Err(Failed),
                }
            };
            // Dropping sig_tx will lead to sig_rx failing and the thread
            // ending. The drop is actually not necessary because sig_tx was
            // moved here, but just in case a ref sneaks in later, let’s keep
            // it.
            drop(sig_tx);
            res
        });

        let _ = join.join();
        res.map_err(Into::into)
    }

    fn process_once(
        config: &Config,
        engine: &Engine,
        history: &SharedHistory,
        notify: &mut NotifySender,
        exceptions: &LocalExceptions,
        initial: bool,
    ) -> Result<(), RunFailed> {
        info!("Starting a validation run.");
        history.mark_update_start();
        let (report, metrics) = ValidationReport::process(
            engine, config, initial
        )?;
        let must_notify = history.update(
            report, exceptions, metrics,
        );
        history.mark_update_done();
        if log::max_level() >= log::Level::Info {
            let (metrics, serial, duration) = {
                let history = history.read();
                (
                    history.metrics(),
                    history.serial(),
                    history.last_update_duration()
                )
            };
            match duration {
                Some(duration) => {
                    info!(
                        "Validation completed in {} seconds.",
                        duration.as_secs()
                    );
                }
                None => info!("Validation completed.")
            }
            if let Some(metrics) = metrics {
                output::Summary::log(&metrics)
            }
            info!(
                "New serial is {serial}."
            );
        }
        if must_notify {
            info!("Sending out notifications.");
            notify.notify();
        }
        Ok(())
    }
}


//------------ Vrps ----------------------------------------------------------

/// Produce a list of Validated ROA Payload.
#[derive(Debug)]
pub struct Vrps {
    /// The destination to output the list to.
    ///
    /// If this is some path, then we print the list into that file.
    /// Otherwise we just dump it to stdout.
    path: Option<PathBuf>,

    /// The desired output format.
    format: OutputFormat,

    /// Configuration of the output.
    output: Output,

    /// Don’t update the repository.
    noupdate: bool,

    /// Only update the repository if the cache is older than this.
    update_after: Option<Duration>,

    /// Return an error on incomplete update.
    complete: bool,
}

/// The command line arguments for the vrps sub-command.
#[derive(Clone, Debug, Parser)]
struct VrpsArgs {
    /// The destination of the output list
    #[arg(short, long, value_name = "PATH", default_value = "-")]
    output: PathBuf,

    /// The format of the output list
    #[arg(
        short, long, value_name = "FORMAT",
        default_value = OutputFormat::DEFAULT_VALUE,
    )]
    format: String,

    /// Only include records for the given prefix
    #[arg(
        short = 'p',
        long, alias = "filter-prefix",
        value_name = "PREFIX"
    )]
    select_prefix: Option<Vec<Prefix>>,

    /// Only include records for the given AS number
    #[arg(
        short = 'a',
        long, alias = "filter-asn",
        value_name = "ASN"
    )]
    select_asn: Option<Vec<Asn>>,

    /// Include more specific prefixes in selected output
    #[arg(short, long)]
    more_specifics: bool,

    /// Don’t include route origins in output
    #[arg(long)]
    no_route_origins: bool,

    /// Don’t include router keys in output
    #[arg(long)]
    no_router_keys: bool,

    /// Don’t include ASPA in output
    #[arg(long)]
    no_aspas: bool,

    /// Don't update the local cache
    #[arg(
        short, long,
        conflicts_with = "update_after",
    )]
    noupdate: bool,

    /// Only update the cache if the last run was at least this long ago.
    #[arg(
        short, long,
        value_name = "MINTUES",
        conflicts_with = "noupdate",
    )]
    update_after: Option<u32>,

    /// Return an error status on incomplete update
    #[arg(long)]
    complete: bool,
}

impl Vrps {
    /// Adds the command configuration to a clap app.
    pub fn config_args<'a: 'b, 'b>(app: clap::Command) -> clap::Command {
        app.subcommand(
            VrpsArgs::augment_args(
                clap::Command::new("vrps")
                    .about("Produces a list of validated ROA payload")
                    .after_help(AFTER_HELP)
            )
        )
    }

    /// Creates a command from clap matches.
    pub fn from_arg_matches(
        matches: &ArgMatches,
    ) -> Result<Self, Failed> {
        let args = VrpsArgs::from_arg_matches(matches).unwrap();

        let format = match OutputFormat::from_str(&args.format) {
            Ok(format) => format,
            Err(_) => {
                error!("Unknown output format '{}'", args.format);
                return Err(Failed)
            }
        };

        let path = if args.output == Path::new("-") {
            None
        }
        else {
            Some(args.output)
        };

        let mut output = Output::new();

        if args.select_prefix.is_some() || args.select_asn.is_some() {
            let mut selection = output::Selection::new();
            if let Some(list) = args.select_prefix {
                for value in list {
                    selection.push_prefix(value)
                }
            }
            if let Some(list) = args.select_asn {
                for value in list {
                    selection.push_asn(value)
                }
            }
            selection.set_more_specifics(args.more_specifics);
            output.set_selection(selection);
        };

        if args.no_route_origins {
            output.no_route_origins();
        }
        if args.no_router_keys {
            output.no_router_keys();
        }
        if args.no_aspas{
            output.no_aspas();
        }

        Ok(Vrps {
            path,
            format,
            output,
            noupdate: args.noupdate,
            update_after: args.update_after.map(|minutes| {
                // Safety: a u32 converted to a u64 multiplied by 60 always
                //         fits.
                Duration::from_secs(u64::from(minutes) * 60)
            }),
            complete: args.complete,
        })
    }

    /// Produces a list of Validated ROA Payload.
    ///
    /// The list will be written to the file identified by `path` or
    /// stdout if that is `None`. The format is determined by `format`.
    /// If `noupdate` is `false`, the local repository will be updated first
    /// and rsync will be enabled during validation to sync any new
    /// publication points.
    fn run(mut self, process: Process) -> Result<(), ExitError> {
        self.output.update_from_config(process.config());
        let mut engine = Engine::new(process.config(), !self.noupdate)?;

        // Disable collector if update_after demands it. If anything goes
        // wrong here, we simply keep the collector in place.
        if let Some(duration) = self.update_after {
            if let Some(status) = engine.store_status()? {
                if let Ok(age) = SystemTime::from(
                    status.last_update
                ).elapsed() {
                    if age < duration {
                        engine.disable_collector()
                    }
                }
            }
        }

        engine.ignite()?;
        process.switch_logging(false, false)?;
        warn!("Using config file {}.", process.config().config_file.display());
        let exceptions = LocalExceptions::load(process.config(), true)?;
        let (report, mut metrics) = {
            // Retry once if we get a non-fatal error.
            let mut once = false;

            loop {
                match ValidationReport::process(
                    &engine, process.config(), false
                ) {
                    Ok(res) => break res,
                    Err(err) => {
                        if err.should_retry() {
                            if once {
                                error!(
                                    "Restarted run failed again. Aborting."
                                );
                            }
                            if engine.sanitize().is_ok() {
                                once = true;
                                continue
                            }
                        }
                        return Err(ExitError::Generic)
                    }
                }
            }
        };
        let vrps = Arc::new(report.into_snapshot(&exceptions, &mut metrics));
        let rsync_complete = metrics.rsync_complete();
        let metrics = Arc::new(metrics);
        let res = match self.path {
            Some(ref path) => {
                let mut file = match fs::File::create(path) {
                    Ok(file) => file,
                    Err(err) => {
                        error!(
                            "Failed to open output file '{}': {}",
                            path.display(), err
                        );
                        return Err(Failed.into())
                    }
                };
                self.output.write(vrps, metrics, self.format, &mut file)
            }
            None => {
                let out = io::stdout();
                let mut out = out.lock();
                self.output.write(vrps, metrics, self.format, &mut out)
            }
        };
        if let Err(err) = res {
            // Surpress an error message for broken pipe on stdout.
            if 
                self.path.is_some() ||
                err.kind() != io::ErrorKind::BrokenPipe
            {
                error!(
                    "Failed to output result: {err}"
                );
            }
            Err(ExitError::Generic)
        }
        else if self.complete && !rsync_complete {
            Err(ExitError::IncompleteUpdate)
        }
        else {
            Ok(())
        }
    }

}


//------------ Validate ------------------------------------------------------

/// Validate a route announcement.
pub struct Validate {
    /// What to validate?
    what: ValidateWhat,

    /// Use JSON for parsing and writing.
    json: bool,

    /// The destination to output the list to.
    ///
    /// If this is some path, then we print the list into that file.
    /// Otherwise we just dump it to stdout.
    output: Option<PathBuf>,

    /// Don’t update the repository.
    noupdate: bool,

    /// Return an error on incomplete update.
    complete: bool,
}

/// What route(s) should we validate, please?
enum ValidateWhat {
    /// Validate a single route with the given prefix and ASN.
    Single(Prefix, Asn),

    /// Validate the routes provided in the given file.
    File(PathBuf),

    /// Validate the routes provided on stdin.
    Stdin,
}

/// The command line arguments for the validate sub-command.
#[derive(Clone, Debug, Parser)]
struct ValidateArgs {
    /// Address prefix of the announcement
    #[arg(short, long, requires = "asn", conflicts_with = "input")]
    prefix: Option<Prefix>,

    /// Origin AS number of the announcement
    #[arg(short, long, requires = "prefix", conflicts_with = "input")]
    asn: Option<Asn>,

    /// Expect input and produce output in JSON
    #[arg(short, long)]
    json: bool,

    /// Read routes from a file
    #[arg(
        short, long, value_name = "PATH",
        conflicts_with_all = &["prefix", "asn"]
    )]
    input: Option<PathBuf>,

    /// Write output to a file
    #[arg(short, long, value_name = "PATH", default_value = "-")]
    output: PathBuf,

    /// Don't update the local cache
    #[arg(short, long)]
    noupdate: bool,

    /// Return an error status on incomplete update
    #[arg(long)]
    complete: bool,
}

impl Validate {
    /// Adds the command configuration to a clap app.
    pub fn config_args<'a: 'b, 'b>(app: clap::Command) -> clap::Command {
        app.subcommand(
            ValidateArgs::augment_args(
                clap::Command::new("validate")
                    .about("Validates a route announcement")
                    .after_help(AFTER_HELP)
            )
        )
    }

    /// Creates a command from clap matches.
    pub fn from_arg_matches(matches: &ArgMatches) -> Result<Self, Failed> {
        let args = ValidateArgs::from_arg_matches(matches).unwrap();

        Ok(Validate {
            what: if let Some(path) = args.input {
                if path == Path::new("-") {
                    ValidateWhat::Stdin
                }
                else {
                    ValidateWhat::File(path)
                }
            }
            else {
                ValidateWhat::Single(
                    match args.prefix {
                        Some(prefix) => prefix,
                        None => {
                            error!("Missing required --prefix argument");
                            return Err(Failed)
                        }
                    },
                    match args.asn {
                        Some(asn) => asn,
                        None => {
                            error!("Missing required --asn argument");
                            return Err(Failed)
                        }
                    },
                )
            },
            json: args.json,
            output: {
                if args.output == Path::new("-") {
                    None
                }
                else {
                    Some(args.output)
                }
            },
            noupdate: args.noupdate,
            complete: args.complete,
        })
    }


    /// Outputs whether the given route announcement is valid.
    fn run(self, process: Process) -> Result<(), ExitError> {
        let requests = self.read_requests()?;
        let snapshot = self.get_snapshot(process)?;
        self.output_validity(requests, snapshot)
    }

    fn read_requests(&self) -> Result<validity::RequestList, ExitError> {
        match self.what {
            ValidateWhat::Single(prefix, asn) => {
                Ok(validity::RequestList::single(prefix, asn))
            }
            ValidateWhat::File(ref path) => {
                let mut stream = match fs::File::open(path) {
                    Ok(file) => io::BufReader::new(file),
                    Err(err) => {
                        error!(
                            "Failed to open input file '{}': {}'",
                            path.display(), err
                        );
                        return Err(ExitError::Generic)
                    }
                };
                if self.json {
                    validity::RequestList::from_json_reader(
                        &mut stream
                    ).map_err(|err| {
                        error!(
                            "Failed to read input file '{}': {}'",
                            path.display(), err
                        );
                        ExitError::Generic
                    })
                }
                else {
                    validity::RequestList::from_plain_reader(
                        &mut stream
                    ).map_err(|err| {
                        error!(
                            "Failed to read input file '{}': {}'",
                            path.display(), err
                        );
                        ExitError::Generic
                    })
                }
            }
            ValidateWhat::Stdin => {
                let file = io::stdin();
                let mut file = file.lock();
                if self.json {
                    validity::RequestList::from_json_reader(
                        &mut file
                    ).map_err(|err| {
                        error!("Failed to read input: {err}'");
                        ExitError::Generic
                    })
                }
                else {
                    validity::RequestList::from_plain_reader(
                        file
                    ).map_err(|err| {
                        error!("Failed to read input: {err}'");
                        ExitError::Generic
                    })
                }
            }
        }
    }

    fn get_snapshot(
        &self, process: Process
    ) -> Result<PayloadSnapshot, ExitError> {
        let mut engine = Engine::new(process.config(), !self.noupdate)?;
        engine.ignite()?;
        process.switch_logging(false, false)?;
        let (report, mut metrics) = ValidationReport::process(
            &engine, process.config(), false,
        )?;
        let snapshot = report.into_snapshot(
            &LocalExceptions::load(process.config(), false)?,
            &mut metrics,
        );
        if self.complete && !metrics.rsync_complete() {
            error!("Failed: Incomplete update.");
            Err(ExitError::IncompleteUpdate)
        }
        else {
            Ok(snapshot)
        }
    }

    fn output_validity(
        &self,
        requests: validity::RequestList,
        snapshot: PayloadSnapshot
    ) -> Result<(), ExitError> {
        let result = requests.validity(&snapshot);
        match self.output.as_ref() {
            Some(path) => {
                let mut stream = match fs::File::create(path) {
                    Ok(file) => io::BufWriter::new(file),
                    Err(err) => {
                        error!(
                            "Failed to open output file '{}': {}",
                            path.display(), err
                        );
                        return Err(ExitError::Generic)
                    }
                };
                let res = if self.json {
                    result.write_json(&mut stream)
                }
                else {
                    result.write_plain(&mut stream)
                };
                let res = res.and_then(|_| stream.flush());
                res.map_err(|err| {
                    error!(
                        "Failed to write to output file '{}': {}",
                        path.display(), err
                    );
                    ExitError::Generic
                })
            }
            None => {
                let stdout = io::stdout();
                let mut stdout = stdout.lock();
                let res = if self.json {
                    result.write_json(&mut stdout)
                }
                else {
                    result.write_plain(&mut stdout)
                };
                res.map_err(|err| {
                    error!("Failed to write output: {err}");
                    ExitError::Generic
                })
            }
        }
    }
}


//------------ ValidateDocument ----------------------------------------------

/// Validates an RTA-signed document.
///
/// Performs a validation run in order to find the necessary certificates.
#[cfg(feature = "rta")]
#[derive(Clone, Debug, Parser)]
pub struct ValidateDocument {
    /// Path to the signed document.
    #[arg(long, value_name = "PATH")]
    document: PathBuf,

    /// Path to the signature file.
    #[arg(long, value_name = "PATH")]
    signature: PathBuf,

    /// Don’t update the repository.
    #[arg(short, long)]
    noupdate: bool,
}

#[cfg(feature = "rta")]
impl ValidateDocument {
    /// Adds the command configuration to a clap app.
    pub fn config_args<'a: 'b, 'b>(app: clap::Command) -> clap::Command {
        app.subcommand(
            ValidateDocument::augment_args(
                clap::Command::new("rta")
                .about("Validates an RTA-signed document")
                .after_help(AFTER_HELP)
            )
        )
    }

    /// Creates a command from clap matches.
    pub fn from_arg_matches(
        matches: &ArgMatches,
    ) -> Result<Self, Failed> {
        Ok(
            <ValidateDocument as FromArgMatches>::from_arg_matches(
                matches
            ).unwrap()
        )
    }

    /// Tries to validate a document through RTA signatures.
    ///
    /// Returns successfully if validation is successful or with an
    /// appropriate error otherwise.
    fn run(self, process: Process) -> Result<(), ExitError> {
        let mut validation = Engine::new(process.config(), !self.noupdate)?;
        validation.ignite()?;
        process.switch_logging(false, false)?;

        // Load and decode the signature.
        let data = match fs::read(&self.signature) {
            Ok(data) => Bytes::from(data),
            Err(err) => {
                error!(
                    "Failed to read signature '{}': {}",
                    self.signature.display(), err
                );
                return Err(ExitError::Generic)
            }
        };
        let rta = match Rta::decode(data, process.config().strict) {
            Ok(rta) => rta,
            Err(err) => {
                error!(
                    "Failed to decode signature '{}': {}",
                    self.signature.display(), err
                );
                return Err(ExitError::Invalid)
            }
        };

        // Load and digest the document.
        let digest = match rta.digest_algorithm().digest_file(&self.document) {
            Ok(digest) => digest,
            Err(err) => {
                error!(
                    "Failed to read document '{}': {}",
                    self.document.display(), err
                );
                return Err(ExitError::Generic)
            }
        };

        // Check that the digests matches.
        if digest.as_ref() != rta.message_digest().as_ref() {
            error!("RTA signature invalid.");
            return Err(ExitError::Invalid)
        }

        let rta_validation = match rta::ValidationReport::new(
            &rta, process.config()
        ) {
            Ok(rta_validation) => rta_validation,
            Err(_) => {
                error!("RTA did not validate. (new)");
                return Err(ExitError::Invalid);
            }
        };

        if rta_validation.process(&validation).is_err() {
            error!("RTA did not validate. (process)");
            return Err(ExitError::Invalid);
        }

        match rta_validation.finalize() {
            Ok(rta) => {
                for block in rta.as_resources().iter() {
                    println!("{block}");
                }
                for block in rta.v4_resources().iter() {
                    println!("{}", block.display_v4());
                }
                for block in rta.v6_resources().iter() {
                    println!("{}", block.display_v6());
                }
                Ok(())
            }
            Err(_) => {
                error!("RTA did not validate. (finalize)");
                Err(ExitError::Invalid)
            }
        }
    }
}


//------------ ValidateRsc ---------------------------------------------------

/// Validates an RSC-signed document.
///
/// Performs a validation run in order to find the necessary certificates.
#[derive(Clone, Debug, Parser)]
pub struct ValidateRsc {
    /// Path to the signed document.
    #[arg(long, value_name = "PATH")]
    document: Vec<PathBuf>,

    /// Path to the signature file.
    #[arg(long, value_name = "PATH")]
    signature: PathBuf,

    /// Don’t update the repository.
    #[arg(short, long)]
    noupdate: bool,
}

impl ValidateRsc {
    /// Adds the command configuration to a clap app.
    pub fn config_args<'a: 'b, 'b>(app: clap::Command) -> clap::Command {
        app.subcommand(
            Self::augment_args(
                clap::Command::new("rsc")
                .about("Validates an RSC-signed document")
                .after_help(AFTER_HELP)
            )
        )
    }

    /// Creates a command from clap matches.
    pub fn from_arg_matches(
        matches: &ArgMatches,
    ) -> Result<Self, Failed> {
        Ok(
            <Self as FromArgMatches>::from_arg_matches(
                matches
            ).unwrap()
        )
    }

    /// Tries to validate a document through RTA signatures.
    ///
    /// Returns successfully if validation is successful or with an
    /// appropriate error otherwise.
    fn run(self, process: Process) -> Result<(), ExitError> {
        let mut validation = Engine::new(process.config(), !self.noupdate)?;
        validation.ignite()?;
        process.switch_logging(false, false)?;

        // Load and decode the signature.
        let data = match fs::read(&self.signature) {
            Ok(data) => Bytes::from(data),
            Err(err) => {
                error!(
                    "Failed to read signature '{}': {}",
                    self.signature.display(), err
                );
                return Err(ExitError::Generic)
            }
        };
        let rsc = match Rsc::decode(data, process.config().strict) {
            Ok(rsc) => rsc,
            Err(err) => {
                error!(
                    "Failed to decode signature '{}': {}",
                    self.signature.display(), err
                );
                return Err(ExitError::Invalid)
            }
        };
        
        let hashes: Vec<FileNameAndHash> = rsc.content().iter().collect();

        let digest_algorithm = rsc.content().digest_algorithm();
        for document in &self.document {
            let digest = match digest_algorithm.digest_file(document) {
                Ok(digest) => digest,
                Err(err) => {
                    error!(
                        "Failed to read document '{}': {}",
                        document.display(), err
                    );
                    return Err(ExitError::Generic)
                }
            };
            let Some(doc_file_name) = document.file_name() else {
                error!(
                    "Failed to read document file name '{}'",
                    document.display()
                );
                return Err(ExitError::Generic)
            };
            let doc_file_name = doc_file_name.to_string_lossy();
            
            let mut found = false;
            for item in hashes.iter() {
                if item.hash() == digest.as_ref() {
                    if let Some(file_name) = item.file_name() {
                        if file_name == doc_file_name.as_bytes() {
                            found = true;
                            break;
                        }
                    } else {
                        found = true;
                        break;
                    }
                }
            }

            if !found {
                // At this point none of the entries in the check list matched 
                // the document we supplied.

                error!("Failed to match document to valid entry in the check list '{}'.", 
                    document.display());
                return Err(ExitError::Invalid)
            }
        }

        let rsc_validation = match rsc::ValidationReport::new(
            rsc, process.config()
        ) {
            Ok(validation) => validation,
            Err(_) => {
                error!("RSC did not validate. (new)");
                return Err(ExitError::Invalid);
            }
        };

        if rsc_validation.process(&validation).is_err() {
            error!("RSC did not validate. (process)");
            return Err(ExitError::Invalid);
        }

        match rsc_validation.finalize() {
            Ok(rsc) => {
                println!("Validation of your RSC succeeded.");
                println!("It has these resources:");
                for block in rsc.as_resources().iter() {
                    println!("{block}");
                }
                for block in rsc.v4_resources().iter() {
                    println!("{}", block.display_v4());
                }
                for block in rsc.v6_resources().iter() {
                    println!("{}", block.display_v6());
                }
                Ok(())
            }
            Err(_) => {
                error!("RSC did not validate. (finalize)");
                Err(ExitError::Invalid)
            }
        }
    }
}


//------------ Update --------------------------------------------------------


/// Update the local repository.
///
/// This will also do a validation run in order to discover possible new
/// publication points.
#[derive(Clone, Debug, Parser)]
pub struct Update {
    /// Return an error on incomplete update.
    #[arg(short, long)]
    complete: bool,
}

impl Update {
    /// Adds the command configuration to a clap app.
    pub fn config_args<'a: 'b, 'b>(app: clap::Command) -> clap::Command {
        app.subcommand(
            Update::augment_args(
                clap::Command::new("update")
                    .about("Updates the local RPKI repository")
                    .after_help(AFTER_HELP)
            )
        )
    }

    /// Creates a command from clap matches.
    pub fn from_arg_matches(matches: &ArgMatches) -> Result<Self, Failed> {
        Ok(<Update as FromArgMatches>::from_arg_matches(matches).unwrap())
    }

    /// Updates the repository.
    ///
    /// This runs both an update of the already known publication points but
    /// also does validation in order to discover new points.
    ///
    /// Which turns out is just a shortcut for `vrps` with no output.
    fn run(self, process: Process) -> Result<(), ExitError> {
        let mut engine = Engine::new(process.config(), true)?;
        engine.ignite()?;
        process.switch_logging(false, false)?;
        let (_, metrics) = ValidationReport::process(
            &engine, process.config(), false
        )?;
        if self.complete && !metrics.rsync_complete() {
            Err(ExitError::IncompleteUpdate)
        }
        else {
           Ok(())
        }
    }
}


//------------ Config --------------------------------------------------------


/// Shows the current configuration.
pub struct PrintConfig;

impl PrintConfig {
    /// Adds the command configuration to a clap app.
    pub fn config_args<'a: 'b, 'b>(app: clap::Command) -> clap::Command {
        // config
        app.subcommand(Config::server_args(clap::Command::new("config")
            .about("Prints the current config and exits")
            .after_help(AFTER_HELP)
        ))
    }

    /// Creates a command from clap matches.
    pub fn from_arg_matches(
        matches: &ArgMatches,
        cur_dir: &Path,
        config: &mut Config,
    ) -> Result<Self, Failed> {
        config.apply_server_arg_matches(matches, cur_dir)?;
        Ok(PrintConfig)
    }

    /// Prints the current configuration to stdout and exits.
    fn run(self, process: Process) -> Result<(), ExitError> {
        println!("{}", process.config());
        Ok(())
    }
}


//------------ Dump ----------------------------------------------------------

/// Dumps the database content.
#[derive(Clone, Debug, Parser)]
pub struct Dump {
    /// Output directory.
    #[arg(short, long, value_name = "PATH")]
    output: PathBuf,
}

impl Dump {
    /// Adds the command configuration to a clap app.
    pub fn config_args<'a: 'b, 'b>(app: clap::Command) -> clap::Command {
        // config
        app.subcommand(
            Dump::augment_args(
                clap::Command::new("dump")
                    .about("Writes the cache content to disk")
                    .after_help(AFTER_HELP)
            )
        )
    }

    /// Creates a command from clap matches.
    pub fn from_arg_matches(
        matches: &ArgMatches,
        cur_dir: &Path,
    ) -> Result<Self, Failed> {
        let mut res =
            <Dump as FromArgMatches>::from_arg_matches(matches).unwrap();
        res.output = cur_dir.join(res.output);
        Ok(res)
    }

    /// Prints the current configuration to stdout and exits.
    fn run(self, process: Process) -> Result<(), ExitError> {
        let engine = Engine::new(process.config(), true)?;
        process.switch_logging(false, false)?;
        engine.dump(&self.output)?;
        Ok(())
    }
}


//------------ ArchiveStats --------------------------------------------------

/// Prints archive statistics.
#[derive(Clone, Debug, Parser)]
pub struct ArchiveStats {
    /// Archive file.
    #[arg(value_name = "PATH")]
    archive: PathBuf,
}

impl ArchiveStats {
    /// Adds the command configuration to a clap app.
    pub fn config_args<'a: 'b, 'b>(app: clap::Command) -> clap::Command {
        // config
        app.subcommand(
            ArchiveStats::augment_args(
                clap::Command::new("archive-stats")
                    .about("Prints statics for an RRDP archive")
                    .after_help(AFTER_HELP)
            )
        )
    }

    /// Creates a command from clap matches.
    pub fn from_arg_matches(matches: &ArgMatches) -> Result<Self, Failed> {
        Ok(
            <ArchiveStats as FromArgMatches>::from_arg_matches(
                matches
            ).unwrap()
        )
    }

    fn run(self, process: Process) -> Result<(), ExitError> {
        use crate::collector::RrdpArchive;

        process.switch_logging(false, false)?;
        match RrdpArchive::verify(&self.archive) {
            Ok(stats) => {
                println!("RRDP archive {}:", self.archive.display());
                stats.print();
                Ok(())
            }
            Err(err) => {
                eprintln!("Archive is corrupt: {err}");
                Err(ExitError::Generic)
            }
        }
    }
}


//------------ Man -----------------------------------------------------------

/// Show the manual page.
pub struct Man {
    /// Output the page instead of showing it.
    ///
    /// Output is requested by this being some. If there is a path,
    /// then we output to the file identified by the path, otherwise
    /// we print to stdout.
    #[allow(clippy::option_option)]
    output: Option<Option<PathBuf>>,
}

impl Man {
    /// Adds the command configuration to a clap app.
    pub fn config_args<'a: 'b, 'b>(app: clap::Command) -> clap::Command {
        app.subcommand(clap::Command::new("man")
            .about("Shows the man page")
            .arg(Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FILE")
                .action(ArgAction::Set)
                .help("Output file, '-' or not present for stdout")
            )
        )
    }

    /// Creates a command from clap matches.
    pub fn from_arg_matches(matches: &ArgMatches) -> Result<Self, Failed> {
        Ok(Man {
            output: matches.get_one::<String>("output").map(|value| {
                if value == "-" {
                    None
                }
                else {
                    Some(value.clone().into())
                }
            })
        })
    }

    fn run(self, _process: Process) -> Result<(), ExitError> {
        match self.output {
            Some(path) => Self::output_man(path),
            None => Self::display_man(),
        }
    }

    /// Outputs the manual page to the given path.
    ///
    /// If the path is `None`, outputs to stdout.
    fn output_man(output: Option<PathBuf>) -> Result<(), ExitError> {
        match output {
            Some(path) => {
                let mut file = match fs::File::create(&path) {
                    Ok(file) => file,
                    Err(err) => {
                        error!(
                            "Failed to open output file {}: {}",
                            path.display(), err
                        );
                        return Err(Failed.into())
                    }
                };
                if let Err(err) = file.write_all(MAN_PAGE) {
                    error!("Failed to write to output file: {err}");
                    return Err(Failed.into())
                }
                info!(
                    "Successfully writen manual page to {}",
                    path.display()
                );
            }
            None => {
                let out = io::stdout();
                let mut out = out.lock();
                if let Err(err) = out.write_all(MAN_PAGE) {
                    error!("Failed to write man page: {err}");
                    return Err(Failed.into())
                }
            }
        }
        Ok(())
    }

    /// Displays the manual page.
    ///
    /// This puts the manual page into a temporary file and then executes
    /// the `man` command. This probably doesn’t work on Windows.
    fn display_man() -> Result<(), ExitError> {
        let mut file = NamedTempFile::new().map_err(|err| {
            error!(
                "Can't display man page: \
                 Failed to create temporary file: {err}."
            );
            Failed
        })?;
        file.write_all(MAN_PAGE).map_err(|err| {
            error!(
                "Can't display man page: \
                Failed to write to temporary file: {err}."
            );
            Failed
        })?;
        Command::new("man").arg(file.path()).status().map_err(|err| {
            error!("Failed to run man: {err}");
            Failed
        }).and_then(|exit| {
            if exit.success() {
                Ok(())
            }
            else {
                Err(Failed)
            }
        }).map_err(Into::into)
    }
}


//------------ SignalListener --------------------------------------------------

#[allow(dead_code)]
enum UserSignal {
    ReloadTals,
    RotateLog,
}

/// Wait for the next validation run or a user telling us to quit or reload.
///
/// This is going to receive a proper impl on Unix and possibly Windows.
#[cfg(unix)]
struct SignalListener {
    usr1: Signal,
    usr2: Signal,
}

#[cfg(unix)]
impl SignalListener {
    pub fn new() -> Result<Self, Failed> {
        Ok(SignalListener {
            usr1: match signal(SignalKind::user_defined1()) {
                Ok(usr1) => usr1,
                Err(err) => {
                    error!("Attaching to signal USR1 failed: {err}");
                    return Err(Failed)
                }
            },
            usr2: match signal(SignalKind::user_defined2()) {
                Ok(usr2) => usr2,
                Err(err) => {
                    error!("Attaching to signal USR2 failed: {err}");
                    return Err(Failed)
                }
            },
        })
    }

    /// Waits for the next thing to do.
    ///
    /// Returns what to do.
    pub async fn next(&mut self) -> UserSignal {
        tokio::select! {
            _ = self.usr1.recv() => UserSignal::ReloadTals,
            _ = self.usr2.recv() => UserSignal::RotateLog,
        }
    }
}

#[cfg(not(unix))]
struct SignalListener;

#[cfg(not(unix))]
impl SignalListener {
    pub fn new() -> Result<Self, Failed> {
        Ok(SignalListener)
    }

    /// Waits for the next thing to do.
    ///
    /// Returns whether to continue working.
    pub async fn next(&mut self) -> UserSignal {
        pending().await
    }
}


//------------ Constants -----------------------------------------------------

/// The raw bytes of the manual page.
const MAN_PAGE: &[u8] = include_bytes!("../doc/routinator.1");

/// The after help message pointing to the main help.
const AFTER_HELP: &str = 
    "Additional global options are available. \
    Please consult 'routinator --help' for those.";

