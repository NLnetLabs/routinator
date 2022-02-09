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
use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::mpsc::RecvTimeoutError;
use std::time::Duration;
#[cfg(feature = "rta")] use bytes::Bytes;
use clap::{App, Arg, ArgMatches, SubCommand};
use log::{error, info};
use routecore::addr;
use rpki::repository::resources::Asn;
#[cfg(feature = "rta")] use rpki::repository::rta::Rta;
use rpki::rtr::server::NotifySender;
use tempfile::NamedTempFile;
use tokio::sync::oneshot;
#[cfg(feature = "rta")] use crate::rta;
use crate::{output, tals, validity};
use crate::config::Config;
use crate::error::{ExitError, Failed};
use crate::http::http_listener;
use crate::metrics::{SharedRtrServerMetrics};
use crate::output::OutputFormat;
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
/// all necessary sub-commands and arguments to a clap `App` via
/// [`config_args`] and then process the argument matches into a value in
/// [`from_arg_matches`]. Finally, you can execute the created command
/// through the [`run`] method.
///
/// [`config_args`]: #method.config_args
/// [`from_arg_matches`]: #method.from_arg_matches
/// [`run`]: #method.run
pub enum Operation {
    Init(Init),
    Server(Server),
    Vrps(Vrps),
    Validate(Validate),
    #[cfg(feature = "rta")]
    ValidateDocument(ValidateDocument),
    Update(Update),
    PrintConfig(PrintConfig),
    Dump(Dump),
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
    pub fn config_args<'a: 'b, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let app = Init::config_args(app);
        let app = Server::config_args(app);
        let app = Vrps::config_args(app);
        let app = Validate::config_args(app);

        #[cfg(feature = "rta")]
        let app = ValidateDocument::config_args(app);

        let app = Update::config_args(app);
        let app = PrintConfig::config_args(app);
        let app = Dump::config_args(app);
        Man::config_args(app)
    }

    /// Creates a command from clap matches.
    pub fn from_arg_matches(
        matches: &ArgMatches,
        cur_dir: &Path,
        config: &mut Config
    ) -> Result<Self, Failed> {
        Ok(match matches.subcommand() {
            ("init", Some(matches)) => {
                Operation::Init(Init::from_arg_matches(matches)?)
            }
            ("server", Some(matches)) => {
                Operation::Server(
                    Server::from_arg_matches(matches, cur_dir, config)?
                )
            }
            ("vrps", Some(matches)) => {
                Operation::Vrps(Vrps::from_arg_matches(matches)?)
            }
            ("validate", Some(matches)) => {
                Operation::Validate(Validate::from_arg_matches(matches)?)
            },
            #[cfg(feature = "rta")]
            ("rta", Some(matches)) => {
                Operation::ValidateDocument(
                    ValidateDocument::from_arg_matches(matches)?
                )
            }
            ("update", Some(matches)) => {
                Operation::Update(Update::from_arg_matches(matches)?)
            }
            ("config", Some(matches)) => {
                Operation::PrintConfig(
                    PrintConfig::from_arg_matches(matches, cur_dir, config)?
                )
            }
            ("dump", Some(matches)) => {
                Operation::Dump( Dump::from_arg_matches(matches, cur_dir)?)
            }
            ("man", Some(matches)) => {
                Operation::Man(Man::from_arg_matches(matches)?)
            }
            ("", _) => {
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
            _ => panic!("Unexpected subcommand."),
        })
    }

    /// Runs the command.
    ///
    /// Depending on the command, this method may switch to logging at some
    /// point.
    pub fn run(self, config: Config) -> Result<(), ExitError> {
        let process = Process::new(config);
        match self {
            Operation::Init(cmd) => cmd.run(process),
            Operation::Server(cmd) => cmd.run(process),
            Operation::Vrps(cmd) => cmd.run(process),
            Operation::Validate(cmd) => cmd.run(process),
            #[cfg(feature = "rta")]
            Operation::ValidateDocument(cmd) => cmd.run(process),
            Operation::Update(cmd) => cmd.run(process),
            Operation::PrintConfig(cmd) => cmd.run(process),
            Operation::Dump(cmd) => cmd.run(process),
            Operation::Man(cmd) => cmd.run(process),
        }
    }
}


//------------ Init ----------------------------------------------------------

/// Initialize the local repository.
pub enum Init {
    /// Only list TALs and exit.
    ListTals,

    /// Actually do an initialization.
    Init {
        /// Force installation of TALs.
        ///
        /// If the TAL directory is present, we will not touch it unless this
        /// flag is `true`.
        force: bool,

        /// The set of TALs to install.
        tals: Vec<&'static tals::BundledTal>,
    }
}

impl Init {
    /// Adds the command configuration to a clap app.
    pub fn config_args<'a: 'b, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        let mut cmd = SubCommand::with_name("init")
            .about("Initializes the local repository")
            .arg(Arg::with_name("force")
                .short("f")
                .long("force")
                .help("Overwrite an existing TAL directory")
            )
            .arg(Arg::with_name("rir-tals")
                .long("rir-tals")
                .help("Install all RIR production TALs")
            )
            .arg(Arg::with_name("rir-test-tals")
                .long("rir-test-tals")
                .help("Install all RIR testbed TALs")
            )
            .arg(Arg::with_name("tal")
                .long("tal")
                .help(
                    "Name a TAL to be installed \
                     (--list-tals shows available TALs)"
                )
                .takes_value(true)
                .multiple(true)
                .number_of_values(1)
            )
            .arg(Arg::with_name("skip-tal")
                .long("skip-tal")
                .help("Name a TAL not to be in installed")
                .takes_value(true)
                .multiple(true)
                .number_of_values(1)
            )
            .arg(Arg::with_name("decline-arin-rpa")
                .long("decline-arin-rpa")
                .help("Same as '--skip-tal arin' (deprecated)")
            )
            .arg(Arg::with_name("list-tals")
                .long("list-tals")
                .help("List available TALs and exit")
            )
            .after_help(
                "If none of --rir-tals, --rir-test-tals, or --tal is \
                given, assumes --rir-tals.\n
                \n\
                Additional global options are available. \
                Please consult 'routinator --help' for those."
            );

        for tal in tals::BUNDLED_TALS {
            if let Some(opt_in) = tal.opt_in.as_ref() {
                cmd = cmd.arg(
                    Arg::with_name(opt_in.option_name)
                    .long(opt_in.option_name)
                    .help(opt_in.option_help)
                );
            }
        }

        app.subcommand(cmd)
    }

    /// Creates a command from clap matches.
    pub fn from_arg_matches(
        matches: &ArgMatches,
    ) -> Result<Self, Failed> {
        // Easy out for --list-tals
        if matches.is_present("list-tals") {
            return Ok(Init::ListTals)
        }

        // Collect the names of all requested TALs.
        let mut requested: HashSet<_> = matches.values_of("tal").map(|tals| {
            tals.collect()
        }).unwrap_or_default();
        if matches.is_present("rir-test-tals") {
            for tal in tals::BUNDLED_TALS {
                if tal.category == tals::Category::RirTest {
                    requested.insert(tal.name);
                }
            }
        }
        // --rir-tals or lack of other TAL commands includes all RIR TALs.
        if matches.is_present("rir-tals") || requested.is_empty() {
            for tal in tals::BUNDLED_TALS {
                if tal.category == tals::Category::Production {
                    requested.insert(tal.name);
                }
            }
        }

        // Removed --skip-tal TALs.
        if let Some(values) = matches.values_of("skip-tal") {
            for tal in values {
                // Be strict to avoid accidents.
                if !requested.remove(tal) {
                    eprintln!("Attempt to skip non-included TAL '{}'", tal);
                    return Err(Failed)
                }
            }
        }

        // Remove ARIN Tal.
        if matches.is_present("decline-arin-rpa") {
            eprintln!(
                "Warning: '--decline-arin-rpa' has been replaced \
                 by '--skip-tal arin' and \n         will be removed."
            );
            if !requested.remove("arin") {
                eprintln!("Attempt to skip non-included TAL 'arin'");
                return Err(Failed)
            }
        }

        let mut tals = Vec::new();

        for tal in tals::BUNDLED_TALS {
            if !requested.remove(tal.name) {
                continue
            }
            tals.push(tal);
            if let Some(opt_in) = tal.opt_in.as_ref() {
                if !matches.is_present(opt_in.option_name) {
                    eprintln!("{}", opt_in.message);
                    return Err(Failed)
                }
            }
        }

        if !requested.is_empty() {
            for name in requested {
                eprintln!("Unknown TAL '{}'", name);
            }
            return Err(Failed)
        }

        Ok(Init::Init {
            force: matches.is_present("force"),
            tals,
        })
    }

    /// Initializes the local repository.
    ///
    /// Tries to create `config.cache_dir` if it doesn’t exist. Creates the
    /// `config.tal_dir` if it doesn’t exist and installs the bundled TALs.
    /// It also does the latter if the directory exists and `force` is
    /// `true`.
    pub fn run(self, process: Process) -> Result<(), ExitError> {
        let (force, tals) = match self {
            Init::ListTals => {
                Self::list_tals();
                return Ok(())
            }
            Init::Init { force, tals } => (force, tals)
        };

        process.create_cache_dir()?;

        // Check if TAL directory exists and error out if needed.
        if let Ok(metadata) = fs::metadata(&process.config().tal_dir) {
            if metadata.is_dir() {
                if !force {
                    error!(
                        "TAL directory {} exists.\n\
                        Use -f to force installation of TALs.",
                        process.config().tal_dir.display()
                    );
                    return Err(Failed.into());
                }
            }
            else {
                error!(
                    "TAL directory {} exists and is not a directory.",
                    process.config().tal_dir.display()
                );
                return Err(Failed.into())
            }
        }

        // Try to create the TAL directory and error out if that fails.
        if let Err(err) = fs::create_dir_all(&process.config().tal_dir) {
            error!(
                "Cannot create TAL directory {}: {}",
                process.config().tal_dir.display(), err
            );
            return Err(Failed.into())
        }

        // Now write all the TALs. Overwrite existing ones.
        for tal in &tals {
            Self::write_tal(&process.config().tal_dir, tal.name, tal.content)?;
        }

        // Not really an error, but that’s our log level right now.
        error!(
            "Created local repository directory {}",
            process.config().cache_dir.display()
        );
        error!(
            "Installed {} TALs in {}",
            tals.len(),
            process.config().tal_dir.display()
        );

        Ok(())
    }

    /// Writes the given tal.
    fn write_tal(
        tal_dir: &Path,
        name: &str,
        content: &str,
    ) -> Result<(), Failed> {
        let mut file = match fs::File::create(tal_dir.join(
            format!("{}.tal", name)
        )) {
            Ok(file) => file,
            Err(err) => {
                error!(
                    "Can't create TAL file {}: {}.\n Aborting.",
                    tal_dir.join(name).display(), err
                );
                return Err(Failed);
            }
        };
        if let Err(err) = file.write_all(content.as_ref()) {
            error!(
                "Can't create TAL file {}: {}.\n Aborting.",
                tal_dir.join(name).display(), err
            );
            return Err(Failed);
        }
        Ok(())
    }

    /// Lists all the bundled TALs and exits.
    fn list_tals() {
        let max_len = tals::BUNDLED_TALS.iter().map(|tal| 
            tal.name.len()
        ).max().unwrap_or(0) + 2;

        println!(" .---- --rir-tals");
        println!(" |  .- --rir-test-tals");
        println!(" V  V\n");

        for tal in tals::BUNDLED_TALS {
            match tal.category {
                tals::Category::Production => print!(" X      "),
                tals::Category::RirTest => print!("    X   "),
                _ => print!("        "),
            }
            println!(
                "{:width$} {}", tal.name, tal.description, width = max_len
            );
        }
    }
}


//------------ Server --------------------------------------------------------

/// Run as server.
pub struct Server {
    /// Detach from the terminal.
    ///
    /// If this is `false`, we just start the server and keep going. If
    /// this is `true`, we detach from the terminal into daemon mode
    /// which has a few extra consequences.
    detach: bool,
}

impl Server {
    /// Adds the command configuration to a clap app.
    pub fn config_args<'a: 'b, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        app.subcommand(Config::server_args(SubCommand::with_name("server")
            .about("Starts as a server")
            .arg(Arg::with_name("detach")
                .short("d")
                .long("detach")
                .help("Detach from the terminal")
            )
            .after_help(AFTER_HELP)
        ))
    }

    /// Creates a command from clap matches.
    pub fn from_arg_matches(
        matches: &ArgMatches,
        cur_dir: &Path,
        config: &mut Config
    ) -> Result<Self, Failed> {
        config.apply_server_arg_matches(matches, cur_dir)?;
        Ok(Server {
            detach: matches.is_present("detach")
        })
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
        process.setup_service(self.detach)?;
        let log = log.map(Arc::new);
        let rtr_metrics = SharedRtrServerMetrics::new(
            process.config().rtr_client_metrics
        );

        let history = SharedHistory::from_config(process.config());
        let (mut notify, rtr) = rtr_listener(
            history.clone(), rtr_metrics.clone(), process.config(),
            process.get_listen_fd()?
        )?;
        let http = http_listener(
            history.clone(), rtr_metrics, log.clone(), process.config()
        )?;

        process.drop_privileges()?;

        let mut validation = Engine::new(process.config(), true)?;
        let runtime = process.runtime()?;
        let mut rtr = runtime.spawn(rtr);
        let mut http = runtime.spawn(http);
        let (sig_tx, sig_rx) = mpsc::channel();
        let (err_tx, mut err_rx) = oneshot::channel();

        validation.ignite()?;

        let join = thread::spawn(move || {
            loop {
                if let Some(log) = log.as_ref() {
                    log.start();
                }
                let timeout = match LocalExceptions::load(
                    process.config(), true
                ) {
                    Ok(exceptions) => {
                        if Self::process_once(
                            process.config(), &validation, &history,
                            &mut notify, exceptions,
                        ).is_err() {
                            break;
                        }
                        history.read().refresh_wait()
                    }
                    Err(_) => {
                        error!(
                            "Failed to load exceptions. \
                            Trying again in 10 seconds."
                        );
                        Duration::from_secs(10)
                    }
                };
                if let Some(log) = log.as_ref() {
                    log.flush();
                }
                match sig_rx.recv_timeout(timeout) {
                    Ok(UserSignal::ReloadTals) => {
                        match validation.reload_tals() {
                            Ok(_) => {
                                info!("Reloaded TALs at user request.");
                            },
                            Err(_) => {
                                error!(
                                    "Fatal: Reloading TALs failed, \
                                     shutting down."
                                );
                                break;
                            }
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => { }
                    Err(RecvTimeoutError::Disconnected) => {
                        break;
                    }
                }
            }
            // An error here means the receiver is gone which is fine.
            let _ = err_tx.send(());
        });

        let _: Result<(), Failed> = runtime.block_on(async move {
            let mut signal = SignalListener::new()?;
            loop {
                tokio::select! {
                    sig = signal.next() => {
                        if sig_tx.send(sig).is_err() {
                            break;
                        }
                    }
                    _  = &mut err_rx => break,
                    _ = &mut rtr => break,
                    _ = &mut http => break,
                }
            }
            // Dropping sig_tx will lead to sig_rx failing and the thread
            // ending. The drop is actually not necessary because sig_tx was
            // moved here, but just in case a ref sneaks in later, let’s keep
            // it.
            drop(sig_tx);
            Ok(())
        });

        let _ = join.join();
        Ok(())
    }

    fn process_once(
        config: &Config,
        engine: &Engine,
        history: &SharedHistory,
        notify: &mut NotifySender,
        exceptions: LocalExceptions,
    ) -> Result<(), Failed> {
        info!("Starting a validation run.");
        history.mark_update_start();
        let (report, metrics) = ValidationReport::process(
            engine, config.enable_bgpsec
        )?;
        let must_notify = history.update(
            report, &exceptions, metrics,
        );
        if log::max_level() >= log::Level::Info {
            info!("Validation completed.");
            let (metrics, serial) = {
                let history = history.read();
                (history.metrics(), history.serial())
            };
            if let Some(metrics) = metrics {
                output::Summary::log(&metrics)
            }
            info!(
                "New serial is {}.", serial
            );
        }
        if must_notify {
            info!("Sending out notifications.");
            notify.notify();
        }
        history.mark_update_done();
        Ok(())
    }
}


//------------ Vrps ----------------------------------------------------------

/// Produce a list of Validated ROA Payload.
pub struct Vrps {
    /// The destination to output the list to.
    ///
    /// If this is some path, then we print the list into that file.
    /// Otherwise we just dump it to stdout.
    output: Option<PathBuf>,

    /// The desired output format.
    format: OutputFormat,

    /// Optional output filters.
    selection: Option<output::Selection>,

    /// Don’t update the repository.
    noupdate: bool,

    /// Return an error on incomplete update.
    complete: bool,
}

impl Vrps {
    /// Adds the command configuration to a clap app.
    pub fn config_args<'a: 'b, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        app.subcommand(SubCommand::with_name("vrps")
            .about("Produces a list of validated ROA payload")
            .arg(Arg::with_name("output")
                .short("o")
                .long("output")
                .value_name("FILE")
                .help("Output file")
                .takes_value(true)
                .default_value("-")
            )
            .arg(Arg::with_name("format")
                .short("f")
                .long("format")
                .value_name("FORMAT")
                .default_value(OutputFormat::DEFAULT_VALUE)
                .help("Sets the output format")
                .takes_value(true)
            )
            .arg(Arg::with_name("noupdate")
                .short("n")
                .long("noupdate")
                .help("Don't update the local cache")
            )
            .arg(Arg::with_name("complete")
                .long("complete")
                .help("Return an error status on incomplete update")
            )
            .arg(Arg::with_name("select-prefix")
                .short("p")
                .long("select-prefix")
                .alias("filter-prefix")
                .help("Filter for an address prefix")
                .takes_value(true)
                .multiple(true)
                .number_of_values(1)
            )
            .arg(Arg::with_name("select-asn")
                .short("a")
                .long("select-asn")
                .alias("filter-asn")
                .help("Filter for an AS number")
                .takes_value(true)
                .multiple(true)
                .number_of_values(1)
            )
            .after_help(AFTER_HELP)
        )
    }

    /// Creates a command from clap matches.
    pub fn from_arg_matches(
        matches: &ArgMatches,
    ) -> Result<Self, Failed> {
        let format = matches.value_of("format").unwrap_or(
            OutputFormat::DEFAULT_VALUE
        );
        let format = match OutputFormat::from_str(format) {
            Ok(format) => format,
            Err(_) => {
                error!("Unknown output format '{}'", format);
                return Err(Failed)
            }
        };
        Ok(Vrps {
            selection: Self::output_selection(matches)?,
            output: match matches.value_of("output").unwrap() {
                "-" => None,
                path => Some(path.into())
            },
            format,
            noupdate: matches.is_present("noupdate"),
            complete: matches.is_present("complete"),
        })
    }

    /// Creates the selection for the vrps command.
    fn output_selection(
        matches: &ArgMatches
    ) -> Result<Option<output::Selection>, Failed> {
        if !matches.is_present("select-prefix")
            && !matches.is_present("select-asn")
        {
            return Ok(None)
        }
        let mut res = output::Selection::new();
        if let Some(list) = matches.values_of("select-prefix") {
            for value in list {
                match addr::Prefix::from_str(value) {
                    Ok(some) => res.push_origin_prefix(some),
                    Err(_) => {
                        error!(
                            "Invalid prefix \"{}\" in --select-prefix",
                            value
                        );
                        return Err(Failed)
                    }
                }
            }
        }
        if let Some(list) = matches.values_of("select-asn") {
            for value in list {
                match Asn::from_str(value) {
                    Ok(asn) => res.push_origin_asn(asn),
                    Err(_) => {
                        error!(
                            "Invalid ASN \"{}\" in --select-asn",
                            value
                        );
                        return Err(Failed)
                    }
                }
            }
        }
        Ok(Some(res))
    }

    /// Produces a list of Validated ROA Payload.
    ///
    /// The list will be written to the file identified by `output` or
    /// stdout if that is `None`. The format is determined by `format`.
    /// If `noupdate` is `false`, the local repository will be updated first
    /// and rsync will be enabled during validation to sync any new
    /// publication points.
    fn run(self, process: Process) -> Result<(), ExitError> {
        let mut engine = Engine::new(process.config(), !self.noupdate)?;
        engine.ignite()?;
        process.switch_logging(false, false)?;
        let exceptions = LocalExceptions::load(process.config(), true)?;
        let (report, mut metrics) = ValidationReport::process(
            &engine, process.config().enable_bgpsec
        )?;
        let vrps = PayloadSnapshot::from_report(
            report,
            &exceptions,
            &mut metrics,
            process.config().unsafe_vrps,
        );
        let res = match self.output {
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
                self.format.output_snapshot(
                    &vrps, self.selection.as_ref(), &metrics, &mut file)
            }
            None => {
                let out = io::stdout();
                let mut out = out.lock();
                self.format.output_snapshot(
                    &vrps, self.selection.as_ref(), &metrics, &mut out
                )
            }
        };
        if let Err(err) = res {
            error!(
                "Failed to output result: {}",
                err
            );
            Err(ExitError::Generic)
        }
        else if self.complete && !metrics.rsync_complete() {
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
    Single(addr::Prefix, Asn),

    /// Validate the routes provided in the given file.
    File(PathBuf),

    /// Validate the routes provided on stdin.
    Stdin,
}

impl Validate {
    /// Adds the command configuration to a clap app.
    pub fn config_args<'a: 'b, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        app.subcommand(SubCommand::with_name("validate")
            .about("Validates a route announcement")
            .arg(Arg::with_name("prefix")
                .short("p")
                .long("prefix")
                .help("Address prefix of the announcement")
                .takes_value(true)
                .requires("asn")
                .conflicts_with("input-file")
            )
            .arg(Arg::with_name("asn")
                .short("a")
                .long("asn")
                .help("Origin AS number of the announcement")
                .takes_value(true)
                .requires("prefix")
                .conflicts_with("input-file")
            )
            .arg(Arg::with_name("json")
                .short("j")
                .long("json")
                .help("Expect input and produce output in JSON")
            )
            .arg(Arg::with_name("input-file")
                .short("i")
                .long("input")
                .help("Read routes from a file")
                .value_name("FILE")
                .takes_value(true)
                .conflicts_with_all(&["prefix", "asn"])
            )
            .arg(Arg::with_name("output-file")
                .short("o")
                .long("output")
                .value_name("FILE")
                .help("Write output to a file")
                .takes_value(true)
                .default_value("-")
            )
            .arg(Arg::with_name("noupdate")
                .short("n")
                .long("noupdate")
                .help("Don't update the local cache")
            )
            .arg(Arg::with_name("complete")
                .long("complete")
                .help("Return an error status on incomplete update")
            )
            .after_help(AFTER_HELP)
        )
    }

    /// Creates a command from clap matches.
    pub fn from_arg_matches(matches: &ArgMatches) -> Result<Self, Failed> {
        Ok(Validate {
            what: if let Some(path) = matches.value_of("input-file") {
                if path == "-" {
                    ValidateWhat::Stdin
                }
                else {
                    ValidateWhat::File(path.into())
                }
            }
            else {
                ValidateWhat::Single(
                    {
                        let prefix = match matches.value_of("prefix") {
                            Some(prefix) => prefix,
                            None => {
                                error!("Missing required --prefix argument");
                                return Err(Failed)
                            }
                        };
                        match addr::Prefix::from_str(prefix) {
                            Ok(prefix) => prefix,
                            Err(err) => {
                                error!("illegal address prefix: {}", err);
                                return Err(Failed);
                            }
                        }
                    },
                    {
                        let asn = match matches.value_of("asn") {
                            Some(asn) => asn,
                            None => {
                                error!("Missing required --asn argument");
                                return Err(Failed)
                            }
                        };
                        match Asn::from_str(asn) {
                            Ok(asn) => asn,
                            Err(_) => {
                                error!("illegal AS number");
                                return Err(Failed);
                            }
                        }
                    },
                )
            },
            json: matches.is_present("json"),
            output: match matches.value_of("output-file").unwrap() {
                "-" => None,
                path => Some(path.into())
            },
            noupdate: matches.is_present("noupdate"),
            complete: matches.is_present("complete"),
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
                let mut file = match fs::File::open(path) {
                    Ok(file) => file,
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
                        &mut file
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
                        io::BufReader::new(file)
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
                        error!("Failed to read input: {}'", err);
                        ExitError::Generic
                    })
                }
                else {
                    validity::RequestList::from_plain_reader(
                        file
                    ).map_err(|err| {
                        error!("Failed to read input: {}'", err);
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
            &engine, process.config().enable_bgpsec
        )?;
        let snapshot = PayloadSnapshot::from_report(
            report,
            &LocalExceptions::load(process.config(), false)?,
            &mut metrics,
            process.config().unsafe_vrps,
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
                let mut file = match fs::File::create(path) {
                    Ok(file) => file,
                    Err(err) => {
                        error!(
                            "Failed to open output file '{}': {}",
                            path.display(), err
                        );
                        return Err(ExitError::Generic)
                    }
                };
                let res = if self.json {
                    result.write_json(&mut file)
                }
                else {
                    result.write_plain(&mut file)
                };
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
                    error!("Failed to write output: {}", err);
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
pub struct ValidateDocument {
    /// Path to the signed document.
    document: PathBuf,

    /// Path to the signature.
    signature: PathBuf,

    /// Don’t update the repository.
    noupdate: bool,
}

#[cfg(feature = "rta")]
impl ValidateDocument {
    /// Adds the command configuration to a clap app.
    pub fn config_args<'a: 'b, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        app.subcommand(SubCommand::with_name("rta")
            .about("Validates an RTA-signed document")
            .arg(Arg::with_name("noupdate")
                .short("n")
                .long("noupdate")
                .help("Don't update the local cache")
            )
            .arg(Arg::with_name("document")
                .value_name("DOCUMENT")
                .required(true)
                .help("Path to the signed document")
            )
            .arg(Arg::with_name("signature")
                .value_name("SIGNATURE")
                .required(true)
                .help("Path to the signature")
            )
            .after_help(AFTER_HELP)
        )
    }

    /// Creates a command from clap matches.
    pub fn from_arg_matches(
        matches: &ArgMatches,
    ) -> Result<Self, Failed> {
        Ok(ValidateDocument {
            document: matches.value_of("document").unwrap().into(),
            signature: matches.value_of("signature").unwrap().into(),
            noupdate: matches.is_present("noupdate"),
        })
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
                    println!("{}", block);
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


//------------ Update --------------------------------------------------------


/// Update the local repository.
///
/// This will also do a validation run in order to discover possible new
/// publication points.
pub struct Update {
    /// Return an error on incomplete update.
    complete: bool,
}

impl Update {
    /// Adds the command configuration to a clap app.
    pub fn config_args<'a: 'b, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        app.subcommand(SubCommand::with_name("update")
            .about("Updates the local RPKI repository")
            .arg(Arg::with_name("complete")
                .long("complete")
                .help("Return an error status on incomplete update")
            )
            .after_help(AFTER_HELP)
        )
    }

    /// Creates a command from clap matches.
    pub fn from_arg_matches(matches: &ArgMatches) -> Result<Self, Failed> {
        Ok(Update {
            complete: matches.is_present("complete"),
        })
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
            &engine, process.config().enable_bgpsec
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
    pub fn config_args<'a: 'b, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        // config
        app.subcommand(Config::server_args(SubCommand::with_name("config")
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
pub struct Dump {
    /// The output directory.
    output: PathBuf,
}

impl Dump {
    /// Adds the command configuration to a clap app.
    pub fn config_args<'a: 'b, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        // config
        app.subcommand(SubCommand::with_name("dump")
            .about("Writes the cache content to disk")
            .arg(Arg::with_name("output")
                .short("o")
                .long("output")
                .value_name("DIR")
                .help("Output directory")
                .takes_value(true)
            )
            .after_help(AFTER_HELP)
        )
    }

    /// Creates a command from clap matches.
    pub fn from_arg_matches(
        matches: &ArgMatches,
        cur_dir: &Path,
    ) -> Result<Self, Failed> {
        Ok(Dump {
            output: {
                matches.value_of("output").map(|path| {
                    cur_dir.join(path)
                }).unwrap_or_else(|| cur_dir.into())
            }
        })
    }

    /// Prints the current configuration to stdout and exits.
    fn run(self, process: Process) -> Result<(), ExitError> {
        let engine = Engine::new(process.config(), true)?;
        process.switch_logging(false, false)?;
        engine.dump(&self.output)?;
        Ok(())
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
    pub fn config_args<'a: 'b, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        app.subcommand(SubCommand::with_name("man")
            .about("Shows the man page")
            .arg(Arg::with_name("output")
                .short("o")
                .long("output")
                .value_name("FILE")
                .help("Output file, '-' or not present for stdout")
                .takes_value(true)
            )
        )
    }

    /// Creates a command from clap matches.
    pub fn from_arg_matches(matches: &ArgMatches) -> Result<Self, Failed> {
        Ok(Man {
            output: matches.value_of("output").map(|value| {
                match value {
                    "-" => None,
                    path => Some(path.into())
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
                    error!("Failed to write to output file: {}", err);
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
                    error!("Failed to write man page: {}", err);
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
                 Failed to create temporary file: {}.",
                err
            );
            Failed
        })?;
        file.write_all(MAN_PAGE).map_err(|err| {
            error!(
                "Can't display man page: \
                Failed to write to temporary file: {}.",
                err
            );
            Failed
        })?;
        Command::new("man").arg(file.path()).status().map_err(|err| {
            error!("Failed to run man: {}", err);
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
}

/// Wait for the next validation run or a user telling us to quit or reload.
///
/// This is going to receive a proper impl on Unix and possibly Windows.
#[cfg(unix)]
struct SignalListener {
    usr1: Signal,
}

#[cfg(unix)]
impl SignalListener {
    pub fn new() -> Result<Self, Failed> {
        Ok(SignalListener {
            usr1: match signal(SignalKind::user_defined1()) {
                Ok(usr1) => usr1,
                Err(err) => {
                    error!("Attaching to signal USR1 failed: {}", err);
                    return Err(Failed)
                }
            }
        })
    }

    /// Waits for the next thing to do.
    ///
    /// Returns what to do.
    pub async fn next(&mut self) -> UserSignal {
        self.usr1.recv().await;
        UserSignal::ReloadTals
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

