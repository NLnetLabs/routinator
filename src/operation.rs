//! What Routinator can do for you.
//!
//! This module implements all the commands users can ask Routinator to
//! perform. They are encapsulated in the type [`Operation`] which can
//! determine the command from the command line argumments and then execute
//! it.
//!
//! [`Operation`]: enum.Operation.html

use std::{fs, io, thread};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::sync::mpsc;
use std::sync::mpsc::RecvTimeoutError;
use std::time::Duration;
#[cfg(feature = "rta")] use bytes::Bytes;
use clap::{App, Arg, ArgMatches, SubCommand};
use log::{error, info, warn};
use rpki::resources::AsId;
#[cfg(feature = "rta")] use rpki::rta::Rta;
use rpki_rtr::server::NotifySender;
use tempfile::NamedTempFile;
use tokio::sync::oneshot;
#[cfg(feature = "rta")] use crate::rta;
use crate::config::Config;
use crate::http::http_listener;
use crate::origins::{AddressOrigins, AddressPrefix, OriginsHistory};
use crate::output;
use crate::output::OutputFormat;
use crate::process::Process;
use crate::repository::Repository;
use crate::rtr::{rtr_listener};
use crate::slurm::LocalExceptions;
use crate::validity::RouteValidity;

#[cfg(unix)] use tokio::signal::unix::{Signal, SignalKind, signal};
#[cfg(unix)] use tokio::stream::StreamExt;
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
    Man(Man),
}

impl Operation {
    /// Prepares everything.
    ///
    /// Call this before doing anything else.
    pub fn prepare() -> Result<(), Error> {
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
        Man::config_args(app)
    }

    /// Creates a command from clap matches.
    pub fn from_arg_matches(
        matches: &ArgMatches,
        cur_dir: &Path,
        config: &mut Config
    ) -> Result<Self, Error> {
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
            ("man", Some(matches)) => {
                Operation::Man(Man::from_arg_matches(matches)?)
            }
            ("", _) => {
                error!(
                    "Error: a command is required.\n\
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
                return Err(Error)
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
            Operation::Man(cmd) => cmd.run(process),
        }
    }
}


//------------ Init ----------------------------------------------------------

/// Initialize the local repository.
pub struct Init {
    /// Force installation of TALs.
    ///
    /// If the TAL directory is present, we will not touch it unless this
    /// flag is `true`.
    force: bool,

    /// Accept the ARIN Relying Party Agreement.
    ///
    /// We can only install the ARIN TAL if this flag is `true`.
    accept_arin_rpa: bool,

    /// Decline the ARIN Relying Party Agreement.
    ///
    /// If this is `true`, we won’t install the ARIN TAL at all.
    decline_arin_rpa: bool,
}

impl Init {
    /// Adds the command configuration to a clap app.
    pub fn config_args<'a: 'b, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        app.subcommand(SubCommand::with_name("init")
            .about("Initializes the local repository")
            .arg(Arg::with_name("force")
                .short("f")
                .long("force")
                .help("Force creation of TALs")
            )
            .arg(Arg::with_name("accept-arin-rpa")
                .long("accept-arin-rpa")
                .help("You have read and accept \
                       https://www.arin.net/resources/manage/rpki/rpa.pdf")
            )
            .arg(Arg::with_name("decline-arin-rpa")
                .long("decline-arin-rpa")
                .conflicts_with("accept-arin-rpa")
                .help("You have read and declined the ARIN RPA")
            )
        )
    }

    /// Creates a command from clap matches.
    pub fn from_arg_matches(
        matches: &ArgMatches,
    ) -> Result<Self, Error> {
        Ok(Init {
            force: matches.is_present("force"),
            accept_arin_rpa: matches.is_present("accept-arin-rpa"),
            decline_arin_rpa: matches.is_present("decline-arin-rpa"),
        })
    }

    /// Initializes the local repository.
    ///
    /// Tries to create `config.cache_dir` if it doesn’t exist. Creates the
    /// `config.tal_dir` if it doesn’t exist and installs the bundled TALs.
    /// It also does the latter if the directory exists and `force` is
    /// `true`.
    ///
    /// We will, however, refuse to install any TALs until `accept_arin_rpa`
    /// is `true`. If it isn’t we just print a friendly reminder instead.
    pub fn run(self, process: Process) -> Result<(), ExitError> {
        process.create_cache_dir()?;

        // Check if TAL directory exists and error out if needed.
        if let Ok(metadata) = fs::metadata(&process.config().tal_dir) {
            if metadata.is_dir() {
                if !self.force {
                    error!(
                        "TAL directory {} exists.\n\
                        Use -f to force installation of TALs.",
                        process.config().tal_dir.display()
                    );
                    return Err(Error.into());
                }
            }
            else {
                error!(
                    "TAL directory {} exists and is not a directory.",
                    process.config().tal_dir.display()
                );
                return Err(Error.into())
            }
        }

        // Do the ARIN thing. We need to do this before trying to create
        // the directory or it will be there already next time and confuse
        // people.
        if !self.accept_arin_rpa && !self.decline_arin_rpa {
            error!(
                "Before we can install the ARIN TAL, you must have read\n\
                 and agree to the ARIN Relying Party Agreement (RPA).\n\
                 It is available at\n\
                 \n\
                 https://www.arin.net/resources/manage/rpki/rpa.pdf\n\
                 \n\
                 If you agree to the RPA, please run the command\n\
                 again with the --accept-arin-rpa option."
            );
            return Err(Error.into())
        }

        // Try to create the TAL directory and error out if that fails.
        if let Err(err) = fs::create_dir_all(&process.config().tal_dir) {
            error!(
                "Cannot create TAL directory {}: {}",
                process.config().tal_dir.display(), err
            );
            return Err(Error.into())
        }

        // Now write all the TALs. Overwrite existing ones.
        for (name, content) in &DEFAULT_TALS {
            Self::write_tal(&process.config().tal_dir, name, content)?;
        }
        if self.accept_arin_rpa {
            Self::write_tal(&process.config().tal_dir, ARIN_TAL.0, ARIN_TAL.1)?;
        }

        // Not really an error, but that’s our log level right now.
        error!(
            "Created local repository directory {}",
            process.config().cache_dir.display()
        );
        error!(
            "Installed {} TALs in {}",
            if self.accept_arin_rpa {
                DEFAULT_TALS.as_ref().len() + 1
            }
            else {
                DEFAULT_TALS.as_ref().len()
            },
            process.config().tal_dir.display()
        );

        Ok(())
    }

    /// Writes the given tal.
    fn write_tal(
        tal_dir: &Path,
        name: &str,
        content: &[u8]
    ) -> Result<(), Error> {
        let mut file = match fs::File::create(tal_dir.join(name)) {
            Ok(file) => file,
            Err(err) => {
                error!(
                    "Can't create TAL file {}: {}.\n Aborting.",
                    tal_dir.join(name).display(), err
                );
                return Err(Error);
            }
        };
        if let Err(err) = file.write_all(content) {
            error!(
                "Can't create TAL file {}: {}.\n Aborting.",
                tal_dir.join(name).display(), err
            );
            return Err(Error);
        }
        Ok(())
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
        ))
    }

    /// Creates a command from clap matches.
    pub fn from_arg_matches(
        matches: &ArgMatches,
        cur_dir: &Path,
        config: &mut Config
    ) -> Result<Self, Error> {
        config.apply_server_arg_matches(matches, cur_dir)?;
        Ok(Server {
            detach: matches.is_present("detach")
        })
    }

    /// Starts the RTR server.
    ///
    /// If `detach` is `true`, will fork the server and exit. Otherwise
    /// just runs the server forever.
    /// Runs the command.
    pub fn run(self, mut process: Process) -> Result<(), ExitError> {
        Repository::init(process.config())?;
        let log = process.switch_logging(
            self.detach,
            !process.config().http_listen.is_empty()
        )?;
        process.setup_service(self.detach)?;

        let history = OriginsHistory::new(process.config(), log);
        let (mut notify, rtr) = rtr_listener(
            history.clone(), process.config()
        )?;
        let http = http_listener(&history, process.config())?;

        process.drop_privileges()?;

        let mut repo = Repository::new(process.config(), true)?;
        let mut runtime = process.runtime()?;
        let mut rtr = runtime.spawn(rtr);
        let mut http = runtime.spawn(http);
        let (sig_tx, sig_rx) = mpsc::channel();
        let (err_tx, mut err_rx) = oneshot::channel();

        let join = thread::spawn(move || {
            loop {
                let timeout = match LocalExceptions::load(
                    process.config(), false
                ) {
                    Ok(exceptions) => {
                        if Self::process_once(
                            &mut repo, &history, &mut notify, exceptions
                        ).is_err() {
                            break;
                        }
                        history.refresh_wait()
                    }
                    Err(_) => {
                        warn!(
                            "Failed to load exceptions. \
                            Trying again in 10 seconds."
                        );
                        Duration::from_secs(10)
                    }
                };
                match sig_rx.recv_timeout(timeout) {
                    Ok(UserSignal::ReloadTals) => {
                        match repo.reload_tals(process.config()) {
                            Ok(_) => {
                                info!("Reloaded TALs at user request.");
                            },
                            Err(_) => {
                                error!(
                                    "Reloading TALs failed, \
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

        let _: Result<(), Error> = runtime.block_on(async move {
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
        repo: &mut Repository,
        history: &OriginsHistory,
        notify: &mut NotifySender,
        exceptions: LocalExceptions,
    ) -> Result<(), Error> {
        history.mark_update_start();
        let (report, metrics) = repo.process_origins()?;
        let must_notify = history.update(
            report, metrics, &exceptions
        );
        info!(
            "Validation completed. New serial is {}.",
            history.serial()
        );
        history.mark_update_done();
        if must_notify {
            info!("Sending out notifications.");
            notify.notify();
        }
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
    filters: Option<Vec<output::Filter>>,

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
                .possible_values(OutputFormat::VALUES)
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
            .arg(Arg::with_name("filter-prefix")
                .short("p")
                .long("filter-prefix")
                .help("Filter for an address prefix")
                .takes_value(true)
                .multiple(true)
                .number_of_values(1)
            )
            .arg(Arg::with_name("filter-asn")
                .short("a")
                .long("filter-asn")
                .help("Filter for an AS number")
                .takes_value(true)
                .multiple(true)
                .number_of_values(1)
            )
        )
    }

    /// Creates a command from clap matches.
    pub fn from_arg_matches(
        matches: &ArgMatches,
    ) -> Result<Self, Error> {
        Ok(Vrps {
            filters: Self::output_filters(matches)?,
            output: match matches.value_of("output").unwrap() {
                "-" => None,
                path => Some(path.into())
            },
            format: OutputFormat::from_str(
                matches.value_of("format").unwrap()
            )?,
            noupdate: matches.is_present("noupdate"),
            complete: matches.is_present("complete"),
        })
    }

    /// Creates the filters for the vrps command.
    fn output_filters(
        matches: &ArgMatches
    ) -> Result<Option<Vec<output::Filter>>, Error> {
        let mut res = Vec::new();
        if let Some(list) = matches.values_of("filter-prefix") {
            for value in list {
                match AddressPrefix::from_str(value) {
                    Ok(some) => res.push(output::Filter::Prefix(some)),
                    Err(_) => {
                        error!(
                            "Invalid prefix \"{}\" in --filter-prefix",
                            value
                        );
                        return Err(Error)
                    }
                }
            }
        }
        if let Some(list) = matches.values_of("filter-asn") {
            for value in list {
                let asn = match AsId::from_str(value) {
                    Ok(asn) => asn,
                    Err(_) => {
                        error!(
                            "Invalid ASN \"{}\" in --filter-asn",
                            value
                        );
                        return Err(Error)
                    }
                };
                res.push(output::Filter::As(asn))
            }
        }
        if res.is_empty() {
            Ok(None)
        }
        else {
            Ok(Some(res))
        }
    }

    /// Produces a list of Validated ROA Payload.
    ///
    /// The list will be written to the file identified by `output` or
    /// stdout if that is `None`. The format is determined by `format`.
    /// If `noupdate` is `false`, the local repository will be updated first
    /// and rsync will be enabled during validation to sync any new
    /// publication points.
    fn run(self, process: Process) -> Result<(), ExitError> {
        let mut repo = Repository::new(process.config(), !self.noupdate)?;
        process.switch_logging(false, false)?;
        let exceptions = LocalExceptions::load(process.config(), true)?;
        let (report, mut metrics) = repo.process_origins()?;
        let vrps = AddressOrigins::from_report(
            report,
            &exceptions,
            &mut metrics
        );
        let filters = self.filters.as_ref().map(AsRef::as_ref);
        let res = match self.output {
            Some(ref path) => {
                let mut file = match fs::File::create(path) {
                    Ok(file) => file,
                    Err(err) => {
                        error!(
                            "Failed to open output file '{}': {}",
                            path.display(), err
                        );
                        return Err(Error.into())
                    }
                };
                self.format.output(&vrps, filters, &metrics, &mut file)
            }
            None => {
                let out = io::stdout();
                let mut out = out.lock();
                self.format.output(&vrps, filters, &metrics, &mut out)
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
    /// The address prefix of the announcement.
    prefix: AddressPrefix,

    /// The origin AS number of the announcement.
    asn: AsId,

    /// Output details in JSON.
    json: bool,

    /// Don’t update the repository.
    noupdate: bool,

    /// Return an error on incomplete update.
    complete: bool,
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
                .required(true)
            )
            .arg(Arg::with_name("asn")
                .short("a")
                .long("asn")
                .help("Origin AS number of the announcement")
                .takes_value(true)
                .required(true)
            )
            .arg(Arg::with_name("json")
                .short("j")
                .long("json")
                .help("Output detailed analysis in JSON")
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
        )
    }

    /// Creates a command from clap matches.
    pub fn from_arg_matches(matches: &ArgMatches) -> Result<Self, Error> {
        Ok(Validate {
            prefix: {
                let prefix = matches.value_of("prefix").unwrap();
                match AddressPrefix::from_str(prefix) {
                    Ok(prefix) => prefix,
                    Err(err) => {
                        error!("illegal address prefix: {}", err);
                        return Err(Error);
                    }
                }
            },
            asn: {
                let asn = matches.value_of("asn").unwrap();
                match AsId::from_str(asn) {
                    Ok(asn) => asn,
                    Err(_) => {
                        error!("illegal AS number");
                        return Err(Error);
                    }
                }
            }, 
            json: matches.is_present("json"),
            noupdate: matches.is_present("noupdate"),
            complete: matches.is_present("complete"),
        })
    }


    /// Outputs whether the given route announcement is valid.
    fn run(self, process: Process) -> Result<(), ExitError> {
        let mut repo = Repository::new(process.config(), !self.noupdate)?;
        process.switch_logging(false, false)?;
        let (report, mut metrics) = repo.process_origins()?;
        let vrps = AddressOrigins::from_report(
            report,
            &LocalExceptions::load(process.config(), false)?,
            &mut metrics
        );
        let validity = RouteValidity::new(self.prefix, self.asn, &vrps);
        if self.json {
            let stdout = io::stdout();
            let mut stdout = stdout.lock();
            validity.write_json(&mut stdout).map_err(|err| {
                error!("Writing to stdout failed: {}", err);
                Error
            })?;
        }
        else {
            println!("{}", validity.state());
        }
        if self.complete && !metrics.rsync_complete() {
            Err(ExitError::IncompleteUpdate)
        }
        else {
            Ok(())
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
        )
    }

    /// Creates a command from clap matches.
    pub fn from_arg_matches(
        matches: &ArgMatches,
    ) -> Result<Self, Error> {
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
        let mut repo = Repository::new(process.config(), !self.noupdate)?;
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

        let validation = match rta::ValidationReport::new(
            &rta, process.config()
        ) {
            Ok(validation) => validation,
            Err(_) => {
                error!("RTA did not validate. (new)");
                return Err(ExitError::Invalid);
            }
        };

        if validation.process(&mut repo).is_err() {
            error!("RTA did not validate. (process)");
            return Err(ExitError::Invalid);
        }

        match validation.finalize() {
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
        )
    }

    /// Creates a command from clap matches.
    pub fn from_arg_matches(matches: &ArgMatches) -> Result<Self, Error> {
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
        let mut repo = Repository::new(process.config(), true)?;
        let (_, metrics) = repo.process_origins()?;
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
        ))
    }

    /// Creates a command from clap matches.
    pub fn from_arg_matches(
        matches: &ArgMatches,
        cur_dir: &Path,
        config: &mut Config,
    ) -> Result<Self, Error> {
        config.apply_server_arg_matches(matches, cur_dir)?;
        Ok(PrintConfig)
    }

    /// Prints the current configuration to stdout and exits.
    fn run(self, process: Process) -> Result<(), ExitError> {
        println!("{}", process.config());
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
    pub fn from_arg_matches(matches: &ArgMatches) -> Result<Self, Error> {
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
                        return Err(Error.into())
                    }
                };
                if let Err(err) = file.write_all(MAN_PAGE) {
                    error!("Failed to write to output file: {}", err);
                    return Err(Error.into())
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
                    return Err(Error.into())
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
            Error
        })?;
        file.write_all(MAN_PAGE).map_err(|err| {
            error!(
                "Can't display man page: \
                Failed to write to temporary file: {}.",
                err
            );
            Error
        })?;
        Command::new("man").arg(file.path()).status().map_err(|err| {
            error!("Failed to run man: {}", err);
            Error
        }).and_then(|exit| {
            if exit.success() {
                Ok(())
            }
            else {
                Err(Error)
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
    pub fn new() -> Result<Self, Error> {
        Ok(SignalListener {
            usr1: match signal(SignalKind::user_defined1()) {
                Ok(usr1) => usr1,
                Err(err) => {
                    error!("Attaching to signal USR1 failed: {}", err);
                    return Err(Error)
                }
            }
        })
    }

    /// Waits for the next thing to do.
    ///
    /// Returns what to do.
    pub async fn next(&mut self) -> UserSignal {
        self.usr1.next().await;
        UserSignal::ReloadTals
    }
}

#[cfg(not(unix))]
struct SignalListener;

#[cfg(not(unix))]
impl SignalListener {
    pub fn new() -> Result<Self, Error> {
        Ok(SignalListener)
    }

    /// Waits for the next thing to do.
    ///
    /// Returns whether to continue working.
    pub async fn next(&mut self) -> UserSignal {
        pending().await
    }
}

//------------ Error ---------------------------------------------------------

/// An error has occurred during operation.
///
/// This is really just a placeholder type. All necessary output has happend
/// already.
///
/// When returning this error, you should specify whether error is printed
/// to stderr, as should happen in early stages of operation, or should be
/// logged.
#[derive(Clone, Copy, Debug)]
pub struct Error;


//------------ ExitError -----------------------------------------------------

/// An error should be reported after running has completed.
#[derive(Clone, Copy, Debug)]
pub enum ExitError {
    /// Something has happened.
    ///
    /// This should be exit status 1.
    Generic,

    /// Incomplete update.
    ///
    /// This should be exit status 2.
    IncompleteUpdate,

    /// An object could not be validated.
    ///
    /// This should be exit status 3.
    Invalid,
}

impl From<Error> for ExitError {
    fn from(_: Error) -> ExitError {
        ExitError::Generic
    }
}


//------------ The Man Page --------------------------------------------------

/// The raw bytes of the manual page.
const MAN_PAGE: &[u8] = include_bytes!("../doc/routinator.1");


//------------ DEFAULT_TALS --------------------------------------------------

const DEFAULT_TALS: [(&str, &[u8]); 4] = [
    ("afrinic.tal", include_bytes!("../tals/afrinic.tal")),
    ("apnic.tal", include_bytes!("../tals/apnic.tal")),
    ("lacnic.tal", include_bytes!("../tals/lacnic.tal")),
    ("ripe.tal", include_bytes!("../tals/ripe.tal")),
];
const ARIN_TAL: (&str, &[u8]) =
    ("arin.tal", include_bytes!("../tals/arin.tal"))
;

