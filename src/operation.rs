//! What Routinator can do for you.
//!
//! This module implements all the commands users can ask Routinator to
//! perform. They are encapsulated in the type [`Operation`] which can
//! determine the command from the command line argumments and then execute
//! it.
//!
//! [`Operation`]: enum.Operation.html

use std::{fs, io};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::time::Instant;
use clap::{App, Arg, ArgMatches, SubCommand};
use futures::future;
use futures::future::Future;
use rpki::resources::AsId;
use tempfile::NamedTempFile;
use tokio::timer::Delay;
use crate::config::Config;
use crate::http::http_listener;
use crate::metrics::Metrics;
use crate::origins::{AddressOrigins, AddressPrefix, OriginsHistory};
use crate::output;
use crate::output::OutputFormat;
use crate::repository::Repository;
use crate::rtr::{rtr_listener, NotifySender};


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
    /// Initialize the local repository.
    Prepare {
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
    },

    /// Run as server.
    Server {
        /// Detach from the terminal.
        ///
        /// If this is `false`, we just start the server and keep going. If
        /// this is `true`, we detach from the terminal into daemon mode
        /// which has a few extra consequences.
        detach: bool,
    },

    /// Produce a list of Validated ROA Payload.
    Vrps {
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
    },

    /// Update the local repository.
    ///
    /// This will also do a validation run in order to discover possible new
    /// publication points.
    Update,

    /// Shows the current configuration.
    Config,

    /// Show the manual page.
    Man {
        /// Output the page instead of showing it.
        ///
        /// Output is requested by this being some. If there is a path,
        /// then we output to the file identified by the path, otherwise
        /// we print to stdout.
        #[allow(clippy::option_option)]
        output: Option<Option<PathBuf>>,
    },
}

impl Operation {
    /// Initialize everything.
    ///
    /// Call this before doing anything else.
    pub fn init() -> Result<(), Error> {
        Config::init_logging()
    }

    /// Adds the command configuration to a clap app.
    pub fn config_args<'a: 'b, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        app

        // init
        .subcommand(SubCommand::with_name("init")
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

        // vrps
        .subcommand(SubCommand::with_name("vrps")
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

        // update
        .subcommand(SubCommand::with_name("update")
            .about("Updates the local RPKI repository")
        )

        // server
        .subcommand(Config::server_args(SubCommand::with_name("server")
            .about("Starts as a server")
            .arg(Arg::with_name("detach")
                .short("d")
                .long("detach")
                .help("Detach from the terminal")
            )
        ))

        // config
        .subcommand(Config::server_args(SubCommand::with_name("config")
            .about("Prints the current config and exits")
        ))

        // man
        .subcommand(SubCommand::with_name("man")
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
    pub fn from_arg_matches(
        matches: &ArgMatches,
        cur_dir: &Path,
        config: &mut Config
    ) -> Result<Self, Error> {
        Ok(match matches.subcommand() {
            ("init", Some(matches)) => {
                Operation::Prepare {
                    force: matches.is_present("force"),
                    accept_arin_rpa: matches.is_present("accept-arin-rpa"),
                    decline_arin_rpa: matches.is_present("decline-arin-rpa"),
                }
            }
            ("server", Some(matches)) => {
                config.apply_server_arg_matches(matches, cur_dir)?;
                Operation::Server {
                    detach: matches.is_present("detach")
                }
            }
            ("update", _) => Operation::Update,
            ("vrps", Some(matches)) => {
                Operation::Vrps {
                    filters: Self::output_filters(matches)?,
                    output: match matches.value_of("output").unwrap() {
                        "-" => None,
                        path => Some(path.into())
                    },
                    format: OutputFormat::from_str(
                        matches.value_of("format").unwrap()
                    )?,
                    noupdate: matches.is_present("noupdate")
                }
            }
            ("config", Some(matches)) => {
                config.apply_server_arg_matches(matches, cur_dir)?;
                Operation::Config
            }
            ("man", Some(matches)) => {
                Operation::Man {
                    output: matches.value_of("output").map(|value| {
                        match value {
                            "-" => None,
                            path => Some(path.into())
                        }
                    })
                }
            }
            ("", _) => {
                error!(
                    "Error: a command is required.\n\
                     \nCommonly used commands are:\
                     \n   vrps    Produces a list of validated ROA payload\
                     \n   server  Start the RTR server\
                     \n   man     Show the manual page\
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
    pub fn run(self, config: Config) -> Result<(), Error> {
        match self {
            Operation::Prepare { force, accept_arin_rpa, decline_arin_rpa }
                => Self::prepare(config, force, accept_arin_rpa,
                                 decline_arin_rpa),
            Operation::Server { detach }
                => Self::server(config, detach),
            Operation::Vrps { output, format, filters, noupdate } 
                => Self::vrps(config, output, format, filters, noupdate),
            Operation::Update
                => Self::update(config),
            Operation::Config => 
                Self::print_config(config),
            Operation::Man { output } => {
                match output {
                    Some(output) => Self::output_man(output),
                    None => Self::display_man(),
                }
            }
        }
    }
}

/// # Running Actual Commands
///
impl Operation {
    /// Initializes the local repository.
    ///
    /// Tries to create `config.cache_dir` if it doesn’t exist. Creates the
    /// `config.tal_dir` if it doesn’t exist and installs the bundled TALs.
    /// It also does the latter if the directory exists and `force` is
    /// `true`.
    ///
    /// We will, however, refuse to install any TALs until `accept_arin_rpa`
    /// is `true`. If it isn’t we just print a friendly reminder instead.
    fn prepare(
        config: Config,
        force: bool,
        accept_arin_rpa: bool,
        decline_arin_rpa: bool,
    ) -> Result<(), Error> {
        if let Err(err) = fs::create_dir_all(&config.cache_dir) {
            error!(
                "Failed to create repository directory {}: {}.",
                config.cache_dir.display(), err
            );
            return Err(Error);
        }

        // Check if TAL directory exists and error out if needed.
        if let Ok(metadata) = fs::metadata(&config.tal_dir) {
            if metadata.is_dir() {
                if !force {
                    error!(
                        "TAL directory {} exists.\n\
                        Use -f to force installation of TALs.",
                        config.tal_dir.display()
                    );
                    return Err(Error);
                }
            }
            else {
                error!(
                    "TAL directory {} exists and is not a directory.",
                    config.tal_dir.display()
                );
                return Err(Error)
            }
        }

        // Do the ARIN thing. We need to do this before trying to create
        // the directory or it will be there already next time and confuse
        // people.
        if !accept_arin_rpa && !decline_arin_rpa {
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
            return Err(Error)
        }

        // Try to create the TAL directory and error out if that fails.
        if let Err(err) = fs::create_dir_all(&config.tal_dir) {
            error!(
                "Cannot create TAL directory {}: {}",
                config.tal_dir.display(), err
            );
            return Err(Error)
        }

        // Now write all the TALs. Overwrite existing ones.
        for (name, content) in &DEFAULT_TALS {
            Self::write_tal(&config, name, content)?;
        }
        if accept_arin_rpa {
            Self::write_tal(&config, ARIN_TAL.0, ARIN_TAL.1)?;
        }

        // Not really an error, but that’s our log level right now.
        error!(
            "Created local repository directory {}",
            config.cache_dir.display()
        );
        error!(
            "Installed {} TALs in {}",
            if accept_arin_rpa {
                DEFAULT_TALS.as_ref().len() + 1
            }
            else {
                DEFAULT_TALS.as_ref().len()
            },
            config.tal_dir.display()
        );

        Ok(())
    }

    /// Writes the given tal.
    fn write_tal(
        config: &Config,
        name: &str,
        content: &[u8]
    ) -> Result<(), Error> {
        let mut file = match fs::File::create(config.tal_dir.join(name)) {
            Ok(file) => file,
            Err(err) => {
                error!(
                    "Can't create TAL file {}: {}.\n Aborting.",
                    config.tal_dir.join(name).display(), err
                );
                return Err(Error);
            }
        };
        if let Err(err) = file.write_all(content) {
            error!(
                "Can't create TAL file {}: {}.\n Aborting.",
                config.tal_dir.join(name).display(), err
            );
            return Err(Error);
        }
        Ok(())
    }

    /// Starts the RTR server.
    ///
    /// If `detach` is `true`, will fork the server and exit. Otherwise
    /// just runs the server forever.
    fn server(mut config: Config, detach: bool) -> Result<(), Error> {
        let repo = config.create_repository(false, true)?;
        if detach {
            Self::daemonize(&mut config)?;
        }
        config.switch_logging(detach)?;

        // Start out with validation so that we only fire up our sockets
        // once we are actually ready.
        if repo.update().is_err() {
            warn!("Repository update failed. Continuing anyway.");
        }
        let roas = match repo.process() {
            Ok(roas) => roas,
            Err(_) => {
                error!("Fatal: Validation failed. Aborting");
                return Err(Error)
            }
        };
        let mut metrics = Metrics::new();
        let history = OriginsHistory::new(
            AddressOrigins::from_route_origins(
                roas, &config.load_exceptions(false)?, false, &mut metrics,
            ),
            config.history_size
        );
        history.push_metrics(metrics);
        history.mark_update_done();

        info!("Starting listeners...");
        let (notify, rtr) = rtr_listener(history.clone(), &config);
        let http = http_listener(history.clone(), &config);
        tokio::runtime::run(
            Self::update_future(repo, history, notify, config)
            .join3(rtr, http)
            .map(|_| ())
        );
        Ok(())
    }

    #[cfg(unix)]
    fn daemonize(config: &mut Config) -> Result<(), Error> {
        if let Err(err) = config.daemonize()?.start() {
            error!("Detaching failed: {}", err);
            return Err(Error)
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn daemonize(_config: &mut Config) -> Result<(), Error> {
        Ok(())
    }

    /// Updates the repository.
    ///
    /// This runs both an update of the already known publication points but
    /// also does validation in order to discover new points.
    ///
    /// Which turns out is just a shortcut for `vrps` with no output.
    fn update(config: Config) -> Result<(), Error> {
        Self::vrps(config, None, OutputFormat::None, None, false)
    }

    /// Produces a list of Validated ROA Payload.
    ///
    /// The list will be written to the file identified by `output` or
    /// stdout if that is `None`. The format is determined by `format`.
    /// If `noupdate` is `false`, the local repository will be updated first
    /// and rsync will be enabled during validation to sync any new
    /// publication points.
    fn vrps(
        config: Config,
        output: Option<PathBuf>,
        format: OutputFormat,
        filters: Option<Vec<output::Filter>>,
        noupdate: bool
    ) -> Result<(), Error> {
        let repo = config.create_repository(format.extra_output(), !noupdate)?;
        config.switch_logging(false)?;
        let exceptions = repo.load_exceptions(&config)?;

        if repo.update().is_err() {
            warn!("Update failed. Continuing anyway.");
        }
        let roas = match repo.process() {
            Ok(roas) => roas,
            Err(_) => {
                error!("Validation failed. Aborting.");
                return Err(Error)
            }
        };
        debug!("Found {} ROAs.", roas.len());
        let mut metrics = Metrics::new();
        let vrps = AddressOrigins::from_route_origins(
            roas, &exceptions, format.extra_output(), &mut metrics
        );
        metrics.log();
        let filters = filters.as_ref().map(AsRef::as_ref);
        let res = match output {
            Some(ref path) => {
                let mut file = match fs::File::create(path) {
                    Ok(file) => file,
                    Err(err) => {
                        error!(
                            "Failed to open output file '{}': {}",
                            path.display(), err
                        );
                        return Err(Error)
                    }
                };
                format.output(&vrps, filters, &metrics, &mut file)
            }
            None => {
                let out = io::stdout();
                let mut out = out.lock();
                format.output(&vrps, filters, &metrics, &mut out)
            }
        };
        res.map_err(|err| {
            error!(
                "Failed to output result: {}",
                err
            );
            Error
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
                    Err(_) => match u32::from_str(value) {
                        Ok(asn) => asn.into(),
                        Err(_) => {
                            error!(
                                "Invalid ASN \"{}\" in --filter-asn",
                                value
                            );
                            return Err(Error)
                        }
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

    /// Returns a future that updates and validates the local repository.
    ///
    /// The future periodically runs an update and validation on `repo`. It
    /// sdds the result to `history`. If there are changes, it also triggers
    /// a notification on `notify`. 
    fn update_future(
        repo: Repository,
        history: OriginsHistory,
        notify: NotifySender,
        config: Config,
    ) -> impl Future<Item=(), Error=()> {
        future::loop_fn(
            (repo, history, notify, config),
            |(repo, history, mut notify, config)| {
                Delay::new(Instant::now() + config.refresh)
                .map_err(|e| {
                    error!("Fatal: wait timer failed ({})", e);
                    Error
                })
                .and_then(move |_| {
                    repo.start();
                    history.mark_update_start();
                    Ok((repo, history))
                })
                .and_then(|(repo, history)| {
                    info!("Updating the local repository.");
                    repo.update_async().map(|()| (repo, history))
                })
                .and_then(|(repo, history)| {
                    info!("Starting validation of local repository.");
                    repo.process_async()
                    .and_then(move |origins| {
                        info!("Loading exceptions.");
                        let must_notify = match repo.load_exceptions(&config) {
                            Ok(exceptions) => {
                                history.update(
                                    Some(origins),
                                    &exceptions,
                                    false
                                )
                            }
                            Err(_) => {
                                warn!(
                                    "Failed to load exceptions. \
                                     Discarding this validation run but \
                                     continuing."
                                );
                                false
                            }
                        };
                        history.mark_update_done();
                        info!("New serial is {}.", history.serial());
                        if must_notify {
                            info!("Sending out notifications.");
                            notify.notify();
                        }
                        Ok(future::Loop::Continue(
                            (repo, history, notify, config))
                        )
                    })
                })
            }
        ).map_err(|_| ())
    }

    /// Prints the current configuration to stdout and exits.
    #[cfg(unix)]
    fn print_config(mut config: Config) -> Result<(), Error> {
        if config.chroot.is_some() {
            config.daemonize()?;
        }
        println!("{}", config);
        Ok(())
    }

    /// Prints the current configuration to stdout and exits.
    #[cfg(not(unix))]
    fn print_config(config: Config) -> Result<(), Error> {
        println!("{}", config);
        Ok(())
    }

    /// Outputs the manual page to the given path.
    ///
    /// If the path is `None`, outputs to stdout.
    fn output_man(output: Option<PathBuf>) -> Result<(), Error> {
        match output {
            Some(path) => {
                let mut file = match fs::File::create(&path) {
                    Ok(file) => file,
                    Err(err) => {
                        error!(
                            "Failed to open output file {}: {}",
                            path.display(), err
                        );
                        return Err(Error)
                    }
                };
                if let Err(err) = file.write_all(MAN_PAGE) {
                    error!("Failed to write to output file: {}", err);
                    return Err(Error)
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
                    return Err(Error)
                }
            }
        }
        Ok(())
    }

    /// Displays the manual page.
    ///
    /// This puts the manual page into a temporary file and then executes
    /// the `man` command. This probably doesn’t work on Windows.
    fn display_man() -> Result<(), Error> {
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
        })
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

