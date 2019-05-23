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
use std::time::Instant;
use clap::{App, Arg, ArgMatches, SubCommand};
use futures::future;
use futures::future::Future;
use tempfile::NamedTempFile;
use tokio::timer::Delay;
use crate::config::Config;
use crate::metrics::Metrics;
use crate::monitor::monitor_listener;
use crate::origins::{AddressOrigins, OriginsHistory};
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

    /// Run the RTR server.
    Rtrd {
        /// Stay attached to the terminal.
        ///
        /// If this is `true`, we just start the server and keep going. If
        /// this is `false`, we detach from the terminal into daemon mode
        /// which has a few extra consequences.
        attached: bool,
    },

    /// Update the local repository.
    ///
    /// This will also do a validation run in order to discover possible new
    /// publication points.
    Update,

    /// Produce a list of Validated ROA Payload.
    Vrps {
        /// The destination to output the list to.
        ///
        /// If this is some path, then we print the list into that file.
        /// Otherwise we just dump it to stdout.
        output: Option<PathBuf>,

        /// The desired output format.
        format: OutputFormat,

        /// Don’t update the repository.
        noupdate: bool,
    },
}

impl Operation {
    /// Adds the command configuration to a clap app.
    pub fn config_args<'a: 'b, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        app

        // config
        .subcommand(Config::rtrd_args(SubCommand::with_name("config")
            .about("Prints the current config and exits.")
        ))

        // vrps
        .subcommand(SubCommand::with_name("vrps")
            .about("Produces a list of validated ROA payload.")
            .arg(Arg::with_name("output")
                .short("o")
                .long("output")
                .value_name("FILE")
                .help("output file")
                .takes_value(true)
                .default_value("-")
            )
            .arg(Arg::with_name("format")
                .short("f")
                .long("format")
                .value_name("FORMAT")
                .possible_values(&[
                    "csv", "csvext", "json", "openbgpd", "rpsl", "none"
                ])
                .default_value("csv")
                .help("sets the output format")
                .takes_value(true)
            )
            .arg(Arg::with_name("noupdate")
                .short("n")
                .long("noupdate")
                .help("don't update the local cache")
            )
        )

        // update
        .subcommand(SubCommand::with_name("update")
            .about("Updates the local RPKI repository.")
        )

        // rtrd
        .subcommand(Config::rtrd_args(SubCommand::with_name("rtrd")
            .about("Starts the RTR server.")
            .arg(Arg::with_name("attached")
                .short("a")
                .long("attached")
                .help("stay attached to the terminal")
            )
        ))

        // man
        .subcommand(SubCommand::with_name("man")
            .about("Shows the man page")
            .arg(Arg::with_name("output")
                .short("o")
                .long("output")
                .value_name("FILE")
                .help("output file, '-' or not present for stdout")
                .takes_value(true)
            )
        )
    }

    /// Creates a command from clap matches.
    ///
    /// This function prints errors to stderr.
    pub fn from_arg_matches(
        matches: &ArgMatches,
        cur_dir: &Path,
        config: &mut Config
    ) -> Result<Self, Error> {
        Ok(match matches.subcommand() {
            ("config", Some(matches)) => {
                config.apply_rtrd_arg_matches(matches, cur_dir)?;
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
            ("rtrd", Some(matches)) => {
                config.apply_rtrd_arg_matches(matches, cur_dir)?;
                Operation::Rtrd {
                    attached: matches.is_present("attached")
                }
            }
            ("update", _) => Operation::Update,
            ("vrps", Some(matches)) => {
                Operation::Vrps {
                    output: match matches.value_of("output").unwrap() {
                        "-" => None,
                        path => Some(path.into())
                    },
                    format: match matches.value_of("format").unwrap() {
                        "csv" => OutputFormat::Csv,
                        "csvext" => OutputFormat::ExtendedCsv,
                        "json" => OutputFormat::Json,
                        "openbgpd" => OutputFormat::Openbgpd,
                        "rpsl" => OutputFormat::Rpsl,
                        "none" => OutputFormat::None,
                        _ => panic!("unexpected format argument")
                    },
                    noupdate: matches.is_present("noupdate")
                }
            }
            ("", _) => {
                eprintln!(
                    "Error: a command is required.\n\
                     \nCommonly used commands are:\
                     \n   vrps   produces a list of validated ROA payload\
                     \n   rtrd   start the RTR server\
                     \n   man    show the manual page\
                     \n\
                     \nSee routinator -h for a usage summary or\
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
            Operation::Config => 
                Self::print_config(config),
            Operation::Man { output } => {
                match output {
                    Some(output) => Self::output_man(output),
                    None => Self::display_man(),
                }
            }
            Operation::Rtrd { attached }
                => Self::rtrd(config, attached),
            Operation::Update
                => Self::update(config),
            Operation::Vrps { output, format, noupdate } 
                => Self::vrps(config, output, format, noupdate),
        }
    }
}

/// # Running Actual Commands
///
impl Operation {
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
                        eprintln!(
                            "Failed to open output file {}: {}",
                            path.display(), err
                        );
                        return Err(Error)
                    }
                };
                if let Err(err) = file.write_all(MAN_PAGE) {
                    eprintln!("Failed to write to output file: {}", err);
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
                    eprintln!("Failed to write man page: {}", err);
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
            eprintln!(
                "Can't display man page: \
                 Failed to create temporary file: {}.",
                err
            );
            Error
        })?;
        file.write_all(MAN_PAGE).map_err(|err| {
            eprintln!(
                "Can't display man page: \
                Failed to write to temporary file: {}.",
                err
            );
            Error
        })?;
        Command::new("man").arg(file.path()).status().map_err(|err| {
            eprintln!("Failed to run man: {}", err);
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

    /// Starts the RTR server.
    ///
    /// If `attached` is `false`, will fork the server and exit. Otherwise
    /// just runs the server forever.
    fn rtrd(mut config: Config, attached: bool) -> Result<(), Error> {
        let repo = config.create_repository(false, true)?;
        if !attached {
            Self::daemonize(&mut config)?;
        }
        config.switch_logging(!attached)?;

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

        info!("Starting RTR listener...");
        let (notify, rtr) = rtr_listener(history.clone(), &config);
        let monitor = monitor_listener(history.clone(), &config);
        tokio::runtime::run(
            Self::update_future(repo, history, notify, config)
            .map_err(|_| ())
            .select(rtr).map(|_| ()).map_err(|_| ())
            .select(monitor).map(|_| ()).map_err(|_| ())
        );
        Ok(())
    }

    #[cfg(unix)]
    fn daemonize(config: &mut Config) -> Result<(), Error> {
        if let Err(err) = config.daemonize()?.start() {
            eprintln!("Detaching failed: {}", err);
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
        Self::vrps(config, None, OutputFormat::None, false)
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
                format.output(&vrps, &mut file)
            }
            None => {
                let out = io::stdout();
                let mut out = out.lock();
                format.output(&vrps, &mut out)
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
    ) -> impl Future<Item=(), Error=Error> {
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
        )
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

