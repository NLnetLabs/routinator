//! What Routinator can do for you.
//!
//! This module contains all the commands you can give to the executable.

use std::{fs, io};
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;
use chrono::Utc;
use clap::{App, Arg, ArgMatches, SubCommand};
use futures::future;
use futures::future::Future;
use tempfile::NamedTempFile;
use tokio::timer::Delay;
use crate::config::Config;
use crate::origins::{AddressOrigins, OriginsHistory};
use crate::repository::Repository;
use crate::rtr::{rtr_listener, NotifySender};


//------------ Orders --------------------------------------------------------

/// Routinator’s orders.
///
/// This type combines the config and the command in one convenient package
/// for use with `lazy_static!`.
pub struct Orders {
    config: Config,
    operation: Operation,
}

impl Orders {
    pub fn from_args<'a: 'b, 'b>(app: App<'a, 'b>) -> Result<Self, Error> {
        let matches = Operation::config_args(
            Config::config_args(app)
        ).get_matches();
        Ok(Orders {
            config: Config::from_arg_matches(&matches),
            operation: Operation::from_arg_matches(&matches)
        })
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn operation(&self) -> &Operation {
        &self.operation
    }

    pub fn run(self) -> Result<(), Error> {
        self.operation.run(self.config)
    }
}


//------------ Operation -----------------------------------------------------

/// The command to run.
pub enum Operation {
    Man,
    Update,
    Vrps {
        output: Option<PathBuf>,
        format: OutputFormat,
        noupdate: bool,
    },
    Rtrd {
        attached: bool,
    }
}

impl Operation {
    /// Adds the command configuration to a clap app.
    pub fn config_args<'a: 'b, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
        app

        // vrps
        .subcommand(SubCommand::with_name("vrps")
            .about("Produces a list of valid ROA prefixes.")
            .arg(Arg::with_name("output")
                .short("o")
                .long("output")
                .value_name("FILE")
                .help("output file, '-' or not present for stdout")
                .default_value("-")
                .takes_value(true)
            )
            .arg(Arg::with_name("format")
                .short("f")
                .long("format")
                .value_name("FORMAT")
                .possible_values(&[
                    "csv", "json", "openbgpd", "rpsl", "none"
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
        .subcommand(SubCommand::with_name("rtrd")
            .about("Starts the RTR server.")
            .arg(Arg::with_name("attached")
                .short("a")
                .long("attached")
                .help("stay attached to the terminal")
            )
        )

        // man
        .subcommand(SubCommand::with_name("man")
            .about("Shows the man page")
        )
    }

    /// Creates a command from clap matches.
    pub fn from_arg_matches(matches: &ArgMatches) -> Self {
        match matches.subcommand() {
            ("man", _) => Operation::Man,
            ("rtrd", Some(matches)) => {
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
                        "json" => OutputFormat::Json,
                        "openbgpd" => OutputFormat::Openbgpd,
                        "rpsl" => OutputFormat::Rpsl,
                        "none" => OutputFormat::None,
                        _ => panic!("unexpected format argument")
                    },
                    noupdate: matches.is_present("noupdate")
                }
            }
            _ => panic!("Unexpected subcommand."),
        }
    }

    pub fn run(self, config: Config) -> Result<(), Error> {
        match self {
            Operation::Man
                => Self::man(),
            Operation::Rtrd { attached }
                => Self::rtrd(config, attached),
            Operation::Update
                => Self::update(config),
            Operation::Vrps { output, format, noupdate } 
                => Self::vrps(config, output, format, noupdate),
        }
    }

    fn man() -> Result<(), Error> {
        let mut file = NamedTempFile::new().map_err(|err| {
            println!(
                "Can't display man page: \
                 Failed to create temporary file: {}.",
                err
            );
            Error
        })?;
        file.write_all(MAN_PAGE).map_err(|err| {
            println!(
                "Can't display man page: \
                Failed to write to temporary file: {}.",
                err
            );
            Error
        })?;
        Command::new("man").arg(file.path()).status().map_err(|err| {
            println!("Failed to run man: {}", err);
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

    fn rtrd(config: Config, attached: bool) -> Result<(), Error> {
        let repo = config.create_repository(true)?;

        if !attached {
            if let Err(err) = daemonize::Daemonize::new().start() {
                println!("Detaching failed: {}", err);
                return Err(Error)
            }
        }
        config.switch_logging(!attached)?;


        // Start out with validation so that we only fire up our sockets
        // once we are actually ready.
        if let Err(_) = repo.update() {
            warn!("Update failed. Continuing anyway.");
        }
        let roas = match repo.process() {
            Ok(roas) => roas,
            Err(err) => {
                error!("Fatal: Validation failed: {}", err);
                error!("Aborting.");
                return Err(Error)
            }
        };
        let history = OriginsHistory::new(
            AddressOrigins::from_route_origins(
                roas, &config.load_exceptions()?
            ),
            config.history_size
        );

        info!("Starting RTR listener...");
        let (notify, rtr) = rtr_listener(history.clone(), &config);
        tokio::runtime::run(
            update_future(repo, history, notify, config)
            .select(rtr).map(|_| ()).map_err(|_| ())
        );
        Ok(())
    }

    fn update(config: Config) -> Result<(), Error> {
        let repo = config.create_repository(true)?;
        repo.update().map_err(|err| {
            println!("Updating the repository has failed: {}", err);
            Error
        })
    }

    fn vrps(
        config: Config,
        output: Option<PathBuf>,
        format: OutputFormat,
        noupdate: bool
    ) -> Result<(), Error> {
        let repo = config.create_repository(!noupdate)?;
        let exceptions = config.load_exceptions()?;
        config.switch_logging(false)?;

        if let Err(_) = repo.update() {
            println!("Update failed. Continuing anyway.");
        }
        let roas = match repo.process() {
            Ok(roas) => roas,
            Err(err) => {
                error!("Validation failed: {}", err);
                return Err(Error)
            }
        };
        debug!("Found {} ROAs.", roas.len());
        let vrps = AddressOrigins::from_route_origins(roas, &exceptions);
        match output {
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
        }
    }
}


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
            .map_err(|e| error!("timer failed; err={:?}", e))
            .and_then(move |_| {
                repo.start();
                Ok(repo)
            })
            .and_then(|repo| {
                repo.update_async()
                .then(|res| {
                    // Print error but keep going.
                    if let Err(err) = res {
                        error!("repository update failed: {}", err);
                    }
                    Ok(repo)
                })
            })
            .and_then(|repo| {
                repo.process_async()
                .then(move |origins| {
                    let origins = match origins {
                        Ok(origins) => origins,
                        Err(err) => {
                            error!("repository processing failed; err={:?}", err);
                            return Ok(
                                future::Loop::Continue(
                                    (repo, history, notify, config)
                                )
                            )
                        }
                    };
                    let must_notify = match config.load_exceptions() {
                        Ok(exceptions) => {
                            history.update(Some(origins), &exceptions)
                        }
                        Err(_) => {
                            false
                        }
                    };
                    debug!("New serial is {}.", history.serial());
                    if must_notify {
                        debug!("Sending out notifications.");
                        notify.notify();
                    }
                    Ok(future::Loop::Continue((repo, history, notify, config)))
                })
            })
        }
    )
}

//------------ OutputFormat --------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub enum OutputFormat {
    Csv,
    Json,
    Openbgpd,
    Rpsl,
    None,
}

impl OutputFormat {
    fn output<W: io::Write>(
        self,
        vrps: &AddressOrigins,
        target: &mut W,
    ) -> Result<(), Error> {
        let res = match self {
            OutputFormat::Csv => Self::output_csv(vrps, target),
            OutputFormat::Json => Self::output_json(vrps, target),
            OutputFormat::Openbgpd => Self::output_openbgpd(vrps, target),
            OutputFormat::Rpsl => Self::output_rpsl(vrps, target),
            OutputFormat::None => Ok(())
        };
        if let Err(err) = res {
            error!(
                "Failed to output result: {}",
                err
            );
            Err(Error)
        }
        else {
            Ok(())
        }
    }

    fn output_csv<W: io::Write>(
        vrps: &AddressOrigins,
        output: &mut W,
    ) -> Result<(), io::Error> {
        writeln!(output, "ASN,IP Prefix,Max Length,Trust Anchor")?;
        for addr in vrps.iter() {
            writeln!(output, "{},{}/{},{},{}",
                addr.as_id(),
                addr.address(), addr.address_length(),
                addr.max_length(),
                addr.tal_name(),
            )?;
        }
        Ok(())
    }

    fn output_json<W: io::Write>(
        vrps: &AddressOrigins,
        output: &mut W,
    ) -> Result<(), io::Error> {
        let mut first = true;
        writeln!(output, "{{\n  \"roas\": [")?;
        for addr in vrps.iter() {
            if first {
                first = false
            }
            else {
                write!(output, ",\n")?;
            }
            write!(output,
                "    {{ \"asn\": \"{}\", \"prefix\": \"{}/{}\", \
                \"maxLength\": {}, \"ta\": \"{}\" }}",
                addr.as_id(),
                addr.address(), addr.address_length(),
                addr.max_length(),
                addr.tal_name(),
            )?;
        }
        writeln!(output, "\n  ]\n}}")?;
        Ok(())
    }

    fn output_openbgpd<W: io::Write>(
        vrps: &AddressOrigins,
        output: &mut W,
    ) -> Result<(), io::Error> {
        writeln!(output, "roa-set {{")?;
        for addr in vrps.iter() {
            write!(output, "    {}/{}",
                addr.address(), addr.address_length(),
            )?;
            if addr.address_length() < addr.max_length() {
                write!(output, " maxlen {}",
                    addr.max_length(),
                )?;
            }
            writeln!(output, " source-as {}",
                u32::from(addr.as_id()),
            )?;
        }
        writeln!(output, "}}")?;
        Ok(())
    }

    fn output_rpsl<W: io::Write>(
        vrps: &AddressOrigins,
        output: &mut W,
    ) -> Result<(), io::Error> {
        let now = Utc::now().to_rfc3339();
        let mut source = RpslSource::default();
        for addr in vrps.iter() {
            writeln!(output,
                "\r\nroute: {}/{}\r\norigin: {}\r\n\
                descr: RPKI attestation\r\nmnt-by: NA\r\ncreated: {}\r\n\
                last-modified: {}\r\nsource: {}\r\n",
                addr.address(), addr.address_length(),
                addr.as_id(), now, now, source.display(addr.tal_name())
            )?;
        }
        Ok(())
    }
}


//------------ Error ---------------------------------------------------------

/// An error has occurred during operation.
///
/// This is really just a placeholder type. All necessary output has happend
/// already.
#[derive(Clone, Copy, Debug)]
pub struct Error;


//------------ RpslSource ----------------------------------------------------

#[derive(Default)]
struct RpslSource(HashMap<String, String>);

impl RpslSource {
    fn display(&mut self, tal: &str) -> &str {
        if self.0.contains_key(tal) {
            // This is double lookup is necessary for the borrow checker ...
            self.0.get(tal).unwrap()
        }
        else {
            self.0.entry(tal.to_string())
                .or_insert(format!("ROA-{}-RPKI-ROOT", tal.to_uppercase()))
        }
    }
}


//------------ The Man Page --------------------------------------------------

const MAN_PAGE: &[u8] = include_bytes!("../doc/routinator.1");

