//! Configuration.

use std::{env, process};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;
use clap::{App, Arg};
use log::LevelFilter;


/// Routinator configuration.
#[derive(Clone, Debug)]
pub struct Config {
    /// Path to the directory that contains the repository cache.
    pub cache_dir: PathBuf,

    /// Path to the directory that contains the trust anchor locators.
    pub tal_dir: PathBuf,

    /// Path to the optional local exceptions file.
    pub exceptions: Option<PathBuf>,

    /// Expected mode of operation.
    pub mode: RunMode,

    /// Path to the output file.
    ///
    /// If this is `None`, we are supposed to output to stdout. 
    pub output: Option<PathBuf>,

    /// Format for output to a file.
    pub outform: OutputFormat,

    /// Should we do strict validation?
    pub strict: bool,

    /// Should we update the repository cache?
    pub update: bool,

    /// Should we process the repository?
    pub process: bool,

    /// The log level filter for setting up logging.
    pub verbose: LevelFilter,

    /// The refresh interval for repository validation.
    pub refresh: Duration,

    pub retry: Duration,

    pub expire: Duration,

    /// How many diffs to keep in the history.
    pub history_size: usize,

    /// Addresses to listen for RTR connections on.
    pub rtr_listen: Vec<SocketAddr>,
}

impl Config {
    pub fn create() -> Self {
        // Remember to update the man page if you change this here!
        let matches = App::new("Routinator")
            .version("0.1")

            .author(crate_authors!())
            .about("validates RPKI route origin attestations")
            .arg(Arg::with_name("cache")
                 .short("c")
                 .long("cache")
                 .value_name("DIR")
                 .help("sets the cache directory")
                 .takes_value(true)
            )
            .arg(Arg::with_name("tal")
                 .short("t")
                 .long("tal")
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
            )
            .arg(Arg::with_name("repeat")
                 .short("r")
                 .long("repeat")
                 .help("repeatedly run validation")
            )
            .arg(Arg::with_name("daemon")
                 .short("d")
                 .long("daemon")
                 .help("run in daemon mode (detach from terminal)")
            )
            .arg(Arg::with_name("output")
                 .short("o")
                 .long("output")
                 .value_name("FILE")
                 .help("output file, '-' or not present for stdout")
                 .takes_value(true)
            )
            .arg(Arg::with_name("outform")
                 .short("f")
                 .long("outform")
                 .value_name("FORMAT")
                 .possible_values(&["csv", "json", "rpsl", "none"])
                 //.help("sets the output format (csv, json, rpsl, none)")
                 .help("sets the output format")
                 .takes_value(true)
            )
            .arg(Arg::with_name("strict")
                 .long("strict")
                 .help("parse RPKI data in strict mode")
            )
            .arg(Arg::with_name("noupdate")
                 .short("n")
                 .long("noupdate")
                 .help("don't update local cache")
            )
            .arg(Arg::with_name("noprocess")
                 .short("N")
                 .long("noprocess")
                 .help("don't process the repository")
            )
            .arg(Arg::with_name("verbose")
                 .short("v")
                 .long("verbose")
                 .multiple(true)
                 .help("print more (and more) information")
            )
            .arg(Arg::with_name("refresh")
                 .long("refresh")
                 .value_name("SECONDS")
                 .default_value("3600")
                 .help("refresh interval in seconds")
            )
            .arg(Arg::with_name("history_size")
                 .long("history")
                 .value_name("COUNT")
                 .default_value("10")
                 .help("number of history items to keep in repeat mode")
            )
            .get_matches();

        let cur_dir = match env::current_dir() {
            Ok(dir) => dir,
            Err(err) => {
                println!(
                    "Fatal: cannot get current directory ({}). Aborting.",
                    err
                );
                process::exit(1);
            }
        };

        Config {
            cache_dir: cur_dir.join(
                matches.value_of("cache").unwrap_or("rpki-cache/repository")
            ),
            tal_dir: cur_dir.join(
                matches.value_of("tal").unwrap_or("rpki-cache/tal")
            ),
            exceptions: matches.value_of("exceptions").map(|path| {
                cur_dir.join(path)
            }),
            mode: if matches.is_present("daemon") {
                RunMode::Daemon
            }
            else if matches.is_present("repeat") {
                RunMode::Repeat
            }
            else {
                RunMode::Once
            },
            output: match matches.value_of("output") {
                None | Some("-") => None,
                Some(path) => Some(cur_dir.join(path)),
            },
            outform: match matches.value_of("outform") {
                Some("csv") => OutputFormat::Csv,
                Some("json") => OutputFormat::Json,
                Some("rpsl") => OutputFormat::Rpsl,
                Some("none") => OutputFormat::None,
                Some(_) => {
                    // This should be covered by clap above.
                    unreachable!();
                }
                None => OutputFormat::None,
            },
            strict: matches.is_present("strict"),
            update: !matches.is_present("noupdate"),
            process: !matches.is_present("noprocess"),
            verbose: match matches.occurrences_of("verbose") {
                0 => LevelFilter::Error,
                1 => LevelFilter::Info,
                _ => LevelFilter::Debug,
            },
            refresh: {
                let value = matches.value_of("refresh").unwrap();
                match u64::from_str(value) {
                    Ok(some) => Duration::from_secs(some),
                    Err(_) => {
                        error!(
                            "Invalid value '{}' for refresh argument.\
                             Needs to be number of seconds.",
                            value
                        );
                        process::exit(1);
                    }
                }
            },
            retry: Duration::from_secs(600),
            expire: Duration::from_secs(7200),
            history_size: {
                let value = matches.value_of("refresh").unwrap();
                match usize::from_str(value) {
                    Ok(some) => some,
                    Err(_) => {
                        error!(
                            "Invalid value '{}' for refresh argument.\
                             Needs to be number of seconds.",
                            value
                        );
                        process::exit(1);
                    }
                }
            },
            rtr_listen: {
                use std::net::ToSocketAddrs;

                "127.0.0.1:3323".to_socket_addrs().unwrap().collect()
            }
        }
    }

    pub fn touch(&self) { }
}


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunMode {
    Once,
    Repeat,
    Daemon,
}

impl RunMode {
    pub fn is_once(self) -> bool {
        self == RunMode::Once
    }
}


#[derive(Clone, Copy, Debug)]
pub enum OutputFormat {
    Csv,
    Json,
    Rpsl,
    None,
}

