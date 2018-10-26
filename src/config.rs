//! Configuration.

use std::{env, fs, process};
use std::io::Write;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
use clap::{App, Arg, ArgMatches};
use dirs::home_dir;
use log::LevelFilter;


//------------ Config --------------------------------------------------------

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
        // Remember to update the man page if you change things here!
        let matches = App::new("Routinator")
            .version("0.1")

            .author(crate_authors!())
            .about("validates RPKI route origin attestations")
            .arg(Arg::with_name("basedir")
                 .short("b")
                 .long("base-dir")
                 .value_name("DIR")
                 .help("sets the base directory for cache and TALs")
                 .takes_value(true)
            )
            .arg(Arg::with_name("cachedir")
                 .short("c")
                 .long("cache-dir")
                 .value_name("DIR")
                 .help("sets the cache directory")
                 .takes_value(true)
            )
            .arg(Arg::with_name("taldir")
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
            )
            .arg(Arg::with_name("daemon")
                 .short("d")
                 .long("daemon")
                 .help("run in daemon mode (detach from terminal)")
            )
            .arg(Arg::with_name("repeat")
                 .short("r")
                 .long("repeat")
                 .help("repeatedly run validation")
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
            .arg(Arg::with_name("listen")
                 .short("l")
                 .long("listen")
                 .value_name("ADDR:PORT")
                 .help("listen addr:port for RTR.")
                 .takes_value(true)
                 .multiple(true)
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
            .arg(Arg::with_name("strict")
                 .long("strict")
                 .help("parse RPKI data in strict mode")
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
            .arg(Arg::with_name("verbose")
                 .short("v")
                 .long("verbose")
                 .multiple(true)
                 .help("print more (and more) information")
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

        let listen = match matches.values_of("listen") {
            Some(values) => {
                let mut listen = Vec::new();
                for val in values {
                    match val.to_socket_addrs() {
                        Ok(some) => listen.extend(some),
                        Err(_) => {
                            println!("Invalid socket address {}", val);
                            process::exit(1);
                        }
                    }
                }
                listen
            }
            None => {
                "127.0.0.1:3323".to_socket_addrs().unwrap().collect()
            }
        };

        let (cache_dir, tal_dir) = Self::prepare_dirs(&matches, &cur_dir);

        Config {
            cache_dir,
            tal_dir,
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
            rtr_listen: listen,
        }
    }

    /// Prepares and returns the cache dir and tal dir.
    fn prepare_dirs(
        matches: &ArgMatches,
        cur_dir: &Path
    ) -> (PathBuf, PathBuf) {
        let base_dir = match matches.value_of("basedir") {
            Some(dir) => Some(cur_dir.join(dir)),
            None => match home_dir() {
                Some(dir) => Some(dir.join(".rpki-cache")),
                None => None,
            }
        };
        let cache_dir = match matches.value_of("cachedir") {
            Some(dir) => cur_dir.join(dir),
            None => match base_dir {
                Some(ref dir) => dir.join("repository"),
                None => {
                    println!("Can't determine default working directory. \
                              Please use the -b option.\nAborting.");
                    process::exit(1)
                }
            }
        };
        let tal_dir = match matches.value_of("taldir") {
            Some(dir) => cur_dir.join(dir),
            None => match base_dir {
                Some(ref dir) => dir.join("tals"),
                None => {
                    println!("Can't determine default working directory. \
                              Please use the -b option.\nAborting.");
                    process::exit(1)
                }
            }
        };

        if let Err(err) = fs::create_dir_all(&cache_dir) {
            println!(
                "Can't create repository directory {}: {}.\nAborting.",
                cache_dir.display(), err
            );
            process::exit(1);
        }
        if fs::read_dir(&tal_dir).is_err() {
            if let Err(err) = fs::create_dir_all(&tal_dir) {
                println!(
                    "Can't create TAL directory {}: {}.\nAborting.",
                    tal_dir.display(), err
                );
                process::exit(1);
            }
            for (name, content) in &DEFAULT_TALS {
                let mut file = match fs::File::create(tal_dir.join(name)) {
                    Ok(file) => file,
                    Err(err) => {
                        println!(
                            "Can't create TAL file {}: {}.\n Aborting.",
                            tal_dir.join(name).display(), err
                        );
                        process::exit(1);
                    }
                };
                if let Err(err) = file.write_all(content) {
                    println!(
                        "Can't create TAL file {}: {}.\n Aborting.",
                        tal_dir.join(name).display(), err
                    );
                    process::exit(1);
                }
            }
        }

        (cache_dir, tal_dir)
    }
}


//------------ RunMode -------------------------------------------------------

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

    pub fn is_daemon(self) -> bool {
        self == RunMode::Daemon
    }
}


//------------ OutputFormat --------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub enum OutputFormat {
    Csv,
    Json,
    Rpsl,
    None,
}


//------------ DEFAULT_TALS --------------------------------------------------

const DEFAULT_TALS: [(&str, &[u8]); 5] = [
    ("afrinic.tal", include_bytes!("../tals/afrinic.tal")),
    ("apnic.tal", include_bytes!("../tals/apnic.tal")),
    ("arin.tal", include_bytes!("../tals/arin.tal")),
    ("lacnic.tal", include_bytes!("../tals/lacnic.tal")),
    ("ripe.tal", include_bytes!("../tals/ripe.tal")),
];

