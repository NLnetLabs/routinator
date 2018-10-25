extern crate chrono;
extern crate daemonize;
extern crate env_logger;
extern crate futures;
#[macro_use] extern crate lazy_static;
#[macro_use] extern crate log;
extern crate routinator;
extern crate rpki;
extern crate tokio;

use std::{io, process};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::time::Instant;
use chrono::Utc;
use futures::future;
use futures::future::Future;
use tokio::timer::Delay;
use routinator::config::{Config, OutputFormat};
use routinator::repository::{ProcessingError, Repository};
use routinator::origins::{AddressOrigins, OriginsHistory};
use routinator::rtr::{rtr_listener, NotifySender};
use routinator::slurm::LocalExceptions;

lazy_static! {
    static ref CONFIG: Config = Config::create();
}

fn main() {
    let config = &CONFIG;

    env_logger::Builder::new()
        .filter_level(config.verbose)
        .format(|buf, record| write!(buf, "{}\n", record.args()))
        .init();

    let res = if config.mode.is_once() {
        run_once(config)
    }
    else {
        run_forever(config)
    };

    if let Err(err) = res {
        println!("{}\nAborted.", err);
    }
}


fn run_forever(config: &Config) -> Result<(), ProcessingError> {
    if !config.update {
        warn!("no-update option ignored in repeat mode");
    }
    if !config.process {
        warn!("no-process option ignored in repeat mode");
    }

    if config.mode.is_daemon() {
        if let Err(err) = daemonize::Daemonize::new().start() {
            println!("Daemonization failed: {}", err);
            process::exit(1);
        }
    }

    let repo = Repository::new(
        config.cache_dir.clone(), config.tal_dir.clone(), config.strict, true
    )?;

    // Start out with validation so that we only fire up our sockets once we
    // are actually ready.
    if let Err(_) = repo.update() {
        warn!("Update failed. Continuing anyway.");
    }
    let history = OriginsHistory::new(
        AddressOrigins::from_route_origins(
            repo.process()?,
            &load_exceptions(&config)?
        ),
        config.history_size
    );

    info!("Starting RTR listener...");
    
    let (notify, rtr) = rtr_listener(history.clone(), &CONFIG);

    tokio::runtime::run(
        update_future(repo, history, notify)
        .select(rtr).map(|_| ()).map_err(|_| ())
    );

    Ok(())
}


fn update_future(
    repo: Repository,
    history: OriginsHistory,
    notify: NotifySender,
) -> impl Future<Item=(), Error=()> {
    future::loop_fn((repo, history, notify), |(repo, history, mut notify)| {
        Delay::new(Instant::now() + CONFIG.refresh)
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
                            future::Loop::Continue((repo, history, notify))
                        )
                    }
                };
                let must_notify = match load_exceptions(&CONFIG) {
                    Ok(exceptions) => {
                        history.update(Some(origins), &exceptions)
                    }
                    Err(err) => {
                        error!("failed loading exceptions: {}", err);
                        false
                    }
                };
                debug!("New serial is {}.", history.serial());
                if must_notify {
                    debug!("Sending out notifications.");
                    notify.notify();
                }
                Ok(future::Loop::Continue((repo, history, notify)))
            })
        })
    })
}


fn run_once(config: &Config) -> Result<(), ProcessingError> {
    let exceptions = load_exceptions(&config)?;

    let repo = Repository::new(
        config.cache_dir.clone(), config.tal_dir.clone(), config.strict,
        config.update
    )?;
    if let Err(_) = repo.update() {
        warn!("Update failed. Continuing anyway.");
    }

    if !config.process {
        return Ok(())
    }
    let roas = match repo.process() {
        Ok(res) => res,
        Err(err) => {
            error!("Fatal error during validation. Aborted.");
            return Err(err)
        }
    };
    debug!("Found {} ROAs.", roas.len());

    let roas = AddressOrigins::from_route_origins(roas, &exceptions);

    output(&roas, &config)
}


fn load_exceptions(
    config: &Config
) -> Result<LocalExceptions, ProcessingError> {
    match config.exceptions {
        Some(ref path) => match LocalExceptions::from_file(path) {
            Ok(res) => Ok(res),
            Err(err) => {
                error!("Failed to load exceptions: {}\nAborted.", err);
                Err(ProcessingError::Other)
            }
        }
        None => Ok(LocalExceptions::empty())
    }
}


fn output(
    roas: &AddressOrigins,
    config: &Config
) -> Result<(), ProcessingError> {
    let output = FileOrStdout::open(config.output.as_ref())?;
    let mut output = output.lock();
    match config.outform {
        OutputFormat::Csv => output_csv(roas, &mut output),
        OutputFormat::Json => output_json(roas, &mut output),
        OutputFormat::Rpsl => output_rpsl(roas, &mut output),
        OutputFormat::None => { Ok(()) }
    }
}


fn output_csv<W: io::Write>(
    roas: &AddressOrigins,
    output: &mut W
) -> Result<(), ProcessingError> {
    writeln!(output, "ASN,IP Prefix,Max Length")?;
    for addr in roas.iter() {
        writeln!(output, "{},{}/{},{}",
            addr.as_id(),
            addr.address(), addr.address_length(),
            addr.max_length()
        )?;
    }
    Ok(())
}

fn output_json<W: io::Write>(
    roas: &AddressOrigins,
    output: &mut W
) -> Result<(), ProcessingError> {
    let mut first = true;
    writeln!(output, "{{\n  \"roas\": [")?;
    for addr in roas.iter() {
        if first {
            first = false
        }
        else {
            write!(output, ",\n")?;
        }
        write!(output,
            "    {{ \"asn\": \"{}\", \"prefix\": \"{}/{}\", \
            \"maxLength\": {} }}",
            addr.as_id(),
            addr.address(), addr.address_length(),
            addr.max_length()
        )?;
    }
    writeln!(output, "\n  ]\n}}")?;
    Ok(())
}

fn output_rpsl<W: io::Write>(
    roas: &AddressOrigins,
    output: &mut W
) -> Result<(), ProcessingError> {
    let now = Utc::now().to_rfc3339();
    for addr in roas.iter() {
        writeln!(output,
            "\r\nroute: {}/{}\r\norigin: {}\r\n\
            descr: RPKI attestation\r\nmnt-by: NA\r\ncreated: {}\r\n\
            last-modified: {}\r\nsource: NA\r\n",
            addr.address(), addr.address_length(),
            addr.as_id(), now, now
        )?;
    }
    Ok(())
}


pub enum FileOrStdout<F, S> {
    File(F),
    Stdout(S)
}

impl FileOrStdout<File, io::Stdout> {
    fn open<P: AsRef<Path>>(path: Option<P>) -> Result<Self, io::Error> {
        match path {
            Some(path) => File::create(path).map(FileOrStdout::File),
            None => Ok(FileOrStdout::Stdout(io::stdout())),
        }
    }

    fn lock(&self) -> FileOrStdout<&File, io::StdoutLock> {
        match *self {
            FileOrStdout::File(ref file) => FileOrStdout::File(file),
            FileOrStdout::Stdout(ref s) => FileOrStdout::Stdout(s.lock())
        }
    }
}

impl<'a> io::Write for FileOrStdout<&'a File, io::StdoutLock<'a>> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        match *self {
            FileOrStdout::File(ref mut file) => file.write(buf),
            FileOrStdout::Stdout(ref mut lock) => lock.write(buf),
        }
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        match *self {
            FileOrStdout::File(ref mut file) => file.flush(),
            FileOrStdout::Stdout(ref mut lock) => lock.flush(),
        }
    }
}

