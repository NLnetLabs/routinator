extern crate chrono;
#[macro_use] extern crate clap;
extern crate env_logger;
#[macro_use] extern crate log;
extern crate routinator;
extern crate rpki;

use std::io;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use chrono::Utc;
use clap::{Arg, App};
use routinator::repository::{ProcessingError, Repository};
use routinator::origins::AddressOrigins;
use routinator::slurm::LocalExceptions;

fn main() -> Result<(), ProcessingError> {
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
        .arg(Arg::with_name("exceptions")
             .short("x")
             .long("exceptions")
             .value_name("FILE")
             .help("file with local exceptions (see RFC 8416 for format)")
             .takes_value(true)
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
             .help("sets the output format (csv, json, rpsl, none)")
             .takes_value(true)
        )
        .arg(Arg::with_name("unique")
             .short("u")
             .long("unique")
             .help("output unique value only")
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
        .get_matches();


    env_logger::Builder::new()
        .filter_level(match matches.occurrences_of("verbose") {
            0 => log::LevelFilter::Error,
            1 => log::LevelFilter::Info,
            _ => log::LevelFilter::Debug,
        })
        .format(|buf, record| write!(buf, "{}\n", record.args()))
        .init();

    let exceptions = match matches.value_of("exceptions") {
        Some(path) => match LocalExceptions::from_file(path) {
            Ok(res) => res,
            Err(err) => {
                println!("Failed to load exceptions: {}\nAborted.", err);
                ::std::process::exit(1);
            }
        }
        None => LocalExceptions::empty()
    };

    let repo = Repository::new(
        Path::new(matches.value_of("cache").unwrap_or("rpki-cache")),
        matches.is_present("strict"),
        !matches.is_present("noupdate")
    )?;
    if let Err(_) = repo.update() {
        warn!("Update failed. Continuing anyway.");
    }

    if matches.is_present("noprocess") {
        ::std::process::exit(0);
    }
    let roas = match repo.process() {
        Ok(res) => res,
        Err(err) => {
            println!("Fatal error during validation. Aborted.");
            return Err(err)
        }
    };
    debug!("Found {} ROAs.", roas.len());

    let outform = matches.value_of("outform").unwrap_or("csv");
    if outform == "none" {
        Ok(())
    }
    else {
        let output = FileOrStdout::open(
            matches.value_of("output").unwrap_or("-")
        )?;
        let mut output = output.lock();
        let roas = AddressOrigins::from_route_origins(
            roas,
            &exceptions,
            matches.is_present("unique")
        );

        match matches.value_of("outform").unwrap_or("csv") {
            "csv" => output_csv(roas, &mut output),
            "json" => output_json(roas, &mut output),
            "rpsl" => output_rpsl(roas, &mut output),
            other => {
                error!("unknown output format {}", other);
                Err(ProcessingError::Other)
            }
        }
    }
}


fn output_csv<W: io::Write>(
    roas: AddressOrigins,
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
    roas: AddressOrigins,
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
    roas: AddressOrigins,
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
    fn open(path: &str) -> Result<Self, io::Error> {
        match path {
            "-" => Ok(FileOrStdout::Stdout(io::stdout())),
            path => File::create(Path::new(path)).map(FileOrStdout::File)
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

