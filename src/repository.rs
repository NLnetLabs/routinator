//! The complete RPKI repository.
//!
//! # Structure of the Local Copy
//!
//! Such a repository consists of a number of _repository instances_
//! identifier via a unique rsync base URI. All the publication points within
//! that instance have URIs startin with that base URI.
//!
//! As an initial approach to storing a local copy of the repository, we
//! keep a directory structure under a configured base directory. This
//! directory contains another directory names `"repository"`. It will
//! contain a set of directories whose name is the hostname portion of
//! an rsync URI and who mirror the structure of encountered URIs.
//!
//! When updating a repository, we will walk this tree searching for the
//! set of directories that contain more than one entry and whose parents
//! are not part of the set. We construct the rsync URIs from their path
//! and run the `rsync` command to update them.
//!
//! The configured base directory also contains a directory named `"tal"`
//! that contains trust anchor locator files in RFC 7730 format.
//!
//!
//! # Validation
//!
//! The files read during validation are referenced through rsync URIs which
//! will be translated into file system paths in the local copy of the
//! repository. If the indicated file is present it will be used and
//! validated. If it isn’t, the directory the file should be in will be
//! created and validation continue. Once it concludes, if there was at least
//! one missing file, the local copy is updated to fetch the missing files.
//! If this update resulted in any changes to the local copy at all,
//! validatio is repeated. Otherwise, it ends with an error.

use std::io;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use bytes::Bytes;
use super::{ber, rsync};
use super::cert::Cert;
use super::tal::{self, Tal};


//------------ Repository ----------------------------------------------------

#[derive(Clone, Debug)]
pub struct Repository {
    base: PathBuf,
}

impl Repository {
    pub fn new<P: AsRef<Path>>(base: P) -> Self {
        Repository {
            base: base.as_ref().into()
        }
    }

    pub fn base(&self) -> &Path {
        self.base.as_ref()
    }

    pub fn process(&self) -> Result<RouteOrigins, ProcessingError> {
        self.update()?;
        self.run()
    }

    fn update(&self) -> Result<bool, ProcessingError> {
        Ok(false)
    }

    fn run(&self) -> Result<RouteOrigins, ProcessingError> {
        let mut res = RouteOrigin;
        for tal in Tal::read_dir(self.base.join("tal"))? {
            let tal = tal?;
            for uri in tal.uris() {
                match self.load_ta(&uri) {
                    Ok(cert) => {
                        println!("processing {}", uri);
                        if cert.subject_public_key_info() != tal.key_info() {
                            println!("key info doesn’t match");
                            continue;
                        }
                        if let Err(_) = cert.validate_self_signed() {
                            println!("validation failed");
                            continue;
                        }
                        self.process_ca(cert, &mut res)?;
                    }
                    Err(FileError::Encoding(_)) => {
                        // bad trust anchor. ignore.
                    }
                    Err(FileError::Io(err)) => return Err(err.into())
                }
            }
        }
        Ok(())
    }

    fn process_ca(
        &self,
        cert: Cert,
        res: &mut RouteOrigin
    ) -> Result<(), ProcessingError> {
        // get the manifest from the cert.
        // validate the manifest against the cert.
        // load the objects mentioned in the manifest.
        // validate those objects against the cert.
        // drop the cert.
        // process child cas.
        Ok(())
    }
}

impl Repository {
    pub fn load_ta(&self, uri: &rsync::Uri) -> Result<Cert, FileError> {
        Ok(Cert::decode(self.load_file(uri, true)?)?)
    }

    pub fn load_cert(&self, uri: &rsync::Uri) -> Result<Cert, FileError> {
        Ok(Cert::decode(self.load_file(uri, false)?)?)
    }

    fn load_file(
        &self,
        uri: &rsync::Uri,
        create: bool
    ) -> Result<Bytes, FileError> {
        match File::open(self.uri_to_path(uri)) {
            Ok(mut file) => {
                let mut data = Vec::new();
                file.read_to_end(&mut data)?;
                Ok(data.into())
            }
            Err(ref err) if err.kind() == io::ErrorKind::NotFound && create => {
                self.populate_uri_dir(uri)?;
                self.load_file(uri, false)
            }
            Err(err) => Err(err.into())
        }
    }

    fn uri_to_path(&self, uri: &rsync::Uri) -> PathBuf {
        let mut res = self.base.clone();
        res.push("repository");
        if let Some(port) = uri.port() {
            res.push(format!("{}:{}", uri.host(), port))
        }
        else {
            res.push(uri.host())
        }
        res.push(uri.path());
        res
    }

    fn populate_uri_dir(&self, uri: &rsync::Uri) -> Result<(), io::Error> {
        let dir_uri = uri.parent();
        rsync::update(&dir_uri, self.uri_to_path(&dir_uri))
    }
}


//------------ RouteOrigins --------------------------------------------------

pub struct RouteOrigins;


//------------ ProcessingError -----------------------------------------------

#[derive(Debug)]
pub enum ProcessingError {
    Io(io::Error),
    Tal(tal::ReadError),
}

impl From<io::Error> for ProcessingError {
    fn from(err: io::Error) -> ProcessingError {
        ProcessingError::Io(err)
    }
}

impl From<tal::ReadError> for ProcessingError {
    fn from(err: tal::ReadError) -> ProcessingError {
        ProcessingError::Tal(err)
    }
}


//------------ FileError -----------------------------------------------------

#[derive(Debug)]
pub enum FileError {
    Io(io::Error),
    Encoding(ber::Error),
}

impl From<io::Error> for FileError {
    fn from(err: io::Error) -> FileError {
        FileError::Io(err)
    }
}

impl From<ber::Error> for FileError {
    fn from(err: ber::Error) -> FileError {
        FileError::Encoding(err)
    }
}

