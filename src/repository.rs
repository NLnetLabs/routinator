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
use super::cert::{Cert, ResourceCert};
use super::crl::{Crl, CrlStore};
use super::manifest::{Manifest, ManifestContent, ManifestHash};
use super::roa::{Roa, RouteOrigins};
use super::tal::{self, Tal};
use super::x509::ValidationError;


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
        let mut res = RouteOrigins::new();
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
                        let cert = match cert.validate_ta() {
                            Ok(cert) => cert,
                            Err(_) => {
                                println!("validation failed");
                                continue;
                            }
                        };
                        self.process_ca(cert, &mut res)?;
                        // We stop once we have had the first working URI.
                        break;
                    }
                    Err(FileError::Encoding(_)) => {
                        // bad trust anchor. ignore.
                    }
                    Err(FileError::Io(err)) => return Err(err.into())
                }
            }
        }
        Ok(res)
    }

    fn process_ca(
        &self,
        cert: ResourceCert,
        routes: &mut RouteOrigins
    ) -> Result<(), ProcessingError> {
        let mut store = CrlStore::new();

        let repo_uri = match cert.repository_uri() {
            Some(uri) => uri,
            None => return Ok(())
        };
        let manifest = match self.get_manifest(&cert, &mut store)? {
            Some(manifest) => manifest,
            None => return Ok(())
        };

        for item in manifest.iter_uris(repo_uri) {
            let (uri, hash) = match item {
                Ok(item) => item,
                Err(_) => continue,
            };

            self.process_object(uri, hash, &cert, routes)?;
        }
        Ok(())
    }

    fn process_object(
        &self,
        uri: rsync::Uri,
        hash: ManifestHash,
        issuer: &ResourceCert,
        routes: &mut RouteOrigins,
    ) -> Result<(), ProcessingError> {
        // XXX We should have the directory already from the fetching the
        //     manifest. So we should be fine calling load_file without
        //     request for file creation.
        if uri.ends_with(".cer") {
            let bytes = match self.load_file(&uri, false) {
                Ok(bytes) => bytes,
                Err(_) => return Ok(())
            };
            if let Err(_) = hash.verify(&bytes) {
                return Ok(())
            }
            let cert = match Cert::decode(bytes) {
                Ok(cert) => cert,
                Err(_) => return Ok(())
            };
            let cert = match cert.validate_ca(issuer) {
                Ok(cert) => cert,
                Err(_) => return Ok(())
            };
            self.process_ca(cert, routes)
        }
        else if uri.ends_with(".roa") {
            let bytes = match self.load_file(&uri, false) {
                Ok(bytes) => bytes,
                Err(_) => return Ok(())
            };
            if let Err(_) = hash.verify(&bytes) {
                return Ok(())
            }
            let roa = match Roa::decode(bytes) {
                Ok(roa) => roa,
                Err(_) => {
                    debug!("Decoding failed for {}", uri);
                    return Ok(())
                }
            };
            let _ = roa.process(issuer, routes);
            Ok(())
        }
        else if uri.ends_with(".crl") {
            Ok(())
        }
        else {
            warn!("skipping unknown file {}", uri);
            Ok(())
        }
    }

    fn get_manifest(
        &self,
        issuer: &ResourceCert,
        store: &mut CrlStore,
    ) -> Result<Option<ManifestContent>, ProcessingError> {
        for uri in issuer.manifest_uris() {
            let uri = match uri.into_rsync_uri() {
                Some(uri) => uri,
                None => continue,
            };
            let bytes = match self.load_file(&uri, true) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };
            let manifest = match Manifest::decode(bytes) {
                Ok(manifest) => manifest,
                Err(_) => continue,
            };
            let (cert, manifest) = match manifest.validate(issuer) {
                Ok(manifest) => manifest,
                Err(_) => continue,
            };
            if let Err(_) = self.check_crl(cert, issuer, store) {
                continue
            }
            return Ok(Some(manifest))
        }
        Ok(None)
    }

    fn check_crl<C: AsRef<Cert>>(
        &self,
        cert: C,
        issuer: &ResourceCert,
        store: &mut CrlStore,
    ) -> Result<(), ValidationError> {
        let uri_list = match cert.as_ref().crl_distribution() {
            Some(some) => some,
            None => return Ok(())
        };
        for uri in uri_list.iter() {
            let uri = match uri.into_rsync_uri() {
                Some(uri) => uri,
                None => continue
            };

            // If we already have that CRL, use it.
            if let Some(crl) = store.get(&uri) {
                if crl.contains(&cert.as_ref().serial_number()) {
                    return Err(ValidationError)
                }
                else {
                    return Ok(())
                }
            }

            // Otherwise, try to load it, use it, and then store it.
            let bytes = match self.load_file(&uri, true) {
                Ok(bytes) => bytes,
                Err(_) => continue
            };
            let crl = match Crl::decode(bytes) {
                Ok(crl) => crl,
                Err(_) => continue
            };
            if let Err(_) = crl.validate(issuer) {
                continue
            }

            let revoked = crl.contains(&cert.as_ref().serial_number());
            store.push(uri, crl);
            if revoked {
                return Err(ValidationError)
            }
            else {
                return Ok(())
            }
        }
        Err(ValidationError)
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

