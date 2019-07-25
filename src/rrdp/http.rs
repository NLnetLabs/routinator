//! The HTTP client for RRDP.
//!
//! This is an internal module for organizational purposes.

use std::{fs, io};
use std::io::Write;
use std::path::{Path, PathBuf};
use bytes::Bytes;
use derive_more::{Display, From};
use log::{error, info};
use ring::digest;
use ring::constant_time::verify_slices_are_equal;
use rpki::uri;
use rpki::rrdp::{NotificationFile, ProcessDelta, ProcessSnapshot, UriAndHash};
use rpki::xml::decode as xml;
use tempfile::TempDir;
use unwrap::unwrap;
use uuid::Uuid;
use crate::config::Config;
use crate::operation::Error;
use super::utils::create_unique_file;


//------------ HttpClient ----------------------------------------------------

#[derive(Clone, Debug)]
pub struct HttpClient {
    client: reqwest::Client,
    tmp_dir: PathBuf,
}

impl HttpClient {
    pub fn new(config: &Config) -> Result<Self, Error> {
        let builder = reqwest::Client::builder();
        let client = match builder.build() {
            Ok(client) => client,
            Err(err) => {
                error!("Failed to initialize HTTP client: {}.", err);
                error!("No RRDP, using rsync only.");
                return Err(Error)
            }
        };
        Ok(HttpClient {
            client,
            tmp_dir: config.cache_dir.join("tmp"),
        })
    }
    
    pub fn tmp_dir(&self) -> &Path {
        &self.tmp_dir
    }

    pub fn notification_file(
        &self,
        uri: &uri::Https
    ) -> Result<NotificationFile, Error> {
        match NotificationFile::parse(io::BufReader::new(self.response(uri)?)) {
            Ok(res) => Ok(res),
            Err(err) => {
                error!("{}: {}", uri, err);
                Err(Error)
            }
        }
    }

    pub fn snapshot<F: Fn(&uri::Rsync) -> PathBuf>(
        &self,
        notify: &NotificationFile,
        path_op: F
    ) -> Result<(), Error> {
        let mut processor = SnapshotProcessor { notify, path_op };
        let mut reader = io::BufReader::new(DigestRead::sha256(
                self.response(notify.snapshot.uri())?
        ));
        if let Err(err) = processor.process(&mut reader) {
            error!("{}: {}", notify.snapshot.uri(), err);
            return Err(Error)
        }
        let digest = reader.into_inner().into_digest();
        if let Err(_) = verify_slices_are_equal(digest.as_ref(),
                                            notify.snapshot.hash().as_ref()) {
            error!("{}: hash value mismatch.", notify.snapshot.uri());
            return Err(Error)
        }
        Ok(())
    }

    pub fn delta<F: Fn(&uri::Rsync) -> PathBuf>(
        &self,
        server_uri: &uri::Https,
        notify: &NotificationFile,
        delta: &(usize, UriAndHash),
        targets: &mut DeltaTargets,
        path_op: F
    ) -> Result<(), Error> {
        let mut processor = DeltaProcessor {
            server_uri, notify, delta, path_op, targets
        };
        let mut reader = io::BufReader::new(DigestRead::sha256(
            self.response(delta.1.uri())?
        ));
        if let Err(err) = processor.process(&mut reader) {
            if let ProcessError::Xml(err) = err {
                info!("Bad content in {}: {}", delta.1.uri(), err);
            }
            return Err(Error)
        }
        let digest = reader.into_inner().into_digest();
        if let Err(_) = verify_slices_are_equal(digest.as_ref(),
                                                delta.1.hash().as_ref()) {
            error!("{}: hash value mismatch.", delta.1.uri());
            return Err(Error)
        }
        Ok(())
    }

    fn response(&self, uri: &uri::Https) -> Result<reqwest::Response, Error> {
        match self.client.get(uri.as_str()).send() {
            Ok(response) => Ok(response),
            Err(err) => {
                error!("{}: {}", uri, err);
                Err(Error)
            }
        }
    }
}


//------------ DigestRead ----------------------------------------------------

pub struct DigestRead<R> {
    reader: R,
    context: digest::Context,
}

impl<R> DigestRead<R> {
    pub fn sha256(reader: R) -> Self {
        DigestRead {
            reader,
            context: digest::Context::new(&digest::SHA384)
        }
    }

    pub fn into_digest(self) -> digest::Digest {
        self.context.finish()
    }

    pub fn read_all(mut self) -> Result<digest::Digest, io::Error>
    where R: io::Read {
        let mut buf = [0u8; 4096];
        while self.reader.read(&mut buf)? > 0 { }
        Ok(self.into_digest())
    }
}


impl<R: io::Read> io::Read for DigestRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        let res = self.reader.read(buf)?;
        self.context.update(&buf[..res]);
        Ok(res)
    }
}


//------------ SnapshotProcessor ---------------------------------------------

pub struct SnapshotProcessor<'a, F> {
    notify: &'a NotificationFile,
    path_op: F,
}

impl<'a, F> ProcessSnapshot for SnapshotProcessor<'a, F>
where F: Fn(&uri::Rsync) -> PathBuf {
    type Err = SnapshotError;

    fn meta(
        &mut self,
        session_id: Uuid,
        serial: usize
    ) -> Result<(), Self::Err> {
        if session_id != self.notify.session_id {
            return Err(SnapshotError::SessionMismatch {
                expected: self.notify.session_id.clone(),
                received: session_id
            })
        }
        if serial != self.notify.serial {
            return Err(SnapshotError::SerialMismatch {
                expected: self.notify.serial,
                received: serial
            })
        }
        Ok(())
    }

    fn publish(
        &mut self,
        uri: uri::Rsync,
        data: Vec<u8>,
    ) -> Result<(), Self::Err> {
        let path = (self.path_op)(&uri);

        if let Err(err) = fs::create_dir_all(unwrap!(path.parent())) {
            return Err(SnapshotError::Io(
                unwrap!(path.parent()).to_string_lossy().into(),
                err
            ))
        }

        let mut file = match fs::File::create(&path) {
            Ok(file) => file,
            Err(err) => {
                return Err(SnapshotError::Io(
                    path.to_string_lossy().into(),
                    err
                ))
            }
        };

        if let Err(err) = file.write_all(data.as_ref()) {
            return Err(SnapshotError::Io(
                path.to_string_lossy().into(),
                err
            ))
        }
        Ok(())
    }
}


//------------ DeltaProcessor ------------------------------------------------

pub struct DeltaProcessor<'a, F> {
    server_uri: &'a uri::Https,
    notify: &'a NotificationFile,
    delta: &'a (usize, UriAndHash),
    path_op: F,
    targets: &'a mut DeltaTargets,
}

impl<'a, F> DeltaProcessor<'a, F> {
    fn check_hash(
        uri: &uri::Rsync,
        path: &Path,
        hash: Bytes
    ) -> Result<(), ProcessError> {
        let file = match fs::File::open(&path) {
            Ok(file) => file,
            Err(err) => {
                info!(
                    "Failed to open file '{}': {}",
                    path.display(), err
                );
                return Err(ProcessError::Error)
            }
        };
        let digest = match DigestRead::sha256(file).read_all() {
            Ok(digest) => digest,
            Err(err) => {
                info!(
                    "Failed to read file '{}': {}",
                    path.display(), err
                );
                return Err(ProcessError::Error)
            }
        };
        verify_slices_are_equal(hash.as_ref(), digest.as_ref()).map_err(|_| {
            info!(
                "RRDP Hash mismatch in local file {}.", uri
            );
            ProcessError::Error
        })
    }
}

impl<'a, F> ProcessDelta for DeltaProcessor<'a, F>
where F: Fn(&uri::Rsync) -> PathBuf {
    type Err = ProcessError;

    fn meta(
        &mut self,
        session_id: Uuid,
        serial: usize
    ) -> Result<(), Self::Err> {
        if session_id != self.notify.session_id {
            info!(
                "RRDP server {}: \
                Mismatch between notification session and delta session",
                self.server_uri
            );
            return Err(ProcessError::Error)
        }
        if serial != self.delta.0 {
            info!(
                "RRDP server {}: \
                Mismatch between annound and actual serial in delta.",
                self.server_uri
            );
            return Err(ProcessError::Error)
        }
        Ok(())
    }

    fn publish(
        &mut self,
        uri: uri::Rsync,
        hash: Option<Bytes>,
        data: Vec<u8>
    ) -> Result<(), Self::Err> {
        let target = (self.path_op)(&uri);
        if let Some(hash) = hash {
            Self::check_hash(&uri, &target, hash)?;
        }
        self.targets.publish(target, data)
    }

    fn withdraw(
        &mut self,
        uri: uri::Rsync,
        hash: Bytes
    ) -> Result<(), Self::Err> {
        let target = (self.path_op)(&uri);
        Self::check_hash(&uri, &target, hash)?;
        self.targets.withdraw(target);
        Ok(())
    }
}


//------------ DeltaTargets --------------------------------------------------

pub struct DeltaTargets {
    tmp_dir: TempDir,
    targets: Vec<DeltaEntry>,
}

enum DeltaEntry {
    Publish {
        source: PathBuf,
        target: PathBuf,
    },
    Withdraw {
        target: PathBuf
    }
}

impl DeltaTargets {
    pub fn new(cache_dir: &Path) -> Result<Self, Error> {
        Ok(DeltaTargets {
            tmp_dir: match TempDir::new_in(cache_dir) {
                Ok(tmp_dir) => tmp_dir,
                Err(err) => {
                    info!(
                        "Unable to create temporary directory under {}: {}",
                        cache_dir.display(), err
                    );
                    return Err(Error)
                }
            },
            targets: Vec::new()
        })
    }

    pub fn apply(self) -> Result<(), Error> {
        for entry in self.targets {
            match entry {
                DeltaEntry::Publish { source, target } => {
                    let _ = fs::remove_file(&target); // Just to make sure.
                    if let Err(err) = fs::rename(&source, &target) {
                        info!(
                            "Failed to move delta source '{}' to \
                            target '{}': {}",
                            source.display(),
                            target.display(),
                            err
                        );
                        return Err(Error);
                    }
                }
                DeltaEntry::Withdraw { target } => {
                    if let Err(err) = fs::remove_file(&target) {
                        info!(
                            "Failed to delete file '{}': {}",
                            target.display(), err
                        );
                        return Err(Error);
                    }
                }
            }
        }
        Ok(())
    }

    fn publish(
        &mut self,
        target: PathBuf,
        data: Vec<u8>
    ) -> Result<(), ProcessError> {
        let (mut file, source) = create_unique_file(self.tmp_dir.path())?;
        if let Err(err) = file.write_all(data.as_ref()) {
            info!(
                "Failed to temporary file '{}': {}",
                source.display(), err
            );
            return Err(ProcessError::Error)
        }
        self.targets.push(DeltaEntry::Publish { source, target });
        Ok(())
    }

    fn withdraw(&mut self, target: PathBuf) {
        self.targets.push(DeltaEntry::Withdraw { target })
    }
}
    

//============ Errors ========================================================

#[derive(Debug, Display, From)]
pub enum SnapshotError {
    #[display(fmt="{}", _0)]
    Xml(xml::Error),

    #[display(
        fmt="session ID mismatch (notification_file: {}, \
             snapshot file: {}",
        expected, received
    )]
    SessionMismatch {
        expected: Uuid,
        received: Uuid
    },

    #[display(
        fmt="serial number mismatch (notification_file: {}, \
             snapshot file: {}",
        expected, received
    )]
    SerialMismatch {
        expected: usize,
        received: usize 
    },

    #[display(fmt="{}: {}", _0, _1)]
    Io(String, io::Error),
}


#[derive(Debug, From)]
pub enum ProcessError {
    Xml(xml::Error),
    Error,
}

impl From<Error> for ProcessError {
    fn from(_: Error) -> ProcessError {
        ProcessError::Error
    }
}

