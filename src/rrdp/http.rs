//! The HTTP client for RRDP.
//!
//! This is an internal module for organizational purposes.

use std::{error, fmt, fs, io};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;
use log::{error, info};
use reqwest::{Certificate, Proxy, StatusCode};
use reqwest::blocking::{Client, ClientBuilder, Response};
use ring::digest;
use ring::constant_time::verify_slices_are_equal;
use rpki::uri;
use rpki::rrdp::{
    DigestHex, NotificationFile, ProcessDelta, ProcessSnapshot, UriAndHash
};
use rpki::xml::decode as xml;
use tempfile::TempDir;
use uuid::Uuid;
use crate::config::Config;
use crate::operation::Error;
use super::utils::create_unique_file;


//------------ Configuration Constants ---------------------------------------

/// The default timeout for RRDP requests.
///
/// This is mentioned in the man page. If you change it, also change it there.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);


//------------ HttpClient ----------------------------------------------------

#[derive(Debug)]
pub struct HttpClient {
    client: Result<Client, Option<ClientBuilder>>,
    tmp_dir: PathBuf,
}

impl HttpClient {
    pub fn init(config: &Config) -> Result<(), Error> {
        let tmp_dir = config.cache_dir.join("tmp");
        if let Err(err) = fs::create_dir_all(&tmp_dir) {
            error!(
                "Failed to create temporary directory {}: {}.",
                tmp_dir.display(), err
            );
            return Err(Error);
        }
        Ok(())
    }

    pub fn new(config: &Config) -> Result<Self, Error> {
        let mut builder = Client::builder();
        builder = builder.user_agent(config.rrdp_user_agent.clone());
        match config.rrdp_timeout {
            Some(Some(timeout)) => {
                builder = builder.timeout(timeout);
            }
            Some(None) => { /* keep no timeout */ }
            None => {
                builder = builder.timeout(DEFAULT_TIMEOUT);
            }
        }
        if let Some(timeout) = config.rrdp_connect_timeout {
            builder = builder.connect_timeout(timeout);
        }
        if let Some(addr) = config.rrdp_local_addr {
            builder = builder.local_address(addr)
        }
        for path in &config.rrdp_root_certs {
            builder = builder.add_root_certificate(
                Self::load_cert(path)?
            );
        }
        for proxy in &config.rrdp_proxies {
            let proxy = match Proxy::all(proxy) {
                Ok(proxy) => proxy,
                Err(err) => {
                    error!(
                        "Invalid rrdp-proxy '{}': {}", proxy, err
                    );
                    return Err(Error)
                }
            };
            builder = builder.proxy(proxy);
        }
        Ok(HttpClient {
            client: Err(Some(builder)),
            tmp_dir: config.cache_dir.join("tmp"),
        })
    }

    pub fn ignite(&mut self) -> Result<(), Error> {
        let builder = match self.client.as_mut() {
            Ok(_) => return Ok(()),
            Err(builder) => match builder.take() {
                Some(builder) => builder,
                None => {
                    error!("Previously failed to initialize HTTP client.");
                    return Err(Error)
                }
            }
        };
        let client = match builder.build() {
            Ok(client) => client,
            Err(err) => {
                error!("Failed to initialize HTTP client: {}.", err);
                return Err(Error)
            }
        };
        self.client = Ok(client);
        Ok(())
    }

    fn client(&self) -> &Client {
        self.client.as_ref().unwrap()
    }

    fn load_cert(path: &Path) -> Result<Certificate, Error> {
        let mut file = match fs::File::open(path) {
            Ok(file) => file,
            Err(err) => {
                error!(
                    "Cannot open rrdp-root-cert file '{}': {}'",
                    path.display(), err
                );
                return Err(Error);
            }
        };
        let mut data = Vec::new();
        if let Err(err) = io::Read::read_to_end(&mut file, &mut data) {
            error!(
                "Cannot read rrdp-root-cert file '{}': {}'",
                path.display(), err
            );
            return Err(Error);
        }
        Certificate::from_pem(&data).map_err(|err| {
            error!(
                "Cannot decode rrdp-root-cert file '{}': {}'",
                path.display(), err
            );
            Error
        })
    }
 
    pub fn tmp_dir(&self) -> &Path {
        &self.tmp_dir
    }

    pub fn notification_file(
        &self,
        uri: &uri::Https,
        status: &mut Option<StatusCode>,
    ) -> Result<NotificationFile, Error> {
        let response = match self.response(uri) {
            Ok(response) => {
                *status = Some(response.status());
                response
            }
            Err(_) => {
                *status = None;
                return Err(Error);
            }
        };
        if !response.status().is_success() {
            info!(
                "RRDP {}: Getting notification file failed with status {}",
                uri, response.status()
            );
            return Err(Error);
        }
        match NotificationFile::parse(io::BufReader::new(response)) {
            Ok(mut res) => {
                res.deltas.sort_by_key(|delta| delta.0);
                Ok(res)
            }
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
        if verify_slices_are_equal(
            digest.as_ref(),
            notify.snapshot.hash().as_ref()
        ).is_err() {
            info!("{}: hash value mismatch.", notify.snapshot.uri());
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
        if verify_slices_are_equal(
            digest.as_ref(),
            delta.1.hash().as_ref()
        ).is_err() {
            error!("{}: hash value mismatch.", delta.1.uri());
            return Err(Error)
        }
        Ok(())
    }

    pub fn response(
        &self,
        uri: &uri::Https
    ) -> Result<Response, Error> {
        self.client().get(uri.as_str()).send().and_then(|res| {
            res.error_for_status()
        }).map_err(|err| {
            info!("{}: {}", uri, err);
            Error
        })
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
            context: digest::Context::new(&digest::SHA256)
        }
    }

    pub fn into_digest(self) -> digest::Digest {
        self.context.finish()
    }

    pub fn read_all(mut self) -> Result<digest::Digest, io::Error>
    where R: io::Read {
        let mut buf = [0u8; 4096];
        while io::Read::read(&mut self, &mut buf)? > 0 { }
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
                expected: self.notify.session_id,
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

        if let Err(err) = fs::create_dir_all(path.parent().unwrap()) {
            return Err(SnapshotError::Io(
                path.parent().unwrap().to_string_lossy().into(),
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
        &self,
        uri: &uri::Rsync,
        path: &Path,
        hash: DigestHex
    ) -> Result<(), ProcessError> {
        let path = match self.targets.target_path(path) {
            Some(path) => path,
            None => {
                info!(
                    "Failed to open file '{}': file has been withdrawn.",
                    path.display()
                );
                return Err(ProcessError::Error)
            }
        };
        let file = match fs::File::open(path) {
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
                "RRDP hash mismatch in local file {}.", uri
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
                Mismatch between announced and actual serial in delta.",
                self.server_uri
            );
            return Err(ProcessError::Error)
        }
        Ok(())
    }

    fn publish(
        &mut self,
        uri: uri::Rsync,
        hash: Option<DigestHex>,
        data: Vec<u8>
    ) -> Result<(), Self::Err> {
        let target = (self.path_op)(&uri);
        if let Some(hash) = hash {
            self.check_hash(&uri, &target, hash)?;
        }
        self.targets.publish(target, data)
    }

    fn withdraw(
        &mut self,
        uri: uri::Rsync,
        hash: DigestHex
    ) -> Result<(), Self::Err> {
        let target = (self.path_op)(&uri);
        self.check_hash(&uri, &target, hash)?;
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
                    let _ = target.parent().map(fs::create_dir_all);
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

    fn target_path<'s>(&'s self, target_path: &'s Path) -> Option<&'s Path> {
        for entry in &self.targets {
            match *entry {
                DeltaEntry::Publish { ref source, ref target } => {
                    if target == target_path {
                        return Some(source)
                    }
                }
                DeltaEntry::Withdraw { ref target } => {
                    if target == target_path {
                        return None
                    }
                }
            }
        }
        Some(target_path)
    }
}
    

//============ Errors ========================================================

#[derive(Debug)]
pub enum SnapshotError {
    Xml(xml::Error),
    SessionMismatch {
        expected: Uuid,
        received: Uuid
    },
    SerialMismatch {
        expected: usize,
        received: usize 
    },
    Io(String, io::Error),
}

impl From<xml::Error> for SnapshotError {
    fn from(err: xml::Error) -> Self {
        SnapshotError::Xml(err)
    }
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SnapshotError::Xml(ref err) => err.fmt(f),
            SnapshotError::SessionMismatch { ref expected, ref received } => {
                write!(
                    f,
                    "session ID mismatch (notification_file: {}, \
                     snapshot file: {}",
                     expected, received
                )
            }
            SnapshotError::SerialMismatch { ref expected, ref received } => {
                write!(
                    f,
                    "serial number mismatch (notification_file: {}, \
                     snapshot file: {}",
                     expected, received
                )
            }
            SnapshotError::Io(ref s, ref err) => {
                write!(f, "{}: {}", s, err)
            }
        }
    }
}

impl error::Error for SnapshotError { }


#[derive(Debug)]
pub enum ProcessError {
    Xml(xml::Error),
    Error,
}

impl From<xml::Error> for ProcessError {
    fn from(err: xml::Error) ->  Self {
        ProcessError::Xml(err)
    }
}

impl From<Error> for ProcessError {
    fn from(_: Error) -> ProcessError {
        ProcessError::Error
    }
}


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use ring::digest;
    use super::*;

    #[test]
    fn digest_read_read_all() {
        let test = b"sdafkljfasdkjlfashjklfasdklhjfasdklhjfasd";
        assert_eq!(
            DigestRead::sha256(test.as_ref()).read_all().unwrap().as_ref(),
            digest::digest(&digest::SHA256, test).as_ref()
        );
    }
}

