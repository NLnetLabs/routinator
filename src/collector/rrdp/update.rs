
use std::{error, fmt, io};
use std::collections::HashSet;
use std::io::Read;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use log::{error, warn};
use reqwest::StatusCode;
use ring::digest;
use ring::constant_time::verify_slices_are_equal;
use rpki::{rrdp, uri};
use rpki::rrdp::{DeltaInfo, NotificationFile, ProcessDelta, ProcessSnapshot};
use uuid::Uuid;
use crate::error::{Failed, RunFailed};
use crate::metrics::RrdpRepositoryMetrics;
use crate::utils::archive::{ArchiveError, PublishError};
use super::archive::{AccessError, FallbackTime, RepositoryState, RrdpArchive};
use super::base::Collector;
use super::http::{HttpClient, HttpResponse, HttpStatus};


//------------ Notification --------------------------------------------------

/// The notification file of an RRDP repository.
pub struct Notification {
    /// The URI of the notification file.
    uri: uri::Https,

    /// The content of the file.
    content: NotificationFile,

    /// The Etag value if provided.
    etag: Option<Bytes>,

    /// The Last-Modified value if provided,
    last_modified: Option<DateTime<Utc>>,
}

impl Notification {
    /// Requests, parses, and returns the given RRDP notification file.
    ///
    /// The value referred to by `status` will be updated to the received
    /// status code or `HttpStatus::Error` if the request failed.
    ///
    /// Returns the notification file on success. Returns `Ok(None)` if a
    /// response was received successfully but indicated that the
    /// notification file was not updated.
    pub fn get(
        http: &HttpClient,
        uri: &uri::Https,
        state: Option<&RepositoryState>,
        status: &mut HttpStatus,
    ) -> Result<Option<Self>, Failed> {
        let response = match http.conditional_response(
            uri,
            state.and_then(|state| state.etag.as_ref()),
            state.and_then(|state| state.last_modified()),
            true
        ) {
            Ok(response) => {
                *status = response.status().into();
                response
            }
            Err(err) => {
                warn!("RRDP {}: {}", uri, err);
                *status = HttpStatus::Error;
                return Err(Failed)
            }
        };

        if response.status() == StatusCode::NOT_MODIFIED {
            Ok(None)
        }
        else if response.status() != StatusCode::OK {
            warn!(
                "RRDP {}: Getting notification file failed with status {}",
                uri, response.status()
            );
            Err(Failed)
        }
        else {
            Notification::from_response(uri.clone(), response).map(Some)
        }
    }


    /// Creates a new notification from a successful HTTP response.
    ///
    /// Assumes that the response status was 200 OK.
    fn from_response(
        uri: uri::Https, response: HttpResponse
    ) -> Result<Self, Failed> {
        let etag = response.etag();
        let last_modified = response.last_modified();
        let mut content = NotificationFile::parse(
            io::BufReader::new(response)
        ).map_err(|err| {
            warn!("RRDP {}: {}", uri, err);
            Failed
        })?;
        content.sort_deltas();
        Ok(Notification { uri, content, etag, last_modified })
    }

    /// Returns a reference to the content of the notification file.
    pub fn content(&self) -> &NotificationFile {
        &self.content
    }

    /// Creates repository state for this notification.
    pub fn to_repository_state(
        &self, fallback: FallbackTime,
    ) -> RepositoryState {
        RepositoryState {
            rpki_notify: self.uri.clone(),
            session: self.content.session_id(),
            serial: self.content.serial(),
            updated_ts: Utc::now().timestamp(),
            best_before_ts: fallback.best_before().timestamp(),
            last_modified_ts: self.last_modified.map(|x| x.timestamp()),
            etag: self.etag.clone(),
            delta_state: self.content.deltas().iter().map(|delta| {
                (delta.serial(), delta.hash())
            }).collect(),
        }
    }

    /// Checks that the deltas match those present in `state`.
    ///
    /// Ensures that for delta serial numbers present both in the notification
    /// and the state the hash values match.
    pub fn check_deltas(
        &self, state: &RepositoryState
    ) -> Result<(), SnapshotReason> {
        for delta in self.content().deltas() {
            if let Some(state_hash) = state.delta_state.get(&delta.serial()) {
                if delta.hash() != *state_hash {
                    return Err(SnapshotReason::DeltaMutation)
                }
            }
        }
        Ok(())
    }
}


//------------ SnapshotUpdate ------------------------------------------------

/// An update to a repository performed from a snapshot file.
///
/// For this type of update, we collect all the published objects in the
/// repository’s temp directory and move it over to the object directory upon
/// success.
pub struct SnapshotUpdate<'a> {
    /// The collector.
    collector: &'a Collector,

    /// The archive to store the snapshot into.
    archive: &'a mut RrdpArchive,

    /// The notification file pointing to the snapshot.
    notify: &'a Notification,

    /// The metrics for the update.
    metrics: &'a mut RrdpRepositoryMetrics,
}

impl<'a> SnapshotUpdate<'a> {
    pub fn new(
        collector: &'a Collector,
        archive: &'a mut RrdpArchive,
        notify: &'a Notification,
        metrics: &'a mut RrdpRepositoryMetrics,
    ) -> Self {
        SnapshotUpdate { collector, archive, notify, metrics }
    }

    pub fn try_update(mut self) -> Result<(), SnapshotError> {
        let response = match self.collector.http().response(
            self.notify.content.snapshot().uri(), false
        ) {
            Ok(response) => {
                self.metrics.payload_status = Some(response.status().into());
                if response.status() != StatusCode::OK {
                    return Err(response.status().into())
                }
                else {
                    response
                }
            }
            Err(err) => {
                self.metrics.payload_status = Some(HttpStatus::Error);
                return Err(err.into())
            }
        };

        let mut reader = io::BufReader::new(HashRead::new(response));
        self.process(&mut reader)?;
        let hash = reader.into_inner().into_hash();
        if verify_slices_are_equal(
            hash.as_ref(),
            self.notify.content.snapshot().hash().as_ref()
        ).is_err() {
            return Err(SnapshotError::HashMismatch)
        }
        self.archive.publish_state(
            &self.notify.to_repository_state(
                self.collector.config().fallback_time
            )
        )?;
        Ok(())
    }
}

impl<'a> ProcessSnapshot for SnapshotUpdate<'a> {
    type Err = SnapshotError;

    fn meta(
        &mut self,
        session_id: Uuid,
        serial: u64,
    ) -> Result<(), Self::Err> {
        if session_id != self.notify.content.session_id() {
            return Err(SnapshotError::SessionMismatch {
                expected: self.notify.content.session_id(),
                received: session_id
            })
        }
        if serial != self.notify.content.serial() {
            return Err(SnapshotError::SerialMismatch {
                expected: self.notify.content.serial(),
                received: serial
            })
        }
        Ok(())
    }

    fn publish(
        &mut self,
        uri: uri::Rsync,
        data: &mut rrdp::ObjectReader,
    ) -> Result<(), Self::Err> {
        let content = RrdpDataRead::new(
            data, &uri, self.collector.config().max_object_size,
        ).read_all()?;
        self.archive.publish_object(&uri, &content).map_err(|err| match err {
            PublishError::AlreadyExists => {
                SnapshotError::DuplicateObject(uri.clone())
            }
            PublishError::Archive(ArchiveError::Corrupt) => {
                warn!(
                    "Temporary RRDP repository file {} became corrupt.",
                    self.archive.path().display(),
                );
                SnapshotError::RunFailed(RunFailed::retry())
            }
            PublishError::Archive(ArchiveError::Io(err)) => {
                error!(
                    "Fatal: Failed to write to temporary RRDP repository file \
                     {}: {}",
                     self.archive.path().display(), err,
                );
                SnapshotError::RunFailed(RunFailed::fatal())
            }
        })
    }
}


//------------ DeltaUpdate ---------------------------------------------------

/// An update to a repository performed from a delta file.
///
/// For this kind of update, we collect newly published and updated objects in
/// the repository’s temp directory and remember them as well as all deleted
/// objects and if everything is okay, copy files over to and delete files in
/// the object directory.
pub struct DeltaUpdate<'a> {
    /// The collector.
    collector: &'a Collector,

    /// The archive the repository is stored in.
    archive: &'a mut RrdpArchive,

    /// The session ID of the RRDP session.
    session_id: Uuid,

    /// Information about the delta file.
    info: &'a DeltaInfo,

    /// The metrics for the update.
    metrics: &'a mut RrdpRepositoryMetrics,

    /// The URIs we’ve already seen in this delta.
    ///
    /// This is so we can error out if a URI was touched more than once.
    seen: HashSet<uri::Rsync>,
}

impl<'a> DeltaUpdate<'a> {
    /// Creates a new delta update.
    pub fn new(
        collector: &'a Collector,
        archive: &'a mut RrdpArchive,
        session_id: Uuid,
        info: &'a DeltaInfo,
        metrics: &'a mut RrdpRepositoryMetrics,
    ) -> Self {
        DeltaUpdate {
            collector, archive, session_id, info, metrics,
            seen: Default::default(),
        }
    }

    pub fn try_update(mut self) -> Result<(), DeltaError> {
        let response = match self.collector.http().response(
            self.info.uri(), false
        ) {
            Ok(response) => {
                self.metrics.payload_status = Some(response.status().into());
                if response.status() != StatusCode::OK {
                    return Err(response.status().into())
                }
                else {
                    response
                }
            }
            Err(err) => {
                self.metrics.payload_status = Some(HttpStatus::Error);
                return Err(err.into())
            }
        };

        let mut reader = io::BufReader::new(HashRead::new(response));
        self.process(&mut reader)?;
        let hash = reader.into_inner().into_hash();
        if verify_slices_are_equal(
            hash.as_ref(),
            self.info.hash().as_ref()
        ).is_err() {
            return Err(DeltaError::DeltaHashMismatch)
        }
        Ok(())
    }
}

impl<'a> ProcessDelta for DeltaUpdate<'a> {
    type Err = DeltaError;

    fn meta(
        &mut self, session_id: Uuid, serial: u64
    ) -> Result<(), Self::Err> {
        if session_id != self.session_id {
            return Err(DeltaError::SessionMismatch {
                expected: self.session_id,
                received: session_id
            })
        }
        if serial != self.info.serial() {
            return Err(DeltaError::SerialMismatch {
                expected: self.info.serial(),
                received: serial
            })
        }
        Ok(())
    }

    fn publish(
        &mut self,
        uri: uri::Rsync,
        hash: Option<rrdp::Hash>,
        data: &mut rrdp::ObjectReader<'_>
    ) -> Result<(), Self::Err> {
        if !self.seen.insert(uri.clone()) {
            return Err(DeltaError::ObjectRepeated { uri })
        }
        let content = RrdpDataRead::new(
            data, &uri, self.collector.config().max_object_size
        ).read_all()?;
        match hash {
            Some(hash) => {
                self.archive.update_object(
                    &uri, hash, &content
                ).map_err(|err| match err {
                    AccessError::NotFound => {
                        DeltaError::MissingObject { uri: uri.clone() }
                    }
                    AccessError::HashMismatch => {
                        DeltaError::ObjectHashMismatch { uri: uri.clone() }
                    }
                    AccessError::Archive(err) => DeltaError::Archive(err),
                })
            }
            None => {
                self.archive.publish_object(&uri, &content).map_err(|err| {
                    match err {
                        PublishError::AlreadyExists => {
                            DeltaError::ObjectAlreadyPresent {
                                uri: uri.clone()
                            }
                        }
                        PublishError::Archive(err) => {
                            DeltaError::Archive(err)
                        }
                    }
                })
            }
        }
    }

    fn withdraw(
        &mut self,
        uri: uri::Rsync,
        hash: rrdp::Hash
    ) -> Result<(), Self::Err> {
        if !self.seen.insert(uri.clone()) {
            return Err(DeltaError::ObjectRepeated { uri })
        }
        self.archive.delete_object(&uri, hash).map_err(|err| match err {
            AccessError::NotFound => {
                DeltaError::MissingObject { uri: uri.clone() }
            }
            AccessError::HashMismatch => {
                DeltaError::ObjectHashMismatch { uri: uri.clone() }
            }
            AccessError::Archive(err) => DeltaError::Archive(err),
        })
    }
}


//------------ HashRead ------------------------------------------------------

/// A reader wrapper that calculates the SHA-256 hash of all read data.
struct HashRead<R> {
    /// The wrapped reader.
    reader: R,

    /// The context for hash calculation.
    context: digest::Context,
}

impl<R> HashRead<R> {
    /// Creates a new hash reader.
    pub fn new(reader: R) -> Self {
        HashRead {
            reader,
            context: digest::Context::new(&digest::SHA256)
        }
    }

    /// Converts the reader into the hash.
    pub fn into_hash(self) -> rrdp::Hash {
        // Unwrap should be safe: This can only fail if the slice has the
        // wrong length.
        rrdp::Hash::try_from(self.context.finish()).unwrap()
    }
}


impl<R: io::Read> io::Read for HashRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        let res = self.reader.read(buf)?;
        self.context.update(&buf[..res]);
        Ok(res)
    }
}


//------------ RrdpDataRead --------------------------------------------------

/// A reader that reads the data of objects in a snapshot or delta.
///
/// The type ensures the size limit of objects and allows treating read errors
/// differently than write errors by storing any error and making it available
/// after the fact.
struct RrdpDataRead<'a, R> {
    /// The wrapped reader.
    reader: R,

    /// The URI of the object we are reading.
    uri: &'a uri::Rsync,

    /// The number of bytes left to read.
    ///
    /// If this is `None` we are allowed to read an unlimited amount.
    left: Option<u64>,

    /// The last error that happend.
    err: Option<RrdpDataReadError>,
}

impl<'a, R> RrdpDataRead<'a, R> {
    /// Creates a new read from necessary information.
    ///
    /// The returned value will wrap `reader`. The `uri` should be the rsync
    /// URI of the published object. It is only used for generating meaningful
    /// error messages. If `max_size` is some value, the size of the object
    /// will be limited to that value in bytes. Larger objects lead to an
    /// error.
    pub fn new(reader: R, uri: &'a uri::Rsync, max_size: Option<u64>) -> Self {
        RrdpDataRead { reader, uri, left: max_size, err: None }
    }

    /// Returns a stored error if available.
    ///
    /// If it returns some error, that error happened during reading before
    /// an `io::Error` was returned.
    ///
    /// The method takes the stored error and replaces it internally with
    /// `None`.
    pub fn take_err(&mut self) -> Option<RrdpDataReadError> {
        self.err.take()
    }
}

impl<'a, R: io::Read> RrdpDataRead<'a, R> {
    /// Reads the data into a vec.
    pub fn read_all(mut self) -> Result<Vec<u8>, RrdpDataReadError> {
        let mut content = Vec::new();
        if let Err(io_err) = self.read_to_end(&mut content) {
            return Err(
                match self.take_err() {
                    Some(data_err) => data_err,
                    None => RrdpDataReadError::Read(io_err),
                }
            )
        }
        Ok(content)
    }
}

impl<'a, R: io::Read> io::Read for RrdpDataRead<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        let res = match self.reader.read(buf) {
            Ok(res) => res,
            Err(err) => {
                self.err = Some(RrdpDataReadError::Read(err));
                return Err(io::Error::new(
                    io::ErrorKind::Other, "reading data failed",
                ))
            }
        };
        if let Some(left) = self.left {
            let res64 = match u64::try_from(res) {
                Ok(res) => res,
                Err(_) => {
                    // If the usize doesn’t fit into a u64, things are
                    // definitely way too big.
                    self.left = Some(0);
                    self.err = Some(
                        RrdpDataReadError::LargeObject(self.uri.clone())
                    );
                    return Err(io::Error::new(
                        io::ErrorKind::Other, "size limit exceeded"
                    ))
                }
            };
            if res64 > left {
                self.left = Some(0);
                self.err = Some(
                    RrdpDataReadError::LargeObject(self.uri.clone())
                );
                Err(io::Error::new(
                    io::ErrorKind::Other, "size limit exceeded")
                )
            }
            else {
                self.left = Some(left - res64);
                Ok(res)
            }
        }
        else {
            Ok(res)
        }
    }
}


//------------ SnapshotReason ------------------------------------------------

/// The reason why a snapshot was used.
#[derive(Clone, Copy, Debug)]
pub enum SnapshotReason {
    /// The respository is new.
    NewRepository,

    /// A new session was encountered.
    NewSession,

    /// The delta set in the notification file is inconsistent.
    BadDeltaSet,

    /// At least one delta hash has changed from a previous update.
    DeltaMutation,

    /// A larger-than-supported serial number was encountered.
    LargeSerial,

    /// The local copy is outdated and cannot be updated via deltas.
    OutdatedLocal,

    /// A delta file was conflicting with locally stored data.
    ConflictingDelta,

    /// There were too many deltas to process.
    TooManyDeltas,

    /// The local copy was corrupt.
    CorruptArchive,
}

impl SnapshotReason {
    /// Returns a shorthand code for the reason.
    pub fn code(self) -> &'static str {
        use SnapshotReason::*;

        match self {
            NewRepository => "new-repository",
            NewSession => "new-session",
            BadDeltaSet => "inconsistent-delta-set",
            DeltaMutation => "delta-mutation",
            LargeSerial => "large-serial",
            OutdatedLocal => "outdate-local",
            ConflictingDelta => "conflicting-delta",
            TooManyDeltas => "too-many-deltas",
            CorruptArchive => "corrupt-local-copy",
        }
    }
}


//============ Errors ========================================================

//------------ RrdpDataReadError ---------------------------------------------

/// An error happened while reading object data.
///
/// This covers both the case where the maximum allowed file size was
/// exhausted as well as where reading data failed. Neither of them is fatal,
/// so we need to process them separately.
#[derive(Debug)]
enum RrdpDataReadError {
    LargeObject(uri::Rsync),
    Read(io::Error),
}


//------------ SnapshotError -------------------------------------------------

/// An error happened during snapshot processing.
///
/// This is an internal error type only necessary for error handling during
/// RRDP processing. Values will be logged and converted into failures or
/// negative results as necessary.
#[derive(Debug)]
pub enum SnapshotError {
    Http(reqwest::Error),
    HttpStatus(StatusCode),
    Rrdp(rrdp::ProcessError),
    SessionMismatch {
        expected: Uuid,
        received: Uuid
    },
    SerialMismatch {
        expected: u64,
        received: u64,
    },
    DuplicateObject(uri::Rsync),
    HashMismatch,
    LargeObject(uri::Rsync),
    RunFailed(RunFailed),
}

impl From<reqwest::Error> for SnapshotError {
    fn from(err: reqwest::Error) -> Self {
        SnapshotError::Http(err)
    }
}

impl From<StatusCode> for SnapshotError {
    fn from(code: StatusCode) -> Self {
        SnapshotError::HttpStatus(code)
    }
}

impl From<rrdp::ProcessError> for SnapshotError {
    fn from(err: rrdp::ProcessError) -> Self {
        SnapshotError::Rrdp(err)
    }
}

impl From<io::Error> for SnapshotError {
    fn from(err: io::Error) -> Self {
        SnapshotError::Rrdp(err.into())
    }
}

impl From<RunFailed> for SnapshotError {
    fn from(err: RunFailed) -> Self {
        SnapshotError::RunFailed(err)
    }
}

impl From<RrdpDataReadError> for SnapshotError {
    fn from(err: RrdpDataReadError) -> Self {
        match err {
            RrdpDataReadError::LargeObject(uri) => {
                SnapshotError::LargeObject(uri)
            }
            RrdpDataReadError::Read(err) => {
                SnapshotError::Rrdp(err.into())
            }
        }
    }
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SnapshotError::Http(ref err) => err.fmt(f),
            SnapshotError::HttpStatus(status) => {
                write!(f, "HTTP {}", status)
            }
            SnapshotError::Rrdp(ref err) => err.fmt(f),
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
            SnapshotError::DuplicateObject(ref uri) => {
                write!(f, "duplicate object: {}", uri)
            }
            SnapshotError::HashMismatch => {
                write!(f, "hash value mismatch")
            }
            SnapshotError::LargeObject(ref uri) => {
                write!(f, "object exceeds size limit: {}", uri)
            }
            SnapshotError::RunFailed(_) => Ok(()),
        }
    }
}

impl error::Error for SnapshotError { }


//------------ DeltaError ----------------------------------------------------

/// An error happened during delta processing.
///
/// This is an internal error type only necessary for error handling during
/// RRDP processing. Values will be logged and converted into failures or
/// negative results as necessary.
#[derive(Debug)]
pub enum DeltaError {
    Http(reqwest::Error),
    HttpStatus(StatusCode),
    Rrdp(rrdp::ProcessError),
    SessionMismatch {
        expected: Uuid,
        received: Uuid
    },
    SerialMismatch {
        expected: u64,
        received: u64,
    },
    MissingObject {
        uri: uri::Rsync,
    },
    ObjectAlreadyPresent {
        uri: uri::Rsync,
    },
    ObjectHashMismatch {
        uri: uri::Rsync,
    },
    ObjectRepeated {
        uri: uri::Rsync,
    },
    DeltaHashMismatch,
    LargeObject(uri::Rsync),
    Archive(ArchiveError),
}

impl From<reqwest::Error> for DeltaError {
    fn from(err: reqwest::Error) -> Self {
        DeltaError::Http(err)
    }
}

impl From<StatusCode> for DeltaError {
    fn from(code: StatusCode) -> Self {
        DeltaError::HttpStatus(code)
    }
}

impl From<rrdp::ProcessError> for DeltaError {
    fn from(err: rrdp::ProcessError) -> Self {
        DeltaError::Rrdp(err)
    }
}

impl From<io::Error> for DeltaError {
    fn from(err: io::Error) -> Self {
        DeltaError::Rrdp(err.into())
    }
}

impl From<RrdpDataReadError> for DeltaError {
    fn from(err: RrdpDataReadError) -> Self {
        match err {
            RrdpDataReadError::LargeObject(uri) => {
                DeltaError::LargeObject(uri)
            }
            RrdpDataReadError::Read(err) => {
                DeltaError::Rrdp(err.into())
            }
        }
    }
}

impl fmt::Display for DeltaError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DeltaError::Http(ref err) => err.fmt(f),
            DeltaError::HttpStatus(status) => {
                write!(f, "HTTP {}", status)
            }
            DeltaError::Rrdp(ref err) => err.fmt(f),
            DeltaError::SessionMismatch { ref expected, ref received } => {
                write!(
                    f,
                    "session ID mismatch (notification_file: {}, \
                     snapshot file: {}",
                     expected, received
                )
            }
            DeltaError::SerialMismatch { ref expected, ref received } => {
                write!(
                    f,
                    "serial number mismatch (notification_file: {}, \
                     snapshot file: {}",
                     expected, received
                )
            }
            DeltaError::MissingObject { ref uri } => {
                write!(
                    f,
                    "reference to missing object {}",
                    uri
                )
            }
            DeltaError::ObjectAlreadyPresent { ref uri } => {
                write!(
                    f,
                    "attempt to add already present object {}",
                    uri
                )
            }
            DeltaError::ObjectHashMismatch { ref uri } => {
                write!(
                    f,
                    "local object {} has different hash",
                    uri
                )
            }
            DeltaError::ObjectRepeated { ref uri } => {
                write!(f, "object appears multiple times: {}", uri)
            }
            DeltaError::LargeObject(ref uri) => {
                write!(f, "object exceeds size limit: {}", uri)
            }
            DeltaError::DeltaHashMismatch => {
                write!(f, "delta file hash value mismatch")
            }
            DeltaError::Archive(ref err) => {
                write!(f, "archive error: {}", err)
            }
        }
    }
}

impl error::Error for DeltaError { }

