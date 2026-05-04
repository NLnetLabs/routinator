
use std::error::Error;
use std::{error, fmt, io};
use std::collections::HashSet;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use log::{error, warn};
use reqwest::StatusCode;
use ring::digest;
use rpki::{rrdp, uri};
use rpki::rrdp::{DeltaInfo, NotificationFile, ProcessDelta, ProcessSnapshot};
use uuid::Uuid;
use crate::collector::rrdp::http::{LimitedDataRead, LimitedDataReadError};
use crate::error::{Failed, RunFailed};
use crate::log::LogBookWriter;
use crate::metrics::RrdpRepositoryMetrics;
use crate::utils::archive::{ArchiveError, PublishError};
use super::archive::{
    AccessError, FallbackTime, RepositoryState, RrdpArchive,
    SnapshotRrdpArchive,
};
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
        delta_list_limit: usize,
        log: &mut LogBookWriter,
    ) -> Result<Option<Self>, Failed> {
        let response = match http.conditional_response(
            uri,
            state.and_then(|state| state.etag.as_ref()),
            state.and_then(|state| state.last_modified()),
        ) {
            Ok(response) => {
                *status = response.status().into();
                response
            }
            Err(err) => {
                if let Some(source) = err.source() {
                    log.warn(format_args!("{err} ({source})"));
                } else {
                    log.warn(format_args!("{err}"));
                }
                *status = HttpStatus::Error;
                return Err(Failed)
            }
        };

        if response.status() == StatusCode::NOT_MODIFIED {
            Ok(None)
        }
        else if response.status() != StatusCode::OK {
            log.warn(format_args!(
                "Getting notification file failed with status {}",
                response.status()
            ));
            Err(Failed)
        }
        else {
            Notification::from_response(
                uri.clone(), response, delta_list_limit, log,
            ).map(Some)
        }
    }


    /// Creates a new notification from a successful HTTP response.
    ///
    /// Assumes that the response status was 200 OK.
    fn from_response(
        uri: uri::Https,
        response: HttpResponse,
        delta_list_limit: usize,
        log: &mut LogBookWriter,
    ) -> Result<Self, Failed> {
        let etag = response.etag();
        let last_modified = response.last_modified();
        let mut content = NotificationFile::parse_limited(
            io::BufReader::new(response), delta_list_limit
        ).map_err(|err| {
            log.warn(format_args!("{err}"));
            Failed
        })?;
        if !content.has_matching_origins(&uri) {
            log.warn(format_args!(
                "snapshot or delta files with different origin"
            ));
            return Err(Failed)
        }
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
    archive: &'a mut SnapshotRrdpArchive,

    /// The notification file pointing to the snapshot.
    notify: &'a Notification,

    /// The metrics for the update.
    metrics: &'a mut RrdpRepositoryMetrics,
}

impl<'a> SnapshotUpdate<'a> {
    pub fn new(
        collector: &'a Collector,
        archive: &'a mut SnapshotRrdpArchive,
        notify: &'a Notification,
        metrics: &'a mut RrdpRepositoryMetrics,
    ) -> Self {
        SnapshotUpdate { collector, archive, notify, metrics }
    }

    pub fn try_update(mut self) -> Result<(), SnapshotError> {
        let response = match self.collector.http().response(
            self.notify.content.snapshot().uri()
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
        reader.into_inner().verify_hash(
            self.notify.content.snapshot().hash()
        )?;
        self.archive.publish_state(
            &self.notify.to_repository_state(
                self.collector.config().fallback_time
            )
        )?;
        self.archive.finalize()?;
        Ok(())
    }
}

impl ProcessSnapshot for SnapshotUpdate<'_> {
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
        let content = LimitedDataRead::new(
            data, &uri, self.collector.config().max_object_size,
        ).read_all()?;
        self.archive.publish_object(&uri, &content).map_err(|err| match err {
            PublishError::AlreadyExists => {
                SnapshotError::DuplicateObject(uri.clone())
            }
            PublishError::Archive(ArchiveError::Corrupt(_)) => {
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
            self.info.uri()
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
        reader.into_inner().verify_hash(self.info.hash())?;
        Ok(())
    }
}

impl ProcessDelta for DeltaUpdate<'_> {
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
        let content = LimitedDataRead::new(
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

    /// Checks that the hash matches the provided hash.
    pub fn verify_hash(
        self, expected: rrdp::Hash
    ) -> Result<(), HashMismatch> {
        if self.context.finish().as_ref() != expected.as_ref() {
            Err(HashMismatch)
        }
        else {
            Ok(())
        }
    }
}


impl<R: io::Read> io::Read for HashRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        let res = self.reader.read(buf)?;
        self.context.update(&buf[..res]);
        Ok(res)
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

    /// The delta set in the notification file was too large.
    LargeDeltaSet,

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
            LargeDeltaSet => "large-delta-set",
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


//------------ HashMismatch --------------------------------------------------

/// The hash of a snapshot or delta didn’t match the expected value.
struct HashMismatch;


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
    LargeObject(String),
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

impl From<LimitedDataReadError> for SnapshotError {
    fn from(err: LimitedDataReadError) -> Self {
        match err {
            LimitedDataReadError::LargeObject(uri) => {
                SnapshotError::LargeObject(uri)
            }
            LimitedDataReadError::Read(err) => {
                SnapshotError::Rrdp(err.into())
            }
        }
    }
}

impl From<HashMismatch> for SnapshotError {
    fn from(_: HashMismatch) -> Self {
        Self::HashMismatch
    }
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SnapshotError::Http(ref err) => err.fmt(f),
            SnapshotError::HttpStatus(status) => {
                write!(f, "HTTP {status}")
            }
            SnapshotError::Rrdp(ref err) => err.fmt(f),
            SnapshotError::SessionMismatch { ref expected, ref received } => {
                write!(
                    f,
                    "session ID mismatch (notification_file: {expected}, \
                     snapshot file: {received}"
                )
            }
            SnapshotError::SerialMismatch { ref expected, ref received } => {
                write!(
                    f,
                    "serial number mismatch (notification_file: {expected}, \
                     snapshot file: {received}"
                )
            }
            SnapshotError::DuplicateObject(ref uri) => {
                write!(f, "duplicate object: {uri}")
            }
            SnapshotError::HashMismatch => {
                write!(f, "hash value mismatch")
            }
            SnapshotError::LargeObject(ref uri) => {
                write!(f, "object exceeds size limit: {uri}")
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
    LargeObject(String),
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

impl From<LimitedDataReadError> for DeltaError {
    fn from(err: LimitedDataReadError) -> Self {
        match err {
            LimitedDataReadError::LargeObject(uri) => {
                DeltaError::LargeObject(uri)
            }
            LimitedDataReadError::Read(err) => {
                DeltaError::Rrdp(err.into())
            }
        }
    }
}

impl From<HashMismatch> for DeltaError {
    fn from(_: HashMismatch) -> Self {
        Self::DeltaHashMismatch
    }
}

impl fmt::Display for DeltaError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DeltaError::Http(ref err) => err.fmt(f),
            DeltaError::HttpStatus(status) => {
                write!(f, "HTTP {status}")
            }
            DeltaError::Rrdp(ref err) => err.fmt(f),
            DeltaError::SessionMismatch { ref expected, ref received } => {
                write!(
                    f,
                    "session ID mismatch (notification_file: {expected}, \
                     snapshot file: {received}"
                )
            }
            DeltaError::SerialMismatch { ref expected, ref received } => {
                write!(
                    f,
                    "serial number mismatch (notification_file: {expected}, \
                     snapshot file: {received}"
                )
            }
            DeltaError::MissingObject { ref uri } => {
                write!(
                    f,
                    "reference to missing object {uri}"
                )
            }
            DeltaError::ObjectAlreadyPresent { ref uri } => {
                write!(
                    f,
                    "attempt to add already present object {uri}"
                )
            }
            DeltaError::ObjectHashMismatch { ref uri } => {
                write!(
                    f,
                    "local object {uri} has different hash"
                )
            }
            DeltaError::ObjectRepeated { ref uri } => {
                write!(f, "object appears multiple times: {uri}")
            }
            DeltaError::LargeObject(ref uri) => {
                write!(f, "object exceeds size limit: {uri}")
            }
            DeltaError::DeltaHashMismatch => {
                write!(f, "delta file hash value mismatch")
            }
            DeltaError::Archive(ref err) => {
                write!(f, "archive error: {err}")
            }
        }
    }
}

impl error::Error for DeltaError { }

