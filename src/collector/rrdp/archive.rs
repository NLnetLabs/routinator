use std::{cmp, io, fs};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use bytes::Bytes;
use chrono::{DateTime, TimeZone, Utc};
use log::{error, warn};
use rand::Rng;
use rpki::{rrdp, uri};
use uuid::Uuid;
use crate::config::Config;
use crate::error::RunFailed;
use crate::utils::archive;
use crate::utils::archive::{
    Archive, ArchiveError, FetchError, OpenError, PublishError
};
use crate::utils::binio::{Compose, Parse};


//------------ RrdpArchive ---------------------------------------------------

#[derive(Debug)]
pub struct RrdpArchive {
    /// The path where everything from this repository lives.
    path: Arc<PathBuf>,

    /// The archive for the repository.
    archive: archive::Archive<RrdpObjectMeta>,
}

impl RrdpArchive {
    pub fn create(
        path: Arc<PathBuf>
    ) -> Result<Self, RunFailed> {
        let archive = Archive::create(path.as_ref()).map_err(|err| {
            archive_err(err, path.as_ref())
        })?;
        Ok(Self { path, archive })
    }

    pub fn create_with_file(
        file: fs::File,
        path: Arc<PathBuf>,
    ) -> Result<Self, RunFailed> {
        let archive = Archive::create_with_file(file).map_err(|err| {
            archive_err(err, path.as_ref())
        })?;
        Ok(Self { path, archive })
    }

    pub fn try_open(path: Arc<PathBuf>) -> Result<Option<Self>, RunFailed> {
        let archive = match Archive::open(path.as_ref(), true) {
            Ok(archive) => archive,
            Err(OpenError::NotFound) => return Ok(None),
            Err(OpenError::Archive(err)) => {
                return Err(archive_err(err, path.as_ref()))
            }
        };
        Ok(Some(Self { path, archive }))
    }

    pub fn open(path: Arc<PathBuf>) -> Result<Self, RunFailed> {
        let archive = archive::Archive::open(
            path.as_ref(), false
        ).map_err(|err| match err {
            OpenError::NotFound => {
                warn!(
                    "RRDP repository file {} not found.", path.display()
                );
                RunFailed::retry()
            }
            OpenError::Archive(err) => archive_err(err, path.as_ref())
        })?;
        Ok(Self { path, archive })
    }

    pub fn path(&self) -> &Arc<PathBuf> {
        &self.path
    }
}

impl RrdpArchive {
    pub fn verify(path: &Path) -> Result<(), OpenError> {
        let archive = archive::Archive::<RrdpObjectMeta>::open(path, false)?;
        archive.verify()?;
        Ok(())
    }

    /// Loads an object from the archive.
    ///
    /// The object is identified by its rsync URI. If the object doesn’t
    /// exist, returns `None`.
    pub fn load_object(
        &self,
        uri: &uri::Rsync
    ) -> Result<Option<Bytes>, RunFailed> {
        let res = self.archive.fetch_bytes(uri.as_ref());
        match res {
            Ok(res) => Ok(Some(res)),
            Err(FetchError::NotFound) => Ok(None),
            Err(FetchError::Archive(err)) => {
                Err(archive_err(err, self.path.as_ref()))
            }
        }
    }

    /// Loads the repository state.
    ///
    /// Returns an error if the state is missing or broken.
    pub fn load_state(&self) -> Result<RepositoryState, RunFailed> {
        let data = match self.archive.fetch(b"state") {
            Ok(data) => data,
            Err(archive::FetchError::NotFound) => {
                return Err(
                    archive_err(ArchiveError::Corrupt, self.path.as_ref())
                )
            }
            Err(archive::FetchError::Archive(err)) => {
                return Err(archive_err(err, self.path.as_ref()))
            }
        };
        let mut data = data.as_ref();
        RepositoryState::parse(&mut data).map_err(|_| {
            archive_err(ArchiveError::Corrupt, self.path.as_ref())
        })
    }

    /// Iterates over all the objects in the repository.
    pub fn objects(
        &self
    ) -> Result<
        impl Iterator<Item = Result<(uri::Rsync, Bytes), RunFailed>> + '_,
        RunFailed
    > {
        self.archive.objects().map(|iter| {
            iter.filter_map(|item| {
                let (name, _meta, data) = match item {
                    Ok(some) => some,
                    Err(ArchiveError::Corrupt) => {
                        return Some(Err(RunFailed::retry()))
                    }
                    Err(ArchiveError::Io(_)) => {
                        return Some(Err(RunFailed::fatal()))
                    }
                };
                let name = uri::Rsync::from_bytes(
                    name.into_owned().into()
                ).ok()?;
                Some(Ok((name, data.into_owned().into())))
            })
        }).map_err(|err| {
            match err {
                ArchiveError::Corrupt => RunFailed::retry(),
                ArchiveError::Io(_) => RunFailed::fatal(),
            }
        })
    }
}

impl RrdpArchive {
    /// Publishes a new object to the archie.
    pub fn publish_object(
        &mut self,
        uri: &uri::Rsync,
        content: &[u8]
    ) -> Result<(), PublishError> {
        self.archive.publish(
            uri.as_ref(),
            &RrdpObjectMeta::from_content(content),
            content
        )
    }

    /// Updates an object in the archive.
    pub fn update_object(
        &mut self,
        uri: &uri::Rsync,
        hash: rrdp::Hash,
        content: &[u8]
    ) -> Result<(), AccessError> {
        Ok(self.archive.update(
            uri.as_ref(),
            &RrdpObjectMeta::from_content(content),
            content,
            |meta| {
                if meta.hash == hash {
                    Ok(())
                }
                else {
                    Err(HashMismatch)
                }
            }
        )?)
    }

    /// Deletes an object from the archive.
    pub fn delete_object(
        &mut self, uri: &uri::Rsync, hash: rrdp::Hash,
    ) -> Result<(), AccessError> {
        Ok(self.archive.delete(
            uri.as_ref(),
            |meta| {
                if meta.hash == hash {
                    Ok(())
                }
                else {
                    Err(HashMismatch)
                }
            }
        )?)
    }

    pub fn publish_state(
        &mut self, state: &RepositoryState
    ) -> Result<(), RunFailed> {
        let mut buf = Vec::new();
        state.compose(&mut buf).expect("writing to vec failed");
        self.archive.publish(
            b"state", &Default::default(), &buf
        ).map_err(|err| match err {
            archive::PublishError::Archive(ArchiveError::Io(err)) => {
                error!(
                    "Fatal: Failed write to RRDP repository archive {}: {}",
                    self.path.display(), err
                );
                RunFailed::fatal()
            }
            _ => {
                warn!(
                    "Failed to write local RRDP repository state in {}.",
                    self.path.display()
                );
                RunFailed::retry()
            }
        })
    }

    pub fn update_state(
        &mut self, state: &RepositoryState
    ) -> Result<(), RunFailed> {
        let mut buf = Vec::new();
        state.compose(&mut buf).expect("writing to vec failed");
        self.archive.update(
            b"state", &Default::default(), &buf,
            |_| Ok(())
        ).map_err(|err| match err {
            archive::AccessError::Archive(ArchiveError::Io(err)) => {
                error!(
                    "Fatal: Failed write to RRDP repository archive {}: {}",
                    self.path.display(), err
                );
                RunFailed::fatal()
            }
            _ => {
                warn!(
                    "Failed to update local RRDP repository state in {}.",
                    self.path.display()
                );
                RunFailed::retry()
            }
        })
    }
}


//------------ archive_err ---------------------------------------------------

fn archive_err(err: ArchiveError, path: &Path) -> RunFailed {
    match err {
        ArchiveError::Corrupt => {
            warn!(
                "RRDP repository file '{}' is corrupt. \
                Deleting and starting again.",
                path.display()
            );
            match fs::remove_file(path) {
                Ok(()) => {
                    RunFailed::retry()
                }
                Err(err) => {
                    warn!(
                        "Deleting RRDP repository archive '{}' failed: {}",
                        path.display(),
                        err
                    );
                    RunFailed::fatal()
                }
            }
        }
        ArchiveError::Io(err) => {
            error!(
                "Fatal: Failed to access RRDP repository archive '{}': {}",
                path.display(),
                err
            );
            RunFailed::fatal()
        }
    }
}


//------------ RrdpObjectMeta ------------------------------------------------

/// The meta data for an RRDP object.
#[derive(Clone, Copy, Debug)]
pub struct RrdpObjectMeta {
    hash: rrdp::Hash,
}

impl Default for RrdpObjectMeta {
    fn default() -> Self {
        Self {
            hash: [0; 32].into(),
        }
    }
}

impl RrdpObjectMeta {
    pub fn from_content(content: &[u8]) -> Self {
        Self {
            hash: rrdp::Hash::from_data(content)
        }
    }
}

impl archive::ObjectMeta for RrdpObjectMeta {
    const SIZE: usize = 32;

    type ConsistencyError = HashMismatch;

    fn write(
        &self, write: &mut archive::StorageWrite
    ) -> Result<(), ArchiveError> {
        write.write(self.hash.as_slice())
    }

    fn read(
        read: &mut archive::StorageRead
    ) -> Result<Self, ArchiveError> {
        Ok(Self { hash: read.read_array()?.into() })
    }
}


//------------ RepositoryState -----------------------------------------------

/// The current state of an RRDP repository.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryState {
    /// The rpkiNotify URI of the repository.
    pub rpki_notify: uri::Https,

    /// The UUID of the current session of repository.
    pub session: Uuid,

    /// The serial number within the current session.
    pub serial: u64,

    /// Unix timestamp in seconds of the time of last update of the server.
    ///
    /// We are not using `DateTime<Utc>` here since we don’t need sub-second
    /// precision and converting on the fly makes a value change when cycled
    /// through the database as its sub-second portion is forced to zero.
    pub updated_ts: i64,

    /// The time when we consider the stored data to be expired.
    pub best_before_ts: i64,

    /// The value of the date header of the notification file if present.
    ///
    /// Given as the Unix timestamp in seconds.
    pub last_modified_ts: Option<i64>,

    /// The value of the ETag header of the notification file if present.
    ///
    /// This is the complete tag including the quotation marks and possibly
    /// the weak prefix.
    pub etag: Option<Bytes>,

    /// Information of the deltas since in the last notificiation.
    pub delta_state: HashMap<u64, rrdp::Hash>,
}

impl RepositoryState {
    /// The current version of the data.
    ///
    /// This is 1 since version 0 was in the main branch for quite some time.
    const VERSION: u8 = 1;

    /// Reads the state from an IO reader.
    fn parse(reader: &mut impl io::Read) -> Result<Self, io::Error> {
        // Version number.
        let version = u8::parse(reader)?;
        if version != Self::VERSION {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("unexpected version {}", version)
            ))
        }

        Ok(RepositoryState {
            rpki_notify: Parse::parse(reader)?,
            session: Parse::parse(reader)?,
            serial: Parse::parse(reader)?,
            updated_ts: Parse::parse(reader)?,
            best_before_ts: Parse::parse(reader)?,
            last_modified_ts: Parse::parse(reader)?,
            etag: Parse::parse(reader)?,
            delta_state: Parse::parse(reader)?,
        })
    }

    /// Composes the encoded state.
    fn compose(&self, writer: &mut impl io::Write) -> Result<(), io::Error> {
        Self::VERSION.compose(writer)?; // version
        self.rpki_notify.compose(writer)?;
        self.session.compose(writer)?;
        self.serial.compose(writer)?;
        self.updated_ts.compose(writer)?;
        self.best_before_ts.compose(writer)?;
        self.last_modified_ts.compose(writer)?;
        self.etag.compose(writer)?;
        self.delta_state.compose(writer)?;
        Ok(())
    }

    /// Returns the last update time as proper timestamp.
    ///
    /// Returns `None` if the time cannot be converted into a timestamp for
    /// some reason.
    pub fn updated(&self) -> Option<DateTime<Utc>> {
        Utc.timestamp_opt(self.updated_ts, 0).single()
    }

    /// Returns the best before time as a proper timestamp.
    ///
    /// Returns `None` if the time cannot be converted into a timestamp for
    /// some reason.
    pub fn best_before(&self) -> Option<DateTime<Utc>> {
        Utc.timestamp_opt(self.best_before_ts, 0).single()
    }

    /// Sets the update time to now.
    pub fn touch(&mut self, fallback: FallbackTime) {
        self.updated_ts = Utc::now().timestamp();
        self.best_before_ts = fallback.best_before().timestamp();
    }

    /// Returns whether this repository should be considered expired.
    ///
    /// If in doubt, this will return `true`.
    pub fn is_expired(&self) -> bool {
        match self.best_before() {
            Some(best_before) => Utc::now() > best_before,
            None => true,
        }
    }

    /// Returns the last modified time.
    /// 
    /// Returns `None` if there we do not have a last modifed time or if
    /// it cannot be converted from a Unix timestamp into a date-time.
    pub fn last_modified(&self) -> Option<DateTime<Utc>> {
        self.last_modified_ts.and_then(|ts| Utc.timestamp_opt(ts, 0).single())
    }
}


//------------ FallbackTime --------------------------------------------------

/// Parameters for calculating the best-before time of repositories.
#[derive(Clone, Copy, Debug)]
pub struct FallbackTime {
    min: Duration,
    max: Duration,
}

impl FallbackTime {
    /// Creates a new value from the configuration.
    pub fn from_config(config: &Config) -> Self {
        FallbackTime {
            min: config.refresh,
            max: cmp::max(2 * config.refresh, config.rrdp_fallback_time)
        }
    }

    /// Picks a best-before date for a repository updated around now.
    pub fn best_before(self) -> DateTime<Utc> {
        // Saturating conversion between std’s and chrono’s Duration types.
        Utc::now() + chrono::Duration::from_std(
            rand::thread_rng().gen_range(self.min..self.max)
        ).unwrap_or_else(|_| {
            chrono::Duration::try_milliseconds(i64::MAX).unwrap()
        })
    }
}


//============ Errors ========================================================

//------------ HashMismatch --------------------------------------------------

#[derive(Debug)]
pub struct HashMismatch;


//------------ AccessError ---------------------------------------------------

/// An error happened while publishing an object.
#[derive(Debug)]
pub enum AccessError {
    /// The object does not exist.
    NotFound,

    /// The object’s hash is wrong
    HashMismatch,

    /// An error happened while trying to access the archive.
    Archive(ArchiveError),
}

impl From<archive::AccessError<HashMismatch>> for AccessError {
    fn from(err: archive::AccessError<HashMismatch>) -> Self {
        match err {
            archive::AccessError::NotFound => AccessError::NotFound,
            archive::AccessError::Inconsistent(_) => AccessError::HashMismatch,
            archive::AccessError::Archive(err) => AccessError::Archive(err),
        }
    }
}


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn compose_parse_repository_state() {
        let state = RepositoryState {
            rpki_notify: uri::Https::from_str(
                "https://foo.bar/baz"
            ).unwrap(),
            session: Uuid::from_u128(0xa1a2a3a4b1b2c1c2d1d2d3d4d5d6d7d8u128),
            serial: 0x1234567812345678u64,
            updated_ts: -12,
            best_before_ts: 123789123789123,
            last_modified_ts: Some(239123908123),
            etag: None,
            delta_state: [
                (18, rrdp::Hash::from_data(b"123")),
                (19, rrdp::Hash::from_data(b"332")),
            ].iter().cloned().collect(),
        };
        let mut buf = Vec::new();
        state.compose(&mut buf).unwrap();
        let parsed = RepositoryState::parse(&mut buf.as_slice()).unwrap();
        assert_eq!(state, parsed);
    }
}

