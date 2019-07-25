//! The local cache for a single RRDP server.
//!
//! This is a private module and exists only for organizational reasons.

use std::{fmt, fs, io, ops};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;
use bytes::Bytes;
use log::{info, warn};
use ring::digest;
use ring::constant_time::verify_slices_are_equal;
use rpki::uri;
use rpki::rrdp::{NotificationFile, UriAndHash};
use unwrap::unwrap;
use uuid::Uuid;
use crate::operation::Error;
use super::http::{DeltaTargets, HttpClient};
use super::utils::create_unique_dir;


//------------ Server --------------------------------------------------------

/// The local cache of an RRDP server.
///
/// Because values of this type are kept behind arcs, all methods here take
/// imutable selfs and all mutable state is wrapped accordingly.
#[derive(Debug)]
pub struct Server {
    /// The notification URI of the server.
    notify_uri: uri::Https,

    /// The local location of the server.
    ///
    /// This location is set when the server is initially created. It may or
    /// may actually exist.
    server_dir: ServerDir,

    /// Has this server been updated during the current validation run?
    updated: AtomicBool,

    /// Is this server currently unusable for whatever reason?
    ///
    /// If this is set, we don’t need to bother trying to load any files at
    /// all.
    broken: AtomicBool,

    /// A mutex to protect a running update.
    ///
    /// If an update run is warranted, try acquiring this mutex. When this
    /// succeeds, check whether an update is still necessary. If not, drop
    /// the mutex. If it is still necessary, perform the update, set the flags
    /// and drop the mutex.
    mutex: Mutex<()>,
}


impl Server {
    /// Creates a new server.
    fn new(
        notify_uri: uri::Https,
        server_dir: ServerDir,
        broken: bool
    ) -> Self {
        Server {
            notify_uri,
            server_dir,
            updated: AtomicBool::new(broken),
            broken: AtomicBool::new(broken),
            mutex: Mutex::new(())
        }
    }

    /// Creates a new server for an existing, not updated server.
    ///
    /// Assumes that the server directory exists. Marks the server as not
    /// yet updated.
    pub fn existing(notify_uri: uri::Https, server_dir: PathBuf) -> Self {
        Self::new(notify_uri, ServerDir::new(server_dir), false)
    }

    /// Creates a new server for a given notify URI.
    ///
    /// Creates the server’s local directory under `cache_dir` and leaves it
    /// at that. You need to call `update` to actually fetch the server’s
    /// data.
    ///
    /// This call will never fail but may leave the server marked as unusable
    /// if something goes wrong.
    pub fn create(notify_uri: uri::Https, cache_dir: &Path) -> Self {
        let (server_dir, broken) = match ServerDir::create(cache_dir) {
            Ok(server_dir) => (server_dir, true),
            Err(server_dir) => (server_dir, false),
        };
        Self::new(notify_uri, server_dir, broken)
    }

    /// Makes sure the server is up-to-date.
    ///
    /// If the server already has been updated, does nothing. Otherwise starts
    /// an update run.
    pub fn update(&self, http: &HttpClient) {
        // See if we need to update, get the lock, see if we need to update
        // again.
        if self.updated.load(Relaxed) {
            return
        }
        let _lock = unwrap!(self.mutex.lock());
        if self.updated.load(Relaxed) {
            return
        }

        if self._update(http).is_err() {
            self.check_broken();
        }
        self.updated.store(true, Relaxed);
    }

    /// Performs the actual update.
    ///
    /// Returns an error if the update fails.
    fn _update(&self, http: &HttpClient) -> Result<(), Error> {
        let mut notify = http.notification_file(&self.notify_uri)?;
        notify.deltas.sort_by_key(|delta| delta.0);
        if self.delta_update(&mut notify, http).is_ok() {
            return Ok(())
        }
        self.snapshot_update(&notify, http)
    }

    /// Try updating via the deltas.
    fn delta_update(
        &self,
        notify: &NotificationFile,
        http: &HttpClient
    ) -> Result<(), Error> {
        let mut state = ServerState::load(self.server_dir.state_path())?;
        let deltas = match Self::calc_deltas(notify, &state)? {
            Some(deltas) => deltas,
            None => return Ok(()),
        };
        let tmp_dir = self.move_to_tmp(http)?;
        let targets = self.collect_delta_targets(
            &state, notify, deltas, &tmp_dir, http
        );
        let targets = match targets {
            Ok(targets) => targets,
            Err(_) => {
                let _ = self.move_back(tmp_dir);
                return Err(Error)
            }
        };
        if let Err(_) = targets.apply() {
            let _ = fs::remove_dir_all(tmp_dir.base());
            return Err(Error);
        }
        state.serial = notify.serial;
        state.hash = match tmp_dir.digest() {
            Ok(hash) => hash.into(),
            Err(_) => {
                let _ = fs::remove_dir_all(tmp_dir.base());
                return Err(Error);
            }
        };
        if let Err(_) = state.save(tmp_dir.state_path()) {
            let _ = fs::remove_dir_all(tmp_dir.base());
            return Err(Error);
        }
        self.move_back(tmp_dir)
    }

    /// Calculates the slice of deltas to follow for updating.
    ///
    /// Returns an error if there is no way to delta update. Returns `Ok(None)`
    /// if no update is necessary. Returns a slice if a delta update should be
    /// done.
    fn calc_deltas<'a>(
        notify: &'a NotificationFile,
        state: &ServerState
    ) -> Result<Option<&'a [(usize, UriAndHash)]>, Error> {
        if notify.session_id != state.session {
            return Err(Error);
        }
        if notify.serial == state.serial {
            return Ok(None);
        }

        // If there is no last delta (remember, we have a different
        // serial than the notification file) or if the last delta’s
        // serial differs from that noted in the notification file,
        // bail out.
        if notify.deltas.last().map(|delta| delta.0) != Some(notify.serial) {
            return Err(Error)
        }

        let mut deltas = notify.deltas.as_slice();
        let serial = match state.serial.checked_add(1) {
            Some(serial) => serial,
            None => return Err(Error)
        };
        loop {
            let first = match deltas.first() {
                Some(first) => first,
                None => return Err(Error)
            };
            if first.0 > serial {
                return Err(Error)
            }
            else if first.0 == serial {
                break
            }
            else {
                deltas = &deltas[1..];
            }
        }
        Ok(Some(deltas))
    }

    /// Moves the content of the server directory to a new location.
    ///
    /// The location will be under `http.tmp_dir()`. The old server directory
    /// will remain present (just so no other process accidentally grabs it
    /// for a new server). Upon error, the original server directory should
    /// be considered broken, but we will try our best not to leave any
    /// garbage in the tmp dir.
    fn move_to_tmp(&self, http: &HttpClient) -> Result<ServerDir, Error> {
        let tmp_dir = match ServerDir::create(http.tmp_dir()) {
            Ok(dir) => dir,
            Err(_) => return Err(Error)
        };
        let state_res = fs::rename(
            self.server_dir.state_path(), tmp_dir.state_path()
        ).map_err(|err| {
            info!(
                "Failed to move RRDP state file '{}' to temporary location \
                '{}': {}.",
                self.server_dir.state_path().display(),
                tmp_dir.state_path().display(),
                err
            );
            Error
        });
        let data_res = fs::rename(
            self.server_dir.data_path(), tmp_dir.data_path()
        ).map_err(|err| {
            info!(
                "Failed to move RRDP data directory '{}' to temporary \
                 location '{}': {}.",
                self.server_dir.data_path().display(),
                tmp_dir.data_path().display(),
                err
            );
            Error
        });
        if state_res.is_err() || data_res.is_err() {
            let _ = fs::remove_dir_all(tmp_dir.base());
            Err(Error)
        }
        else {
            Ok(tmp_dir)
        }
    }

    /// Moves everything back from a temporary directory.
    fn move_back(&self, tmp_dir: ServerDir) -> Result<(), Error> {
        let state_res = fs::rename(
            tmp_dir.state_path(), self.server_dir.state_path()
        ).map_err(|err| {
            info!(
                "Failed to move RRDP state file '{}' from temporary location \
                '{}': {}.",
                self.server_dir.state_path().display(),
                tmp_dir.state_path().display(),
                err
            );
            Error
        });
        let data_res = fs::rename(
            tmp_dir.data_path(), self.server_dir.data_path()
        ).map_err(|err| {
            info!(
                "Failed to move RRDP data directory '{}' from temporary \
                 location '{}': {}.",
                self.server_dir.data_path().display(),
                tmp_dir.data_path().display(),
                err
            );
            Error
        });
        let _ = fs::remove_dir_all(tmp_dir.base());
        if state_res.is_err() || data_res.is_err() {
            Err(Error)
        }
        else {
            Ok(())
        }
    }

    /// Performs a delta update in the temporary location.
    fn collect_delta_targets(
        &self,
        state: &ServerState,
        notify: &NotificationFile,
        deltas: &[(usize, UriAndHash)],
        tmp_dir: &ServerDir,
        http: &HttpClient
    ) -> Result<DeltaTargets, Error> {
        tmp_dir.check_digest(&state.hash)?;
        let mut targets = DeltaTargets::new(http.tmp_dir())?;
        for delta in deltas {
            http.delta(
                &self.notify_uri, notify, delta, &mut targets,
                |uri| tmp_dir.uri_path(uri)
            )?
        }
        Ok(targets)
    }

    /// Try updating via the deltas.
    fn snapshot_update(
        &self,
        notify: &NotificationFile,
        http: &HttpClient
    ) -> Result<(), Error> {
        let tmp_dir = self.move_to_tmp(http)?;
        if let Err(_) = self.snapshot_into_tmp(notify, http, &tmp_dir) {
            let _ = fs::remove_dir_all(tmp_dir.base());
            return Err(Error);
        }
        self.move_back(tmp_dir)
    }

    fn snapshot_into_tmp(
        &self,
        notify: &NotificationFile,
        http: &HttpClient,
        tmp_dir: &ServerDir,
    ) -> Result<(), Error> {
        http.snapshot(notify, |uri| tmp_dir.uri_path(uri))?;
        let state = ServerState {
            notify_uri: self.notify_uri().clone(),
            session: notify.session_id,
            serial: notify.serial,
            hash: tmp_dir.digest()?.into(),
        };
        state.save(tmp_dir.state_path())
    }

    /// Checks whether the server in its current state is usable.
    ///
    /// For a server to be usable, it has to have a state file that can be
    /// read and its hash must match the current digest of the directory.
    ///
    /// Assumes that the server isn’t currently marked broken and sets the
    /// `broken` flag if anything is fishy.
    fn check_broken(&self) {
        let state = match ServerState::load(self.server_dir.state_path()) {
            Ok(state) => state,
            Err(_) => {
                info!(
                    "Cannot read state file, marking RRPD server '{}' as \
                    unusable",
                    self.notify_uri
                );
                self.broken.store(true, Relaxed);
                return;
            }
        };
        let digest = match self.server_dir.digest() {
            Ok(digest) => digest,
            Err(_) => {
                info!(
                    "Cannot digest RRPD server directory for '{}'. \
                    Marking as unsable.",
                    self.notify_uri
                );
                self.broken.store(true, Relaxed);
                return;
            }
        };
        if verify_slices_are_equal(digest.as_ref(), state.hash.as_ref())
                                                                   .is_err() {
            info!(
                "Hash for RRDP server directory for '{}' doesn’t match. \
                Marking as unusable.",
                self.notify_uri
            );
            self.broken.store(true, Relaxed);
        }
    }

    /// Returns a reference to the server’s notify URI.
    pub fn notify_uri(&self) -> &uri::Https {
        &self.notify_uri
    }

    /// Tries to load a file from this server.
    ///
    /// This assumes that the server is updated already. If there is no file
    /// corresponding to the URI, returns `None`.
    pub fn load_file(&self, uri: &uri::Rsync) -> Option<Bytes> {
        if self.broken.load(Relaxed) {
            return None
        }
        
        let path = self.server_dir.uri_path(uri);
        let mut file = match fs::File::open(&path) {
            Ok(file) => file,
            Err(err) => {
                if err.kind() == io::ErrorKind::NotFound {
                    info!("{} not found in its RRDP repository.", uri);
                }
                else {
                    warn!(
                        "Failed to open file '{}': {}.",
                        path.display(), err
                    );
                }
                return None
            }
        };
        let mut data = Vec::new();
        if let Err(err) = file.read_to_end(&mut data) {
            warn!(
                "Failed to read file '{}': {}",
                path.display(), err
            );
            return None
        }
        Some(data.into())
    }

    /// Removes the server’s local cache if it hasn’t been used.
    ///
    /// Returns whether it indeed removed the cache.
    pub fn remove_unused(&self) -> bool {
        unimplemented!()
    }
}


//------------ ServerDir -----------------------------------------------------

#[derive(Clone, Debug)]
struct ServerDir {
    base: PathBuf,
    state: PathBuf,
}

impl ServerDir {
    fn new(base: PathBuf) -> Self {
        ServerDir {
            state: base.join("state.txt"),
            base
        }
    }

    fn broken() -> Self {
        ServerDir {
            base: PathBuf::new(),
            state: PathBuf::new()
        }
    }

    fn create(cache_dir: &Path) -> Result<Self, Self> {
        match create_unique_dir(cache_dir) {
            Ok(path) => Ok(ServerDir::new(path)),
            Err(_) => Err(ServerDir::broken())
        }
   }

    fn base(&self) -> &Path {
        &self.base
    }

    fn state_path(&self) -> &Path {
        &self.state
    }

    fn data_path(&self) -> PathBuf {
        self.base.join("data")
    }

    fn module_path(&self, module: &uri::RsyncModule) -> PathBuf {
        let mut res = self.data_path();
        res.push(module.authority());
        res.push(module.module());
        res
    }

    fn uri_path(&self, uri: &uri::Rsync) -> PathBuf {
        let mut res = self.module_path(uri.module());
        res.push(uri.path());
        res
    }

    /// Determines the digest of a data directory.
    pub fn digest(&self) -> Result<digest::Digest, Error> {
        self._digest().map_err(|err| {
            info!(
                "Failed to caculate digest for '{}': {}",
                self.data_path().display(), err
            );
            Error
        })
    }

    fn _digest(&self) -> Result<digest::Digest, io::Error> {
        // A vec to keep the sorted content of a directory.
        //
        // When iterating a directory, we push the directories and regular
        // files into this vec as pairs of their full path and whether they
        // are a directory. Once we are done, we sort this vec by name and
        // then process it.
        let mut entries = Vec::new();

        // A stack with the directories we still have to process.
        //
        // The paths of directories in `entries` are push to the back of this
        // vec in their sorted order. When we are done with one directory, we
        // take the last one off the stack and process it. Rince and repeat
        // until the stack is empty.
        //
        // We start with the data directory itself.
        let mut dirs = vec![self.data_path()];

        // The digest context.
        let mut context = digest::Context::new(&digest::SHA256);

        // A buffer for reading files.
        let mut buf = [0u8; 4096];

        while let Some(dir) = dirs.pop() {
            for entry in dir.read_dir()? {
                let entry = entry?;
                let ftype = entry.file_type()?;
                if ftype.is_dir() {
                    entries.push((entry.path(), true))
                }
                else if ftype.is_file() {
                    entries.push((entry.path(), false))
                }
            }
            entries.sort_by(|left, right| left.cmp(right));

            for (path, is_dir) in entries.drain(..) {
                if is_dir {
                    dirs.push(path);
                }
                else {
                    let mut file = fs::File::open(path)?;
                    loop {
                        let read = file.read(&mut buf)?;
                        if read == 0 {
                            break
                        }
                        context.update(&buf[..read]);
                    }
                }
            }
        }
        Ok(context.finish())
    }

    /// Checks that the digest of the data directory matches the given one.
    pub fn check_digest(&self, hash: &DigestHex) -> Result<(), Error> {
        let digest = self.digest()?;
        verify_slices_are_equal(digest.as_ref(), hash.as_ref()).map_err(|_| {
            info!(
                "Mismatch of digest for '{}'. Content must have changed.",
                self.data_path().display()
            );
            Error
        })
    }
}


//------------ ServerState ---------------------------------------------------

#[derive(Clone, Debug)]
pub struct ServerState {
    /// The notify URI of the server.
    pub notify_uri: uri::Https,

    /// The UUID of the current session of this server.
    pub session: Uuid,

    /// The serial number representing the current state of the server.
    pub serial: usize,

    /// A hash over the expected local state of the server.
    pub hash: DigestHex,
}

impl ServerState {
    pub fn load(path: &Path) -> Result<Self, Error> {
        Self::_load(path).map_err(|err| {
            info!(
                "Failed to read state file '{}': {}",
                path.display(), err
            );
            Error
        })
    }

    fn _load(path: &Path) -> Result<Self, io::Error> {
        let file = BufReader::new(fs::File::open(path)?);
        let mut lines = file.lines();
        let res = ServerState {
            notify_uri: process_line(&mut lines, "notify-uri:")?,
            session: process_line(&mut lines, "session:")?,
            serial: process_line(&mut lines, "serial:")?,
            hash: process_line(&mut lines, "hash:")?,
        };
        if lines.next().is_some() {
            Err(io::Error::new(io::ErrorKind::InvalidData, "invalid data"))
        }
        else {
            Ok(res)
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), Error> {
        self._save(path).map_err(|err| {
            info!(
                "Failed to read state file '{}': {}",
                path.display(), err
            );
            Error
        })
    }

    fn _save(&self, path: &Path) -> Result<(), io::Error> {
        let mut file = fs::File::create(path)?;
        writeln!(
            file, "notify-uri: {}\nsession: {}\nserial: {}\n hash: {}",
            self.notify_uri, self.session, self.serial, self.hash
        )
    }

}

fn process_line<B: io::BufRead, T: FromStr>(
    lines: &mut io::Lines<B>, expected_key: &str
) -> Result<T, io::Error> {
    let line = lines.next().ok_or_else(||
        io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF")
    )??;
    let mut line = line.split_whitespace();
    let key = line.next().ok_or_else(||
        io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF")
    )?;
    if key != expected_key {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid data"
        ))
    }
    let value = line.next().ok_or_else(||
        io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF")
    )?;
    if line.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid data"
        ))
    }
    match T::from_str(value) {
        Ok(value) => Ok(value),
        Err(_) => Err(io::Error::new(io::ErrorKind::InvalidData, "bad value"))
    }
}


//------------ DigestHex -----------------------------------------------------

/// A helper type to encode a digest as a sequence of hex-digits.
#[derive(Clone, Debug)]
pub struct DigestHex(Vec<u8>);

impl From<Vec<u8>> for DigestHex {
    fn from(value: Vec<u8>) -> DigestHex {
        DigestHex(value)
    }
}

impl From<digest::Digest> for DigestHex {
    fn from(value: digest::Digest) -> DigestHex {
        DigestHex(Vec::from(value.as_ref()))
    }
}

impl FromStr for DigestHex {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut res = Vec::new();
        let mut s = s.chars();
        loop {
            let first = match s.next() {
                Some(first) => first.to_digit(16).ok_or("invalid digest")?,
                None => break
            };
            let second = s.next().ok_or("invalid digest")?
                .to_digit(16).ok_or("invalid digest")?;

            res.push((first << 8 | second) as u8);
        }
        Ok(DigestHex(res))
    }
}

impl ops::Deref for DigestHex {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsRef<[u8]> for DigestHex {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl fmt::Display for DigestHex {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for &ch in self.0.as_slice() {
            write!(f, "{:02x}", ch)?;
        }
        Ok(())
    }
}

