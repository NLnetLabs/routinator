//! The local cache for a single RRDP server.
//!
//! This is a private module and exists only for organizational reasons.

use std::{cmp, fs, io};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;
use std::time::SystemTime;
use bytes::Bytes;
use log::{info, warn};
use ring::digest;
use ring::constant_time::verify_slices_are_equal;
use rpki::uri;
use rpki::rrdp::{DigestHex, NotificationFile, UriAndHash};
use uuid::Uuid;
use crate::metrics::RrdpServerMetrics;
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
    ///
    /// Because the metrics are only used while updating (and after everything
    /// is done, anyway), we keep them inside the mutex.
    mutex: Mutex<RrdpServerMetrics>,
}


impl Server {
    /// Creates a new server.
    fn new(
        notify_uri: uri::Https,
        server_dir: ServerDir,
        broken: bool
    ) -> Self {
        Server {
            mutex: Mutex::new(RrdpServerMetrics::new(notify_uri.clone())),
            notify_uri,
            server_dir,
            updated: AtomicBool::new(broken),
            broken: AtomicBool::new(broken),
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
            Ok(server_dir) => (server_dir, false),
            Err(server_dir) => (server_dir, true),
        };
        Self::new(notify_uri, server_dir, broken)
    }

    /// Returns a reference to the server directory.
    pub fn server_dir(&self) -> &Path {
        &self.server_dir.base
    }

    /// Returns whether the server has been updated.
    pub fn is_current(&self) -> bool {
        self.updated.load(Relaxed)
    }

    /// Makes sure the server is up-to-date.
    ///
    /// If the server already has been updated, does nothing. Otherwise starts
    /// an update run.
    pub fn update(&self, http: &HttpClient) {
        // See if we need to update, get the lock, see if we still need to
        // update.
        if self.updated.load(Relaxed) {
            return
        }
        let mut metrics = self.mutex.lock().unwrap();
        if self.updated.load(Relaxed) {
            return
        }

        let start_time = SystemTime::now();
        if self.try_update(http, &mut metrics).is_err() && self.check_broken() {
            let _ = fs::remove_dir_all(self.server_dir.base());
        }
        self.updated.store(true, Relaxed);
        metrics.duration = SystemTime::now().duration_since(start_time);
    }

    /// Performs the actual update.
    ///
    /// Returns an error if the update fails.
    fn try_update(
        &self,
        http: &HttpClient,
        metrics: &mut RrdpServerMetrics
    ) -> Result<(), Error> {
        info!("RRDP {}: Updating server", self.notify_uri);
        metrics.serial = None;
        let notify = http.notification_file(
            &self.notify_uri, &mut metrics.notify_status
        )?;
        if self.delta_update(&notify, http, metrics).is_ok() {
            info!("RRDP {}: Delta update succeeded.", self.notify_uri);
            return Ok(())
        }
        self.snapshot_update(&notify, http, metrics)
    }

    /// Try updating via the deltas.
    fn delta_update(
        &self,
        notify: &NotificationFile,
        http: &HttpClient,
        metrics: &mut RrdpServerMetrics
    ) -> Result<(), Error> {
        let mut state = ServerState::load(self.server_dir.state_path())?;
        let deltas = match Self::calc_deltas(notify, &state)? {
            Some(deltas) => deltas,
            None => {
                return self.server_dir.check_digest(&state.hash)
            }
        };
        let targets = self.collect_delta_targets(
            &state, notify, deltas, http
        );
        let targets = match targets {
            Ok(targets) => targets,
            Err(_) => {
                return Err(Error)
            }
        };
        self.server_dir.check_digest(&state.hash)?;
        if targets.apply().is_err() {
            return Err(Error);
        }
        state.serial = notify.serial;
        state.hash = match self.server_dir.digest() {
            Ok(hash) => hash.into(),
            Err(_) => {
                return Err(Error);
            }
        };
        if state.save(self.server_dir.state_path()).is_err() {
            return Err(Error);
        }
        metrics.serial = Some(state.serial);
        Ok(())
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
            info!("New session. Need to get snapshot.");
            return Err(Error);
        }
        info!("Serials: us {}, them {}", state.serial, notify.serial);
        if notify.serial == state.serial {
            return Ok(None);
        }

        // If there is no last delta (remember, we have a different
        // serial than the notification file) or if the last delta’s
        // serial differs from that noted in the notification file,
        // bail out.
        if notify.deltas.last().map(|delta| delta.0) != Some(notify.serial) {
            info!("Last delta serial differs from current serial.");
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
                None => {
                    info!("Ran out of deltas.");
                    return Err(Error)
                }
            };
            match first.0.cmp(&serial) {
                cmp::Ordering::Greater => {
                    info!("First delta is too new ({})", first.0);
                    return Err(Error)
                }
                cmp::Ordering::Equal => break,
                cmp::Ordering::Less => deltas = &deltas[1..]
            }
        }
        Ok(Some(deltas))
    }

    /// Performs a delta update in the temporary location.
    fn collect_delta_targets(
        &self,
        state: &ServerState,
        notify: &NotificationFile,
        deltas: &[(usize, UriAndHash)],
        http: &HttpClient
    ) -> Result<DeltaTargets, Error> {
        self.server_dir.check_digest(&state.hash)?;
        let mut targets = DeltaTargets::new(http.tmp_dir())?;
        for delta in deltas {
            http.delta(
                &self.notify_uri, notify, delta, &mut targets,
                |uri| self.server_dir.uri_path(uri)
            )?
        }
        Ok(targets)
    }

    /// Try updating via the deltas.
    fn snapshot_update(
        &self,
        notify: &NotificationFile,
        http: &HttpClient,
        metrics: &mut RrdpServerMetrics
    ) -> Result<(), Error> {
        info!("RRDP {}: updating from snapshot.", self.notify_uri);
        let tmp_dir = ServerDir::create(http.tmp_dir()).map_err(|_| Error)?;
        let state =  match self.snapshot_into_tmp(notify, http, &tmp_dir) {
            Ok(state) => state,
            Err(_) => {
                let _ = fs::remove_dir_all(tmp_dir.base());
                return Err(Error);
            }
        };
        self.move_from_tmp(tmp_dir)?;
        metrics.serial = Some(state.serial);
        Ok(())
    }

    fn snapshot_into_tmp(
        &self,
        notify: &NotificationFile,
        http: &HttpClient,
        tmp_dir: &ServerDir,
    ) -> Result<ServerState, Error> {
        http.snapshot(notify, |uri| tmp_dir.uri_path(uri))?;
        let state = ServerState {
            notify_uri: self.notify_uri().clone(),
            session: notify.session_id,
            serial: notify.serial,
            hash: tmp_dir.digest()?.into(),
        };
        state.save(tmp_dir.state_path())?;
        Ok(state)
    }

    /// Moves everything back from a temporary directory.
    fn move_from_tmp(&self, tmp_dir: ServerDir) -> Result<(), Error> {
        let _ = fs::remove_file(self.server_dir.state_path());
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
        let _ = fs::remove_dir_all(self.server_dir.data_path());
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

    /// Checks whether the server in its current state is usable.
    ///
    /// For a server to be usable, it has to have a state file that can be
    /// read and its hash must match the current digest of the directory.
    ///
    /// Assumes that the server isn’t currently marked broken and sets the
    /// `broken` flag if anything is fishy.
    fn check_broken(&self) -> bool {
        let state = match ServerState::load(self.server_dir.state_path()) {
            Ok(state) => state,
            Err(_) => {
                info!(
                    "Marking RRPD server '{}' as unusable",
                    self.notify_uri
                );
                self.broken.store(true, Relaxed);
                return true;
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
                return true;
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
            true
        }
        else {
            false
        }
    }

    /// Returns a reference to the server’s notify URI.
    pub fn notify_uri(&self) -> &uri::Https {
        &self.notify_uri
    }

    /// Returns whether the server is broken.
    pub fn is_broken(&self) -> bool {
        self.broken.load(Relaxed)
    }

    /// Tries to load a file from this server.
    ///
    /// This assumes that the server is updated already. If there is no file
    /// corresponding to the URI, returns `None`.
    #[allow(clippy::verbose_file_reads)]
    pub fn load_file(&self, uri: &uri::Rsync) -> Result<Option<Bytes>, Error> {
        if self.broken.load(Relaxed) {
            return Err(Error)
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
                return Ok(None)
            }
        };
        let mut data = Vec::new();
        if let Err(err) = file.read_to_end(&mut data) {
            warn!(
                "Failed to read file '{}': {}",
                path.display(), err
            );
            return Ok(None)
        }
        Ok(Some(data.into()))
    }

    /// Removes the server’s local cache if it hasn’t been used.
    ///
    /// Returns whether it indeed removed the cache.
    pub fn remove_unused(&self) -> bool {
        if self.updated.load(Relaxed) && !self.broken.load(Relaxed) {
            return false
        }
        let _ = fs::remove_dir_all(self.server_dir.base());
        true
    }

    /// Return the server metrics if the server was ever updated.
    pub fn metrics(&self) -> Option<RrdpServerMetrics> {
        if self.updated.load(Relaxed) {
            match self.mutex.try_lock() {
                Ok(metrics) => Some(metrics.clone()),
                Err(err) => {
                    panic!("Failed to acquire metrics lock: {}", err);
                }
            }
        }
        else {
            None
        }
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
        // files into this vec as pairs. The first item in the pair is the
        // file name within the parent directory. The second item is a result.
        // Directories will have `Ok(path)` where `path` is their full path.
        // Regular files will have `Err(len)` where `len` is their file size.
        //
        // After adding, will sort by the file name and then hash the entries.
        // For each item we hash the name. For files we also hash the size.
        let mut entries = Vec::new();

        // A stack with the directories we still have to process.
        //
        // The paths of directories in `entries` are pushed to the back of this
        // vec in their sorted order. When we are done with one directory, we
        // take the last one off the stack and process it. Rince and repeat
        // until the stack is empty.
        //
        // We start with the data directory itself.
        let mut dirs = vec![self.data_path()];

        // The digest context.
        let mut context = digest::Context::new(&digest::SHA256);

        while let Some(dir) = dirs.pop() {
            for entry in dir.read_dir()? {
                let entry = entry?;
                let metadata = entry.metadata()?;
                let name = entry.file_name();
                if metadata.is_dir() {
                    entries.push((name, Ok(entry.path())))
                }
                else if metadata.is_file() {
                    entries.push((name, Err(metadata.len())))
                }
            }
            entries.sort_by(|left, right| left.0.cmp(&right.0));

            for (name, other) in entries.drain(..) {
                context.update(name.to_string_lossy().as_bytes());
                
                match other {
                    Ok(path) => dirs.push(path),
                    Err(len) => context.update(&len.to_ne_bytes()),
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
            // Not found is mostly normal, don’t complain about that.
            if err.kind() != io::ErrorKind::NotFound {
                info!(
                    "Failed to read state file '{}': {}",
                    path.display(), err
                );
            }
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
                "Failed to read write file '{}': {}",
                path.display(), err
            );
            Error
        })
    }

    fn _save(&self, path: &Path) -> Result<(), io::Error> {
        let mut file = fs::File::create(path)?;
        writeln!(
            file, "notify-uri: {}\nsession: {}\nserial: {}\nhash: {}",
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

