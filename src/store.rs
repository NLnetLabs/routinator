//! A store for correctly published RPKI objects.
//!
//! To be more resistant against accidental or malicious errors in the data
//! published by repositories, we retain a separate copy of all RPKI data that
//! has been found to be covered by a valid manifest in what we call the
//! _store._ The types in this module provide access to this store.
//!
//! The store is initialized and configured via [`Store`]. During validation,
//! [`Run`] is used which can be aquired from the store via the
//! [`start`][Store::start] method. It provides access to the trust anchor
//! certificates via the [`load_ta`][Run::load_ta] and
//! [`update_ta`][Run::update_ta] methods individual repositories and
//! publication points via [`repository`][Run::repository] and
//! [`pub_point`][Run::pub_point], respectively. These are represented by the
//! [`Repository`] and [`StoredPoint`] types.
//!
//! # Error Handling
//!
//! Pretty much all methods and functions provided by this module can return
//! an error. This is because the store uses files and that can go wrong in
//! all kinds of ways at any time. The concrete error reason is logged and our
//! generic [`Failed`][crate::error::Failed] is returned. When this happens,
//! the store should be considered broken and not be used anymore.
//!
//! # Data Storage
//!
//! The store uses the file system to store its data. Each repository has a
//! directory of its own. For RRDP, the directory is named after the SHA-256
//! hash of the rpkiNotify URI. For rsync there is only one directory, called
//! `rsync`.
//!
//! Within each repository, all the objects of a publication point are stored
//! in a single file. This file is named using the manifest’s signedObject
//! URI (i.e., where the manifest would be found if the rsync repository
//! would be used). The file contains information about the manifest, the CRL,
//! and each object listed on the manifest.

use std::{error, fs, io};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use bytes::Bytes;
use chrono::{TimeZone, Utc};
use log::{error, warn};
use rand::random;
use rpki::repository::Cert;
use rpki::repository::crypto::digest::DigestAlgorithm;
use rpki::repository::manifest::ManifestHash;
use rpki::repository::tal::TalUri;
use rpki::repository::x509::{Time, ValidationError};
use rpki::uri;
use crate::collector;
use crate::config::Config;
use crate::engine::CaCert;
use crate::error::Failed;
use crate::metrics::Metrics;
use crate::utils::binio::{Compose, Parse};
use crate::utils::dump::DumpRegistry;
use crate::utils::json::JsonBuilder;


//------------ Store ---------------------------------------------------------

/// A store for correctly published RPKI objects.
///
/// The store retains a copy of curated, published RPKI data. Its intended use
/// is for keeping the most recent data of a given RPKI publication point that
/// was found to be correctly published. However, the store doesn’t enforce
/// this, and can be used for other purposes as well.
///
/// A store can be created via the [`new`][Store::new] function which will
/// initialize a new store on disk if necessary and open it. If you only want
/// to make sure that the store is initilized without actually using it,
/// the [`init`][Store::init] function can be used.
///
/// To use the store during a validation run, the [`start`][Store::start]
/// method is used. It returns a [`Run`] object providing actual access to
/// the store.
#[derive(Clone, Debug)]
pub struct Store {
    /// The base path for the store.
    path: PathBuf,
}

impl Store {
    /// Returns the base path for the given config.
    fn create_base_dir(config: &Config) -> Result<PathBuf, Failed> {
        // We are using "stored" since store was foolishly used in 0.9.0 for
        // the database.
        let path = config.cache_dir.join("stored");
        if let Err(err) = fs::create_dir_all(&path) {
            error!(
                "Failed to create store directory {}: {}",
                path.display(), err
            );
            return Err(Failed)
        }
        Ok(path)
    }

    /// Initializes the store without creating a value.
    ///
    /// Ensures that the base directory exists and creates it of necessary.
    ///
    /// The function is called implicitly by [`new`][Self::new].
    pub fn init(config: &Config) -> Result<(), Failed> {
        Self::create_base_dir(config)?;
        Ok(())
    }

    /// Creates a new store at the given path.
    pub fn new(config: &Config) -> Result<Self, Failed> {
        Ok(Store {
            path: Self::create_base_dir(config)?,
        })
    }

    /// Start a validation run with the store.
    pub fn start(&self) -> Run {
        Run::new(self)
    }

    /// Cleans up the store.
    ///
    /// All publication points that have an expired manifest will be removed.
    /// RRDP repositories that have no more publication points are removed,
    /// too.
    ///
    /// The method also triggers a cleanup of the collector via the provided
    /// collector cleanup object. All RRDP repositories and rsync modules that
    /// have still non-expired publication points will be registered to be
    /// retained with the collector cleanup and then a cleaning run is
    /// started.
    pub fn cleanup(
        &self,
        mut collector: Option<collector::Cleanup>,
    ) -> Result<(), Failed> {
        self.cleanup_ta()?;
        self.cleanup_rrdp(collector.as_mut())?;
        self.cleanup_rsync(collector.as_mut())?;
        self.cleanup_tmp()?;
        if let Some(collector) = collector {
            collector.commit()?;
        }
        Ok(())
    }

    /// Cleans up the trust anchors.
    ///
    /// Deletes all files that either don’t successfully parse as certificates
    /// or that are expired certificates.
    fn cleanup_ta(&self) -> Result<(), Failed> {
        cleanup_dir_tree(&self.path.join("ta"), |path| {
            let mut content = Vec::new();
            File::open(&path)?.read_to_end(&mut content)?;
            if let Ok(cert) = Cert::decode(Bytes::from(content)) {
                if cert.validity().not_after() > Time::now() {
                    return Ok(true)
                }
            }
            Ok(false)
        })
    }

    /// Cleans up the RRDP repositories.
    ///
    /// Deletes all publication points with an expired manifest as well as
    /// any obviously garbage files. The RRDP repository of any publication
    /// point that is retained is registered to be retained by the collector.
    fn cleanup_rrdp(
        &self,
        mut collector: Option<&mut collector::Cleanup>
    ) -> Result<(), Failed> {
        cleanup_dir_tree(&self.rrdp_repository_base(), |path| {
            if let Ok(stored) = StoredManifest::read(&mut File::open(&path)?) {
                if let Some(uri) = stored.retain_rrdp() {
                    if let Some(cleanup) = collector.as_mut() {
                        cleanup.retain_rrdp_repository(&uri)
                    }
                    return Ok(true)
                }
            }
            Ok(false)
        })
    }

    fn cleanup_rsync(
        &self,
        mut collector: Option<&mut collector::Cleanup>
    ) -> Result<(), Failed> {
        cleanup_dir_tree(&self.rsync_repository_path(), |path| {
            if let Ok(stored) = StoredManifest::read(&mut File::open(&path)?) {
                if let Some(uri) = stored.retain_rsync() {
                    if let Some(cleanup) = collector.as_mut() {
                        cleanup.retain_rsync_module(&uri)
                    }
                    return Ok(true)
                }
            }
            Ok(false)
        })
    }

    fn cleanup_tmp(&self) -> Result<(), Failed> {
        cleanup_dir_tree(&self.path.join("tmp"), |_path| {
            Ok(false)
        })
    }

    /// Dumps the content of the store.
    pub fn dump(&self, dir: &Path) -> Result<(), Failed> {
        let dir = dir.join("stored");

        if let Err(err) = fs::remove_dir_all(&dir) {
            if err.kind() != io::ErrorKind::NotFound {
                error!(
                    "Failed to delete directory {}: {}",
                    dir.display(), err
                );
                return Err(Failed)
            }
        }

        let mut repos = DumpRegistry::new(dir);
        self.dump_tree(&self.rsync_repository_path(), &mut repos)?;
        self.dump_tree(&self.rrdp_repository_base(), &mut repos)?;
        self.dump_repository_json(repos)?;
        Ok(())
    }

    /// Dumps all the stored points found in the tree under `path`.
    ///
    /// The point’s repository and rsync URI is determined from the stored
    /// points themselves. The target path is being determined from `repos`.
    fn dump_tree(
        &self,
        path: &Path,
        repos: &mut DumpRegistry,
    ) -> Result<(), Failed> {
        for_each_file(path, |path| {
            self.dump_point(path, repos)
        })
    }

    /// Dumps all data for a single stored publication point.
    fn dump_point(
        &self,
        path: &Path,
        repos: &mut DumpRegistry,
    ) -> Result<(), Failed> {
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(err) => {
                error!(
                    "Fatal: failed to open file {}: {}",
                    path.display(), err
                );
                return Err(Failed)
            }
        };
        let manifest = match StoredManifest::read(&mut file) {
            Ok(some) => some,
            Err(err) => {
                error!(
                    "Skipping {}: failed to read file: {}",
                    path.display(), err
                );
                return Ok(())
            }
        };

        let repo_dir = repos.get_repo_path(manifest.rpki_notify.as_ref());

        self.dump_object(
            &repo_dir, &manifest.manifest_uri, &manifest.manifest
        )?;
        self.dump_object(&repo_dir, &manifest.crl_uri, &manifest.crl)?;

        loop {
            let object = match StoredObject::read(&mut file) {
                Ok(Some(object)) => object,
                Ok(None) => break,
                Err(err) => {
                    warn!(
                        "Partially skipping {}: failed to read file: {}",
                        path.display(), err
                    );
                    return Ok(())
                }
            };
            self.dump_object(&repo_dir, &object.uri, &object.content)?;
        }

        Ok(())
    }

    /// Writes the data of a single object.
    fn dump_object(
        &self,
        dir: &Path,
        uri: &uri::Rsync,
        content: &[u8]
    ) -> Result<(), Failed> {
        let path = dir.join(
            format!("{}/{}/{}",
                uri.canonical_authority(),
                uri.module_name(),
                uri.path()
            )
        );
        if let Some(dir) = path.parent() {
            if let Err(err) = fs::create_dir_all(&dir) {
                error!(
                    "Fatal: cannot create directory {}: {}",
                    dir.display(), err
                );
                return Err(Failed)
            }
        }
        let mut target = match File::create(&path) {
            Ok(some) => some,
            Err(err) => {
                error!(
                    "Fatal: cannot create target file {}: {}",
                    path.display(), err
                );
                return Err(Failed)
            }
        };
        if let Err(err) = target.write_all(content) {
            error!(
                "Fatal: failed to write to target file {}: {}",
                path.display(), err
            );
            return Err(Failed)
        }

        Ok(())
    }


    /// Writes the repositories.json file.
    fn dump_repository_json(
        &self,
        repos: DumpRegistry,
    ) -> Result<(), Failed> {
        let path = repos.base_dir().join("repositories.json");
        if let Err(err) = fs::write(
            &path, 
            &JsonBuilder::build(|builder| {
                builder.member_array("repositories", |builder| {
                    for (key, value) in repos.rrdp_uris() {
                        builder.array_object(|builder| {
                            builder.member_str(
                                "path", value
                            );
                            builder.member_str("type", "rrdp");
                            builder.member_str(
                                "rpkiNotify",
                                key
                            );
                        })
                    }
                    builder.array_object(|builder| {
                        builder.member_str("path", "rsync");
                        builder.member_str("type", "rsync");
                    });
                })
            })
        ) {
            error!( "Failed to write {}: {}", path.display(), err);
            return Err(Failed)
        }

        Ok(())
    }

    fn ta_path(&self, uri: &TalUri) -> PathBuf {
        match *uri {
            TalUri::Rsync(ref uri) => {
                self.path.join(format!(
                    "ta/rsync/{}/{}/{}",
                    uri.canonical_authority(),
                    uri.module_name(),
                    uri.path()
                ))
            }
            TalUri::Https(ref uri) => {
                self.path.join(format!(
                    "ta/https/{}/{}",
                    uri.canonical_authority(),
                    uri.path()
                ))
            }
        }
    }

    const RRDP_BASE: &'static str = "rrdp";

    fn rrdp_repository_base(&self) -> PathBuf {
        self.path.join(Self::RRDP_BASE)
    }

    fn rrdp_repository_path(&self, uri: &uri::Https) -> PathBuf {
        let authority = uri.canonical_authority();
        let alg = DigestAlgorithm::sha256();
        let mut dir = String::with_capacity(
            Self::RRDP_BASE.len()
            + authority.len()
            + alg.digest_len()
            + 2 // two slashes
        );
        dir.push_str(Self::RRDP_BASE);
        dir.push('/');
        dir.push_str(&authority);
        dir.push('/');
        for &ch in alg.digest(uri.as_slice()).as_ref() {
            // Unwraps here are fine after the `& 0x0F`.
            dir.push(char::from_digit(((ch >> 4) & 0x0F).into(), 16).unwrap());
            dir.push(char::from_digit((ch & 0x0F).into(), 16).unwrap());
        }
        self.path.join(dir)
    }

    fn rsync_repository_path(&self) -> PathBuf {
        self.path.join("rsync")
    }

    fn tmp_file(&self) -> Result<(PathBuf, File), Failed> {
        let tmp_dir = self.path.join("tmp");
        if let Err(err) = fs::create_dir_all(&tmp_dir) {
            error!(
                "Fatal: cannot create directory at {}: {}",
                tmp_dir.display(), err
            );
            return Err(Failed)
        }
        for _ in 0..100 {
            let tmp_path = tmp_dir.join(format!("{:08x}", random::<u32>()));
            let file = {
                fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp_path)
            };
            match file {
                Ok(file) => return Ok((tmp_path, file)),
                Err(ref err) if err.kind() == io::ErrorKind::AlreadyExists => {
                    continue
                }
                Err(err) => {
                    error!(
                        "Fatal: failed to create temporary file {}: {}",
                        tmp_path.display(), err
                    );
                    return Err(Failed)
                }
            }
        }

        error!(
            "Fatal: repeatedly failed to create temporary file in {}",
            tmp_dir.display()
        );
        Err(Failed)
    }
}


//------------ Run -----------------------------------------------------------

/// A single validation run on using the store.
///
/// The type provides access to the stored versions of trust anchor
/// certificates via the [`load_ta`][Self::load_ta] method and repositories
/// through the [`repository`][Self::repository] method and its more specific
/// friends [`rrdp_repository`][Self::rrdp_repository] and
/// [`rsync_repository`][Self::rsync_repository].
///
/// Stored trust anchor certificates can be updated via
/// [`update_ta`][Self::update_ta] on [`Run`] directly, while the
/// [`Repository`] provides means to that for all other data.
///
/// This type references the underlying [`Store`]. It can be used with
/// multiple threads using
/// [crossbeam’s][https://github.com/crossbeam-rs/crossbeam] scoped threads.
#[derive(Debug)]
pub struct Run<'a> {
    /// A reference to the underlying store.
    store: &'a Store,
}

impl<'a> Run<'a> {
    /// Creates a new runner from a store.
    fn new(
        store: &'a Store,
    ) -> Self {
        Run { store }
    }

    /// Finishes the validation run.
    ///
    /// Updates the `metrics` with the store run’s metrics.
    ///
    /// If you are not interested in the metrics, you can simple drop the
    /// value, instead.
    pub fn done(self, _metrics: &mut Metrics) {
    }

    /// Loads a stored trust anchor certificate.
    pub fn load_ta(&self, uri: &TalUri) -> Result<Option<Bytes>, Failed> {
        let path = self.store.ta_path(uri);
        match fs::read(&path) {
            Ok(res) => Ok(Some(res.into())),
            Err(ref err) if err.kind() == io::ErrorKind::NotFound => {
                Ok(None)
            }
            Err(err) => {
                error!(
                    "Fatal: failed to read from file {}: {}",
                    path.display(), err
                );
                Err(Failed)
            }
        }
    }

    /// Updates or inserts a stored trust anchor certificate.
    pub fn update_ta(
        &self, uri: &TalUri, content: &[u8]
    ) -> Result<(), Failed> {
        let path = self.store.ta_path(uri);
        if let Some(dir) = path.parent() {
            if let Err(err) = fs::create_dir_all(&dir) {
                error!(
                    "Fatal: failed to create directory {}: {}",
                    dir.display(), err
                );
                return Err(Failed)
            }
        }
        fs::write(&path, content).map_err(|err| {
            error!(
                "Fatal: failed to write to file {}: {}",
                path.display(), err
            );
            Failed
        })
    }

    /// Accesses the repository for the provided PRKI CA.
    ///
    /// If the CA’s rpkiNotify URI is present, the RRDP repository identified
    /// by that URI will be returned, otherwise the rsync repository will be
    /// used.
    ///
    /// Note that we even use the RRDP repository if the collector had to fall
    /// back to using rsync. Because rsync is ‘authoritative’ for the object
    /// URIs, it is safe to use objects received via rsync in RRDP
    /// repositories.
    pub fn repository(&self, ca_cert: &CaCert) -> Repository<'a> {
        let (path, rrdp) = if let Some(rpki_notify) = ca_cert.rpki_notify() {
            (self.store.rrdp_repository_path(rpki_notify), true)
        }
        else {
            (self.store.rsync_repository_path(), false)
        };
        Repository::new(self.store, path, rrdp)
    }

    /// Accesses the publication point for the provided RPKI CA.
    ///
    /// If the CA’s rpkiNotify URI is present, the RRDP repository identified
    /// by that URI will be returned, otherwise the rsync repository will be
    /// used.
    ///
    /// Note that we even use the RRDP repository if the collector had to fall
    /// back to using rsync. Because rsync is ‘authoritative’ for the object
    /// URIs, it is safe to use objects received via rsync in RRDP
    /// repositories.
    pub fn pub_point(
        &self, ca_cert: &CaCert
    ) -> Result<StoredPoint<'a>, Failed> {
        self.repository(ca_cert).get_point(ca_cert.rpki_manifest())
    }
}


//------------ Repository ----------------------------------------------------

/// Access to a single repository during a validation run.
///
/// A repository is a collection of publication points. Each of these points
/// has a manifest and a set of objects. The manifest is identified by its
/// signedObject URI while the objects are identified by their name on the
/// manifest’s object list.
///
/// You can get access to a publication point via
/// [`get_point`][Self::get_point] and delete one via
/// [`remove_point`][Self::remove_point].
///
pub struct Repository<'a> {
    /// The store we are part of.
    store: &'a Store,

    /// The path where the repository lives.
    path: PathBuf,

    /// Are we using an rrdp tree?
    is_rrdp: bool,
}

impl<'a> Repository<'a> {
    /// Creates a repository object on a store using the given tree names.
    fn new(store: &'a Store, path: PathBuf, is_rrdp: bool) -> Self {
        Repository { store, path, is_rrdp }
    }

    /// Returns whether this is an RRDP repository.
    pub fn is_rrdp(&self) -> bool {
        self.is_rrdp
    }

    /// Opens the given stored publication point.
    ///
    /// The publication point is identified through the rsync URI of its
    /// manifest.
    ///
    /// A stored point instance will be returned whether there actually is
    /// information stored for the point or not. You can use
    /// [`StoredPoint::exists`] to check if there is previously stored
    /// information.
    pub fn get_point(
        &self, manifest_uri: &uri::Rsync
    ) -> Result<StoredPoint<'a>, Failed> {
        StoredPoint::open(
            self.store, self.point_path(manifest_uri), self.is_rrdp
        )
    }

    /// Completely removes a publication point.
    ///
    /// The publication point to be removed is given via its manifest’s
    /// signedObject URI.
    pub fn remove_point(
        &self, manifest_uri: &uri::Rsync
    ) -> Result<(), io::Error> {
        fs::remove_file(self.point_path(manifest_uri))
    }

    fn point_path(&self, manifest_uri: &uri::Rsync) -> PathBuf {
        self.path.join(
            format!(
                "rsync/{}/{}/{}",
                manifest_uri.canonical_authority(),
                manifest_uri.module_name(),
                manifest_uri.path(),
            )
        )
    }
}


//------------ StoredPoint ---------------------------------------------------

pub struct StoredPoint<'a> {
    store: &'a Store,
    path: PathBuf,
    file: Option<File>,
    manifest: Option<StoredManifest>,
    object_start: u64,
    is_rrdp: bool,
}

impl<'a> StoredPoint<'a> {
    fn open(
        store: &'a Store,
        path: PathBuf,
        is_rrdp: bool,
    ) -> Result<Self, Failed> {
        let mut file = match File::open(&path) {
            Ok(file) => file,
            Err(ref err) if err.kind() == io::ErrorKind::NotFound => {
                return Ok(StoredPoint {
                    store, path,
                    file: None,
                    manifest: None,
                    object_start: 0,
                    is_rrdp
                })
            }
            Err(err) => {
                error!(
                    "Failed to open stored publication point at {}: {}",
                    path.display(), err
                );
                return Err(Failed)
            }
        };

        let manifest = StoredManifest::read(&mut file).map_err(|err| {
            error!(
                "Failed to read stored publication point at {}: {}",
                path.display(), err
            );
            Failed
        })?;

        let object_start = file.stream_position().map_err(|err| {
            error!(
                "Failed to read stored publication point at {}: {}",
                path.display(), err
            );
            Failed
        })?;

        Ok(StoredPoint {
            store, path,
            file: Some(file),
            manifest: Some(manifest),
            object_start,
            is_rrdp
        })
    }

    pub fn is_rrdp(&self) -> bool {
        self.is_rrdp
    }

    pub fn exisits(&self) -> bool {
        self.manifest.is_some()
    }

    pub fn manifest(&self) -> Option<&StoredManifest> {
        self.manifest.as_ref()
    }

    pub fn take_manifest(&mut self) -> Option<StoredManifest> {
        self.manifest.take()
    }

    pub fn rewind(&mut self) -> Result<(), io::Error> {
        if let Some(file) = self.file.as_mut() {
            file.seek(SeekFrom::Start(self.object_start))?;
        }
        Ok(())
    }

    /// Replaces the data of the stored point.
    ///
    /// Updates the manifest with the provided manifest and the objects
    /// provided by the closure. The closure is called repeatedly until it
    /// either returns `Ok(None)` or `Err(_)`. In the latter case, the update
    /// is cancelled, the old point retained unchanged and the error is
    /// returned. Otherwise, `self` represents the new point. It is
    /// positioned at the first object, i.e., if it is iterated over, the
    /// first object will be returned next.
    pub fn update(
        &mut self,
        manifest: StoredManifest,
        mut objects: impl FnMut() -> Result<Option<StoredObject>, UpdateError>
    ) -> Result<(), UpdateError> {
        let (tmp_path, mut tmp_file) = self.store.tmp_file()?;

        if let Err(err) = manifest.write(&mut tmp_file) {
            error!(
                "Fatal: failed to write to file {}: {}",
                tmp_path.display(), err
            );
            return Err(UpdateError::Fatal)
        }
        let tmp_object_start = match tmp_file.stream_position() {
            Ok(some) => some,
            Err(err) => {
                error!(
                    "Fatal: failed to get position in file {}: {}",
                    tmp_path.display(), err
                );
                return Err(UpdateError::Fatal)
            }
        };

        loop {
            match objects() {
                Ok(Some(object)) => {
                    if let Err(err) = object.write(&mut tmp_file) {
                        error!(
                            "Fatal: failed to write to file {}: {}",
                            tmp_path.display(), err
                        );
                        return Err(UpdateError::Fatal)
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    drop(tmp_file);
                    if let Err(err) = fs::remove_file(&tmp_path) {
                        error!(
                            "Fatal: failed to delete file {}: {}",
                            tmp_path.display(), err
                        );
                        return Err(UpdateError::Fatal)
                    }
                    return Err(err)
                }
            }
        }

        drop(tmp_file);
        let existing = self.file.is_some();
        drop(self.file.take());

        if existing {
            if let Err(err) = fs::remove_file(&self.path) {
                error!(
                    "Fatal: cannot delete file {}: {}",
                    self.path.display(), err
                );
                return Err(UpdateError::Fatal)
            }
        }
        else if let Some(path) = self.path.parent() {
            if let Err(err) = fs::create_dir_all(&path) {
                error!(
                    "Fatal: cannot create direcory {}: {}",
                    path.display(), err
                );
                return Err(UpdateError::Fatal)
            }
        }
        if let Err(err) = fs::rename(&tmp_path, &self.path) {
            error!(
                "Fatal: cannot move {} to {}: {}",
                tmp_path.display(), self.path.display(), err
            );
            return Err(UpdateError::Fatal)
        }
        let mut file = match File::open(&self.path) {
            Ok(some) => some,
            Err(err) => {
                error!(
                    "Fatal: failed to open {}: {}",
                    self.path.display(), err
                );
                return Err(UpdateError::Fatal)
            }
        };
        if let Err(err) = file.seek(SeekFrom::Start(tmp_object_start)) {
            error!(
                "Fatal: failed to position file {}: {}",
                self.path.display(), err
            );
            return Err(UpdateError::Fatal)
        }

        self.file = Some(file);
        self.manifest = Some(manifest);
        self.object_start = tmp_object_start;

        Ok(())
    }
}

impl<'a> Iterator for StoredPoint<'a> {
    type Item = Result<StoredObject, Failed>;

    fn next(&mut self) -> Option<Self::Item> {
        match StoredObject::read(self.file.as_mut()?) {
            Ok(Some(res)) => Some(Ok(res)),
            Ok(None) => None,
            Err(err) => {
                error!(
                    "Fatal: failed to read from {}: {}",
                    self.path.display(), err
                );
                Some(Err(Failed))
            }
        }
    }
}


//------------ StoredManifest ------------------------------------------------

/// The content of a manifest placed in the store.
///
/// This type collects all data that is stored as the manifest for a
/// publication point.
///
/// This contains the raw bytes of both the manifest itself plus data that
/// will be needed to use the manifest during processing. In particular:
///
/// * The expiry time of the manifest’s EE certificate via the
///   [`not_after`][Self::not_after] method. This is used during cleanup to
///   determine whether to keep a publication point. It is stored to avoid
///   having to parse the whole manifest.
/// * The caRepository URI of the CA certificate that has issued the manifest
///   via the [`ca_repository`][Self::ca_repository] method.  This is
///   necessary to convert the file names mentioned on the manifest into their
///   full rsync URIs. Confusingly, this information is not available on the
///   manifest itself and therefore needs to be stored.
/// * The raw bytes of the manifest via the [`manifest`][Self::manifest]
///   method.
/// * The raw bytes of the CRL referenced by the manifest via the
///   [`crl`][Self::crl] method. There must always be exactly one CRL used by
///   a publication point. As it needs to be available for validation, we
///   might as well store it together with the manifest.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct StoredManifest {
    /// The expire time of the EE certificate of the manifest.
    not_after: Time,

    /// The rpkiNotify URI of the issuing CA certificate.
    rpki_notify: Option<uri::Https>,

    /// The CA repository rsync URI of the issuing CA certificate.
    ca_repository: uri::Rsync,

    /// The manifest’s rsync URI.
    manifest_uri: uri::Rsync,

    /// The raw content of the manifest.
    manifest: Bytes,

    /// The CRL’s rsync URI.
    crl_uri: uri::Rsync,

    /// The raw content of the CRL.
    crl: Bytes,
}

impl StoredManifest {
    /// Creates a new stored manifest.
    ///
    /// The new value is created from the components of the stored manifest.
    /// See the methods with the same name for their meaning.
    pub fn new(
        not_after: Time,
        rpki_notify: Option<uri::Https>,
        ca_repository: uri::Rsync,
        manifest_uri: uri::Rsync,
        manifest: Bytes,
        crl_uri: uri::Rsync,
        crl: Bytes,
    ) -> Self {
        StoredManifest {
            not_after, rpki_notify, ca_repository,
            manifest_uri, manifest, crl_uri, crl
        }
    }

    /// Reads a stored manifest from an IO reader.
    pub fn read(reader: &mut impl io::Read) -> Result<Self, io::Error> {
        // Version number. Must be 0u8.
        let version = u8::parse(reader)?;
        if version != 0 {
            return io_err_other(format!("unexpected version {}", version))
        }

        let not_after = Utc.timestamp(i64::parse(reader)?, 0).into();
        let rpki_notify = Option::parse(reader)?;
        let ca_repository = uri::Rsync::parse(reader)?;
        let manifest_uri = uri::Rsync::parse(reader)?;
        let manifest = Bytes::parse(reader)?;
        let crl_uri = uri::Rsync::parse(reader)?;
        let crl = Bytes::parse(reader)?;

        Ok(StoredManifest::new(
            not_after, rpki_notify, ca_repository,
            manifest_uri, manifest, crl_uri, crl
        ))
    }

    /// Appends the stored manifest to a writer.
    pub fn write(
        &self, writer: &mut impl io::Write
    ) -> Result<(), io::Error> {
        // Version: 0u8.
        0u8.compose(writer)?;

        self.not_after.timestamp().compose(writer)?;
        self.rpki_notify.compose(writer)?;
        self.ca_repository.compose(writer)?;
        self.manifest_uri.compose(writer)?;
        self.manifest.compose(writer)?;
        self.crl_uri.compose(writer)?;
        self.crl.compose(writer)?;

        Ok(())
    }

    /// Returns whether we should retain the stored manifest in an RRDP repo.
    ///
    /// Returns the URI of the repository if we should or `None` if we
    /// shouldn’t.
    fn retain_rrdp(&self) -> Option<uri::Https> {
        if self.not_after <= Time::now() {
            None
        }
        else {
            self.rpki_notify.clone()
        }
    }

    /// Returns whether we should retain the stored manifest in an rsync repo.
    ///
    /// Returns the manifest URI if we should or `None` if we shouldn’t.
    fn retain_rsync(&self) -> Option<uri::Rsync> {
        if self.not_after <= Time::now() {
            None
        }
        else {
            Some(self.manifest_uri.clone())
        }
    }
}

impl StoredManifest {
    /// Returns the expire time of the manifest.
    ///
    /// This should be equal to the ‘not after’ validity time of the EE
    /// certificate included with the manifest.
    pub fn not_after(&self) -> Time {
        self.not_after
    }

    /// Returns the rsync URI of the directory containing the objects.
    ///
    /// As the manifest only lists relative file names, this URI is necessary
    /// to convert them into full rsync URIs.
    ///
    /// The URI should be taken from the ‘caRepository’ subject information
    /// access extension of the CA certificate that was used to issue the
    /// manifest’s EE certificate.
    pub fn ca_repository(&self) -> &uri::Rsync {
        &self.ca_repository
    }

    /// Returns the bytes of the manifest.
    pub fn manifest(&self) -> &Bytes {
        &self.manifest
    }

    /// Returns the bytes of the publication point’s CRL.
    ///
    /// This CRL should be the CRL referenced via the CRL distribution
    /// point of the manifest’s EE certificate. It should be correctly 
    /// referenced at that location on the manifest.
    pub fn crl(&self) -> &Bytes {
        &self.crl
    }
}


//------------ StoredObject --------------------------------------------------

/// The content of an object placed in the store.
///
/// This type collects all the data that is stored for regular objects of a
/// publication point: the raw bytes of the object as well as its hash as
/// stated on the publication point’s manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredObject {
    /// The URI of the object.
    uri: uri::Rsync,

    /// The manifest hash of the object if available.
    hash: Option<ManifestHash>,

    /// The content of the object.
    content: Bytes,
}

impl StoredObject {
    /// Creates a new stored object from its bytes and manifest hash.
    pub fn new(
        uri: uri::Rsync,
        content: Bytes,
        hash: Option<ManifestHash>,
    ) -> Self {
        StoredObject { uri, hash, content }
    }

    /// Reads a stored object from an IO reader.
    pub fn read(
        reader: &mut impl io::Read
    ) -> Result<Option<Self>, io::Error> {
        // Version number. Must be 0u8.
        let version = match u8::parse(reader) {
            Ok(version) => version,
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                return Ok(None)
            }
            Err(err) => return Err(err)
        };
        if version != 0 {
            return io_err_other(format!("unexpected version {}", version))
        }

        let uri = uri::Rsync::parse(reader)?;
        let hash = match u8::parse(reader)? {
            0 => None,
            1 => {
                let algorithm = DigestAlgorithm::sha256();
                let mut value = vec![0u8; algorithm.digest_len()];
                reader.read_exact(&mut value)?;
                Some(ManifestHash::new(value.into(), algorithm))
            }
            hash_type => {
                return io_err_other(
                    format!("unsupported hash type {}", hash_type)
                );
            }
        };
        let content = Bytes::parse(reader)?;

        Ok(Some(StoredObject { uri, hash, content }))
    }

    /// Appends the stored object to a writer.
    pub fn write(
        &self, writer: &mut impl io::Write
    ) -> Result<(), io::Error> {
        // Version: 0u8.
        0u8.compose(writer)?;

        self.uri.compose(writer)?;

        // Hash.
        //
        // One octet hash type: 0 .. None, 1 .. SHA-256
        // As many octets as the hash type requires.
        //
        // Unknown digest algorithms (there is non yet, but there may be) are
        // encoded as if the field was None.
        match self.hash.as_ref() {
            Some(hash) if hash.algorithm().is_sha256() => {
                1u8.compose(writer)?;
                writer.write_all(hash.as_slice())?;
            }
            _ => {
                0u8.compose(writer)?;
            }
        }

        self.content.compose(writer)?;

        Ok(())
    }

    /// Verifies that the object matches the given hash.
    ///
    /// This will be a simple comparison with [`Self::hash`] if both hashes
    /// use the same algorithm (which currently is always true but may change
    /// in the future) otherwise the object’s bytes are being hashed.
    pub fn verify_hash(
        &self, hash: &ManifestHash
    ) -> Result<(), ValidationError> {
        if let Some(stored_hash) = self.hash.as_ref() {
            if hash.algorithm() == stored_hash.algorithm() {
                if hash.as_slice() == stored_hash.as_slice() {
                    return Ok(())
                }
                else {
                    return Err(ValidationError)
                }
            }
        }

        hash.verify(&self.content)
    }

    /// Returns the URI of the object.
    pub fn uri(&self) -> &uri::Rsync {
        &self.uri
    }

    /// Returns the stored object’s content.
    pub fn content(&self) -> &Bytes {
        &self.content
    }

    /// Converts the stored object into the object’s raw bytes.
    pub fn into_content(self) -> Bytes {
        self.content
    }
}


//============ Error Types ===================================================

/// An error happend while updating a publication point.
#[derive(Clone, Copy, Debug)]
pub enum UpdateError {
    /// The update needs to be aborted and rolled back.
    Abort,

    /// Something really bad and fatal happened.
    Fatal,
}

impl From<Failed> for UpdateError {
    fn from(_: Failed) -> Self {
        UpdateError::Fatal
    }
}


//============ Helper Functions ==============================================

/// Creates an IO error of kind other with the given string.
fn io_err_other<T>(
    err: impl Into<Box<dyn error::Error + Send + Sync>>
) -> Result<T, io::Error> {
    Err(io::Error::new(io::ErrorKind::Other, err))
}

/// Recursively iterate over all files in a directory tree.
fn for_each_file(
    base: &Path,
    mut op: impl FnMut(&Path) -> Result<(), Failed>
) -> Result<(), Failed> {
    fn recurse(
        base: &Path,
        op: &mut impl FnMut(&Path) -> Result<(), Failed>
    ) -> Result<(), Failed> {
        let dir = match fs::read_dir(base) {
            Ok(dir) => dir,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Ok(())
            }
            Err(err) => {
                error!(
                    "Failed to read directory {}: {}",
                    base.display(), err
                );
                return Err(Failed)
            }
        };

        for entry in dir {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    error!(
                        "Failed to read directory {}: {}",
                        base.display(), err
                    );
                    return Err(Failed)
                }
            };
            let ftype = match entry.file_type() {
                Ok(ftype) => ftype,
                Err(err) => {
                    error!(
                        "Failed to read directory {}: {}",
                        base.display(), err
                    );
                    return Err(Failed)
                }
            };
            let path = entry.path();
            if ftype.is_dir() {
                recurse(&path, op)?;
            }
            else if ftype.is_file() {
                op(&path)?;
            }
        }
        Ok(())
    }
    recurse(base, &mut op)
}


/// Cleans up a directory tree.
///
/// If the closure returns `Ok(false)` for a file with the given path, the
/// file will be deleted. If all files in a directory are deleted, that
/// directory is deleted.
fn cleanup_dir_tree(
    base: &Path,
    mut keep: impl FnMut(&Path) -> Result<bool, io::Error>
) -> Result<(), Failed> {
    fn recurse(
        base: &Path,
        op: &mut impl FnMut(&Path) -> Result<bool, io::Error>
    ) -> Result<bool, Failed> {
        let dir = match fs::read_dir(base) {
            Ok(dir) => dir,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Ok(false)
            }
            Err(err) => {
                error!(
                    "Failed to read directory {}: {}",
                    base.display(), err
                );
                return Err(Failed)
            }
        };

        let mut keep = false;
        for entry in dir {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    error!(
                        "Failed to read directory {}: {}",
                        base.display(), err
                    );
                    return Err(Failed)
                }
            };
            let ftype = match entry.file_type() {
                Ok(ftype) => ftype,
                Err(err) => {
                    error!(
                        "Failed to read directory {}: {}",
                        base.display(), err
                    );
                    return Err(Failed)
                }
            };
            let path = entry.path();
            if ftype.is_dir() {
                if !recurse(&path, op)? {
                    if let Err(err) = fs::remove_dir(&path) {
                        error!(
                            "Failed to delete unused directory {}: {}",
                            path.display(), err
                        );
                        return Err(Failed)
                    }
                }
                else {
                    keep = true;
                }
            }
            else if ftype.is_file() {
                let res = match op(&path) {
                    Ok(res) => res,
                    Err(err) => {
                        error!("{}: {}", path.display(), err);
                        return Err(Failed)
                    }
                };
                if !res {
                    if let Err(err) = fs::remove_file(&path) {
                        error!(
                            "Failed to delete unused file {}: {}",
                            path.display(), err
                        );
                        return Err(Failed)
                    }
                }
                else {
                    keep = true;
                }
            }
            else {
                // Something fishy. Let’s not try deleting it.
                keep = true;
            }
        }
        Ok(keep)
    }
    recurse(base, &mut keep).map(|_| ())
}


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use std::str::FromStr;
    use super::*;

    #[test]
    fn write_read_stored_manifest() {
        let mut orig = StoredManifest::new(
            Time::utc(2021, 02, 18, 13, 22, 06),
            Some(uri::Https::from_str("https://foo.bar/bla/blubb").unwrap()),
            uri::Rsync::from_str("rsync://foo.bar/bla/blubb").unwrap(),
            uri::Rsync::from_str("rsync://foo.bar/bla/blubb").unwrap(),
            Bytes::from(b"foobar".as_ref()),
            uri::Rsync::from_str("rsync://foo.bar/bla/blubb").unwrap(),
            Bytes::from(b"blablubb".as_ref())
        );
        let mut written = Vec::new();
        orig.write(&mut written).unwrap();
        let decoded = StoredManifest::read(&mut written.as_slice()).unwrap();
        assert_eq!(orig, decoded);

        orig.rpki_notify = None;
        let mut written = Vec::new();
        orig.write(&mut written).unwrap();
        let decoded = StoredManifest::read(&mut written.as_slice()).unwrap();
        assert_eq!(orig, decoded);
    }

    #[test]
    fn write_read_stored_object() {
        let orig = StoredObject::new(
            uri::Rsync::from_str("rsync://foo.bar/bla/blubb").unwrap(),
            Bytes::from(b"foobar".as_ref()),
            None
        );
        let mut written = Vec::new();
        orig.write(&mut written).unwrap();
        let decoded = StoredObject::read(
            &mut written.as_slice()
        ).unwrap().unwrap();
        assert_eq!(orig, decoded);
    }
}

