//! A store for correctly published RPKI objects.
//!
//! To be more resistant against accidental or malicious errors in the data
//! published by repositories, we retain a separate copy of all RPKI data that
//! has been found to be covered by a valid manifest in what we call the
//! _store._ The types in this module provide access to this store.
//!
//! The store is initialized and configured via [`Store`]. During validation,
//! [`Run`] is used which can be acquired from the store via the
//! [`start`][Store::start] method. It provides access to the trust anchor
//! certificates via the [`load_ta`][Run::load_ta] and
//! [`update_ta`][Run::update_ta] methods, and access to individual
//! repositories and publication points via [`repository`][Run::repository]
//! and [`pub_point`][Run::pub_point], respectively. These are represented
//! by the [`Repository`] and [`StoredPoint`] types.
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
//! The store uses the file system to store its data. It has its dedicated
//! directory within the RPKI repository directory, normally named `stored`
//! (this is because an earlier version used `store` already). Within this
//! directory are four sub-directories: `rrdp` and `rsync` contain the data
//! for each stored publication point; `ta` contains the downloaded trust
//! anchor certificates; and `tmp` is a directory for storing files as they
//! are constructed.
//!
//! All publication points that do not support RRDP are stored under `rsync`.
//! Each has a file stored at a path and file name derived from the
//! signedObject URI of its manifest, starting with the authority part of the
//! URI and then just following along. The file contains status information,
//! the manifest, the CRL, and each object. It starts with a serialized
//! [`StoredManifest`] which is followed by a sequence of serialized
//! [`StoredObject`]s for all the objects as given on the manifest.
//!
//! All publication points that are hosted in an RRDP repository are stored
//! under `rrdp`, independently of whether they have been retrieved via RRDP
//! or rsync. Directly under `rrdp` is a set of directories for all the
//! authorities (i.e., host names) of the RRDP servers seen. Within each of
//! these is a set of directories named after the SHA-256 hash of the
//! rpkiNotify URI of the RRDP repository. These directories in turn contain
//! the same files for each publication point as in the rsync case above. They
//! are similarly stored at a path and file name derived from the signedObject
//! URI of the manifest with the `rsync` scheme used as the first component
//! instead. (There is no good reason for that, it just happened.)
//!
//! Trust anchor certficates are stored under `ta` using a three level
//! directory structure derived from the URI the certificate is retrieved
//! from. The first level is the scheme, `https` or `rsync`, the second
//! level is the authority (i.e., hostname), and the third is the SHA-256
//! hash of the full URI with an extension of `.cer` added.
//!
//! Finally, the `tmp` directory is used to build the publication point files
//! in so they can be constructed without yet knowing whether the update is
//! actually complete and correct. File names here are named using eight
//! random hex-digits.

use std::{error, fs, io};
use std::collections::HashSet;
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use bytes::Bytes;
use chrono::{TimeZone, Utc};
use log::{debug, error, warn};
use rand::random;
use rpki::crypto::KeyIdentifier;
use rpki::crypto::digest::DigestAlgorithm;
use rpki::repository::cert::Cert;
use rpki::repository::manifest::ManifestHash;
use rpki::repository::tal::{Tal, TalUri};
use rpki::repository::x509::Time;
use rpki::uri;
use crate::collector;
use crate::config::Config;
use crate::engine::CaCert;
use crate::error::Failed;
use crate::metrics::Metrics;
use crate::utils::fatal;
use crate::utils::binio::{Compose, Parse};
use crate::utils::dump::DumpRegistry;
use crate::utils::fatal::IoErrorDisplay;
use crate::utils::json::JsonBuilder;
use crate::utils::uri::UriExt;


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
    //  (Or, well, not really, but they both only call `create_base_dir`, so
    //   from a user persepective it does.)
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

    /// Checks whether the store is to be considered current.
    pub fn is_current(&self, tals: &[Tal], refresh: Duration) -> bool {
        let path = self.status_path();
        let mut file = match File::open(&path) {
            Ok(file) => file,
            Err(_) => return false,
        };
        let status = match StoredStatus::read(&mut file) {
            Ok(status) => status,
            Err(_) => return false,
        };

        // An error happens only when refresh is excessively large. Should
        // be safe to claim that we are not current in this case.
        let refresh = match chrono::Duration::from_std(refresh) {
            Ok(refresh) => refresh,
            Err(_) => return false,
        };

        if status.updated + refresh < Time::now() {
            return false
        }

        if !status.contains_tals(tals) {
            return false
        }

        true
    }

    /// Start a validation run with the store.
    ///
    /// If there is an intention to update the store during this run, set
    /// `updates` to `true`.
    pub fn start(&self, updates: bool) -> Result<Run, Failed> {
        Run::new(self, updates)
    }

    /// Dumps the content of the store.
    pub fn dump(&self, dir: &Path) -> Result<(), Failed> {
        self.dump_ta_certs(dir)?;
        let dir = dir.join("store");
        debug!("Dumping store content to {}", dir.display());
        fatal::remove_dir_all(&dir)?;
        let mut repos = DumpRegistry::new(dir);
        self.dump_tree(&self.rsync_repository_path(), &mut repos)?;
        self.dump_tree(&self.rrdp_repository_base(), &mut repos)?;
        self.dump_repository_json(repos)?;
        debug!("Store dump complete.");
        Ok(())
    }

    /// Dumps all the stored trust anchor certificates.
    fn dump_ta_certs(
        &self,
        target_base: &Path
    ) -> Result<(), Failed> {
        let source = self.path.join("ta");
        let target = target_base.join("ta");
        debug!("Dumping trust anchor certificates to {}", target.display());
        fatal::remove_dir_all(&target)?;
        fatal::copy_dir_all(&source, &target)?;
        debug!("Trust anchor certificate dump complete.");
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
        for entry in fatal::read_dir(path)? {
            let entry = entry?;
            if entry.is_dir() {
                self.dump_tree(entry.path(), repos)?;
            }
            else if entry.is_file() {
                self.dump_point(entry.path(), repos)?;
            }
        }
        Ok(())
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
            fatal::create_dir_all(dir)?;
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
        fatal::write_file(
            &path, 
            JsonBuilder::build(|builder| {
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
            }).as_bytes()
        )
    }

    /// Returns the path to use for the trust anchor at the given URI.
    fn ta_path(&self, uri: &TalUri) -> PathBuf {
        match *uri {
            TalUri::Rsync(ref uri) => {
                self.path.join(
                    uri.unique_path("ta/rsync", ".cer")
                )
            }
            TalUri::Https(ref uri) => {
                self.path.join(
                    uri.unique_path("ta/https", ".cer")
                )
            }
        }
    }

    /// The name of the directory where all the RRDP repositories go.
    const RRDP_BASE: &'static str = "rrdp";

    /// Returns the path where all the RRDP repositories are stored.
    fn rrdp_repository_base(&self) -> PathBuf {
        self.path.join(Self::RRDP_BASE)
    }

    /// Returns the path for the RRDP repository with the given rpkiNotify URI.
    fn rrdp_repository_path(&self, uri: &uri::Https) -> PathBuf {
        self.path.join(uri.unique_path(Self::RRDP_BASE, ""))
    }

    /// Returns the path where the combined rsync repository is stored.
    fn rsync_repository_path(&self) -> PathBuf {
        self.path.join("rsync")
    }

    /// Returns the path of the status file.
    fn status_path(&self) -> PathBuf {
        self.path.join("status.bin")
    }

    /// The name of the directory where the temporary files go.
    const TMP_BASE: &'static str = "tmp";

    /// Creates and returns a temporary file.
    ///
    /// The file is created in the store’s temporary path. If this succeeds,
    /// the path and file object are returned.
    fn tmp_file(&self) -> Result<(PathBuf, File), Failed> {
        let tmp_dir = self.path.join(Self::TMP_BASE);
        fatal::create_dir_all(&tmp_dir)?;
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
                        tmp_path.display(), IoErrorDisplay(err)
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
/// through the [`repository`][Self::repository] method.
///
/// Stored trust anchor certificates can be updated via
/// [`update_ta`][Self::update_ta] on [`Run`] directly, while the
/// [`Repository`] provides means to that for all other data.
///
/// This type references the underlying [`Store`]. It can be used with
/// multiple threads using
/// [crossbeam’s](https://github.com/crossbeam-rs/crossbeam) scoped threads.
#[derive(Debug)]
pub struct Run<'a> {
    /// A reference to the underlying store.
    store: &'a Store,

    /// Is the store being updated during this run?
    updates: bool,
}

impl<'a> Run<'a> {
    /// Creates a new runner from a store.
    fn new(
        store: &'a Store,
        updates: bool,
    ) -> Result<Self, Failed> {
        if updates {
            fatal::remove_file(&store.status_path())?;
        }
        Ok(Run { store, updates })
    }

    /// Confirms a successful validation run.
    pub fn confirm_success(&self, tals: &[Tal]) -> Result<(), Failed> {
        if self.updates {
            let path = self.store.status_path();
            let mut file = fatal::create_file(&path)?;
            if let Err(err) = StoredStatus::new(
                Time::now(), tals
            ).write(&mut file) {
                error!("Fatal: failed to write store status to {}: {}",
                    path.display(), IoErrorDisplay(err)
                );
                return Err(Failed);
            }
        }
        Ok(())
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
        fatal::read_existing_file(&self.store.ta_path(uri)).map(|maybe| {
            maybe.map(Into::into)
        })
    }

    /// Updates or inserts a stored trust anchor certificate.
    pub fn update_ta(
        &self, uri: &TalUri, content: &[u8]
    ) -> Result<(), Failed> {
        let path = self.store.ta_path(uri);
        if let Some(dir) = path.parent() {
            fatal::create_dir_all(dir)?;
        }
        fatal::write_file(&path, content)
    }

    /// Accesses the repository for the provided RPKI CA.
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

    /// Cleans up the store.
    ///
    /// All publication points that have an expired manifest will be removed.
    /// RRDP repositories that have no more publication points are removed,
    /// too.
    ///
    /// All RRDP repositories and rsync modules retained are registered with
    /// `collector` for retaining in the collector as well.
    pub fn cleanup(
        &self,
        collector: &mut collector::Cleanup,
    ) -> Result<(), Failed> {
        self.cleanup_ta()?;
        self.cleanup_points(&self.store.rrdp_repository_base(), collector)?;
        self.cleanup_points(&self.store.rsync_repository_path(), collector)?;
        self.cleanup_tmp()?;
        Ok(())
    }

    /// Cleans up the trust anchors.
    ///
    /// Deletes all files that either don’t successfully parse as certificates
    /// or that are expired certificates.
    fn cleanup_ta(&self) -> Result<(), Failed> {
        cleanup_dir_tree(&self.store.path.join("ta"), |path| {
            let content = fatal::read_file(path)?;
            if let Ok(cert) = Cert::decode(Bytes::from(content)) {
                if cert.validity().not_after() > Time::now() {
                    return Ok(true)
                }
            }
            Ok(false)
        })
    }

    /// Cleans up a tree with publication points.
    ///
    /// Deletes all publication points with an expired manifest as well as
    /// any obviously garbage files. The RRDP repository of any publication
    /// point that is retained is registered to be retained by the collector.
    fn cleanup_points(
        &self,
        base: &Path,
        retain: &mut collector::Cleanup,
    ) -> Result<(), Failed> {
        cleanup_dir_tree(base, |path| {
            if let Ok(stored) = StoredManifest::read(
                &mut fatal::open_file(path)?
            ) {
                if stored.retain() {
                    if let Some(uri) = stored.rpki_notify.as_ref() {
                        retain.add_rrdp_repository(uri)
                    }
                    else {
                        retain.add_rsync_module(&stored.manifest_uri)
                    }
                    return Ok(true)
                }
            }
            Ok(false)
        })
    }

    fn cleanup_tmp(&self) -> Result<(), Failed> {
        cleanup_dir_tree(&self.store.path.join("tmp"), |_path| {
            Ok(false)
        })
    }
}


//------------ StoredStatus --------------------------------------------------

/// The status of the store.
#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredStatus {
    /// The time of the last successful update.
    updated: Time,

    /// The TALs used during the last update.
    tals: HashSet<KeyIdentifier>,
}

impl StoredStatus {
    /// Creates a new status from the necessary values.
    pub fn new(
        updated: Time,
        tals: &[Tal],
    ) -> Self {
        StoredStatus {
            updated,
            tals: tals.iter().map(|tal| {
                tal.key_info().key_identifier()
            }).collect(),
        }
    }

    /// Reads the stored status from a reader.
    pub fn read(reader: &mut impl io::Read) -> Result<Self, io::Error> {
        // Version number. Must be 0u8.
        let version = u8::parse(reader)?;
        if version != 0 {
            return io_err_other(format!("unexpected version {}", version))
        }

        Ok(StoredStatus {
            updated: Utc.timestamp(i64::parse(reader)?, 0).into(),
            tals: HashSet::parse(reader)?,
        })
    }

    /// Writes the stored status to a writer.
    pub fn write(
        &self, writer: &mut impl io::Write
    ) -> Result<(), io::Error> {
        // Version: 0u8.
        0u8.compose(writer)?;

        self.updated.timestamp().compose(writer)?;
        self.tals.compose(writer)?;

        Ok(())
    }

    /// Checks that all provided TALs are part of the status.
    pub fn contains_tals(&self, tals: &[Tal]) -> bool {
        for tal in tals {
            if !self.tals.contains(&tal.key_info().key_identifier()) {
                return false
            }
        }
        true
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
/// [`get_point`][Self::get_point].
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
    /// information stored for the point or not.
    pub fn get_point(
        &self, manifest_uri: &uri::Rsync
    ) -> Result<StoredPoint<'a>, Failed> {
        StoredPoint::open(
            self.store, self.point_path(manifest_uri), self.is_rrdp
        )
    }

    /// Returns the path for a publication point with the given manifest URI.
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

/// The stored information of a publication point.
///
/// This types allows access to the stored manifest via
/// [`manifest`][Self::manifest] and acts as an iterator over the
/// publication point’s objects. The method [`update`][Self::update] allows
/// atomically updating the information.
pub struct StoredPoint<'a> {
    /// A reference to the underlying store.
    store: &'a Store,

    /// The path to the file-system location of the repository.
    path: PathBuf,

    /// The file with all the information we need.
    ///
    /// There will only be something here if there actually is a stored
    /// point on disk yet.
    file: Option<File>,

    /// The stored manifest for the point if there is one.
    manifest: Option<StoredManifest>,

    /// Is this a publication point with in an RRDP repository?
    is_rrdp: bool,
}

impl<'a> StoredPoint<'a> {
    /// Opens the stored point.
    ///
    /// If there is a file at the given path, it is opened. Otherwise, er,
    /// well, it is not.
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

        Ok(StoredPoint {
            store, path,
            file: Some(file),
            manifest: Some(manifest),
            is_rrdp
        })
    }

    /// Returns whether the stored point is for an RRDP repository.
    pub fn is_rrdp(&self) -> bool {
        self.is_rrdp
    }

    /// Returns a reference to the stored manifest if available.
    ///
    /// The manifest will not be available if there is no previously stored
    /// version of the publication point and an update has not succeeded yet,
    /// or if the manifest has been taken out via
    /// [`take_manifest`][Self::take_manifest].
    pub fn manifest(&self) -> Option<&StoredManifest> {
        self.manifest.as_ref()
    }

    /// Takes the stored manifest from the point.
    ///
    /// Afterwards, [`manifest`][Self::manifest] will return `None`.
    pub fn take_manifest(&mut self) -> Option<StoredManifest> {
        self.manifest.take()
    }

    /// Replaces the data of the stored point.
    ///
    /// Updates the manifest with the provided manifest and the objects
    /// provided by the closure. The closure is called repeatedly until it
    /// either returns `Ok(None)` or `Err(_)`. In the latter case, the update
    /// is cancelled, the old point remains unchanged and the error is
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
                tmp_path.display(), IoErrorDisplay(err)
            );
            return Err(UpdateError::Fatal)
        }
        let tmp_object_start = match tmp_file.seek(SeekFrom::Current(0)) {
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
                            tmp_path.display(), IoErrorDisplay(err)
                        );
                        return Err(UpdateError::Fatal)
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    drop(tmp_file);
                    fatal::remove_file(&tmp_path)?;
                    return Err(err)
                }
            }
        }

        drop(tmp_file);
        let existing = self.file.is_some();
        drop(self.file.take());

        if existing {
            fatal::remove_file(&self.path)?;
        }
        else if let Some(path) = self.path.parent() {
            fatal::create_dir_all(path)?;
        }
        fatal::rename(&tmp_path, &self.path)?;
        let mut file = fatal::open_file(&self.path)?;
        if let Err(err) = file.seek(SeekFrom::Start(tmp_object_start)) {
            error!(
                "Fatal: failed to position file {}: {}",
                self.path.display(), err
            );
            return Err(UpdateError::Fatal)
        }

        self.file = Some(file);
        self.manifest = Some(manifest);

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

    /// Returns whether we should retain the stored manifest.
    fn retain(&self) -> bool {
        self.not_after > Time::now()
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
/// stated on the publication point’s manifest. This hash is currently not
/// used since we only store objects when we know the publication point was
/// valid. It is retained here solely for compatibility with the existing
/// stored object format.
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


/// Cleans up a directory tree.
///
/// If the closure returns `Ok(false)` for a file with the given path, the
/// file will be deleted. If all files in a directory are deleted, that
/// directory is deleted.
fn cleanup_dir_tree(
    base: &Path,
    mut keep: impl FnMut(&Path) -> Result<bool, Failed>
) -> Result<(), Failed> {
    /// Actual recursion.
    ///
    /// If `top` is `true`, we ignore if the directory `path` is missing.
    ///
    /// Returns whether the `base` needs to be kept. I.e., if `Ok(false)`
    /// is returned, the calling recursing step will perform a
    /// `delete_dir_all(base)`.
    fn recurse(
        base: &Path,
        top: bool,
        op: &mut impl FnMut(&Path) -> Result<bool, Failed>
    ) -> Result<bool, Failed> {
        let dir = if top {
            match fatal::read_existing_dir(base)? {
                Some(dir) => dir,
                None => return Ok(false),
            }
        }
        else {
            fatal::read_dir(base)?
        };

        let mut keep = false;
        for entry in dir {
            let entry = entry?;
            if entry.is_dir() {
                if !recurse(entry.path(), false, op)? {
                    fatal::remove_dir_all(entry.path())?;
                }
                else {
                    keep = true;
                }
            }
            else if entry.is_file() {
                if !op(entry.path())? {
                    fatal::remove_file(entry.path())?;
                }
                else {
                    keep = true;
                }
            }
            // Let’s not try deleting non-file-and-non-dir things here but
            // leave it to remove_dir_all to give it a shot.
        }
        Ok(keep)
    }
    recurse(base, true, &mut keep).map(|_| ())
}


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use std::str::FromStr;
    use super::*;

    #[test]
    fn write_read_stored_manifest() {
        let mut orig = StoredManifest::new(
            Time::utc(2021, 2, 18, 13, 22, 6),
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

