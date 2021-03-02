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
//! [`update_ta`][Run::update_ta] methods and individual repositories via
//! [`repository`][Run::repository]. These repositories are represented by
//! the [`Repository`] type and allow loading manifests and objects. They can
//! only be updated at once.
//!
//! # Error Handling
//!
//! Pretty much all methods and functions provided by this module can return
//! an error. This is because the underlying database may produce an error at
//! any time. The concrete error reason is logged and our generic
//! [`Failed`][crate::error::Failed] is returned. When this happens, the
//! store should be considered broken and not be used anymore.
//!
//! # Data Storage
//!
//! The store uses a [sled] database to store RPKI data. For each
//! RPKI repository accessed via RRDP, two separate trees are used.
//!
//! The _manifest tree_ contains all the manifests published via that
//! repository keyed by their rsync URI. The manifests are stored as
//! [`StoredManifest`] objects, which include the raw manifest, the raw CRL
//! referenced by the manifest plus some additional meta data.
//!
//! The _object tree_ contains all other objects. These objects are keyed by
//! a concatenation of the rsync URI of the manifest and their file name on
//! the manifest. This makes it possible to retain multiple versions of an
//! object that appeared on multiple manifests for some reasons. It also makes
//! it easier to iterate over all objects of a manifest for instance during
//! cleanup. Objects are stored as [`StoredObject`].
//!
//! For an RRDP repository, the rpkiNotify URI of the repository is prefixed
//! by "store:manifest:" for constructing the name of the manifest tree, while
//! the object tree uses this URI prefixed by `"store:object:"`.
//!
//! There is only one pair of manifest and object tree for rsync since the
//! name of the repository is part of the object URIs. The manifest tree is
//! named `"store:manifest:rsync"` and the object tree `"store:objectrsync"`.
//!
//! In addition, the default tree of the database is used for trust anchor
//! certificates. These are keyed by their URI. Only their raw bytes are
//! stored.
//!
//! [sled]: https://github.com/spacejam/sled

use std::{error, fmt, mem, str};
use std::convert::{TryFrom, TryInto};
use bytes::Bytes;
use chrono::{TimeZone, Utc};
use log::error;
use rpki::repository::crypto::digest::DigestAlgorithm;
use rpki::repository::manifest::ManifestHash;
use rpki::repository::tal::TalUri;
use rpki::repository::x509::{Time, ValidationError};
use rpki::uri;
use sled::Transactional;
use sled::transaction::{
    ConflictableTransactionError, TransactionalTree, TransactionError,
    UnabortableTransactionError
};
use crate::collector;
use crate::engine::CaCert;
use crate::error::Failed;
use crate::metrics::Metrics;


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
    /// The database.
    db: sled::Db,
}

impl Store {
    /// Creates a new store based on configuration information.
    pub fn new(db: sled::Db) -> Self {
        Store { db }
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
        mut collector: collector::Cleanup,
    ) -> Result<(), Failed> {
        // Cleanup RRDP repositories
        for tree_name in self.db.tree_names() {
            if let Ok(rpki_notify) = uri::Https::from_slice(&tree_name) {
                let names = TreeNames::rrdp(&rpki_notify);
                if Repository::new(self, &names)?.cleanup_rrdp()? {
                    collector.retain_rrdp_repository(&rpki_notify);
                }
                else {
                    names.drop_trees(&self.db)?;
                }
            }
        }

        // Cleanup rsync modules
        Repository::new(
            self, &TreeNames::rsync()
        )?.cleanup_rsync(&mut collector)?;

        // Cleanup collector.
        collector.commit()
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
        self.store.db.get(uri.as_str()).map(|value| {
            value.map(|value| Bytes::copy_from_slice(value.as_ref()))
        }).map_err(Into::into)
    }

    /// Updates or inserts a stored trust anchor certificate.
    ///
    /// Returns whether the certificate was newly added to the store.
    pub fn update_ta(
        &self, uri: &TalUri, content: &[u8]
    ) -> Result<bool, Failed> {
        self.store.db.insert(
            uri.as_str(), content
        ).map(|res| res.is_some()).map_err(Into::into)
    }

    /// Accesses the repository for the provided PRKI CA.
    ///
    /// Normally, if the CA’s rpkiNotify URI is present, the RRDP repository
    /// identified by that URI will be returned, otherwise the rsync
    /// repository will be used.
    ///
    /// However, if the repository needs to reflect the repository that was
    /// previously updated via the collector and the collector had to fall
    /// back from RRDP to rsync, the rsync repository is used even if the
    /// rpkiNotify URI is present. This is so that data from the two transport
    /// methods is kept strictly separate to avoid potential poisoning.
    ///
    /// Therefore, if `collector` is not `None`, the provided collector
    /// repository’s chosen transport will be used to determine whether RRDP
    /// is used if available or not.
    pub fn repository(
        &self, ca_cert: &CaCert, collector: Option<&collector::Repository>
    ) -> Result<Repository, Failed> {
        match (ca_cert.rpki_notify(), collector.map(|c| c.is_rrdp())) {
            (Some(rpki_notify), Some(true)) | (Some(rpki_notify), None) => {
                self.rrdp_repository(rpki_notify)
            }
            _ => self.rsync_repository()
        }
    }

    /// Accesses the RRDP repository identified by the given rpkiNotify URI.
    ///
    /// The repository is created if it is not yet present.
    pub fn rrdp_repository(
        &self, rpki_notify: &uri::Https,
    ) -> Result<Repository, Failed> {
        Repository::new(self.store, &TreeNames::rrdp(rpki_notify))
    }

    /// Accesses the rsync repository.
    ///
    /// Because all objects retrieved via rsync can safely share a single
    /// namespace, we only have a single store repository for all of them.
    ///
    /// The repository is created if it is not yet present.
    pub fn rsync_repository(&self) -> Result<Repository, Failed> {
        Repository::new(self.store, &TreeNames::rsync())
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
/// You can load the manifest of a publication point via
/// [`load_manifest`][Self::load_manifest] and the objects via
/// [`load_object`][Self::load_object].
///
/// The manifest and multiple objects of
/// a point can updated atomically through
/// [`update_point`][Self::update_point] to make sure that the objects stay in
/// sync with what’s mentioned on the manifest.
///
/// You can delete an entire publication point via
/// [`remove_point`][Self::remove_point] or remove select objects from the
/// point via [`drain_point`][Self::drain_point].
#[derive(Debug)]
pub struct Repository {
    /// The database tree holding the repository’s manifests.
    manifest_tree: sled::Tree,

    /// The database tree holding the repository’s objects.
    object_tree: sled::Tree,
}

impl Repository {
    /// Creates a repository object on a store using the given tree names.
    fn new(
        store: &Store,
        names: &TreeNames,
    ) -> Result<Self, Failed> {
        Ok(Repository {
            manifest_tree: names.open_manifest_tree(&store.db)?,
            object_tree: names.open_object_tree(&store.db)?,
        })
    }

    /// Loads the manifest of a publication point in the repository.
    ///
    /// The manifest is identified via its signedObject URI. If present, it is
    /// return as a [`StoredManifest`].
    pub fn load_manifest(
        &self, uri: &uri::Rsync
    ) -> Result<Option<StoredManifest>, Failed> {
        self.manifest_tree.get(uri.as_slice()).map(|value| {
            value.and_then(|value| StoredManifest::try_from(value).ok())
        }).map_err(Into::into)
    }

    /// Loads an object from the repository.
    ///
    /// The object’s publication point is identified via the signedObject URI
    /// of the point’s manifest while the object itself is identified through
    /// the name it has on the point’s manifest.
    ///
    /// If publication point and object are present, the object is returned
    /// as a [`StoredObject`].
    pub fn load_object(
        &self,
        manifest: &uri::Rsync,
        file: &str
    ) -> Result<Option<StoredObject>, Failed> {
        self.object_tree.get(
            &Self::object_key(manifest, file)
        ).map(|value| {
            value.and_then(|value| StoredObject::try_from(value).ok())
        }).map_err(Into::into)
    }

    /// Calculates the key of an object in the object tree.
    fn object_key(manifest: &uri::Rsync, file: &str) -> Vec<u8> {
        format!("{}\0{}", manifest, file).into()
    }

    /// Updates a publication point in the repository.
    ///
    /// The publication point to be updated is given via its manifest’s
    /// signedObject URI.
    ///
    /// In order to be able to update multiple items of the publication point
    /// atomically, the actual update happens via a closure. This closure
    /// receives a [`RepositoryUpdate`] object that provides means to update
    /// the point’s manifest and objects. The closure should pass through any
    /// error returned by them. Alternatively, it can decide to abort the
    /// update by returning the error produced by [`UpdateError::abort`].
    ///
    /// Note that the closure may be executed multiple times if the underlying
    /// database decides it wants to give updating another try after a
    /// conflict. This is why this is an `Fn` closure and cannot consume any
    /// values in its context.
    ///
    /// If the update succeeds, the method returns whatever it is the closure
    /// returned. If it fails, it was either aborted by the closure or there
    /// was a database error. You can check whether it was indeed aborted by
    /// calling [`was_aborted`](UpdateError::was_aborted) on the error.
    pub fn update_point<T, F: Fn(RepositoryUpdate) -> Result<T, UpdateError>>(
        &self, manifest: &uri::Rsync, op: F
    ) -> Result<T, UpdateError> {
        (&self.manifest_tree, &self.object_tree).transaction(|(mt, ot)| {
            op(RepositoryUpdate::new(manifest, mt, ot)).map_err(|err| err.0)
        }).map_err(Into::into)
    }

    /// Completely removes a publication point.
    ///
    /// The publication point to be updated is given via its manifest’s
    /// signedObject URI.
    ///
    /// If the publication point exists, its manifest and all its objects are
    /// removed from the database.
    pub fn remove_point(
        &self, manifest: &uri::Rsync
    ) -> Result<(), Failed> {
        let mut batch = sled::Batch::default();
        for key in self.object_tree.scan_prefix(
            Self::object_key(manifest, "")
        ).keys() {
            batch.remove(key?);
        }
        (&self.manifest_tree, &self.object_tree).transaction(|(mt, ot)| {
            mt.remove(manifest.as_str())?;
            ot.apply_batch(&batch)?;
            Ok(())
        }).map_err(|err| {
            match err {
                TransactionError::Abort(()) => {
                    unreachable!() // Or is it?
                }
                TransactionError::Storage(err) => {
                    error!("Failed to update storage: {}", err);
                    Failed
                }
            }
        })
    }

    /// Retains only select objects from a publication point.
    ///
    /// The publication point to be updated is given via its manifest’s
    /// signedObject URI.
    ///
    /// For each object of the publication point, the closure `keep` is
    /// executed and receives the file name of the object on the manifest.
    /// If it returns `true`, the object is kept, otherwise it is removed.
    ///
    /// The manifest of the point is not removed.
    pub fn retain_objects(
        &self, manifest: &uri::Rsync,
        keep: impl Fn(&str) -> bool
    ) -> Result<(), Failed> {
        self._retain_objects(manifest.as_ref(), keep)
    }

    /// Retains only selected objects from a publication point.
    ///
    /// This differs from the public [`retain_objects`][Self::retain_objects]
    /// only in that it uses the raw manifest key for identifying the
    /// publication point (which is the octets of the manifest’s signedObject
    /// URI).
    pub fn _retain_objects(
        &self, manifest: &[u8],
        keep: impl Fn(&str) -> bool
    ) -> Result<(), Failed> {
        let mut prefix = Vec::with_capacity(manifest.len() + 1);
        prefix.extend_from_slice(manifest);
        prefix.push(0);
        let prefix = prefix;
        let prefix_len = prefix.len();
        for key in self.object_tree.scan_prefix(prefix).keys() {
            let key = key?;

            let keep_it = str::from_utf8(
                &key.as_ref()[prefix_len..]
            ).map(|key| keep(key)).unwrap_or(false);

            if !keep_it {
                self.object_tree.remove(key)?;
            }
        }
        Ok(())
    }

    /// Cleans the repository assuming it is the rsync repository.
    ///
    /// Removes all publication points that have an expired manifest.
    /// Registers all rsync modules that have at least one non-expired
    /// manifest to be retained by the collector.
    fn cleanup_rsync(
        self, collector: &mut collector::Cleanup
    ) -> Result<(), Failed> {
        let now = Time::now();

        for item in self.manifest_tree.iter() {
            let (key, bytes) = item?;
            let uri = match uri::Rsync::from_slice(&key) {
                Ok(uri) => {
                    match StoredManifest::decode_not_after(&bytes) {
                        Ok(not_after) if not_after > now => Some(uri),
                        _ => None
                    }
                }
                Err(_) => None
            };
            if let Some(uri) = uri {
                collector.retain_rsync_module(&uri);
            }
            else {
                self._retain_objects(&key, |_| false)?;
            }
        }

        Ok(())
    }

    /// Cleans the repository assuming it is an RRDP repository.
    ///
    /// Removes all publication points that have an expired manifest.
    /// Returns whether there was at least one non-expired manifest.
    fn cleanup_rrdp(self) -> Result<bool, Failed> {
        let now = Time::now();
        let mut keep_repository = false;

        for item in self.manifest_tree.iter() {
            let (key, bytes) = item?;
            let keep = match StoredManifest::decode_not_after(&bytes) {
                Ok(not_after) => not_after > now,
                Err(_) => false
            };
            if keep {
                keep_repository = true;
            }
            else {
                self._retain_objects(&key, |_| false)?;
            }
        }

        Ok(keep_repository)
    }
}


//------------ RepositoryUpdate ----------------------------------------------

/// An atomic update to a publication point in a repository.
///
/// This type allows you to update point’s manifest and insert or remove
/// objects of the publication point.
///
/// A value of this type is passed to the closure used in
/// [`Repository::update_point`].
pub struct RepositoryUpdate<'a> {
    /// The signedObject URI of the point’s manifest.
    manifest: &'a uri::Rsync,

    /// The transaction for updating the manifest.
    manifest_tran: &'a TransactionalTree,

    /// The transaction for updating the objects.
    object_tran: &'a TransactionalTree,
}

impl<'a> RepositoryUpdate<'a> {
    /// Creates an update from the manifest URI and the transactions.
    fn new(
        manifest: &'a uri::Rsync,
        manifest_tran: &'a TransactionalTree,
        object_tran: &'a TransactionalTree
    ) -> Self {
        RepositoryUpdate { manifest, manifest_tran, object_tran }
    }

    /// Updates the manifest for the publication point.
    ///
    /// If the publication point is new and has no manifest stored for it yet,
    /// the manifest will be inserted. The method returns whether that was
    /// indeed the case.
    pub fn update_manifest(
        &self, object: &StoredManifest
    ) -> Result<bool, UpdateError> {
        self.manifest_tran.insert(
            self.manifest.as_str(), object
        ).map(|res| res.is_some()).map_err(Into::into)
    }

    /// ‘Upserts’ an object of the publication point.
    ///
    /// The object is identified by its name on the manifest. If an object
    /// by that name is already stored, that object will be updated. If there
    /// is no object yet by that name, the object will be inserted. The method
    /// returns whether the object was indeed newly inserted.
    pub fn insert_object(
        &self, file: &str, object: &StoredObject
    ) -> Result<bool, UpdateError> {
        self.object_tran.insert(
            Repository::object_key(self.manifest, file),
            object
        ).map(|res| res.is_some()).map_err(Into::into)
    }

    /// Removes an object from the publication point.
    ///
    /// The object is identified by its name on the manifest. Returns whether
    /// the object existed and was actually removed.
    pub fn remove_object(&self, file: &str) -> Result<bool, UpdateError> {
        self.object_tran.remove(
            Repository::object_key(self.manifest, file)
        ).map(|res| res.is_some()).map_err(Into::into)
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

    /// The CA repository rsync URI of the issuing CA certificate.
    ca_repository: uri::Rsync,

    /// The raw content of the manifest.
    manifest: Bytes,

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
        ca_repository: uri::Rsync,
        manifest: Bytes,
        crl: Bytes,
    ) -> Self {
        StoredManifest { not_after, ca_repository, manifest, crl}
    }

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

    /// Decodes only the [`not_after`][Self::not_after] field.
    ///
    /// This is used to quickly check if the manifest is still valid during
    /// the cleanup without all the allocations necessary for actual decoding.
    fn decode_not_after(slice: &[u8]) -> Result<Time, ObjectError> {
        // See below for full encoding. First is a 0u8, then time encoded
        // as an i64 in network order.
        if slice.len() < mem::size_of::<i64>() + 1{
            return Err(ObjectError)
        }

        let slice = if slice.first().cloned() == Some(0) {
            &slice[1..]
        }
        else {
            return Err(ObjectError)
        };

        Ok(Utc.timestamp(
            i64::from_be_bytes(
                slice[..mem::size_of::<i64>()].try_into().unwrap()
            ),
            0
        ).into())
    }

}


//--- From and TryFrom

impl<'a> From<&'a StoredManifest> for sled::IVec {
    fn from(manifest: &'a StoredManifest) -> sled::IVec {
        // XXX Limiting the sizes to u32 _should_ be fine. Having bigger
        //     objects will probably cause mayhem before event getting here,
        //     so panicking should be fine, too?
        let ca_rep_len = u32::try_from(
            manifest.ca_repository.as_slice().len()
        ).expect("caRepository URL exceeds size limit");
        let manifest_len = u32::try_from(
            manifest.manifest.len()
        ).expect("manifest exceeds size limit");

        // Actual encoding:
        //
        // We start with a version number of 0u8. Then follows not_after
        // as the i64 timestamp in network order.
        // The caRepository URI and manifest bytes are encoded as its bytes
        // preceeded by the length as a u32 in network byte order. the CRL
        // bytes are just the bytes until the end of the buffer.
        let mut vec = Vec::new();

        vec.push(0u8);
        vec.extend_from_slice(&manifest.not_after.timestamp().to_be_bytes());

        vec.extend_from_slice(&ca_rep_len.to_be_bytes());
        vec.extend_from_slice(manifest.ca_repository.as_slice());
        
        vec.extend_from_slice(&manifest_len.to_be_bytes());
        vec.extend_from_slice(&manifest.manifest);

        vec.extend_from_slice(&manifest.crl);

        vec.into()
    }
}

impl TryFrom<sled::IVec> for StoredManifest {
    type Error = ObjectError;

    fn try_from(stored: sled::IVec) -> Result<StoredManifest, Self::Error> {
        if stored.len() == 0 {
            return Err(ObjectError);
        }
        let mut stored = Bytes::copy_from_slice(stored.as_ref());

        if stored.split_to(1).as_ref() != b"\0" {
            return Err(ObjectError)
        }
        let not_after = take_time(&mut stored)?;
        let len = take_encoded_len(&mut stored)?;
        if stored.len() < len {
            return Err(ObjectError)
        }
        let ca_repository = uri::Rsync::from_bytes(
            stored.split_to(len)
        ).map_err(|_| ObjectError)?;

        let len = take_encoded_len(&mut stored)?;
        if stored.len() < len {
            return Err(ObjectError)
        }
        let manifest = stored.split_to(len);

        Ok(StoredManifest { not_after, ca_repository, manifest, crl: stored })
    }
}


//------------ StoredObject --------------------------------------------------

/// The content of an object placed in the store.
///
/// This type collects all the data that is stored for regular objects of a
/// publication point: the raw bytes of the object as well as its hash as
/// stated on the publication point’s manifest.
#[derive(Clone, Debug)]
pub struct StoredObject {
    /// The manifest hash of the object if available.
    hash: Option<ManifestHash>,

    /// The content of the object.
    content: Bytes,
}

impl StoredObject {
    /// Creates a new stored object from its bytes and manifest hash.
    pub fn new(
        content: Bytes,
        hash: Option<ManifestHash>,
    ) -> Self {
        StoredObject { hash, content }
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

    /// Converts the stored object into the object’s raw bytes.
    pub fn into_content(self) -> Bytes {
        self.content
    }
}


//--- From and TryFrom

impl<'a> From<&'a StoredObject> for sled::IVec {
    fn from(object: &'a StoredObject) -> sled::IVec {
        let mut vec = Vec::new();

        // Version. 0u8.
        vec.push(0u8);

        // Encode the hash.
        //
        // One octet hash type: 0 .. None, 1 .. SHA-256
        // As many octets as the hash type requires.
        //
        // Unknown digest algorithms (there is non yet, but there may be) are
        // encoded as if the field was None.
        match object.hash.as_ref() {
            Some(hash) if hash.algorithm().is_sha256() => {
                vec.push(1);
                vec.extend_from_slice(hash.as_slice());
            }
            _ => {
                vec.push(0)
            }
        }
        
        // Encode the content.
        //
        // It is the rest of the value so no length octets needed.
        vec.extend_from_slice(object.content.as_ref());

        vec.into()
    }
}


impl TryFrom<sled::IVec> for StoredObject {
    type Error = ObjectError;

    fn try_from(stored: sled::IVec) -> Result<StoredObject, Self::Error> {
        if stored.len() == 0 {
            return Err(ObjectError);
        }
        let mut stored = Bytes::copy_from_slice(stored.as_ref());

        if stored.split_to(1).as_ref() != b"\0" {
            return Err(ObjectError)
        }

        // Decode the hash.
        let hash_type = stored.split_to(1);
        let hash = match hash_type.as_ref() {
            b"\x00" => None,
            b"\x01" => {
                let algorithm = DigestAlgorithm::sha256();
                if stored.len() < algorithm.digest_len() {
                    return Err(ObjectError)
                }
                let digest = stored.split_to(algorithm.digest_len());
                Some(ManifestHash::new(digest, algorithm))
            }
            _ => return Err(ObjectError)
        };

        Ok(StoredObject { hash, content: stored })
    }
}


//------------ TreeNames -----------------------------------------------------

/// The names for the manifest and object trees for a given repository.
///
/// This type exists so we are guaranteed to always use the same names.
struct TreeNames<'a> {
    /// The name of the repository.
    repository_name: &'a str,
}

impl<'a> TreeNames<'a> {
    /// Returns the tree names for a RRDP repository.
    pub fn rrdp(rpki_notify: &'a uri::Https) -> Self {
        TreeNames { repository_name: rpki_notify.as_str() }
    }

    /// Returns the tree names for the rsync repository.
    pub fn rsync() -> Self {
        TreeNames { repository_name: "rsync" }
    }

    pub fn manifest_tree_name(&self) -> Vec<u8> {
        format!("store:manifests:{}", self.repository_name).into()
    }

    pub fn object_tree_name(&self) -> Vec<u8> {
        format!("store:objects:{}", self.repository_name).into()
    }

    /// Opens the manifest tree referenced by `self` on the given database.
    pub fn open_manifest_tree(
        &self, db: &sled::Db
    ) -> Result<sled::Tree, sled::Error> {
        db.open_tree(&self.manifest_tree_name())
    }

    /// Opens the objects tree referenced by `self` on the given database.
    pub fn open_object_tree(
        &self, db: &sled::Db
    ) -> Result<sled::Tree, sled::Error> {
        db.open_tree(&self.object_tree_name())
    }

    /// Drops both trees referenced by `self` on the given database.
    pub fn drop_trees(&self, db: &sled::Db) -> Result<(), Failed> {
        db.drop_tree(&self.manifest_tree_name())?;
        db.drop_tree(&self.object_tree_name())?;
        Ok(())
    }
}


//------------ ObjectError ---------------------------------------------------

/// A stored object cannot be decoded correctly.
#[derive(Clone, Copy, Debug)]
pub struct ObjectError;

impl fmt::Display for ObjectError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("stored object cannot be decoded")
    }
}

impl error::Error for ObjectError { }


//------------ UpdateError ---------------------------------------------------

/// An update of a publication point has failed.
///
/// This can be deliberate if the update was aborted. Such an error can be
/// created via the [`UpdateError::abort`][Self::abort] function and checked
/// for via the [`was_aborted`][Self::was_aborted] method.
///
/// Otherwise, this is an error of the underlying database and should be
/// considered fatal.
#[derive(Clone, Debug)]
pub struct UpdateError(ConflictableTransactionError<Result<(), Failed>>);

impl UpdateError {
    /// Abort the update.
    pub fn abort() -> Self {
        UpdateError(ConflictableTransactionError::Abort(Ok(())))
    }

    /// A fatal error has happened during processing.
    pub fn failed() -> Self {
        UpdateError(ConflictableTransactionError::Abort(Err(Failed)))
    }

    /// Returns whether the update was aborted.
    pub fn was_aborted(&self) -> bool {
        matches!(self.0, ConflictableTransactionError::Abort(Ok(())))
    }

    pub fn has_failed(&self) -> bool {
        !self.was_aborted()
    }
}

impl From<Failed> for UpdateError {
    fn from(_: Failed) -> Self {
        Self::failed()
    }
}

impl From<UnabortableTransactionError> for UpdateError {
    fn from(err: UnabortableTransactionError) -> Self {
        UpdateError(err.into())
    }
}

impl From<TransactionError<Result<(), Failed>>> for UpdateError {
    fn from(err: TransactionError<Result<(), Failed>>) -> Self {
        UpdateError(match err {
            TransactionError::Abort(abort)
                => ConflictableTransactionError::Abort(abort),
            TransactionError::Storage(err)
                => ConflictableTransactionError::Storage(err)
        })
    }
}


//------------ Helper Functions ----------------------------------------------

/// Takes an encoded `Time` value from the beginning of a bytes value.
///
/// Upon success, the decoded time will be returned and `bytes` will have
/// been modified to start after the encoded time.
fn take_time(bytes: &mut Bytes) -> Result<Time, ObjectError> {
    if bytes.len() < mem::size_of::<i64>() {
        return Err(ObjectError)
    }

    let int_bytes = bytes.split_to(mem::size_of::<i64>());
    let int = i64::from_be_bytes(int_bytes.as_ref().try_into().unwrap());
    Ok(Utc.timestamp(int, 0).into())
}


/// Takes an encoded sequence length from the beginning of a bytes value.
///
/// Upon success, the decoded length will be returned and `bytes` will have
/// been modified to start after the encoded length.
///
/// All lengths are encoded as `u32` in network byte order, even if we
/// return `usize` for convenience.
fn take_encoded_len(bytes: &mut Bytes) -> Result<usize, ObjectError> {
    if bytes.len() < mem::size_of::<u32>() {
        return Err(ObjectError)
    }

    let int_bytes = bytes.split_to(mem::size_of::<u32>());
    usize::try_from(
        u32::from_be_bytes(int_bytes.as_ref().try_into().unwrap())
    ).map_err(|_| ObjectError)
}


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn encoded_stored_manifest() {
        let orig = StoredManifest::new(
            Time::utc(2021, 02, 18, 13, 22, 06),
            uri::Rsync::from_str("rsync://foo.bar/bla/blubb").unwrap(),
            Bytes::from(b"foobar".as_ref()),
            Bytes::from(b"blablubb".as_ref())
        );

        let encoded = sled::IVec::from(&orig);
        assert_eq!(
            StoredManifest::decode_not_after(&encoded).unwrap(),
            orig.not_after
        );
        let decoded = StoredManifest::try_from(encoded).unwrap();
        assert_eq!(orig, decoded);
    }

    #[test]
    fn encoded_stored_object() {
        let orig = StoredObject::new(
            Bytes::from(b"foobar".as_ref()),
            None
        );
        let decoded = StoredObject::try_from(
            sled::IVec::from(&orig)
        ).unwrap();
        assert_eq!(orig.hash, decoded.hash);
        assert_eq!(orig.content, decoded.content);
    }
}

