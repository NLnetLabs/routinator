//! A store for correctly published RPKI objects.

use std::{error, fmt, fs, io, mem};
use std::convert::{TryFrom, TryInto};
use bytes::Bytes;
use chrono::{TimeZone, Utc};
use log::error;
use rpki::repository::crypto::digest::DigestAlgorithm;
use rpki::repository::crypto::keys::KeyIdentifier;
use rpki::repository::manifest::ManifestHash;
use rpki::repository::tal::TalUri;
use rpki::repository::x509::{Time, ValidationError};
use rpki::uri;
use sled::Transactional;
use sled::transaction::{
    ConflictableTransactionError, TransactionalTree, TransactionError,
    UnabortableTransactionError
};
use crate::cache;
use crate::config::Config;
use crate::metrics::Metrics;
use crate::operation::Error;
use crate::validation::CaCert;


//------------ Store ---------------------------------------------------------

/// A store for correctly published RPKI objects.
#[derive(Clone, Debug)]
pub struct Store {
    /// The database.
    db: sled::Db,

    /// Is rsync support disabled?
    disable_rsync: bool,

    /// Is RRDP support disabled?
    disable_rrdp: bool,
}

impl Store {
    /// Initializes the store.
    pub fn init(config: &Config) -> Result<(), Error> {
        // XXX This checks that config.cache_dir exists which actually happens
        //     elsewhere again. Perhaps move it to Config and only do it once?
        if let Err(err) = fs::read_dir(&config.cache_dir) {
            if err.kind() == io::ErrorKind::NotFound {
                error!(
                    "Missing repository directory {}.\n\
                     You may have to initialize it via \
                     \'routinator init\'.",
                     config.cache_dir.display()
                );
            }
            else {
                error!(
                    "Failed to open repository directory {}: {}",
                    config.cache_dir.display(), err
                );
            }
            return Err(Error)
        }
        Ok(())

    }

    /// Creates a new store.
    pub fn new(config: &Config) -> Result<Self, Error> {
        Self::init(config)?;
        let db_path = config.cache_dir.join("store.db");
        let db = match sled::open(&db_path) {
            Ok(db) => db,
            Err(err) => {
                error!(
                    "Failed to open storage database at {}: {}",
                    db_path.display(),
                    err
                );
                return Err(Error);
            }
        };
        Ok(Self::with_db(db, config.disable_rsync, config.disable_rrdp))
    }

    /// Creates a store using a provided database.
    pub fn with_db(
        db: sled::Db, disable_rsync: bool, disable_rrdp: bool
    ) -> Self {
        Store { db, disable_rsync, disable_rrdp }
    }

    /// Start a validation run with the store.
    pub fn start(&self) -> Run {
        Run::new(self)
    }

    pub fn cleanup(
        &self,
        mut cache: cache::Cleanup,
    ) -> Result<(), Error> {
        if !self.disable_rrdp {
            for tree_name in self.db.tree_names() {
                if let Ok(rpki_notify) = uri::Https::from_slice(&tree_name) {
                    let names = TreeNames::from_rpki_notify(
                        Some(&rpki_notify)
                    );
                    if Repository::new(self, &names)?.cleanup_rrdp()? {
                        cache.retain_rrdp_repository(&rpki_notify);
                    }
                    else {
                        names.drop_trees(&self.db)?;
                    }
                }
            }
        }
        if !self.disable_rsync {
            Repository::new(
                self, &TreeNames::rsync()
            )?.cleanup_rsync(&mut cache)?
        }
        cache.commit();
        Ok(())
    }

}


//------------ Run -----------------------------------------------------------

/// A single validation run on using the store.
#[derive(Debug)]
pub struct Run<'a> {
    store: &'a Store,
}

impl<'a> Run<'a> {
    fn new(
        store: &'a Store,
    ) -> Self {
        Run { store }
    }

    pub fn done(self, _metrics: &mut Metrics) {
    }

    pub fn load_ta(&self, uri: &TalUri) -> Result<Option<Bytes>, Error> {
        self.store.db.get(uri.as_str()).map(|value| {
            value.map(|value| Bytes::copy_from_slice(value.as_ref()))
        }).map_err(Into::into)
    }

    pub fn update_ta(
        &self, uri: &TalUri, content: &[u8]
    ) -> Result<bool, Error> {
        self.store.db.insert(
            uri.as_str(), content
        ).map(|res| res.is_some()).map_err(Into::into)
    }

    pub fn repository(
        &self, ca: &CaCert
    ) -> Result<Repository, Error> {
        if !self.store.disable_rrdp {
            Repository::new(self.store, &TreeNames::from_rpki_notify(
                ca.rpki_notify())
            )
        }
        else {
            Repository::new(self.store, &TreeNames::from_rpki_notify(None))
        }
    }
}


//------------ Repository ----------------------------------------------------

/// Access to a single repository during a validation run.
#[derive(Debug)]
pub struct Repository {
    is_rsync: bool,
    manifest_tree: sled::Tree,
    object_tree: sled::Tree,
}

impl Repository {
    fn new(
        store: &Store,
        names: &TreeNames,
    ) -> Result<Self, Error> {
        Ok(Repository {
            is_rsync: names.is_rsync,
            manifest_tree: names.open_manifest_tree(&store.db)?,
            object_tree: names.open_object_tree(&store.db)?,
        })
    }

    pub fn load_manifest(
        &self, uri: &uri::Rsync
    ) -> Result<Option<StoredManifest>, Error> {
        self.manifest_tree.get(uri.as_slice()).map(|value| {
            value.and_then(|value| StoredManifest::try_from(value).ok())
        }).map_err(Into::into)
    }

    pub fn load_object(
        &self,
        manifest: &uri::Rsync,
        file: &[u8]
    ) -> Result<Option<StoredObject>, Error> {
        self.object_tree.get(
            &Self::object_key(manifest, file)
        ).map(|value| {
            value.and_then(|value| StoredObject::try_from(value).ok())
        }).map_err(Into::into)
    }

    fn object_key(manifest: &uri::Rsync, file: &[u8]) -> Vec<u8> {
        let mut res = Vec::with_capacity(
            manifest.as_slice().len() + file.len() + 1
        );
        res.extend_from_slice(manifest.as_slice());
        res.push(0);
        res.extend_from_slice(file);
        res
    }

    pub fn update_point<T, F: Fn(RepositoryUpdate) -> Result<T, UpdateError>>(
        &self, manifest: &uri::Rsync, op: F
    ) -> Result<T, UpdateError> {
        (&self.manifest_tree, &self.object_tree).transaction(|(mt, ot)| {
            op(RepositoryUpdate::new(manifest, mt, ot)).map_err(|err| err.0)
        }).map_err(Into::into)
    }

    pub fn remove_point(
        &self, manifest: &uri::Rsync
    ) -> Result<(), Error> {
        let mut batch = sled::Batch::default();
        for key in self.object_tree.scan_prefix(
            Self::object_key(manifest, b"")
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
                    Error
                }
            }
        })
    }

    pub fn drain_point(
        &self, manifest: &uri::Rsync,
        keep: impl Fn(&[u8]) -> bool
    ) -> Result<(), Error> {
        self._drain_point(manifest.as_ref(), keep)
    }

    pub fn _drain_point(
        &self, manifest: &[u8],
        keep: impl Fn(&[u8]) -> bool
    ) -> Result<(), Error> {
        let mut prefix = Vec::with_capacity(manifest.len() + 1);
        prefix.extend_from_slice(manifest);
        prefix.push(0);
        let prefix = prefix;
        let prefix_len = prefix.len();
        for key in self.object_tree.scan_prefix(prefix).keys() {
            let key = key?;
            if !keep(&key.as_ref()[prefix_len..]) {
                self.object_tree.remove(key)?;
            }
        }
        Ok(())
    }

    fn cleanup_rsync(self, cache: &mut cache::Cleanup) -> Result<(), Error> {
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
                cache.retain_rsync_module(&uri);
            }
            else {
                self._drain_point(&key, |_| false)?;
            }
        }

        Ok(())
    }

    fn cleanup_rrdp(self) -> Result<bool, Error> {
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
                self._drain_point(&key, |_| false)?;
            }
        }

        Ok(keep_repository)
    }
}


//------------ RepositoryUpdate ----------------------------------------------

/// An atomic update to a repository.
pub struct RepositoryUpdate<'a> {
    manifest: &'a uri::Rsync,
    manifest_tran: &'a TransactionalTree,
    object_tran: &'a TransactionalTree,
}

impl<'a> RepositoryUpdate<'a> {
    fn new(
        manifest: &'a uri::Rsync,
        manifest_tran: &'a TransactionalTree,
        object_tran: &'a TransactionalTree
    ) -> Self {
        RepositoryUpdate { manifest, manifest_tran, object_tran }
    }

    pub fn update_manifest(
        &self, object: &StoredManifest
    ) -> Result<bool, UpdateError> {
        self.manifest_tran.insert(
            self.manifest.as_str(), object
        ).map(|res| res.is_some()).map_err(Into::into)
    }

    pub fn insert_object(
        &self, file: &[u8], object: &StoredObject
    ) -> Result<bool, UpdateError> {
        self.object_tran.insert(
            Repository::object_key(self.manifest, file),
            object
        ).map(|res| res.is_some()).map_err(Into::into)
    }

    pub fn remove_object(&self, file: &[u8]) -> Result<bool, UpdateError> {
        self.object_tran.remove(
            Repository::object_key(self.manifest, file)
        ).map(|res| res.is_some()).map_err(Into::into)
    }
}


//------------ StoredManifest ------------------------------------------------

/// The content of a manifest placed in the store.
#[derive(Clone, Debug)]
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
    pub fn new(
        not_after: Time,
        ca_repository: uri::Rsync,
        manifest: Bytes,
        crl: Bytes,
    ) -> Self {
        StoredManifest { not_after, ca_repository, manifest, crl}
    }

    pub fn not_after(&self) -> Time {
        self.not_after
    }

    pub fn ca_repository(&self) -> &uri::Rsync {
        &self.ca_repository
    }

    pub fn manifest(&self) -> &Bytes {
        &self.manifest
    }

    pub fn crl(&self) -> &Bytes {
        &self.crl
    }

    fn decode_not_after(slice: &[u8]) -> Result<Time, ObjectError> {
        // See below for full encoding. The time is at the start and encoded
        // as an i64 in network order.
        if slice.len() < mem::size_of::<i64>() {
            return Err(ObjectError)
        }
        Ok(Utc.timestamp(
            i64::from_be_bytes(
                slice[..mem::size_of::<i64>()].try_into().unwrap()
            ),
            0
        ).into())
    }

}


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

        // Actual encoding: not_after is the i64 timestamp in network order.
        // The caRepository URI and manifest bytes are encoded as its bytes
        // preceeded by the length as a u32 in network byte order. the CRL
        // bytes are just the bytes until the end of the buffer.
        let mut vec = Vec::new();

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
#[derive(Clone, Debug)]
pub struct StoredObject {
    /// The manifest hash of the object if available.
    hash: Option<ManifestHash>,

    /// The key identifier for the CA cert that signed the object.
    ca_key: Option<KeyIdentifier>,

    /// The content of the object.
    content: Bytes,
}

impl StoredObject {
    pub fn new(
        content: Bytes,
        hash: Option<ManifestHash>,
        ca_key: Option<KeyIdentifier>,
    ) -> Self {
        StoredObject { hash, ca_key, content }
    }

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

    pub fn into_content(self) -> Bytes {
        self.content
    }
}

impl<'a> From<&'a StoredObject> for sled::IVec {
    fn from(object: &'a StoredObject) -> sled::IVec {
        let mut vec = Vec::new();

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

        // Encode CA key identifier.
        //
        // One octets as the identifier length followed by that many octets.
        // A length of zero means `None`.
        match object.ca_key.as_ref() {
            Some(key) => {
                let key = key.as_slice();
                vec.push(u8::try_from(key.len()).unwrap());
                vec.extend_from_slice(key);
            }
            None => {
                vec.push(0);
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

        // Decode the CA key identifier.
        if stored.is_empty() {
            return Err(ObjectError)
        }
        let key_len = usize::from(stored.split_to(1)[0]);
        let ca_key = if key_len == 0 {
            None
        }
        else {
            if stored.len() < key_len {
                return Err(ObjectError)
            }
            Some(
                KeyIdentifier::try_from(
                    stored.split_to(key_len).as_ref()
                ).map_err(|_| ObjectError)?
            )
        };

        Ok(StoredObject { hash, ca_key, content: stored })
    }
}


//------------ TreeNames -----------------------------------------------------

/// The names for the manifest and object trees for a given repository.
struct TreeNames<'a> {
    is_rsync: bool,
    manifests: &'a [u8],
    objects: Vec<u8>,
}

impl<'a> TreeNames<'a> {
    pub fn from_rpki_notify(rpki_notify: Option<&'a uri::Https>) -> Self {
        match rpki_notify {
            Some(uri) => Self::from_manifest_name(uri.as_ref()),
            None => Self::rsync()
        }
    }

    pub fn rsync() -> Self {
        Self::new(true, b"rsync")
    }

    pub fn from_manifest_name(manifests: &'a [u8]) -> Self {
        Self::new(false, manifests)
    }

    fn new(is_rsync: bool, manifests: &'a [u8]) -> Self {
        let mut objects = Vec::with_capacity(manifests.len() + 8);
        objects.extend_from_slice(b"objects:");
        objects.extend_from_slice(manifests);
        TreeNames { is_rsync, manifests, objects }
    }

    pub fn open_manifest_tree(
        &self, db: &sled::Db
    ) -> Result<sled::Tree, sled::Error> {
        db.open_tree(self.manifests)
    }

    pub fn open_object_tree(
        &self, db: &sled::Db
    ) -> Result<sled::Tree, sled::Error> {
        db.open_tree(&self.objects)
    }

    pub fn drop_trees(&self, db: &sled::Db) -> Result<(), Error> {
        db.drop_tree(self.manifests)?;
        db.drop_tree(&self.objects)?;
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

#[derive(Clone, Debug)]
pub struct UpdateError(ConflictableTransactionError<()>);

impl UpdateError {
    pub fn abort() -> Self {
        UpdateError(ConflictableTransactionError::Abort(()))
    }

    pub fn was_aborted(&self) -> bool {
        matches!(self.0, ConflictableTransactionError::Abort(_))
    }
}

impl From<UnabortableTransactionError> for UpdateError {
    fn from(err: UnabortableTransactionError) -> Self {
        UpdateError(err.into())
    }
}

impl From<TransactionError<()>> for UpdateError {
    fn from(err: TransactionError<()>) -> Self {
        UpdateError(match err {
            TransactionError::Abort(())
                => ConflictableTransactionError::Abort(()),
            TransactionError::Storage(err)
                => ConflictableTransactionError::Storage(err)
        })
    }
}


//------------ Sled Error Conversion -----------------------------------------

impl From<sled::Error> for Error {
    fn from(err: sled::Error) -> Error {
        error!("RPKI storage error: {}", err);
        Error
    }
}

//------------ Helper Functions ----------------------------------------------

fn take_time(bytes: &mut Bytes) -> Result<Time, ObjectError> {
    if bytes.len() < mem::size_of::<i64>() {
        return Err(ObjectError)
    }

    let int_bytes = bytes.split_to(mem::size_of::<i64>());
    let int = i64::from_be_bytes(int_bytes.as_ref().try_into().unwrap());
    Ok(Utc.timestamp(int, 0).into())
}


fn take_encoded_len(bytes: &mut Bytes) -> Result<usize, ObjectError> {
    if bytes.len() < mem::size_of::<u32>() {
        return Err(ObjectError)
    }

    let int_bytes = bytes.split_to(mem::size_of::<u32>());
    usize::try_from(
        u32::from_be_bytes(int_bytes.as_ref().try_into().unwrap())
    ).map_err(|_| ObjectError)
}

