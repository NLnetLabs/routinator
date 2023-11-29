//! A simple archive for RRDP repository data.
//!
//! This module contains a very simple file archive that is tailored towards
//! the needs of RRDP. It can be used to store the RPKI objects published via
//! RRDP in a single file per repository.
//!
//! Each archive is a sequence of objects (basically: files, but the term is
//! confusingly overloaded in this context) preceeded by its name and size
//! and some additional accounting information. An object can be empty and
//! its space available for use by new objects. When objects are deleted, they
//! are replaced by such empty objects.
//!
//! If a new object needs to be added, an attempt is made to reuse the largest
//! empty object that it fits into. If there aren’t any empty objects it would
//! fit into, it is simply appended to the end of the archive.
//! 
//! If an object needs to be updated and the new version is the same
//! size, it is just overwritten. If it is smaller, it is overwritten and the
//! remaining space added as an empty object. It if is larger, it is appended
//! at the end of the archive and the old version replaced by an empty object.
//!
//! For finding objects with a given name, an index is kept. This index is
//! essentially a hash map with a linked list for each bucket. The basic
//! index is created at the beginning of the archive. It consists of an array
//! of pointers to an object who’s name hashes into that bucket. Each
//! object’s header contains a pointer to the next object in the same bucket.
//! An additional bucket contains a pointer to the first empty object.
//!
//! If possible (currently on Unix systems only), the file is memory mapped
//! for faster access.

use std::{fmt, fs, io, mem};
use std::borrow::Cow;
use std::hash::Hasher;
use std::marker::PhantomData;
use std::num::{NonZeroU64, NonZeroUsize};
use std::ops::Range;
use std::path::Path;
use std::io::{Read, Seek, SeekFrom, Write};
use bytes::Bytes;
use siphasher::sip::SipHasher24;
use crate::utils::sync::{Mutex, MutexGuard};


//------------ Configuration -------------------------------------------------

/// The default number of buckets.
///
/// This value has been picked out of thin air for now. We should probably
/// switch to a model that derives this from from the size of a snapshot.
const DEFAULT_BUCKET_COUNT: usize = 1024;


//------------ Archive -------------------------------------------------------

/// A simple object archive in a file.
///
/// An archive is backed by a single file and stores any number of objects
/// identified by a name. Additionally, application-specific meta data can
/// be stored through the type provided via the `Meta` type argument and the
/// [`ObjectMeta`] trait.
///
/// Object can be added – which is called _publish_ –, update, deleted, and,
/// of course read – which we call _fetch._
#[derive(Debug)]
pub struct Archive<Meta> {
    /// The physical file.
    file: Storage,

    /// The meta data of the archive.
    meta: ArchiveMeta,

    /// A marker for the Meta type argument.
    marker: PhantomData<Meta>,
}

impl<Meta> Archive<Meta> {
    /// Creates a new archive at the given path.
    ///
    /// The archive is opened for reading and writing.
    ///
    /// If there already is a file at the given path, the function fails.
    pub fn create(path: impl AsRef<Path>) -> Result<Self, ArchiveError> {
        Self::create_with_file(
            fs::OpenOptions::new()
                .read(true).write(true).create_new(true)
                .open(path)?
        )
    }

    /// Create a new archive inside a given file.
    ///
    /// The file is trunacated back to zero length and the header and index
    /// added.
    pub fn create_with_file(
        mut file: fs::File
    ) -> Result<Self, ArchiveError> {
        file.set_len(0)?;
        let meta = ArchiveMeta::new(DEFAULT_BUCKET_COUNT);
        file.write_all(&FILE_MAGIC)?;
        meta.write(&mut file)?;
        let len = file.stream_position()? + Self::index_size(&meta);
        file.set_len(len)?;

        Ok(Self {
            file: Storage::new(file, true)?,
            meta,
            marker: PhantomData,
        })
    }

    /// Opens an existing archive at the given path.
    ///
    /// Returns an error if the file doesn’t start with header and index.
    pub fn open(
        path: impl AsRef<Path>, writable: bool
    ) -> Result<Self, OpenError> {
        let mut file = 
            fs::OpenOptions::new().read(true).write(writable).open(path)?;
        let mut magic = [0; MAGIC_SIZE];
        file.read_exact(&mut magic)?;
        if magic != FILE_MAGIC {
            return Err(ArchiveError::Corrupt.into())
        }
        let meta = ArchiveMeta::read(&mut file)?;

        Ok(Self {
            file: Storage::new(file, writable)?,
            meta,
            marker: PhantomData,
        })
    }

    /// Verifies the consistency of an archive.
    ///
    /// The method traverses the entire archive and makes sure that the
    /// entiry file is covered by objects and that these objects aren’t
    /// overlapping.
    pub fn verify(&self) -> Result<(), ArchiveError> {
        // We’re going to collect a list of all encountered objects in here.
        // Items are pair of the start position and the length.
        // At the end we check that they form a consecutive sequence.
        let mut objects = Vec::new();

        // Step 1. Go over each index bucket and collect all the objects.
        // Check that the name hashes correctly.
        for idx in 0.. usize_to_u64(self.meta.bucket_count) {
            let mut start = self.get_index(idx)?;
            while let Some(pos) = start {
                let (header, name) = ObjectHeader::read_with_name(
                    &self.file, pos.into()
                )?;
                if self.hash_name(&name) != idx {
                    return Err(ArchiveError::Corrupt)
                }
                objects.push((u64::from(pos), header.size));
                start = header.next;
            }
        }

        // Step 2. Go over the empty space.
        let mut start = self.get_empty_index()?;
        while let Some(pos) = start {
            let header = ObjectHeader::read(&self.file, pos.into())?;
            objects.push((u64::from(pos), header.size));
            start = header.next;
        }

        // Step 3. Check them objects.
        objects.sort_by(|left, right| left.0.cmp(&right.0));

        for window in objects.windows(2) {
            if window[1].0 != window[0].0 + window[0].1 {
                return Err(ArchiveError::Corrupt)
            }
        }

        Ok(())
    }

    /// Returns an iterator over all the objects in the archive.
    ///
    /// The iterator will _not_ traverse objects in any kind of order.
    pub fn objects(&self) -> Result<ObjectsIter<Meta>, ArchiveError> {
        ObjectsIter::new(self)
    }
}

/// # Access to specific objects
///
impl<Meta: ObjectMeta> Archive<Meta> {
    /// Returns the content of the object with the given name.
    ///
    /// Assumes that the object exists and returns an error if not.
    ///
    /// The method returns borrowed data if the archive is currently memory
    /// mapped or owned data otherwise.
    pub fn fetch(
        &self,
        name: &[u8],
    ) -> Result<Cow<[u8]>, FetchError> {
        let hash = self.hash_name(name);
        let found = match self.find(hash, name)? {
            Some(found) => found,
            None => return Err(FetchError::NotFound),
        };
        self.file.read(found.data_start::<Meta>(), |read| {
            Ok(read.read_slice(found.header.data_size::<Meta>()?)?)
        })
    }

    /// Returns the content of the object with the given name as bytes.
    ///
    /// Assumes that the object exists and returns an error if not.
    pub fn fetch_bytes(
        &self,
        name: &[u8],
    ) -> Result<Bytes, FetchError> {
        self.fetch(name).map(|res| {
            match res {
                Cow::Borrowed(slice) => Bytes::copy_from_slice(slice),
                Cow::Owned(vec) => vec.into()
            }
        })
    }

    /// Fetch the contents of an object.
    ///
    /// The object is identified by its `name`. The closure `check` can be
    /// used to verify that the object has the expected additional
    /// properties stored in the meta data.
    ///
    /// Upon success, the contents will be returned as a cow. This will be
    /// a slice of the memory mapped contents of the backing file if this is
    /// available and a vec otherwise.
    ///
    /// The method will return an error if the file does not exists. It will
    /// also return an error if the `check` closure refuses the object.
    /// Finally, it will return an error if the archive is discovered to be
    /// broken or cannot be accessed.
    pub fn fetch_if(
        &self,
        name: &[u8],
        check: impl FnOnce(&Meta) -> Result<(), Meta::ConsistencyError>,
    ) -> Result<Cow<[u8]>, AccessError<Meta::ConsistencyError>> {
        let hash = self.hash_name(name);
        let found = match self.find(hash, name)? {
            Some(found) => found,
            None => return Err(AccessError::NotFound),
        };
        self.file.read(found.meta_start(), |read| {
            check(
                &Meta::read(read)?
            ).map_err(AccessError::Inconsistent)?;
            Ok(read.read_slice(found.header.data_size::<Meta>()?)?)
        })
    }

    /// Publishes (i.e., adds) a new object.
    ///
    /// The object will be identified by the given `name` and carry the
    /// given `meta` data and contents `data`.
    ///
    /// The method will return an error if there already is an object by
    /// `name`. It will also error if the archive is found to be broken or
    /// cannot be accessed.
    pub fn publish(
        &mut self, name: &[u8], meta: &Meta, data: &[u8]
    ) -> Result<(), PublishError> {
        let hash = self.hash_name(name);
        if self.find(hash, name)?.is_some() {
            return Err(PublishError::AlreadyExists)
        }
        match self.find_empty(name, data)? {
            Some((empty, pos)) => {
                self.publish_replace(hash, name, meta, data, empty, pos)?
            }
            None => self.publish_append(hash, name, meta, data)?,
        }
        Ok(())
    }

    /// Publishes a new object in the space of the given empty object.
    ///
    /// This assumes that the object fits and that there is either no space
    /// at the end or that there is enough space to add at least an object
    /// header.
    ///
    /// The empty space starts at `start`. It’s previously used object header
    /// is provided through `empty`, which includes the size as well as the
    /// next pointer to keep the chain intact.
    fn publish_replace(
        &mut self,
        hash: u64, name: &[u8], meta: &Meta, data: &[u8],
        mut empty: ObjectHeader, start: NonZeroU64,
    ) -> Result<(), ArchiveError> {
        self.unlink_empty(start.into(), empty.next)?;
        let empty_end = u64::from(start) + empty.size;
        let head = ObjectHeader::new(
            Self::object_size(name, data), self.get_index(hash)?, name
        );
        let object_end = self.write_object(
            start.into(), head, name, meta, data
        )?;
        self.set_index(hash, start.into())?;
        if empty_end > object_end {
            empty.size = empty_end - object_end;
            assert!(empty.size >= ObjectHeader::SIZE);
            empty.next = self.get_empty_index()?;
            empty.write(&mut self.file, object_end)?;
            self.set_empty_index(NonZeroU64::new(object_end))?;
        }
        Ok(())
    }

    /// Publishes a new object by appending it to the end of the archive.
    fn publish_append(
        &mut self, hash: u64, name: &[u8], meta: &Meta, data: &[u8]
    ) -> Result<(), ArchiveError> {
        let start = self.file.size;
        let head = ObjectHeader::new(
            Self::object_size(name, data), self.get_index(hash)?, name
        );
        self.write_object(start, head, name, meta, data)?;
        self.set_index(hash, NonZeroU64::new(start))?;
        Ok(())
    }

    /// Updates an object with new meta data and content.
    ///
    /// The `check` closure received the meta data of the current object and
    /// can be used to verify that the current meta data fulfills certain
    /// requirements or return a consistency error otherwise.
    ///
    /// The method will return an error if there is no object with `name`.
    /// It will also return an error if the `check` closure fails or if the
    /// archive is broken or cannot be accessed.
    pub fn update(
        &mut self,
        name: &[u8], meta: &Meta, data: &[u8],
        check: impl FnOnce(&Meta) -> Result<(), Meta::ConsistencyError>,
    ) -> Result<(), AccessError<Meta::ConsistencyError>> {
        let hash = self.hash_name(name);
        let found = match self.find(hash, name)? {
            Some(found) => found,
            None => return Err(AccessError::NotFound),
        };
        check(
            &self.file.read(found.meta_start(), |read| Meta::read(read))?
        ).map_err(AccessError::Inconsistent)?;

        let new_size = Self::object_size(name, data);
        if Self::fits(found.header.size, new_size) {
            // We can squeeze the new object data into its current space.
            ObjectHeader::update_size(found.start, new_size, &mut self.file)?;
            self.file.write(found.meta_start(), |write| {
                meta.write(write)?;
                write.write(data)
            })?;
            // If there’s empty space, we need to mark and add that.
            let empty_size = found.header.size - new_size;
            if empty_size > 0 {
                self.create_empty(
                    found.start + new_size,
                    empty_size,
                )?;
            }
        }
        else {
            self.delete_found(hash, found)?;
            self.publish_append(hash, name, meta, data)?;
        }
        Ok(())
    }

    /// Deletes an object.
    ///
    /// The `check` closure received the meta data of the current object and
    /// can be used to verify that the current meta data fulfills certain
    /// requirements or return a consistency error otherwise.
    ///
    /// The method will return an error if there is no object with `name`.
    /// It will also return an error if the `check` closure fails or if the
    /// archive is broken or cannot be accessed.
    pub fn delete(
        &mut self,
        name: &[u8],
        check: impl FnOnce(&Meta) -> Result<(), Meta::ConsistencyError>,
    ) -> Result<(), AccessError<Meta::ConsistencyError>> {
        let hash = self.hash_name(name);
        let found = match self.find(hash, name)? {
            Some(found) => found,
            None => return Err(AccessError::NotFound),
        };
        check(
            &self.file.read(found.meta_start(), |read| Meta::read(read))?
        ).map_err(AccessError::Inconsistent)?;
        Ok(self.delete_found(hash, found)?)
    }

    /// Deletes an object after it has been found.
    ///
    /// This unlinks the object from its bucket chain and replaces it with an
    /// empty object.
    fn delete_found(
        &mut self, hash: u64, found: FoundObject
    ) -> Result<(), ArchiveError> {
        match found.prev {
            Some(pos) => {
                ObjectHeader::update_next(
                    pos.into(), found.header.next, &mut self.file)?
            }
            None => self.set_index(hash, found.header.next)?,
        }
        self.create_empty(found.start, found.header.size)?;
        Ok(())
    }

    /// Creates an empty object.
    fn create_empty(
        &mut self, start: u64, mut size: u64
    ) -> Result<(), ArchiveError> {
        let next_start = start.saturating_add(size);
        if next_start < self.file.size {
            let header = ObjectHeader::read(&self.file, next_start)?;
            if header.name_len.is_none() {
                self.unlink_empty(next_start, header.next)?;
                size += header.size;
            }
        }
        ObjectHeader::new_empty(size, self.get_empty_index()?).write(
            &mut self.file, start
        )?;
        self.set_empty_index(NonZeroU64::new(start))?;
        Ok(())
    }

    /// Unlinks an empty object from the empty chain.
    fn unlink_empty(
        &mut self, start: u64, next: Option<NonZeroU64>
    ) -> Result<(), ArchiveError> {
        let mut curr = self.get_empty_index()?;
        let start = NonZeroU64::new(start);

        // We are the start of the chain.
        if curr == start {
            self.set_empty_index(next)?;
            return Ok(())
        }

        // We are further down the chain.
        while let Some(pos) = curr {
            let header = ObjectHeader::read(&self.file, pos.into())?;
            if header.next == start {
                ObjectHeader::update_next(pos.into(), next, &mut self.file)?;
                return Ok(())
            }
            curr = header.next;
        }

        // We are not in the chain at all???
        Err(ArchiveError::Corrupt)
    }

    /// Finds the start of the object with the given name.
    fn find(
        &self, hash: u64, name: &[u8]
    ) -> Result<Option<FoundObject>, ArchiveError> {
        let mut start = self.get_index(hash)?;
        let mut prev = None;
        while let Some(pos) = start {
            let (header, object_name) = ObjectHeader::read_with_name(
                &self.file, pos.into()
            )?;
            if name == object_name.as_ref() {
                return Ok(Some(FoundObject {
                    start: pos.into(),
                    header, 
                    prev,
                }))
            }
            prev = Some(pos);
            start = header.next;
        }
        Ok(None)
    }

    /// Finds empty space large enough to contain the given data.
    ///
    /// Returns `None` if no such space can be found. Otherwise returns
    /// the object header of the empty space and the starting position.
    fn find_empty(
        &self, name: &[u8], data: &[u8]
    ) -> Result<Option<(ObjectHeader, NonZeroU64)>, ArchiveError> {
        let mut start = self.get_empty_index()?;
        if start.is_none() {
            return Ok(None)
        }
        let size = Self::object_size(name, data);
        let mut candidates = Vec::new();
        while let Some(pos) = start {
            let header = ObjectHeader::read(&self.file, pos.into())?;
            start = header.next;
            if Self::fits(header.size, size) {
                candidates.push((header, pos));
            }
        }
        if candidates.is_empty() {
            return Ok(None)
        }
        candidates.sort_by(|left, right| left.0.size.cmp(&right.0.size));
        Ok(candidates.first().copied())
    }

    /// Writes an object.
    fn write_object(
        &mut self, start: u64,
        head: ObjectHeader, name: &[u8], meta: &Meta, data: &[u8]
    ) -> Result<u64, ArchiveError> {
        self.file.write(start, |write| {
            head.write_into(write)?;
            write.write(name)?;
            meta.write(write)?;
            write.write(data)?;
            Ok(write.pos()?)
        })
    }

    /// Returns the size of an object with the given name and content.
    fn object_size(name: &[u8], data: &[u8]) -> u64 {
          ObjectHeader::SIZE
        + usize_to_u64(name.len())
        + usize_to_u64(Meta::SIZE)
        + usize_to_u64(data.len())
    }

    /// Returns whether an object fits into a given space.
    ///
    /// Specifically, checks that an object of a total size of `object_size`
    /// (i.e., including header and name and meta) fits into empty space of
    /// a total size of `empty_size`. This is true if they are the same or
    /// if there is enough space left to add an empty object.
    fn fits(empty_size: u64, object_size: u64) -> bool {
        // Either the object fits exactly or there is enough space to add
        // an object header
           empty_size == object_size
        || empty_size >= object_size + ObjectHeader::SIZE
    }
}


/// # Access to the Index
///
impl<Meta> Archive<Meta> {
    /// The size of a single bucket.
    ///
    /// This is equal to the size of the integer type we are using for archive
    /// positions, i.e., `u64`.
    const BUCKET_SIZE: usize = mem::size_of::<u64>();

    /// Returns the hash value for a given name.
    ///
    /// The returned value will already be taken modulo the number of buckets,
    /// i.e., this is actually the bucket index for the name, not really its
    /// hash.
    fn hash_name(&self, name: &[u8]) -> u64 {
        let mut hasher = SipHasher24::new_with_key(&self.meta.hash_key);
        hasher.write(name);
        hasher.finish() % usize_to_u64(self.meta.bucket_count)
    }

    /// Returns the size of the index.
    ///
    /// There are one more buckets than the archive’s bucket count since that
    /// count is without the empty bucket.
    fn index_size(meta: &ArchiveMeta) -> u64 {
        usize_to_u64(
            (meta.bucket_count + 1) * Self::BUCKET_SIZE
        ) 
    }

    /// Returns the archive position of the bucket for `hash`.
    fn index_pos(&self, hash: u64) -> u64 {
        usize_to_u64(MAGIC_SIZE) + ArchiveMeta::size()
        + hash * usize_to_u64(Self::BUCKET_SIZE)
    }

    /// Returns the archive position for the empty bucket.
    ///
    /// The empty bucket lives behind all the other buckets.
    fn empty_index_pos(&self) -> u64 {
        usize_to_u64(MAGIC_SIZE) + ArchiveMeta::size()
        + usize_to_u64(self.meta.bucket_count * Self::BUCKET_SIZE)
    }

    /// Returns the archive position of the first object with `hash`.
    fn get_index(
        &self, hash: u64
    ) -> Result<Option<NonZeroU64>, ArchiveError> {
        Ok(NonZeroU64::new(
            self.file.read(self.index_pos(hash), |read| read.read_u64())?
        ))
    }

    /// Returns the archive position of the first empty object.
    fn get_empty_index(&self) -> Result<Option<NonZeroU64>, ArchiveError> {
        Ok(NonZeroU64::new(
            self.file.read(self.empty_index_pos(),|read| read.read_u64())?
        ))
    }

    /// Updates the archive position of the first object with `hash`.
    fn set_index(
        &mut self, hash: u64, pos: Option<NonZeroU64>,
    ) -> Result<(), ArchiveError> {
        self.file.write(self.index_pos(hash), |write| {
            write.write_u64(pos.map(Into::into).unwrap_or(0))
        })
    }

    /// Updates the archive position of the first empty object.
    fn set_empty_index(
        &mut self, pos: Option<NonZeroU64>
    ) -> Result<(), ArchiveError> {
        self.file.write(self.empty_index_pos(), |write| {
            write.write_u64(pos.map(Into::into).unwrap_or(0))
        })
    }
}


//------------ ObjectsIter ---------------------------------------------------

/// An iterator over the objects in an archive.
///
/// The iterator returns tuples of name, meta, and content. It can be
/// acquired via [`Archive::objects`].
pub struct ObjectsIter<'a, Meta> {
    /// The archive we are operating on.
    archive: &'a Archive<Meta>,

    /// The remaining buckets we haven’t visited yet.
    buckets: Range<u64>,

    /// The next item in the currently visited bucket.
    next: Option<NonZeroU64>,
}

impl<'a, Meta> ObjectsIter<'a, Meta> {
    /// Creates a new iterator.
    fn new(archive: &'a Archive<Meta>) -> Result<Self, ArchiveError> {
        Ok(Self {
            archive,
            buckets: 1..usize_to_u64(archive.meta.bucket_count),
            next: archive.get_index(0)?,
        })
    }
}

impl<'a, Meta: ObjectMeta> ObjectsIter<'a, Meta> {
    /// Returns the next item.
    ///
    /// This method returns the transposed result so we can use the question
    /// mark operator.
    #[allow(clippy::type_complexity)]
    fn transposed_next(
        &mut self
    ) -> Result<Option<(Cow<'a, [u8]>, Meta, Cow<'a, [u8]>)>, ArchiveError> {
        loop {
            if let Some(pos) = self.next {
                let (next, res) = self.archive.file.read(pos.into(), |read| {
                    let header = ObjectHeader::read_from(read)?;
                    let name_len = match header.name_len {
                        Some(len) => len,
                        None => return Err(ArchiveError::Corrupt)
                    };
                    let name = read.read_slice(name_len)?;
                    let meta = Meta::read(read)?;
                    let data = read.read_slice(header.data_size::<Meta>()?)?;
                    Ok((header.next, (name, meta, data)))
                })?;
                self.next = next;
                return Ok(Some(res))
            }
            let idx = match self.buckets.next() {
                Some(idx) => idx,
                None => return Ok(None)
            };
            self.next = self.archive.get_index(idx)?;
        }
    }
}

impl<'a, Meta: ObjectMeta> Iterator for ObjectsIter<'a, Meta> {
    type Item = Result<(Cow<'a, [u8]>, Meta, Cow<'a, [u8]>), ArchiveError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.transposed_next().transpose()
    }
}


//------------ ObjectMeta ----------------------------------------------------

/// A type representing meta data of an object.
///
/// A value of a type of this trait is stored with every object in an archive.
/// Values need to be of fixed size.
pub trait ObjectMeta: Sized {
    /// The size of the stored meta data.
    ///
    /// The `write` method needs to always write this many bytes if
    /// successful, and `read` needs to always read this many bytes.
    const SIZE: usize;

    /// The error type returned by the check closures.
    type ConsistencyError: fmt::Debug;

    /// Write a meta data value.
    ///
    /// This method must try to write exactly `Self::SIZE` bytes.
    fn write(&self, write: &mut StorageWrite) -> Result<(), ArchiveError>;

    /// Read a meta data value.
    ///
    /// This method must try to read exactly `Self::SIZE` bytes.
    fn read(read: &mut StorageRead) -> Result<Self, ArchiveError>;
}


//------------ ArchiveMeta ---------------------------------------------------

/// The meta data of an archive.
///
/// This is stored at the beginning of a file right after the magic cookie.
#[derive(Default, Debug)]
struct ArchiveMeta {
    /// The key for the hasher.
    hash_key: [u8; 16],

    /// The number of hash buckets.
    bucket_count: usize,
}

impl ArchiveMeta {
    /// Creates a new value.
    ///
    /// This uses a random hash key and the given bucket number.
    fn new(bucket_count: usize) -> Self {
        ArchiveMeta {
            hash_key: rand::random(),
            bucket_count,
        }
    }

    /// Returns the size of the encoded archive meta data.
    const fn size() -> u64 {
        usize_to_u64(
            mem::size_of::<[u8; 16]>() + mem::size_of::<usize>()
        )
    }

    /// Write the data to a file.
    fn write(&self, target: &mut impl io::Write) -> Result<(), io::Error> {
        target.write_all(&self.hash_key)?;
        target.write_all(&self.bucket_count.to_ne_bytes())?;
        Ok(())
    }

    /// Reads the data from a file.
    fn read(source: &mut impl io::Read) -> Result<Self, io::Error> {
        let mut res = Self::default();
        source.read_exact(&mut res.hash_key)?;
        let mut buf = [0u8; mem::size_of::<usize>()];
        source.read_exact(&mut buf)?;
        res.bucket_count = usize::from_ne_bytes(buf);
        Ok(res)
    }
}


//------------ ObjectHeader --------------------------------------------------

/// The header of an object.
///
/// This header is of a fixed size and is followed directly by the name, meta.
/// and content.
#[derive(Clone, Copy, Debug)]
struct ObjectHeader {
    /// The size of the object including the header.
    size: u64,

    /// The next object of the hash bucket.
    next: Option<NonZeroU64>,

    /// The size of the name.
    ///
    /// If this is `None`, this object is an empty object.
    name_len: Option<usize>,
}

impl ObjectHeader {
    /// Creates a new object header.
    fn new(
        size: u64, next: Option<NonZeroU64>, name: &[u8]
    ) -> Self {
        ObjectHeader { size, next, name_len: Some(name.len()) }
    }

    /// Creates a new object header for an empty object.
    fn new_empty(size: u64, next: Option<NonZeroU64>) -> Self {
        ObjectHeader { size, next, name_len: None }
    }

    /// Reads the contents of the header from a storage reader.
    fn read_from(read: &mut StorageRead) -> Result<Self, ArchiveError> {
        Ok(Self {
            size: read.read_u64()?,
            next: NonZeroU64::new(read.read_u64()?),
            name_len: read.read_opt_usize()?,
        })
    }

    /// Reads the header from the given archive position.
    fn read(
        storage: &Storage, start: u64
    ) -> Result<Self, ArchiveError> {
        storage.read(start, Self::read_from)
    }

    /// Reads the header and name from the given archive position.
    fn read_with_name(
        storage: &Storage, start: u64
    ) -> Result<(Self, Cow<[u8]>), ArchiveError> {
        storage.read(start, |read| {
            let header = Self::read_from(read)?;
            let name_len = match header.name_len {
                Some(len) => len,
                None => return Err(ArchiveError::Corrupt),
            };
            let name = read.read_slice(name_len)?;
            Ok((header, name))
        })
    }

    /// Writes the header into the given storage writer.
    fn write_into(
        &self, write: &mut StorageWrite
    ) -> Result<(), ArchiveError> {
        write.write_u64(self.size)?;
        write.write_nonzero_u64(self.next)?;
        write.write_opt_usize(self.name_len)?;
        Ok(())
    }

    /// Writes the header at the given archive position.
    fn write(
        &self, storage: &mut Storage, start: u64
    ) -> Result<(), ArchiveError> {
        storage.write(start, |write| self.write_into(write))
    }

    /// Updates the object size of a header beginning at the given position.
    fn update_size(
        start: u64, new_size: u64, storage: &mut Storage
    ) -> Result<(), ArchiveError> {
        storage.write(start, |write| write.write_u64(new_size))
    }

    /// Updates the next pointer of a header beginning at the given position.
    fn update_next(
        start: u64, new_next: Option<NonZeroU64>, storage: &mut Storage
    ) -> Result<(), ArchiveError> {
        storage.write(
            start + usize_to_u64(mem::size_of::<u64>()),
            |write| write.write_nonzero_u64(new_next),
        )
    }

    /// The written size of the header.
    const SIZE:  u64 = usize_to_u64(
          mem::size_of::<u64>()
        + mem::size_of::<u64>()
        + Storage::OPT_USIZE_SIZE
    );

    /// Returns the start of the meta data.
    fn meta_start(&self, start: u64) -> u64 {
        start + Self::SIZE + opt_usize_to_u64(self.name_len)
    }

    /// Returns the start of the content.
    fn data_start<Meta: ObjectMeta>(&self, start: u64) -> u64 {
          start + Self::SIZE
        + usize_to_u64(Meta::SIZE)
        + opt_usize_to_u64(self.name_len)
    }

    /// Returns the size of the data.
    fn data_size<Meta: ObjectMeta>(&self) -> Result<usize, ArchiveError> {
        let name_len = match self.name_len {
            Some(len) => usize_to_u64(len),
            None => return Err(ArchiveError::Corrupt)
        };
        usize::try_from(
            self.size - Self::SIZE- usize_to_u64(Meta::SIZE) - name_len
        ).map_err(|_| ArchiveError::Corrupt)
    }
}


//------------ FoundObject ---------------------------------------------------

/// Information about an object found in the archive.
///
/// This is just so we don’t need to juggle tuples all the time.
struct FoundObject {
    /// The start position of the object.
    start: u64,

    /// The heeader of the object.
    header: ObjectHeader,

    /// The start position of the previous object with the same hash.
    prev: Option<NonZeroU64>,
}

impl FoundObject {
    /// Returns the start of the meta data.
    fn meta_start(&self) -> u64 {
        self.header.meta_start(self.start)
    }

    /// Returns the start of the content.
    fn data_start<Meta: ObjectMeta>(&self) -> u64 {
        self.header.data_start::<Meta>(self.start)
    }
}


//------------ Magic Cookie --------------------------------------------------
//
// The marker we use for a quick file type check.

#[cfg(all(target_endian = "little", target_pointer_width = "16"))]
const SYSTEM: u8 = b'A';

#[cfg(all(target_endian = "little", target_pointer_width = "32"))]
const SYSTEM: u8 = b'B';

#[cfg(all(target_endian = "little", target_pointer_width = "64"))]
const SYSTEM: u8 = b'C';

#[cfg(all(target_endian = "big", target_pointer_width = "16"))]
const SYSTEM: u8 = b'D';

#[cfg(all(target_endian = "big", target_pointer_width = "32"))]
const SYSTEM: u8 = b'E';

#[cfg(all(target_endian = "big", target_pointer_width = "64"))]
const SYSTEM: u8 = b'F';

const VERSION: u8 = 0;

const MAGIC_SIZE: usize = 6;
const FILE_MAGIC: [u8; MAGIC_SIZE] = [
    b'R', b'T', b'N', b'R', VERSION, SYSTEM,
];


//============ Physical File Access ==========================================

//------------ Storage -------------------------------------------------------

/// The underlying storage of an archive.
#[derive(Debug)]
struct Storage {
    /// The physical file.
    ///
    /// This is protected by a mutex so the archive can be shared.
    file: Mutex<fs::File>,

    /// The optional memory map.
    #[cfg(unix)]
    mmap: Option<mmapimpl::Mmap>,

    /// Do we need write permissions?
    #[cfg(unix)]
    writable: bool,

    /// The size of the archive.
    size: u64,
}

impl Storage {
    /// Creates a new storage value using the given file.
    #[allow(unused_variables)]
    pub fn new(file: fs::File, writable: bool) -> Result<Self, io::Error> {
        let mut res = Self {
            file: Mutex::new(file),
            #[cfg(unix)]
            mmap: None,
            #[cfg(unix)]
            writable,
            size: 0,
        };
        res.mmap()?;
        Ok(res)
    }

    /// Re-memory maps the storage.
    ///
    /// You can un-memory map the storage by setting `self.mmap` to `None`.
    fn mmap(&mut self) -> Result<(), io::Error> {
        #[cfg(unix)]
        {
            self.mmap = mmapimpl::Mmap::new(
                &mut self.file.lock(), self.writable
            )?;
            if let Some(mmap) = self.mmap.as_ref() {
                self.size = mmap.size();
                return Ok(())
            }
        }

        let mut file = self.file.lock();
        file.seek(SeekFrom::End(0))?;
        self.size = file.stream_position()?; 
        Ok(())
    }

    /// Starts reading from the storage at the given position.
    pub fn read<'s, T, E: From<ArchiveError>>(
        &'s self,
        start: u64,
        op: impl FnOnce(&mut StorageRead<'s>) -> Result<T, E>
    ) -> Result<T, E> {
        op(&mut StorageRead::new(self, start)?)
    }

    /// Starts writing to the storage at the given position.
    ///
    /// If `start` is equal to the size of the archive, starts appending.
    pub fn write<T>(
        &mut self,
        start: u64,
        op: impl FnOnce(&mut StorageWrite) -> Result<T, ArchiveError>
    ) -> Result<T, ArchiveError> {
        let mut write = if self.size == start {
            StorageWrite::new_append(self)?
        }
        else {
            StorageWrite::new(self, start)?
        };
        let res = op(&mut write)?;
        if write.finish()? {
            self.mmap()?;
        }
        Ok(res)
    }
}

/// # Stored size constants
///
/// They live here purely for the naming to make some sort of sense.
impl Storage {
    const OPT_USIZE_SIZE: usize
        = mem::size_of::<u8>() + mem::size_of::<usize>();
}


//------------ StorageRead ---------------------------------------------------

/// Reading data from the underlying storage.
#[derive(Debug)]
pub struct StorageRead<'a>(ReadInner<'a>);

/// How are we reading?
#[derive(Debug)]
enum ReadInner<'a> {
    /// The storage is memory-mapped and we read from there.
    #[cfg(unix)]
    Mmap {
        /// The memory map.
        mmap: &'a mmapimpl::Mmap,

        /// The current read position.
        pos: u64,
    },

    /// The storage is not memory-mapped and we read from the file.
    File {
        file: MutexGuard<'a, fs::File>,
    }
}

impl<'a> StorageRead<'a> {
    /// Creates a new storage reader.
    fn new(storage: &'a Storage, start: u64) -> Result<Self, ArchiveError> {
        if start > storage.size {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected EOF"
            ).into())
        }

        #[cfg(unix)]
        if let Some(mmap) = storage.mmap.as_ref() {
            return Ok(StorageRead(
                ReadInner::Mmap { mmap, pos: start }
            ))
        }

        let mut file = storage.file.lock();
        file.seek(SeekFrom::Start(start))?;
        Ok(StorageRead(
            ReadInner::File { file }
        ))
    }

    /// Returns the current read position.
    pub fn pos(&mut self) -> Result<u64, ArchiveError> {
        match self.0 {
            #[cfg(unix)]
            ReadInner::Mmap { pos, .. } => Ok(pos),
            ReadInner::File { ref mut file } => Ok(file.stream_position()?),
        }
    }

    /// Reads data into a provided buffer.
    pub fn read_into(
        &mut self, buf: &mut [u8]
    ) -> Result<(), ArchiveError> {
        match self.0 {
            #[cfg(unix)]
            ReadInner::Mmap { mmap, ref mut pos } => {
                *pos = mmap.read_into(*pos, buf)?;
                Ok(())
            }
            ReadInner::File { ref mut file } => {
                Ok(file.read_exact(buf)?)
            }
        }
    }

    /// Reads a slice of data.
    ///
    /// If the storage is memory-mapped, this will return a slice into the
    /// mapped region. Otherwise a vec will be allocated.
    pub fn read_slice(
        &mut self, len: usize,
    ) -> Result<Cow<'a, [u8]>, ArchiveError> {
        match self.0 {
            #[cfg(unix)]
            ReadInner::Mmap { mmap, ref mut pos } => {
                let (res, end) = mmap.read(*pos, len)?;
                *pos = end;
                Ok(res)
            }
            ReadInner::File { ref mut file }  => {
                // XXX This may or may not be sound. We’re not using read_exact
                //     just to be a little more sure?
                let mut buf = Vec::with_capacity(len);
                let mut len = len;
                unsafe {
                    buf.set_len(len);
                    let mut buf = buf.as_mut_slice();
                    while len > 0 {
                        let read = file.read(buf)?;
                        if read == 0 {
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "unexpected end of file"
                            ).into())
                        }

                        // Let’s not panic if Read::read is broken and rather
                        // error out.
                        buf = match buf.get_mut(read..) {
                            Some(buf) => buf,
                            None => {
                                return Err(io::Error::new(
                                    io::ErrorKind::Other,
                                    "read claimed to read beyond buffer len"
                                ).into())
                            }
                        };

                        len -= read;
                    }
                }
                Ok(buf.into())
            }
        }
    }

    /// Reads a byte array.
    pub fn read_array<const N: usize>(
        &mut self
    ) -> Result<[u8; N], ArchiveError> {
        let mut res = [0; N];
        self.read_into(&mut res)?;
        Ok(res)
    }

    /// Reads a `usize`.
    pub fn read_usize(&mut self) -> Result<usize, ArchiveError> {
        Ok(usize::from_ne_bytes(self.read_array()?))
    }

    /// Reads an optional `usize`.
    ///
    /// We don’t do any optimisations here and instead store this is an
    /// one-byte boolean and, if that is 1, the length as a usize.
    pub fn read_opt_usize(&mut self) -> Result<Option<usize>, ArchiveError> {
        let opt = self.read_array::<1>()?;
        let size = self.read_usize()?;
        match opt[0] {
            0 => {
                if size != 0 {
                    Err(ArchiveError::Corrupt)
                }
                else {
                    Ok(None)
                }
            }
            1 => Ok(Some(size)),
            _ => Err(ArchiveError::Corrupt),
        }
    }

    /// Reads a `u64`.
    pub fn read_u64(&mut self) -> Result<u64, ArchiveError> {
        Ok(u64::from_ne_bytes(self.read_array()?))
    }
}


//------------ StorageWrite --------------------------------------------------

/// Writing data to storage.
#[derive(Debug)]
pub struct StorageWrite<'a>(WriteInner<'a>);

/// How are we writing, exactly?
#[derive(Debug)]
enum WriteInner<'a> {
    /// We are writing into a memory mapped region.
    #[cfg(unix)]
    Mmap {
        /// The memory-map.
        mmap: &'a mut mmapimpl::Mmap,

        /// The current write position.
        pos: u64,
    },

    /// We are overwriting a portion of the underlying file.
    Overwrite {
        file: MutexGuard<'a, fs::File>,
    },

    /// We are appending to the underlying file.
    Append {
        file: MutexGuard<'a, fs::File>,
    },
}

impl<'a> StorageWrite<'a> {
    /// Creates a new storage writer for overwriting existing data..
    fn new(
        storage: &'a mut Storage, pos: u64
    ) -> Result<Self, ArchiveError> {
        if pos >= storage.size {
            return Err(ArchiveError::Corrupt)
        }

        #[cfg(unix)]
        match storage.mmap.as_mut() {
            Some(mmap) => {
                Ok(Self(WriteInner::Mmap { mmap, pos, }))
            }
            None => {
                let mut file = storage.file.lock();
                file.seek(SeekFrom::Start(pos))?;
                Ok(Self(WriteInner::Overwrite { file }))
            }
        }

        #[cfg(not(unix))]
        {
            let mut file = storage.file.lock();
            file.seek(SeekFrom::Start(pos))?;
            Ok(Self(WriteInner::Overwrite { file }))
        }
    }

    /// Creates a new storage writer for appending data.
    fn new_append(storage: &'a mut Storage) -> Result<Self, ArchiveError> {
        #[cfg(unix)]
        if let Some(mmap) = storage.mmap.take() {
            drop(mmap)
        }
        let mut file = storage.file.lock();
        file.seek(SeekFrom::End(0))?;
        Ok(Self(WriteInner::Append { file }))
    }

    /// Finishes writing.
    ///
    /// Returns whether a memory-map needs to be renewed.
    fn finish(self) -> Result<bool, ArchiveError> {
        match self.0 {
            #[cfg(unix)]
            WriteInner::Mmap { mmap, .. } => {
                mmap.sync()?;
                Ok(false)
            }
            WriteInner::Overwrite { mut file } => {
                file.flush()?;
                Ok(false)
            }
            WriteInner::Append { mut file } => {
                file.flush()?;
                Ok(true)
            }
        }
    }

    /// Returns the current writing position.
    pub fn pos(&mut self) -> Result<u64, io::Error> {
        match self.0 {
            #[cfg(unix)]
            WriteInner::Mmap { pos, .. } => Ok(pos),
            WriteInner::Overwrite { ref mut file } => file.stream_position(),
            WriteInner::Append { ref mut file } => file.stream_position(),
        }
    }

    /// Writes data to storage.
    ///
    /// Note that because a storage writer either overwrites existing data or
    /// appends new data, this may fail with an EOF error if you reach the
    /// end of the file in the overwrite case.
    pub fn write(
        &mut self, data: &[u8]
    ) -> Result<(), ArchiveError> {
        match self.0 {
            #[cfg(unix)]
            WriteInner::Mmap { ref mut mmap, ref mut pos } => {
                *pos = mmap.write(*pos, data)?;
                Ok(())
            }
            WriteInner::Overwrite { ref mut file }  => {
                Ok(file.write_all(data)?)
            }
            WriteInner::Append { ref mut file, .. }  => {
                Ok(file.write_all(data)?)
            }
         }
    }

    /// Writes a `usize` to storage.
    pub fn write_usize(&mut self, value: usize) -> Result<(), ArchiveError> {
        self.write(&value.to_ne_bytes())
    }

    /// Write an optional `usize` to storage.
    pub fn write_opt_usize(
        &mut self, value: Option<usize>
    ) -> Result<(), ArchiveError> {
        match value {
            Some(value) => {
                self.write(b"\x01")?;
                self.write_usize(value)?;
            }
            None => {
                self.write(b"\0")?;
                self.write_usize(0)?;
            }
        }
        Ok(())
    }

    /// Writes a `u64` to storage.
    pub fn write_u64(&mut self, value: u64) -> Result<(), ArchiveError> {
        self.write(&value.to_ne_bytes())
    }

    /// Writes a `Option<NonZeroUsize>` to storage.
    pub fn write_nonzero_usize(
        &mut self, value: Option<NonZeroUsize>
    ) -> Result<(), ArchiveError> {
        self.write(&value.map(Into::into).unwrap_or(0).to_ne_bytes())
    }

    /// Writes a `Option<NonZeroU64>` to storage.
    pub fn write_nonzero_u64(
        &mut self, value: Option<NonZeroU64>
    ) -> Result<(), ArchiveError> {
        self.write(&value.map(Into::into).unwrap_or(0).to_ne_bytes())
    }

}


//------------ Mmap ----------------------------------------------------------#

#[cfg(unix)]
mod mmapimpl {
    use std::{fs, io, slice};
    use std::borrow::Cow;
    use std::ffi::c_void;
    use std::io::{Seek, SeekFrom};
    use nix::sys::mman::{MapFlags, MsFlags, ProtFlags, mmap, msync, munmap};


    /// A memory-mapped file.
    #[derive(Debug)]
    pub struct Mmap {
        /// The pointer to the start of the memory.
        ptr: *mut c_void,

        /// The size of the memory,
        len: usize,
    }

    impl Mmap {
        /// Creates a new value mapping the given file and mode.
        pub fn new(
            file: &mut fs::File,
            writable: bool,
        ) -> Result<Option<Self>, io::Error> {
            file.seek(SeekFrom::End(0))?;
            let size = file.stream_position()?;
            file.rewind()?;
            let size = match usize::try_from(size).and_then(TryInto::try_into) {
                Ok(size) => size,
                Err(_) => return Ok(None)
            };
            let ptr = unsafe {
                mmap(
                    None, size, 
                    if writable {
                        ProtFlags::PROT_READ | ProtFlags::PROT_WRITE
                    }
                    else {
                        ProtFlags::PROT_READ
                    },
                    MapFlags::MAP_SHARED,
                    Some(file),
                    0
                )?
            };
            Ok(Some(Mmap { ptr, len: size.into() }))
        }

        /// Returns the size of the mapped file.
        pub fn size(&self) -> u64 {
            super::usize_to_u64(self.len)
        }
    }

    impl Drop for Mmap {
        fn drop(&mut self) {
            unsafe {
                let _  = munmap(self.ptr, self.len); // XXX Error handling?
            }
        }
    }

    impl Mmap {
        /// Returns the whole memory map.
        fn as_slice(&self) -> &[u8] {
            unsafe { slice::from_raw_parts(self.ptr as *const u8, self.len) }
        }

        /// Returns the whole memory map mutably.
        fn as_slice_mut(&mut self) -> &mut [u8] {
            unsafe { slice::from_raw_parts_mut(self.ptr as *mut u8, self.len) }
        }
    }

    impl Mmap {
        /// Reads data into the given buffer.
        pub fn read_into(
            &self, start: u64, buf: &mut [u8]
        ) -> Result<u64, io::Error> {
            let (slice, end) = self.read(start, buf.len())?;
            buf.copy_from_slice(slice.as_ref());
            Ok(end)
        }

        /// Returns a cow of the given data.
        ///
        /// This will always be borrowed.
        pub fn read(
            &self, start: u64, len: usize,
        ) -> Result<(Cow<[u8]>, u64), io::Error> {
            let start = match usize::try_from(start) {
                Ok(start) => start,
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof, "unexpected EOF"
                    ))
                }
            };
            let end = match start.checked_add(len) {
                Some(end) => end,
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof, "unexpected EOF"
                    ))
                }
            };
            if end > self.len {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof, "unexpected EOF"
                ))
            }
            Ok((self.as_slice()[start..end].into(), super::usize_to_u64(end)))
        }

        /// Writes the given data starting at the given position.
        ///
        /// The data needs to fully fit into the current memory block.
        pub fn write(
            &mut self, start: u64, data: &[u8]
        ) -> Result<u64, io::Error> {
            let start = match usize::try_from(start) {
                Ok(start) => start,
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof, "unexpected EOF"
                    ))
                }
            };
            let end = match start.checked_add(data.len()) {
                Some(end) => end,
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof, "unexpected EOF"
                    ))
                }
            };
            if end > self.len {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof, "unexpected EOF"
                ))
            }
            self.as_slice_mut()[start..end].copy_from_slice(data);
            Ok(super::usize_to_u64(end))
        }

        /// Synchronizes the memory mapped data onto disk.
        pub fn sync(&self) -> Result<(), io::Error> {
            unsafe {
                Ok(msync(self.ptr, self.len, MsFlags::MS_ASYNC)?)
            }
        }
    }

    unsafe impl Sync for Mmap { }
    unsafe impl Send for Mmap { }
}


//============ Helper Function ===============================================

/// Converts a usize to a u64.
///
/// This will panic on systems where a usize doesn’t fit into a u64 if the
/// value is too big.
const fn usize_to_u64(value: usize) -> u64 {
    #[cfg(not(any(
        target_pointer_width = "16",
        target_pointer_width = "32",
        target_pointer_width = "64",
    )))]
    assert!(value <= u64::MAX as usize);
    value as u64
}

/// Converts an optional usize into a u64.
fn opt_usize_to_u64(value: Option<usize>) -> u64 {
    usize_to_u64(value.map(Into::into).unwrap_or(0))
}


//============ Error Types ===================================================

//------------ ArchiveError --------------------------------------------------

/// An error happened while trying to access the archive.
#[derive(Debug)]
pub enum ArchiveError {
    /// The archive is corrupt and cannot be used any more.
    Corrupt,

    /// An IO error happened while accessing the underlying file.
    Io(io::Error),
}

impl From<io::Error> for ArchiveError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ArchiveError::Corrupt => f.write_str("archive corrupted"),
            ArchiveError::Io(ref err) => write!(f, "{}", err)
        }
    }
}

//------------ OpenError -----------------------------------------------------

/// An error happened while opening an existing archive.
#[derive(Debug)]
pub enum OpenError {
    /// The archive does not exist.
    NotFound,

    /// An error happened while trying to access the archive.
    Archive(ArchiveError),
}

impl From<io::Error> for OpenError {
    fn from(err: io::Error) -> Self {
        ArchiveError::Io(err).into()
    }
}

impl From<ArchiveError> for OpenError {
    fn from(err: ArchiveError) -> Self {
        match err {
            ArchiveError::Io(err) if matches!(
                err.kind(), io::ErrorKind::NotFound
            ) => Self::NotFound,
            _ => Self::Archive(err),
        }
    }
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            OpenError::NotFound => f.write_str("not found"),
            OpenError::Archive(ref err) => write!(f, "{}", err),
        }
    }
}


//------------ PublishError --------------------------------------------------

/// An error happened while publishing an object.
#[derive(Debug)]
pub enum PublishError {
    /// The object already exists.
    AlreadyExists,

    /// An error happened while trying to access the archive.
    Archive(ArchiveError),
}

impl From<ArchiveError> for PublishError {
    fn from(err: ArchiveError) -> Self {
        Self::Archive(err)
    }
}


//------------ AccessError ---------------------------------------------------

/// An error happened while publishing an object.
#[derive(Debug)]
pub enum AccessError<T> {
    /// The object does not exist.
    NotFound,

    /// The object’s meta data is wrong.
    Inconsistent(T),

    /// An error happened while trying to access the archive.
    Archive(ArchiveError),
}

impl<T> From<ArchiveError> for AccessError<T> {
    fn from(err: ArchiveError) -> Self {
        Self::Archive(err)
    }
}


//------------ FetchError ----------------------------------------------------

/// An error happened while publishing an object.
#[derive(Debug)]
pub enum FetchError {
    /// The object does not exist.
    NotFound,

    /// An error happened while trying to access the archive.
    Archive(ArchiveError),
}

impl From<ArchiveError> for FetchError {
    fn from(err: ArchiveError) -> Self {
        Self::Archive(err)
    }
}


//============ Testing =======================================================

#[cfg(test)]
mod test {
    use super::*;
    use std::collections::HashMap;

    #[derive(Clone, Copy, Debug)]
    enum Op {
        Publish { name: &'static [u8], data: &'static [u8] },
        Update { name: &'static [u8], data: &'static [u8] },
        Delete { name: &'static [u8] },
    }

    use self::Op::*;

    impl ObjectMeta for () {
        const SIZE: usize = 4;
        type ConsistencyError = ();

        fn write(
            &self, write: &mut StorageWrite
        ) -> Result<(), ArchiveError> {
            write.write(b"abcd")
        }

        fn read(
            read: &mut StorageRead
        ) -> Result<Self, ArchiveError> {
            let slice = read.read_slice(4).unwrap();
            assert_eq!(slice.as_ref(), b"abcd");
            Ok(())
        }
    }

    fn check_archive(
        archive: &Archive<()>,
        content: &HashMap<&'static [u8], &'static [u8]>,
    ) {
        archive.verify().unwrap();
        let mut content = content.clone();
        for item in archive.objects().unwrap() {
            let (name, _, data) = item.unwrap();
            assert_eq!(
                content.remove(name.as_ref()),
                Some(data.as_ref())
            );
        }
        assert!(content.is_empty());
    }

    fn run_archive(ops: impl IntoIterator<Item = Op>) {
        let mut archive = Archive::create_with_file(
            tempfile::tempfile().unwrap()
        ).unwrap();
        let mut content = HashMap::new();

        for item in ops {
            match item {
                Op::Publish { name, data } => {
                    assert!(content.insert(name, data).is_none());
                    archive.publish(name, &(), data).unwrap();
                    check_archive(&archive, &content);
                    assert_eq!(
                        archive.fetch(name).unwrap().as_ref(),
                        data
                    );
                }
                Op::Update { name, data } => {
                    assert!(content.insert(name, data).is_some());
                    archive.update(name, &(), data, |_| Ok(())).unwrap();
                    assert_eq!(
                        archive.fetch(name).unwrap().as_ref(),
                        data
                    );
                }
                Op::Delete { name } => {
                    assert!(content.remove(name).is_some());
                    archive.delete(name, |_| Ok(())).unwrap();
                    assert!(matches!(
                        archive.fetch(name),
                        Err(FetchError::NotFound)
                    ));
                }
            }

            check_archive(&archive, &content);
        }
    }

    #[test]
    fn empty_archive() {
        run_archive([])
    }

    #[test]
    fn publish_replace() {
        run_archive([
            Publish { name: b"1", data: b"bar" },
            Publish { name: b"2", data: &[0; 1024]},
            Publish { name: b"3", data: b"aaa" },
            Delete  { name: b"2" },
            Publish { name: b"4", data: b"bar" },
            Update  { name: b"4", data: b"bar" },
        ])
    }
}

