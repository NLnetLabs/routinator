/// Utilities for dealing with the file system.
///
/// This module contains variations on some of the functions provided by
/// `std::fs` that instead of returning `std::io::Error` log that error and
/// return our own [`Failed`] instead.

use std::{fs, io};
use std::ffi::{OsStr, OsString};
use std::fs::{File, Metadata};
use std::path::{Path, PathBuf};
use log::error;
use crate::error::Failed;


//------------ DirEntry ------------------------------------------------------

/// A version of `DirEntry` that has all its components resolved.
#[derive(Clone, Debug)]
pub struct DirEntry {
    path: PathBuf,
    metadata: Metadata,
    file_name: OsString,
}

impl DirEntry {
    /// Returns a reference to the path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Converts the entry into the path.
    pub fn into_path(self) -> PathBuf {
        self.path
    }

    /// Returns a reference to metadata.
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    /// Returns a reference to the file name.
    pub fn file_name(&self) -> &OsStr {
        &self.file_name
    }

    /// Converts the entry into the file name.
    pub fn into_file_name(self) -> OsString {
        self.file_name
    }

    /// Converts the entry into file name and path.
    pub fn into_name_and_path(self) -> (OsString, PathBuf) {
        (self.file_name, self.path)
    }

    /// Returns whether the entry is a file.
    pub fn is_file(&self) -> bool {
        self.metadata.is_file()
    }

    /// Returns whether the entry is a directory.
    pub fn is_dir(&self) -> bool {
        self.metadata.is_dir()
    }

    /// Returns the size of the underlying file.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> u64 {
        self.metadata.len()
    }
}


//------------ ReadDir -------------------------------------------------------

/// A version of `ReadDir` that logs on error.
#[derive(Debug)]
pub struct ReadDir<'a> {
    path: &'a Path,
    iter: fs::ReadDir,
}

impl<'a> Iterator for ReadDir<'a> {
    type Item = Result<DirEntry, Failed>;

    fn next(&mut self) -> Option<Self::Item> {
        let entry = match self.iter.next()? {
            Ok(entry) => entry,
            Err(err) => {
                error!(
                    "Fatal: failed to read directory {}: {}",
                    self.path.display(), err
                );
                return Some(Err(Failed))
            }
        };
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(err) => {
                error!(
                    "Fatal: failed to read directory {}: {}",
                    self.path.display(), err
                );
                return Some(Err(Failed))
            }
        };
        Some(Ok(DirEntry {
            path: entry.path(),
            metadata,
            file_name: entry.file_name()
        }))
    }
}


//------------ read_dir ------------------------------------------------------

/// Returns an iterator over a directory, logging fatal errors on any error.
pub fn read_dir(path: &Path) -> Result<ReadDir, Failed> {
    match fs::read_dir(path) {
        Ok(iter) => Ok(ReadDir { path, iter }),
        Err(err) => {
            error!(
                "Fatal: failed to open directory {}: {}",
                path.display(), err
            );
            Err(Failed)
        }
    }
}


//------------ read_existing_dir ---------------------------------------------

/// Returns an iterator over an existing directory.
///
/// Returns `None` if the repository doesn’t exist.
pub fn read_existing_dir(path: &Path) -> Result<Option<ReadDir>, Failed> {
    match fs::read_dir(path) {
        Ok(iter) => Ok(Some(ReadDir { path, iter })),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => {
            error!(
                "Fatal: failed to open directory {}: {}",
                path.display(), err
            );
            Err(Failed)
        }
    }
}


//------------ create_dir_all ------------------------------------------------

/// Creates all directories leading to the given directory or logs an error.
pub fn create_dir_all(path: &Path) -> Result<(), Failed> {
    fs::create_dir_all(path).map_err(|err| {
        error!(
            "Fatal: failed to create directory {}: {}",
            path.display(), err
        );
        Failed
    })
}


//------------ create_parent_all ---------------------------------------------

/// Creates all directories leading necessary to create a file.
pub fn create_parent_all(path: &Path) -> Result<(), Failed> {
    if let Some(path) = path.parent() {
        fs::create_dir_all(path).map_err(|err| {
            error!(
                "Fatal: failed to create directory {}: {}",
                path.display(), err
            );
            Failed
        })?
    }
    Ok(())
}


//------------ remove_dir_all ------------------------------------------------

/// Removes a directory tree.
pub fn remove_dir_all(path: &Path) -> Result<(), Failed> {
    fs::remove_dir_all(path).map_err(|err| {
        error!(
            "Fatal: failed to remove directory tree {}: {}",
            path.display(), err
        );
        Failed
    })
}


//------------ remove_file ---------------------------------------------------

/// Removes a file.
///
/// Ignores if the file doesn’t exist.
pub fn remove_file(path: &Path) -> Result<(), Failed> {
    if let Err(err) = fs::remove_file(path) {
        if err.kind() != io::ErrorKind::NotFound {
            error!(
                "Fatal: failed to remove file {}: {}",
                path.display(), err
            );
            return Err(Failed)
        }
    }
    Ok(())
}


//------------ remove_all ----------------------------------------------------

/// Removes a file or a directory tree.
pub fn remove_all(path: &Path) -> Result<(), Failed> {
    if path.is_dir() {
        remove_dir_all(path)
    }
    else {
        remove_file(path)
    }
}


//------------ rename --------------------------------------------------------

/// Renames a file or directory.
///
/// See ´std::fs::rename`` for the various ramifications.
pub fn rename(source: &Path, target: &Path) -> Result<(), Failed> {
    fs::rename(source, target).map_err(|err| {
        error!(
            "Fatal: failed to move {} to {}: {}",
            source.display(), target.display(), err
        );
        Failed
    })
}


//------------ open_file -----------------------------------------------------

/// Opens a file.
///
/// Errors out if the file doesn’t exist.
pub fn open_file(path: &Path) -> Result<File, Failed> {
    File::open(path).map_err(|err| {
        error!(
            "Fatal: failed to open file {}: {}",
            path.display(), err
        );
        Failed
    })
}


//------------ read_file -----------------------------------------------------

/// Reads a file’s entire content into a vec.
///
/// Errors out if the file cannot be opened for reading or reading fails.
pub fn read_file(path: &Path) -> Result<Vec<u8>, Failed> {
    fs::read(path).map_err(|err| {
        error!(
            "Fatal: failed to read file {}: {}",
            path.display(), err
        );
        Failed
    })
}


//------------ read_existing_file --------------------------------------------

/// Reads an existing file’s entire content into a vec.
///
/// Returns `Ok(None)` if the file doesn’t exist.  Errors out if the file
/// fails to be opened for reading or reading fails.
pub fn read_existing_file(path: &Path) -> Result<Option<Vec<u8>>, Failed> {
    match fs::read(path) {
        Ok(some) => Ok(Some(some)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => {
            error!(
                "Fatal: failed to read file {}: {}",
                path.display(), err
            );
            Err(Failed)
        }
    }
}


//------------ write_file ----------------------------------------------------

/// Writes a slice to a file.
///
/// Errors out if the file cannot be opened for writing or writing fails.
/// If the file exists, overwrites the current content.
pub fn write_file(path: &Path, contents: &[u8]) -> Result<(), Failed> {
    fs::write(path, contents).map_err(|err| {
        error!(
            "Fatal: failed to write file {}: {}",
            path.display(), err
        );
        Failed
    })
}

