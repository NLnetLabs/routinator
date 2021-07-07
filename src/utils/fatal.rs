/// Utilities for dealing with the file system.

use std::fs;
use std::ffi::{OsStr, OsString};
use std::fs::Metadata;
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


//------------ remove_file ---------------------------------------------------

/// Removes a file.
pub fn remove_file(path: &Path) -> Result<(), Failed> {
    fs::remove_file(path).map_err(|err| {
        error!(
            "Fatal: failed to remove file {}: {}",
            path.display(), err
        );
        Failed
    })
}

