//! Utilities for RRDP.
//!
//! This is a private module here only for organizional purposes.

use std::io;
use std::fs::{File, create_dir_all};
use std::path::{Path, PathBuf};
use log::error;
use rand::random;
use crate::operation::Error;


/// Creates a new directory under the given path with a unique name.
pub fn create_unique_dir(path: &Path) -> Result<PathBuf, Error> {
    for _ in 0..100 {
        let target = random_path(path);
        match create_dir_all(&target) {
            Ok(()) => return Ok(target),
            Err(err) => {
                if err.kind() != io::ErrorKind::AlreadyExists {
                    error!(
                        "Failed to create unique directory under {}: {}",
                        path.display(), err
                    );
                    return Err(Error);
                }
            }
        }
    }
    error!(
        "Failed to create unique directory under {}: tried a hundred times.",
        path.display()
    );
    Err(Error)
}

/// Creates a new file under the given path with a unique name.
pub fn create_unique_file(path: &Path) -> Result<(File, PathBuf), Error> {
    for _ in 0..100 {
        let target = random_path(path);
        match File::create(&target) {
            Ok(file) => return Ok((file, target)),
            Err(err) => {
                if err.kind() != io::ErrorKind::AlreadyExists {
                    error!(
                        "Failed to create unique directory under {}: {}",
                        path.display(), err
                    );
                    return Err(Error);
                }
            }
        }
    }
    error!(
        "Failed to create unique directory under {}: tried a hundred times.",
        path.display()
    );
    Err(Error)
}

/// Creates a new path name.
pub fn random_path(path: &Path) -> PathBuf {
    path.join(format!("{}", random::<u32>()))
}

