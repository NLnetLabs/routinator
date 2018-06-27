//! The complete RPKI repository.
//!
//! # Structure of the Local Copy
//!
//! Such a repository consists of a number of _repository instances_
//! identifier via a unique rsync base URI. All the publication points within
//! that instance have URIs startin with that base URI.
//!
//! As an initial approach to storing a local copy of the repository, we
//! keep a directory structure under a configured base directory. This
//! directory contains another directory names `"repository"`. It will
//! contain a set of directories whose name is the hostname portion of
//! an rsync URI and who mirror the structure of encountered URIs.
//!
//! When updating a repository, we will walk this tree searching for the
//! set of directories that contain more than one entry and whose parents
//! are not part of the set. We construct the rsync URIs from their path
//! and run the `rsync` command to update them.
//!
//! The configured base directory also contains a directory named `"tal"`
//! that contains trust anchor locator files in RFC 7730 format.
//!
//!
//! # Validation
//!
//! The files read during validation are referenced through rsync URIs which
//! will be translated into file system paths in the local copy of the
//! repository. If the indicated file is present it will be used and
//! validated. If it isn’t, the directory the file should be in will be
//! created and validation continue. Once it concludes, if there was at least
//! one missing file, the local copy is updated to fetch the missing files.
//! If this update resulted in any changes to the local copy at all,
//! validatio is repeated. Otherwise, it ends with an error.

use std::path::PathBuf;


//------------ Repository ----------------------------------------------------

#[derive(Clone, Debug)]
pub struct Repository {
    base: PathBuf,
}


