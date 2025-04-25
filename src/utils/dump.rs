//! Utilities for creating data dumps.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use rpki::uri;


//------------ DumpRegistry --------------------------------------------------

/// A registration for all the repositories encountered during a dump.
#[derive(Clone, Debug)]
pub struct DumpRegistry {
    /// The base directory under which to store repositories.
    base_dir: PathBuf,

    /// The RRDP repositories we’ve already seen and where they go.
    rrdp_uris: HashMap<uri::Https, String>,

    /// The directory names we have already used for RRDP repositories..
    ///
    /// This is the last component of the path.
    rrdp_dirs: HashSet<String>,
}

impl DumpRegistry {
    /// Creates a new registry.
    pub fn new(base_dir: PathBuf) -> Self {
        DumpRegistry {
            base_dir,
            rrdp_uris: HashMap::new(),
            rrdp_dirs: HashSet::new(),
        }
    }

    /// Returns the base directory of the dump.
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    /// Registers the repository for the manifest and returns the target path.
    pub fn get_repo_path(
        &mut self, rpki_notify: Option<&uri::Https>
    ) -> PathBuf {
        if let Some(rpki_notify) = rpki_notify {
            if let Some(path) = self.rrdp_uris.get(rpki_notify) {
                self.base_dir.join(path)
            }
            else {
                self.make_path(rpki_notify)
            }
        }
        else {
            self.base_dir.join("rsync")
        }
    }

    fn make_path(&mut self, uri: &uri::Https) -> PathBuf {
        let authority = uri.canonical_authority();
        if !self.rrdp_dirs.contains(authority.as_ref()) {
            self.rrdp_dirs.insert(authority.as_ref().into());
            self.rrdp_uris.insert(uri.clone(), authority.as_ref().into());
            self.base_dir.join(authority.as_ref())
        }
        else {
            let mut i = 1;
            loop {
                let name = format!("{}-{}", authority, i);
                if !self.rrdp_dirs.contains(&name) {
                    self.rrdp_dirs.insert(name.clone());
                    self.rrdp_uris.insert(uri.clone(), name.clone()); 
                    return self.base_dir.join(name)
                }
                i += 1
            }
        }
    }

    /// Returns an iterator over the URIs and their paths.
    pub fn rrdp_uris(
        &self
    ) -> impl Iterator<Item = (&'_ uri::Https, &'_ str)> + '_ {
        self.rrdp_uris.iter().map(|(key, value)| (key, value.as_str()))
    }
}

