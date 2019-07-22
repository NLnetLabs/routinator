//! Synchronizing repositories via RRDP.

use std::path::PathBuf;
use bytes::Bytes;
use rpki::uri;
use crate::config::Config;
use crate::metrics::Metrics;
use crate::operation::Error;


///----------- Cache ---------------------------------------------------------

/// Access to local copies of repositories synchronized via RRDP.
#[derive(Debug)]
pub struct Cache {
    /// The base directory of the cache.
    cache_dir: PathBuf,
}

impl Cache {
    /// Creates a new RRDP cache.
    pub fn new(
        _config: &Config,
        cache_dir: PathBuf,
        _update: bool,
    ) -> Result<Self, Error> {
        Ok(Cache {
            cache_dir
        })
    }

    /// Start a new validation run.
    pub fn start(&self) {
    }

    pub fn load_server(&self, _notify_uri: &uri::Https) -> Option<ServerId> {
        None
    }

    /// Loads the content of a file from the given URI.
    ///
    /// If `create` is `true`, it will try to rsync missing files.
    ///
    /// If loading the file fails, logs a warning and returns `None`.
    pub fn load_file(
        &self,
        _server_id: ServerId,
        _uri: &uri::Rsync,
        _create: bool
    ) -> Option<Bytes> {
        None
    }

    pub fn cleanup(&self) {
    }

    pub fn update_metrics(&self, _metrics: &mut Metrics) {
    }
}


//------------ ServerId ------------------------------------------------------

/// Identifies an RRDP server in the cache.
#[derive(Clone, Copy, Debug)]
pub struct ServerId;

