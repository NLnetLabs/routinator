//! The RPKI data as currently published by the repositories.

use std::{fs, io};
use std::path::PathBuf;
use bytes::Bytes;
use log::{error, warn};
use rpki::repository::tal::TalUri;
use rpki::uri;
use crate::config::Config;
use crate::metrics::Metrics;
use crate::operation::Error;
use crate::validation::CaCert;
use super::{rrdp, rsync};


//------------ Cache ---------------------------------------------------------

/// The cache maintains a copy of the current RPKI data as published.
#[derive(Debug)]
pub struct Cache {
    /// The base directory of the cache.
    cache_dir: PathBuf,

    /// The cache for RRDP transport.
    ///
    /// If this is `None`, use of RRDP has been disable entirely.
    rrdp: Option<rrdp::Cache>,

    /// The cache for rsync transport.
    ///
    /// If this is `None`, use of RRDP has been disable entirely.
    rsync: Option<rsync::Cache>,
}

impl Cache {
    /// Initializes the cache.
    ///
    /// Ensures that the base directory exisits and creates it if necessary.
    pub fn init(config: &Config) -> Result<(), Error> {
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
        rrdp::Cache::init(config)?;
        rsync::Cache::init(config)?;
        Ok(())
    }

    /// Creates a new cache.
    ///
    /// Takes all necessary information from `config`. If `update` is `false`,
    /// the cache will not be updated from upstream and only files already
    /// present will be used.
    pub fn new(
        config: &Config,
        update: bool
    ) -> Result<Self, Error> {
        Self::init(config)?;
        Ok(Cache {
            cache_dir: config.cache_dir.clone(),
            rrdp: rrdp::Cache::new(config, update)?,
            rsync: rsync::Cache::new( config, update)?,
        })
    }

    /// Ignites the cache.
    ///
    /// This needs to be done after a possible fork as the caches may use
    /// their own threads.
    pub fn ignite(&mut self) -> Result<(), Error> {
        self.rsync.as_mut().map_or(Ok(()), rsync::Cache::ignite)?;
        self.rrdp.as_mut().map_or(Ok(()), rrdp::Cache::ignite)?;
        Ok(())
    }

    /// Starts a new validation run using this cache.
    pub fn start(&self) -> Result<Run, Error> {
        Run::new(self)
    }
}


//------------ Run -----------------------------------------------------------

/// Using the cache for a single validation run.
#[derive(Debug)]
pub struct Run<'a> {
    cache: &'a Cache,
    rsync: Option<rsync::Run<'a>>,
    rrdp: Option<rrdp::Run<'a>>,
}

impl<'a> Run<'a> {
    /// Creates a new validation run for the given cache.
    fn new(cache: &'a Cache) -> Result<Self, Error> {
        Ok(Run {
            cache,
            rsync: if let Some(ref rsync) = cache.rsync {
                Some(rsync.start()?)
            }
            else {
                None
            },
            rrdp: if let Some(ref rrdp) = cache.rrdp {
                Some(rrdp.start()?)
            }
            else {
                None
            }
        })
    }

    /// Finishes the validation run and updates the provided metrics.
    pub fn done(self, metrics: &mut Metrics) {
        if let Some(rrdp) = self.rrdp {
            rrdp.done(metrics)
        }
        if let Some(rsync) = self.rsync {
            rsync.done(metrics)
        }
    }

    /// Loads the trust anchor certificate at the given URI.
    pub fn load_ta(&self, uri: &TalUri) -> Option<Bytes> {
        match *uri {
            TalUri::Rsync(ref uri) => {
                self.rsync.as_ref().and_then(|rsync| {
                    rsync.load_module(uri);
                    rsync.load_file(uri)
                })
            }
            TalUri::Https(ref uri) => {
                self.rrdp.as_ref().and_then(|rrdp| rrdp.load_ta(uri))
            }
        }
    }

    /// Accesses the repository for the provided RPKI CA.
    ///
    /// This method blocks if the repository is deemed to need updating until
    /// the update has finished.
    ///
    /// If the repository is definitely unavailable, returns `None`.
    pub fn repository<'s>(
        &'s self, ca: &CaCert
    ) -> Option<Repository<'s>> {
        // See if we should and can use RRDP
        if let Some(rrdp_uri) = ca.rpki_notify() {
            if let Some(ref rrdp) = self.rrdp {
                if let Some(server) = rrdp.load_server(rrdp_uri) {
                    return Some(Repository(RepoInner::Rrdp { rrdp, server }))
                }
                warn!(
                    "RRDP repository {} unavailable. Falling back to rsync.",
                    rrdp_uri
                );
            }
        }

        // Well, okay, then. How about rsync?
        if let Some(ref rsync) = self.rsync {
            rsync.load_module(ca.ca_repository());
            return Some(Repository(RepoInner::Rsync { rsync }))
        }

        // All is lost.
        None
    }

    /// Returns whether the repository for the provided PRKI CA is up-to-date.
    pub fn is_current(&self, ca: &CaCert) -> bool {
        if let Some(rrdp_uri) = ca.rpki_notify() {
            if let Some(ref rrdp) = self.rrdp {
                return rrdp.is_current(rrdp_uri);
            }
        }
        if let Some(ref rsync) = self.rsync {
            return rsync.is_current(ca.ca_repository());
        }
        true
    }
}


//------------ Repository ----------------------------------------------------

/// Access to a single repository during a validation run.
#[derive(Debug)]
pub struct Repository<'a>(RepoInner<'a>);

#[derive(Debug)]
enum RepoInner<'a> {
    Rrdp {
        rrdp: &'a rrdp::Run<'a>,
        server: rrdp::ServerId,
    },
    Rsync {
        rsync: &'a rsync::Run<'a>,
    }
}

impl<'a> Repository<'a> {
    /// Loads an object from the repository.
    pub fn load_object(&self, uri: &uri::Rsync) -> Option<Bytes> {
        match self.0 {
            RepoInner::Rrdp { rrdp, server } => {
                rrdp.load_file(server, uri).unwrap_or(None)
            }
            RepoInner::Rsync { rsync } => {
                rsync.load_file(uri)
            }
        }
    }
}

