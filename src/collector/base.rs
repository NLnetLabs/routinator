//! The overall collector, binding the various transports together.
//!
//! This is a private module. It’s types are re-exported by the parent.

use std::{fs, io};
use std::collections::HashSet;
use std::path::PathBuf;
use bytes::Bytes;
use log::{error, warn};
use rpki::repository::tal::TalUri;
use rpki::uri;
use crate::config::Config;
use crate::error::Failed;
use crate::metrics::Metrics;
use crate::engine::CaCert;
use super::{rrdp, rsync};


//------------ Collector -----------------------------------------------------

/// Access to the currently published RPKI data.
///
/// A collector can be created based on the configuration via
/// [Collector::new]. If you don’t actually want to perform a validation run 
/// but just initialize everything, [Collector::init] will suffice.
///
/// `Collector` values don’t actually do anything. Instead, when starting a
/// validation run, you have to call [`start`][Self::start] to acquire a
/// [`Run`] that does all the work. Before doing that for the first time,
/// you need to call [`ignite`][Self::ignite] once.
#[derive(Debug)]
pub struct Collector {
    /// The base directory of the cache.
    cache_dir: PathBuf,

    /// The collector for RRDP transport.
    ///
    /// If this is `None`, use of RRDP has been disabled entirely.
    rrdp: Option<rrdp::Cache>,

    /// The collector for rsync transport.
    ///
    /// If this is `None`, use of rsync has been disabled entirely.
    rsync: Option<rsync::Collector>,
}

impl Collector {
    /// Initializes the collector without creating a value.
    ///
    /// Ensures that the base directory exists and creates it if necessary.
    ///
    /// The function is called implicitly by [`new`][Self::new].
    pub fn init(config: &Config) -> Result<(), Failed> {
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
            return Err(Failed)
        }
        rrdp::Cache::init(config)?;
        rsync::Collector::init(config)?;
        Ok(())
    }

    /// Creates a new collector.
    ///
    /// Takes all necessary information from `config`. If `update` is `false`,
    /// the collector will not be updated from upstream and only data that has
    /// been collected previosuly will be used. This differs from disabling
    /// transports as it will still use whatever is present on disk as
    /// potentially updated data.
    pub fn new(
        config: &Config,
        update: bool
    ) -> Result<Self, Failed> {
        Self::init(config)?;
        Ok(Collector {
            cache_dir: config.cache_dir.clone(),
            rrdp: rrdp::Cache::new(config, update)?,
            rsync: rsync::Collector::new(config, update)?,
        })
    }

    /// Ignites the collector.
    ///
    /// This needs to be done after a possible fork as the collector may spawn
    /// a set of worker threads.
    pub fn ignite(&mut self) -> Result<(), Failed> {
        self.rrdp.as_mut().map_or(Ok(()), rrdp::Cache::ignite)?;
        self.rsync.as_mut().map_or(Ok(()), rsync::Collector::ignite)?;
        Ok(())
    }

    /// Starts a new validation run using this collector.
    pub fn start(&self) -> Result<Run, Failed> {
        Run::new(self)
    }

    /// Prepares for a cleanup run.
    ///
    /// The method returns a [`Cleanup`] value that can be used to register
    /// those repositories that should be kept around.
    pub fn cleanup(&self) -> Cleanup {
        Cleanup::new(self)
    }
}


//------------ Run -----------------------------------------------------------

/// Using the collector for a single validation run.
///
/// The type provides access to updated versions of trust anchor certificates
/// and RPKI repositories via the [`load_ta`][Self::load_ta] and
/// [`repository`][Self::repository] methods, respectively.
///
/// This type references the underlying [`Collector`]. It can be used with
/// multiple threads using
/// [crossbeam’s][https://github.com/crossbeam-rs/crossbeam] scoped threads.
#[derive(Debug)]
pub struct Run<'a> {
    /// A reference to the underlying collector.
    collector: &'a Collector,

    /// The runner for rsync if this transport is enabled.
    rsync: Option<rsync::Run<'a>>,

    /// The runner for RRDP if this transport is enabled.
    rrdp: Option<rrdp::Run<'a>>,
}

impl<'a> Run<'a> {
    /// Creates a new validation run for the given collector.
    fn new(collector: &'a Collector) -> Result<Self, Failed> {
        Ok(Run {
            collector,
            rsync: if let Some(ref rsync) = collector.rsync {
                Some(rsync.start())
            }
            else {
                None
            },
            rrdp: if let Some(ref rrdp) = collector.rrdp {
                Some(rrdp.start()?)
            }
            else {
                None
            }
        })
    }

    /// Finishes the validation run.
    ///
    /// Updates `metrics` with the collector run’s metrics.
    ///
    /// If you are not interested in the metrics, you can simply drop the
    /// value, instead.
    pub fn done(self, metrics: &mut Metrics) {
        if let Some(rrdp) = self.rrdp {
            rrdp.done(metrics)
        }
        if let Some(rsync) = self.rsync {
            rsync.done(metrics)
        }
    }

    /// Loads the trust anchor certificate at the given URI.
    ///
    /// The method will block until the certificate has been downloaded or
    /// the download failed. In the latter case, diagnostic information will
    /// be logged and `None` returned.
    ///
    /// Trust anchor certificates referenced by a rsync URI will cause that
    /// module to be updated once, whereas those referenced via HTTPS URIs
    /// will be newly downloaded upon each call.
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
    /// If the repository is definitely unavailable, logs diagnositic
    /// information and returns `None`.
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
    /// The repository is accessed via RRDP.
    Rrdp {
        /// The RRDP runner.
        rrdp: &'a rrdp::Run<'a>,

        /// The server ID for the RRDP server.
        server: rrdp::ServerId,
    },

    /// The repository is accessed via rsync.
    Rsync {
        /// The rsync runner.
        rsync: &'a rsync::Run<'a>,
    }
}

impl<'a> Repository<'a> {
    /// Returns whether the repository was accessed via RRDP.
    pub fn is_rrdp(&self) -> bool {
        matches!(self.0, RepoInner::Rrdp { .. })
    }

    /// Loads an object from the repository.
    ///
    /// If the object is unavailable for some reason, logs diagnostic
    /// information and returns `None`.
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


//------------ Cleanup -------------------------------------------------------

/// A builder-style type for cleanup.
///
/// This type can be requested from a collector via [`Collector::cleanup`]. 
/// Repositories that should be be kept in the collector can be registered via
/// the [`retain_rrdp_repository`][Cleanup::retain_rrdp_repository] and
/// [`retain_rsync_module`][Cleanup::retain_rsync_module] methods. A call to
/// [`commit`][Cleanup::commit] will cause the collector to delete all
/// repositories that have not been registered.
#[derive(Clone, Debug)]
pub struct Cleanup<'a> {
    /// A reference to the underlying collector.
    collector: &'a Collector,

    /// The set of rsync modules to retain.
    rsync: rsync::ModuleSet,

    /// The set of RRDP repositories to retain.
    rrdp: HashSet<uri::Https>,
}

impl<'a> Cleanup<'a> {
    /// Creates a new cleanup object for the given collector.
    fn new(collector: &'a Collector) -> Self {
        Cleanup {
            collector,
            rsync: Default::default(),
            rrdp: Default::default(),
        }
    }

    /// Registers an RRDP repository to be retained in cleanup.
    pub fn retain_rrdp_repository(&mut self, rpki_notify: &uri::Https) {
        if self.collector.rrdp.is_some() {
            self.rrdp.insert(rpki_notify.clone());
        }
    }

    /// Registers an rsync module to be retained in cleanup.
    pub fn retain_rsync_module(&mut self, uri: &uri::Rsync) {
        if self.collector.rsync.is_some() {
            self.rsync.add_from_uri(uri);
        }
    }

    /// Performs the cleanup run.
    pub fn commit(self) {
        if let Some(rsync) = self.collector.rsync.as_ref() {
            rsync.cleanup(&self.rsync)
        }
        if let Some(rrdp) = self.collector.rrdp.as_ref() {
            rrdp.cleanup(&self.rrdp)
        }
    }
}

