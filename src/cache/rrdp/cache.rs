/// The RRDP cache.
///
/// This is a private module. It’s types are reexported by the parent.

use std::fs;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use bytes::Bytes;
use log::{debug, error, info, warn};
use rpki::uri;
use crate::config::Config;
use crate::metrics::{Metrics, RrdpServerMetrics};
use crate::operation::Error;
use crate::utils::UriExt;
use super::http::HttpClient;
use super::server::{Server, ServerState};


///----------- Configuration Constants ---------------------------------------

/// The maximum size of a HTTP response for a trust anchor certificate.
const MAX_TA_SIZE: u64 = 64 * 1024;


//------------ Cache ---------------------------------------------------------

/// A local copy of repositories synchronized via RRDP.
#[derive(Debug)]
pub struct Cache {
    /// The base directory of the RRDP server cache.
    cache_dir: PathBuf,

    /// The base directory of the TA cache.
    ta_dir: PathBuf,

    /// A HTTP client.
    ///
    /// If this is `None`, we don’t actually do updates.
    http: Option<HttpClient>,

    /// Whether to filter dubious authorities in notify URIs.
    filter_dubious: bool,
}

impl Cache {
    pub fn init(config: &Config) -> Result<(), Error> {
        let rrdp_dir = Self::cache_dir(config);
        if let Err(err) = fs::create_dir_all(&rrdp_dir) {
            error!(
                "Failed to create RRDP cache directory {}: {}.",
                rrdp_dir.display(), err
            );
            return Err(Error);
        }
        let ta_dir = Self::ta_dir(config);
        if let Err(err) = fs::create_dir_all(&ta_dir) {
            error!(
                "Failed to create HTTP cache directory {}: {}.",
                ta_dir.display(), err
            );
            return Err(Error);
        }
        HttpClient::init(config)?;
        Ok(())
    }

    pub fn new(config: &Config, update: bool) -> Result<Option<Self>, Error> {
        if config.disable_rrdp {
            Ok(None)
        }
        else {
            Self::init(config)?;
            Ok(Some(Cache {
                cache_dir: Self::cache_dir(config),
                ta_dir: Self::ta_dir(config),
                http: if update { Some(HttpClient::new(config)?) }
                      else { None },
                filter_dubious: !config.allow_dubious_hosts
            }))
        }
    }

    pub fn ignite(&mut self) -> Result<(), Error> {
        self.http.as_mut().map_or(Ok(()), HttpClient::ignite)
    }

    fn cache_dir(config: &Config) -> PathBuf {
        config.cache_dir.join("rrdp")
    }

    fn ta_dir(config: &Config) -> PathBuf {
        config.cache_dir.join("http")
    }

    pub fn start(&self) -> Result<Run, Error> {
        Run::new(self)
    }

    #[allow(clippy::mutable_key_type)]
    pub fn cleanup(&self, _retain: &HashSet<uri::Https>) {
        // XXX Unimplemented pending RRDP rewrite.
    }
}


//------------ Run -----------------------------------------------------------

/// Information for a validation run.
#[derive(Debug)]
pub struct Run<'a> {
    /// A reference to the underlying cache.
    cache: &'a Cache,

    /// All the servers we know about.
    servers: RwLock<ServerSet>,
}

impl<'a> Run<'a> {
    fn new(cache: &'a Cache) -> Result<Self, Error> {
        let mut servers = ServerSet::new();
        let dir = match cache.cache_dir.read_dir() {
            Ok(dir) => dir,
            Err(err) => {
                error!(
                    "Fatal: Cannot open RRDP cache dir '{}': {}",
                    cache.cache_dir.display(), err
                );
                return Err(Error)
            }
        };
        for entry in dir {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    error!(
                        "Fatal: Cannot iterate over RRDP cache dir '{}': {}",
                        cache.cache_dir.display(), err
                    );
                    return Err(Error)
                }
            };
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                debug!(
                    "{}: unexpected file. Skipping.",
                    entry.path().display()
                );
                continue
            }
            let path = entry.path();
            match ServerState::load(&path.join("state.txt")) {
                Ok(state) => {
                    debug!(
                        "RRDP: Known server {} at {}",
                        state.notify_uri,
                        path.display()
                    );
                    let _ = servers.insert(
                        Server::existing(state.notify_uri, path)
                    );
                }
                Err(_) => {
                    debug!(
                        "{}: bad RRDP server directory. Skipping.",
                        entry.path().display()
                    );
                }
            }
        }
        Ok(Run {
            cache,
            servers: RwLock::new(servers)
        })
    }
    
    pub fn load_ta(&self, uri: &uri::Https) -> Option<Bytes> {
        let http = match self.cache.http {
            Some(ref http) => http,
            None => return None,
        };
        let mut response = match http.response(uri) {
            Ok(response) => response,
            Err(_) => return None,
        };
        if response.content_length() > Some(MAX_TA_SIZE) {
            warn!(
                "Trust anchor certificate {} exceeds size limit of {} bytes. \
                 Ignoring.",
                uri, MAX_TA_SIZE
            );
            return None
        }
        let mut bytes = Vec::new();
        if let Err(err) = response.copy_to(&mut bytes) {
            info!("Failed to get trust anchor {}: {}", uri, err);
            return None
        }
        Some(Bytes::from(bytes))
    }

    pub fn is_current(&self, notify_uri: &uri::Https) -> bool {
        // If updating is disabled, everything is already current.
        if self.cache.http.is_none() {
            return true
        }
        match self.servers.read().unwrap().find(notify_uri) {
            Some((_, server)) => server.is_current(),
            None => false
        }
    }

    /// Loads an RRDP server.
    ///
    /// If the server has already been used during this validation run,
    /// it will simply return its server ID. Otherwise it will try to either
    /// create or update the server and then return its ID.
    ///
    /// Returns `None` if creating failed or if the server is unknown and
    /// updating is disabled
    #[allow(clippy::question_mark)] // Explicit if: more understandable code
    pub fn load_server(&self, notify_uri: &uri::Https) -> Option<ServerId> {
        let res = self.servers.read().unwrap().find(notify_uri);
        let (id, server) = match res {
            Some(some) => some,
            None => {
                if self.cache.http.is_none() {
                    return None
                }
                let server = if
                    self.cache.filter_dubious
                    && notify_uri.has_dubious_authority()
                {
                    Server::create_broken(notify_uri.clone())
                }
                else {
                    Server::create(notify_uri.clone(), &self.cache.cache_dir)
                };
                self.servers.write().unwrap().insert(server)
            }
        };
        if let Some(ref http) = self.cache.http {
            server.update(http);
        }
        if server.is_broken() {
            None
        }
        else {
            Some(id)
        }
    }

    pub fn load_file(
        &self,
        server_id: ServerId,
        uri: &uri::Rsync
    ) -> Result<Option<Bytes>, Error> {
        self.servers.read().unwrap().get(server_id).load_file(uri)
    }

    pub fn into_metrics(self) -> Vec<RrdpServerMetrics> {
        self.servers.into_inner().unwrap().into_metrics()
    }

    pub fn done(self, metrics: &mut Metrics) {
        metrics.set_rrdp(self.into_metrics())
    }
}


//------------ ServerSet -----------------------------------------------------

/// A collection of servers.
#[derive(Clone, Debug)]
pub struct ServerSet {
    /// The servers we know of.
    ///
    /// The index portion of server ID refers to indexes in this vector.
    servers: Vec<Arc<Server>>,

    /// The rsyncNotify URIs of the servers.
    ///
    /// This is only here to speed up those lookups.
    uris: HashMap<uri::Https, ServerId>,
}

impl ServerSet {
    /// Creates a new empty server set.
    pub fn new() -> Self {
        ServerSet {
            servers: Default::default(),
            uris: Default::default(),
        }
    }

    /// Moves a servers into the set and returns an arc of it.
    ///
    /// If there is already a server with server’s this notify URI, the newly
    /// inserted server will take precedence.
    pub fn insert(&mut self, server: Server) -> (ServerId, Arc<Server>) {
        let server_id = ServerId(self.servers.len());
        let _ = self.uris.insert(server.notify_uri().clone(), server_id);
        let arc = Arc::new(server);
        self.servers.push(arc.clone());
        (server_id, arc)
    }

    /// Looks up a server for a given notify URI.
    ///
    /// Returns both the server ID and a reference to the server.
    pub fn find(
        &self,
        notify_uri: &uri::Https
    ) -> Option<(ServerId, Arc<Server>)> {
        let server_id = *self.uris.get(notify_uri)?;
        let server = self.servers[server_id.0].clone();
        Some((server_id, server))
    }

    /// Looks up a server based on its server ID
    pub fn get(&self, id: ServerId) -> Arc<Server> {
        self.servers[id.0].clone()
    }

    pub fn into_metrics(self) -> Vec<RrdpServerMetrics> {
        self.servers.into_iter().filter_map(|server| server.metrics()).collect()
    }
}


//------------ ServerId ------------------------------------------------------

/// Identifies an RRDP server in the cache.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ServerId(usize);

