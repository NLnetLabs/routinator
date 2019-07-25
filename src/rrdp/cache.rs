//! The overall RRDP cache.
//!
//! This is a private module for organizational purposes with `Cache` and
//! `ServerId` reexported by the parent module.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use bytes::Bytes;
use log::{error, info};
use rpki::uri;
use unwrap::unwrap;
use crate::config::Config;
use crate::metrics::Metrics;
use crate::operation::Error;
use super::http::HttpClient;
use super::server::{Server, ServerState};


///----------- Cache ---------------------------------------------------------

/// Access to local copies of repositories synchronized via RRDP.
#[derive(Debug)]
pub struct Cache {
    /// The base directory of the cache.
    cache_dir: PathBuf,

    /// All the servers we know about.
    servers: RwLock<ServerSet>,

    /// A HTTP client.
    ///
    /// If this is `None`, we don’t actually do updates.
    http: Option<HttpClient>,
}

impl Cache {
    /// Creates a new RRDP cache.
    pub fn new(
        config: &Config,
        cache_dir: PathBuf,
        update: bool,
    ) -> Result<Self, Error> {
        let res = Cache {
            cache_dir,
            servers: RwLock::new(ServerSet::new()),
            http: if update { Some(HttpClient::new(config)?) }
                  else { None }
        };
        res.start()?;
        Ok(res)
    }

    /// Start a new validation run.
    ///
    /// Refreshes the set of servers from those present at the cache directory.
    /// It assumes that all directories under that location are in fact
    /// server directories. Tries to access their state file to determine
    /// whether they really are and what notify URI they are responsible for.
    /// Skips over all directories where reading the state file fails.
    ///
    /// This will fail if the cache directpry is unreadable or iterating over
    /// its contents fails.
    pub fn start(&self) -> Result<(), Error> {
        let mut servers = unwrap!(self.servers.write());
        servers.clear();
        let dir = match self.cache_dir.read_dir() {
            Ok(dir) => dir,
            Err(err) => {
                error!(
                    "Fatal: Cannot open RRDP cache dir '{}': {}",
                    self.cache_dir.display(), err
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
                        self.cache_dir.display(), err
                    );
                    return Err(Error)
                }
            };
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                info!(
                    "{}: unexpected file. Skipping.",
                    entry.path().display()
                );
                continue
            }
            let path = entry.path();
            match ServerState::load(&path) {
                Ok(state) => {
                    let _ = servers.insert(
                        Server::existing(state.notify_uri, path)
                    );
                }
                Err(_) => {
                    info!(
                        "{}: bad RRDP server directory. Skipping.",
                        entry.path().display()
                    );
                }
            }
        }
        Ok(())
    }

    /// Loads an RRDP server.
    ///
    /// If the server has already been used during this validation run,
    /// it will simply return its server ID. Otherwise it will try to either
    /// create or update the server and then return its ID.
    ///
    /// Returns `None` if creating failed or if the server is unknown and
    /// updating is disabled
    pub fn load_server(&self, notify_uri: &uri::Https) -> Option<ServerId> {
        let res = unwrap!(self.servers.read()).find(notify_uri);
        let (id, server) = match res {
            Some(some) => some,
            None => {
                unwrap!(self.servers.write()).insert(
                    Server::create(notify_uri.clone(), &self.cache_dir)
                )
            }
        };
        if let Some(ref http) = self.http {
            server.update(http);
        }
        Some(id)
    }

    /// Loads the content of a file from the given URI.
    ///
    /// If `create` is `true`, it will try to rsync missing files.
    ///
    /// If loading the file fails, logs a warning and returns `None`.
    pub fn load_file(
        &self,
        server_id: ServerId,
        uri: &uri::Rsync,
    ) -> Option<Bytes> {
        let server = unwrap!(self.servers.read()).get(server_id)?;
        server.load_file(uri)
    }

    pub fn cleanup(&self) {
        unwrap!(self.servers.write()).cleanup();
    }

    pub fn update_metrics(&self, _metrics: &mut Metrics) {
    }
}


//------------ ServerSet -----------------------------------------------------

/// A collection of servers.
#[derive(Clone, Debug)]
pub struct ServerSet {
    /// The epoch of this server set.
    ///
    /// This value is changed every time the repository is refreshed. This
    /// is a measure to block reuse of server IDs beyond refreshs.
    epoch: usize,

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
            epoch: 0,
            servers: Default::default(),
            uris: Default::default(),
        }
    }

    /// Flushes all the servers and increases the epoch.
    pub fn clear(&mut self) {
        self.epoch = self.epoch.wrapping_add(1);
        self.servers.clear();
        self.uris.clear();
    }

    /// Moves a servers into the set and returns an arc of it.
    ///
    /// If there is already a server with server’s this notify URI, the newly
    /// inserted server will take precedence.
    pub fn insert(&mut self, server: Server) -> (ServerId, Arc<Server>) {
        let server_id = ServerId::new(self.epoch, self.servers.len());
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
        let server = self.servers[server_id.index].clone();
        Some((server_id, server))
    }

    /// Looks up a server based on its server ID
    pub fn get(&self, id: ServerId) -> Option<Arc<Server>> {
        if id.epoch != self.epoch {
            None
        }
        else {
            Some(self.servers[id.index].clone())
        }
    }

    /// Cleans up the server set.
    ///
    /// This will call `remove_unused` on all known servers and only keeps
    /// those that return `false`.
    pub fn cleanup(&mut self) {
        self.epoch = self.epoch.wrapping_add(1);
        self.servers = self.servers.drain(..)
            .filter(|s| !s.remove_unused())
            .collect();
        self.uris.clear();
        for (idx, server) in self.servers.iter().enumerate() {
            self.uris.insert(
                server.notify_uri().clone(),
                ServerId::new(self.epoch, idx)
            );
        }
    }
}


//------------ ServerId ------------------------------------------------------

/// Identifies an RRDP server in the cache.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ServerId {
    /// The epoch value of the repository for this server ID.
    epoch: usize,

    /// The index in the repository’s server list.
    index: usize,
}

impl ServerId {
    /// Creates a new ID from its components.
    fn new(epoch: usize, index: usize) -> Self {
        ServerId { epoch, index }
    }
}

