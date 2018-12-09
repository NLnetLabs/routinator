//! RPKI Validation.
//!
//! The _Resource Public Key Infrastructure_ (RPKI) is an application of
//! PKI to Internet routing security. It allows owners of IP address prefixes
//! to publish cryptographically signed associations of their prefixes to
//! autonomous systems, allowing the validation of the origin of a route
//! announcement in BGP.
//!
//! RPKI employs a repository of signed objects that contains all the
//! information one needs to validate so-called _ROAs_ (or Route Origin
//! Attestations), each of which describes a mapping between a set of IP
//! address prefixes and an AS number. This repository is publicly available
//! via the rsync.
//!
//! This crate implements everything that is necessary to create a local
//! copy of the repository, validate it and output the list of valid ROAs.
//! The main entry point is the [`Repository`] type that represents this
//! local copy somewhere in the file system.
//!
//! [`Repository`]: repository/struct.Repository.html

extern crate bytes;
extern crate chrono;
extern crate clap;
extern crate daemonize;
extern crate dirs;
#[macro_use] extern crate failure;
extern crate fern;
#[macro_use] extern crate futures;
extern crate futures_cpupool;
extern crate json;
#[macro_use] extern crate log;
extern crate num_cpus;
extern crate rpki;
extern crate slab;
extern crate syslog;
extern crate tempfile;
extern crate tokio;
extern crate tokio_process;
extern crate toml;

pub mod config;
pub mod operation;
pub mod origins;
pub mod repository;
pub mod rtr;
pub mod slurm;


