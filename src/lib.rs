//! The Routinator Library
//!
//! This crate contains all the moving parts of the Routinator. The
//! application itself, via `main.rs` is only a very tiny frontend.

extern crate bytes;
extern crate chrono;
#[macro_use] extern crate clap;
#[cfg(unix)] extern crate daemonize;
#[macro_use] extern crate derive_more;
extern crate dirs;
extern crate fern;
#[macro_use] extern crate futures;
extern crate futures_cpupool;
extern crate httparse;
extern crate hyper;
extern crate json;
extern crate listenfd;
#[cfg(unix)] extern crate libc;
#[macro_use] extern crate log;
extern crate log_reroute;
extern crate num_cpus;
extern crate rpki;
extern crate slab;
#[cfg(unix)] extern crate syslog;
extern crate tempfile;
extern crate tokio;
extern crate tokio_process;
extern crate toml;
#[macro_use] extern crate unwrap;

pub use self::config::Config;
pub use self::operation::{Error, Operation};

pub mod config;
pub mod http;
pub mod metrics;
pub mod operation;
pub mod origins;
pub mod output;
pub mod repository;
pub mod rtr;
pub mod slurm;
pub mod utils;

