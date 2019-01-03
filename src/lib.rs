//! The Routinator Library
//!
//! This crate contains all the moving parts of the Routinator. The
//! application itself, via `main.rs` is only a very tiny frontend.

extern crate bytes;
extern crate chrono;
extern crate clap;
#[cfg(unix)] extern crate daemonize;
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
#[cfg(unix)] extern crate syslog;
extern crate tempfile;
extern crate tokio;
extern crate tokio_process;
extern crate toml;

pub use self::config::Config;
pub use self::operation::{Error, Operation};

pub mod config;
pub mod operation;
pub mod origins;
pub mod repository;
pub mod rtr;
pub mod slurm;

