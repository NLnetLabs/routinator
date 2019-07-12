//! The Routinator Library
//!
//! This crate contains all the moving parts of the Routinator. The
//! application itself, via `main.rs` is only a very tiny frontend.

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

