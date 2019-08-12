//! The Routinator Library
//!
//! This crate contains all the moving parts of the Routinator. The
//! application itself, via `main.rs` is only a very tiny frontend.
//!
//! In addition, this also lets you use Routinator as a library for your own
//! dedicated RPKI validation needs. The [operation] module should serve as a
//! good starting point and set of examples since it contains the code for the
//! various commands Routinator provides.
//!
//! The most important modules of the crate are:
//!
//! * [config], which contains all the configuration options as well as means
//! to load them from config files and command line options,
//! * [repository], which provides access to the local copy of the RPKI
//! repository and knows how to update and validate it,
//! * [origins], which allows working with the result of validation, and
//! * [metrics], which contains useful metrics.
//!
//! The additional modules provide additional functionality provided or
//! relied upon by Routinator.
//!
//! [config]: config/index.html
//! [metrics]: metrics/index.html
//! [operation]: operation/index.html
//! [origins]: origins/index.html
//! [repository]: repository/index.html
//!

pub use self::config::Config;
pub use self::operation::{Error, ExitError, Operation};

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
pub mod validity;

