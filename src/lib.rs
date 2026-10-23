//! The Routinator Library
//!
//! This crate contains all the moving parts of the Routinator. The
//! application itself, via `main.rs` is only a very tiny frontend.
//!
//! In addition, this also lets you use Routinator as a library for your own
//! dedicated RPKI validation needs. The [operation] module should serve as a
//! good starting point and set of examples since it contains the code for the
//! various commands Routinator provides and uses all functionality.
//!
//! The library roughly consists of three parts: one part collects and
//! validates RPKI data, one processes the validated data, and the third
//! part distributes the output data to whomever it may concern.
//!
//! The first part can be found in three modules:
//!
//! * [collector], which synchronizes a local copy of the published RPKI data
//!   with its upstream sources,
//! * [store], which maintains a set of data that has passed fundamental
//!   vetting in order to deal with incomplete or broken updates from upstream
//!   sources, and
//! * [engine], which performs a validation run using both collector and
//!   store.
//!
//! The second part currently comes in two flavours:
//!
//! * [payload], which collects and processes data for distribution to
//!   routers or local use, and
//! * [rta], which processes Resource Tagged Authorizations (i.e., objects
//!   signed by resource holders).
//!
//! Additional modules can be added in the future.
//!
//! The third part is represented by a number of modules with differing
//! purposes:
//!
//! * [output] allows formatting data  in different formats,
//! * [http] provides an HTTP server with multiple endpoints for all sorts
//!   of purposes,
//! * [rtr] provides an RTR server which allows routers to synchronize their
//!   RPKI filter tables, and
//! * [validity] can be used to perform route origin validation.
//!
//! Apart from these, there are a few more modules that support these core
//! parts in their work.
//!
#![allow(renamed_and_removed_lints)]
#![allow(clippy::unknown_clippy_lints)]

pub use self::config::Config;
pub use self::error::{Failed, ExitError};
pub use self::operation::Operation;
pub use rpki;
pub use reqwest;

pub mod collector;
pub mod config;
pub mod engine;
pub mod error;
pub mod http;
pub mod log;
pub mod metrics;
pub mod operation;
pub mod output;
pub mod payload;
pub mod process;
pub mod rsc;
pub mod rtr;
pub mod slurm;
pub mod store;
pub mod tals;
pub mod utils;
pub mod validity;

