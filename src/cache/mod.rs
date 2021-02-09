//! Maintaining a local copy of the RPKI repositories.
//!
//! This module provides a means to collect the raw data published via the
//! RPKI repository system. This system consists of a number of so-called
//! RPKI repositories, servers that allow access to set of RPKI objects.
//! Access happens through one of two protocols: rsync (yes, _that_ rsync)
//! or RRDP which sits atop HTTP. Both these protocols are capable of only
//! transmitting changes relative to a previously seen set, so keeping the
//! data downloaded from each repository for later use greatly improves
//! performance.
//!
//! This module provides three public types: [`Cache`] collects all
//! information necessary to run the cache. When it is time to actually use
//! the cache, its [`start`][Cache::start] method creates and returns a [`Run`]
//! which represents an ‘active’ cache that can actually go and fetch data.
//! It provides two methods: [`load_ta`][Run::load_ta] to fetch and load a
//! trust anchor certificate, and [`repository`][Run::repository] to update a
//! respository and subsequently provide access to the updated data via a
//! [`Repository`] object.
//
//  Internally, the module is split up into three private sub-modules. The
//  public types mentioned above live in the base module. In addition, the
//  rsync and rrdp modules that implement those two transport protocols,
//  mirroring the structure of the base module, i.e., they also have `Cache`
//  and `Run` types.
//
pub use self::base::{Cache, Cleanup, Run, Repository};

mod base;
mod rrdp;
mod rsync;

