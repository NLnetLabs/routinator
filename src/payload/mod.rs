//! Payload data collected during validation runs.
//!
//! This module contains types to collect data during a validation run –
//! the [`ValidationReport`] – and store the resulting data set afterwards.
//! A full such data set is called a [`PayloadSnapshot`] with differences
//! between consecutive such snapshots available as [`PayloadDelta`]. A
//! collection of the two plus additional information is the
//! [`PayloadHistory`] or, wrapped in an arc, [`SharedHistory`].

pub use self::delta::{DeltaArcIter, PayloadDelta};
pub use self::history::{PayloadHistory, SharedHistory};
pub use self::info::PayloadInfo;
pub use self::snapshot::{
    PayloadSnapshot, SnapshotArcAspaIter, SnapshotArcIter,
    SnapshotArcOriginIter, SnapshotArcRouterKeyIter,
};
pub use self::validation::ValidationReport;

mod delta;
mod history;
mod info;
mod validation;
mod snapshot;

