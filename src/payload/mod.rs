//! Payload data collected during validation runs.
//!
//! This module contains types to collect data during a validation run,
//! store the resulting data set after, and produce difference sets between
//! consecutive versions of the data. It also contains the types for metrics
//! related to this data.

pub use self::delta::{DeltaArcIter, PayloadDelta};
pub use self::history::{PayloadHistory, SharedHistory};
pub use self::info::PayloadInfo;
pub use self::snapshot::{
    PayloadSnapshot, SnapshotArcOriginsIter, SnapshotArcIter,
    SnapshotArcRouterKeysIter,
};
pub use self::validation::ValidationReport;

mod delta;
mod history;
mod info;
mod validation;
mod snapshot;

