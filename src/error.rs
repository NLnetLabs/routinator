/// Error types used by multiple modules.
///
/// There are two error types that are used widely within the Routinator
/// library.
///
/// The most important is [`Failed`]. This error indicates that an
/// operation had to be canceled for some reason and callers can assume
/// that all diagnostic information has been logged and they need not do
/// anything further.
///
/// Secondly, [`ExitError`] is used when the program should be terminated. It
/// provides enough information to determine the exit code of the program.

use log::error;


//------------ Failed --------------------------------------------------------

/// An operation has failed to complete.
///
/// This error types is used to indicate that an operation has failed,
/// diagnostic information has been printed or logged, and the caller can’t
/// really do anything to recover.
#[derive(Clone, Copy, Debug)]
pub struct Failed;

impl From<Fatal> for Failed {
    fn from(_: Fatal) -> Failed {
        Failed
    }
}


//------------ RunFailed -----------------------------------------------------

/// A validation run has failed to complete.
///
/// This error may be recoverable, which typically happens after some local
/// data corruption has been discovered and the offending was data removed. A
/// new validation run should then be started immediately to hopefully lead
/// to a success.
///
/// The error may also be fatal in which Routinator should just exit.
#[derive(Clone, Copy, Debug)]
pub struct RunFailed {
    /// Was the error fatal?
    fatal: bool,
}

impl RunFailed {
    /// Create a new fatal run failure.
    pub fn fatal() -> Self {
        RunFailed { fatal: true }
    }

    /// Create a new “retry” run failure.
    pub fn retry() -> Self {
        RunFailed { fatal: false }
    }

    /// Returns whether the error is fatal.
    pub fn is_fatal(self) -> bool {
        self.fatal
    }

    /// Returns whether the run should be retried.
    pub fn should_retry(self) -> bool {
        !self.fatal
    }
}

impl From<Fatal> for RunFailed {
    fn from(_: Fatal) -> Self {
        RunFailed::fatal()
    }
}

impl From<Failed> for RunFailed {
    fn from(_: Failed) -> Self {
        RunFailed::fatal()
    }
}


//------------ Fatal ---------------------------------------------------------

/// An operation has failed and continuing is pointless.
///
/// This error types is used to indicate that an operation has failed,
/// diagnostic information has been printed or logged, and continuing is
/// pointless or even dangerous.
#[derive(Clone, Copy, Debug)]
pub struct Fatal;

// XXX This shouldn’t be here.
impl From<Failed> for Fatal {
    fn from(_: Failed) -> Self {
        Self
    }
}


//------------ ExitError -----------------------------------------------------

/// An error happened that should lead to terminating the program.
#[derive(Clone, Copy, Debug)]
pub enum ExitError {
    /// Something has happened.
    ///
    /// This should be exit status 1.
    Generic,

    /// Incomplete update.
    ///
    /// This should be exit status 2.
    IncompleteUpdate,

    /// An object could not be validated.
    ///
    /// This should be exit status 3.
    Invalid,
}

impl From<Failed> for ExitError {
    fn from(_: Failed) -> ExitError {
        error!("Fatal error. Exiting.");
        ExitError::Generic
    }
}

impl From<RunFailed> for ExitError {
    fn from(_: RunFailed) -> ExitError {
        error!("Fatal error. Exiting.");
        ExitError::Generic
    }
}

impl From<Fatal> for ExitError {
    fn from(_: Fatal) -> ExitError {
        error!("Fatal error. Exiting.");
        ExitError::Generic
    }
}

