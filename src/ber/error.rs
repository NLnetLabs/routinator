//! Error Handling.
//!
//! This is a private module. Its public content is being re-exported by the
//! parent module.


//------------ Error ---------------------------------------------------------

/// An error happned while decoding BER data.
#[derive(Clone, Copy, Debug, Fail)]
pub enum Error {
    #[fail(display="malformed data")]
    Malformed,

    #[fail(display="format not implemented")]
    Unimplemented,
}

