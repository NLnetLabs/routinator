
use untrusted::EndOfInput;


//------------ Error ---------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub enum Error {
    /// Malformed DER.
    Malformed,

    /// DER uses features we haven’t implemented.
    Unimplemented,
}

impl From<EndOfInput> for Error {
    fn from(_: EndOfInput) -> Error {
        Error::Malformed
    }
}

