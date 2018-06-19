

//------------ Error ---------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub enum Error {
    /// Malformed DER.
    Malformed,

    /// DER uses features we haven’t implemented.
    Unimplemented,
}

