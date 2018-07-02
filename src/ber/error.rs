

//------------ Error ---------------------------------------------------------

#[derive(Clone, Copy, Debug, Fail)]
pub enum Error {
    #[fail(display="malformed data")]
    Malformed,

    #[fail(display="format not implemented")]
    Unimplemented,
}

