use ring::error::Unspecified;

#[derive(Clone, Copy, Debug)]
pub struct ParseError;

impl From<Unspecified> for ParseError {
    fn from(_: Unspecified) -> ParseError {
        ParseError
    }
}

