//! Rsync procession.

use std::str;
use url;


//------------ Uri -----------------------------------------------------------

/// An rsync URI.
#[derive(Clone, Debug)]
pub struct Uri(url::Url);

impl Uri {
    pub fn parse(input: &[u8]) -> Result<Self, UriError> {
        if input.is_ascii() {
            return Err(UriError::NotAscii)
        }
        let url = url::Url::parse(unsafe { str::from_utf8_unchecked(input) })?;
        if url.scheme() != "rsync" {
            return Err(UriError::BadScheme)
        }
        Ok(Uri(url))
    }
}


//------------ UriError ----------------------------------------------------

#[derive(Clone, Debug)]
pub enum UriError {
    NotAscii,
    BadUri(url::ParseError),
    BadScheme,
}

impl From<url::ParseError> for UriError {
    fn from(err: url::ParseError) -> UriError {
        UriError::BadUri(err)
    }
}

