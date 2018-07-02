//! Rsync procession.

use std::{fmt, io, str};
use std::fs::create_dir_all;
use std::path::Path;
use std::process::Command;
use url;


//------------ update --------------------------------------------------------

pub fn update<P: AsRef<Path>>(
    source: &Uri,
    destination: P
) -> Result<(), io::Error> {
    debug!("rsyncing from {}", source);
    create_dir_all(destination.as_ref())?;
    let status = Command::new("rsync")
        .arg("-az")
        .arg("--delete")
        .arg(source.as_str())
        .arg(destination.as_ref())
        .status()?;
    if !status.success() {
        Err(io::Error::new(io::ErrorKind::Other, "rsync failed"))
    }
    else {
        Ok(())
    }
}


//------------ Uri -----------------------------------------------------------

/// An rsync URI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Uri(url::Url);

impl Uri {
    pub fn parse(input: &[u8]) -> Result<Self, UriError> {
        if !input.is_ascii() {
            return Err(UriError::NotAscii)
        }
        let url = url::Url::parse(unsafe { str::from_utf8_unchecked(input) })?;
        if url.scheme() != "rsync" {
            return Err(UriError::BadScheme)
        }
        Ok(Uri(url))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn host(&self) -> &str {
        self.0.host_str().unwrap()
    }

    pub fn port(&self) -> Option<u16> {
        self.0.port()
    }

    pub fn path(&self) -> &str {
        self.0.path().trim_left_matches('/')
    }

    pub fn parent(&self) -> Uri {
        let mut res = self.clone();
        res.0.set_path(
            &format!("{}/",
                Path::new(self.path()).parent().unwrap().to_str().unwrap()
            )
        );
        res
    }

    pub fn join(&self, path: &str) -> Result<Self, UriError> {
        Ok(Uri(self.0.join(path)?))
    }

    pub fn ends_with(&self, extension: &str) -> bool {
        self.0.path().ends_with(extension)
    }
}

impl fmt::Display for Uri {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}


//------------ UriError ----------------------------------------------------

#[derive(Clone, Debug, Fail)]
pub enum UriError {
    #[fail(display="invalid characters")]
    NotAscii,

    #[fail(display="{}", _0)]
    BadUri(url::ParseError),

    #[fail(display="bad URI scheme")]
    BadScheme,
}

impl From<url::ParseError> for UriError {
    fn from(err: url::ParseError) -> UriError {
        UriError::BadUri(err)
    }
}

