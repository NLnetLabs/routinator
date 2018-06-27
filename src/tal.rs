//! Trust Anchor Locators

use std::io::{self, Read};
use base64;
use super::rsync;


//------------ Tal -----------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Tal {
    uris: Vec<rsync::Uri>,
    key_info: Vec<u8>,
}

impl Tal {
    pub fn read<R: Read>(reader: &mut R) -> Result<Self, ReadError> {
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;
        
        let mut data = data.as_ref();
        let mut uris = Vec::new();
        while let Some(uri) = Self::take_uri(&mut data)? {
            uris.push(uri)
        }
        let key_info = base64::decode(data)?;
        Ok(Tal { uris, key_info })
    }

    fn take_uri(data: &mut &[u8]) -> Result<Option<rsync::Uri>, ReadError> {
        let mut split = data.splitn(1, |&ch| ch == b'\n');
        let mut line = split.next().ok_or(ReadError::UnexpectedEor)?;
        *data = split.next().ok_or(ReadError::UnexpectedEor)?;
        if line.ends_with(b"\r") {
            line = line.split_last().unwrap().1;
        }
        if line.is_empty() {
            Ok(None)
        }
        else {
            Ok(Some(rsync::Uri::parse(line)?))
        }
    }
}


//------------ ReadError -----------------------------------------------------

#[derive(Debug)]
pub enum ReadError {
    Io(io::Error),
    UnexpectedEor,
    BadUri(rsync::UriError),
    BadKeyInfo(base64::DecodeError),
}

impl From<io::Error> for ReadError {
    fn from(err: io::Error) -> ReadError {
        ReadError::Io(err)
    }
}

impl From<rsync::UriError> for ReadError {
    fn from(err: rsync::UriError) -> ReadError {
        ReadError::BadUri(err)
    }
}

impl From<base64::DecodeError> for ReadError {
    fn from(err: base64::DecodeError) -> ReadError {
        ReadError::BadKeyInfo(err)
    }
}

