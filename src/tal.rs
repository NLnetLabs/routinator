//! Trust Anchor Locators

use std::fs::{read_dir, DirEntry, File, ReadDir};
use std::io::{self, Read};
use std::path::Path;
use base64;
use super::ber;
use super::cert::SubjectPublicKeyInfo;
use super::rsync;


//------------ Tal -----------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Tal {
    uris: Vec<rsync::Uri>,
    key_info: SubjectPublicKeyInfo,
}

impl Tal {
    pub fn read_dir<P: AsRef<Path>>(path: P) -> Result<TalIter, io::Error> {
        read_dir(path).map(TalIter)
    }

    pub fn read<R: Read>(reader: &mut R) -> Result<Self, ReadError> {
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;
        
        let mut data = data.as_ref();
        let mut uris = Vec::new();
        while let Some(uri) = Self::take_uri(&mut data)? {
            uris.push(uri)
        }
        let key_info = base64::decode_config(data, base64::MIME)?;
        let key_info = SubjectPublicKeyInfo::decode(key_info.as_ref())?;
        Ok(Tal { uris, key_info })
    }

    fn take_uri(data: &mut &[u8]) -> Result<Option<rsync::Uri>, ReadError> {
        let mut split = data.splitn(2, |&ch| ch == b'\n');
        let mut line = split.next().ok_or(ReadError::UnexpectedEof)?;
        *data = split.next().ok_or(ReadError::UnexpectedEof)?;
        if line.ends_with(b"\r") {
            line = line.split_last().unwrap().1;
        }
        if line.is_empty() {
            Ok(None)
        }
        else {
            Ok(Some(rsync::Uri::from_slice(line)?))
        }
    }
}

impl Tal {
    pub fn uris(&self) -> ::std::slice::Iter<rsync::Uri> {
        self.uris.iter()
    }

    pub fn key_info(&self) -> &SubjectPublicKeyInfo {
        &self.key_info
    }
}


//------------ TalIter -------------------------------------------------------

pub struct TalIter(ReadDir);

impl Iterator for TalIter {
    type Item = Result<Tal, ReadError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.0.next() {
                Some(Ok(entry)) => {
                    match next_entry(entry) {
                        Ok(Some(res)) => return Some(Ok(res)),
                        Ok(None) => { },
                        Err(err) => {
                            error!("Bad trust anchor {}", err);
                            return Some(Err(err))
                        }
                    }
                }
                Some(Err(err)) => return Some(Err(err.into())),
                None => return None
            };
        }
    }
}

fn next_entry(entry: DirEntry) -> Result<Option<Tal>, ReadError> {
    if !entry.file_type()?.is_file() {
        return Ok(None)
    }
    let path = entry.path();
    debug!("Processing TAL {}", path.display());
    Tal::read(&mut File::open(path)?).map(Some)
}


//------------ ReadError -----------------------------------------------------

#[derive(Debug, Fail)]
pub enum ReadError {
    #[fail(display="{}", _0)]
    Io(io::Error),

    #[fail(display="unexpected end of file")]
    UnexpectedEof,

    #[fail(display="bad trunst anchor URI: {}", _0)]
    BadUri(rsync::UriError),

    #[fail(display="bad key info: {}", _0)]
    BadKeyInfoEncoding(base64::DecodeError),

    #[fail(display="bad key info: {}", _0)]
    BadKeyInfo(ber::Error),
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
        ReadError::BadKeyInfoEncoding(err)
    }
}

impl From<ber::Error> for ReadError {
    fn from(err: ber::Error) -> ReadError {
        ReadError::BadKeyInfo(err)
    }
}

