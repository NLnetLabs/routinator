//! Simple binary data serialization.
//!
//! The trait [`Compose`] and [`Parse`] are implemented by types that know
//! how to serialize themselves. The module implements the traits for all the
//! types we need.

use std::{error, io, slice};
use std::convert::TryFrom;
use bytes::Bytes;
use rpki::uri;


//------------ Compose + Parse -----------------------------------------------

pub trait Compose<W> {
    fn compose(&self, target: &mut W) -> Result<(), io::Error>;
}

pub trait Parse<R>
where Self: Sized {
    fn parse(source: &mut R) -> Result<Self, io::Error>;
}


//------------ u8 ------------------------------------------------------------

impl<W: io::Write> Compose<W> for u8 {
    fn compose(&self, target: &mut W) -> Result<(), io::Error> {
        target.write_all(slice::from_ref(self))
    }
}

impl<R: io::Read> Parse<R> for u8 {
    fn parse(source: &mut R) -> Result<Self, io::Error> {
        let mut res = 0u8;
        source.read_exact(slice::from_mut(&mut res))?;
        Ok(res)
    }
}


//------------ u32 -----------------------------------------------------------

impl<W: io::Write> Compose<W> for u32 {
    fn compose(&self, target: &mut W) -> Result<(), io::Error> {
        target.write_all(&self.to_be_bytes())
    }
}

impl<R: io::Read> Parse<R> for u32 {
    fn parse(source: &mut R) -> Result<Self, io::Error> {
        let mut res = 0u32.to_ne_bytes();
        source.read_exact(&mut res)?;
        Ok(u32::from_be_bytes(res))
    }
}


//------------ u64 -----------------------------------------------------------

impl<W: io::Write> Compose<W> for u64 {
    fn compose(&self, target: &mut W) -> Result<(), io::Error> {
        target.write_all(&self.to_be_bytes())
    }
}

impl<R: io::Read> Parse<R> for u64 {
    fn parse(source: &mut R) -> Result<Self, io::Error> {
        let mut res = 0u64.to_ne_bytes();
        source.read_exact(&mut res)?;
        Ok(u64::from_be_bytes(res))
    }
}


//------------ i64 -----------------------------------------------------------

impl<W: io::Write> Compose<W> for i64 {
    fn compose(&self, target: &mut W) -> Result<(), io::Error> {
        target.write_all(&self.to_be_bytes())
    }
}

impl<R: io::Read> Parse<R> for i64 {
    fn parse(source: &mut R) -> Result<Self, io::Error> {
        let mut res = 0i64.to_ne_bytes();
        source.read_exact(&mut res)?;
        Ok(i64::from_be_bytes(res))
    }
}


//----------- uri::Rsync -----------------------------------------------------

impl<W: io::Write> Compose<W> for uri::Rsync {
    fn compose(&self, target: &mut W) -> Result<(), io::Error> {
        u32::try_from(self.as_slice().len())
        .map_err(|_| io_err_other("excessively large URI"))?
        .compose(target)?;
        target.write_all(self.as_slice())
    }
}

impl<R: io::Read> Parse<R> for uri::Rsync {
    fn parse(source: &mut R) -> Result<Self, io::Error> {
        let len = u32::parse(source)?;
        let len = usize::try_from(len).map_err(|_| {
            io_err_other("URI too large for this system")
        })?;
        let mut bits = vec![0u8; len];
        source.read_exact(&mut bits)?;
        Self::from_bytes(bits.into()).map_err(|err| {
            io_err_other(format!("bad URI: {}", err))
        })
    }
}


//----------- uri::Https -----------------------------------------------------

impl<W: io::Write> Compose<W> for uri::Https {
    fn compose(&self, target: &mut W) -> Result<(), io::Error> {
        u32::try_from(self.as_slice().len())
        .map_err(|_| io_err_other("excessively large URI"))?
        .compose(target)?;
        target.write_all(self.as_slice())
    }
}

impl<R: io::Read> Parse<R> for uri::Https {
    fn parse(source: &mut R) -> Result<Self, io::Error> {
        let len = usize::try_from(u32::parse(source)?).map_err(|_| {
            io_err_other("URI too large for this system")
        })?;
        let mut bits = vec![0u8; len];
        source.read_exact(&mut bits)?;
        Self::from_bytes(bits.into()).map_err(|err| {
            io_err_other(format!("bad URI: {}", err))
        })
    }
}


//----------- Option<uri::Https> ---------------------------------------------

impl<W: io::Write> Compose<W> for Option<uri::Https> {
    fn compose(&self, target: &mut W) -> Result<(), io::Error> {
        if let Some(uri) = self.as_ref() {
            u32::try_from(uri.as_slice().len())
            .map_err(|_| io_err_other("excessively large URI"))?
            .compose(target)?;
            target.write_all(uri.as_slice())
        }
        else {
            0u32.compose(target)
        }
    }
}

impl<R: io::Read> Parse<R> for Option<uri::Https> {
    fn parse(source: &mut R) -> Result<Self, io::Error> {
        let len = u32::parse(source)?;
        if len == 0 {
            return Ok(None)
        }
        let len = usize::try_from(len).map_err(|_| {
            io_err_other("URI too large for this system")
        })?;
        let mut bits = vec![0u8; len];
        source.read_exact(&mut bits)?;
        uri::Https::from_bytes(bits.into()).map_err(|err| {
            io_err_other(format!("bad URI: {}", err))
        }).map(Some)
    }
}


//------------ Bytes ---------------------------------------------------------

impl<W: io::Write> Compose<W> for Bytes {
    fn compose(&self, target: &mut W) -> Result<(), io::Error> {
        u64::try_from(self.len())
        .map_err(|_| io_err_other("excessively large data"))?
        .compose(target)?;
        target.write_all(self.as_ref())
    }
}

impl<R: io::Read> Parse<R> for Bytes {
    fn parse(source: &mut R) -> Result<Self, io::Error> {
        let len = usize::try_from(u64::parse(source)?).map_err(|_| {
            io_err_other("URI too large for this system")
        })?;
        let mut bits = vec![0u8; len];
        source.read_exact(&mut bits)?;
        Ok(bits.into())
    }
}


//============ Helper Functions ==============================================

/// Creates an IO error of kind other with the given string.
fn io_err_other(
    err: impl Into<Box<dyn error::Error + Send + Sync>>
) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}

