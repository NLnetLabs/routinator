//! Simple binary data serialization.
//!
//! The trait [`Compose`] and [`Parse`] are implemented by types that know
//! how to serialize themselves. The module implements the traits for all the
//! types we need.

use std::{error, fmt, io, slice};
use bytes::Bytes;
use rpki::{rrdp, uri};
use rpki::repository::x509::Serial;
use uuid::Uuid;


//------------ Compose + Parse -----------------------------------------------

pub trait Compose<W> {
    fn compose(&self, target: &mut W) -> Result<(), io::Error>;
}

pub trait Parse<R>
where Self: Sized {
    fn parse(source: &mut R) -> Result<Self, ParseError>;
}


//------------ u8 ------------------------------------------------------------

impl<W: io::Write> Compose<W> for u8 {
    fn compose(&self, target: &mut W) -> Result<(), io::Error> {
        target.write_all(slice::from_ref(self))
    }
}

impl<R: io::Read> Parse<R> for u8 {
    fn parse(source: &mut R) -> Result<Self, ParseError> {
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
    fn parse(source: &mut R) -> Result<Self, ParseError> {
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
    fn parse(source: &mut R) -> Result<Self, ParseError> {
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
    fn parse(source: &mut R) -> Result<Self, ParseError> {
        let mut res = 0i64.to_ne_bytes();
        source.read_exact(&mut res)?;
        Ok(i64::from_be_bytes(res))
    }
}


//------------ Option<i64> ---------------------------------------------------
//
// Encoding starts with a single octet marking the option. If this is 0, the
// option is `None` and nothing follows. If this is 1, the option is `Some(_)`
// and the value follows.

impl<W: io::Write> Compose<W> for Option<i64> {
    fn compose(&self, target: &mut W) -> Result<(), io::Error> {
        match *self {
            Some(value) => {
                1u8.compose(target)?;
                value.compose(target)
            }
            None => {
                0u8.compose(target)
            }
        }
    }
}

impl<R: io::Read> Parse<R> for Option<i64> {
    fn parse(source: &mut R) -> Result<Self, ParseError> {
        match u8::parse(source)? {
            0 => return Ok(None),
            1 => { },
            _ => {
                return Err(ParseError::format("illegally encoded Option<i64>"))
            }
        };
        Ok(Some(i64::parse(source)?))
    }
}


//----------- uri::Rsync -----------------------------------------------------
//
// Encoded as a u32 for the length and then that many bytes. If the length
// doesn’t fit in a u32, the encoder produces an error.

impl<W: io::Write> Compose<W> for uri::Rsync {
    fn compose(&self, target: &mut W) -> Result<(), io::Error> {
        u32::try_from(self.as_slice().len())
        .map_err(|_| ParseError::format("excessively large URI"))?
        .compose(target)?;
        target.write_all(self.as_slice())
    }
}

impl<R: io::Read> Parse<R> for uri::Rsync {
    fn parse(source: &mut R) -> Result<Self, ParseError> {
        let len = usize::try_from(u32::parse(source)?).map_err(|_| {
            ParseError::format("URI too large for this system")
        })?;
        let mut bits = vec![0u8; len];
        source.read_exact(&mut bits)?;
        Self::from_bytes(bits.into()).map_err(|err| {
            ParseError::format(format!("bad URI: {}", err))
        })
    }
}


//----------- uri::Https -----------------------------------------------------
//
// Encoded as a u32 for the length and then that many bytes. If the length
// doesn’t fit in a u32, the encoder produces an error.

impl<W: io::Write> Compose<W> for uri::Https {
    fn compose(&self, target: &mut W) -> Result<(), io::Error> {
        u32::try_from(self.as_slice().len())
        .map_err(|_| ParseError::format("excessively large URI"))?
        .compose(target)?;
        target.write_all(self.as_slice())
    }
}

impl<R: io::Read> Parse<R> for uri::Https {
    fn parse(source: &mut R) -> Result<Self, ParseError> {
        let len = usize::try_from(u32::parse(source)?).map_err(|_| {
            ParseError::format("URI too large for this system")
        })?;
        let mut bits = vec![0u8; len];
        source.read_exact(&mut bits)?;
        Self::from_bytes(bits.into()).map_err(|err| {
            ParseError::format(format!("bad URI: {}", err))
        })
    }
}


//----------- Option<uri::Https> ---------------------------------------------
//
// Encoded as a u32 for the length and then that many bytes. If the length
// doesn’t fit in a u32, the encoder produces an error.

impl<W: io::Write> Compose<W> for Option<uri::Https> {
    fn compose(&self, target: &mut W) -> Result<(), io::Error> {
        if let Some(uri) = self.as_ref() {
            u32::try_from(uri.as_slice().len())
            .map_err(|_| ParseError::format("excessively large URI"))?
            .compose(target)?;
            target.write_all(uri.as_slice())
        }
        else {
            0u32.compose(target)
        }
    }
}

impl<R: io::Read> Parse<R> for Option<uri::Https> {
    fn parse(source: &mut R) -> Result<Self, ParseError> {
        let len = u32::parse(source)?;
        if len == 0 {
            return Ok(None)
        }
        let len = usize::try_from(len).map_err(|_| {
            ParseError::format("URI too large for this system")
        })?;
        let mut bits = vec![0u8; len];
        source.read_exact(&mut bits)?;
        uri::Https::from_bytes(bits.into()).map_err(|err| {
            ParseError::format(format!("bad URI: {}", err))
        }).map(Some)
    }
}


//------------ Bytes ---------------------------------------------------------
//
// Encoded as a u64 for the length and then that many bytes. If the length
// doesn’t fit in a u64, the encoder produces an error.

impl<W: io::Write> Compose<W> for Bytes {
    fn compose(&self, target: &mut W) -> Result<(), io::Error> {
        u64::try_from(self.len())
        .map_err(|_| ParseError::format("excessively large data"))?
        .compose(target)?;
        target.write_all(self.as_ref())
    }
}

impl<R: io::Read> Parse<R> for Bytes {
    fn parse(source: &mut R) -> Result<Self, ParseError> {
        let len = usize::try_from(u64::parse(source)?).map_err(|_| {
            ParseError::format("data block too large for this system")
        })?;
        let mut bits = vec![0u8; len];
        source.read_exact(&mut bits)?;
        Ok(bits.into())
    }
}


//------------ Option<Bytes> -------------------------------------------------
//
// Encoded as a u64 for the length and then that many bytes. If the length
// doesn’t fit in a u64, the encoder produces an error.
//
// Uses u64::MAX in the length field as the marker for `None`

impl<W: io::Write> Compose<W> for Option<Bytes> {
    fn compose(&self, target: &mut W) -> Result<(), io::Error> {
        match self.as_ref() {
            Some(bytes) => bytes.compose(target),
            None => u64::MAX.compose(target)
        }
    }
}

impl<R: io::Read> Parse<R> for Option<Bytes> {
    fn parse(source: &mut R) -> Result<Self, ParseError> {
        let len = u64::parse(source)?;
        if len == u64::MAX {
            return Ok(None)
        }
        let len = usize::try_from(len).map_err(|_| {
            ParseError::format("data block large for this system")
        })?;
        let mut bits = vec![0u8; len];
        source.read_exact(&mut bits)?;
        Ok(Some(bits.into()))
    }
}


//------------ Uuid ----------------------------------------------------------

impl<W: io::Write> Compose<W> for Uuid {
    fn compose(&self, target: &mut W) -> Result<(), io::Error> {
        target.write_all(self.as_bytes())
    }
}

impl<R: io::Read> Parse<R> for Uuid {
    fn parse(source: &mut R) -> Result<Self, ParseError> {
        let mut data = uuid::Bytes::default();
        source.read_exact(&mut data)?;
        Ok(Self::from_bytes(data))
    }
}


//------------ rrdp::Hash ----------------------------------------------------

impl<W: io::Write> Compose<W> for rrdp::Hash {
    fn compose(&self, target: &mut W) -> Result<(), io::Error> {
        target.write_all(self.as_slice())
    }
}

impl<R: io::Read> Parse<R> for rrdp::Hash {
    fn parse(source: &mut R) -> Result<Self, ParseError> {
        let mut res = [0u8; 32];
        source.read_exact(&mut res)?;
        Ok(res.into())
    }
}


//------------ Serial --------------------------------------------------------

impl<W: io::Write> Compose<W> for Serial {
    fn compose(&self, target: &mut W) -> Result<(), io::Error> {
        target.write_all(&self.into_array())
    }
}

impl<R: io::Read> Parse<R> for Serial {
    fn parse(source: &mut R) -> Result<Self, ParseError> {
        let mut res = [0u8; 20];
        source.read_exact(&mut res)?;
        Self::from_array(res).map_err(|_| {
            ParseError::format("invalid X.509 serial number")
        })
    }
}


//------------ ParseError ----------------------------------------------------

#[derive(Debug)]
pub struct ParseError {
    err: io::Error,
    is_fatal: bool,
}

impl ParseError {
    /// Creates an error for bad formatting.
    pub fn format(
        err: impl Into<Box<dyn error::Error + Send + Sync>>
    ) -> Self {
        ParseError {
            err: io::Error::new(io::ErrorKind::Other, err),
            is_fatal: false,
        }
    }

    /// Returns whether parsing failed fatally.
    ///
    /// Any error other than bad formatting or early EOF is considered fatal.
    pub fn is_fatal(&self) -> bool {
        self.is_fatal
    }

    /// Returns whether the error was an unexpected EOF.
    pub fn is_eof(&self) -> bool {
        self.err.kind() == io::ErrorKind::UnexpectedEof
    }
}

impl From<io::Error> for ParseError {
    fn from(err: io::Error) -> Self {
        ParseError {
            is_fatal: err.kind() != io::ErrorKind::UnexpectedEof,
            err
        }
    }
}

impl From<ParseError> for io::Error {
    fn from(err: ParseError) -> Self {
        err.err
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.err.fmt(f)
    }
}


//============ Testing =======================================================

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;

    pub(crate) fn test_write_read<T>(t: T)
    where T: Compose<Vec<u8>> + for<'a> Parse<&'a [u8]> + Eq + std::fmt::Debug
    {
        let mut encoded = Vec::new();
        t.compose(&mut encoded).unwrap();
        let mut slice = encoded.as_slice();
        let decoded = T::parse(&mut slice).unwrap();
        assert!(slice.is_empty());
        assert_eq!(t, decoded)
    }

    #[test]
    fn write_read_u8() {
        test_write_read(0u8);
        test_write_read(127u8);
        test_write_read(255u8);
    }

    #[test]
    fn write_read_u32() {
        test_write_read(0u32);
        test_write_read(127u32);
        test_write_read(0xFFFF_FFFFu32);
    }

    #[test]
    fn write_read_u64() {
        test_write_read(0u64);
        test_write_read(127u64);
        test_write_read(0xFFFF_FFFF_FFFF_FFFFu64);
    }

    #[test]
    fn write_read_i64() {
        test_write_read(0i64);
        test_write_read(127i64);
        test_write_read(0x7FFF_FFFF_FFFF_FFFFi64);
        test_write_read(-127i64);
        test_write_read(-1i64);
    }

    #[test]
    fn write_read_opt_i64() {
        test_write_read(Some(0i64));
        test_write_read(Some(127i64));
        test_write_read(Some(0x7FFF_FFFF_FFFF_FFFFi64));
        test_write_read(Some(-127i64));
        test_write_read(Some(-1i64));
        test_write_read(None::<i64>);
    }

    #[test]
    fn write_read_uri_rsync() {
        test_write_read(
            uri::Rsync::from_str("rsync://foo.bar/bla/blubb").unwrap()
        );
    }

    #[test]
    fn write_read_uri_https() {
        test_write_read(
            uri::Https::from_str("https://foo.bar/bla/blubb").unwrap()
        );
    }

    #[test]
    fn write_read_opt_uri_https() {
        test_write_read(
            Some(uri::Https::from_str("https://foo.bar/bla/blubb").unwrap())
        );
        test_write_read(None::<uri::Https>);
    }

    #[test]
    fn write_read_bytes() {
        test_write_read(Bytes::new());
        test_write_read(Bytes::copy_from_slice(b"bla"));
    }

    #[test]
    fn write_read_opt_bytes() {
        test_write_read(Some(Bytes::new()));
        test_write_read(Some(Bytes::copy_from_slice(b"bla")));
        test_write_read(None::<Bytes>);
    }

    #[test]
    fn write_read_uuid() {
        test_write_read(Uuid::nil());
    }

    #[test]
    fn write_read_hash() {
        test_write_read(rrdp::Hash::from([7u8; 32]));
    }
}

