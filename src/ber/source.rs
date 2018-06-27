
use std::mem;
use std::cmp::min;
use bytes::Bytes;
use super::error::Error;


//------------ Source --------------------------------------------------------

/// A Source is a view into a sequence of octets.
///
/// It can only progress forward over time. It provides the ability to access
/// the next few bytes as a slice, advance forward, or advance forward
/// returning a Bytes value of the data it advanced over.
pub trait Source {
    /// The error produced by the source.
    ///
    /// The type used here needs to wrap `ber::Error` and extends it by
    /// whatever happens if acquiring additional data fails.
    type Err: From<Error>;

    /// Request at least `len` bytes to be available.
    ///
    /// The method returns the number of bytes that are actually available.
    /// This may only be smaller than `len` if the source ends with less
    /// bytes available.
    ///
    /// The method should only return an error if the source somehow fails
    /// to get more data such as an IO error or reset connection.
    fn request(&mut self, len: usize) -> Result<usize, Self::Err>;

    /// Advance the source by `len` bytes.
    ///
    /// The method advances the start of the view provided by the source by
    /// `len` bytes. Advancing beyond the end of a source is an error.
    /// Implementations should return their equivalient of `Error::Malformed`.
    ///
    /// The value of `len` may be larger than the last length previously
    /// request via `request`.
    fn advance(&mut self, len: usize) -> Result<(), Self::Err>;

    /// Returns a bytes slice with the available data.
    ///
    /// The slice will be at least as long the value returned by the last
    /// successful `request` call. It may be longer if more data is
    /// available.
    fn slice(&self) -> &[u8];

    /// Produces a `Bytes` value from part of the data.
    ///
    /// The method returns a `Bytes` value of the range `start..end` from
    /// the beginning of the current view of the source. Both indexes must
    /// not be greater than the value returned by the last successful call
    /// to `request`.
    ///
    /// # Panics
    ///
    /// The method panics if `start` or `end` are larger than the last
    /// successful call to `request`.
    fn bytes(&self, start: usize, end: usize) -> Bytes;

    //--- Advanced access

    fn take_u8(&mut self) -> Result<u8, Self::Err> {
        if self.request(1)? < 1 {
            xerr!(return Err(Error::Malformed.into()))
        }
        let res = self.slice()[0];
        self.advance(1)?;
        Ok(res)
    }

    fn take_opt_u8(&mut self) -> Result<Option<u8>, Self::Err> {
        if self.request(1)? < 1 {
            return Ok(None)
        }
        let res = self.slice()[0];
        self.advance(1)?;
        Ok(Some(res))
    }
}

impl Source for Bytes {
    type Err = Error;

    fn request(&mut self, _len: usize) -> Result<usize, Self::Err> {
        Ok(self.len())
    }

    fn advance(&mut self, len: usize) -> Result<(), Self::Err> {
        if len > self.len() {
            Err(Error::Malformed)
        }
        else {
            self.advance(len);
            Ok(())
        }
    }

    fn slice(&self) -> &[u8] {
        self.as_ref()
    }

    fn bytes(&self, start: usize, end: usize) -> Bytes {
        self.slice(start, end)
    }
}

impl<'a> Source for &'a [u8] {
    type Err = Error;

    fn request(&mut self, _len: usize) -> Result<usize, Self::Err> {
        Ok(self.len())
    }

    fn advance(&mut self, len: usize) -> Result<(), Self::Err> {
        if len > self.len() {
            Err(Error::Malformed)
        }
        else {
            *self = &self[len..];
            Ok(())
        }
    }

    fn slice(&self) -> &[u8] {
        self
    }

    fn bytes(&self, start: usize, end: usize) -> Bytes {
        Bytes::from(&self[start..end])
    }
}

impl<'a, T: Source> Source for &'a mut T {
    type Err = T::Err;

    fn request(&mut self, len: usize) -> Result<usize, Self::Err> {
        Source::request(*self, len)
    }
    
    fn advance(&mut self, len: usize) -> Result<(), Self::Err> {
        Source::advance(*self, len)
    }

    fn slice(&self) -> &[u8] {
        Source::slice(*self)
    }

    fn bytes(&self, start: usize, end: usize) -> Bytes {
        Source::bytes(*self, start, end)
    }
}


//------------ LimitedSource -------------------------------------------------

#[derive(Debug)]
pub struct LimitedSource<S> {
    source: S,
    limit: Option<usize>,
}

impl<S> LimitedSource<S> {
    pub fn new(source: S) -> Self {
        LimitedSource {
            source,
            limit: None
        }
    }

    pub fn unwrap(self) -> S {
        self.source
    }

    pub fn limit(&self) -> Option<usize> {
        self.limit
    }

    pub fn limit_further(&mut self, limit: Option<usize>) -> Option<usize> {
        if let Some(cur) = self.limit {
            match limit {
                Some(limit) => assert!(limit <= cur),
                None => panic!("relimiting to unlimited"),
            }
        }
        mem::replace(&mut self.limit, limit)
    }

    pub fn set_limit(&mut self, limit: Option<usize>) {
        self.limit = limit
    }
}

impl<S: Source> LimitedSource<S> {
    pub fn skip_all(&mut self) -> Result<(), S::Err> {
        let limit = self.limit.unwrap();
        self.advance(limit)
    }

    pub fn take_all(&mut self) -> Result<Bytes, S::Err> {
        let limit = self.limit.unwrap();
        if self.request(limit)? < limit {
            return Err(Error::Malformed.into())
        }
        let res = self.bytes(0, limit);
        self.advance(limit)?;
        Ok(res)
    }

    pub fn exhausted(&mut self) -> Result<(), S::Err> {
        match self.limit {
            Some(0) => Ok(()),
            Some(_limit) => {
                xerr!(Err(Error::Malformed.into()))
            }
            None => {
                if self.source.request(1)? == 0 {
                    Ok(())
                }
                else {
                    xerr!(Err(Error::Malformed.into()))
                }
            }
        }
    }
}

impl<S: Source> Source for LimitedSource<S> {
    type Err = S::Err;

    fn request(&mut self, len: usize) -> Result<usize, Self::Err> {
        if let Some(limit) = self.limit {
            Ok(min(limit, self.source.request(min(limit, len))?))
        }
        else {
            self.source.request(len)
        }
    }

    fn advance(&mut self, len: usize) -> Result<(), Self::Err> {
        if let Some(limit) = self.limit {
            if len > limit {
                xerr!(return Err(Error::Malformed.into()))
            }
            self.limit = Some(limit - len);
        }
        self.source.advance(len)
    }

    fn slice(&self) -> &[u8] {
        let res = self.source.slice();
        if let Some(limit) = self.limit {
            if res.len() > limit {
                return &res[..limit]
            }
        }
        res
    }

    fn bytes(&self, start: usize, end: usize) -> Bytes {
        if let Some(limit) = self.limit {
            assert!(start <= limit);
            assert!(end <= limit);
        }
        self.source.bytes(start, end)
    }
}


//------------ CaptureSource -------------------------------------------------

pub struct CaptureSource<'a, S: 'a> {
    source: &'a mut S,
    pos: usize,
}

impl<'a, S: Source> CaptureSource<'a, S> {
    pub fn new(source: &'a mut S) -> Self {
        CaptureSource {
            source,
            pos: 0
        }
    }

    pub fn into_bytes(self) -> Bytes {
        let res = self.source.bytes(0, self.pos);
        self.skip();
        res
    }

    pub fn skip(self) {
        if let Err(_) = self.source.advance(self.pos) {
            panic!("failed to advance capture source");
        }
    }
}

impl<'a, S: Source + 'a> Source for CaptureSource<'a, S> {
    type Err = S::Err;

    fn request(&mut self, len: usize) -> Result<usize, Self::Err> {
        self.source.request(self.pos + len).map(|res| res - self.pos)
    }

    fn advance(&mut self, len: usize) -> Result<(), Self::Err> {
        if self.request(len)? < len {
            return Err(Error::Malformed.into())
        }
        self.pos += len;
        Ok(())
    }

    fn slice(&self) -> &[u8] {
        &self.source.slice()[self.pos..]
    }

    fn bytes(&self, start: usize, end: usize) -> Bytes {
        self.source.bytes(start + self.pos, end + self.pos)
    }
}

