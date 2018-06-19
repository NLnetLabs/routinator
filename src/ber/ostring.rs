//! A BER-encoded OCTET STRING.
//!
//! This is an internal module. It’s public types are re-exportet by the
//! parent.

use std::{cmp, mem};
use bytes::{BytesMut, Bytes};
use ring::digest;
use super::content::{Content, Constructed, Mode};
use super::error::Error;
use super::length::Length;
use super::source::Source;
use super::tag::Tag;


//------------ OctetString ---------------------------------------------------

/// An OCTET STRING value.
#[derive(Clone, Debug)]
pub struct OctetString {
    bytes: Bytes,
    primitive: bool,
}

impl OctetString {
    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.value_if(Tag::OCTET_STRING, Self::take_content_from)
    }

    pub fn take_content_from<S: Source>(
        content: &mut Content<S>
    ) -> Result<Self, S::Err> {
        match *content {
            Content::Primitive(ref mut inner) => {
                if inner.mode() == Mode::Cer && inner.remaining() > 1000 {
                    xerr!(return Err(Error::Malformed.into()))
                }
                Ok(OctetString {
                    bytes: inner.take_all()?,
                    primitive: true
                })
            }
            Content::Constructed(ref mut inner) => {
                match inner.mode() {
                    Mode::Ber => Self::take_constructed_ber(inner),
                    Mode::Cer => Self::take_constructed_cer(inner),
                    Mode::Der => {
                        xerr!(Err(Error::Malformed.into()))
                    }
                }
            }
        }
    }

    /// Parses a constructed BER encoded octet string.
    ///
    /// It contains of octet string values either primitive or constructed.
    fn take_constructed_ber<S: Source>(
        constructed: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        constructed.capture(|constructed| skip_nested(constructed))
            .map(|bytes| OctetString { bytes, primitive: false })
    }

    /// Parses a constructed CER encoded octet string.
    ///
    /// The constructed form contains a sequence of primitive OCTET STRING
    /// values each except for the last one exactly 1000 octets long.
    fn take_constructed_cer<S: Source>(
        constructed: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        let mut short = false;
        constructed.capture(|con| {
            while let Some(()) = con.opt_primitive_if(Tag::OCTET_STRING,
                                                      |primitive| {
                if primitive.remaining() > 1000 {
                    xerr!(return Err(Error::Malformed.into()));
                }
                if primitive.remaining() < 1000 {
                    if short {
                        xerr!(return Err(Error::Malformed.into()));
                    }
                    short = true
                }
                primitive.skip_all()
            })? { }
            Ok(())
        }).map(|bytes| OctetString { bytes, primitive: false })
    }
}

impl OctetString {
    pub fn iter(&self) -> OctetStringIter {
        OctetStringIter {
            bytes: self.bytes.as_ref(),
            primitive: self.primitive
        }
    }

    pub fn process_segments_mut<F>(&self, mut op: F)
    where F: FnMut(&[u8]) -> bool {
        for segment in self.iter() {
            if !op(segment) {
                break
            }
        }
    }

    pub fn to_bytes(&self) -> Bytes {
        if self.primitive {
            self.bytes.clone()
        }
        else {
            let mut res = BytesMut::new();
            self.process_segments_mut(|x| { 
                res.extend_from_slice(x);
                true
            });
            res.freeze()
        }
    }

    pub fn len(&self) -> usize {
        if self.primitive {
            self.bytes.len()
        }
        else {
            let mut len = 0;
            self.process_segments_mut(|x| { len += x.len(); true });
            len
        }
    }

    pub fn as_source(&self) -> OctetStringSource {
        OctetStringSource::new(self)
    }

    pub fn sha256(&self) -> digest::Digest {
        let mut context = digest::Context::new(&digest::SHA256);
        self.process_segments_mut(|x| { context.update(x); true });
        context.finish()
    }
}

impl PartialEq for OctetString {
    fn eq(&self, other: &OctetString) -> bool {
        if self.primitive && other.primitive {
            return self.bytes == other.bytes
        }
        let mut sit = self.iter();
        let mut oit = other.iter();
        let (mut ssl, mut osl) = match (sit.next(), oit.next()) {
            (Some(ssl), Some(osl)) => (ssl, osl),
            (None, None) => return true,
            _ => return false,
        };
        loop {
            if ssl.is_empty() {
                ssl = sit.next().unwrap_or(b"");
            }
            if osl.is_empty() {
                osl = oit.next().unwrap_or(b"");
            }
            match (ssl.is_empty(), osl.is_empty()) {
                (true, true) => return true,
                (false, false) => { },
                _ => return false,
            }
            let len = cmp::min(ssl.len(), osl.len());
            if ssl[..len] != osl[..len] {
                return false
            }
            ssl = &ssl[len..];
            osl = &osl[len..];
        }
    }
}


//------------ OctetStringSource ---------------------------------------------

/// A source atop an octet string.
//
//  Assuming we have a correctly encoded octet string, its content is a
//  sequence of value headers (i.e., tag and length octets) and actual string
//  content. There’s three types of headers we could encounter: primitive
//  octet strings, constructed octet strings, and end-of-values. The first
//  one is followed by as many octets of actual content as given in the
//  length octets. The second one is followed by more values recursively and
//  the third one is by nothing. So, only the primitive values actually
//  contain content and, because however they are nested, they appear in
//  order, we can ignore all the rest.
pub struct OctetStringSource {
    /// The content of primitive value we currently work on.
    current: Bytes,

    /// The remainder of the value after the value in `current`.
    remainder: Bytes,
}

impl OctetStringSource {
    fn new(from: &OctetString) -> Self {
        if from.primitive {
            OctetStringSource {
                current: from.bytes.clone(),
                remainder: Bytes::new(),
            }
        }
        else {
            OctetStringSource {
                current: Bytes::new(),
                remainder: from.bytes.clone(),
            }
        }
    }
                
    fn next_primitive(&mut self) -> Option<Bytes> {
        while !self.remainder.is_empty() {
            let (tag, cons) = Tag::take_from(&mut self.remainder).unwrap();
            let length = Length::take_from(&mut self.remainder).unwrap();
            match tag {
                Tag::OCTET_STRING => {
                    if cons {
                        continue
                    }
                    let length = match length {
                        Length::Definite(len) => len,
                        _ => unreachable!()
                    };
                    return Some(self.remainder.split_to(length))
                }
                Tag::END_OF_VALUE => continue,
                _ => unreachable!()
            }
        }
        None
    }
}

impl Source for OctetStringSource {
    type Err = Error;

    fn request(&mut self, len: usize) -> Result<usize, Error> {
        if self.current.len() < len && !self.remainder.is_empty() {
            // Make a new current that is at least `len` long.
            let mut current = BytesMut::from(self.current.clone());
            while current.len() < len {
                if let Some(bytes) = self.next_primitive() {
                    current.extend_from_slice(bytes.as_ref())
                }
                else {
                    break
                }
            }
            self.current = current.freeze()
        }
        Ok(self.current.len())
    }

    fn advance(&mut self, mut len: usize) -> Result<(), Error> {
        while len > self.current.len() {
            len -= self.current.len();
            self.current = match self.next_primitive() {
                Some(value) => value,
                None => {
                    xerr!(return Err(Error::Malformed))
                }
            }
        }
        self.current.advance(len);
        Ok(())
    }

    fn slice(&self) -> &[u8] {
        self.current.as_ref()
    }

    fn bytes(&self, start: usize, end: usize) -> Bytes {
        self.current.slice(start, end)
    }
}


//------------ OctetStringIter -----------------------------------------------

/// An iterator over the segments of an octet string.
//
//  This is a simpler version of `OctetStringSource` that simply returns
//  byte slices.
#[derive(Copy, Clone, Debug)]
pub struct OctetStringIter<'a> {
    bytes: &'a [u8],
    primitive: bool
}

impl<'a> Iterator for OctetStringIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.primitive {
            if self.bytes.is_empty() {
                None
            }
            else {
                Some(mem::replace(&mut self.bytes, &b""[..]))
            }
        }
        else {
            while !self.bytes.is_empty() {
                let (tag, cons) = Tag::take_from(&mut self.bytes).unwrap();
                let length = Length::take_from(&mut self.bytes).unwrap();
                match tag {
                    Tag::OCTET_STRING => {
                        if cons {
                            continue
                        }
                        let length = match length {
                            Length::Definite(len) => len,
                            _ => unreachable!()
                        };
                        let res = &self.bytes[..length];
                        self.bytes = &self.bytes[length..];
                        return Some(res)
                    }
                    Tag::END_OF_VALUE => continue,
                    _ => unreachable!()
                }
            }
            None
        }
    }
}


//------------ Helper Functions ----------------------------------------------

fn skip_nested<S>(con: &mut Constructed<S>) -> Result<(), S::Err>
where S: Source {
    while let Some(()) = con.opt_value_if(Tag::OCTET_STRING, |content| {
        match content {
            Content::Constructed(ref mut inner) => {
                skip_nested(inner)?
            }
            Content::Primitive(ref mut inner) => {
                inner.skip_all()?
            }
        }
        Ok(())
    })? { }
    Ok(())
}

