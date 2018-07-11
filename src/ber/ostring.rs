//! A BER-encoded OCTET STRING.
//!
//! This is an internal module. It’s public types are re-exported by the
//! parent.

use std::{cmp, hash, mem};
use bytes::{BytesMut, Bytes};
use ring::digest;
use super::content::{Content, Constructed, Mode};
use super::error::Error;
use super::length::Length;
use super::source::Source;
use super::tag::Tag;


//------------ OctetString ---------------------------------------------------

/// An OCTET STRING value.
///
/// An octet string is a sequence of octets, i.e., a glorified `[u8]`. Basic
/// Encoding Rules, however, allow this sequence to be broken up into chunks
/// that are encoded separatedly to allow for very large octet strings and
/// cases where one doesn’t yet know the length of the string.
///
/// In order to avoid unnecessary allocations, this type wraps the raw content
/// octets of a BER encoded octet string. As a consequence, assembling the
/// complete string may actually be costly and should only be done if really
/// necessary. As an alternative, there is an iterator over the parts via the
/// `iter` method or the `IntoIterator` trait as well as an iterator over the
/// individual octets via the `octets` method.
/// 
/// Octet strings are sometimes used to store BER encoded data. The
/// `OctetStringSource` type, accessible via the `to_source` method, provides
/// an implementation of the `Source` trait to run a decoder on.
///
/// # BER Encoding
///
/// Octet strings are either encoded as a primitive or a constructed value.
/// In the primitive form, the content octets are the string’s octets. In a
/// constructed form, the content is a sequence of encoded octets strings
/// which in turn may be primitive or constructed. In this case, the string’s
/// octets are the concatenation of all the content octets of the primitive
/// forms in the order as encountered.
///
/// In CER, the string must use the primitive form if it is less than 1000
/// octets long and the constructed form otherwise. The constructed form must
/// consists of a sequence of primitive values each exactly with a 1000
/// octets of content except for the last one.
///
/// In DER, only the primitive form is allowed.
#[derive(Clone, Debug)]
pub struct OctetString {
    /// The content octets of the octet string value.
    bytes: Bytes,

    /// Whether the primitive or constructed form was used.
    primitive: bool,
}

/// # Parsing of BER Encoded Octet Strings
///
impl OctetString {
    /// Takes a single octet string value from constructed value content.
    ///
    /// If there is no next value, if the next value does not have the tag
    /// `Tag::OCTET_STRING`, or if it doesn’t contain a correctly encoded
    /// octet string, a malformed error is returned.
    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_value_if(Tag::OCTET_STRING, Self::take_content_from)
    }

    /// Takes an octet string value from content.
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
    /// It consists octet string values either primitive or constructed.
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
            while let Some(()) = con.take_opt_primitive_if(Tag::OCTET_STRING,
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

/// # Content Access
///
impl OctetString {
    /// Returns an iterator over the parts of the octet string.
    ///
    /// The iterator will produce `&[u8]` which, when appended produce the
    /// complete content of the octet string.
    pub fn iter(&self) -> OctetStringIter {
        OctetStringIter {
            bytes: self.bytes.as_ref(),
            primitive: self.primitive
        }
    }

    /// Returns an iterator over the individual octets of the string.
    pub fn octets(&self) -> OctetStringOctets {
        OctetStringOctets::new(self.iter())
    }

    /// Returns a reference to the complete content if possible.
    ///
    /// The method will return a bytes slice of the content if the octet
    /// string was encoded as a single primitive value or `None` otherwise.
    ///
    /// This is guaranteed to return some slice if the value was produced by
    /// decoding in DER mode.
    pub fn as_slice(&self) -> Option<&[u8]> {
        if self.primitive {
            Some(self.bytes.as_ref())
        }
        else {
            None
        }
    }

    /// Produces a bytes value with the string’s content.
    ///
    /// If the octet string was encoded as a single primitive value, the
    /// method will simply clone the contnent. Otherwise it will produce
    /// an entirely new bytes value from the concatenated content of all
    /// the primitive values.
    pub fn to_bytes(&self) -> Bytes {
        if self.primitive {
            self.bytes.clone()
        }
        else {
            let mut res = BytesMut::new();
            self.iter().for_each(|x| res.extend_from_slice(x));
            res.freeze()
        }
    }

    /// Returns the length of the content.
    ///
    /// This is _not_ the length of the encoded value but of the actual
    /// octet string.
    pub fn len(&self) -> usize {
        if self.primitive {
            self.bytes.len()
        }
        else {
            self.iter().fold(0, |len, x| len + x.len())
        }
    }

    /// Creates a source that can be used to decode the string’s content.
    ///
    /// The returned value contains a clone of the string (which, because of
    /// the use of `Bytes` is rather cheap) that implements the `Source`
    /// trait and thus can be used to decode the string’s content.
    pub fn to_source(&self) -> OctetStringSource {
        OctetStringSource::new(self)
    }

    /// Calculates the SHA256 hash of the content.
    pub fn sha256(&self) -> digest::Digest {
        let mut context = digest::Context::new(&digest::SHA256);
        self.iter().for_each(|x| context.update(x));
        context.finish()
    }
}


//--- PartialEq and Eq

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

impl<T: AsRef<[u8]>> PartialEq<T> for OctetString {
    fn eq(&self, other: &T) -> bool {
        let mut other = other.as_ref();

        if self.primitive {
            return self.bytes.as_ref() == other
        }

        for part in self.iter() {
            if part.len() > other.len() {
                return false
            }
            if part.len() == other.len() {
                return part == other
            }
            if part != &other[..part.len()] {
                return false
            }
            other = &other[part.len()..]
        }
        return false
    }
}

impl Eq for OctetString { }


//--- PartialOrd and Ord

impl PartialOrd for OctetString {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: AsRef<[u8]>> PartialOrd<T> for OctetString {
    fn partial_cmp(&self, other: &T) -> Option<cmp::Ordering> {
        let mut other = other.as_ref();

        if self.primitive {
            return self.bytes.partial_cmp(other)
        }

        for part in self.iter() {
            if part.len() >= other.len() {
                return Some(part.cmp(other))
            }
            match part.cmp(&other[..part.len()]) {
                cmp::Ordering::Equal => { }
                other => return Some(other)
            }
            other = &other[part.len()..]
        }
        return Some(cmp::Ordering::Less)
    }
}

impl Ord for OctetString {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        if self.primitive && other.primitive {
            return self.bytes.cmp(&other.bytes)
        }

        let mut siter = self.iter();
        let mut oiter = other.iter();
        let mut spart = b"".as_ref();
        let mut opart = b"".as_ref();

        loop {
            if spart.is_empty() {
                spart = siter.next().unwrap_or(b"");
            }
            if opart.is_empty() {
                opart = oiter.next().unwrap_or(b"");
            }
            match (spart.is_empty(), opart.is_empty()) {
                (true, true) => return cmp::Ordering::Equal,
                (true, false) => return cmp::Ordering::Less,
                (false, true) => return cmp::Ordering::Greater,
                (false, false) => { },
            }
            let len = cmp::min(spart.len(), opart.len());
            match spart[..len].cmp(&opart[..len]) {
                cmp::Ordering::Equal => { }
                other => return other
            }
            spart = &spart[len..];
            opart = &opart[len..];
        }
    }
}


//--- Hash

impl hash::Hash for OctetString {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        for part in self.iter() {
            part.hash(state)
        }
    }
}


//--- IntoIterator

impl<'a> IntoIterator for &'a OctetString {
    type Item = &'a [u8];
    type IntoIter = OctetStringIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}


//------------ OctetStringSource ---------------------------------------------

/// A source atop an octet string.
///
/// You can get a value of this type by calling `OctetString::source`.
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
            let length = Length::take_from(
                &mut self.remainder, Mode::Ber
            ).unwrap();
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
///
/// You can get a value of this type by calling `OctetString::iter` or relying
/// on the `IntoIterator` impl for a `&OctetString`.
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
                let length = Length::take_from(
                    &mut self.bytes, Mode::Ber
                ).unwrap();
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


//------------ OctetStringOctets ---------------------------------------------

/// An iterator over the octets in an octet string.
///
/// You can get a value of this type by calling `OctetString::octets`.
pub struct OctetStringOctets<'a> {
    cur: &'a [u8],
    iter: OctetStringIter<'a>,
}

impl<'a> OctetStringOctets<'a> {
    fn new(iter: OctetStringIter<'a>) -> Self {
        OctetStringOctets {
            cur: b"",
            iter: iter
        }
    }
}

impl<'a> Iterator for OctetStringOctets<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        if self.cur.is_empty() {
            let next = match self.iter.next() {
                Some(some) => some,
                None => return None,
            };
            self.cur = next;
        }
        let res = self.cur[0];
        self.cur = &self.cur[1..];
        Some(res)
    }
}


//------------ Helper Functions ----------------------------------------------

fn skip_nested<S>(con: &mut Constructed<S>) -> Result<(), S::Err>
where S: Source {
    while let Some(()) = con.take_opt_value_if(Tag::OCTET_STRING, |content| {
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

