use untrusted::{Input, Reader};
use super::{Error, Length, Tag};

// XXX TODO Add a flag to enforce DER encoding.

//------------ Content -------------------------------------------------------

/// BER-encoded content.
pub struct Content<'a> {
    reader: Reader<'a>,
    state: State,
}

//  # Internal Basics
impl<'a> Content<'a> {
    /// Creates a new content value from its parts.
    fn new(reader: Reader<'a>, indefinite: bool) -> Self {
        Content {
            reader,
            state: State::new(indefinite)
        }
    }

    /// Checks whether content has been completely read.
    fn complete(&mut self) -> Result<(), Error> {
        match self.state {
            State::Definite => {
                if self.reader.at_end() {
                    Ok(())
                }
                else {
                    Err(Error::Malformed)
                }
            }
            State::Indefinite => {
                let tag = Tag::parse(&mut self.reader)?;
                if tag != Tag::END_OF_VALUE {
                    return Err(Error::Malformed)
                }
                if let Length::Definite(0) = Length::parse(&mut self.reader)? {
                    Ok(())
                }
                else {
                    Err(Error::Malformed)
                }
            }
            State::Done => {
                Ok(())
            }
        }
    }

    /// Parses a tag and length from the content if there are values left.
    ///
    /// Returns `Ok(None)` if we have reached the end of content.
    fn parse_header(&mut self) -> Result<Option<(Tag, Length)>, Error> {
        match self.state {
            State::Definite => {
                if self.reader.at_end() {
                    return Ok(None)
                }
            }
            State::Done => return Ok(None),
            _ => { }
        }
        let tag = Tag::parse(&mut self.reader)?;
        let length = Length::parse(&mut self.reader)?;
        if tag == Tag::END_OF_VALUE {
            if let State::Indefinite = self.state {
                if length.is_zero() {
                    self.state = State::Done;
                    Ok(None)
                }
                else {
                    Err(Error::Malformed)
                }
            }
            else {
                Err(Error::Malformed)
            }
        }
        else {
            Ok(Some((tag, length)))
        }
    }

    /// Parses the content of a constructed value.
    fn parse_content<F, T>(
        &mut self,
        tag: Tag,
        length: Length,
        op: F
    ) -> Result<T, Error>
    where F: FnOnce(Tag, &mut Content<'a>) -> Result<T, Error> {
        match length {
            Length::Definite(len) => {
                let mut reader = Reader::new(
                    self.reader.skip_and_get_input(len)?
                );
                let mut content = Content::new(reader, false);
                let res = op(tag, &mut content)?;
                content.complete()?;
                Ok(res)
            }
            Length::Indefinite => {
                let state = self.state.swap(true);
                let res = op(tag, self)?;
                self.complete()?;
                self.state = state;
                Ok(res)
            }
        }
    }
}


/// # Basic Parsing
impl<'a> Content<'a> {
    /// Parses input as BER-encoded content.
    ///
    /// The actual parsing happens inside the closure `op` which will receive
    /// a representation of the input as encoded content.
    pub fn parse<F, T>(input: Input<'a>, op: F) -> Result<T, Error>
    where F: FnOnce(&mut Content<'a>) -> Result<T, Error> {
        let mut content = Content::new(Reader::new(input), false);
        let res = op(&mut content)?;
        content.complete()?;
        Ok(res)
    }

    /// Parses a byte slice as BER-encoded content.
    pub fn parse_slice<F, T>(slice: &'a [u8], op: F) -> Result<T, Error>
    where F: FnOnce(&mut Content<'a>) -> Result<T, Error> {
        Self::parse(Input::from(slice), op)
    }

    /// Parses a mandatory constructed value from the beginning of content.
    ///
    /// A constructed value is a value that in turn consists of values. Which
    /// values these are is described via an ASN.1 specification.
    ///
    /// This method expects there to be at least one more value in the
    /// content. It fails with `Err(Error::Malformed)` if the content has
    /// reached its end.
    ///
    /// The closure `op` will receive both the value’s tag and its content
    /// for futher processing. It must process all the content. If there is
    /// anything left after the closure returns successfully, this will
    /// result in an `Err(Error::Malformed)`.
    pub fn constructed<F, T>(&mut self, op: F) -> Result<T, Error>
    where F: FnOnce(Tag, &mut Content<'a>) -> Result<T, Error> {
        let (tag, length) = match self.parse_header()? {
            Some(some) => some,
            None => return Err(Error::Malformed)
        };
        if tag.is_primitive() {
            return Err(Error::Malformed)
        }
        self.parse_content(tag, length, op)
    }

    /// Parses a mandatory constructed value if it has the right tag.
    pub fn constructed_if<F, T>(
        &mut self, expected: Tag, op: F
    ) -> Result<T, Error>
    where F: FnOnce(&mut Content<'a>) -> Result<T, Error> {
        self.constructed(|tag, content| {
            if tag == expected { op(content) }
            else { Err(Error::Malformed) }
        })
    }

    /// Parses an optional constructed value from the beginning of content.
    ///
    /// This is similar to `constructed` but returns `Ok(None)` if there are
    /// no values left in the content.
    pub fn opt_constructed<F, T>(&mut self, op: F) -> Result<Option<T>, Error>
    where F: FnOnce(Tag, &mut Content<'a>) -> Result<T, Error> {
        let (tag, length) = match self.parse_header()? {
            Some(some) => some,
            None => return Ok(None)
        };
        self.parse_content(tag, length, op).map(Some)
    }

    /// Parses an optional constructed value if the tag matches.
    ///
    /// This will return `Ok(None)` both if there are no more values left or
    /// if the tag of the next value does not match the given tag.
    pub fn opt_constructed_if<F, T>(
        &mut self, expected: Tag, op: F
    ) -> Result<Option<T>, Error>
    where F: FnOnce(&mut Content<'a>) ->Result<T, Error> {
        if !expected.peek(&self.reader) {
            return Ok(None)
        }
        self.opt_constructed(|_, content| op(content))
    }

    /// Parses a mandatory primitive value from the beginning of content.
    ///
    /// A primitive value is one that actually contains some encoded data.
    /// This data will be passed together with the tag to the closure `op`.
    pub fn primitive<F, T>(&mut self, op: F) -> Result<T, Error>
    where F: FnOnce(Tag, Input<'a>) -> Result<T, Error> {
        let (tag, length) = match self.parse_header()? {
            Some(some) => some,
            None => return Err(Error::Malformed)
        };
        if !tag.is_primitive() {
            return Err(Error::Malformed)
        }
        let length = match length {
            Length::Definite(len) => len,
            Length::Indefinite => return Err(Error::Malformed)
        };
        op(tag, self.reader.skip_and_get_input(length)?)
    }

    /// Parses a primitive value if the tag matches.
    ///
    /// If a different tag is encountered, the method will return an error.
    pub fn primitive_if<F, T>(
        &mut self, expected: Tag, op: F
    ) -> Result<T, Error>
    where F: FnOnce(Input<'a>) -> Result<T, Error> {
        self.primitive(|tag, input| {
            if tag == expected {
                op(input)
            }
            else {
                xdebug!("primitive_if: expected {:?}, got {:?}", expected, tag);
                Err(Error::Malformed)
            }
        })
    }

    /// Parses an optional primitive value from the beginning of content.
    ///
    /// This method is similar to `primitive` but it won’t fail if there
    /// are no more values left.
    pub fn opt_primitive<F, T>(&mut self, op: F) -> Result<Option<T>, Error>
    where F: FnOnce(Tag, Input<'a>) -> Result<T, Error> {
        let (tag, length) = match self.parse_header()? {
            Some(some) => some,
            None => return Ok(None)
        };
        if !tag.is_primitive() {
            return Err(Error::Malformed)
        }
        let length = match length {
            Length::Definite(len) => len,
            Length::Indefinite => return Err(Error::Malformed)
        };
        op(tag, self.reader.skip_and_get_input(length)?).map(Some)
    }

    /// Parses an optional primitive value if the tag matches.
    ///
    /// The method returns `Ok(None)` both if the end of content is reached
    /// or if there is a value with a different tag.
    pub fn opt_primitive_if<F, T>(
        &mut self, expected: Tag, op: F
    ) -> Result<Option<T>, Error>
    where F: FnOnce(Input<'a>) -> Result<T, Error> {
        if !expected.peek(&self.reader) {
            return Ok(None)
        }
        self.opt_primitive(|_, input| op(input))
    }

    /// Parses the remaining content into input.
    pub fn into_input(&mut self) -> Result<Input<'a>, Error> {
        let start = self.reader.mark();
        self.skip_all()?;
        let end = self.reader.mark();
        Ok(self.reader.get_input_between_marks(start, end)?)
    }

    /// Returns the next value as input.
    ///
    /// The returned input will include tag and length of the value.
    pub fn value_as_input(&mut self) -> Result<Input<'a>, Error> {
        let start = self.reader.mark();
        self.skip()?;
        let end = self.reader.mark();
        Ok(self.reader.get_input_between_marks(start, end)?)
    }

    /// Skips over the remaining content.
    pub fn skip_all(&mut self) -> Result<(), Error> {
        while let Some(()) = self.opt_skip()? { }
        Ok(())
    }

    /// Skips over the next value.
    pub fn skip(&mut self) -> Result<(), Error> {
        match self.opt_skip()? {
            Some(()) => Ok(()),
            None => Err(Error::Malformed)
        }
    }

    /// Skips over the next value, if there is one.
    pub fn opt_skip(&mut self) -> Result<Option<()>, Error> {
        let (tag, length) = match self.parse_header()? {
            Some(some) => some,
            None => return Ok(None)
        };
        match length {
            Length::Definite(len) => {
                self.reader.skip(len)?;
                Ok(Some(()))
            }
            Length::Indefinite => {
                if tag.is_primitive() {
                    return Err(Error::Malformed)
                }
                self.parse_content(tag, length, |_, content| {
                    content.skip_all()
                }).map(Some)
            }
        }
    }

    /// Parses anything that is coming up.
    pub fn any<F, T>(&mut self, op: F) -> Result<Option<T>, Error>
    where
        F: FnOnce(
            Tag, Length, Option<&mut Content<'a>>
        ) -> Result<T, Error>
    {
        let (tag, length) = match self.parse_header()? {
            Some(some) => some,
            None => return Ok(None)
        };
        if tag.is_primitive() {
            if let Length::Definite(len) = length { 
                self.reader.skip(len)?;
                op(tag, length, None).map(Some)
            }
            else {
                Err(Error::Malformed)
            }
        }
        else {
            self.parse_content(tag, length, |tag, content| {
                op(tag, length, Some(content))
            }).map(Some)
        }
    }

    pub fn recursive_input<F>(
        &mut self, op: &mut F
    ) -> Result<Input<'a>, Error>
    where F: FnMut(Tag, Option<Input<'a>>) -> Result<(), Error> {
        let start = self.reader.mark();
        if self.opt_recursive_input(op)?.is_none() {
            return Err(Error::Malformed)
        }
        let end = self.reader.mark();
        self.reader.get_input_between_marks(start, end).map_err(Into::into)
    }

    pub fn opt_recursive_input<F>(
        &mut self, op: &mut F
    ) -> Result<Option<()>, Error>
    where F: FnMut(Tag, Option<Input<'a>>) -> Result<(), Error> {
        let (tag, length) = match self.parse_header()? {
            Some(some) => some,
            None => return Ok(None)
        };
        if tag.is_primitive() {
            if let Length::Definite(len) = length { 
                op(tag, Some(self.reader.skip_and_get_input(len)?)).map(Some)
            }
            else {
                Err(Error::Malformed)
            }
        }
        else {
            self.parse_content(tag, length, |tag, content| {
                op(tag, None)?;
                while let Some(()) = content.opt_recursive_input(op)? { }
                Ok(())
            }).map(Some)
        }
    }
}


/// # High-level Parsing
impl<'a> Content<'a> {
    //--- BOOLEAN

    pub fn parse_bool(&mut self) -> Result<bool, Error> {
        self.primitive_if(Tag::BOOLEAN, |input| {
            input.read_all(Error::Malformed, |reader| {
                // DER: for true, value must be 0xFF.
                Ok(reader.read_byte()? != 0)
            })
        })
    }

    pub fn parse_opt_bool(&mut self) -> Result<Option<bool>, Error> {
        self.opt_primitive_if(Tag::BOOLEAN, |input| {
            input.read_all(Error::Malformed, |reader| {
                // DER: for true, value must be 0xFF.
                Ok(reader.read_byte()? != 0)
            })
        })
    }


    //--- INTEGER

    pub fn parse_u8(&mut self) -> Result<u8, Error> {
        self.primitive_if(Tag::INTEGER, |input| {
            input.read_all(Error::Malformed, |reader| {
                let res = reader.read_byte()?;
                if res & 0x80 != 0 {
                    Err(Error::Malformed)
                }
                else {
                    Ok(res)
                }
            })
        })
    }

    pub fn parse_u32(&mut self) -> Result<u32, Error> {
        self.primitive_if(Tag::INTEGER, |input| {
            input.read_all(Error::Malformed, |reader| {
                let mut res = reader.read_byte()? as u32;
                if res & 0x80 != 0 {
                    return Err(Error::Malformed)
                }
                for _ in 1..4 {
                    if reader.at_end() {
                        return Ok(res)
                    }
                    res = (res << 8)
                        | (reader.read_byte()? as u32);
                }
                Err(Error::Malformed)
            })
        })
    }

    pub fn parse_u64(&mut self) -> Result<u64, Error> {
        self.primitive_if(Tag::INTEGER, |input| {
            input.read_all(Error::Malformed, |reader| {
                let mut res = reader.read_byte()? as u64;
                if res & 0x80 != 0 {
                    return Err(Error::Malformed)
                }
                for _ in 1..8 {
                    if reader.at_end() {
                        return Ok(res)
                    }
                    res = (res << 8)
                        | (reader.read_byte()? as u64);
                }
                Err(Error::Malformed)
            })
        })
    }

    pub fn skip_u8_if(&mut self, value: u8) -> Result<(), Error> {
        if self.parse_u8()? == value { Ok(()) }
        else { Err(Error::Malformed) }
    }


    //--- BIT STRING

    /// Parses a BIT STRING.
    pub fn bit_string(&mut self) -> Result<(u8, Input<'a>), Error> {
        self.primitive_if(Tag::BIT_STRING, |input| {
            input.read_all(Error::Malformed, |reader| {
                Ok((
                   reader.read_byte()?,
                   reader.skip_to_end()
                ))
            })
        })
    }

    /// Parses a BIT STRING with no unused bits.
    pub fn filled_bit_string(&mut self) -> Result<Input<'a>, Error> {
        self.primitive_if(Tag::BIT_STRING, |input| {
            input.read_all(Error::Malformed, |reader| {
                if reader.read_byte()? != 0 {
                    return Err(Error::Malformed)
                }
                Ok(reader.skip_to_end())
            })
        })
    }

    pub fn opt_filled_bit_string_if(
        &mut self, expected: Tag
    ) -> Result<Option<Input<'a>>, Error> {
        self.opt_primitive_if(expected, |input| {
            input.read_all(Error::Malformed, |reader| {
                if reader.read_byte()? != 0 {
                    return Err(Error::Malformed)
                }
                Ok(reader.skip_to_end())
            })
        })
    }

    //--- OCTET STRING

    pub fn octet_string(&mut self) -> Result<Input<'a>, Error> {
        self.primitive_if(Tag::OCTET_STRING, Ok)
    }

    pub fn octet_string_if(
        &mut self, expected: Tag
    ) -> Result<Input<'a>, Error> {
        self.primitive_if(expected, Ok)
    }

    //--- NULL

    pub fn skip_opt_null(&mut self) -> Result<(), Error> {
        self.opt_primitive_if(Tag::NULL, |_| Ok(())).map(|_| ())
    }

    //--- SEQUENCE

    pub fn sequence<F, T>(&mut self, op: F) -> Result<T, Error>
    where F: FnOnce(&mut Content<'a>) -> Result<T, Error> {
        self.constructed_if(Tag::SEQUENCE, op)
    }

    pub fn opt_sequence<F, T>(&mut self, op: F) -> Result<Option<T>, Error>
    where F: FnOnce(&mut Content<'a>) -> Result<T, Error> {
        self.opt_constructed_if(Tag::SEQUENCE, op)
    }

    //--- SET
    
    pub fn set<F, T>(&mut self, op: F) -> Result<T, Error>
    where F: FnOnce(&mut Content<'a>) -> Result<T, Error> {
        self.constructed_if(Tag::SET, op)
    }
}


//------------ State ---------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum State {
    /// We are reading until the end of the reader.
    Definite,

    /// Indefinite value, we haven’t reached the end yet.
    Indefinite,

    /// End of value reached.
    Done
}

impl State {
    fn new(indefinite: bool) -> Self {
        if indefinite { State::Indefinite }
        else { State::Definite }
    }

    fn swap(&mut self, indefinite: bool) -> Self {
        let res = *self;
        *self = Self::new(indefinite);
        res
    }
}

