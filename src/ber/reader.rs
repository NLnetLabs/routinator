
use untrusted::{Input, Reader};
use super::{Error, Length, Tag};

pub trait ReaderExt<'a> {
    //--- Basic parsing
    //
    fn parse_primitive<F, T>(&mut self, op: F) -> Result<T, Error>
    where F: FnOnce(Tag, Input<'a>) -> Result<T, Error>;

    fn parse_primitive_if<F, T>(
        &mut self, expected: Tag, op: F
    ) -> Result<T, Error>
    where F: FnOnce(Input<'a>) -> Result<T, Error> {
        self.parse_primitive(|tag, input| {
            if tag == expected {
                op(input)
            }
            else {
                Err(Error::Malformed)
            }
        })
    }

    fn parse<F, T>(&mut self, op: F) -> Result<T, Error>
    where F: FnOnce(Tag, &mut Self) -> Result<T, Error>;

    fn parse_if<F, T>(&mut self, expected: Tag, op: F) -> Result<T, Error>
    where F: FnOnce(&mut Self) -> Result<T, Error> {
        self.parse(|tag, reader| {
            if tag != expected {
                Err(Error::Malformed)
            }
            else {
                op(reader)
            }
        })
    }

    fn parse_of<F>(&mut self, tag: Tag, op: F) -> Result<(), Error>
    where F: FnMut(&mut Self) -> Result<(), Error>;

    fn parse_optional<F, T>(
        &mut self, tag: Tag, op: F
    ) -> Result<Option<T>, Error>
    where F: FnMut(&mut Self) -> Result<T, Error>;

    fn parse_content(&mut self) -> Result<Input<'a>, Error>;

    fn parse_constructed(&mut self, tag: Tag) -> Result<Input<'a>, Error> {
        self.parse_if(tag, |reader| reader.parse_content())
    }

    //--- Specific parsing
    //
    fn parse_u8(&mut self) -> Result<u8, Error> {
        self.parse_primitive_if(Tag::INTEGER, |input| {
            input.read_all(Error::Malformed, |reader| {
                reader.read_byte().map_err(|_| Error::Malformed)
            })
        })
    }

    fn skip_u8_if(&mut self, value: u8) -> Result<(), Error> {
        if self.parse_u8()? == value {
            Ok(())
        }
        else {
            Err(Error::Malformed)
        }
    }

    fn parse_u32(&mut self) -> Result<u32, Error> {
        self.parse_primitive_if(Tag::INTEGER, |input| {
            input.read_all(Error::Malformed, |reader| {
                Ok((reader.read_byte()? as u32) << 24 |
                   (reader.read_byte()? as u32) << 16 |
                   (reader.read_byte()? as u32) << 8 |
                   (reader.read_byte()? as u32))
            })
        })
    }

    fn parse_null(&mut self) -> Result<(), Error> {
        self.parse_primitive_if(Tag::NULL, |_| Ok(()))
    }

    fn parse_optional_null(&mut self) -> Result<Option<()>, Error> {
        self.parse_optional(Tag::NULL, |_| Ok(()))
    }

    fn parse_sequence<F, T>(&mut self, op: F) -> Result<T, Error>
    where F: FnOnce(&mut Self) -> Result<T, Error> {
        self.parse_if(Tag::SEQUENCE, op)
    }

    fn parse_sequence_of<F>(&mut self, op: F) -> Result<(), Error>
    where F: FnMut(&mut Self) -> Result<(), Error> {
        self.parse_of(Tag::SEQUENCE, op)
    }

    fn parse_set<F, T>(&mut self, op: F) -> Result<T, Error>
    where F: FnOnce(&mut Self) -> Result<T, Error> {
        self.parse_if(Tag::SET, op)
    }

    fn parse_set_of<F>(&mut self, op: F) -> Result<(), Error>
    where F: FnMut(&mut Self) -> Result<(), Error> {
        self.parse_of(Tag::SET, op)
    }
}

impl<'a> ReaderExt<'a> for Reader<'a> {
    fn parse_primitive<F, T>(&mut self, op: F) -> Result<T, Error>
    where F: FnOnce(Tag, Input<'a>) -> Result<T, Error> {
        let tag = Tag::parse(self)?;
        let len = match Length::parse(self)? {
            Length::Definite(len) => len,
            Length::Indefinite => return Err(Error::Malformed)
        };
        op(tag, self.skip_and_get_input(len)?)
    }

    fn parse<F, T>(&mut self, op: F) -> Result<T, Error>
    where F: FnOnce(Tag, &mut Self) -> Result<T, Error> {
        let tag = Tag::parse(self)?;
        match Length::parse(self)? {
            Length::Definite(len) => {
                println!("Definite {}", len);
                let mut reader = Reader::new(self.skip_and_get_input(len)?);
                let res = op(tag, &mut reader)?;
                if !reader.at_end() {
                    Err(Error::Malformed)
                }
                else {
                    Ok(res)
                }
            }
            Length::Indefinite => {
                if tag.is_primitive() {   
                    return Err(Error::Malformed)
                }
                let res = op(tag, self)?;
                if self.read_byte()? == 0 && self.read_byte()? == 0 {
                    Ok(res)
                }
                else {
                    Err(Error::Malformed)
                }
            }
        }
    }

    fn parse_of<F>(&mut self, expected: Tag, mut op: F) -> Result<(), Error>
    where F: FnMut(&mut Self) -> Result<(), Error> {
        let tag = Tag::parse(self)?;
        if tag != expected {
            return Err(Error::Malformed)
        }
        match Length::parse(self)? {
            Length::Definite(len) => {
                let mut reader = Reader::new(self.skip_and_get_input(len)?);
                while !reader.at_end() {
                    op(&mut reader)?;
                }
                Ok(())
            }
            Length::Indefinite => {
                while !self.peek(0) {
                    op(self)?;
                }
                if self.read_byte()? == 0 && self.read_byte()? == 0 {
                    Ok(())
                }
                else {
                    Err(Error::Malformed)
                }
            }
        }
    }

    fn parse_optional<F, T>(
        &mut self, expected: Tag, op: F
    ) -> Result<Option<T>, Error>
    where F: FnMut(&mut Self) -> Result<T, Error> {
        if !expected.peek(self) {
            return Ok(None)
        }
        self.parse_if(expected, op).map(Some)
    }

    fn parse_content(&mut self) -> Result<Input<'a>, Error> {
        let start = self.mark();
        skip_value(self)?;
        let end = self.mark();
        self.get_input_between_marks(start, end).map_err(Into::into)
    }
}

fn skip_value(reader: &mut Reader) -> Result<(), Error> {
    let _ = Tag::parse(reader)?;
    match Length::parse(reader)? {
        Length::Definite(len) => {
            println!("Definite {}", len);
            reader.skip(len).map_err(Into::into)
        }
        Length::Indefinite => {
            println!("Indefinite");
            while !reader.peek(0) {
                skip_value(reader)?;
            }
            if reader.read_byte()? == 0 && reader.read_byte()? == 0 {
                Ok(())
            }
            else {
                Err(Error::Malformed)
            }
        }
    }
}



