use untrusted::Reader;
use super::error::Error;


//------------ Length -------------------------------------------------------

/// The length octets of an encoded value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Length {
    /// A length value in definite form.
    ///
    /// Provides the actual length of the content in octets.
    Definite(usize),

    /// A length value in indefinite form.
    ///
    /// In this form, the end of a value is determined by a special tag.
    Indefinite
}

impl Length {
    pub fn parse<'a>(input: &mut Reader<'a>) -> Result<Self, Error> {
        match input.read_byte()? {
            // Bit 7 clear: other bits are the length
            n if (n & 0x80) == 0 => Ok(Length::Definite(n as usize)),

            // Bit 7 set: other bits are the number of octets that 
            // encode the length. Unless they are all 0, in which case this
            // is the indefinite form.
            0x80 => Ok(Length::Indefinite),
            0x81 => Ok(Length::Definite(input.read_byte()? as usize)),
            0x82 => {
                Ok(Length::Definite(
                    (input.read_byte()? as usize) << 8 |
                    (input.read_byte()? as usize)
                ))
            }
            0x83 => {
                Ok(Length::Definite(
                    (input.read_byte()? as usize) << 16 |
                    (input.read_byte()? as usize) << 8 |
                    (input.read_byte()? as usize)
                ))
            }
            0x84 => {
                Ok(Length::Definite(
                    (input.read_byte()? as usize) << 24 |
                    (input.read_byte()? as usize) << 16 |
                    (input.read_byte()? as usize) << 8 |
                    (input.read_byte()? as usize)
                ))
            }
            _ => {
                // We only implement up to two length bytes for now.
                Err(Error::Unimplemented)
            }
        }
    }

    pub fn is_zero(&self) -> bool {
        if let Length::Definite(0) = *self { true }
        else { false }
    }
}

