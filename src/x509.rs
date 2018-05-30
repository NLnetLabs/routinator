//! Types common to all things X.509.

use std::str;
use std::str::FromStr;
use chrono::{DateTime, LocalResult, TimeZone, Utc};
use untrusted::{Input, Reader};
use super::ber::{Content, Error, Tag};


//------------ Functions -----------------------------------------------------

pub fn update_once<F, T>(opt: &mut Option<T>, op: F) -> Result<(), Error>
where F: FnOnce() -> Result<T, Error> {
    if opt.is_some() {
        Err(Error::Malformed)
    }
    else {
        *opt = Some(op()?);
        Ok(())
    }
}


//------------ Name ----------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Name<'a>(Input<'a>);

impl<'a> Name<'a> {
    pub fn parse(content: &mut Content<'a>) -> Result<Self, Error> {
        content.sequence(Content::into_input).map(Name)
    }
}


//------------ SerialNumber --------------------------------------------------

/// A certificate’s serial number.
///
/// RFC 5280 demands implementations to support serial number of up to twenty
/// octets. Because of that we keep the serial internally as a byte slice and
/// go from there.
#[derive(Clone, Copy, Debug)]
pub struct SerialNumber<'a>(Input<'a>);

impl<'a> SerialNumber<'a> {
    /// Parses the serial number.
    ///
    /// ```text
    /// CertificateSerialNumber  ::=  INTEGER
    /// ```
    pub fn parse(content: &mut Content<'a>) -> Result<Self, Error> {
        content.primitive_if(Tag::INTEGER, |input| {
            match input.iter().next() {
                Some(x) => {
                    if *x & 0x80 != 0 {
                        return Err(Error::Malformed)
                    }
                }
                None => return Err(Error::Malformed)
            }
            Ok(SerialNumber(input))
        })
    }
}


//------------ SignatureAlgorithm --------------------------------------------

#[derive(Clone, Debug)]
pub enum SignatureAlgorithm {
    Sha256WithRsaEncryption
}

impl SignatureAlgorithm {
    pub fn parse(content: &mut Content) -> Result<Self, Error> {
        content.sequence(Self::parse_content)
    }

    pub fn parse_content(content: &mut Content) -> Result<Self, Error> {
        oid::SHA256_WITH_RSA_ENCRYPTION.skip_if(content)?;
        content.skip_opt_null()?;
        Ok(SignatureAlgorithm::Sha256WithRsaEncryption)
    }
}


//------------ SignedData ----------------------------------------------------

#[derive(Clone, Debug)]
pub struct SignedData<'a> {
    data: Input<'a>,
    signature_algorithm: SignatureAlgorithm,
    signature_value: Input<'a>
}

impl<'a> SignedData<'a> {
    pub fn parse(content: &mut Content<'a>) -> Result<Self, Error> {
        content.sequence(Self::parse_content)
    }

    pub fn parse_content(content: &mut Content<'a>) -> Result<Self, Error> {
        Ok(SignedData {
            data: content.value_as_input()?,
            signature_algorithm: SignatureAlgorithm::parse(content)?,
            signature_value: content.filled_bit_string()?,
        })
    }

    pub fn data(&self) -> Input<'a> {
        self.data.clone()
    }
}


//------------ Time ----------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Time(DateTime<Utc>);

impl Time {
    pub fn parse(content: &mut Content) -> Result<Self, Error> {
        content.primitive(|tag, input| {
            input.read_all(Error::Malformed, |reader| {
                match tag {
                    Tag::UTC_TIME => {
                        // RFC 5280 requires the format YYMMDDHHMMSSZ
                        let year = read_two_char(reader)? as i32;
                        let year = if year >= 50 { year + 1900 }
                                   else { year + 2000 };
                        let res = (
                            year,
                            read_two_char(reader)?,
                            read_two_char(reader)?,
                            read_two_char(reader)?,
                            read_two_char(reader)?,
                            read_two_char(reader)?,
                        );
                        if reader.read_byte()? != b'Z' {
                            return Err(Error::Malformed)
                        }
                        Self::from_parts(res)
                    }
                    Tag::GENERALIZED_TIME => {
                        // RFC 5280 requires the format YYYYMMDDHHMMSSZ
                        let res = (
                            read_four_char(reader)? as i32,
                            read_two_char(reader)?,
                            read_two_char(reader)?,
                            read_two_char(reader)?,
                            read_two_char(reader)?,
                            read_two_char(reader)?,
                        );
                        if reader.read_byte()? != b'Z' {
                            return Err(Error::Malformed)
                        }
                        Self::from_parts(res)
                    }
                    _ => Err(Error::Malformed)
                }
            })
        })
    }

    pub fn parse_opt(content: &mut Content) -> Result<Option<Self>, Error> {
        let res = content.opt_primitive_if(Tag::UTC_TIME, |input| {
            input.read_all(Error::Malformed, |reader| {
                let year = read_two_char(reader)? as i32;
                let year = if year >= 50 { year + 1900 }
                           else { year + 2000 };
                let res = (
                    year,
                    read_two_char(reader)?,
                    read_two_char(reader)?,
                    read_two_char(reader)?,
                    read_two_char(reader)?,
                    read_two_char(reader)?,
                );
                if reader.read_byte()? != b'Z' {
                    return Err(Error::Malformed)
                }
                Self::from_parts(res)
            })
        })?;
        if let Some(res) = res {
            return Ok(Some(res))
        }
        content.opt_primitive_if(Tag::GENERALIZED_TIME, |input| {
            input.read_all(Error::Malformed, |reader| {
                let res = (
                    read_four_char(reader)? as i32,
                    read_two_char(reader)?,
                    read_two_char(reader)?,
                    read_two_char(reader)?,
                    read_two_char(reader)?,
                    read_two_char(reader)?,
                );
                if reader.read_byte()? != b'Z' {
                    return Err(Error::Malformed)
                }
                Self::from_parts(res)
            })
        })
    }

    fn from_parts(
        parts: (i32, u32, u32, u32, u32, u32)
    ) -> Result<Self, Error> {
        Ok(Time(match Utc.ymd_opt(parts.0, parts.1, parts.2) {
            LocalResult::Single(dt) => {
                match dt.and_hms_opt(parts.3, parts.4, parts.5) {
                    Some(dt) => dt,
                    None => return Err(Error::Malformed),
                }
            }
            _ => return Err(Error::Malformed)
        }))
    }
}

fn read_two_char(reader: &mut Reader) -> Result<u32, Error> {
    let mut s = [0u8; 2];
    s[0] = reader.read_byte()?;
    s[1] = reader.read_byte()?;
    let s = match str::from_utf8(&s[..]) {
        Ok(s) => s,
        Err(_) => return Err(Error::Malformed)
    };
    u32::from_str(s).map_err(|_| Error::Malformed)
}


fn read_four_char(reader: &mut Reader) -> Result<u32, Error> {
    let mut s = [0u8; 4];
    s[0] = reader.read_byte()?;
    s[1] = reader.read_byte()?;
    s[2] = reader.read_byte()?;
    s[3] = reader.read_byte()?;
    let s = match str::from_utf8(&s[..]) {
        Ok(s) => s,
        Err(_) => return Err(Error::Malformed)
    };
    u32::from_str(s).map_err(|_| Error::Malformed)
}


//------------ Object Identifiers --------------------------------------------

mod oid {
    use ::ber::Oid;

    pub const SHA256_WITH_RSA_ENCRYPTION: Oid
        = Oid(&[42, 134, 72, 134, 247, 13, 1, 1, 11]);
}
