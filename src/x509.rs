
use std::str;
use std::str::FromStr;
use chrono::{DateTime, LocalResult, TimeZone, Utc};
use untrusted::{Input, Reader};
use ::ber::{Content, Error, Tag};


#[derive(Clone, Debug)]
pub struct Cert<'a> {
    tbs_certificate: TbsCertificate<'a>,
    signature_algorithm: SignatureAlgorithm,
    signature_value: Input<'a>,
}

impl<'a> Cert<'a> {
    pub fn parse(content: &mut Content<'a>) -> Result<Self, Error> {
        content.sequence(Self::parse_content)
    }

    /// Parses the content of a Certificate value.
    pub fn parse_content(content: &mut Content<'a>) -> Result<Self, Error> {
        Ok(Cert {
            tbs_certificate: TbsCertificate::parse(content)?,
            signature_algorithm: SignatureAlgorithm::parse(content)?,
            signature_value: content.filled_bit_string()?,
        })
    }

    pub fn public_key(&self) -> Input<'a> {
        self.tbs_certificate
            .subject_public_key_info
            .subject_public_key.clone()
    }

    pub fn public_key_components(
        &self
    ) -> Result<(Input<'a>, Input<'a>), Error> {
        self.tbs_certificate.subject_public_key_info.public_key_components()
    }
}


//------------ TbsCertificate ------------------------------------------------

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct TbsCertificate<'a> {
    raw: Input<'a>,
    serial_number: SerialNumber<'a>,
    signature: SignatureAlgorithm,
    issuer: Name<'a>,
    validity: Validity,
    subject: Name<'a>,
    subject_public_key_info: SubjectPublicKeyInfo<'a>,
    issuer_unique_id: Option<Input<'a>>,
    subject_unique_id: Option<Input<'a>>,
    extensions: Input<'a>,
}

impl<'a> TbsCertificate<'a> {
    pub fn parse(content: &mut Content<'a>) -> Result<Self, Error> {
        let raw = content.value_as_input()?;
        Content::parse(raw.clone(), |content| {
            content.sequence(|content| {
                // version [0] EXPLICIT Version DEFAULT v1.
                //  -- we need extensions so apparently, we want v3 which,
                //     confusingly, is 2.
                content.constructed_if(Tag::CTX_CON_0, |content| {
                    content.skip_u8_if(2)
                })?;

                Ok(TbsCertificate {
                    raw,
                    serial_number: SerialNumber::parse(content)?,
                    signature: SignatureAlgorithm::parse(content)?,
                    issuer: Name::parse(content)?,
                    validity: Validity::parse(content)?,
                    subject: Name::parse(content)?,
                    subject_public_key_info:
                        SubjectPublicKeyInfo::parse(content)?,
                    issuer_unique_id:
                        content.opt_filled_bit_string_if(Tag::CTX_1)?,
                    subject_unique_id:
                        content.opt_filled_bit_string_if(Tag::CTX_1)?,
                    extensions:
                        content.constructed_if(Tag::CTX_CON_3, |content| {
                            content.sequence(Content::into_input)
                        })?,
                })
            })
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


//------------ Name ----------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Name<'a>(Input<'a>);

impl<'a> Name<'a> {
    pub fn parse(content: &mut Content<'a>) -> Result<Self, Error> {
        content.sequence(Content::into_input).map(Name)
    }
}


//------------ Validity ------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Validity {
    not_before: Time,
    not_after: Time,
}

impl Validity {
    pub fn new(not_before: Time, not_after: Time) -> Self {
        Validity { not_before, not_after }
    }

    pub fn parse(content: &mut Content) -> Result<Self, Error> {
        content.sequence(|content| {
            Ok(Validity::new(
                Time::parse(content)?,
                Time::parse(content)?
            ))
        })
    }
}


//------------ Time ----------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Time(DateTime<Utc>);

impl Time {
    pub fn parse(content: &mut Content) -> Result<Self, Error> {
        let parts = content.primitive(|tag, input| {
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
                        Ok(res)
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
                        Ok(res)
                    }
                    _ => Err(Error::Malformed)
                }
            })
        })?;
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


//------------ SubjectPublicKeyInfo ------------------------------------------

#[derive(Clone, Debug)]
pub struct SubjectPublicKeyInfo<'a> {
    algorithm: PublicKeyAlgorithm,
    subject_public_key: Input<'a>,
}

impl<'a> SubjectPublicKeyInfo<'a> {
    pub fn parse(content: &mut Content<'a>) -> Result<Self, Error> {
        content.sequence(|content| {
            Ok(SubjectPublicKeyInfo {
                algorithm: PublicKeyAlgorithm::parse(content)?,
                subject_public_key: content.filled_bit_string()?,
            })
        })
    }

    pub fn public_key_components(
        &self
    ) -> Result<(Input<'a>, Input<'a>), Error> {
        Content::parse(self.subject_public_key.clone(), |content| {
            content.sequence(|content| {
                Ok((
                    content.primitive_if(Tag::INTEGER, Ok)?,
                    content.primitive_if(Tag::INTEGER, Ok)?,
                ))
            })
        })
    }
}


//------------ PublicKeyAlgorithm --------------------------------------------

#[derive(Clone, Debug)]
pub enum PublicKeyAlgorithm {
    RsaEncryption,
}

impl PublicKeyAlgorithm {
    pub fn parse(content: &mut Content) -> Result<Self, Error> {
        content.sequence(Self::parse_content)
    }

    pub fn parse_content(content: &mut Content) -> Result<Self, Error> {
        oid::RSA_ENCRYPTION.skip_if(content)?;
        content.skip_opt_null()?;
        Ok(PublicKeyAlgorithm::RsaEncryption)
    }
}


//------------ OIDs ----------------------------------------------------------

mod oid {
    use ::ber::Oid;

    pub const RSA_ENCRYPTION: Oid
        = Oid(&[42, 134, 72, 134, 247, 13, 1, 1, 1]);
    pub const SHA256_WITH_RSA_ENCRYPTION: Oid
        = Oid(&[42, 134, 72, 134, 247, 13, 1, 1, 11]);
}

