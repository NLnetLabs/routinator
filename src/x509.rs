//! Types common to all things X.509.

use std::str;
use std::str::FromStr;
use bytes::Bytes;
use chrono::{DateTime, LocalResult, TimeZone, Utc};
use super::ber::{BitString, Constructed, Error, Source, Tag};


//------------ Functions -----------------------------------------------------

pub fn update_once<F, T, E>(opt: &mut Option<T>, op: F) -> Result<(), E>
where F: FnOnce() -> Result<T, E>, E: From<Error> {
    if opt.is_some() {
        Err(Error::Malformed.into())
    }
    else {
        *opt = Some(op()?);
        Ok(())
    }
}


//------------ Name ----------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Name(Bytes);

impl Name {
    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        println!("taking name");
        cons.sequence(|cons| cons.take_all()).map(Name)
    }
}


//------------ SerialNumber --------------------------------------------------

/// A certificate’s serial number.
///
/// RFC 5280 demands implementations to support serial number of up to twenty
/// octets. Because of that we keep the serial internally as a bytes value
/// and go from there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SerialNumber(Bytes);

impl SerialNumber {
    /// Parses the serial number.
    ///
    /// ```text
    /// CertificateSerialNumber  ::=  INTEGER
    /// ```
    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.primitive_if(Tag::INTEGER, |prim| {
            match prim.slice_all()?.first() {
                Some(&x) => {
                    if x & 0x80 != 0 {
                        xerr!(return Err(Error::Malformed.into()))
                    }
                }
                None => {
                    xerr!(return Err(Error::Malformed.into()))
                }
            }
            Ok(SerialNumber(prim.take_all()?))
        })
    }
}


//------------ SignatureAlgorithm --------------------------------------------

#[derive(Clone, Debug)]
pub enum SignatureAlgorithm {
    Sha256WithRsaEncryption
}

impl SignatureAlgorithm {
    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.sequence(Self::take_content_from)
    }

    pub fn take_content_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        oid::SHA256_WITH_RSA_ENCRYPTION.skip_if(cons)?;
        cons.skip_opt_null()?;
        Ok(SignatureAlgorithm::Sha256WithRsaEncryption)
    }
}


//------------ SignedData ----------------------------------------------------

#[derive(Clone, Debug)]
pub struct SignedData {
    data: Bytes,
    signature_algorithm: SignatureAlgorithm,
    signature_value: BitString,
}

impl SignedData {
    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.sequence(Self::take_content_from)
    }

    pub fn take_content_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        Ok(SignedData {
            data: cons.take_one()?,
            signature_algorithm: SignatureAlgorithm::take_from(cons)?,
            signature_value: BitString::take_from(cons)?,
        })
    }

    pub fn data(&self) -> &Bytes {
        &self.data
    }
}


//------------ Time ----------------------------------------------------------

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Time(DateTime<Utc>);

impl Time {
    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.primitive(|tag, prim| {
            match tag {
                Tag::UTC_TIME => {
                    // RFC 5280 requires the format YYMMDDHHMMSSZ
                    let year = read_two_char(prim)? as i32;
                    let year = if year >= 50 { year + 1900 }
                               else { year + 2000 };
                    let res = (
                        year,
                        read_two_char(prim)?,
                        read_two_char(prim)?,
                        read_two_char(prim)?,
                        read_two_char(prim)?,
                        read_two_char(prim)?,
                    );
                    if prim.take_u8()? != b'Z' {
                        return Err(Error::Malformed.into())
                    }
                    Self::from_parts(res).map_err(Into::into)
                }
                Tag::GENERALIZED_TIME => {
                    // RFC 5280 requires the format YYYYMMDDHHMMSSZ
                    let res = (
                        read_four_char(prim)? as i32,
                        read_two_char(prim)?,
                        read_two_char(prim)?,
                        read_two_char(prim)?,
                        read_two_char(prim)?,
                        read_two_char(prim)?,
                    );
                    if prim.take_u8()? != b'Z' {
                        return Err(Error::Malformed.into())
                    }
                    Self::from_parts(res).map_err(Into::into)
                }
                _ => {
                    xerr!(Err(Error::Malformed.into()))
                }
            }
        })
    }

    pub fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Option<Self>, S::Err> {
        let res = cons.opt_primitive_if(Tag::UTC_TIME, |prim| {
            let year = read_two_char(prim)? as i32;
            let year = if year >= 50 { year + 1900 }
                       else { year + 2000 };
            let res = (
                year,
                read_two_char(prim)?,
                read_two_char(prim)?,
                read_two_char(prim)?,
                read_two_char(prim)?,
                read_two_char(prim)?,
            );
            if prim.take_u8()? != b'Z' {
                return Err(Error::Malformed.into())
            }
            Self::from_parts(res).map_err(Into::into)
        })?;
        if let Some(res) = res {
            return Ok(Some(res))
        }
        cons.opt_primitive_if(Tag::GENERALIZED_TIME, |prim| {
            let res = (
                read_four_char(prim)? as i32,
                read_two_char(prim)?,
                read_two_char(prim)?,
                read_two_char(prim)?,
                read_two_char(prim)?,
                read_two_char(prim)?,
            );
            if prim.take_u8()? != b'Z' {
                return Err(Error::Malformed.into())
            }
            Self::from_parts(res).map_err(Into::into)
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

fn read_two_char<S: Source>(source: &mut S) -> Result<u32, S::Err> {
    let mut s = [0u8; 2];
    s[0] = source.take_u8()?;
    s[1] = source.take_u8()?;
    let s = match str::from_utf8(&s[..]) {
        Ok(s) => s,
        Err(_err) => {
            xerr!(return Err(Error::Malformed.into()))
        }
    };
    u32::from_str(s).map_err(|_err| {
        xerr!(Error::Malformed.into())
    })
}


fn read_four_char<S: Source>(source: &mut S) -> Result<u32, S::Err> {
    let mut s = [0u8; 4];
    s[0] = source.take_u8()?;
    s[1] = source.take_u8()?;
    s[2] = source.take_u8()?;
    s[3] = source.take_u8()?;
    let s = match str::from_utf8(&s[..]) {
        Ok(s) => s,
        Err(_err) => {
            xerr!(return Err(Error::Malformed.into()))
        }
    };
    u32::from_str(s).map_err(|_err| {
        xerr!(Error::Malformed.into())
    })
}


//------------ Object Identifiers --------------------------------------------

mod oid {
    use ::ber::Oid;

    pub const SHA256_WITH_RSA_ENCRYPTION: Oid<&[u8]>
        = Oid(&[42, 134, 72, 134, 247, 13, 1, 1, 11]);
}

