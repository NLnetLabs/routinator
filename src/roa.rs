//! Route Origin Authorizations.
//!
//! For details, see RFC 6482.

use bytes::Bytes;
use super::asres::AsId;
use super::ber::{BitString, Constructed, Error, Mode, Source, Tag};
use super::cert::ResourceCert;
use super::ipres::AddressFamily;
use super::sigobj::SignedObject;
use super::x509::ValidationError;


//------------ Roa -----------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Roa {
    signed: SignedObject,
    content: RouteOriginAttestation,
}

impl Roa {
    pub fn decode<S: Source>(source: S) -> Result<Self, S::Err> {
        let signed = SignedObject::decode(source)?;
        let content = signed.decode_content(|cons| {
            RouteOriginAttestation::take_from(cons)
        })?;
        Ok(Roa { signed, content })
    }

    pub fn process(
        self,
        issuer: &ResourceCert,
        origins: &mut RouteOrigins
    ) -> Result<(), ValidationError> {
        let cert = self.signed.validate(issuer)?;
        self.content.validate(&cert)?;
        origins.push(self.content);
        Ok(())
    }
}


//------------ RouteOriginAttestation ----------------------------------------

#[derive(Clone, Debug)]
pub struct RouteOriginAttestation {
    as_id: AsId,
    v4_addrs: RoaIpAddresses,
    v6_addrs: RoaIpAddresses,
}

impl RouteOriginAttestation {
    fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.sequence(|cons| {
            cons.opt_primitive_if(Tag::CTX_0, |prim| {
                if prim.take_u8()? != 0 {
                    xerr!(Err(Error::Malformed.into()))
                }
                else {
                    Ok(())
                }
            })?;
            let as_id = AsId::take_from(cons)?;
            let mut v4 = None;
            let mut v6 = None;
            cons.sequence(|cons| {
                while let Some(()) = cons.opt_sequence(|cons| {
                    match AddressFamily::take_from(cons)? {
                        AddressFamily::Ipv4 => {
                            if v4.is_some() {
                                xerr!(return Err(Error::Malformed.into()));
                            }
                            v4 = Some(RoaIpAddresses::take_from(cons)?);
                        }
                        AddressFamily::Ipv6 => {
                            if v6.is_some() {
                                xerr!(return Err(Error::Malformed.into()));
                            }
                            v6 = Some(RoaIpAddresses::take_from(cons)?);
                        }
                    }
                    Ok(())
                })? { }
                Ok(())
            })?;
            Ok(RouteOriginAttestation {
                as_id,
                v4_addrs: match v4 {
                    Some(addrs) => addrs,
                    None => RoaIpAddresses(Bytes::from_static(b""))
                },
                v6_addrs: match v6 {
                    Some(addrs) => addrs,
                    None => RoaIpAddresses(Bytes::from_static(b""))
                }
            })
        })
    }

    fn validate(&self, cert: &ResourceCert) -> Result<(), ValidationError> {
        if !self.v4_addrs.is_empty() {
            let blocks = match cert.ip_resources().v4() {
                Some(blocks) => blocks,
                None => return Err(ValidationError)
            };
            for addr in self.v4_addrs.iter() {
                if !blocks.contain(&addr) {
                    return Err(ValidationError)
                }
            }
        }
        if !self.v6_addrs.is_empty() {
            let blocks = match cert.ip_resources().v6() {
                Some(blocks) => blocks,
                None => return Err(ValidationError)
            };
            for addr in self.v6_addrs.iter() {
                if !blocks.contain(&addr) {
                    return Err(ValidationError)
                }
            }
        }
        Ok(())
    }
}


//------------ RoaIpAddresses ------------------------------------------------

#[derive(Clone, Debug)]
pub struct RoaIpAddresses(Bytes);

impl RoaIpAddresses {
    fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.sequence(|cons| {
            cons.capture(|cons| {
                while let Some(()) = RoaIpAddress::skip_opt_in(cons)? { }
                Ok(())
            })
        }).map(RoaIpAddresses)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> RoaIpAddressIter {
        RoaIpAddressIter(self.0.as_ref())
    }
}


//------------ RoaIpAddressIter ----------------------------------------------

#[derive(Clone, Debug)]
pub struct RoaIpAddressIter<'a>(&'a [u8]);

impl<'a> Iterator for RoaIpAddressIter<'a> {
    type Item = RoaIpAddress;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            None
        }
        else {
            Mode::Der.decode(&mut self.0, |cons| {
                RoaIpAddress::take_opt_from(cons)
            }).unwrap()
        }
    }
}


//------------ RoaIpAddress --------------------------------------------------

#[derive(Clone, Debug)]
pub struct RoaIpAddress {
    address: u128,
    address_length: u8,
    max_length: Option<u8>
}

impl RoaIpAddress {
    pub fn range(&self) -> (u128, u128) {
        let mask = !0u128 >> self.address_length;
        (self.address & !mask, self.address | mask)
    }
}

impl RoaIpAddress {
    fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Option<Self>, S::Err> {
        cons.opt_sequence(|cons| {
            let bs = BitString::take_from(cons)?;
            let max = cons.take_opt_u8()?;
            if bs.octet_len() > 16 {
                xerr!(return Err(Error::Malformed.into()))
            }
            let mut addr = 0;
            for octet in bs.octets() {
                addr = (addr << 8) | (octet as u128)
            }
            for _ in bs.octet_len()..16 {
                addr = addr << 8
            }
            Ok(RoaIpAddress {
                address: addr,
                address_length: bs.bit_len() as u8,
                max_length: max
            })
        })
    }

    fn skip_opt_in<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Option<()>, S::Err> {
        cons.opt_sequence(|cons| {
            let bs = BitString::take_from(cons)?;
            let _ = cons.take_opt_u8()?;
            if bs.octet_len() > 16 {
                xerr!(return Err(Error::Malformed.into()))
            }
            Ok(())
        })
    }
}


//------------ RouteOrigins --------------------------------------------------

pub struct RouteOrigins {
    origins: Vec<RouteOriginAttestation>
}

impl RouteOrigins {
    pub fn new() -> Self {
        RouteOrigins { origins: Vec::new() }
    }

    pub fn push(&mut self, attestation: RouteOriginAttestation) {
        self.origins.push(attestation)
    }
}

