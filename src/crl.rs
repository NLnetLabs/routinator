
use bytes::Bytes;
use super::ber::{
    Constructed, Error, Mode, OctetString, Oid, Source, Tag
};
use super::x509::{
    update_once, Name, SerialNumber, SignatureAlgorithm, SignedData, Time
};


//------------ Crl -----------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Crl {
    signed_data: SignedData,

    signature: SignatureAlgorithm,
    issuer: Name,
    this_update: Time,
    next_update: Option<Time>,
    revoked_certs: RevokedCertificates,
    extensions: Extensions
}

impl Crl {
    pub fn decode<S: Source>(source: S) -> Result<Self, S::Err> {
        Mode::Der.decode(source, Self::take_from)
    }

    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.sequence(Self::take_content_from)
    }

    pub fn take_content_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        let signed_data = SignedData::take_content_from(cons)?;

        Mode::Der.decode(signed_data.data().clone(), |cons| {
            cons.sequence(|cons| {
                cons.skip_u8_if(1)?; // v2 => 1
                Ok(Crl {
                    signed_data,
                    signature: SignatureAlgorithm::take_from(cons)?,
                    issuer: Name::take_from(cons)?,
                    this_update: Time::take_from(cons)?,
                    next_update: Time::take_opt_from(cons)?,
                    revoked_certs: RevokedCertificates::take_from(cons)?,
                    extensions: cons.constructed_if(
                        Tag::CTX_0,
                        Extensions::take_from
                    )?
                })
            })
        }).map_err(Into::into)
    }
}


//------------ RevokedCertificates ------------------------------------------

#[derive(Clone, Debug)]
pub struct RevokedCertificates(Bytes);

impl RevokedCertificates {
    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        let res = cons.opt_sequence(|cons| {
            cons.capture(|cons| {
                while let Some(_) = CrlEntry::take_opt_from(cons)? { }
                Ok(())
            })
        })?;
        Ok(RevokedCertificates(match res {
            Some(res) => res,
            None => Bytes::new(),
        }))
    }
}


//------------ CrlEntry ------------------------------------------------------

#[derive(Clone, Debug)]
pub struct CrlEntry {
    user_certificate: SerialNumber,
    revocation_date: Time,
}

impl CrlEntry {
    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.sequence(Self::take_content_from)
    }

    pub fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Option<Self>, S::Err> {
        cons.opt_sequence(Self::take_content_from)
    }

    pub fn take_content_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        Ok(CrlEntry {
            user_certificate: SerialNumber::take_from(cons)?,
            revocation_date: Time::take_from(cons)?,
            // crlEntryExtensions are forbidden by RFC 6487.
        })
    }
}


//------------ Extensions ----------------------------------------------------

#[derive(Clone, Debug)]
pub struct Extensions {
    /// Authority Key Identifier
    authority_key_id: OctetString,

    /// CRL Number
    crl_number: SerialNumber,
}

impl Extensions {
    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.sequence(|cons| {
            let mut authority_key_id = None;
            let mut crl_number = None;
            while let Some(()) = cons.opt_sequence(|cons| {
                let id = Oid::take_from(cons)?;
                let _critical = cons.take_opt_bool()?.unwrap_or(false);
                let value = OctetString::take_from(cons)?;
                Mode::Der.decode(value.as_source(), |cons| {
                    if id == oid::CE_AUTHORITY_KEY_IDENTIFIER {
                        Self::take_authority_key_identifier(
                            cons, &mut authority_key_id
                        )
                    }
                    else if id == oid::CE_CRL_NUMBER {
                        Self::take_crl_number(cons, &mut crl_number)
                    }
                    else {
                        // RFC 6487 says that no other extensions are
                        // allowed. So we fail even if there is only
                        // non-critical extension.
                        xerr!(Err(Error::Malformed))
                    }
                }).map_err(Into::into)
            })? { }
            let authority_key_id = match authority_key_id {
                Some(some) => some,
                None => return Err(Error::Malformed.into())
            };
            let crl_number = match crl_number {
                Some(some) => some,
                None => return Err(Error::Malformed.into())
            };
            Ok(Extensions {
                authority_key_id,
                crl_number
            })
        })
    }

    /// Parses the Authority Key Identifier Extension.
    ///
    /// Must be present.
    ///
    /// ```text
    /// AuthorityKeyIdentifier ::= SEQUENCE {
    ///   keyIdentifier             [0] KeyIdentifier           OPTIONAL,
    ///   authorityCertIssuer       [1] GeneralNames            OPTIONAL,
    ///   authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
    ///
    /// KeyIdentifier ::= OCTET STRING
    /// ```
    ///
    /// For certificates, only keyIdentifier must be present. Let’s assume
    /// the same is true for CRLs.
    fn take_authority_key_identifier<S: Source>(
        cons: &mut Constructed<S>,
        authority_key_id: &mut Option<OctetString>
    ) -> Result<(), S::Err> {
        update_once(authority_key_id, || {
            let res = cons.sequence(|cons| {
                cons.value_if(Tag::CTX_0, OctetString::take_content_from)
            })?;
            if res.len() != 20 {
                return Err(Error::Malformed.into())
            }
            else {
                Ok(res)
            }
        })
    }

    /// Parses the CRL Number Extension.
    ///
    /// Must be present
    ///
    /// ```text
    /// CRLNumber ::= INTEGER (0..MAX)
    /// ```
    fn take_crl_number<S: Source>(
        cons: &mut Constructed<S>,
        crl_number: &mut Option<SerialNumber>
    ) -> Result<(), S::Err> {
        update_once(crl_number, || {
            SerialNumber::take_from(cons)
        })
    }
}


//------------ OIDs ----------------------------------------------------------

mod oid {
    use ::ber::Oid;

    pub const CE_CRL_NUMBER: Oid<&[u8]> = Oid(&[85, 29, 20]);
    pub const CE_AUTHORITY_KEY_IDENTIFIER: Oid<&[u8]> = Oid(&[85, 29, 35]);
}

