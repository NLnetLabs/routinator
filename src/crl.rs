
use untrusted::Input;
use super::ber::{Content, Error, Oid, Tag};
use super::x509::{
    update_once, Name, SerialNumber, SignatureAlgorithm, SignedData, Time
};


//------------ Crl -----------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Crl<'a> {
    signed_data: SignedData<'a>,

    signature: SignatureAlgorithm,
    issuer: Name<'a>,
    this_update: Time,
    next_update: Option<Time>,
    revoked_certs: RevokedCertificates<'a>,
    extensions: Extensions<'a>
}

impl<'a> Crl<'a> {
    pub fn parse(content: &mut Content<'a>) -> Result<Self, Error> {
        content.sequence(Self::parse_content)
    }

    pub fn parse_slice(slice: &'a [u8]) -> Result<Self, Error> {
        Content::parse_slice(slice, Self::parse)
    }

    pub fn parse_content(content: &mut Content<'a>) -> Result<Self, Error> {
        let signed_data = SignedData::parse_content(content)?;

        Content::parse(signed_data.data(), |content| {
            content.sequence(|content| {
                content.skip_u8_if(1)?; // v2 => 1
                Ok(Crl {
                    signed_data,
                    signature: SignatureAlgorithm::parse(content)?,
                    issuer: Name::parse(content)?,
                    this_update: Time::parse(content)?,
                    next_update: Time::parse_opt(content)?,
                    revoked_certs: RevokedCertificates::parse(content)?,
                    extensions: content.constructed_if(
                        Tag::CTX_CON_0,
                        Extensions::parse
                    )?
                })
            })
        })
    }
}


//------------ RevokedCertificates ------------------------------------------

#[derive(Clone, Debug)]
pub struct RevokedCertificates<'a>(Input<'a>);

impl<'a> RevokedCertificates<'a> {
    pub fn parse(content: &mut Content<'a>) -> Result<Self, Error> {
        let input = match content.opt_sequence(Content::into_input)? {
            Some(input) => input,
            None => return Ok(RevokedCertificates(Input::from(b"")))
        };

        Content::parse(input.clone(), |content| {
            while let Some(_) = CrlEntry::parse_opt(content)? { }
            Ok(())
        })?;
        Ok(RevokedCertificates(input))
    }
}


//------------ CrlEntry ------------------------------------------------------

#[derive(Clone, Debug)]
pub struct CrlEntry<'a> {
    user_certificate: SerialNumber<'a>,
    revocation_date: Time,
}

impl<'a> CrlEntry<'a> {
    pub fn parse(content: &mut Content<'a>) -> Result<Self, Error> {
        content.sequence(Self::parse_content)
    }

    pub fn parse_opt(content: &mut Content<'a>) -> Result<Option<Self>, Error> {
        content.opt_sequence(Self::parse_content)
    }

    pub fn parse_content(content: &mut Content<'a>) -> Result<Self, Error> {
        Ok(CrlEntry {
            user_certificate: SerialNumber::parse(content)?,
            revocation_date: Time::parse(content)?,
            /// crlEntryExtensions are forbidden by RFC 6487.
        })
    }
}


//------------ Extensions ----------------------------------------------------

#[derive(Clone, Debug)]
pub struct Extensions<'a> {
    /// Authority Key Identifier
    authority_key_id: Input<'a>,

    /// CRL Number
    crl_number: SerialNumber<'a>,
}

impl<'a> Extensions<'a> {
    pub fn parse(content: &mut Content<'a>) -> Result<Self, Error> {
        content.sequence(|content| {
            let mut authority_key_id = None;
            let mut crl_number = None;
            while let Some(()) = content.opt_sequence(|content| {
                let id = Oid::parse(content)?;
                let _critical = content.parse_opt_bool()?.unwrap_or(false);
                Content::parse(content.octet_string()?, |content| {
                    match id {
                        oid::CE_AUTHORITY_KEY_IDENTIFIER => {
                            xerr!(
                                Self::parse_authority_key_identifier(
                                    content, &mut authority_key_id
                                ),
                                "crl::authority_key_identifier"
                            )
                        }
                        oid::CE_CRL_NUMBER => {
                            xerr!(
                                Self::parse_crl_number(
                                    content, &mut crl_number
                                ),
                                "crl::crl_number"
                            )
                        }
                        _ => {
                            // RFC 6487 says that no other extensions are
                            // allowed. So we fail even if there is any other
                            // non-critical extension.
                            xdebug!("crl: unexpected extension {:?}", id);
                            Err(Error::Malformed)
                        }
                    }
                })
            })? { }
            let authority_key_id = match authority_key_id {
                Some(some) => some,
                None => return Err(Error::Malformed)
            };
            let crl_number = match crl_number {
                Some(some) => some,
                None => return Err(Error::Malformed)
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
    fn parse_authority_key_identifier(
        content: &mut Content<'a>, authority_key_id: &mut Option<Input<'a>>
    ) -> Result<(), Error> {
        update_once(authority_key_id, || {
            let res = content.sequence(|content| {
                content.octet_string_if(Tag::CTX_0)
            })?;
            if res.len() != 20 {
                return Err(Error::Malformed)
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
    fn parse_crl_number(
        content: &mut Content<'a>, crl_number: &mut Option<SerialNumber<'a>>
    ) -> Result<(), Error> {
        update_once(crl_number, || {
            SerialNumber::parse(content)
        })
    }
}


//------------ OIDs ----------------------------------------------------------

mod oid {
    use ::ber::Oid;

    pub const CE_CRL_NUMBER: Oid = Oid(&[85, 29, 20]);
    pub const CE_AUTHORITY_KEY_IDENTIFIER: Oid = Oid(&[85, 29, 35]);
}

