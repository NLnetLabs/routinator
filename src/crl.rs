//! Certificate Revocation Lists for RPKI.
//!
//! Much like for certificates, RPKI reuses X.509 for its certifcate
//! revocation lists (CRLs), limiting the values that are allowed in the
//! various fields.
//!
//! This module implements the CRLs themselves via the type [`Crl`] as well
//! as a [`CrlStore`] that can keep several CRLs which may be helpful during
//! validation.
//!
//! The RPKI CRL profile is defined in RFC 6487 based on the Internet RPIX
//! profile defined in RFC 5280.
//!
//! [`Crl`]: struct.Crl.html
//! [`CrlStore`]: struct.CrlStore.html

use bytes::Bytes;
use super::rsync;
use super::ber::{
    Constructed, Error, Mode, OctetString, Oid, Source, Tag, Unsigned
};
use super::cert::Cert;
use super::x509::{
    update_once, Name, SignatureAlgorithm, SignedData, Time, ValidationError
};


//------------ Crl -----------------------------------------------------------

/// An RPKI certificate revocation list.
///
/// A value of this type is the result of parsing a CRL file found in the
/// RPKI repository. You can use the `decode` function for parsing a CRL out
/// of such a file.
#[derive(Clone, Debug)]
pub struct Crl {
    /// The outer structure of the CRL.
    signed_data: SignedData,

    /// The algorithm used for signing the certificate.
    signature: SignatureAlgorithm,

    /// The name of the issuer.
    ///
    /// This isn’t really used in RPKI at all.
    issuer: Name,

    /// The time this version of the CRL was created.
    this_update: Time,

    /// The time the next version of the CRL is likely to be created.
    next_update: Option<Time>,

    /// The list of revoked certificates.
    revoked_certs: RevokedCertificates,

    /// The CRL extensions.
    extensions: Extensions
}

impl Crl {
    /// Parses a source as a certificate revocation list.
    pub fn decode<S: Source>(source: S) -> Result<Self, S::Err> {
        Mode::Der.decode(source, Self::take_from)
    }

    /// Takes an encoded CRL from the beginning of a constructed value.
    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(Self::take_content_from)
    }

    /// Parses the content of a certificate revocation list.
    pub fn take_content_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        let signed_data = SignedData::take_content_from(cons)?;

        Mode::Der.decode(signed_data.data().clone(), |cons| {
            cons.take_sequence(|cons| {
                cons.skip_u8_if(1)?; // v2 => 1
                Ok(Crl {
                    signed_data,
                    signature: SignatureAlgorithm::take_from(cons)?,
                    issuer: Name::take_from(cons)?,
                    this_update: Time::take_from(cons)?,
                    next_update: Time::take_opt_from(cons)?,
                    revoked_certs: RevokedCertificates::take_from(cons)?,
                    extensions: cons.take_constructed_if(
                        Tag::CTX_0,
                        Extensions::take_from
                    )?
                })
            })
        }).map_err(Into::into)
    }

    /// Validates the certificate revocation list.
    ///
    /// The list’s signature is validated against the certificate provided
    /// via `issuer`.
    pub fn validate<C: AsRef<Cert>>(
        &self,
        issuer: C
    ) -> Result<(), ValidationError> {
        self.signed_data.verify_signature(issuer.as_ref().public_key())
    }

    /// Returns whether the given serial number is on this revocation list.
    pub fn contains(&self, serial: &Unsigned) -> bool {
        self.revoked_certs.contains(serial)
    }
}


//------------ RevokedCertificates ------------------------------------------

/// The list of revoked certificates.
///
/// A value of this type wraps the bytes of the DER encoded list. You can
/// check whether a certain serial number is part of this list via the
/// `contains` method.
#[derive(Clone, Debug)]
pub struct RevokedCertificates(Bytes);

impl RevokedCertificates {
    /// Takes a revoked certificates list from the beginning of a value.
    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        let res = cons.take_opt_sequence(|cons| {
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

    /// Returns whether the given serial number is contained on this list.
    ///
    /// The method walks over the list, decoding it on the fly and checking
    /// each entry.
    pub fn contains(&self, serial: &Unsigned) -> bool {
        Mode::Der.decode(self.0.as_ref(), |cons| {
            while let Some(entry) = CrlEntry::take_opt_from(cons).unwrap() {
                if entry.user_certificate == *serial {
                    return Ok(true)
                }
            }
            Ok(false)
        }).unwrap()
    }
}


//------------ CrlEntry ------------------------------------------------------

/// An entry in the revoked certificates list.
#[derive(Clone, Debug)]
pub struct CrlEntry {
    /// The serial number of the revoked certificate.
    user_certificate: Unsigned,

    /// The time of revocation.
    revocation_date: Time,
}

impl CrlEntry {
    /// Takes a single CRL entry from the beginning of a constructed value.
    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(Self::take_content_from)
    }

    /// Takes an optional CRL entry from the beginning of a contructed value.
    pub fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Option<Self>, S::Err> {
        cons.take_opt_sequence(Self::take_content_from)
    }

    /// Parses the content of a CRL entry.
    pub fn take_content_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        Ok(CrlEntry {
            user_certificate: Unsigned::take_from(cons)?,
            revocation_date: Time::take_from(cons)?,
            // crlEntryExtensions are forbidden by RFC 6487.
        })
    }
}


//------------ Extensions ----------------------------------------------------

/// Extensions of a RPKI certificate revocation list.
///
/// Only two extension are allowed to be present: the authority key
/// identifier extension which contains the key identifier of the certificate
/// this CRL is associated with, and the CRL number which is the serial
/// number of this version of the CRL.
#[derive(Clone, Debug)]
pub struct Extensions {
    /// Authority Key Identifier
    authority_key_id: OctetString,

    /// CRL Number
    crl_number: Unsigned,
}

impl Extensions {
    /// Takes the CRL extension from the beginning of a constructed value.
    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            let mut authority_key_id = None;
            let mut crl_number = None;
            while let Some(()) = cons.take_opt_sequence(|cons| {
                let id = Oid::take_from(cons)?;
                let _critical = cons.take_opt_bool()?.unwrap_or(false);
                let value = OctetString::take_from(cons)?;
                Mode::Der.decode(value.to_source(), |cons| {
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
            let res = cons.take_sequence(|cons| {
                cons.take_value_if(Tag::CTX_0, OctetString::take_content_from)
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
        crl_number: &mut Option<Unsigned>
    ) -> Result<(), S::Err> {
        update_once(crl_number, || {
            Unsigned::take_from(cons)
        })
    }
}


//------------ CrlStore ------------------------------------------------------

/// A place to cache CRLs for reuse.
///
/// This type allows to store CRLs you have seen in case you may need them
/// again soon. This is useful when validating the objects issued by a CA as
/// they likely all refer to the same CRL, so keeping it around makes sense.
#[derive(Clone, Debug)]
pub struct CrlStore {
    // This is a simple vector because most likely we’ll only ever have one.
    crls: Vec<(rsync::Uri, Crl)>
}

impl CrlStore {
    /// Creates a new CRL store.
    pub fn new() -> Self {
        CrlStore { crls: Vec::new() }
    }

    /// Adds an entry to the CRL store.
    ///
    /// The CRL is keyed by its rsync `uri`.
    pub fn push(&mut self, uri: rsync::Uri, crl: Crl) {
        self.crls.push((uri, crl))
    }

    /// Returns a reference to a CRL if it is available in the store.
    pub fn get(&self, uri: &rsync::Uri) -> Option<&Crl> {
        for &(ref stored_uri, ref crl) in &self.crls {
            if *stored_uri == *uri {
                return Some(crl)
            }
        }
        None
    }
}



//------------ OIDs ----------------------------------------------------------

mod oid {
    use ::ber::Oid;

    pub const CE_CRL_NUMBER: Oid<&[u8]> = Oid(&[85, 29, 20]);
    pub const CE_AUTHORITY_KEY_IDENTIFIER: Oid<&[u8]> = Oid(&[85, 29, 35]);
}

