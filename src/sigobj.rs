//! Signed Objects

use bytes::Bytes;
use untrusted::Input;
use super::ber::{
    Constructed, Error, Mode, OctetString, OctetStringSource, Oid, Source, Tag
};
use super::x509::update_once;
use super::cert::{Cert, ResourceCert};
use super::x509::{Time, ValidationError};


//------------ SignedObject --------------------------------------------------

/// A signed object.
///
/// Signed objects are a more strict profile of a CMS signed-data object.
/// They are specified in [RFC 6088] while CMS is specified in [RFC 5652].
#[derive(Clone, Debug)]
pub struct SignedObject {
    content_type: Oid<Bytes>,
    content: OctetString,
    cert: Cert,
    signer_info: SignerInfo,
}

impl SignedObject {
    pub fn decode<S: Source>(source: S) -> Result<Self, S::Err> {
        Mode::Ber.decode(source, Self::take_from)
    }

    /// Returns a reference to the object’s content type.
    pub fn content_type(&self) -> &Oid<Bytes> {
        &self.content_type
    }

    /// Returns a reference to the object’s content.
    pub fn content(&self) -> &OctetString {
        &self.content
    }

    pub fn decode_content<F, T>(&self, op: F) -> Result<T, Error>
    where F: FnOnce(&mut Constructed<OctetStringSource>) -> Result<T, Error> {
        // XXX Let’s see if using DER here at least holds.
        Mode::Der.decode(self.content.to_source(), op)
    }

    /// Returns a reference to the certificate the object is signed with.
    pub fn cert(&self) -> &Cert {
        &self.cert
    }
}


impl SignedObject {
    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.sequence(|cons| {
            oid::SIGNED_DATA.skip_if(cons)?; // contentType
            cons.constructed_if(Tag::CTX_0, Self::take_signed_data)
        })
    }

    /// Parses a SignedData value.
    ///
    /// RFC 6488:
    ///
    /// ```text
    /// SignedData ::= SEQUENCE {
    ///     version CMSVersion,
    ///     digestAlgorithms DigestAlgorithmIdentifiers,
    ///     encapContentInfo EncapsulatedContentInfo,
    ///     certificates [0] IMPLICIT CertificateSet OPTIONAL,
    ///     crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
    ///     signerInfos SignerInfos }
    /// ```
    ///
    /// `version` must be 3, `certificates` present and `crls` not.
    fn take_signed_data<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.sequence(|cons| {
            cons.skip_u8_if(3)?; // version -- must be 3
            DigestAlgorithm::skip_set(cons)?; // digestAlgorithms
            let (content_type, content)
                = Self::take_encap_content_info(cons)?;
            let cert = Self::take_certificates(cons)?;
            let signer_info = SignerInfo::take_set_from(cons)?;
            Ok(SignedObject {
                content_type, content, cert, signer_info
            })
        })
    }

    /// Parses an EncapsulatedContentInfo value.
    ///
    /// RFC 6488:
    ///
    /// ```text
    /// EncapsulatedContentInfo ::= SEQUENCE {
    ///       eContentType ContentType,
    ///       eContent [0] EXPLICIT OCTET STRING OPTIONAL }
    /// ```
    ///
    /// For a ROA, `eContentType` must be `oid:::ROUTE_ORIGIN_AUTH`.
    fn take_encap_content_info<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<(Oid<Bytes>, OctetString), S::Err> {
        cons.sequence(|cons| {
            Ok((
                Oid::take_from(cons)?,
                cons.constructed_if(
                    Tag::CTX_0,
                    OctetString::take_from
                )?
            ))
        })
    }

    /// Parse a certificates field of a SignedData value.
    ///
    /// The field is `[0] IMPLICIT CertificateSet`.
    ///
    /// And then, RFC 5652:
    ///
    /// ```text
    /// CertificateSet ::= SET OF CertificateChoices
    /// CertificateChoices ::= CHOICE {
    ///   certificate Certificate,
    ///   extendedCertificate [0] IMPLICIT ExtendedCertificate,  -- Obsolete
    ///   v1AttrCert [1] IMPLICIT AttributeCertificateV1,        -- Obsolete
    ///   v2AttrCert [2] IMPLICIT AttributeCertificateV2,
    ///   other [3] IMPLICIT OtherCertificateFormat }
    /// ```
    /// 
    /// Certificate is a SEQUENCE. For the moment, we don’t implement the
    /// other choices.
    ///
    /// RFC 6288 limites the set to exactly one.
    fn take_certificates<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Cert, S::Err> {
        cons.constructed_if(Tag::CTX_0, |cons| {
            cons.constructed(|tag, cons| {
                match tag {
                    Tag::SEQUENCE =>  Cert::take_content_from(cons),
                    _ => {
                        xerr!(Err(Error::Unimplemented.into()))
                    }
                }
            })
        })
    }

    /// Validates the signed object.
    ///
    /// The requirements for an object to be valid are given in section 3
    /// of [RFC 6488].
    ///
    /// Upon success, the method returns the validated certificate and the
    /// content.
    pub fn validate(
        self,
        issuer: &ResourceCert
    ) -> Result<ResourceCert, ValidationError> {
        self.verify_compliance()?;
        self.verify_signature()?;
        self.cert.validate_ee(issuer)
    }

    /// Validates that the signed object complies with the specification.
    ///
    /// This is item 1 of [RFC 6488]`s section 3.
    fn verify_compliance(&self) -> Result<(), ValidationError> {
        // Sub-items a, b, d, e, f, g, i, j, k, l have been validated while
        // parsing. This leaves these:
        //
        // c. cert is an EE cert with the SubjectKeyIdentifer matching
        //    the sid field of the SignerInfo.
        if &self.signer_info.sid != self.cert.subject_key_identifier() {
            return Err(ValidationError)
        }
        // h. eContentType equals the OID in the value of the content-type
        //    signed attribute.
        if self.content_type != self.signer_info.signed_attrs.content_type {
            return Err(ValidationError)
        }
        Ok(())
    }

    /// Verifies the signature of the object against contained certificate.
    ///
    /// This is item 2 of [RFC 6488]’s section 3.
    fn verify_signature(&self) -> Result<(), ValidationError> {
        let digest = self.content.sha256();
        if digest.as_ref() != self.signer_info.message_digest() {
            return Err(ValidationError)
        }
        let msg = self.signer_info.signed_attrs.encode_verify();
        ::ring::signature::verify(
            &::ring::signature::RSA_PKCS1_2048_8192_SHA256,
            Input::from(self.cert.public_key().as_ref()),
            Input::from(&msg),
            Input::from(self.signer_info.signature_value.to_bytes().as_ref())
        ).map_err(|_| ValidationError)
    }
}


//------------ DigestAlgorithm -----------------------------------------------

#[derive(Clone, Debug)]
pub enum DigestAlgorithm {
    Sha256,
}


impl DigestAlgorithm {
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

    fn take_content_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        oid::SHA256.skip_if(cons)?;
        cons.skip_opt_null()?;
        Ok(DigestAlgorithm::Sha256)
    }


    /// Parses a SET OF DigestAlgorithmIdentifiers.
    ///
    /// This is used in the digestAlgorithms field of the SignedData
    /// container. It provides all the digest algorithms used later on, so
    /// that the data can be read over. We don’t really need this, so this
    /// function returns `()` on success.
    ///
    /// Section 2.1.2. of RFC 6488 requires there to be exactly one element
    /// chosen from the allowed values.
    pub fn skip_set<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<(), S::Err> {
        cons.constructed_if(Tag::SET, |cons| {
            while let Some(_) = Self::take_opt_from(cons)? { }
            Ok(())
        })
    }
}


//------------ SignerInfo ----------------------------------------------------

#[derive(Clone, Debug)]
pub struct SignerInfo {
    sid: OctetString,
    digest_algorithm: DigestAlgorithm,
    signed_attrs: SignedAttributes,
    signature_algorithm: SignatureAlgorithm,
    signature_value: OctetString
}

impl SignerInfo {
    pub fn take_set_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.set(Self::take_from)
    }

    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.sequence(|cons| {
            cons.skip_u8_if(3)?;
            Ok(SignerInfo {
                sid: cons.take_value_if(Tag::CTX_0, |content| {
                    OctetString::take_content_from(content)
                })?,
                digest_algorithm: DigestAlgorithm::take_from(cons)?,
                signed_attrs: SignedAttributes::take_from(cons)?,
                signature_algorithm: SignatureAlgorithm::take_from(cons)?,
                signature_value: OctetString::take_from(cons)?
            })
        })
    }

    pub fn message_digest(&self) -> Bytes {
        self.signed_attrs.message_digest.to_bytes()
    }
}


//------------ SignedAttributes ----------------------------------------------

#[derive(Clone, Debug)]
pub struct SignedAttributes {
    raw: Bytes,
    message_digest: OctetString,
    content_type: Oid<Bytes>,
    signing_time: Option<Time>,
    binary_signing_time: Option<u64>,
}

impl SignedAttributes {
    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        let raw = cons.constructed_if(Tag::CTX_0, |c| c.take_all())?;
        Mode::Ber.decode(raw.clone(), |cons| {
            let mut message_digest = None;
            let mut content_type = None;
            let mut signing_time = None;
            let mut binary_signing_time = None;
            while let Some(()) = cons.opt_sequence(|cons| {
                let oid = Oid::take_from(cons)?;
                if oid == oid::CONTENT_TYPE {
                    Self::take_content_type(cons, &mut content_type)
                }
                else if oid == oid::MESSAGE_DIGEST {
                    Self::take_message_digest(cons, &mut message_digest)
                }
                else if oid == oid::SIGNING_TIME {
                    Self::take_signing_time(cons, &mut signing_time)
                }
                else if oid == oid::AA_BINARY_SIGNING_TIME {
                    Self::take_bin_signing_time(
                        cons,
                        &mut binary_signing_time
                    )
                }
                else {
                    xerr!(Err(Error::Malformed))
                }
            })? { }
            let message_digest = match message_digest {
                Some(some) => some,
                None => return Err(Error::Malformed)
            };
            let content_type = match content_type {
                Some(some) => some,
                None => return Err(Error::Malformed)
            };
            Ok(SignedAttributes {
                raw,
                message_digest,
                content_type,
                signing_time,
                binary_signing_time,
            })
        }).map_err(Into::into)
    }

    /// Parses the Content Type attribute.
    ///
    /// This attribute is defined in section 11.1. of RFC 5652. The attribute
    /// value is a SET of exactly one OBJECT IDENTIFIER.
    fn take_content_type<S: Source>(
        cons: &mut Constructed<S>,
        content_type: &mut Option<Oid<Bytes>>
    ) -> Result<(), S::Err> {
        update_once(content_type, || {
            cons.set(|cons| Oid::take_from(cons))
        })
    }

    fn take_message_digest<S: Source>(
        cons: &mut Constructed<S>,
        message_digest: &mut Option<OctetString>
    ) -> Result<(), S::Err> {
        update_once(message_digest, || {
            cons.set(|cons| OctetString::take_from(cons))
        })
    }

    fn take_signing_time<S: Source>(
        cons: &mut Constructed<S>,
        signing_time: &mut Option<Time>
    ) -> Result<(), S::Err> {
        update_once(signing_time, || {
            cons.set(Time::take_from)
        })
    }

    fn take_bin_signing_time<S: Source>(
        cons: &mut Constructed<S>,
        bin_signing_time: &mut Option<u64>
    ) -> Result<(), S::Err> {
        update_once(bin_signing_time, || {
            cons.set(|cons| cons.take_u64())
        })
    }

    pub fn encode_verify(&self) -> Vec<u8> {
        let mut res = Vec::new();
        res.push(0x31); // SET
        let len = self.raw.len();
        if len < 128 {
            res.push(len as u8)
        }
        else if len < 0x10000 {
            res.push(2);
            res.push((len >> 8) as u8);
            res.push(len as u8);
        }
        else {
            panic!("overly long signed attrs");
        }
        res.extend_from_slice(self.raw.as_ref());
        res
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
        let oid = Oid::take_from(cons)?;
        if oid != oid::RSA_ENCRYPTION &&
            oid != oid::SHA256_WITH_RSA_ENCRYPTION
        {
            return Err(Error::Malformed.into())
        }
        cons.skip_opt_null()?;
        Ok(SignatureAlgorithm::Sha256WithRsaEncryption)
    }
}


//------------ OIDs ----------------------------------------------------------

pub mod oid {
    use ::ber::Oid;

    pub const SIGNED_DATA: Oid<&[u8]>
        = Oid(&[42, 134, 72, 134, 247, 13, 1, 7, 2]);
    pub const SHA256: Oid<&[u8]> = Oid(&[96, 134, 72, 1, 101, 3, 4, 2, 1]);
    pub const RSA_ENCRYPTION: Oid<&[u8]>
        = Oid(&[42, 134, 72, 134, 247, 13, 1, 1, 1]);
    pub const SHA256_WITH_RSA_ENCRYPTION: Oid<&[u8]>
        = Oid(&[42, 134, 72, 134, 247, 13, 1, 1, 11]);

    pub const CONTENT_TYPE: Oid<&[u8]>
        = Oid(&[42, 134, 72, 134, 247, 13, 1, 9, 3]);
    pub const MESSAGE_DIGEST: Oid<&[u8]>
        = Oid(&[42, 134, 72, 134, 247, 13, 1, 9, 4]);
    pub const SIGNING_TIME: Oid<&[u8]>
        = Oid(&[42, 134, 72, 134, 247, 13, 1, 9, 5]);
    pub const AA_BINARY_SIGNING_TIME: Oid<&[u8]> =
        Oid(&[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 46]);
}

