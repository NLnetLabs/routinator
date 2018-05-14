//! Route Origin Authorizations

use untrusted::Input;
use ::ber::{Content, Error, OctetString, Oid, Tag};
use ::x509;
use ::x509::Time;


//------------ RouteOriginAttestations ---------------------------------------

/// Route Origin Attestation.
#[derive(Clone, Debug)]
pub struct RouteOriginAttestation<'a> {
    #[allow(dead_code)]
    encap_content: OctetString<'a>,
    #[allow(dead_code)]
    cert: x509::Cert<'a>,
    signer_info: SignerInfo<'a>,
}


impl<'a> RouteOriginAttestation<'a> {
    /// Parses the ROA from input
    pub fn parse(input: Input<'a>) -> Result<Self, Error> {
        Content::parse(input, Self::parse_content_info)
    }

    pub fn parse_slice(slice: &'a [u8]) -> Result<Self, Error> {
        Content::parse_slice(slice, Self::parse_content_info)
    }

    fn parse_content_info(content: &mut Content<'a>) -> Result<Self, Error> {
        content.sequence(|content| {
            oid::SIGNED_DATA.skip_if(content)?; // contentType
            content.constructed_if(Tag::CTX_CON_0, Self::parse_signed_data)
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
    fn parse_signed_data(content: &mut Content<'a>) -> Result<Self, Error> {
        content.sequence(|content| {
            content.skip_u8_if(3)?; // version -- must be 3
            DigestAlgorithm::skip_set(content)?; // digestAlgorithms
            let encap_content = Self::parse_encap_content_info(content)?;
            let cert = Self::parse_certificates(content)?;
            let signer_info = SignerInfo::parse_set(content)?;
            Ok(RouteOriginAttestation {
                encap_content, cert, signer_info
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
    fn parse_encap_content_info(
        content: &mut Content<'a>
    ) -> Result<OctetString<'a>, Error> {
        content.sequence(|content| {
            oid::ROUTE_ORIGIN_AUTHZ.skip_if(content)?;
            //content.constructed_if(Tag::CTX_CON_0, Content::into_input)
            content.constructed_if(Tag::CTX_CON_0, OctetString::parse)
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
    fn parse_certificates(
        content: &mut Content<'a>
    ) -> Result<x509::Cert<'a>, Error> {
        content.constructed_if(Tag::CTX_CON_0, |content| {
            content.constructed(|tag, content| {
                match tag {
                    Tag::SEQUENCE =>  x509::Cert::parse_content(content),
                    _ => Err(Error::Unimplemented)
                }
            })
        })
    }

    pub fn verify_signature(&self) -> Result<(), Error> {
        let digest = self.encap_content.sha256();
        if digest.as_ref() != self.signer_info.message_digest() {
            return Err(Error::Malformed)
        }
        let msg = self.signer_info.signed_attrs.encode_verify();
        ::ring::signature::verify(
            &::ring::signature::RSA_PKCS1_2048_8192_SHA256,
            self.cert.public_key(),
            Input::from(&msg),
            self.signer_info.signature_value.clone()
        ).map_err(|_| Error::Malformed)
    }
}


//------------ DigestAlgorithm -----------------------------------------------

#[derive(Clone, Debug)]
pub enum DigestAlgorithm {
    Sha256,
}


impl DigestAlgorithm {
    pub fn parse(content: &mut Content) -> Result<Self, Error> {
        content.sequence(Self::parse_content)
    }

    pub fn parse_opt(content: &mut Content) -> Result<Option<Self>, Error> {
        content.opt_sequence(Self::parse_content)
    }

    fn parse_content(content: &mut Content) -> Result<Self, Error> {
        oid::SHA256.skip_if(content)?;
        content.skip_opt_null()?;
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
    pub fn skip_set(content: &mut Content) -> Result<(), Error> {
        content.constructed_if(Tag::SET, |content| {
            while let Some(_) = Self::parse_opt(content)? { }
            Ok(())
        })
    }
}


//------------ SignerInfo ----------------------------------------------------

#[derive(Clone, Debug)]
pub struct SignerInfo<'a> {
    sid: Input<'a>,
    digest_algorithm: DigestAlgorithm,
    signed_attrs: SignedAttributes<'a>,
    signature_algorithm: SignatureAlgorithm,
    signature_value: Input<'a>,
}

impl<'a> SignerInfo<'a> {
    pub fn parse_set(content: &mut Content<'a>) -> Result<Self, Error> {
        content.set(Self::parse)
    }

    pub fn parse(content: &mut Content<'a>) -> Result<Self, Error> {
        content.sequence(|content| {
            content.skip_u8_if(3)?;
            Ok(SignerInfo {
                sid: content.octet_string_if(Tag::CTX_0)?,
                digest_algorithm: DigestAlgorithm::parse(content)?,
                signed_attrs: SignedAttributes::parse(content)?,
                signature_algorithm: SignatureAlgorithm::parse(content)?,
                signature_value: content.octet_string()?,
            })
        })
    }

    pub fn message_digest(&self) -> &[u8] {
        self.signed_attrs.message_digest.as_slice_less_safe()
    }
}


//------------ SignedAttributes ----------------------------------------------

#[derive(Clone, Debug)]
pub struct SignedAttributes<'a> {
    raw: Input<'a>,
    message_digest: Input<'a>,
    content_type: Oid<'a>,
    signing_time: Option<Time>,
    binary_signing_time: Option<u64>,
}

impl<'a> SignedAttributes<'a> {
    pub fn parse(content: &mut Content<'a>) -> Result<Self, Error> {
        /*
        let raw = content.value_as_input()?;
        Content::parse(raw.clone(), |content| {
            let parts = content.constructed_if(Tag::CTX_CON_0, |content| {
        */
        let raw = content.constructed_if(Tag::CTX_CON_0, Content::into_input)?;
        Content::parse(raw.clone(), |content| {
                let mut message_digest = None;
                let mut content_type = None;
                let mut signing_time = None;
                let mut binary_signing_time = None;
                while let Some(()) = content.opt_sequence(|content| {
                    match Oid::parse(content)? {
                        oid::CONTENT_TYPE => {
                            if content_type.is_some() {
                                return Err(Error::Malformed)
                            }
                            content_type
                                = Some(Self::parse_content_type(content)?);
                        }
                        oid::MESSAGE_DIGEST => {
                            if message_digest.is_some() {
                                return Err(Error::Malformed)
                            }
                            message_digest
                                = Some(Self::parse_message_digest(content)?);
                        }
                        oid::SIGNING_TIME => {
                            if signing_time.is_some() {
                                return Err(Error::Malformed)
                            }
                            signing_time
                                = Some(Self::parse_signing_time(content)?);
                        }
                        oid::AA_BINARY_SIGNING_TIME => {
                            if binary_signing_time.is_some() {
                                return Err(Error::Malformed)
                            }
                            binary_signing_time
                                = Some(Self::parse_bin_signing_time(content)?);
                        }
                        _ => return Err(Error::Malformed)
                    }
                    Ok(())
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
            /*
                Ok((
                   message_digest,
                   content_type,
                   signing_time,
                   binary_signing_time
                ))
            })?;
            Ok(SignedAttributes {
                raw,
                message_digest: parts.0,
                content_type: parts.1,
                signing_time: parts.2,
                binary_signing_time: parts.3
            })
            */
        })
    }

    fn parse_content_type(
        content: &mut Content<'a>
    ) -> Result<Oid<'a>, Error> {
        content.set(|content| {
            Oid::parse(content)
        })
    }

    fn parse_message_digest(
        content: &mut Content<'a>
    ) -> Result<Input<'a>, Error> {
        content.set(|content| {
            content.octet_string()
        })
    }

    fn parse_signing_time(content: &mut Content<'a>) -> Result<Time, Error> {
        content.set(Time::parse)
    }

    fn parse_bin_signing_time(
        content: &mut Content<'a>
    ) -> Result<u64, Error> {
        content.set(Content::parse_u64)
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
        res.extend_from_slice(self.raw.as_slice_less_safe());
        res
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
        let oid = Oid::parse(content)?;
        if oid != oid::RSA_ENCRYPTION &&
            oid != oid::SHA256_WITH_RSA_ENCRYPTION
        {
            return Err(Error::Malformed)
        }
        content.skip_opt_null()?;
        Ok(SignatureAlgorithm::Sha256WithRsaEncryption)
    }
}


//------------ OIDs ----------------------------------------------------------

mod oid {
    use ::ber::Oid;

    pub const SIGNED_DATA: Oid = Oid(&[42, 134, 72, 134, 247, 13, 1, 7, 2]);
    pub const SHA256: Oid = Oid(&[96, 134, 72, 1, 101, 3, 4, 2, 1]);
    pub const ROUTE_ORIGIN_AUTHZ: Oid
        = Oid(&[42, 134, 72, 134, 247, 13, 1, 9, 16, 1, 24]);
    pub const RSA_ENCRYPTION: Oid
        = Oid(&[42, 134, 72, 134, 247, 13, 1, 1, 1]);
    pub const SHA256_WITH_RSA_ENCRYPTION: Oid
        = Oid(&[42, 134, 72, 134, 247, 13, 1, 1, 11]);

    pub const CONTENT_TYPE: Oid = Oid(&[42, 134, 72, 134, 247, 13, 1, 9, 3]);
    pub const MESSAGE_DIGEST: Oid = Oid(&[42, 134, 72, 134, 247, 13, 1, 9, 4]);
    pub const SIGNING_TIME: Oid = Oid(&[42, 134, 72, 134, 247, 13, 1, 9, 5]);
    pub const AA_BINARY_SIGNING_TIME: Oid =
        Oid(&[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 46]);
}

