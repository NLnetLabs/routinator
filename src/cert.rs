
use bytes::Bytes;
use super::asres::AsIdentifiers;
use super::ber::{
    BitString, Constructed, Error, Mode, OctetString, Oid, Source, Tag
};
use super::ipres::IpAddrBlocks;
use super::x509::{
    update_once, Name, SerialNumber, SignatureAlgorithm, SignedData, Time
};


//------------ Cert ----------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Cert {
    signed_data: SignedData,

    serial_number: SerialNumber,
    signature: SignatureAlgorithm,
    issuer: Name,
    validity: Validity,
    subject: Name,
    subject_public_key_info: SubjectPublicKeyInfo,
    issuer_unique_id: Option<BitString>,
    subject_unique_id: Option<BitString>,
    extensions: Extensions,
}

impl Cert {
    pub fn decode<S: Source>(source: S) -> Result<Self, S::Err> {
        Mode::Der.decode(source, Self::take_from)
    }

    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.sequence(Self::take_content_from)
    }

    /// Parses the content of a Certificate sequence.
    pub fn take_content_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        let signed_data = SignedData::take_content_from(cons)?;

        Mode::Der.decode(signed_data.data().clone(), |cons| {
            cons.sequence(|cons| {
                // version [0] EXPLICIT Version DEFAULT v1.
                //  -- we need extensions so apparently, we want v3 which,
                //     confusingly, is 2.
                cons.constructed_if(Tag::CTX_0, |c| c.skip_u8_if(2))?;

                Ok(Cert {
                    signed_data,
                    serial_number: SerialNumber::take_from(cons)?,
                    signature: SignatureAlgorithm::take_from(cons)?,
                    issuer: Name::take_from(cons)?,
                    validity: Validity::take_from(cons)?,
                    subject: Name::take_from(cons)?,
                    subject_public_key_info: 
                        SubjectPublicKeyInfo::take_from(cons)?,
                    issuer_unique_id: cons.opt_value_if(
                        Tag::CTX_1,
                        |c| BitString::parse_content(c)
                    )?,
                    subject_unique_id: cons.opt_value_if(
                        Tag::CTX_2,
                        |c| BitString::parse_content(c)
                    )?,
                    extensions: cons.constructed_if(
                        Tag::CTX_3,
                        Extensions::take_from
                    )?,
                })
            })
        }).map_err(Into::into)
    }

    pub fn public_key(&self) -> BitString {
        self.subject_public_key_info
            .subject_public_key.clone()
    }

    /*
    pub fn public_key_components(
        &self
    ) -> Result<(Input<'a>, Input<'a>), Error> {
        self.subject_public_key_info.public_key_components()
    }
    */

    pub fn subject_key_identifier(&self) -> &OctetString {
        &self.extensions.subject_key_id
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

    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.sequence(|cons| {
            Ok(Validity::new(
                Time::take_from(cons)?,
                Time::take_from(cons)?,
            ))
        })
    }
}


//------------ SubjectPublicKeyInfo ------------------------------------------

#[derive(Clone, Debug)]
pub struct SubjectPublicKeyInfo {
    algorithm: PublicKeyAlgorithm,
    subject_public_key: BitString,
}

impl SubjectPublicKeyInfo {
    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.sequence(|cons| {
            Ok(SubjectPublicKeyInfo {
                algorithm: PublicKeyAlgorithm::take_from(cons)?,
                subject_public_key: BitString::take_from(cons)?
            })
        })
    }

    /*
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
    */
}


//------------ PublicKeyAlgorithm --------------------------------------------

#[derive(Clone, Debug)]
pub enum PublicKeyAlgorithm {
    RsaEncryption,
}

impl PublicKeyAlgorithm {
    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.sequence(Self::take_content_from)
    }

    pub fn take_content_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        oid::RSA_ENCRYPTION.skip_if(cons)?;
        cons.skip_opt_null()?;
        Ok(PublicKeyAlgorithm::RsaEncryption)
    }
}


//------------ Extensions ----------------------------------------------------

#[derive(Clone, Debug)]
pub struct Extensions {
    /// Basic Contraints.
    ///
    /// The field indicates whether the extension is present and, if so,
    /// whether the "cA" boolean is set. See 4.8.1. of RFC 6487.
    basic_ca: Option<bool>,

    /// Subject Key Identifier.
    subject_key_id: OctetString,

    /// Authority Key Identifier
    authority_key_id: Option<OctetString>,

    /// Key Usage.
    ///
    key_usage_ca: bool,

    /// Extended Key Usage.
    ///
    /// The valud is the content of the DER-encoded sequence of object
    /// identifiers.
    extended_key_usage: Option<Bytes>,

    /// CRL Distribution Points
    crl_distribution: Option<UriGeneralNames>,

    /// Authority Information Access
    authority_info_access: Option<UriGeneralName>,

    /// Subject Information Access
    ///
    /// This value contains the content of the SubjectInfoAccessSyntax
    /// sequence.
    subject_info_access: Bytes,

    /// Certificate Policies
    ///
    /// Must be present and critical. RFC 6484 describes the policies for
    /// PKIX certificates. This value contains the content of the
    /// certificatePolicies sequence.
    certificate_policies: CertificatePolicies,

    /// IP Resources
    ip_resources: Option<IpAddrBlocks>,

    /// AS Resources
    as_resources: Option<AsIdentifiers>,
}

impl Extensions {
    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.sequence(|cons| {
            let mut basic_ca = None;
            let mut subject_key_id = None;
            let mut authority_key_id = None;
            let mut key_usage_ca = None;
            let mut extended_key_usage = None;
            let mut crl_distribution = None;
            let mut authority_info_access = None;
            let mut subject_info_access = None;
            let mut certificate_policies = None;
            let mut ip_resources = None;
            let mut as_resources = None;
            while let Some(()) = cons.opt_sequence(|cons| {
                let id = Oid::take_from(cons)?;
                let critical = cons.take_opt_bool()?.unwrap_or(false);
                let value = OctetString::take_from(cons)?;
                Mode::Der.decode(value.as_source(), |content| {
                    if id == oid::CE_BASIC_CONSTRAINTS {
                        Self::take_basic_ca(content, &mut basic_ca)
                    }
                    else if id == oid::CE_SUBJECT_KEY_IDENTIFIER {
                        Self::take_subject_key_identifier(
                            content, &mut subject_key_id
                        )
                    }
                    else if id == oid::CE_AUTHORITY_KEY_IDENTIFIER {
                        Self::take_authority_key_identifier(
                            content, &mut authority_key_id
                        )
                    }
                    else if id == oid::CE_KEY_USAGE {
                        Self::take_key_usage(
                            content, &mut key_usage_ca
                        )
                    }
                    else if id == oid::CE_EXTENDED_KEY_USAGE {
                        Self::take_extended_key_usage(
                            content, &mut extended_key_usage
                        )
                    }
                    else if id == oid::CE_CRL_DISTRIBUTION_POINTS {
                        Self::take_crl_distribution_points(
                            content, &mut crl_distribution
                        )
                    }
                    else if id == oid::PE_AUTHORITY_INFO_ACCESS {
                        Self::take_authority_info_access(
                            content, &mut authority_info_access
                        )
                    }
                    else if id == oid::PE_SUBJECT_INFO_ACCESS {
                        Self::take_subject_info_access(
                            content, &mut subject_info_access
                        )
                    }
                    else if id == oid::CE_CERTIFICATE_POLICIES {
                        Self::take_certificate_policies(
                            content, &mut certificate_policies
                        )
                    }
                    else if id == oid::PE_IP_ADDR_BLOCK {
                        Self::take_ip_resources(
                            content, &mut ip_resources
                        )
                    }
                    else if id == oid::PE_AUTONOMOUS_SYS_IDS {
                        Self::take_as_resources(
                            content, &mut as_resources
                        )
                    }
                    else if critical {
                        xerr!(Err(Error::Malformed))
                    }
                    else {
                        // RFC 5280 says we can ignore non-critical
                        // extensions we don’t know of. RFC 6487
                        // agrees. So let’s do that.
                        Ok(())
                    }
                })?;
                Ok(())
            })? { }
            if ip_resources.is_none() && as_resources.is_none() {
                xerr!(return Err(Error::Malformed.into()))
            }
            Ok(Extensions {
                basic_ca,
                subject_key_id: subject_key_id.ok_or(Error::Malformed)?,
                authority_key_id,
                key_usage_ca: key_usage_ca.ok_or(Error::Malformed)?,
                extended_key_usage,
                crl_distribution,
                authority_info_access,
                subject_info_access:
                    subject_info_access.ok_or(Error::Malformed)?,
                certificate_policies:
                    certificate_policies.ok_or(Error::Malformed)?,
                ip_resources,
                as_resources,
            })
        })
    }

    /// Parses the Basic Constraints Extension.
    ///
    /// The extension must be present in CA certificates and must not be
    /// present in EE certificats.
    ///
    /// ```text
    ///   BasicConstraints ::= SEQUENCE {
    ///        cA                      BOOLEAN DEFAULT FALSE,
    ///        pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
    /// ```
    ///
    /// The cA field gets chosen by the CA. The pathLenConstraint field must
    /// not be present.
    fn take_basic_ca<S: Source>(
        cons: &mut Constructed<S>,
        basic_ca: &mut Option<bool>
    ) -> Result<(), S::Err> {
        update_once(basic_ca, || {
            match cons.sequence(|cons| cons.take_opt_bool())? {
                Some(res) => Ok(res),
                None => Ok(false)
            }
        })
    }

    /// Parses the Subject Key Identifier Extension.
    ///
    /// The extension must be present and contain the 160 bit SHA-1 hash of
    /// the value of the DER-encoded bit string of the subject public key. 
    ///
    /// ```text
    /// SubjectKeyIdentifier ::= KeyIdentifier
    /// KeyIdentifier        ::= OCTET STRING
    /// ```
    fn take_subject_key_identifier<S: Source>(
        cons: &mut Constructed<S>,
        subject_key_id: &mut Option<OctetString>
    ) -> Result<(), S::Err> {
        update_once(subject_key_id, || {
            let id = OctetString::take_from(cons)?;
            if id.len() != 20 {
                xerr!(Err(Error::Malformed.into()))
            }
            else {
                Ok(id)
            }
        })
    }

    /// Parses the Authority Key Identifier Extension.
    ///
    /// Must be present except in self-signed CA certificates where it is
    /// optional.
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
    /// Only keyIdentifier must be present.
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

    /// Parses the Key Usage extension.
    ///
    /// ```text
    /// KeyUsage ::= BIT STRING {
    ///      digitalSignature        (0),
    ///      nonRepudiation          (1), -- recent editions of X.509 have
    ///                           -- renamed this bit to contentCommitment
    ///      keyEncipherment         (2),
    ///      dataEncipherment        (3),
    ///      keyAgreement            (4),
    ///      keyCertSign             (5),
    ///      cRLSign                 (6),
    ///      encipherOnly            (7),
    ///      decipherOnly            (8) }
    ///
    /// Must be present. In CA certificates, keyCertSign and
    /// CRLSign must be set, in EE certificates, digitalSignatures must be
    /// set. This field therefore simply describes whether the certificate
    /// is for a CA.
    fn take_key_usage<S: Source>(
        cons: &mut Constructed<S>,
        key_usage_ca: &mut Option<bool>
    ) -> Result<(), S::Err> {
        update_once(key_usage_ca, || {
            let bits = BitString::take_from(cons)?;
            if bits.bit(5) && bits.bit(6) {
                Ok(true)
            }
            else if bits.bit(0) {
                Ok(false)
            }
            else {
                Err(Error::Malformed.into())
            }
        })
    }

    /// Parses the Extended Key Usage extension.
    ///
    /// ```text
    /// ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
    /// KeyPurposeId ::= OBJECT IDENTIFIER
    /// ```
    ///
    /// May only be present in EE certificates issued to devices.
    fn take_extended_key_usage<S: Source>(
        cons: &mut Constructed<S>,
        extended_key_usage: &mut Option<Bytes>
    ) -> Result<(), S::Err> {
        update_once(extended_key_usage, || {
            let res = cons.sequence(|c| c.take_all())?;
            Mode::Der.decode(res.clone(), |cons| {
                Oid::skip_in(cons)?;
                while let Some(_) = Oid::skip_opt_in(cons)? { }
                Ok(res)
            }).map_err(Into::into)
        })
    }

    /// Parses the CRL Distribution Points extension.
    ///
    /// ```text
    /// CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
    ///
    /// DistributionPoint ::= SEQUENCE {
    ///    distributionPoint       [0]     DistributionPointName OPTIONAL,
    ///    reasons                 [1]     ReasonFlags OPTIONAL,
    ///    cRLIssuer               [2]     GeneralNames OPTIONAL }
    ///
    /// DistributionPointName ::= CHOICE {
    ///    fullName                [0]     GeneralNames,
    ///    nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
    /// ```
    ///
    /// Must be present except in self-signed certificates.
    ///
    /// It must contain exactly one Distribution Point. Only its
    /// distributionPoint field must be present and it must contain
    /// the fullName choice which can be one or more uniformResourceIdentifier
    /// choices.
    fn take_crl_distribution_points<S: Source>(
        cons: &mut Constructed<S>,
        crl_distribution: &mut Option<UriGeneralNames>
    ) -> Result<(), S::Err> {
        update_once(crl_distribution, || {
            cons.sequence(|cons| {
                cons.sequence(|cons| {
                    cons.constructed_if(Tag::CTX_0, |cons| {
                        cons.constructed_if(Tag::CTX_0, |cons| {
                            UriGeneralNames::take_content_from(cons)
                        })
                    })
                })
            })
        })
    }

    /// Parses the Authority Information Access extension.
    ///
    /// ```text
    /// AuthorityInfoAccessSyntax  ::=
    ///         SEQUENCE SIZE (1..MAX) OF AccessDescription
    ///
    /// AccessDescription  ::=  SEQUENCE {
    ///         accessMethod          OBJECT IDENTIFIER,
    ///         accessLocation        GeneralName  }
    /// ```
    ///
    /// Must be present except in self-signed certificates. Must contain
    /// exactly one entry with accessMethod id-ad-caIssuers and a URI as a
    /// generalName.
    fn take_authority_info_access<S: Source>(
        cons: &mut Constructed<S>,
        authority_info_access: &mut Option<UriGeneralName>
    ) -> Result<(), S::Err> {
        update_once(authority_info_access, || {
            cons.sequence(|cons| {
                cons.sequence(|cons| {
                    oid::AD_CA_ISSUERS.skip_if(cons)?;
                    UriGeneralName::take_from(cons)
                })
            })
        })
    }

    /// Parses the Subject Information Access extension.
    ///
    /// ```text
    /// SubjectInfoAccessSyntax  ::=
    ///         SEQUENCE SIZE (1..MAX) OF AccessDescription
    ///
    /// AccessDescription  ::=  SEQUENCE {
    ///         accessMethod          OBJECT IDENTIFIER,
    ///         accessLocation        GeneralName  }
    /// ```
    ///
    /// Must be present.
    ///
    /// For CA certificates, there must be two AccessDescriptions, one with
    /// id-ad-caRepository and one with id-ad-rpkiManifest, both with rsync
    /// URIs. Additional id-ad-rpkiManifest descriptions may be present with
    /// additional access mechanisms for the manifest.
    ///
    /// For EE certificates, there must at least one AccessDescription value
    /// with an id-ad-signedObject access method.
    ///
    /// Since we don’t necessarily know what kind of certificate we have yet,
    /// we may accept the wrong kind here. This needs to be checked later.
    fn take_subject_info_access<S: Source>(
        cons: &mut Constructed<S>,
        subject_info_access: &mut Option<Bytes>,
    ) -> Result<(), S::Err> {
        update_once(subject_info_access, || {
            let res = cons.sequence(|cons| cons.take_all())?;
            Mode::Der.decode(res.clone(), |cons| {
                let mut ca = None;
                while let Some(()) = cons.opt_sequence(|cons| {
                    let oid = Oid::take_from(cons)?;
                    if oid == oid::AD_CA_REPOSITORY
                        || oid == oid::AD_RPKI_MANIFEST
                    {
                        match ca {
                            None => ca = Some(true),
                            Some(true) => { }
                            Some(false) => {
                                return Err(Error::Malformed)
                            }
                        }
                    }
                    else if oid == oid::AD_SIGNED_OBJECT {
                        match ca {
                            None => ca = Some(false),
                            Some(false) => { }
                            Some(true) => {
                                return Err(Error::Malformed)
                            }
                        }
                    }
                    let _ = UriGeneralName::take_from(cons)?;
                    Ok(())
                })? { }
                if ca.is_none() {
                    // The sequence was empty.
                    xerr!(Err(Error::Malformed))
                }
                else {
                    Ok(res)
                }
            }).map_err(Into::into)
        })
    }

    /// Parses the Certificate Policies extension.
    ///
    /// Must be present.
    fn take_certificate_policies<S: Source>(
        cons: &mut Constructed<S>,
        certificate_policies: &mut Option<CertificatePolicies>,
    ) -> Result<(), S::Err> {
        update_once(certificate_policies, || {
            CertificatePolicies::take_from(cons)
        })
    }

    /// Parses the IP Resources extension.
    fn take_ip_resources<S: Source>(
        cons: &mut Constructed<S>,
        ip_resources: &mut Option<IpAddrBlocks>
    ) -> Result<(), S::Err> {
        update_once(ip_resources, || {
            IpAddrBlocks::take_from(cons)
        })
    }

    /// Parses the AS Resources extension.
    fn take_as_resources<S: Source>(
        cons: &mut Constructed<S>,
        as_resources: &mut Option<AsIdentifiers>
    ) -> Result<(), S::Err> {
        update_once(as_resources, || {
            AsIdentifiers::take_from(cons)
        })
    }
}


//------------ URIGeneralNames -----------------------------------------------

/// A GeneralNames value limited to uniformResourceIdentifier choices.
#[derive(Clone, Debug)]
pub struct UriGeneralNames(Bytes);

impl<'a> UriGeneralNames {
    /// ```text
    /// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
    ///
    /// GeneralName ::= CHOICE {
    ///    ...
    ///    uniformResourceIdentifier       [6]     IA5String,
    ///    ... }
    /// ```
    fn take_content_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        Ok(UriGeneralNames(cons.capture(|cons| {
            if let None = UriGeneralName::skip_opt(cons)? {
                xerr!(return Err(Error::Malformed.into()))
            }
            while let Some(()) = UriGeneralName::skip_opt(cons)? { }
            Ok(())
        })?))
    }
}


//------------ UriGeneralName ------------------------------------------------

#[derive(Clone, Debug)]
pub struct UriGeneralName(Bytes);

impl UriGeneralName {
    fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.primitive_if(Tag::CTX_6, |prim| {
            let res = prim.take_all()?;
            if res.is_ascii() {
                Ok(UriGeneralName(res))
            }
            else {
                xerr!(Err(Error::Malformed.into()))
            }
        })
    }

    /*
    fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Option<Self>, S::Err> {
        cons.opt_primitive_if(Tag::CTX_6, |prim| {
            let res = prim.take_all()?;
            if res.is_ascii() {
                Ok(UriGeneralName(res))
            }
            else {
                xerr!(Err(Error::Malformed.into()))
            }
        })
    }
    */

    fn skip_opt<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Option<()>, S::Err> {
        cons.opt_primitive_if(Tag::CTX_6, |prim| {
            if prim.slice_all()?.is_ascii() {
                prim.skip_all()?;
                Ok(())
            }
            else {
                xerr!(Err(Error::Malformed.into()))
            }
        })
    }
}


//------------ CertificatePolicies -------------------------------------------

#[derive(Clone, Debug)]
pub struct CertificatePolicies(Bytes);

impl CertificatePolicies {
    fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        // XXX TODO Parse properly.
        cons.sequence(|c| c.take_all()).map(CertificatePolicies)
    }
}


//------------ OIDs ----------------------------------------------------------

#[allow(dead_code)] // XXX
mod oid {
    use ::ber::Oid;

    pub const RSA_ENCRYPTION: Oid<&[u8]>
        = Oid(&[42, 134, 72, 134, 247, 13, 1, 1, 1]);

    pub const AD_CA_ISSUERS: Oid<&[u8]> = Oid(&[43, 6, 1, 5, 5, 7, 48, 2]);
    pub const AD_CA_REPOSITORY: Oid<&[u8]> = Oid(&[43, 6, 1, 5, 5, 7, 48, 5]);
    pub const AD_RPKI_MANIFEST: Oid<&[u8]> = Oid(&[43, 6, 1, 5, 5, 7, 48, 10]);
    pub const AD_SIGNED_OBJECT: Oid<&[u8]> = Oid(&[43, 6, 1, 5, 5, 7, 48, 11]);
    pub const CE_SUBJECT_KEY_IDENTIFIER: Oid<&[u8]> = Oid(&[85, 29, 14]);
    pub const CE_KEY_USAGE: Oid<&[u8]> = Oid(&[85, 29, 15]);
    pub const CE_BASIC_CONSTRAINTS: Oid<&[u8]> = Oid(&[85, 29, 19]);
    pub const CE_CRL_DISTRIBUTION_POINTS: Oid<&[u8]> = Oid(&[85, 29, 31]);
    pub const CE_CERTIFICATE_POLICIES: Oid<&[u8]> = Oid(&[85, 29, 32]);
    pub const CE_AUTHORITY_KEY_IDENTIFIER: Oid<&[u8]> = Oid(&[85, 29, 35]);
    pub const CE_EXTENDED_KEY_USAGE: Oid<&[u8]> = Oid(&[85, 29, 37]);
    pub const PE_AUTHORITY_INFO_ACCESS: Oid<&[u8]>
        = Oid(&[43, 6, 1, 5, 5, 7, 1, 1]);
    pub const PE_IP_ADDR_BLOCK: Oid<&[u8]> = Oid(&[43, 6, 1, 5, 5, 7, 1, 7]);
    pub const PE_AUTONOMOUS_SYS_IDS: Oid<&[u8]>
        = Oid(&[43, 6, 1, 5, 5, 7, 1, 8]);
    pub const PE_SUBJECT_INFO_ACCESS: Oid<&[u8]>
        = Oid(&[43, 6, 1, 5, 5, 7, 1, 11]);
}

