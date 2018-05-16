
use std::str;
use std::str::FromStr;
use chrono::{DateTime, LocalResult, TimeZone, Utc};
use untrusted::{Input, Reader};
use ::ber::{BitString, Content, Error, OctetString, Oid, Tag};


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

    pub fn subject_key_identifier(&self) -> OctetString<'a> {
        unimplemented!()
    }
}


//------------ TbsCertificate ------------------------------------------------

/// The signed part of a certificate.
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
        // XXX RFC 5280 demands the signed part to be DER encoded. Enforce
        //     this.
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


//------------ Extensions ----------------------------------------------------

#[derive(Clone, Debug)]
#[allow(dead_code)] // XXX
pub struct Extensions<'a> {
    /// Basic Contraints.
    ///
    /// The field indicates whether the extension is present and, if so,
    /// whether the "cA" boolean is set. See 4.8.1. of RFC 6487.
    basic_ca: Option<bool>,

    /// Subject Key Identifier.
    subject_key_id: Input<'a>,

    /// Authority Key Identifier
    authority_key_id: Option<Input<'a>>,

    /// Key Usage.
    ///
    key_usage_ca: bool,

    /// Extended Key Usage.
    ///
    /// The valud is the content of the DER-encoded sequence of object
    /// identifiers.
    extended_key_usage: Option<Input<'a>>,

    /// CRL Distribution Points
    crl_distribution: Option<UriGeneralNames<'a>>,

    /// Authority Information Access
    authority_info_access: Option<UriGeneralName<'a>>,

    /// Subject Information Access
    ///
    /// This value contains the content of the SubjectInfoAccessSyntax
    /// sequence.
    subject_info_access: Input<'a>,

    /// Certificate Policies
    ///
    /// Must be present and critical. RFC 6484 describes the policies for
    /// PKIX certificates. This value contains the content of the
    /// certificatePolicies sequence.
    certificate_policies: CertificatePolicies<'a>,

    /// Resources
    resources: Resources<'a>,
}

impl<'a> Extensions<'a> {
    pub fn parse(content: &mut Content<'a>) -> Result<Self, Error> {
        content.sequence(|content| {
            let mut basic_ca = None;
            let mut subject_key_id = None;
            let mut authority_key_id = None;
            let mut key_usage_ca = None;
            let mut extended_key_usage = None;
            let mut crl_distribution = None;
            let mut authority_info_access = None;
            let mut subject_info_access = None;
            let mut certificate_policies = None;
            let mut resources = None;
            while let Some(()) = content.opt_sequence(|content| {
                let id = Oid::parse(content)?;
                let critical = content.parse_opt_bool()?.unwrap_or(false);
                Content::parse(content.octet_string()?, |content| {
                    match id {
                        oid::CE_BASIC_CONSTRAINTS => {
                            Self::parse_basic_ca(content, &mut basic_ca)
                        }
                        oid::CE_SUBJECT_KEY_IDENTIFIER => {
                            Self::parse_subject_key_identifier(
                                content, &mut subject_key_id
                            )
                        }
                        oid::CE_AUTHORITY_KEY_IDENTIFIER => {
                            Self::parse_authority_key_identifier(
                                content, &mut authority_key_id
                            )
                        }
                        oid::CE_KEY_USAGE => {
                            Self::parse_key_usage(content, &mut key_usage_ca)
                        }
                        oid::CE_EXTENDED_KEY_USAGE => {
                            Self::parse_extended_key_usage(
                                content, &mut extended_key_usage
                            )
                        }
                        oid::CE_CRL_DISTRIBUTION_POINTS => {
                            Self::parse_crl_distribution_points(
                                content, &mut crl_distribution
                            )
                        }
                        oid::PE_AUTHORITY_INFO_ACCESS => {
                            Self::parse_authority_info_access(
                                content, &mut authority_info_access
                            )
                        }
                        oid::PE_SUBJECT_INFO_ACCESS => {
                            Self::parse_subject_info_access(
                                content, &mut subject_info_access
                            )
                        }
                        oid::CE_CERTIFICATE_POLICIES => {
                            Self::parse_certificate_policies(
                                content, &mut certificate_policies
                            )
                        }
                        oid::PE_IP_ADDR_BLOCK => {
                            Self::parse_ip_resources(content, &mut resources)
                        }
                        oid::PE_AUTONOMOUS_SYS_IDS => {
                            Self::parse_as_resources(content, &mut resources)
                        }
                        _ => {
                            if critical {
                                Err(Error::Malformed)
                            }
                            else {
                                // RFC 5280 says we can ignore non-critical
                                // extensions we don’t know of. RFC 6487
                                // agrees. So let’s do that.
                                Ok(())
                            }
                        }
                    }
                })?;
                Ok(())
            })? { }
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
                resources: resources.ok_or(Error::Malformed)?,
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
    fn parse_basic_ca(
        content: &mut Content<'a>, basic_ca: &mut Option<bool>
    ) -> Result<(), Error> {
        update_once(basic_ca, || {
            match content.sequence(Content::parse_opt_bool)? {
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
    fn parse_subject_key_identifier(
        content: &mut Content<'a>, subject_key_id: &mut Option<Input<'a>>
    ) -> Result<(), Error> {
        update_once(subject_key_id, || {
            let id = content.octet_string()?;
            if id.len() != 20 {
                Err(Error::Malformed)
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
    fn parse_authority_key_identifier(
        content: &mut Content<'a>, authority_key_id: &mut Option<Input<'a>>
    ) -> Result<(), Error> {
        update_once(authority_key_id, || {
            let res = content.sequence(Content::octet_string)?;
            if res.len() != 20 {
                return Err(Error::Malformed)
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
    fn parse_key_usage(
        content: &mut Content<'a>, key_usage_ca: &mut Option<bool>
    ) -> Result<(), Error> {
        update_once(key_usage_ca, || {
            let bits = BitString::parse(content)?;
            if bits.bit(5) && bits.bit(6) {
                Ok(true)
            }
            else if bits.bit(0) {
                Ok(false)
            }
            else {
                Err(Error::Malformed)
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
    fn parse_extended_key_usage(
        content: &mut Content<'a>,
        extended_key_usage: &mut Option<Input<'a>>
    ) -> Result<(), Error> {
        update_once(extended_key_usage, || {
            let res = content.sequence(Content::into_input)?;
            Content::parse(res.clone(), |content| {
                let _ = Oid::parse(content)?;
                while let Some(_) = Oid::opt_parse(content)? { }
                Ok(res)
            })
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
    fn parse_crl_distribution_points(
        content: &mut Content<'a>,
        crl_distribution: &mut Option<UriGeneralNames<'a>>
    ) -> Result<(), Error> {
        update_once(crl_distribution, || {
            content.sequence(|content| {
                content.sequence(|content| {
                    content.constructed_if(Tag::CTX_CON_0, |content| {
                        content.constructed_if(Tag::CTX_CON_0, |content| {
                            UriGeneralNames::parse(content)
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
    fn parse_authority_info_access(
        content: &mut Content<'a>,
        authority_info_access: &mut Option<UriGeneralName<'a>>
    ) -> Result<(), Error> {
        update_once(authority_info_access, || {
            content.sequence(|content| {
                content.sequence(|content| {
                    oid::AD_CA_ISSUERS.skip_if(content)?;
                    UriGeneralName::parse(content)
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
    /// we may accept the wrong kind here. This needs to be check later.
    fn parse_subject_info_access(
        content: &mut Content<'a>,
        subject_info_access: &mut Option<Input<'a>>,
    ) -> Result<(), Error> {
        update_once(subject_info_access, || {
            let res = content.sequence(Content::into_input)?;
            Content::parse(res.clone(), |content| {
                let mut ca = None;
                while let Some(()) = content.opt_sequence(|content| {
                    let oid = Oid::parse(content)?;
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
                    let _ = UriGeneralName::parse(content)?;
                    Ok(())
                })? { }
                if ca.is_none() {
                    // The sequence was empty.
                    Err(Error::Malformed)
                }
                else {
                    Ok(res)
                }
            })
        })
    }

    /// Parses the Certificate Policies extension.
    ///
    /// Must be present.
    fn parse_certificate_policies(
        content: &mut Content<'a>,
        certificate_policies: &mut Option<CertificatePolicies<'a>>,
    ) -> Result<(), Error> {
        update_once(certificate_policies, || {
            CertificatePolicies::parse(content)
        })
    }

    /// Parses the IP Resources extension.
    fn parse_ip_resources(
        content: &mut Content<'a>,
        resources: &mut Option<Resources<'a>>
    ) -> Result<(), Error> {
        update_once(resources, || {
            IpResources::parse(content).map(Resources::Ip)
        })
    }

    /// Parses the AS Resources extension.
    fn parse_as_resources(
        content: &mut Content<'a>,
        resources: &mut Option<Resources<'a>>
    ) -> Result<(), Error> {
        update_once(resources, || {
            AsResources::parse(content).map(Resources::As)
        })
    }
}

fn update_once<F, T>(opt: &mut Option<T>, op: F) -> Result<(), Error>
where F: FnOnce() -> Result<T, Error> {
    if opt.is_some() {
        Err(Error::Malformed)
    }
    else {
        *opt = Some(op()?);
        Ok(())
    }
}


//------------ URIGeneralNames -----------------------------------------------

/// A GeneralNames value limited to uniformResourceIdentifier choices.
#[derive(Clone, Debug)]
pub struct UriGeneralNames<'a>(Input<'a>);

impl<'a> UriGeneralNames<'a> {
    /// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
    ///
    /// GeneralName ::= CHOICE {
    ///    ...
    ///    uniformResourceIdentifier       [6]     IA5String,
    ///    ... }
    /// ```
    fn parse(content: &mut Content<'a>) -> Result<Self, Error> {
        let res = content.sequence(Content::into_input)?;
        Content::parse(res.clone(), |content| {
            let _ = UriGeneralName::parse(content)?;
            while let Some(_) = UriGeneralName::opt_parse(content)? { }
            Ok(UriGeneralNames(res))
        })
    }
}


//------------ UriGeneralName ------------------------------------------------

#[derive(Clone, Debug)]
pub struct UriGeneralName<'a>(Input<'a>);

impl<'a> UriGeneralName<'a> {
    fn parse(content: &mut Content<'a>) -> Result<Self, Error> {
        content.primitive_if(Tag::CTX_6, |input| {
            if input.as_slice_less_safe().is_ascii() {
                Ok(UriGeneralName(input))
            }
            else {
                Err(Error::Malformed)
            }
        })
    }

    fn opt_parse(content: &mut Content<'a>) -> Result<Option<Self>, Error> {
        content.opt_primitive_if(Tag::CTX_6, |input| {
            if input.as_slice_less_safe().is_ascii() {
                Ok(UriGeneralName(input))
            }
            else {
                Err(Error::Malformed)
            }
        })
    }
}


//------------ CertificatePolicies -------------------------------------------

#[derive(Clone, Debug)]
pub struct CertificatePolicies<'a>(Input<'a>);

impl<'a> CertificatePolicies<'a> {
    fn parse(content: &mut Content<'a>) -> Result<Self, Error> {
        // XXX TODO Actually parse the whole thing.
        content.sequence(Content::into_input).map(CertificatePolicies)
    }
}


//------------ Resources -----------------------------------------------------

#[derive(Clone, Debug)]
pub enum Resources<'a> {
    Ip(IpResources<'a>),
    As(AsResources<'a>)
}


//------------ IpResources ---------------------------------------------------

#[derive(Clone, Debug)]
pub struct IpResources<'a>(Input<'a>);

impl<'a> IpResources<'a> {
    fn parse(content: &mut Content<'a>) -> Result<Self, Error> {
        // XXX TODO Parse properly.
        content.sequence(Content::into_input).map(IpResources)
    }
}


//------------ AsResources ---------------------------------------------------

#[derive(Clone, Debug)]
pub struct AsResources<'a>(Input<'a>);

impl<'a> AsResources<'a> {
    fn parse(content: &mut Content<'a>) -> Result<Self, Error> {
        // XXX TODO Parse properly.
        content.sequence(Content::into_input).map(AsResources)
    }
}


//------------ OIDs ----------------------------------------------------------

mod oid {
    use ::ber::Oid;

    pub const RSA_ENCRYPTION: Oid
        = Oid(&[42, 134, 72, 134, 247, 13, 1, 1, 1]);
    pub const SHA256_WITH_RSA_ENCRYPTION: Oid
        = Oid(&[42, 134, 72, 134, 247, 13, 1, 1, 11]);

    pub const AD_CA_ISSUERS: Oid = Oid(&[43, 6, 1, 5, 5, 7, 48, 2]);
    pub const AD_CA_REPOSITORY: Oid = Oid(&[43, 6, 1, 5, 5, 7, 48, 5]);
    pub const AD_RPKI_MANIFEST: Oid = Oid(&[43, 6, 1, 5, 5, 7, 48, 10]);
    pub const AD_SIGNED_OBJECT: Oid = Oid(&[43, 6, 1, 5, 5, 7, 48, 11]);
    pub const CE_SUBJECT_KEY_IDENTIFIER: Oid = Oid(&[85, 29, 14]);
    pub const CE_KEY_USAGE: Oid = Oid(&[85, 29, 15]);
    pub const CE_BASIC_CONSTRAINTS: Oid = Oid(&[85, 29, 19]);
    pub const CE_CRL_DISTRIBUTION_POINTS: Oid = Oid(&[85, 29, 31]);
    pub const CE_CERTIFICATE_POLICIES: Oid = Oid(&[85, 29, 32]);
    pub const CE_AUTHORITY_KEY_IDENTIFIER: Oid = Oid(&[85, 29, 35]);
    pub const CE_EXTENDED_KEY_USAGE: Oid = Oid(&[85, 29, 37]);
    pub const PE_AUTHORITY_INFO_ACCESS: Oid = Oid(&[43, 6, 1, 5, 5, 7, 1, 1]);
    pub const PE_IP_ADDR_BLOCK: Oid = Oid(&[43, 6, 1, 5, 5, 7, 1, 7]);
    pub const PE_AUTONOMOUS_SYS_IDS: Oid = Oid(&[43, 6, 1, 5, 5, 7, 1, 8]);
    pub const PE_SUBJECT_INFO_ACCESS: Oid = Oid(&[43, 6, 1, 5, 5, 7, 1, 11]);
}

