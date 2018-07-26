//! RPKI Certificates.
//!
//! For its certificates, RPKI defines a profile for X.509 certificates. That
//! is, while it uses the format defined for X.509 certificates, it limits
//! the allowed values for various fields, making the overall structure more
//! simple and predictable.
//!
//! This module implements the raw certificates in the type [`Cert`] and
//! validated certificates in the type [`ResourceCert`]. The latter are used
//! as the issuer certificates when validating other certificates.
//!
//! In addition, there are several types for the components of a certificate.
//!
//! RPKI resource certificates are defined in RFC 6487 based on the Internet
//! PKIX profile defined in RFC 5280.
//!
//! [`Cert`]: struct.Cert.html
//! [`ResourceCert`]: struct.ResourceCert.html

use bytes::Bytes;
use ring::digest::{self, Digest};
use super::rsync;
use super::asres::{AsBlocks, AsResources};
use super::ber::{
    BitString, Constructed, Error, Mode, OctetString, Oid, Source, Tag,
    Unsigned
};
use super::ipres::{IpAddressBlocks, IpResources};
use super::x509::{
    update_once, Name, SignatureAlgorithm, SignedData, Time, ValidationError
};


//------------ Cert ----------------------------------------------------------

/// An RPKI resource certificate.
///
/// A value of this type is the result of parsing a resource certificate. It
/// can be one of three different variants: A CA certificate appears in its
/// own file in the repository. It main use is to sign other certificates.
/// An EE certificate is used to sign other objects in the repository, such
/// as manifests or ROAs. In RPKI, EE certificates are used only once.
/// Whenever a new such object is created, a new EE certificate is created,
/// signed by its CA, used to sign the object, and then the private key is
/// thrown away. Thus, EE certificates only appear inside these signed
/// objects.
/// Finally, TA certificates are the installed trust anchors. These are
/// self-signed.
/// 
/// If a certificate is stored in a file, you can use the `decode` function
/// to parse the entire file. If the certificate is part of some other
/// structure, the `take_from` and `take_content_from` function can be used
/// during parsing of that structure.
///
/// Once parsing succeeded, the three methods `validate_ta`, `validate_ca`,
/// and `validate_ee` can be used to validate the certificate and turn it
/// into a [`ResourceCert`] so it can be used for further processing.
///
/// [`ResourceCert`]: struct.ResourceCert.html
#[derive(Clone, Debug)]
pub struct Cert {
    /// The outer structure of the certificate.
    signed_data: SignedData,

    /// The serial number.
    serial_number: Unsigned,

    /// The algorithm used for signing the certificate.
    signature: SignatureAlgorithm,

    /// The name of the issuer.
    ///
    /// It isn’t really relevant in RPKI.
    issuer: Name,

    /// The validity of the certificate.
    validity: Validity,

    /// The name of the subject of this certificate.
    ///
    /// This isn’t really relevant in RPKI.
    subject: Name,

    /// Information about the public key of this certificate.
    subject_public_key_info: SubjectPublicKeyInfo,

    /// The optional Issuer Unique ID.
    issuer_unique_id: Option<BitString>,

    /// The optional Subject Unique ID.
    subject_unique_id: Option<BitString>,

    /// The certificate extensions.
    extensions: Extensions,
}

impl Cert {
    /// Decodes a source as a certificate.
    pub fn decode<S: Source>(source: S) -> Result<Self, S::Err> {
        Mode::Der.decode(source, Self::take_from)
    }

    /// Takes an encoded certificate from the beginning of a value.
    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(Self::take_content_from)
    }

    /// Parses the content of a Certificate sequence.
    pub fn take_content_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        let signed_data = SignedData::take_content_from(cons)?;

        Mode::Der.decode(signed_data.data().clone(), |cons| {
            cons.take_sequence(|cons| {
                // version [0] EXPLICIT Version DEFAULT v1.
                //  -- we need extensions so apparently, we want v3 which,
                //     confusingly, is 2.
                cons.take_constructed_if(Tag::CTX_0, |c| c.skip_u8_if(2))?;

                Ok(Cert {
                    signed_data,
                    serial_number: Unsigned::take_from(cons)?,
                    signature: SignatureAlgorithm::take_from(cons)?,
                    issuer: Name::take_from(cons)?,
                    validity: Validity::take_from(cons)?,
                    subject: Name::take_from(cons)?,
                    subject_public_key_info: 
                        SubjectPublicKeyInfo::take_from(cons)?,
                    issuer_unique_id: cons.take_opt_value_if(
                        Tag::CTX_1,
                        |c| BitString::parse_content(c)
                    )?,
                    subject_unique_id: cons.take_opt_value_if(
                        Tag::CTX_2,
                        |c| BitString::parse_content(c)
                    )?,
                    extensions: cons.take_constructed_if(
                        Tag::CTX_3,
                        Extensions::take_from
                    )?,
                })
            })
        }).map_err(Into::into)
    }

    /// Returns a reference to the certificate’s public key.
    pub fn public_key(&self) -> &[u8] {
        self.subject_public_key_info
            .subject_public_key.octet_slice().unwrap()
    }

    /// Returns a reference to the subject key identifier.
    pub fn subject_key_identifier(&self) -> &OctetString {
        &self.extensions.subject_key_id
    }

    /// Returns a reference to the entire public key information structure.
    pub fn subject_public_key_info(&self) -> &SubjectPublicKeyInfo {
        &self.subject_public_key_info
    }

    /// Returns a reference to the certificate’s CRL distributionb point.
    ///
    /// If present, this will be an `rsync` URI. 
    pub fn crl_distribution(&self) -> Option<&UriGeneralNames> {
        self.extensions.crl_distribution.as_ref()
    }

    /// Returns a reference to the certificate’s serial number.
    pub fn serial_number(&self) -> &Unsigned {
        &self.serial_number
    }
}

/// # Validation
///
impl Cert {
    /// Validates the certificate as a trust anchor.
    ///
    /// This validates that the certificate “is a current, self-signed RPKI
    /// CA certificate that conforms to the profile as specified in
    /// RFC6487” (RFC7730, section 3, step 2).
    pub fn validate_ta(self) -> Result<ResourceCert, ValidationError> {
        self.validate_basics()?;
        self.validate_ca_basics()?;

        // 4.8.3. Authority Key Identifier. May be present, if so, must be
        // equal to the subject key indentifier.
        if let Some(ref aki) = self.extensions.authority_key_id {
            if *aki != self.extensions.subject_key_id {
                return Err(ValidationError);
            }
        }

        // 4.8.6. CRL Distribution Points. There musn’t be one.
        if self.extensions.crl_distribution.is_some() {
            return Err(ValidationError)
        }

        // 4.8.7. Authority Information Access. Must not be present.
        if self.extensions.authority_info_access.is_some() {
            return Err(ValidationError)
        }

        // 4.8.10.  IP Resources. If present, musn’t be "inherit".
        let ip_resources = IpAddressBlocks::from_resources(
            self.extensions.ip_resources.as_ref()
        )?;
 
        // 4.8.11.  AS Resources. If present, musn’t be "inherit". That
        // IP resources (logical) or AS resources are present has already
        // been checked during parsing.
        let as_resources = AsBlocks::from_resources(
            self.extensions.as_resources.as_ref()
        )?;

        self.signed_data.verify_signature(
            self.subject_public_key_info
                .subject_public_key.octet_slice().unwrap()
        )?;

        Ok(ResourceCert {
            cert: self,
            ip_resources,
            as_resources,
        })
    }

    /// Validates the certificate as a CA certificate.
    ///
    /// For validation to succeed, the certificate needs to have been signed
    /// by the provided `issuer` certificate.
    ///
    /// Note that this does _not_ check the CRL.
    pub fn validate_ca(
        self,
        issuer: &ResourceCert
    ) -> Result<ResourceCert, ValidationError> {
        self.validate_basics()?;
        self.validate_ca_basics()?;
        self.validate_issued(issuer)?;
        self.validate_signature(issuer)?;
        self.validate_resources(issuer)
    }

    /// Validates the certificate as an EE certificate.
    ///
    /// For validation to succeed, the certificate needs to have been signed
    /// by the provided `issuer` certificate.
    ///
    /// Note that this does _not_ check the CRL.
    pub fn validate_ee(
        self,
        issuer: &ResourceCert,
    ) -> Result<ResourceCert, ValidationError>  {
        self.validate_basics()?;
        self.validate_issued(issuer)?;

        // 4.8.1. Basic Constraints: Must not be present.
        if self.extensions.basic_ca != None {
            return Err(ValidationError)
        }

        // 4.8.4. Key Usage. Bits for CA or not CA have been checked during
        // parsing already.
        if self.extensions.key_usage_ca {
            return Err(ValidationError)
        }

        // 4.8.8.  Subject Information Access.
        if self.extensions.subject_info_access.ca {
            return Err(ValidationError)
        }

        self.validate_signature(issuer)?;
        self.validate_resources(issuer)
    }


    //--- Validation Components

    /// Validates basic compliance with section 4 of RFC 6487.
    fn validate_basics(&self) -> Result<(), ValidationError> {
        // The following lists all such constraints in the RFC, noting those
        // that we cannot check here.

        // 4.2 Serial Number: must be unique over the CA. We cannot check
        // here, and -- XXX --- probably don’t care?

        // 4.3 Signature Algorithm: limited to those in RFC 6485. Already
        // checked in parsing.

        // 4.4 Issuer: must have certain format. Since it is not intended to
        // be descriptive, we simply ignore it.

        // 4.5 Subject: same as 4.4.
        
        // 4.6 Validity. Check according to RFC 5280.
        self.validity.validate()?;

        // 4.7 Subject Public Key Info: limited algorithms. Already checked
        // during parsing.

        // 4.8.1. Basic Constraints. Differing requirements for CA and EE
        // certificates.
        
        // 4.8.2. Subject Key Identifer. Must be the SHA-1 hash of the octets
        // of the subjectPublicKey.
        if self.extensions.subject_key_id.as_slice().unwrap()
                != self.subject_public_key_info().key_identifier().as_ref()
        {
            return Err(ValidationError)
        }

        // 4.8.3. Authority Key Identifier. Differing requirements of TA and
        // other certificates.

        // 4.8.4. Key Usage. Differs between CA and EE certificates.

        // 4.8.5. Extended Key Usage. Must not be present for the kind of
        // certificates we use here.
        if self.extensions.extended_key_usage.is_some() {
            return Err(ValidationError)
        }

        // 4.8.6. CRL Distribution Points. Differs between TA and other
        // certificates.

        // 4.8.7. Authority Information Access. Differs between TA and other
        // certificates.

        // 4.8.8.  Subject Information Access. Differs between CA and EE
        // certificates.

        // 4.8.9.  Certificate Policies. XXX I think this can be ignored.
        // At least for now.

        // 4.8.10.  IP Resources. Differs between trust anchor and issued
        // certificates.
        
        // 4.8.11.  AS Resources. Differs between trust anchor and issued
        // certificates.

        Ok(())
    }

    /// Validates that the certificate is a correctly issued certificate.
    fn validate_issued(
        &self,
        issuer: &ResourceCert,
    ) -> Result<(), ValidationError> {
        // 4.8.3. Authority Key Identifier. Must be present and match the
        // subject key ID of `issuer`.
        if let Some(ref aki) = self.extensions.authority_key_id {
            if *aki != issuer.cert.extensions.subject_key_id {
                return Err(ValidationError)
            }
        }
        else {
            return Err(ValidationError);
        }

        // 4.8.6. CRL Distribution Points. There must be one. There’s a rule
        // that there must be at least one rsync URI. This will be implicitely
        // checked when verifying the CRL later.
        if self.extensions.crl_distribution.is_none() {
            return Err(ValidationError)
        }

        // 4.8.7. Authority Information Access. Must be present and contain
        // the URI of the issuer certificate. Since we do top-down validation,
        // we don’t really need that URI so – XXX – leave it unchecked for
        // now.
        if self.extensions.authority_info_access.is_none() {
            return Err(ValidationError);
        }

        Ok(())
    }

    /// Validates that the certificate is a valid CA certificate.
    ///
    /// Checks the parts that are common in normal and trust anchor CA
    /// certificates.
    fn validate_ca_basics(&self) -> Result<(), ValidationError> {
        // 4.8.1. Basic Constraints: For a CA it must be present (RFC6487)
        // und the “cA” flag must be set (RFC5280).
        if self.extensions.basic_ca != Some(true) {
            return Err(ValidationError)
        }

        // 4.8.4. Key Usage. Bits for CA or not CA have been checked during
        // parsing already.
        if !self.extensions.key_usage_ca {
            return Err(ValidationError)
        }

        // 4.8.8.  Subject Information Access.
        if !self.extensions.subject_info_access.ca {
            return Err(ValidationError)
        }
        
        Ok(())
    }

    /// Validates the certificate’s signature.
    fn validate_signature(
        &self,
        issuer: &ResourceCert
    ) -> Result<(), ValidationError> {
        self.signed_data.verify_signature(issuer.cert.public_key())
    }

    /// Validates and extracts the IP and AS resources.
    ///
    /// Upon success, this converts the certificate into a `ResourceCert`.
    fn validate_resources(
        self,
        issuer: &ResourceCert
    ) -> Result<ResourceCert, ValidationError> {
        // 4.8.10.  IP Resources. If present, must be encompassed by issuer.
        // certificates.
        let ip_resources = issuer.ip_resources.encompasses(
            self.extensions.ip_resources.as_ref()
        )?;
        
        // 4.8.11.  AS Resources. If present, must be encompassed by issuer.
        // That IP or AS resources need to be present has been
        // checked during parsing.
        let as_resources = issuer.as_resources.encompasses(
            self.extensions.as_resources.as_ref()
        )?;

        Ok(ResourceCert {
            cert: self,
            ip_resources,
            as_resources,
        })
    }
}


//--- AsRef

impl AsRef<Cert> for Cert {
    fn as_ref(&self) -> &Self {
        self
    }
}


//------------ ResourceCert --------------------------------------------------

/// A validated resource certificate.
///
/// This differs from a normal [`Cert`] in that its IP and AS resources are
/// resolved into concrete values.
#[derive(Clone, Debug)]
pub struct ResourceCert {
    /// The underlying resource certificate.
    cert: Cert,

    /// The resolved IP resources.
    ip_resources: IpAddressBlocks,

    /// The resolved AS resources.
    as_resources: AsBlocks,
}

impl ResourceCert {
    /// Returns a reference to the IP resources of this certificate.
    pub fn ip_resources(&self) -> &IpAddressBlocks {
        &self.ip_resources
    }

    /// Returns a reference to the AS resources of this certificate.
    pub fn as_resources(&self) -> &AsBlocks {
        &self.as_resources
    }

    /// Returns an iterator over the manifest URIs of this certificate.
    pub fn manifest_uris(&self) -> impl Iterator<Item=UriGeneralName> {
        self.cert.extensions.subject_info_access.iter().filter_oid(
            oid::AD_RPKI_MANIFEST
        )
    }

    /// Returns the repository rsync URI of this certificate if available.
    pub fn repository_uri(&self) -> Option<rsync::Uri> {
        for uri in self.cert.extensions.subject_info_access
                       .iter().filter_oid(oid::AD_CA_REPOSITORY)
        {
            if let Some(mut uri) = uri.into_rsync_uri() {
                return Some(uri)
            }
        }
        None
    }
}


//--- AsRef

impl AsRef<Cert> for ResourceCert {
    fn as_ref(&self) -> &Cert {
        &self.cert
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
        cons.take_sequence(|cons| {
            Ok(Validity::new(
                Time::take_from(cons)?,
                Time::take_from(cons)?,
            ))
        })
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        self.not_before.validate_not_before()?;
        self.not_after.validate_not_after()?;
        Ok(())
    }
}


//------------ SubjectPublicKeyInfo ------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectPublicKeyInfo {
    algorithm: PublicKeyAlgorithm,
    subject_public_key: BitString,
}

impl SubjectPublicKeyInfo {
    pub fn decode<S: Source>(source: S) -> Result<Self, S::Err> {
        Mode::Der.decode(source, Self::take_from)
    }
 
    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            Ok(SubjectPublicKeyInfo {
                algorithm: PublicKeyAlgorithm::take_from(cons)?,
                subject_public_key: BitString::take_from(cons)?
            })
        })
    }

    pub fn key_identifier(&self) -> Digest {
        digest::digest(
            &digest::SHA1,
            self.subject_public_key.octet_slice().unwrap()
        )
    }
}


//------------ PublicKeyAlgorithm --------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicKeyAlgorithm {
    RsaEncryption,
}

impl PublicKeyAlgorithm {
    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(Self::take_content_from)
    }

    pub fn take_content_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        oid::RSA_ENCRYPTION.skip_if(cons)?;
        cons.take_opt_null()?;
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
    subject_info_access: SubjectInfoAccess,

    /// Certificate Policies
    ///
    /// Must be present and critical. RFC 6484 describes the policies for
    /// PKIX certificates. This value contains the content of the
    /// certificatePolicies sequence.
    certificate_policies: CertificatePolicies,

    /// IP Resources
    ip_resources: Option<IpResources>,

    /// AS Resources
    as_resources: Option<AsResources>,
}

impl Extensions {
    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
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
            while let Some(()) = cons.take_opt_sequence(|cons| {
                let id = Oid::take_from(cons)?;
                let critical = cons.take_opt_bool()?.unwrap_or(false);
                let value = OctetString::take_from(cons)?;
                Mode::Der.decode(value.to_source(), |content| {
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
            match cons.take_sequence(|cons| cons.take_opt_bool())? {
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
            let res = cons.take_sequence(|c| c.capture_all())?;
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
            cons.take_sequence(|cons| {
                cons.take_sequence(|cons| {
                    cons.take_constructed_if(Tag::CTX_0, |cons| {
                        cons.take_constructed_if(Tag::CTX_0, |cons| {
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
            cons.take_sequence(|cons| {
                cons.take_sequence(|cons| {
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
        subject_info_access: &mut Option<SubjectInfoAccess>,
    ) -> Result<(), S::Err> {
        update_once(
            subject_info_access,
            || SubjectInfoAccess::take_from(cons)
        )
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
        ip_resources: &mut Option<IpResources>
    ) -> Result<(), S::Err> {
        update_once(ip_resources, || {
            IpResources::take_from(cons)
        })
    }

    /// Parses the AS Resources extension.
    fn take_as_resources<S: Source>(
        cons: &mut Constructed<S>,
        as_resources: &mut Option<AsResources>
    ) -> Result<(), S::Err> {
        update_once(as_resources, || {
            AsResources::take_from(cons)
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

    pub fn iter(&self) -> UriGeneralNameIter {
        UriGeneralNameIter(self.0.clone())
    }
}


//------------ UriGeneralNameIter --------------------------------------------

// XXX This can be improved quite a bit.
#[derive(Clone, Debug)]
pub struct UriGeneralNameIter(Bytes);

impl Iterator for UriGeneralNameIter {
    type Item = UriGeneralName;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            None
        }
        else {
            Mode::Der.decode(&mut self.0, |cons| {
                UriGeneralName::take_opt_from(cons)
            }).unwrap()
        }
    }
}


//------------ UriGeneralName ------------------------------------------------

#[derive(Clone, Debug)]
pub struct UriGeneralName(Bytes);

impl UriGeneralName {
    fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_primitive_if(Tag::CTX_6, |prim| {
            let res = prim.take_all()?;
            if res.is_ascii() {
                Ok(UriGeneralName(res))
            }
            else {
                xerr!(Err(Error::Malformed.into()))
            }
        })
    }

    fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Option<Self>, S::Err> {
        cons.take_opt_primitive_if(Tag::CTX_6, |prim| {
            let res = prim.take_all()?;
            if res.is_ascii() {
                Ok(UriGeneralName(res))
            }
            else {
                xerr!(Err(Error::Malformed.into()))
            }
        })
    }

    fn skip_opt<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Option<()>, S::Err> {
        cons.take_opt_primitive_if(Tag::CTX_6, |prim| {
            if prim.slice_all()?.is_ascii() {
                prim.skip_all()?;
                Ok(())
            }
            else {
                xerr!(Err(Error::Malformed.into()))
            }
        })
    }

    pub fn into_rsync_uri(self) -> Option<rsync::Uri> {
        rsync::Uri::from_bytes(self.0.clone()).ok()
    }
}


//------------ SubjectInfoAccess ---------------------------------------------

#[derive(Clone, Debug)]
pub struct SubjectInfoAccess {
    content: Bytes,
    ca: bool
}

impl SubjectInfoAccess {
    pub fn iter(&self) -> SiaIter {
        SiaIter { content: self.content.clone() }
    }

    fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            let mut ca = None;
            let content = cons.capture(|cons| {
                while let Some(()) = cons.take_opt_sequence(|cons| {
                    let oid = Oid::take_from(cons)?;
                    if oid == oid::AD_CA_REPOSITORY
                        || oid == oid::AD_RPKI_MANIFEST
                    {
                        match ca {
                            None => ca = Some(true),
                            Some(true) => { }
                            Some(false) => {
                                xerr!(return Err(Error::Malformed.into()))
                            }
                        }
                    }
                    else if oid == oid::AD_SIGNED_OBJECT {
                        match ca {
                            None => ca = Some(false),
                            Some(false) => { }
                            Some(true) => {
                                xerr!(return Err(Error::Malformed.into()))
                            }
                        }
                    }
                    let _ = UriGeneralName::take_from(cons)?;
                    Ok(())
                })? { }
                Ok(())
            })?;
            if let Some(ca) = ca {
                Ok(SubjectInfoAccess { content, ca })
            }
            else {
                // The sequence was empty.
                xerr!(Err(Error::Malformed.into()))
            }
        })
    }
}


//------------ SiaIter -------------------------------------------------------

#[derive(Clone, Debug)]
pub struct SiaIter {
    content: Bytes,
}

impl SiaIter {
    pub fn filter_oid<O: AsRef<[u8]>>(
        self,
        expected: Oid<O>
    ) -> impl Iterator<Item=UriGeneralName> {
        self.filter_map(move |(oid, uri)| {
            if oid == expected {
                Some(uri)
            }
            else {
                None
            }
        })
    }
}


impl Iterator for SiaIter {
    type Item = (Oid, UriGeneralName);

    fn next(&mut self) -> Option<Self::Item> {
        Mode::Der.decode(&mut self.content, |cons| {
            cons.take_opt_sequence(|cons| {
                Ok((
                    Oid::take_from(cons)?,
                    UriGeneralName::take_from(cons)?
                ))
            })
        }).unwrap()
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
        cons.take_sequence(|c| c.capture_all()).map(CertificatePolicies)
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

