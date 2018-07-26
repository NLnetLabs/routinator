//! RPKI Manifests.
//!
//! Manifests list all the files that are currently published by an RPKI CA.
//! They are defined in RFC 6486.
//!
//! This module defines the type [`Manifest`] that represents a decoded
//! manifest and the type [`ManifestContent`] for the content of a validated
//! manifest, as well as some helper types for accessing the content.
//!
//! [`Manifest`]: struct.Manifest.html
//! [`ManifestContent`]: struct.ManifestContent.html

use bytes::Bytes;
use super::rsync;
use super::ber::{
    BitString, Constructed, Error, Mode, OctetString, Source, Tag, Unsigned
};
use super::cert::{ResourceCert};
use super::sigobj::{self, SignedObject};
use super::x509::{Time, ValidationError};


//------------ Manifest ------------------------------------------------------

/// A decoded RPKI manifest.
///
/// This type represents a manifest decoded from a source. In order to get to
/// the manifest’s content, you need to validate it via the `validate`
/// method.
#[derive(Clone, Debug)]
pub struct Manifest {
    signed: SignedObject,
    content: ManifestContent,
}

impl Manifest {
    /// Decodes a manifest from a source.
    pub fn decode<S: Source>(
        source: S,
        strict: bool
    ) -> Result<Self, S::Err> {
        let signed = SignedObject::decode(source, strict)?;
        let content = signed.decode_content(
            |cons| ManifestContent::decode(cons)
        )?;
        Ok(Manifest { signed, content })
    }

    /// Validates the manifest.
    ///
    /// You need to pass in the certificate of the issuing CA. If validation
    /// succeeds, the result will be the EE certificate of the manifest and
    /// the manifest content.
    pub fn validate(
        self,
        cert: &ResourceCert,
    ) -> Result<(ResourceCert, ManifestContent), ValidationError> {
        let cert = self.signed.validate(cert)?;
        Ok((cert, self.content))
    }
}


//------------ ManifestContent -----------------------------------------------

/// The content of an RPKI manifest.
///
/// A manifests consists chiefly of a list of files and their hash value. You
/// can access this list via the `iter_uris` method.
#[derive(Clone, Debug)]
pub struct ManifestContent {
    /// The number of this manifest.
    ///
    /// These numbers are similar to the serial numbers of certificates.
    manifest_number: Unsigned,

    /// The time this iteration of the manifest was created.
    this_update: Time,

    /// The time the next iteration of the manifest is likely to be created.
    next_update: Time,

    /// The list of files in its encoded form.
    file_list: Bytes,
}

impl ManifestContent {
    /// Decodes the manifest content from its encoded form.
    fn decode<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            cons.take_opt_primitive_if(Tag::CTX_0, |prim| {
                if prim.to_u8()? != 0 {
                    xerr!(Err(Error::Malformed.into()))
                }
                else {
                    Ok(())
                }
            })?;
            let manifest_number = Unsigned::take_from(cons)?;
            let this_update = Time::take_from(cons)?;
            let next_update = Time::take_from(cons)?;
            if this_update > next_update {
                xerr!(return Err(Error::Malformed.into()));
            }
            sigobj::oid::SHA256.skip_if(cons)?;
            let file_list = cons.take_sequence(|cons| {
                cons.capture(|cons| {
                    while let Some(()) = FileAndHash::skip_opt_in(cons)? {
                    }
                    Ok(())
                })
            })?;
            Ok(ManifestContent {
                manifest_number, this_update, next_update, file_list
            })
        })
    }

    /// Returns an iterator over the files in the manifest.
    ///
    /// Since the manifest only contains file names, the iterator needs a base
    /// URI to produce complete URIs. It is taken from `base`.
    ///
    /// The returned iterator returns a pair of the file URI and the SHA256
    /// hash of the file.
    pub fn iter_uris(&self, base: rsync::Uri) -> ManifestIter {
        ManifestIter { base, file_list: self.file_list.clone() }
    }
}


//------------ ManifestIter --------------------------------------------------

/// An iterator over the files in the manifest.
///
/// The iterator returns pairs of the absolute URIs of the files and their
/// SHA256 hash values.
#[derive(Clone, Debug)]
pub struct ManifestIter{
    base: rsync::Uri,
    file_list: Bytes,
}

impl Iterator for ManifestIter {
    type Item = Result<(rsync::Uri, ManifestHash), ValidationError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.file_list.is_empty() {
            None
        }
        else {
            Mode::Ber.decode(&mut self.file_list, |cons| {
                FileAndHash::take_opt_from(cons)
            }).unwrap().map(|item| {
                item.to_uri_etc(&self.base)
            })
        }
    }
}


//------------ FileAndHash ---------------------------------------------------

/// An entry in the list of a manifest.
#[derive(Clone, Debug)]
pub struct FileAndHash {
    /// The name of the file.
    file: OctetString,

    /// A SHA256 hash over the file’s content.
    hash: ManifestHash,
}

impl FileAndHash {
    /// Skips over an optional value in a constructed value.
    fn skip_opt_in<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Option<()>, S::Err> {
        cons.take_opt_sequence(|cons| {
            cons.take_value_if(
                Tag::IA5_STRING,
                OctetString::take_content_from
            )?;
            BitString::skip_in(cons)?;
            Ok(())
        })
    }

    /// Takes an optional value from the beginning of a constructed value.
    fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Option<Self>, S::Err> {
        cons.take_opt_sequence(|cons| {
            Ok(FileAndHash {
                file: cons.take_value_if(
                    Tag::IA5_STRING,
                    OctetString::take_content_from
                )?,
                hash: ManifestHash(BitString::take_from(cons)?)
            })
        })
    }

    /// Converts a value into a pair of an absolute URI and its hash.
    fn to_uri_etc(
        self,
        base: &rsync::Uri
    ) -> Result<(rsync::Uri, ManifestHash), ValidationError> {
        let name = self.file.to_bytes();
        if !name.is_ascii() {
            return Err(ValidationError)
        }
        Ok((base.join(&name), self.hash))
    }
}


//------------ ManifestHash --------------------------------------------------

/// A manifest hash.
///
/// This is a SHA256 hash.
#[derive(Clone, Debug)]
pub struct ManifestHash(BitString);

impl ManifestHash {
    /// Check that `bytes` has the same hash value as `this`.
    pub fn verify<B: AsRef<[u8]>>(
        &self,
        bytes: B
    ) -> Result<(), ValidationError> {
        ::ring::constant_time::verify_slices_are_equal(
            self.0.octet_slice().unwrap(),
            ::ring::digest::digest(
                &::ring::digest::SHA256,
                bytes.as_ref()
            ).as_ref()
        ).map_err(|_| ValidationError)
    }
}

