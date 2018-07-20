//! RPKI Manifests

use bytes::Bytes;
use super::rsync;
use super::ber::{
    BitString, Constructed, Error, Mode, OctetString, Source, Tag, Unsigned
};
use super::cert::{ResourceCert};
use super::sigobj::{self, SignedObject};
use super::x509::{Time, ValidationError};


//------------ Manifest ------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Manifest {
    signed: SignedObject,
    content: ManifestContent,
}

impl Manifest {
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

    pub fn validate(
        self,
        cert: &ResourceCert,
    ) -> Result<(ResourceCert, ManifestContent), ValidationError> {
        let cert = self.signed.validate(cert)?;
        Ok((cert, self.content))
    }
}


//------------ ManifestContent -----------------------------------------------

#[derive(Clone, Debug)]
pub struct ManifestContent {
    manifest_number: Unsigned,
    this_update: Time,
    next_update: Time,
    file_list: Bytes,
}

impl ManifestContent {
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

    pub fn iter_uris(&self, base: rsync::Uri) -> ManifestIter {
        ManifestIter { base, file_list: self.file_list.clone() }
    }
}


//------------ ManifestIter --------------------------------------------------

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

#[derive(Clone, Debug)]
pub struct FileAndHash {
    file: OctetString,
    hash: ManifestHash,
}

impl FileAndHash {
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

#[derive(Clone, Debug)]
pub struct ManifestHash(BitString);

impl ManifestHash {
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

