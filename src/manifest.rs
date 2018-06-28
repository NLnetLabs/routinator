//! RPKI Manifests

use bytes::Bytes;
use super::ber::{BitString, Constructed, Error, OctetString, Source, Tag};
use super::sigobj::{self, SignedObject};
use super::x509::Time;


//------------ Manifest ------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Manifest {
    signed: SignedObject,
    manifest_number: Bytes,
    this_update: Time,
    next_update: Time,
    file_list: Bytes,
}

impl Manifest {
    pub fn decode<S: Source>(source: S) -> Result<Self, S::Err> {
        let signed = SignedObject::decode(source)?;
        signed.clone().decode_content(|cons| {
            cons.sequence(|cons| {
                cons.opt_primitive_if(Tag::CTX_0, |prim| {
                    if prim.to_u8()? != 0 {
                        xerr!(Err(Error::Malformed.into()))
                    }
                    else {
                        Ok(())
                    }
                })?;
                let manifest_number = cons.take_unsigned()?;
                let this_update = Time::take_from(cons)?;
                let next_update = Time::take_from(cons)?;
                sigobj::oid::SHA256.skip_if(cons)?;
                let file_list = cons.sequence(|cons| {
                    cons.capture(|cons| {
                        while let Some(()) = FileAndHash::skip_opt_in(cons)? {
                        }
                        Ok(())
                    })
                })?;
                Ok(Manifest {
                    signed, manifest_number, this_update, next_update, file_list
                })
            })
        }).map_err(Into::into)
    }
}


//------------ FileAndHash ---------------------------------------------------

#[derive(Clone, Debug)]
pub struct FileAndHash {
    file: OctetString,
    hash: BitString,
}

impl FileAndHash {
    fn skip_opt_in<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Option<()>, S::Err> {
        cons.opt_sequence(|cons| {
            cons.value_if(Tag::IA5_STRING, OctetString::take_content_from)?;
            BitString::skip_in(cons)?;
            Ok(())
        })
    }
}

