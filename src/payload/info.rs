//! Information about where payload came from.
//!
//! This is a private module. Its public types are re-exported by the parent.

use std::sync::Arc;
use rpki::uri;
use rpki::repository::cert::{Cert, ResourceCert};
use rpki::repository::tal::TalInfo;
use rpki::repository::x509::{Validity, Time};
use crate::slurm::ExceptionInfo;

//------------ PayloadInfo ---------------------------------------------------

/// Information about the sources of a payload item.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct PayloadInfo {
    /// The head of a linked list of origin infos.
    ///
    /// We are abusing `Result` here to distinguish between origins from
    /// published objects and from local exceptions. If you squint real hard,
    /// this even kind of makes sense.
    head: Result<Arc<PublishInfo>, Arc<ExceptionInfo>>,

    /// The tail of the linked list.
    tail: Option<Box<PayloadInfo>>,
}


impl PayloadInfo {
    pub fn add_published(&mut self, info: Arc<PublishInfo>) {
        self.tail = Some(Box::new(PayloadInfo {
            head: Ok(info),
            tail: self.tail.take()
        }));
    }

    pub fn add_local(&mut self, info: Arc<ExceptionInfo>) {
        self.tail = Some(Box::new(PayloadInfo {
            head: Err(info),
            tail: self.tail.take()
        }));
    }

    /// Returns an iterator over the chain of information.
    pub fn iter(&self) -> PayloadInfoIter {
        PayloadInfoIter { info: Some(self) }
    }

    /// Returns the name of the first TAL if available.
    pub fn tal_name(&self) -> Option<&str> {
        self.head.as_ref().map(|info| info.tal.name()).ok()
    }

    /// Returns the URI of the first ROA if available.
    pub fn uri(&self) -> Option<&uri::Rsync> {
        self.head.as_ref().ok().and_then(|info| info.uri.as_ref())
    }

    /// Returns the validity of the first ROA if available.
    ///
    pub fn validity(&self) -> Option<Validity> {
        self.head.as_ref().map(|info| info.roa_validity).ok()
    }

    /// Returns the published object info if available.
    pub fn publish_info(&self) -> Option<&PublishInfo> {
        match self.head {
            Ok(ref info) => Some(info),
            Err(_) => None
        }
    }

    /// Returns the exception info if available.
    pub fn exception_info(&self) -> Option<&ExceptionInfo> {
        match self.head {
            Ok(_) => None,
            Err(ref info) => Some(info),
        }
    }
}


//--- From

impl From<Arc<PublishInfo>> for PayloadInfo {
    fn from(src: Arc<PublishInfo>) -> Self {
        PayloadInfo { head: Ok(src), tail: None }
    }
}

impl From<Arc<ExceptionInfo>> for PayloadInfo {
    fn from(src: Arc<ExceptionInfo>) -> Self {
        PayloadInfo { head: Err(src), tail: None }
    }
}

//--- IntoIterator

impl<'a> IntoIterator for &'a PayloadInfo {
    type Item = &'a PayloadInfo;
    type IntoIter = PayloadInfoIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}


//------------ PayloadInfoIter -----------------------------------------------

/// An iterator over origin information.
#[derive(Clone, Debug)]
pub struct PayloadInfoIter<'a> {
    info: Option<&'a PayloadInfo>,
}

impl<'a> Iterator for PayloadInfoIter<'a> {
    type Item = &'a PayloadInfo;

    fn next(&mut self) -> Option<Self::Item> {
        let res = self.info?;
        self.info = res.tail.as_ref().map(AsRef::as_ref);
        Some(res)
    }
}


//------------ PublishInfo ---------------------------------------------------

/// Information about the published object a payload item came from.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct PublishInfo {
    /// The TAL the ROA is derived from.
    pub tal: Arc<TalInfo>,

    /// The rsync URI identifying the ROA.
    pub uri: Option<uri::Rsync>,

    /// The validity of the ROA itself.
    pub roa_validity: Validity,

    /// The validity of the validation chain.
    pub chain_validity: Validity,

    /// When will the object’s publication point become stale?
    pub point_stale: Time,
}

impl PublishInfo {
    /// Creates a new origin info from the EE certificate of a ROA.
    pub fn signed_object(
        cert: &ResourceCert,
        ca_validity: Validity,
        point_stale: Time,
    ) -> Self {
        PublishInfo {
            tal: cert.tal().clone(),
            uri: cert.signed_object().cloned().map(|mut uri| {
                uri.unshare(); uri
            }),
            roa_validity: cert.validity(),
            chain_validity: cert.validity().trim(ca_validity),
            point_stale,
        }
    }

    pub fn router_cert(
        cert: &Cert,
        uri: &uri::Rsync,
        tal: Arc<TalInfo>,
        ca_validity: Validity,
        point_stale: Time,
    ) -> Self {
        PublishInfo {
            tal,
            uri: Some(uri.clone()),
            roa_validity: cert.validity(),
            chain_validity: cert.validity().trim(ca_validity),
            point_stale,
        }
    }

}

