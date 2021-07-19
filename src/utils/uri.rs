//! Utilities for handling rsync and HTTPS URIs.

use std::borrow::Cow;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use rpki::uri;
use rpki::repository::crypto::{Digest, DigestAlgorithm};


//------------ UriExt --------------------------------------------------------

/// An extension trait for URI kind of types.
pub trait UriExt {
    fn get_authority(&self) -> &str;
    fn unique_components(&self) -> (Cow<str>, Digest);

    /// Returns whether the URI has a dubious authority.
    ///
    /// A dubious authority is a hostname portion of the URI that definitely
    /// cannot be reached from the public Internet or that shouldn’t be.
    ///
    /// Currently, we filter out the reserved name `localhost`, anything that
    /// uses an IP address as the host name, and anything that specifies an
    /// explicit port.
    fn has_dubious_authority(&self) -> bool {
        let authority = self.get_authority();

        // Filter out "localhost"
        if authority == "localhost" {
            return true;
        }

        // Filter out anything that contains a colon.
        if authority.contains(':') {
            return true
        }

        // Filter out anything that parses as an IP address.
        //
        // Socket addresses have gone via the previous rule already.
        if IpAddr::from_str(authority).is_ok() {
            return true
        }

        false
    }

    /// Returns a unique relative path derived from this URI.
    fn unique_path(
        &self, prefix: &str, extension: &str
    ) -> PathBuf {
        let (authority, digest) = self.unique_components();
        let mut res = String::with_capacity(
            prefix.len()
            + authority.len()
            + digest.as_ref().len() * 2 // two hexdigits per octet
            + extension.len()
            + 2 // up to two slashes.
        );
        if !prefix.is_empty() {
            res.push_str(prefix);
            res.push('/');
        }
        res.push_str(&authority);
        res.push('/');
        crate::utils::str::append_hex(
            digest.as_ref(),
            &mut res
        );
        if !extension.is_empty() {
            res.push_str(extension)
        }
        res.into()
    }
}

impl UriExt for uri::Https {
    fn get_authority(&self) -> &str {
        self.authority()
    }

    fn unique_components(&self) -> (Cow<str>, Digest) {
        let authority = self.canonical_authority();
        let mut digest = DigestAlgorithm::sha256().start();
        digest.update(b"https://");
        digest.update(authority.as_bytes());
        digest.update(b"/");
        digest.update(self.path().as_bytes());
        (authority, digest.finish())
    }
}

impl UriExt for uri::Rsync {
    fn get_authority(&self) -> &str {
        self.authority()
    }

    fn unique_components(&self) -> (Cow<str>, Digest) {
        let authority = self.canonical_authority();
        let mut digest = DigestAlgorithm::sha256().start();
        digest.update(b"https://");
        digest.update(authority.as_bytes());
        digest.update(b"/");
        digest.update(self.module_name().as_bytes());
        digest.update(b"/");
        digest.update(self.path().as_bytes());
        (authority, digest.finish())
    }
}

