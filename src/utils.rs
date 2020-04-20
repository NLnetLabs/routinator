//! Various useful things.
//!
use std::net::IpAddr;
use std::str::FromStr;
use rpki::uri;


/// An extension trait for URI kind of types.
pub trait UriExt {
    fn get_authority(&self) -> &str;

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
}

impl UriExt for uri::Https {
    fn get_authority(&self) -> &str {
        self.authority()
    }
}

impl UriExt for uri::Rsync {
    fn get_authority(&self) -> &str {
        self.authority()
    }
}

impl UriExt for uri::RsyncModule {
    fn get_authority(&self) -> &str {
        self.authority()
    }
}

