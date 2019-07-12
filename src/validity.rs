//! Checking for validity of route announcements.

use std::io;
use derive_more::Display;
use rpki::resources::AsId;
use unwrap::unwrap;
use crate::origins::{AddressOrigin, AddressOrigins, AddressPrefix};


//------------ RouteValidity -------------------------------------------------

/// Information about the RPKI validity of a route announcement.
pub struct RouteValidity<'a> {
    /// The address prefix of the route announcement.
    prefix: AddressPrefix,

    /// The origin AS number of the route announcement.
    asn: AsId,

    /// Indexes of the matched VRPs in `origins`.
    matched: Vec<&'a AddressOrigin>,

    /// Indexes of covering VRPs that don’t match because of the ´asn`.
    bad_asn: Vec<&'a AddressOrigin>,

    /// Indexes of covering VRPs that don’t match because of the prefix length.
    bad_len: Vec<&'a AddressOrigin>,
}

impl<'a> RouteValidity<'a> {
    pub fn new(
        prefix: AddressPrefix,
        asn: AsId,
        origins: &'a AddressOrigins
    ) -> Self {
        let mut matched = Vec::new();
        let mut bad_asn = Vec::new();
        let mut bad_len = Vec::new();
        for origin in origins.iter() {
            if origin.prefix().covers(prefix) {
                if prefix.address_length() > origin.max_length() {
                    bad_len.push(origin);
                }
                else if origin.as_id() != asn {
                    bad_asn.push(origin);
                }
                else {
                    matched.push(origin)
                }
            }
        }
        RouteValidity { prefix, asn, matched, bad_asn, bad_len }
    }

    pub fn prefix(&self) -> AddressPrefix {
        self.prefix
    }

    pub fn asn(&self) -> AsId {
        self.asn
    }

    pub fn state(&self) -> RouteState {
        if self.matched.is_empty() {
            if self.bad_asn.is_empty() && self.bad_len.is_empty() {
                RouteState::NotFound
            }
            else {
                RouteState::Invalid
            }
        }
        else {
            RouteState::Valid
        }
    }

    pub fn reason(&self) -> Option<&'static str> {
        if self.matched.is_empty() {
            if !self.bad_asn.is_empty() {
                Some("as")
            }
            else if !self.bad_len.is_empty() {
                Some("length")
            }
            else {
                None
            }
        }
        else {
            None
        }
    }

    pub fn description(&self) -> &'static str {
        if self.matched.is_empty() {
            if !self.bad_asn.is_empty() {
                DESCRIPTION_BAD_ASN
            }
            else if !self.bad_len.is_empty() {
                DESCRIPTION_BAD_LEN
            }
            else {
                DESCRIPTION_NOT_FOUND
            }
        }
        else {
            DESCRIPTION_VALID
        }
    }

    pub fn matched(&self) -> &[&'a AddressOrigin] {
        &self.matched
    }

    pub fn bad_asn(&self) -> &[&'a AddressOrigin] {
        &self.bad_asn
    }

    pub fn bad_len(&self) -> &[&'a AddressOrigin] {
        &self.bad_len
    }

    pub fn into_json(self) -> Vec<u8> {
        let mut res = Vec::new();
        unwrap!(self.write_json(&mut res));
        res
    }

    pub fn write_json<W: io::Write>(
        &self,
        target: &mut W
    ) -> Result<(), io::Error> {
        writeln!(target, "\
            {{\n  \"validated_route\": {{\n    \
            \"route\": {{\n      \
            \"origin_asn\": \"{}\",\n      \
            \"prefix\": \"{}\"\n    \
            }},\n    \
            \"validity\": {{\n      \
            \"state\": \"{}\",",  
            self.asn,
            self.prefix,
            self.state()
        )?;
        if let Some(reason) = self.reason() {
            writeln!(target, "      \"reason\": \"{}\",", reason)?;
        }
        writeln!(
            target,
            "      \"description\": \"{}\",\n      \"VRPs\": {{",
            self.description()
        )?;

        Self::write_vrps_json("matched", &self.matched, target)?;
        writeln!(target, ",")?;
        Self::write_vrps_json("unmatched_as", &self.bad_asn, target)?;
        writeln!(target, ",")?;
        Self::write_vrps_json("unmatched_length", &self.bad_len, target)?;

        writeln!( target, "      }}\n    }}\n  }}\n}}")
    }

    fn write_vrps_json<W: io::Write>(
        category: &str,
        vrps: &[&'a AddressOrigin],
        target: &mut W
    ) -> Result<(), io::Error> {
        write!(target, "        \"{}\": [", category)?;
        let mut iter = vrps.iter();
        if let Some(item) = iter.next() {
            writeln!(
                target,
                "\n          {{\n            \
                \"asn\": \"{}\",\n            \
                \"prefix\": \"{}\",\n            \
                \"max_length\": \"{}\"\n          }}",
                item.as_id(),
                item.prefix(),
                item.max_length()
            )?
        }
        for item in iter {
            writeln!(
                target,
                ",\n          {{\n            \
                \"asn\": \"{}\",\n            \
                \"prefix\": \"{}\",\n            \
                \"max_length\": \"{}\"\n          }}",
                item.as_id(),
                item.prefix(),
                item.max_length()
            )?
        }
        write!(target, "\n        ]")
    }

}


//------------ RouteState ----------------------------------------------------

/// The RPKI state of a route announcement.
///
/// These states are defined in [RFC 6811] and determine whether a route
/// announcement has passed by RPKI route origin validation.
///
/// The states are determined based on two terms:
///
/// * A VRP is said to _cover_ an announcement if its prefix covers the
///   announcement, that is the VRP’s prefixes length is less or equal and
///   the bits of its network prefix match the respective bits of the
///   announcment’s prefix.
/// * A VRP is said to _match_ an announcement if it covers the announcment
///   and in addition the announcement’s origin AS number is equal to the
///   VRP’s AS number and the announcement’s prefix length is less or equal
///   to the VRP’s maximum length (which is considered equal to the prefix
///   length if absent).
///
/// With these definitions in mind, there are three states described by the
/// three variants of this enum.
///
/// [RFC 6811]: https://tools.ietf.org/html/rfc6811
#[derive(Clone, Copy, Debug, Display)]
pub enum RouteState {
    /// RPKI Valid.
    ///
    /// At least one VRP matches the annoncement.
    Valid,

    /// RPKI Invalid.
    ///
    /// At least one VRP covers the announcement but no VRP matches it.
    Invalid,

    /// RPKI Not Found.
    ///
    /// No VRP covers the announcement.
    NotFound
}


//------------ Constants -----------------------------------------------------

// Description texts as provided by the RIPE NCC Validator.
//
const DESCRIPTION_VALID: &str = "At least one VRP Matches the Route Prefix";
const DESCRIPTION_BAD_ASN: &str = "At least one VRP Covers the Route Prefix, \
                                   but no VRP ASN matches the route origin \
                                   ASN";
const DESCRIPTION_BAD_LEN: &str = "At least one VRP Covers the Route Prefix, \
                                   but the Route Prefix length is greater \
                                   than the maximum length allowed by VRP(s) \
                                   matching this route origin ASN";
const DESCRIPTION_NOT_FOUND: &str = "No VRP Covers the Route Prefix";
