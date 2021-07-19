//! Checking for validity of route announcements.

use std::{fmt, io};
use std::str::FromStr;
use chrono::{DateTime, Utc};
use rpki::repository::resources::AsId;
use serde::Deserialize;
use crate::payload::{AddressPrefix, OriginInfo, PayloadSnapshot, RouteOrigin};
use crate::utils::date::format_iso_date;


//------------ RouteValidityList ---------------------------------------------

/// Information about the RPKI validity of route announcements.
#[derive(Clone, Debug)]
pub struct RouteValidityList<'a> {
    routes: Vec<RouteValidity<'a>>,
    created: DateTime<Utc>,
}

impl<'a> RouteValidityList<'a> {
    /// Creates a value from requests and a snapshot.
    fn from_requests(
        requests: &RequestList, snapshot: &'a PayloadSnapshot
    ) -> Self {
        RouteValidityList {
            routes: requests.routes.iter().map(|route| {
                RouteValidity::new(route.prefix, route.asn, snapshot)
            }).collect(),
            created: snapshot.created(),
        }
    }

    pub fn write_plain<W: io::Write>(
        &self,
        target: &mut W
    ) -> Result<(), io::Error> {
        for route in &self.routes {
            route.write_plain(target)?;
        }
        Ok(())
    }

    pub fn write_json<W: io::Write>(
        &self,
        target: &mut W
    ) -> Result<(), io::Error> {
        writeln!(target, "{{\n  \"validated_routes\": [")?;
        let mut first = true;
        for route in &self.routes {
            if first {
                first = false;
            }
            else {
                writeln!(target, ",")?;
            }
            write!(target, "    ")?;
            route.write_single_json("    ", target)?;
        }
        writeln!(target,
            "\n  ],\
            ,\n  \"generatedTime\": \"{}\"\
            \n}}",
            format_iso_date(self.created),
        )
    }

    pub fn iter_state(
        &self
    ) -> impl Iterator<Item = (AddressPrefix, AsId, RouteState)> + '_ {
        self.routes.iter().map(|route| {
            (route.prefix, route.asn, route.state())
        })
    }
}


//------------ RouteValidity -------------------------------------------------

/// Information about the RPKI validity of a single route announcement.
#[derive(Clone, Debug)]
pub struct RouteValidity<'a> {
    /// The address prefix of the route announcement.
    prefix: AddressPrefix,

    /// The origin AS number of the route announcement.
    asn: AsId,

    /// Indexes of the matched VRPs in `origins`.
    matched: Vec<&'a (RouteOrigin, OriginInfo)>,

    /// Indexes of covering VRPs that don’t match because of the ´asn`.
    bad_asn: Vec<&'a (RouteOrigin, OriginInfo)>,

    /// Indexes of covering VRPs that don’t match because of the prefix length.
    bad_len: Vec<&'a (RouteOrigin, OriginInfo)>,
}

impl<'a> RouteValidity<'a> {
    pub fn new(
        prefix: AddressPrefix,
        asn: AsId,
        snapshot: &'a PayloadSnapshot
    ) -> Self {
        let mut matched = Vec::new();
        let mut bad_asn = Vec::new();
        let mut bad_len = Vec::new();
        for item in snapshot.origins().iter() {
            if item.0.prefix().covers(prefix) {
                if prefix.address_length() > item.0.max_length() {
                    bad_len.push(item);
                }
                else if item.0.as_id() != asn {
                    bad_asn.push(item);
                }
                else {
                    matched.push(item)
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

    pub fn matched(&self) -> &[&'a (RouteOrigin, OriginInfo)] {
        &self.matched
    }

    pub fn bad_asn(&self) -> &[&'a (RouteOrigin, OriginInfo)] {
        &self.bad_asn
    }

    pub fn bad_len(&self) -> &[&'a (RouteOrigin, OriginInfo)] {
        &self.bad_len
    }

    pub fn write_plain<W: io::Write>(
        &self,
        target: &mut W
    ) -> Result<(), io::Error> {
        writeln!(target, "{} => {}: {}", self.prefix, self.asn, self.state())
    }

    pub fn into_json(self, current: &PayloadSnapshot) -> Vec<u8> {
        let mut res = Vec::new();
        self.write_json(current, &mut res).unwrap();
        res
    }

    pub fn write_json<W: io::Write>(
        &self,
        current: &PayloadSnapshot,
        target: &mut W
    ) -> Result<(), io::Error> {
        write!(target, "{{\n  \"validated_route\": ")?;
        self.write_single_json("  ", target)?;
        writeln!(target,
            ",\n  \"generatedTime\": \"{}\"\
            \n}}",
            format_iso_date(current.created()),
        )
    }

    fn write_single_json<W: io::Write>(
        &self,
        indent: &str,
        target: &mut W
    ) -> Result<(), io::Error> {
        writeln!(target, "{{\n\
            {indent}  \"route\": {{\n\
            {indent}    \"origin_asn\": \"{}\",\n\
            {indent}    \"prefix\": \"{}\"\n\
            {indent}  }},\n\
            {indent}  \"validity\": {{\n\
            {indent}    \"state\": \"{}\",",  
            self.asn,
            self.prefix,
            self.state(),
            indent = indent,
        )?;
        if let Some(reason) = self.reason() {
            writeln!(target, "{}    \"reason\": \"{}\",", indent, reason)?;
        }
        writeln!(
            target,
            "{indent}    \"description\": \"{}\",\n\
             {indent}    \"VRPs\": {{",
            self.description(), indent = indent
        )?;

        Self::write_vrps_json(
            indent, "matched", &self.matched, target
        )?;
        writeln!(target, ",")?;
        Self::write_vrps_json(
            indent, "unmatched_as", &self.bad_asn, target
        )?;
        writeln!(target, ",")?;
        Self::write_vrps_json(
            indent, "unmatched_length", &self.bad_len, target
        )?;

        write!(
            target, "\n\
            {indent}    }}\n\
            {indent}  }}\n\
            {indent}}}",
            indent = indent
        )
    }

    fn write_vrps_json<W: io::Write>(
        indent: &str,
        category: &str,
        vrps: &[&'a (RouteOrigin, OriginInfo)],
        target: &mut W
    ) -> Result<(), io::Error> {
        write!(target, "{}      \"{}\": [", indent, category)?;
        let mut first = true;
        for item in vrps.iter() {
            if first {
                first = false;
            }
            else {
                write!(target, ",")?;
            }

            write!(
                target,
                "\n\
                {indent}        {{\n\
                {indent}          \"asn\": \"{}\",\n\
                {indent}          \"prefix\": \"{}\",\n\
                {indent}          \"max_length\": \"{}\"\n\
                {indent}        }}",
                item.0.as_id(),
                item.0.prefix(),
                item.0.max_length(),
                indent = indent
            )?
        }
        write!(target, "\n{}      ]", indent)
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
#[derive(Clone, Copy, Debug)]
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

impl fmt::Display for RouteState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match *self {
            RouteState::Valid => "valid",
            RouteState::Invalid => "invalid",
            RouteState::NotFound => "not-found",
        })
    }
}


//------------ RequestList ---------------------------------------------------

/// A list of requests for route validity checks.
///
/// This type is intended to be used for deserialization of such a list from a
/// file.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct RequestList {
    /// All the requests.
    routes: Vec<Request>,
}

impl RequestList {
    /// Loads the request list from a plain text reader.
    pub fn from_plain_reader<R: io::BufRead>(
        reader: R
    ) -> Result<Self, io::Error>
    {
        let mut res = Self::default();

        for (line_no, line) in reader.lines().enumerate() {
            let line = line?;
            let mut tokens = line.split_whitespace();

            // PREFIX => ASN [# anything ]

            let prefix = match tokens.next() {
                Some(prefix) => {
                    match AddressPrefix::from_str(prefix) {
                        Ok(prefix) => prefix,
                        Err(_) => {
                            return Err(io::Error::new(
                                io::ErrorKind::Other,
                                format!(
                                    "line {}: expecting prefix, got '{}'",
                                    line_no + 1, prefix
                                )
                            ))
                        }
                    }
                }
                None => continue
            };

            match tokens.next() {
                Some("=>") => { }
                Some(token) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!(
                            "line {}: expecting '=>', got '{}'",
                            line_no + 1, token
                        )
                    ))
                }
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!(
                            "line {}: expecting '=>', got end of line",
                            line_no + 1
                        )
                    ))
                }
            }

            let asn = match tokens.next() {
                Some(asn) => {
                    match AsId::from_str(asn) {
                        Ok(asn) => asn,
                        Err(_) => {
                            return Err(io::Error::new(
                                io::ErrorKind::Other,
                                format!(
                                    "line {}: expecting AS number, got '{}'",
                                    line_no + 1, asn
                                )
                            ))
                        }
                    }
                }
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!(
                            "line {}: expecting AS number, got end of line",
                            line_no + 1
                        )
                    ))
                }
            };

            match tokens.next() {
                Some("#") | None => { }
                Some(token) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!(
                            "line {}: expecting '#'  or end of line, got '{}'",
                            line_no + 1, token
                        )
                    ))
                }
            }

            res.routes.push(Request { prefix, asn });
        }

        Ok(res)
    }

    /// Loads the request list from a json-formatted reader.
    pub fn from_json_reader<R: io::Read>(
        reader: &mut R
    ) -> Result<Self, serde_json::Error> {
        serde_json::from_reader(reader)
    }

    /// Creates a request list with a single entry.
    pub fn single(prefix: AddressPrefix, asn: AsId) -> Self {
        RequestList {
            routes: vec![Request { prefix, asn }]
        }
    }

    /// Checks the validity of all routes and returns a vec with results.
    pub fn validity<'a>(
        &self,
        snapshot: &'a PayloadSnapshot
    ) -> RouteValidityList<'a> {
        RouteValidityList::from_requests(self, snapshot)
    }
}


//------------ Request -------------------------------------------------------

/// A request for a route validity check.
#[derive(Clone, Debug, Deserialize)]
struct Request {
    /// The address prefix of the route announcement.
    prefix: AddressPrefix,

    /// The origin AS number of the route announcement.
    asn: AsId,
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

