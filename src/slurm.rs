//! Local exceptions per RFC 8416 aka SLURM.

use std::io;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;
use json;
use json::JsonValue;
use json::object::Object as JsonObject;
use rpki::asres::AsId;
use super::origins;
use super::origins::{AddressOrigin, AddressPrefix};


//------------ LocalExceptions -----------------------------------------------

#[derive(Clone, Debug)]
pub struct LocalExceptions {
    filters: Vec<PrefixFilter>,
    assertions: Vec<AddressOrigin>,
}

impl LocalExceptions {
    pub fn empty() -> Self {
        LocalExceptions {
            filters: Vec::new(),
            assertions: Vec::new(),
        }
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, LoadError> {
        let mut file = File::open(path)?;
        let mut buf = String::new();
        file.read_to_string(&mut buf)?;
        Ok(Self::from_json(json::parse(&buf)?)?)
    }

    pub fn from_json(json: JsonValue) -> Result<Self, ParseError> {
        let mut json = match json {
            JsonValue::Object(json) => json,
            _ => {
                return Err(ParseError::type_error("", "object"))
            }
        };
        let version = json.remove("slurmVersion")
            .ok_or_else(|| ParseError::missing("slurmVersion"))?
            .as_u8()
            .ok_or_else(|| ParseError::type_error("slurmVersion", "u8"))?;
        if version != 1 {
            return Err(ParseError::BadVersion(version))
        }

        let mut filters = json.remove("validationOutputFilters")
            .ok_or_else(
                || ParseError::missing("validationOutputFilters")
            )?
            .into_object()
            .ok_or_else(
                || ParseError::type_error("validationOutputFilters", "object")
            )?;
        let mut assertions = json.remove("locallyAddedAssertions")
            .ok_or_else(
                || ParseError::missing("locallyAddedAssertions")
            )?
            .into_object()
            .ok_or_else(
                || ParseError::type_error("locallyAddedAssertions", "object")
            )?;

        // We just ignore the bgpsecFilters for now.

        let filters = filters.remove("prefixFilters")
            .ok_or_else(
                || ParseError::missing(
                    "validationOutputFilters.prefixFilters"
                )
            )?;
        let assertions = assertions.remove("prefixAssertions")
            .ok_or_else(
                || ParseError::missing(
                    "locallyAddedAssertions.prefixAssertions"
                )
            )?;
        Ok(LocalExceptions {
            filters: PrefixFilter::vec_from_json(filters)?,
            assertions: AddressOrigin::vec_from_json(assertions)?,
        })
    }

    pub fn keep_origin(&self, addr: &AddressOrigin) -> bool {
        for filter in &self.filters {
            if filter.filter_origin(addr) {
                return false
            }
        }
        true
    }

    pub fn assertions(&self) -> &[AddressOrigin] {
        self.assertions.as_ref()
    }
}


//------------ PrefixFilter --------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrefixFilter {
    prefix: Option<AddressPrefix>,
    asn: Option<AsId>,
}

impl PrefixFilter {
    fn vec_from_json(json: JsonValue) -> Result<Vec<Self>, ParseError> {
        let json = match json {
            JsonValue::Array(json) => json,
            _ => {
                return Err(ParseError::type_error(
                    "validationOutputFilters.prefixFilters",
                    "list"
                ))
            }
        };
        let mut res = Vec::new();
        for item in json {
            res.push(Self::from_json(item)?);
        }
        Ok(res)
    }

    fn from_json(json: JsonValue) -> Result<Self, ParseError> {
        match json {
            JsonValue::Object(mut value) => {
                Ok(PrefixFilter {
                    prefix: Self::prefix_from_json(&mut value)?,
                    asn: Self::asn_from_json(&mut value)?,
                })
            }
            _ => {
                Err(ParseError::type_error(
                    "validationOutputFilters.prefixFilters.[]",
                    "object"
                ))
            }
        }
    }

    fn prefix_from_json(
        json: &mut JsonObject,
    ) -> Result<Option<AddressPrefix>, ParseError> {
        match json.remove("prefix") {
            Some(mut json) => match json.take_string() {
                Some(value) => {
                    Ok(Some(AddressPrefix::from_str(&value)?))
                }
                None => {
                    Err(ParseError::type_error(
                        "validationOutputFilters.prefixFilters.[].prefix",
                        "string"
                    ))
                }
            }
            None => Ok(None)
        }
    }

    fn asn_from_json(
        json: &mut JsonObject
    ) -> Result<Option<AsId>, ParseError> {
        match json.remove("asn") {
            Some(json) => match json.as_u32() {
                Some(value) => Ok(Some(AsId::from(value))),
                None => {
                    Err(ParseError::type_error(
                        "validationOutputFilters.prefixFilters.[].prefix",
                        "u32"
                    ))
                }
            }
            None => Ok(None)
        }
    }

    fn filter_origin(&self, addr: &AddressOrigin) -> bool {
        match (self.prefix, self.asn) {
            (Some(prefix), Some(asn)) => {
                prefix.covers(addr.prefix()) && asn == addr.as_id()
            }
            (Some(prefix), None) => {
                prefix.covers(addr.prefix())
            }
            (None, Some(asn)) => {
                asn == addr.as_id()
            }
            (None, None) => true
        }
    }
}


//------------ AddressOrigin -------------------------------------------------
//
// see super::origins.

impl AddressOrigin {
    fn vec_from_json(json: JsonValue) -> Result<Vec<Self>, ParseError> {
        let json = match json {
            JsonValue::Array(json) => json,
            _ => {
                return Err(ParseError::type_error(
                    "locallyAddedAssertions.prefixFilters",
                    "list"
                ))
            }
        };
        let mut res = Vec::new();
        for item in json {
            res.push(Self::from_json(item)?);
        }
        Ok(res)
    }

    fn from_json(json: JsonValue) -> Result<Self, ParseError> {
        match json {
            JsonValue::Object(mut value) => {
                let prefix = Self::prefix_from_json(&mut value)?;
                let asn = Self::asn_from_json(&mut value)?;
                let max_len = Self::max_len_from_json(&mut value, &prefix)?;
                Ok(AddressOrigin::new(asn, prefix, max_len))
            }
            _ => {
                Err(ParseError::type_error(
                    "locallyAddedAssertions.prefixFilters.[]",
                    "object"
                ))
            }
        }
    }

    fn prefix_from_json(
        json: &mut JsonObject
    ) -> Result<AddressPrefix, ParseError> {
        match json.remove("prefix") {
            Some(mut json) => match json.take_string() {
                Some(value) => {
                    Ok(AddressPrefix::from_str(&value)?)
                }
                None => {
                    Err(ParseError::type_error(
                        "locallyAddedAssertions.prefixFilters.[].prefix",
                        "string"
                    ))
                }
            }
            None => {
                Err(ParseError::missing(
                    "locallyAddedAssertions.prefixFilters.[].prefix",
                ))
            }
        }
    }

    fn asn_from_json(
        json: &mut JsonObject
    ) -> Result<AsId, ParseError> {
        match json.remove("asn") {
            Some(json) => match json.as_u32() {
                Some(value) => Ok(AsId::from(value)),
                None => {
                    Err(ParseError::type_error(
                        "locallyAddedAssertions.prefixFilters.[].asn",
                        "u32"
                    ))
                }
            }
            None => {
                Err(ParseError::missing(
                    "locallyAddedAssertions.prefixFilters.[].asn",
                ))
            }
        }
    }

    fn max_len_from_json(
        json: &mut JsonObject,
        addr: &AddressPrefix
    ) -> Result<u8, ParseError> {
        match json.remove("maxPrefixLength") {
            Some(json) => match json.as_u8() {
                Some(value) => Ok(value),
                None => {
                    Err(ParseError::type_error(
                        "locallyAddedAssertions.prefixFilters.[].\
                        maxPrefxiLength",
                        "u8"
                    ))
                }
            }
            None => Ok(addr.address_length())
        }
    }

}


//------------ Helpers -------------------------------------------------------

trait JsonValueExt {
    fn into_object(self) -> Option<JsonObject>;
}

impl JsonValueExt for JsonValue {
    fn into_object(self) -> Option<JsonObject> {
        match self {
            JsonValue::Object(json) => Some(json),
            _ => None
        }
    }
}


//------------ ParseError ----------------------------------------------------

#[derive(Debug, Fail)]
pub enum ParseError {
    #[fail(display="expected {} for '{}'", expected, element)]
    TypeError {
        element: &'static str,
        expected: &'static str,
    },

    #[fail(display="missing field {}", _0)]
    MissingElement(&'static str),

    #[fail(display="{}", _0)]
    BadPrefix(origins::FromStrError),

    #[fail(display="{}", _0)]
    BadVersion(u8),
}

impl ParseError {
    fn type_error(element: &'static str, expected: &'static str) -> Self {
        ParseError::TypeError { element, expected }
    }

    fn missing(element: &'static str) -> Self {
        ParseError::MissingElement(element)
    }
}

impl From<origins::FromStrError> for ParseError {
    fn from(err: origins::FromStrError) -> ParseError {
        ParseError::BadPrefix(err)
    }
}


//------------ LoadError ----------------------------------------------------

#[derive(Debug, Fail)]
pub enum LoadError {
    #[fail(display="{}", _0)]
    Io(io::Error),

    #[fail(display="{}", _0)]
    Json(json::Error),

    #[fail(display="{}", _0)]
    Parse(ParseError),
}

impl From<io::Error> for LoadError {
    fn from(err: io::Error) -> LoadError {
        LoadError::Io(err)
    }
}

impl From<json::Error> for LoadError {
    fn from(err: json::Error) -> LoadError {
        LoadError::Json(err)
    }
}

impl From<ParseError> for LoadError {
    fn from(err: ParseError) -> LoadError {
        LoadError::Parse(err)
    }
}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
pub mod tests {

    use super::*;
    use origins::AddressPrefix;

    fn address_origin(
        asn: u32,
        ip_string: &str,
        length: u8,
        max_length: u8
    ) -> AddressOrigin {
        AddressOrigin::new(
            AsId::from(asn),
            AddressPrefix::new(
                ip_string.parse().unwrap(),
                length
            ),
            max_length
        )
    }

    fn make_prefix_filter(
        prefix: Option<AddressPrefix>,
        asn: Option<u32>
    ) -> PrefixFilter {
        PrefixFilter { prefix, asn: asn.map(|asn| AsId::from(asn)) }
    }

    fn address_prefix(
        ip_string: &str,
        length: u8
    ) -> Option<AddressPrefix> {
        Some(AddressPrefix::new(ip_string.parse().unwrap(), length))
    }



    #[test]
    fn should_parse_empty_slurm_file() {
        let empty = include_str!("../test/slurm/empty.json");
        let json = json::parse(empty).unwrap();
        let exceptions = LocalExceptions::from_json(json).unwrap();

        assert_eq!(0, exceptions.assertions.len());
        assert_eq!(0, exceptions.filters.len());
    }

    #[test]
    fn should_parse_full_slurm_file() {
        let empty = include_str!("../test/slurm/full.json");
        let json = json::parse(empty).unwrap();
        let exceptions = LocalExceptions::from_json(json).unwrap();

        assert_eq!(2, exceptions.assertions.len());
        assert!(
            exceptions.assertions.contains(
                &address_origin(64496, "198.51.100.0", 24, 24)
            )
        );
        assert!(
            exceptions.assertions.contains(
                &address_origin(64496, "2001:DB8::", 32, 48)
            )
        );

        assert_eq!(3, exceptions.filters.len());

        assert!(
            exceptions.filters.contains(
                &make_prefix_filter(
                    address_prefix("192.0.2.0", 24),
                    None
                )
            )
        );
        assert!(
            exceptions.filters.contains(
                &make_prefix_filter(
                    None,
                    Some(64496)
                )
            )
        );
        assert!(
            exceptions.filters.contains(
                &make_prefix_filter(
                    address_prefix("198.51.100.0", 24),
                    Some(64497)
                )
            )
        );
    }
}
