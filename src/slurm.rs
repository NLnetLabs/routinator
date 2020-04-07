//! Local exceptions per RFC 8416 aka SLURM.

use std::{fs, io};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use derive_more::Display;
use json::JsonValue;
use json::object::Object as JsonObject;
use log::error;
use rpki::resources::AsId;
use crate::config::Config;
use crate::operation::Error;
use crate::origins::{AddressOrigin, AddressPrefix, FromStrError, OriginInfo};


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

    pub fn load(config: &Config, extra_info: bool) -> Result<Self, Error> {
        let mut res = LocalExceptions::empty();
        let mut ok = true;
        for path in &config.exceptions {
            if let Err(err) = res.extend_from_file(path, extra_info) {
                error!(
                    "Failed to load exceptions file {}: {}",
                    path.display(), err
                );
                ok = false;
            }
        }
        if ok {
            Ok(res)
        }
        else {
            Err(Error)
        }
    }

    pub fn from_file<P: AsRef<Path>>(
        path: P,
        extra_info: bool
    ) -> Result<Self, LoadError> {
        let buf = fs::read_to_string(&path)?;
        Ok(Self::from_json(
            json::parse(&buf)?,
            &Self::info_from_path(path, extra_info)
        )?)
    }

    pub fn from_json(
        json: JsonValue,
        info: &OriginInfo
    ) -> Result<Self, ParseError> {
        let mut res = Self::empty();
        res.extend_from_json(json, info)?;
        Ok(res)
    }

    pub fn extend_from_file<P: AsRef<Path>>(
        &mut self,
        path: P,
        extra_info: bool
    ) -> Result<(), LoadError> {
        let buf = fs::read_to_string(&path)?;
        self.extend_from_json(
            json::parse(&buf)?,
            &Self::info_from_path(path, extra_info)
        )?;
        Ok(())
    }

    fn info_from_path<P: AsRef<Path>>(path: P, extra: bool) -> OriginInfo {
        if extra {
            OriginInfo::Exception(Arc::new(path.as_ref().into()))
        }
        else {
            OriginInfo::None
        }
    }

    pub fn extend_from_json(
        &mut self,
        json: JsonValue,
        info: &OriginInfo,
    ) -> Result<(), ParseError> {
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
        PrefixFilter::extend_from_json(filters, &mut self.filters)?;
        AddressOrigin::extend_from_json(
            assertions, info, &mut self.assertions
        )?;
        Ok(())
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
    fn extend_from_json(
        json: JsonValue,
        vec: &mut Vec<Self>
    ) -> Result<(), ParseError> {
        let json = match json {
            JsonValue::Array(json) => json,
            _ => {
                return Err(ParseError::type_error(
                    "validationOutputFilters.prefixFilters",
                    "list"
                ))
            }
        };
        vec.reserve(json.len());
        for item in json {
            vec.push(Self::from_json(item)?);
        }
        Ok(())
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
    fn extend_from_json(
        json: JsonValue,
        info: &OriginInfo,
        vec: &mut Vec<Self>
    ) -> Result<(), ParseError> {
        let json = match json {
            JsonValue::Array(json) => json,
            _ => {
                return Err(ParseError::type_error(
                    "locallyAddedAssertions.prefixFilters",
                    "list"
                ))
            }
        };
        vec.reserve(json.len());
        for item in json {
            vec.push(Self::from_json(item, info)?);
        }
        Ok(())
    }

    fn from_json(
        json: JsonValue,
        info: &OriginInfo,
    ) -> Result<Self, ParseError> {
        match json {
            JsonValue::Object(mut value) => {
                let prefix = Self::prefix_from_json(&mut value)?;
                let asn = Self::asn_from_json(&mut value)?;
                let max_len = Self::max_len_from_json(&mut value, &prefix)?;
                Ok(AddressOrigin::new(asn, prefix, max_len, info.clone()))
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

#[derive(Debug, Display)]
pub enum ParseError {
    #[display(fmt="expected {} for '{}'", expected, element)]
    TypeError {
        element: &'static str,
        expected: &'static str,
    },

    #[display(fmt="missing field {}", _0)]
    MissingElement(&'static str),

    #[display(fmt="{}", _0)]
    BadPrefix(FromStrError),

    #[display(fmt="{}", _0)]
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

impl From<FromStrError> for ParseError {
    fn from(err: FromStrError) -> ParseError {
        ParseError::BadPrefix(err)
    }
}


//------------ LoadError ----------------------------------------------------

#[derive(Debug, Display)]
pub enum LoadError {
    #[display(fmt="{}", _0)]
    Io(io::Error),

    #[display(fmt="{}", _0)]
    Json(json::Error),

    #[display(fmt="{}", _0)]
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
    use crate::origins::AddressPrefix;

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
            max_length,
            OriginInfo::None,
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
        let exceptions = LocalExceptions::from_json(
            json, &OriginInfo::None
        ).unwrap();

        assert_eq!(0, exceptions.assertions.len());
        assert_eq!(0, exceptions.filters.len());
    }

    #[test]
    fn should_parse_full_slurm_file() {
        let empty = include_str!("../test/slurm/full.json");
        let json = json::parse(empty).unwrap();
        let exceptions = LocalExceptions::from_json(
            json, &OriginInfo::None
        ).unwrap();

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
