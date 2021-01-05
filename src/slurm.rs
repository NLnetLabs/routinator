//! Local exceptions per RFC 8416 aka SLURM.

use std::{cmp, error, fmt, fs, io};
use std::convert::TryFrom;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use log::error;
use rpki::repository::resources::AsId;
use serde::Deserialize;
use crate::config::Config;
use crate::operation::Error;
use crate::origins::{AddressOrigin, AddressPrefix, OriginInfo};


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

    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        let mut res = LocalExceptions::empty();
        res.extend_from_json(json, None)?;
        Ok(res)
    }

    pub fn from_file<P: AsRef<Path>>(
        path: P,
        extra_info: bool
    ) -> Result<Self, LoadError> {
        let mut res = Self::empty();
        res.extend_from_file(path, extra_info)?;
        Ok(res)
    }

    pub fn extend_from_file<P: AsRef<Path>>(
        &mut self,
        path: P,
        extra_info: bool
    ) -> Result<(), LoadError> {
        let buf = fs::read_to_string(&path)?;
        self.extend_from_json(&buf, Self::info_from_path(path, extra_info))?;
        Ok(())
    }

    #[allow(clippy::option_option)]
    fn info_from_path<P: AsRef<Path>>(
        path: P, extra: bool
    ) -> Option<Option<Arc<Path>>> {
        if extra {
            Some(Some(path.as_ref().to_path_buf().into()))
        }
        else {
            None
        }
    }

    #[allow(clippy::option_option)]
    pub fn extend_from_json(
        &mut self,
        json: &str,
        info: Option<Option<Arc<Path>>>,
    ) -> Result<(), serde_json::Error> {
        let json = SlurmFile::from_str(json)?;
        self.filters.extend(json.filters.prefix.into_iter().map(Into::into));
        self.assertions.extend(json.assertions.prefix.into_iter().map(|item| {
            AddressOrigin::new(
                item.asn.into(), item.prefix,
                item.max_prefix_len.map(|len| {
                    cmp::min(len, if item.prefix.is_v4() { 32 } else { 128 })
                }).unwrap_or_else(|| item.prefix.address_length()),
                match info.as_ref() {
                    Some(path) => {
                        OriginInfo::Exception(ExceptionInfo {
                            path: path.clone(),
                            comment: item.comment,
                        })
                    }
                    None => OriginInfo::None,
                }
            )
        }));
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

impl From<RawPrefixFilter> for PrefixFilter {
    fn from(raw: RawPrefixFilter) -> Self {
        PrefixFilter {
            prefix: raw.prefix,
            asn: raw.asn.map(Into::into)
        }
    }
}


//------------ ExceptionInfo -------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct ExceptionInfo {
    path: Option<Arc<Path>>,
    comment: Option<String>,
}


//============ Deserialization -----------------------------------------------
//
// We use serde because it provides for better error reporting. The following
// represent the raw SLURM JSON structure.

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SlurmFile {
    #[serde(rename = "slurmVersion")]
    version: SlurmVersion,

    #[serde(rename = "validationOutputFilters")]
    filters: ValidationOutputFilters,

    #[serde(rename = "locallyAddedAssertions")]
    assertions: LocallyAddedAssertions,
}

impl FromStr for SlurmFile {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(try_from = "u8")]
struct SlurmVersion;

impl Default for SlurmVersion {
    fn default() -> SlurmVersion {
        SlurmVersion
    }
}

impl TryFrom<u8> for SlurmVersion {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value == 1 {
            Ok(Self)
        }
        else {
            Err("slurmVersion must be 1")
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidationOutputFilters {
    #[serde(rename = "prefixFilters")]
    prefix: Vec<RawPrefixFilter>,

    #[serde(rename = "bgpsecFilters")]
    bgpsec: Vec<BgpsecFilter>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocallyAddedAssertions {
    #[serde(rename = "prefixAssertions")]
    prefix: Vec<PrefixAssertion>,

    #[serde(rename = "bgpsecAssertions")]
    bgpsec: Vec<BgpsecAssertion>,
}

// serde doesn’t allow enums to be flattened. So we will have to allow empty
// filters unless we want to do our own Deserialize impl. Which we don’t.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPrefixFilter {
    prefix: Option<AddressPrefix>,

    asn: Option<u32>,

    comment: Option<String>,
}

// serde doesn’t allow enums to be flattened. So we will have to allow empty
// filters unless we want to do our own Deserialize impl. Which we don’t.
#[derive(Clone, Debug, Deserialize)]
struct BgpsecFilter {
    #[serde(rename = "SKI")]
    ski: Option<String>,

    asn: Option<u32>,

    comment: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrefixAssertion {
    prefix: AddressPrefix,

    asn: u32,

    #[serde(rename = "maxPrefixLength")]
    max_prefix_len: Option<u8>,

    comment: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BgpsecAssertion {
    asn: u32,

    #[serde(rename = "SKI")]
    ski: String,

    #[serde(rename = "routerPublicKey")]
    router_public_key: String,

    comment: Option<String>,
}


//------------ LoadError ----------------------------------------------------

#[derive(Debug)]
pub enum LoadError {
    Io(io::Error),
    Json(serde_json::Error),
}

impl From<io::Error> for LoadError {
    fn from(err: io::Error) -> LoadError {
        LoadError::Io(err)
    }
}

impl From<serde_json::Error> for LoadError {
    fn from(err: serde_json::Error) -> LoadError {
        LoadError::Json(err)
    }
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            LoadError::Io(ref err) => err.fmt(f),
            LoadError::Json(ref err) => err.fmt(f),
        }
    }
}

impl error::Error for LoadError { }


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
        let json = include_str!("../test/slurm/empty.json");
        let exceptions = LocalExceptions::from_json(json).unwrap();

        assert_eq!(0, exceptions.assertions.len());
        assert_eq!(0, exceptions.filters.len());
    }

    #[test]
    fn should_parse_full_slurm_file() {
        let json = include_str!("../test/slurm/full.json");
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
