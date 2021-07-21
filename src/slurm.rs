//! Local exceptions per RFC 8416 aka SLURM.

use std::{cmp, error, fmt, fs, io};
use std::convert::TryFrom;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use log::error;
use rpki::repository::resources::AsId;
use serde::{Deserialize, Deserializer};
use crate::config::Config;
use crate::error::Failed;
use crate::payload::{AddressPrefix, RouteOrigin};


//------------ LocalExceptions -----------------------------------------------

#[derive(Clone, Debug)]
pub struct LocalExceptions {
    filters: Vec<PrefixFilter>,
    origin_assertions: Vec<(RouteOrigin, Arc<ExceptionInfo>)>,
}

impl LocalExceptions {
    pub fn empty() -> Self {
        LocalExceptions {
            filters: Vec::new(),
            origin_assertions: Vec::new(),
        }
    }

    pub fn load(config: &Config, keep_comments: bool) -> Result<Self, Failed> {
        let mut res = LocalExceptions::empty();
        let mut ok = true;
        for path in &config.exceptions {
            if let Err(err) = res.extend_from_file(path, keep_comments) {
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
            Err(Failed)
        }
    }

    pub fn from_json(
        json: &str,
        keep_comments: bool
    ) -> Result<Self, serde_json::Error> {
        let mut res = LocalExceptions::empty();
        res.extend_from_json(json, keep_comments)?;
        Ok(res)
    }

    pub fn from_file<P: AsRef<Path>>(
        path: P,
        keep_comments: bool
    ) -> Result<Self, LoadError> {
        let mut res = Self::empty();
        res.extend_from_file(path, keep_comments)?;
        Ok(res)
    }

    pub fn extend_from_json(
        &mut self,
        json: &str,
        keep_comments: bool
    ) -> Result<(), serde_json::Error> {
        self.extend_from_parsed(
            SlurmFile::from_str(json)?, None, keep_comments
        );
        Ok(())
    }

    pub fn extend_from_file<P: AsRef<Path>>(
        &mut self,
        path: P,
        keep_comments: bool
    ) -> Result<(), LoadError> {
        let buf = fs::read_to_string(&path)?;
        self.extend_from_parsed(
            SlurmFile::from_str(&buf)?,
            Some(path.as_ref().into()), keep_comments
        );
        Ok(())
    }

    fn extend_from_parsed(
        &mut self,
        json: SlurmFile,
        path: Option<Arc<Path>>,
        keep_comments: bool,
    ) {
        self.filters.extend(json.filters.prefix.into_iter().map(Into::into));
        self.origin_assertions.extend(
            json.assertions.prefix.into_iter().map(|item| {
                (
                    RouteOrigin::new(
                        item.asn.into(), item.prefix,
                        item.max_prefix_len.map(|len| {
                            cmp::min(
                                len, if item.prefix.is_v4() { 32 } else { 128 }
                            )
                        }).unwrap_or_else(|| item.prefix.address_length())
                    ),
                    Arc::new(ExceptionInfo {
                        path: path.clone(),
                        comment: if keep_comments {
                            item.comment
                        }
                        else {
                            None
                        }
                    })
                )
            })
        );
    }

    pub fn keep_origin(&self, origin: RouteOrigin) -> bool {
        for filter in &self.filters {
            if filter.filter_origin(origin) {
                return false
            }
        }
        true
    }

    pub fn origin_assertions(
        &self
    ) -> impl Iterator<Item = (RouteOrigin, Arc<ExceptionInfo>)> + '_ {
        self.origin_assertions.iter().map(|(origin, info)| {
            (*origin, info.clone())
        })
    }
}


//------------ PrefixFilter --------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrefixFilter {
    prefix: Option<AddressPrefix>,
    asn: Option<AsId>,
}

impl PrefixFilter {
    fn filter_origin(&self, addr: RouteOrigin) -> bool {
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
    pub path: Option<Arc<Path>>,
    pub comment: Option<String>,
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

#[derive(Clone, Debug)]
struct PrefixAssertion {
    prefix: AddressPrefix,

    asn: u32,

    max_prefix_len: Option<u8>,

    comment: Option<String>,
}

// We need to enforce that max_prefix_len is greater than or equal to
// prefix.len(), so we need to roll our own implementation.
impl<'de> Deserialize<'de> for PrefixAssertion {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D
    ) -> Result<Self, D::Error> {
        use serde::de;

        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        enum Fields { Prefix, Asn, MaxPrefixLength, Comment }

        struct StructVisitor;

        impl<'de> de::Visitor<'de> for StructVisitor {
            type Value = PrefixAssertion;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("PrefixAssertion struct")
            }

            fn visit_map<V: de::MapAccess<'de>>(
                self, mut map: V
            ) -> Result<Self::Value, V::Error> {
                let mut prefix = None;
                let mut asn = None;
                let mut max_prefix_len = None;
                let mut comment = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Fields::Prefix => {
                            if prefix.is_some() {
                                return Err(
                                    de::Error::duplicate_field("prefix")
                                );
                            }
                            prefix = Some(map.next_value()?);
                        }
                        Fields::Asn => {
                            if asn.is_some() {
                                return Err(
                                    de::Error::duplicate_field("asn")
                                );
                            }
                            asn = Some(map.next_value()?);
                        }
                        Fields::MaxPrefixLength => {
                            if max_prefix_len.is_some() {
                                return Err(
                                    de::Error::duplicate_field(
                                        "maxPrefixLength"
                                    )
                                );
                            }
                            max_prefix_len = Some(map.next_value()?);
                        }
                        Fields::Comment => {
                            if comment.is_some() {
                                return Err(
                                    de::Error::duplicate_field("comment")
                                );
                            }
                            comment = Some(map.next_value()?);
                        }
                    }
                }

                let prefix: AddressPrefix = prefix.ok_or_else(|| {
                    de::Error::missing_field("prefix")
                })?;
                let asn = asn.ok_or_else(|| {
                    de::Error::missing_field("asn")
                })?;

                if let Some(max_prefix_len) = max_prefix_len {
                    if
                        (prefix.is_v4() && max_prefix_len > 32)
                        || max_prefix_len > 128
                    {
                        return Err(de::Error::custom(
                            "maxPrefixLen is too large"
                        ))
                    }
                    if prefix.address_length() > max_prefix_len {
                        return Err(de::Error::custom(
                            "maxPrefixLen exceeds prefix length")
                        )
                    }
                }

                Ok(PrefixAssertion { prefix, asn, max_prefix_len, comment })
            }
        }

        const FIELDS: &[&str] = &[
            "prefix", "asn", "maxPrefixLen", "comment"
        ];
        deserializer.deserialize_struct(
            "PrefixAssertion", FIELDS, StructVisitor
        )
    }
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
    use crate::payload::AddressPrefix;

    fn address_origin(
        asn: u32,
        ip_string: &str,
        length: u8,
        max_length: u8
    ) -> RouteOrigin {
        RouteOrigin::new(
            AsId::from(asn),
            AddressPrefix::new(
                ip_string.parse().unwrap(),
                length
            ),
            max_length,
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
    fn parse_empty_slurm_file() {
        let json = include_str!("../test/slurm/empty.json");
        let exceptions = LocalExceptions::from_json(json, false).unwrap();

        assert_eq!(0, exceptions.origin_assertions.len());
        assert_eq!(0, exceptions.filters.len());
    }

    #[test]
    fn parse_full_slurm_file() {
        let json = include_str!("../test/slurm/full.json");
        let exceptions = LocalExceptions::from_json(json, false).unwrap();

        assert_eq!(2, exceptions.origin_assertions.len());
        assert_eq!(
            exceptions.origin_assertions[0].0, 
            address_origin(64496, "198.51.100.0", 24, 24)
        );
        assert_eq!(
            exceptions.origin_assertions[1].0,
            address_origin(64496, "2001:DB8::", 32, 48)
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

    #[test]
    fn parse_bad_maxlen_file() {
        let json = include_str!("../test/slurm/bad_maxlen.json");
        assert!(LocalExceptions::from_json(json, false).is_err());
    }
}
