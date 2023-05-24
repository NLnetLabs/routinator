//! Local exceptions per RFC 8416 aka SLURM.

use std::{error, fmt, fs, io};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use log::error;
use rpki::rtr::payload::{RouteOrigin, RouterKey};
use rpki::slurm::{BgpsecFilter, PrefixFilter, SlurmFile};
use crate::config::Config;
use crate::error::Failed;


//------------ LocalExceptions -----------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct LocalExceptions {
    origin_filters: Vec<PrefixFilter>,
    router_key_filters: Vec<BgpsecFilter>,

    origin_assertions: Vec<(RouteOrigin, Arc<ExceptionInfo>)>,
    router_key_assertions: Vec<(RouterKey, Arc<ExceptionInfo>)>,
}

impl LocalExceptions {
    pub fn empty() -> Self {
        Self::default()
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
        // If we don’t keep comments, we can have one info value for
        // everything and safe a bit of memory.
        let info = keep_comments.then(|| {
            Arc::new(ExceptionInfo {
                path: path.clone(),
                comment: None
            })
        });
        let info = info.as_ref(); // So we can use info.cloned() below.

        self.origin_filters.extend(
            json.filters.prefix.into_iter().map(|mut item| {
                if !keep_comments {
                    item.comment = None
                }
                item
            })
        );
        self.router_key_filters.extend(
            json.filters.bgpsec.into_iter().map(|mut item| {
                if !keep_comments {
                    item.comment = None
                }
                item
            })
        );
        self.origin_assertions.extend(
            json.assertions.prefix.into_iter().map(|item| {
                (
                    RouteOrigin::new(item.prefix, item.asn),
                    info.cloned().unwrap_or_else(|| {
                        Arc::new(ExceptionInfo {
                            path: path.clone(),
                            comment: item.comment,
                        })
                    })
                )
            })
        );
        self.router_key_assertions.extend(
            json.assertions.bgpsec.into_iter().map(|item| {
                (
                    RouterKey::new(
                        item.ski, item.asn, item.router_public_key.into()
                    ),
                    info.cloned().unwrap_or_else(|| {
                        Arc::new(ExceptionInfo {
                            path: path.clone(),
                            comment: item.comment,
                        })
                    })
                )
            })
        );
    }

    pub fn drop_origin(&self, origin: RouteOrigin) -> bool {
        self.origin_filters.iter().any(|filter| filter.drop_origin(origin))
    }

    pub fn drop_router_key(&self, key: &RouterKey) -> bool {
        self.router_key_filters.iter().any(|filter| {
            filter.drop_router_key(key)
        })
    }

    pub fn origin_assertions(
        &self
    ) -> impl Iterator<Item = (RouteOrigin, Arc<ExceptionInfo>)> + '_ {
        self.origin_assertions.iter().map(|(origin, info)| {
            (*origin, info.clone())
        })
    }

    pub fn router_key_assertions(
        &self
    ) -> impl Iterator<Item = (RouterKey, Arc<ExceptionInfo>)> + '_ {
        self.router_key_assertions.iter().map(|(key, info)| {
            (key.clone(), info.clone())
        })
    }
}


//------------ ExceptionInfo -------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct ExceptionInfo {
    pub path: Option<Arc<Path>>,
    pub comment: Option<String>,
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for ExceptionInfo {
    fn arbitrary(
        u: &mut arbitrary::Unstructured<'a>
    ) -> arbitrary::Result<Self> {
        Ok(Self {
            path: if bool::arbitrary(u)? {
                Some(
                    std::path::PathBuf::arbitrary(u)?.into_boxed_path().into()
                )
            }
            else {
                None
            },
            comment: Option::arbitrary(u)?,
        })
    }
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

