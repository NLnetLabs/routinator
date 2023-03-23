//! Local exceptions per RFC 8416 aka SLURM.

use std::{error, fmt, fs, io};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use log::error;
use rpki::rtr::payload::{Payload, RouteOrigin};
use rpki::slurm::{PrefixFilter, SlurmFile};
use crate::config::Config;
use crate::error::Failed;


//------------ LocalExceptions -----------------------------------------------

#[derive(Clone, Debug)]
pub struct LocalExceptions {
    filters: Vec<PrefixFilter>,
    assertions: Vec<(Payload, Arc<ExceptionInfo>)>,
}

impl LocalExceptions {
    pub fn empty() -> Self {
        LocalExceptions {
            filters: Vec::new(),
            assertions: Vec::new(),
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
        self.assertions.extend(
            json.assertions.prefix.into_iter().map(|item| {
                (
                    RouteOrigin::new(item.prefix, item.asn).into(),
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

    pub fn keep_payload(&self, payload: &Payload) -> bool {
        for filter in &self.filters {
            if filter.drop_payload(payload) {
                return false
            }
        }
        true
    }

    pub fn assertions(
        &self
    ) -> impl Iterator<Item = (&Payload, Arc<ExceptionInfo>)> + '_ {
        self.assertions.iter().map(|(payload, info)| {
            (payload, info.clone())
        })
    }
}


//------------ ExceptionInfo -------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct ExceptionInfo {
    pub path: Option<Arc<Path>>,
    pub comment: Option<String>,
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

