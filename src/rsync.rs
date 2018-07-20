//! Rsync procession.

use std::{fmt, io, str};
use std::fs::create_dir_all;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Condvar, Mutex};
use bytes::Bytes;


//------------ update --------------------------------------------------------

pub fn update<P: AsRef<Path>>(
    source: &Module,
    destination: P
) -> Result<(), io::Error> {
    debug!("rsyncing from {}.", source);
    let destination = destination.as_ref();
    create_dir_all(destination)?;
    let mut destination = format!("{}", destination.display());
    if !destination.ends_with("/") {
        destination.push('/')
    }
    let status = Command::new("rsync")
        .arg("-az")
        .arg("--delete")
        .arg("--contimeout=10")
        .arg(source.to_string())
        .arg(destination)
        .status()?;
    if !status.success() {
        return Err(io::Error::new(io::ErrorKind::Other, "rsync failed"))
    }
    Ok(())
}


//------------ Runner --------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Runner(Arc<Mutex<State>>);

#[derive(Clone, Debug)]
struct State {
    running: Vec<(Uri, Arc<(Mutex<bool>, Condvar)>)>,
}

impl Runner {
    pub fn new() -> Self {
        Runner(Arc::new(Mutex::new(
            State {
                running: Vec::new(),
            }
        )))
    }

    /*

    pub fn update<P: AsRef<Path>>(
        &self,
        source: &Uri,
        destination: P
    ) -> Result<(), io::Error> {
        let cvar = self.wait(source);
        let mut finished = cvar.0.lock().unwrap();
        let res = self._update(source, destination);
        self.remove_cvar(source);
        *finished = true;
        cvar.1.notify_all();
        res
    }

    pub fn _update<P: AsRef<Path>>(
        &self,
        source: &Uri,
        destination: P
    ) -> Result<(), io::Error> {
        debug!("rsyncing from {}.", source);
        let destination = destination.as_ref();
        create_dir_all(destination)?;
        let mut destination = format!("{}", destination.display());
        if !destination.ends_with("/") {
            destination.push('/')
        }
        let status = Command::new("rsync")
            .arg("-az")
            .arg("--delete")
            .arg("--contimeout=10")
            .arg(source.to_string())
            .arg(destination)
            .status()?;
        if !status.success() {
            return Err(io::Error::new(io::ErrorKind::Other, "rsync failed"))
        }
        Ok(())
    }

    fn wait(&self, source: &Uri) -> Arc<(Mutex<bool>, Condvar)> {
        loop {
            match self.get_cvar(source) {
                Ok(cvar) => return cvar,
                Err(cvar) => {
                    let mut finished = cvar.0.lock().unwrap();
                    while !*finished {
                        finished = cvar.1.wait(finished).unwrap();
                    }
                }
            }
        }
    }

    fn get_cvar(
        &self,
        source: &Uri
    ) -> Result<Arc<(Mutex<bool>, Condvar)>, Arc<(Mutex<bool>, Condvar)>> {
        let mut state = self.0.lock().unwrap();
        for item in &state.running {
            if item.0.eq_module(source) {
                return Err(item.1.clone())
            }
        }
        let res = Arc::new((Mutex::new(false), Condvar::new()));
        state.running.push((source.clone(), res.clone()));
        Ok(res)
    }

    fn remove_cvar(&self, source: &Uri) {
        let mut state = self.0.lock().unwrap();
        state.running.retain(|item| !item.0.eq_module(source))
    }

    */
}


//------------ Uri -----------------------------------------------------------

/// An rsync URI.
///
/// This implements a simplified form of the the rsync URI defined in RFC 5781
/// which in turn references RFC 3986. Only absolute URIs including an
/// authority are allowed.
///
/// Parsing is simplified in that it only checks for the correct structure and
/// that no forbidden characters are present.
///
//  In particular, forbidden characters are
//
//     SPACE CONTROL " # < > ? [ \\ ] ^ ` { | }
//
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Uri {
    module: Module,
    path: Bytes
}

impl Uri {
    pub fn from_slice(slice: &[u8]) -> Result<Self, UriError> {
        Self::from_bytes(slice.into())
    }

    pub fn from_bytes(mut bytes: Bytes) -> Result<Self, UriError> {
        if !is_uri_ascii(&bytes) {
            return Err(UriError::NotAscii)
        }
        if !bytes.starts_with(b"rsync://") {
            return Err(UriError::BadScheme)
        }
        bytes.advance(8);
        let (authority, module) = {
            let mut parts = bytes.splitn(3, |ch| *ch == b'/');
            let authority = match parts.next() {
                Some(part) => part.len(),
                None => return Err(UriError::BadUri)
            };
            let module = match parts.next() {
                Some(part) => part.len(),
                None => return Err(UriError::BadUri)
            };
            (authority, module)
        };
        let authority = bytes.split_to(authority);
        bytes.advance(1);
        let module = bytes.split_to(module);
        bytes.advance(1);
        Ok(Uri {
            module: Module::new(authority, module),
            path: bytes
        })
    }

    pub fn module(&self) -> &Module {
        &self.module
    }

    pub fn to_module(&self) -> Module {
        self.module.clone()
    }

    pub fn path(&self) -> &str {
        unsafe { ::std::str::from_utf8_unchecked(self.path.as_ref()) }
    }

    pub fn to_string(&self) -> String {
        format!("{}", self)
    }

    pub fn parent(&self) -> Option<Self> {
        // rsplit always returns at least one element.
        let tail = self.path.rsplit(|ch| *ch == b'/').next().unwrap().len();
        if tail == 0 {
            None
        }
        else {
            let mut res = self.clone();
            if tail == self.path.len() {
                res.path = Bytes::from_static(b"")
            }
            else {
                res.path = self.path.slice(
                    0, self.path.len() - tail - 1
                );
            }
            Some(res)
        }
    }

    pub fn join(&self, path: &[u8]) -> Self {
        assert!(is_uri_ascii(path));
        let mut res = self.clone();
        if !res.path.ends_with(b"/") {
            res.path.to_mut().extend_from_slice(b"/");
        }
        res.path.to_mut().extend_from_slice(path);
        res
    }

    pub fn ends_with(&self, extension: &str) -> bool {
        self.path.ends_with(extension.as_bytes())
    }
}

impl fmt::Display for Uri {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.module.fmt(f)?;
        if !self.path.is_empty() {
            write!(f, "{}", self.path())?;
        }
        Ok(())
    }
}


//------------ Module --------------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Module {
    authority: Bytes,
    module: Bytes,
}

impl Module {
    pub fn new<A, M>(authority: A, module: M) -> Self
    where A: Into<Bytes>, M: Into<Bytes> {
        let authority = authority.into();
        let module = module.into();
        assert!(is_uri_ascii(authority.as_ref()));
        assert!(is_uri_ascii(module.as_ref()));
        Module { authority, module }
    }

    pub fn to_uri(&self) -> Uri {
        Uri {
            module: self.clone(),
            path: Bytes::from_static(b""),
        }
    }

    pub fn to_string(&self) -> String {
        format!("{}", self)
    }

    pub fn authority(&self) -> &str {
        unsafe { ::std::str::from_utf8_unchecked(self.authority.as_ref()) }
    }

    pub fn module(&self) -> &str {
        unsafe { ::std::str::from_utf8_unchecked(self.module.as_ref()) }
    }
}

impl fmt::Display for Module {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "rsync://{}/{}/", self.authority(), self.module())
    }
}


//------------ Helper Functions ----------------------------------------------

pub fn is_uri_ascii<S: AsRef<[u8]>>(slice: S) -> bool {
    slice.as_ref().iter().all(|&ch| {
        ch > b' ' && ch != b'"' && ch != b'#' && ch != b'<' && ch != b'>'
            && ch != b'?' && ch != b'[' && ch != b'\\' && ch != b']'
            && ch != b'^' && ch != b'`' && ch != b'{' && ch != b'|'
            && ch != b'}' && ch < 0x7F
    })
}


//------------ UriError ------------------------------------------------------

#[derive(Clone, Debug, Fail)]
pub enum UriError {
    #[fail(display="invalid characters")]
    NotAscii,

    #[fail(display="bad URI")]
    BadUri,

    #[fail(display="bad URI scheme")]
    BadScheme,
}


//============ Testing =======================================================

#[cfg(test)]
mod test {
    use super::*;

    fn from_parts(
        auth: &'static str,
        module: &'static str,
        path: &'static str,
        is_dir: bool
    ) -> Uri {
        Uri {
            authority: Bytes::from_static(auth.as_bytes()),
            module: Bytes::from_static(module.as_bytes()),
            path: Bytes::from_static(path.as_bytes()),
            is_dir
        }
    }

    #[test]
    fn parse() {
        assert_eq!(
            Uri::from_slice(b"rsync://user@foo.bar:322/mod/path").unwrap(),
            from_parts("user@foo.bar:322", "mod", "path", false)
        );
        assert_eq!(
            Uri::from_slice(b"rsync://user@foo.bar:322/mod/path/").unwrap(),
            from_parts("user@foo.bar:322", "mod", "path", true)
        );
    }

    #[test]
    fn parent() {
        let uri = Uri::from_slice(b"rsync://auth/mod/a/b/c").unwrap();
        assert_eq!(uri.path(), "a/b/c");
        assert!(!uri.is_dir());
        let uri = uri.parent().unwrap();
        assert_eq!(uri.path(), "a/b");
        assert!(uri.is_dir());
        let uri = uri.parent().unwrap();
        assert_eq!(uri.path(), "a");
        assert!(uri.is_dir());
        let uri = uri.parent().unwrap();
        assert_eq!(uri.path(), "");
        assert!(uri.is_dir());
        assert_eq!(uri.parent(), None)
    }
}
