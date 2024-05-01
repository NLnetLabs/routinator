//! Request handling.

use hyper::{Method, Uri};
use hyper::header::HeaderMap;


//------------ Request -------------------------------------------------------

pub struct Request {
    hyper: hyper::Request<hyper::body::Incoming>,
}

impl Request {
    /// Returns whether the method is GET or HEAD.
    pub fn is_get_or_head(&self) -> bool {
        self.hyper.method() == Method::GET
            || self.hyper.method() == Method::HEAD
    }

    /// Returns whether the method is HEAD.
    pub fn is_head(&self) -> bool {
        self.hyper.method() == Method::HEAD
    }

    /// Returns the URI of the request.
    pub fn uri(&self) -> &Uri {
        self.hyper.uri()
    }

    /// Returns the headers.
    pub fn headers(&self) -> &HeaderMap {
        self.hyper.headers()
    }
}


//--- From

impl From<hyper::Request<hyper::body::Incoming>> for Request {
    fn from(hyper: hyper::Request<hyper::body::Incoming>) -> Self {
        Self { hyper }
    }
}

