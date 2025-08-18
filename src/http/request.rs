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

    /// Returns whether the request is an API request.
    ///
    /// API requests have their path start with `/api/`.
    pub fn is_api(&self) -> bool {
        self.hyper.uri().path().starts_with("/api/")
    }
}


//--- From

impl From<hyper::Request<hyper::body::Incoming>> for Request {
    fn from(hyper: hyper::Request<hyper::body::Incoming>) -> Self {
        Self { hyper }
    }
}

