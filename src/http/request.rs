//! Request handling.

use hyper::body::Incoming;
use hyper::{Method, Uri};
use hyper::header::HeaderMap;


//------------ Request -------------------------------------------------------

pub struct Request {
    parts: hyper::http::request::Parts,
    body: Option<Incoming>,
}

impl Request {
    /// Returns whether the method is GET or HEAD.
    pub fn is_get_or_head(&self) -> bool {
        self.parts.method == Method::GET
            || self.parts.method == Method::HEAD
    }

    /// Returns whether the method is HEAD.
    pub fn is_head(&self) -> bool {
        self.parts.method == Method::HEAD
    }

    /// Returns whether the method is POST.
    pub fn is_post(&self) -> bool {
        self.parts.method == Method::POST
    }

    /// Returns the URI of the request.
    pub fn uri(&self) -> &Uri {
        &self.parts.uri
    }

    /// Returns the body of the request
    pub fn body(self) -> Option<Incoming> {
        self.body
    }

    /// Returns the headers.
    pub fn headers(&self) -> &HeaderMap {
        &self.parts.headers
    }

    /// Returns whether the request is an API request.
    ///
    /// API requests have their path start with `/api/`.
    pub fn is_api(&self) -> bool {
        self.parts.uri.path().starts_with("/api/")
    }

    pub fn new(
        parts: hyper::http::request::Parts, 
        body: Option<Incoming>
    ) -> Self {
        Self { parts, body }
    }
}


