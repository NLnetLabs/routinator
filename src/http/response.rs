//! Building responses.

use std::fmt;
use std::convert::Infallible;
use chrono::{DateTime, Utc};
use futures::stream::{Stream, StreamExt};
use http_body_util::{BodyExt, Empty, Full, StreamBody};
use http_body_util::combinators::BoxBody;
use hyper::body::{Body, Bytes, Frame};
use hyper::StatusCode;
use hyper::http::response::Builder;
use crate::utils::date::{parse_http_date, format_http_date};
use crate::utils::json::JsonBuilder;
use super::request::Request;


//------------ ResponseBody --------------------------------------------------

type ResponseBody = BoxBody<Bytes, Infallible>;


//------------ Response ------------------------------------------------------

pub struct Response(hyper::Response<ResponseBody>);

impl Response {
    /// Creates a response indicating initial validation.
    pub fn initial_validation(api: bool) -> Self {
        Self::error(
            api,
            StatusCode::SERVICE_UNAVAILABLE,
            "Initial validation ongoing. Please wait."
        )
    }

    /// Returns a Bad Request response.
    pub fn bad_request(api: bool, message: impl fmt::Display) -> Self {
        Self::error(api, StatusCode::BAD_REQUEST, message)
    }

    /// Returns a Not Modified response.
    pub fn not_found(api: bool) -> Self {
        Self::error(api, StatusCode::NOT_FOUND, "resource not found")
    }

    /// Returns a Not Modified response.
    pub fn not_modified(etag: &str, done: DateTime<Utc>) -> Self {
        ResponseBuilder::new(
            StatusCode::NOT_MODIFIED
        ).etag(etag).last_modified(done).empty()
    }

    /// Returns a Method Not Allowed response.
    pub fn method_not_allowed(api: bool) -> Self {
        Self::error(
            api, StatusCode::METHOD_NOT_ALLOWED,
            "method not allowed"
        )
    }

    /// Creates an error response.
    ///
    /// If `api` is `true`, the reponse will havea JSON body, otherwise a
    /// plain text body is used.
    ///
    /// The status code of the response is taken from `status` and the
    /// error message included in the body from `message`.
    pub fn error(
        api: bool,
        status: StatusCode,
        message: impl fmt::Display
    ) -> Self {
        if api {
            ResponseBuilder::new(
                status
            ).content_type(
                ContentType::JSON
            ).body(
                JsonBuilder::build(|json| {
                    json.member_str("error", message);
                })
            )
        }
        else {
            ResponseBuilder::new(
                status
            ).content_type(
                ContentType::TEXT
            ).body(message.to_string())
        }
    }

    /// Returns a Moved Permanently response pointing to the given location.
    #[allow(dead_code)]
    pub fn moved_permanently(location: &str) -> Self {
        ResponseBuilder::new(StatusCode::MOVED_PERMANENTLY)
            .content_type(ContentType::TEXT)
            .location(location)
            .body(format!("Moved permanently to {location}"))
    }

    /// Returns a 304 Not Modified response if appropriate.
    ///
    /// If either the etag or the completion time are referred to by the
    /// request, returns the reponse. If a new response needs to be generated,
    /// returns `None`.
    pub fn maybe_not_modified(
        req: &Request,
        etag: &str,
        done: DateTime<Utc>,
    ) -> Option<Response> {
        // First, check If-None-Match.
        for value in req.headers().get_all("If-None-Match").iter() {
            // Skip ill-formatted values. By being lazy here we may falsely
            // return a full response, so this should be fine.
            let value = match value.to_str() {
                Ok(value) => value,
                Err(_) => continue
            };
            let value = value.trim();
            if value == "*" {
                return Some(Self::not_modified(etag, done))
            }
            for tag in EtagsIter(value) {
                if tag.trim() == etag {
                    return Some(Self::not_modified(etag, done))
                }
            }
        }

        // Now, the If-Modified-Since header.
        if let Some(value) = req.headers().get("If-Modified-Since") {
            if let Some(date) = parse_http_date(value.to_str().ok()?) {
                if date >= done {
                    return Some(Self::not_modified(etag, done))
                }
            }
        }

        None
    }

    /// Converts the response into a hyper response.
    pub fn into_hyper(
        self
    ) -> Result<hyper::Response<ResponseBody>, Infallible> {
        Ok(self.0)
    }
}


//------------ ResponseBuilder ----------------------------------------------

#[derive(Debug)]
pub struct ResponseBuilder {
    builder: Builder,
}

impl ResponseBuilder {
    /// Creates a new builder with the given status.
    pub fn new(status: StatusCode) -> Self {
        ResponseBuilder {
            builder:  Builder::new().status(status).header(
                "Access-Control-Allow-Origin", "*"
            )
        }
    }

    /// Creates a new builder for a 200 OK response.
    pub fn ok() -> Self {
        Self::new(StatusCode::OK)
    }

    /// Adds the content type header.
    pub fn content_type(self, content_type: ContentType) -> Self {
        ResponseBuilder {
            builder: self.builder.header("Content-Type", content_type.0)
        }
    }

    /// Adds the ETag header.
    pub fn etag(self, etag: &str) -> Self {
        ResponseBuilder {
            builder: self.builder.header("ETag", etag)
        }
    }

    /// Adds the Last-Modified header.
    pub fn last_modified(self, last_modified: DateTime<Utc>) -> Self {
        ResponseBuilder {
            builder: self.builder.header(
                "Last-Modified",
                format_http_date(last_modified)
            )
        }
    }

    /// Adds the Location header.
    #[allow(dead_code)]
    pub fn location(self, location: &str) -> Self {
        ResponseBuilder {
            builder: self.builder.header(
                "Location",
                location
            )
        }
    }

    fn finalize<B>(self, body: B) -> Response
    where
        B: Body<Data = Bytes, Error = Infallible> + Send + Sync + 'static
    {
        Response(
            self.builder.body(
                body.boxed()
            ).expect("broken HTTP response builder")
        )
    }

    /// Finalizes the response by adding a body.
    pub fn body(self, body: impl Into<Bytes>) -> Response {
        self.finalize(Full::new(body.into()))
    }

    /// Finalies the response by adding an empty body.
    pub fn empty(self) -> Response {
        self.finalize(Empty::new())
    }

    pub fn stream<S>(self, body: S) -> Response
    where
        S: Stream<Item = Bytes> + Send + Sync + 'static
    {
        self.finalize(
            StreamBody::new(body.map(|item| {
                Ok(Frame::data(item))
            }))
        )
    }
}


//------------ ContentType ---------------------------------------------------

#[derive(Clone, Debug)]
pub struct ContentType(&'static [u8]);

impl ContentType {
    pub const CSV: ContentType = ContentType(
        b"text/csv;charset=utf-8;header=present"
    );
    pub const JSON: ContentType = ContentType(b"application/json");
    pub const TEXT: ContentType = ContentType(b"text/plain;charset=utf-8");
    pub const PROMETHEUS: ContentType = ContentType(
        b"text/plain; version=0.0.4"
    );

    pub fn external(value: &'static [u8]) -> Self {
        ContentType(value)
    }
}


//------------ Parsing Etags -------------------------------------------------

/// An iterator over the etags in an If-Not-Match header value.
///
/// This does not handle the "*" value.
///
/// One caveat: The iterator stops when it encounters bad formatting which
/// makes this indistinguishable from reaching the end of a correctly
/// formatted value. As a consequence, we will 304 a request that has the
/// right tag followed by garbage.
struct EtagsIter<'a>(&'a str);

impl<'a> Iterator for EtagsIter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        // Skip white space and check if we are done.
        self.0 = self.0.trim_start();
        if self.0.is_empty() {
            return None
        }

        // We either have to have a lone DQUOTE or one prefixed by W/
        let prefix_len = if self.0.starts_with('"') {
            1
        }
        else if self.0.starts_with("W/\"") {
            3
        }
        else {
            return None
        };

        // Find the end of the tag which is after the next DQUOTE.
        let end = match self.0[prefix_len..].find('"') {
            Some(index) => index + prefix_len + 1,
            None => return None
        };

        let res = &self.0[0..end];

        // Move past the second DQUOTE and any space.
        self.0 = self.0[end..].trim_start();

        // If we have a comma, skip over that and any space.
        if self.0.starts_with(',') {
            self.0 = self.0[1..].trim_start();
        }

        Some(res)
    }
}


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn etags_iter() {
        assert_eq!(
            EtagsIter("\"foo\", \"bar\", \"ba,zz\"").collect::<Vec<_>>(),
            ["\"foo\"", "\"bar\"", "\"ba,zz\""]
        );
        assert_eq!(
            EtagsIter("\"foo\", W/\"bar\" , \"ba,zz\", ").collect::<Vec<_>>(),
            ["\"foo\"", "W/\"bar\"", "\"ba,zz\""]
        );
    }
}

