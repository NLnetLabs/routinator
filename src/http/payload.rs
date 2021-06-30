//! Handles endpoints related to output of payload sets.

use std::convert::Infallible;
use chrono::{DateTime, Utc};
use futures::stream;
use hyper::{Body, Request, Response};
use crate::output;
use crate::output::OutputFormat;
use crate::payload::SharedHistory;
use crate::utils::http::{parse_http_date, format_http_date};
use super::errors::{bad_request, initial_validation};


//------------ handle_get ----------------------------------------------------

pub fn handle_get(
    req: &Request<Body>,
    history: &SharedHistory,
) -> Option<Response<Body>> {
    let format = OutputFormat::from_path(req.uri().path())?;

    let (session, serial, created, snapshot, metrics) = {
        let history = history.read();
        (
            history.session(),
            history.serial(),
            history.created(),
            history.current(),
            history.metrics()
        )
    };
    let (snapshot, metrics, created) = match (snapshot, metrics, created) {
        (Some(snapshot), Some(metrics), Some(created)) => {
            (snapshot, metrics, created)
        }
        _ => return Some(initial_validation()),
    };

    let etag = format!("\"{:x}-{}\"", session, serial);

    if let Some(response) = maybe_not_modified(req, &etag, created) {
        return Some(response)
    }

    let selection = match output::Selection::from_query(req.uri().query()) {
        Ok(selection) => selection,
        Err(_) => return Some(bad_request()),
    };
    let stream = format.stream(snapshot, selection, metrics);

    let builder = Response::builder()
        .header("Content-Type", format.content_type())
        .header("ETag", etag)
        .header("Last-Modified", format_http_date(created));

    Some(builder.body(Body::wrap_stream(stream::iter(
        stream.map(Result::<_, Infallible>::Ok)
    )))
    .unwrap())
}

/// Returns a 304 Not Modified response if appropriate.
///
/// If either the etag or the completion time are referred to by the request,
/// returns the reponse. If a new response needs to be generated, returns
/// `None`.
fn maybe_not_modified(
    req: &Request<Body>,
    etag: &str,
    done: DateTime<Utc>,
) -> Option<Response<Body>> {
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
            return Some(not_modified(etag, done))
        }
        for tag in EtagsIter(value) {
            if tag.trim() == etag {
                return Some(not_modified(etag, done))
            }
        }
    }

    // Now, the If-Modified-Since header.
    if let Some(value) = req.headers().get("If-Modified-Since") {
        if let Some(date) = parse_http_date(value.to_str().ok()?) {
            if date >= done {
                return Some(not_modified(etag, done))
            }
        }
    }

    None
}

/// Returns the 304 Not Modified response.
fn not_modified(etag: &str, done: DateTime<Utc>) -> Response<Body> {
    Response::builder()
    .status(304)
    .header("ETag", etag)
    .header("Last-Modified", format_http_date(done))
    .body(Body::empty()).unwrap()
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

