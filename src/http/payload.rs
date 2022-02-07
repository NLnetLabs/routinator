//! Handles endpoints related to output of payload sets.

use std::convert::Infallible;
use futures::stream;
use hyper::{Body, Method, Request};
use crate::output;
use crate::output::OutputFormat;
use crate::payload::SharedHistory;
use super::response::{Response, ResponseBuilder};


//------------ Request Handlers ----------------------------------------------

pub fn handle_get_or_head(
    req: &Request<Body>,
    history: &SharedHistory,
) -> Option<Response> {
    let path = req.uri().path();
    let format = if path == "/api/v1/origins/" {
        OutputFormat::Json
    }
    else {
        OutputFormat::from_path(req.uri().path())?
    };

    let selection = match output::Selection::from_query(req.uri().query()) {
        Ok(selection) => selection,
        Err(_) => return Some(Response::bad_request()),
    };

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
        _ => return Some(Response::initial_validation()),
    };

    let etag = format!("\"{:x}-{}\"", session, serial);

    if let Some(response) = Response::maybe_not_modified(req, &etag, created) {
        return Some(response)
    }

    let res = ResponseBuilder::ok()
        .content_type(format.content_type())
        .etag(&etag).last_modified(created);
    if *req.method() == Method::HEAD {
        Some(res.empty())
    }
    else {
        Some(res.body(Body::wrap_stream(stream::iter(
            format.stream(snapshot, selection, metrics)
                .map(Result::<_, Infallible>::Ok)
        ))))
    }
}

