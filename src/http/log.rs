//! Handles endpoints related to the log.

use hyper::{Body, Request, Response};
use crate::process::LogOutput;


//------------ handle_get ----------------------------------------------------

pub fn handle_get(
    req: &Request<Body>,
    log: Option<&LogOutput>,
) -> Option<Response<Body>> {
    if req.uri().path() == "/log" {
        Some(
            Response::builder()
            .header("Content-Type", "text/plain;charset=UTF-8")
            .body(
                if let Some(log) = log {
                    log.get_output().into()
                }
                else {
                    Body::empty()
                }
            )
            .unwrap()
        )
    }
    else {
        None
    }
}

