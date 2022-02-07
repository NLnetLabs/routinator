//! Handles endpoints related to the log.

use hyper::{Body, Method, Request};
use crate::process::LogOutput;
use super::response::{ContentType, Response, ResponseBuilder};


//------------ handle_get ----------------------------------------------------

pub fn handle_get_or_head(
    req: &Request<Body>,
    log: Option<&LogOutput>,
) -> Option<Response> {
    if req.uri().path() == "/log" {
        let res = ResponseBuilder::ok().content_type(ContentType::JSON);
        if *req.method() == Method::HEAD {
            Some(res.empty())
        }
        else {
            match log {
                Some(log) => Some(res.body(log.get_output())),
                None => Some(res.empty())
            }
        }
    }
    else {
        None
    }
}

