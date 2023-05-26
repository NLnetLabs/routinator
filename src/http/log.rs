//! Handles endpoints related to the log.

use std::sync::Arc;
use hyper::{Body, Method, Request};
use crate::process::LogOutput;
use super::response::{ContentType, Response, ResponseBuilder};

//------------ State ---------------------------------------------------------

pub struct State {
    log: Option<Arc<LogOutput>>,
}

impl State {
    pub fn new(log: Option<Arc<LogOutput>>) -> Self {
        Self { log }
    }

    pub fn handle_get_or_head(
        &self,
        req: &Request<Body>,
    ) -> Option<Response> {
        if req.uri().path() == "/log" {
            let res = ResponseBuilder::ok().content_type(ContentType::TEXT);
            if *req.method() == Method::HEAD {
                Some(res.empty())
            }
            else {
                match self.log.as_ref() {
                    Some(log) => Some(res.body(log.get_output())),
                    None => Some(res.empty())
                }
            }
        }
        else {
            None
        }
    }
}

