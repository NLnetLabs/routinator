//! Handles endpoints related to the log.

use std::sync::Arc;
use crate::log::LogOutput;
use super::request::Request;
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
        req: Request,
    ) -> Result<Response, Request> {
        if req.uri().path() == "/log" {
            let res = ResponseBuilder::ok().content_type(ContentType::TEXT);
            if req.is_head() {
                Ok(res.empty())
            }
            else {
                match self.log.as_ref() {
                    Some(log) => Ok(res.body(log.get_output())),
                    None => Ok(res.empty())
                }
            }
        }
        else {
            Err(req)
        }
    }
}

