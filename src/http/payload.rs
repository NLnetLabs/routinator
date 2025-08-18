//! Handles endpoints related to output of payload sets.

use futures::stream;
use crate::config::Config;
use crate::output::{Output, OutputFormat};
use crate::payload::SharedHistory;
use super::request::Request;
use super::response::{Response, ResponseBuilder};


//------------ State ---------------------------------------------------------

pub struct State {
    output: Output,
}

impl State {
    pub fn new(config: &Config) -> Self {
        Self {
            output: Output::from_config(config),
        }
    }

    pub fn handle_get_or_head(
        &self,
        req: Request,
        history: &SharedHistory,
    ) -> Result<Response, Request> {
        let path = req.uri().path();
        let format = if path == "/api/v1/origins/" {
            OutputFormat::Json
        }
        else {
            let Some(format) = OutputFormat::from_path(req.uri().path()) else {
                return Err(req);
            };
            format
        };

        let mut output = self.output.clone();
        if let Err(err) = output.update_from_query(req.uri().query()) {
            return Ok(Response::bad_request(req.is_api(), err))
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
            _ => return Ok(Response::initial_validation(req.is_api())),
        };

        let etag = format!("\"{session:x}-{serial}\"");

        if let Some(response) = Response::maybe_not_modified(
            &req, &etag, created
        ) {
            return Ok(response)
        }

        let res = ResponseBuilder::ok()
            .content_type(format.content_type())
            .etag(&etag).last_modified(created);
        if req.is_head() {
            Ok(res.empty())
        }
        else {
            Ok(res.stream(
                stream::iter(output.stream(snapshot, metrics, format))
            ))
        }
    }
}

