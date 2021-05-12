//! The HTTP server.
//!
//! The module provides all functionality exposed by the HTTP server to
//! those interested. The only public item, [`http_listener`] creates all
//! necessary networking services based on the current configuration and
//! returns a future that drives the server.
//!
//! [`http_listener`]: fn.http_listener.html

pub use self::listener::http_listener;

mod delta;
mod errors;
mod listener;
mod log;
mod payload;
mod status;
mod ui;
mod validity;


//------------ handle_request ------------------------------------------------

use hyper::{Body, Method, Request, Response};
use crate::metrics::{HttpServerMetrics, SharedRtrServerMetrics};
use crate::payload::SharedHistory;
use crate::process::LogOutput;
use self::errors::{method_not_allowed, not_found};


async fn handle_request(
    req: Request<Body>,
    origins: &SharedHistory,
    metrics: &HttpServerMetrics,
    rtr_metrics: &SharedRtrServerMetrics,
    log: Option<&LogOutput>,
) -> Response<Body> {
    metrics.inc_requests();
    if *req.method() != Method::GET {
        return method_not_allowed()
    }

    if let Some(response) = payload::handle_get(&req, origins) {
        return response
    }
    if let Some(response) = delta::handle_get(&req, origins) {
        return response
    }
    if let Some(response) = log::handle_get(&req, log) {
        return response
    }
    if let Some(response) = status::handle_get(
        &req, origins, metrics, rtr_metrics
    ).await {
        return response
    }
    if let Some(response) = validity::handle_get(&req, origins) {
        return response
    }

    #[cfg(feature = "ui")]
    if let Some(response) = ui::handle_get(&req) {
        return response
    }
    
    not_found()
}

