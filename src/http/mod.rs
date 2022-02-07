//! The HTTP server.
//!
//! The module provides all functionality exposed by the HTTP server to
//! those interested. The only public item, [`http_listener`] creates all
//! necessary networking services based on the current configuration and
//! returns a future that drives the server.
//!
//! [`http_listener`]: fn.http_listener.html

pub use self::listener::http_listener;
pub use self::response::ContentType;

mod delta;
mod listener;
mod log;
mod metrics;
mod payload;
mod response;
mod status;
mod ui;
mod validity;


//------------ handle_request ------------------------------------------------

use hyper::{Body, Method, Request};
use crate::metrics::{HttpServerMetrics, SharedRtrServerMetrics};
use crate::payload::SharedHistory;
use crate::process::LogOutput;
use self::response::Response;


async fn handle_request(
    req: Request<Body>,
    origins: &SharedHistory,
    metrics: &HttpServerMetrics,
    rtr_metrics: &SharedRtrServerMetrics,
    log: Option<&LogOutput>,
) -> Response {
    metrics.inc_requests();
    if *req.method() != Method::GET && *req.method() != Method::HEAD {
        return Response::method_not_allowed()
    }

    if let Some(response) = payload::handle_get_or_head(&req, origins) {
        return response
    }
    if let Some(response) = delta::handle_get_or_head(&req, origins) {
        return response
    }
    if let Some(response) = log::handle_get_or_head(&req, log) {
        return response
    }
    if let Some(response) = metrics::handle_get_or_head(
        &req, origins, metrics, rtr_metrics
    ).await {
        return response
    }
    if let Some(response) = status::handle_get_or_head(
        &req, origins, metrics, rtr_metrics
    ).await {
        return response
    }
    if let Some(response) = validity::handle_get_or_head(&req, origins) {
        return response
    }

    #[cfg(feature = "ui")]
    if let Some(response) = ui::handle_get_or_head(&req) {
        return response
    }
    
    Response::not_found()
}

