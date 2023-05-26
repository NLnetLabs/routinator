//! Rules on how to dispatch a request.

use std::sync::Arc;
use hyper::{Body, Method, Request};
use crate::config::Config;
use crate::metrics::{HttpServerMetrics, SharedRtrServerMetrics};
use crate::payload::SharedHistory;
use crate::process::LogOutput;
use super::{delta, log, metrics, payload, status, validity};
use super::response::Response;

//------------ State ---------------------------------------------------------

pub struct State {
    payload: payload::State,
    log: log::State,
    history: SharedHistory,
    metrics: Arc<HttpServerMetrics>,
    rtr_metrics: SharedRtrServerMetrics,
}

impl State {
    pub fn new(
        config: &Config,
        history: SharedHistory,
        rtr_metrics: SharedRtrServerMetrics,
        log: Option<Arc<LogOutput>>
    ) -> Self {
        Self {
            payload: payload::State::new(config),
            log: log::State::new(log),
            history,
            metrics: Arc::new(HttpServerMetrics::default()),
            rtr_metrics,
        }
    }
    
    pub fn metrics(&self) -> &Arc<HttpServerMetrics> {
        &self.metrics
    }

    pub async fn handle_request(
        &self,
        req: Request<Body>,
    ) -> Response {
        self.metrics.inc_requests();
        if *req.method() != Method::GET && *req.method() != Method::HEAD {
            return Response::method_not_allowed()
        }

        if let Some(response) = self.payload.handle_get_or_head(
            &req, &self.history
        ) {
            return response
        }
        if let Some(response) = delta::handle_get_or_head(
            &req, &self.history
        ) {
            return response
        }
        if let Some(response) = self.log.handle_get_or_head(&req) {
            return response
        }
        if let Some(response) = metrics::handle_get_or_head(
            &req, &self.history, &self.metrics, &self.rtr_metrics
        ).await {
            return response
        }
        if let Some(response) = status::handle_get_or_head(
            &req, &self.history, &self.metrics, &self.rtr_metrics
        ).await {
            return response
        }
        if let Some(response) = validity::handle_get_or_head(
            &req, &self.history) {
            return response
        }

        #[cfg(feature = "ui")]
        if let Some(response) = super::ui::handle_get_or_head(&req) {
            return response
        }
        
        Response::not_found()
    }
}

