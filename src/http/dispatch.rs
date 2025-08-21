//! Rules on how to dispatch a request.

use std::sync::Arc;
use rpki::rtr::server::NotifySender;
use crate::config::Config;
use crate::log::LogOutput;
use crate::metrics::{HttpServerMetrics, RtrServerMetrics};
use crate::payload::SharedHistory;
use super::{delta, log, metrics, payload, status, validity};
use super::request::Request;
use super::response::Response;

//------------ State ---------------------------------------------------------

pub struct State {
    payload: payload::State,
    log: log::State,
    history: SharedHistory,
    metrics: Arc<HttpServerMetrics>,
    rtr_metrics: Arc<RtrServerMetrics>,
    notify: NotifySender,
}

impl State {
    pub fn new(
        config: &Config,
        history: SharedHistory,
        rtr_metrics: Arc<RtrServerMetrics>,
        log: Option<Arc<LogOutput>>,
        notify: NotifySender,
    ) -> Self {
        Self {
            payload: payload::State::new(config),
            log: log::State::new(log),
            history,
            metrics: Arc::new(HttpServerMetrics::default()),
            rtr_metrics,
            notify,
        }
    }
    
    pub fn metrics(&self) -> &Arc<HttpServerMetrics> {
        &self.metrics
    }

    pub async fn handle_request(&self, req: Request) -> Response {
        self.metrics.inc_requests();
        if !req.is_get_or_head() && !req.is_post() {
            return Response::method_not_allowed(req.is_api())
        }

        let req = match self.payload.handle_get_or_head(
            req, &self.history
        ) {
            Ok(response) => return response,
            Err(req) => req
        };
        let req = match delta::handle_notify_get_or_head(
            req, &self.history, &self.notify,
        ).await {
            Ok(response) => return response,
            Err(req) => req
        };
        let req = match delta::handle_get_or_head(
            req, &self.history
        ) {
            Ok(response) => return response,
            Err(req) => req
        };
        let req = match self.log.handle_get_or_head(req) {
            Ok(response) => return response,
            Err(req) => req
        };
        let req = match metrics::handle_get_or_head(
            req, &self.history, &self.metrics, &self.rtr_metrics
        ).await {
            Ok(response) => return response,
            Err(req) => req
        };
        let req = match status::handle_get_or_head(
            req, &self.history, &self.metrics, &self.rtr_metrics
        ).await {
            Ok(response) => return response,
            Err(req) => req
        };
        let req = match validity::handle(
            req, &self.history).await {
                Ok(response) => return response,
                Err(req) => req
        };

        #[cfg(feature = "ui")]
        let req = match super::ui::handle_get_or_head(req) {
            Ok(response) => return response,
            Err(req) => req
        };
        
        Response::not_found(req.is_api())
    }
}

