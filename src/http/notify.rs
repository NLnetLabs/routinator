//! Handles the notification websocket.

use hyper::{Body, Method, Request};
use rpki::rtr::server::{NotifySender, PayloadSource};
use crate::payload::SharedHistory;
use crate::utils::json::JsonBuilder;
use super::response::{ContentType, Response, ResponseBuilder};


//------------ handle_get_or_head --------------------------------------------

pub async fn handle_get_or_head(
    req: &Request<Body>,
    history: &SharedHistory,
    notify: &NotifySender,
) -> Option<Response> {
    if req.uri().path() != "/json-delta/notify" {
        return None
    }

    notify.subscribe().recv().await;

    let state = history.notify();

    if *req.method() == Method::HEAD {
        Some(
            ResponseBuilder::ok().content_type(ContentType::JSON).empty()
        )
    }
    else {
        Some(
            ResponseBuilder::ok().content_type(ContentType::JSON).body(
                JsonBuilder::build(|json| {
                    json.member_raw("session", state.session());
                    json.member_raw("serial", state.serial());
                })
            )
        )
    }
}

