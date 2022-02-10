//! Handling of endpoints related to route validity.

use std::str::FromStr;
use std::sync::Arc;
use hyper::{Body, Method, Request};
use routecore::addr::Prefix;
use rpki::repository::resources::Asn;
use crate::payload::{PayloadSnapshot, SharedHistory};
use crate::validity::RouteValidity;
use super::response::{ContentType, Response, ResponseBuilder};


//------------ handle_get ----------------------------------------------------

pub fn handle_get_or_head(
    req: &Request<Body>,
    history: &SharedHistory,
) -> Option<Response> {
    let head = *req.method() == Method::HEAD;
    match req.uri().path() {
        "/validity" => {
            Some(handle_validity_query(head, history, req.uri().query()))
        }
        path if path.starts_with("/api/v1/validity/") => {
            Some(handle_validity_path(head, history, &path[17..]))
        }
        _ => None
    }
}


//------------ handle_validity_path and handle_validity_query ----------------

fn handle_validity_path(
    head: bool, origins: &SharedHistory, path: &str
) -> Response {
    let current = match validity_check(origins) {
        Ok(current) => current,
        Err(resp) => return resp
    };
    let mut path = path.splitn(2, '/');
    let asn = match path.next() {
        Some(asn) => asn,
        None => return Response::bad_request()
    };
    let prefix = match path.next() {
        Some(prefix) => prefix,
        None => return Response::bad_request()
    };
    validity(head, asn, prefix, current)
}

fn handle_validity_query(
    head: bool,
    origins: &SharedHistory,
    query: Option<&str>
) -> Response {
    let current = match validity_check(origins) {
        Ok(current) => current,
        Err(resp) => return resp
    };
    let query = match query {
        Some(query) => query.as_bytes(),
        None => return Response::bad_request()
    };

    let mut asn = None;
    let mut prefix = None;
    for (key, value) in form_urlencoded::parse(query) {
        if key == "asn" {
            asn = Some(value)
        }
        else if key == "prefix" {
            prefix = Some(value)
        }
        else {
            return Response::bad_request()
        }
    }
    let asn = match asn {
        Some(asn) => asn,
        None => return Response::bad_request()
    };
    let prefix = match prefix {
        Some(prefix) => prefix,
        None => return Response::bad_request()
    };
    validity(head, &asn, &prefix, current)
}

fn validity_check(
    history: &SharedHistory
) -> Result<Arc<PayloadSnapshot>, Response> {
    match history.read().current() {
        Some(history) => Ok(history),
        None => Err(Response::initial_validation())
    }
}

fn validity(
    head: bool, asn: &str, prefix: &str, current: Arc<PayloadSnapshot>
) -> Response {
    let asn = match Asn::from_str(asn) {
        Ok(asn) => asn,
        Err(_) => return Response::bad_request()
    };
    let prefix = match Prefix::from_str(prefix) {
        Ok(prefix) => prefix,
        Err(_) => return Response::bad_request()
    };
    let res = ResponseBuilder::ok().content_type(ContentType::JSON);
    if head {
        res.empty()
    }
    else {
        res.body(
            RouteValidity::new(prefix, asn, &current)
            .into_json(&current)
        )
    }
}

