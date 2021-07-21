//! Handling of endpoints related to route validity.

use std::str::FromStr;
use std::sync::Arc;
use hyper::{Body, Request, Response};
use rpki::repository::resources::AsId;
use crate::payload::{AddressPrefix, PayloadSnapshot, SharedHistory};
use crate::validity::RouteValidity;
use super::errors::bad_request;


//------------ handle_get ----------------------------------------------------

pub fn handle_get(
    req: &Request<Body>,
    history: &SharedHistory,
) -> Option<Response<Body>> {
    match req.uri().path() {
        "/validity" => {
            Some(handle_validity_query(history, req.uri().query()))
        }
        path if path.starts_with("/api/v1/validity/") => {
            Some(handle_validity_path(history, &path[17..]))
        }
        _ => None
    }
}


//------------ handle_validity_path and handle_validity_query ----------------

fn handle_validity_path(
    origins: &SharedHistory, path: &str
) -> Response<Body> {
    let current = match validity_check(origins) {
        Ok(current) => current,
        Err(resp) => return resp
    };
    let mut path = path.splitn(2, '/');
    let asn = match path.next() {
        Some(asn) => asn,
        None => return bad_request()
    };
    let prefix = match path.next() {
        Some(prefix) => prefix,
        None => return bad_request()
    };
    validity(asn, prefix, current)
}

fn handle_validity_query(
    origins: &SharedHistory,
    query: Option<&str>
) -> Response<Body> {
    let current = match validity_check(origins) {
        Ok(current) => current,
        Err(resp) => return resp
    };
    let query = match query {
        Some(query) => query.as_bytes(),
        None => return bad_request()
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
            return bad_request()
        }
    }
    let asn = match asn {
        Some(asn) => asn,
        None => return bad_request()
    };
    let prefix = match prefix {
        Some(prefix) => prefix,
        None => return bad_request()
    };
    validity(&asn, &prefix, current)
}

fn validity_check(
    history: &SharedHistory
) -> Result<Arc<PayloadSnapshot>, Response<Body>> {
    match history.read().current() {
        Some(history) => Ok(history),
        None => {
            Err(
                Response::builder()
                .status(503)
                .header("Content-Type", "text/plain")
                .body("Initial validation ongoing. Please wait.".into())
                .unwrap()
            )
        }
    }
}

fn validity(
    asn: &str, prefix: &str, current: Arc<PayloadSnapshot>
) -> Response<Body> {
    let asn = match AsId::from_str(asn) {
        Ok(asn) => asn,
        Err(_) => return bad_request()
    };
    let prefix = match AddressPrefix::from_str(prefix) {
        Ok(prefix) => prefix,
        Err(_) => return bad_request()
    };
    Response::builder()
    .header("Content-Type", "application/json")
    .body(
        RouteValidity::new(prefix, asn, &current)
        .into_json(&current)
        .into()
    ).unwrap()
}

