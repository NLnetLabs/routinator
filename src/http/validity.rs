//! Handling of endpoints related to route validity.

use std::io::{BufReader, Cursor};
use std::str::FromStr;
use std::sync::Arc;
use rpki::resources::{Asn, Prefix};
use crate::payload::{PayloadSnapshot, SharedHistory};
use crate::validity::{RequestList, RouteValidity};
use super::request::Request;
use super::response::{ContentType, Response, ResponseBuilder};


//------------ handle_get ----------------------------------------------------

pub fn handle(
    req: &Request,
    history: &SharedHistory,
) -> Option<Response> {
    let head = req.is_head();
    match req.uri().path() {
        path if path == "/validity" && req.is_get_or_head() => {
            Some(handle_validity_query(head, history, req.uri().query()))
        }
        path if path == "/validity" && req.is_post() => {
            Some(handle_validity_batch(history, req))
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
    let Some(current) = origins.read().current() else {
        return Response::initial_validation(true)
    };
    let mut path = path.splitn(2, '/');
    let asn = match path.next() {
        Some(asn) => asn,
        None => return Response::bad_request(true, "missing ASN in path")
    };
    let prefix = match path.next() {
        Some(prefix) => prefix,
        None => return Response::bad_request(true, "missing prefix in path")
    };
    validity(head, asn, prefix, current)
}

fn handle_validity_query(
    head: bool,
    origins: &SharedHistory,
    query: Option<&str>
) -> Response {
    let Some(current) = origins.read().current() else {
        return Response::initial_validation(true)
    };
    let query = match query {
        Some(query) => query.as_bytes(),
        None => return Response::bad_request(true, "missing query arguments")
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
            return Response::bad_request(
                true, format_args!("unexpected argument '{key}' in query")
            )
        }
    }
    let asn = match asn {
        Some(asn) => asn,
        None => {
            return Response::bad_request(
                true, "missing 'asn' argument in query"
            )
        }
    };
    let prefix = match prefix {
        Some(prefix) => prefix,
        None => {
            return Response::bad_request(
                true, "missing 'prefix' argument in query"
            )
        }
    };
    validity(head, &asn, &prefix, current)
}

fn handle_validity_batch(
    origins: &SharedHistory,
    req: &Request
) -> Response {
    let Some(current) = origins.read().current() else {
        return Response::initial_validation(true)
    };
    let mut reader = BufReader::new(Cursor::new(req.body()));
    
    let Ok(requests) = RequestList::from_json_reader(&mut reader) else {
        return Response::bad_request(
            true, "could not decode JSON"
        )
    };
    let validity_list = requests.validity(&current);
    let res = ResponseBuilder::ok().content_type(ContentType::JSON);
    let mut json = Vec::new();
    let Ok(_) = validity_list.write_json(&mut json) else {
        return Response::bad_request(
            true, "could not write JSON"
        )
    };
    res.body(json)
}

fn validity(
    head: bool, asn: &str, prefix: &str, current: Arc<PayloadSnapshot>
) -> Response {
    let asn = match Asn::from_str(asn) {
        Ok(asn) => asn,
        Err(_) => return Response::bad_request(true, "invalid ASN")
    };
    let prefix = match Prefix::from_str_relaxed(prefix) {
        Ok(prefix) => prefix,
        Err(_) => return Response::bad_request(true, "invalid prefix")
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

