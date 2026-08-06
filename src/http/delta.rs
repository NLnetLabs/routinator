//! Handles endpoints related to output of payload deltas.

use std::io;
use std::str::FromStr;
use std::sync::Arc;
use chrono::{DateTime, Utc};
use rpki::rtr::Serial;
use rpki::rtr::payload::{Aspa, RouteOrigin, RouterKey};
use rpki::rtr::server::NotifySender;
use crate::output::{FrameWriter, WriteOutput};
use crate::payload::{PayloadDelta, PayloadSnapshot, SharedHistory};
use crate::utils::date::format_iso_date;
use crate::utils::json::JsonBuilder;
use super::request::Request;
use super::response::{ContentType, Response, ResponseBuilder};

//------------ handle_get_or_head --------------------------------------------

pub async fn handle_get_or_head(
    req: Request,
    history: &SharedHistory,
) -> Result<Response, Request> {
    if req.uri().path() != "/json-delta" {
        return Err(req)
    }
    let history = history.read();

    if !history.is_active() {
        return Ok(Response::initial_validation(true))
    }

    let version = match version_from_query(req.uri().query()) {
        Ok(version) => version,
        Err(response) => return Ok(response)
    };

    if req.is_head() {
        return Ok(
            ResponseBuilder::ok().content_type(ContentType::JSON).empty()
        )
    }

    // We are past initial validation so there is a creation time, so any
    // fallback here is fine.
    let created = history.created().unwrap_or(Utc::now());

    if let Some((session, serial)) = version {
        if session == history.session() {
            if let Some(delta) = history.delta_since(serial) {
                return Ok(handle_delta(
                    session, serial, history.serial(), delta, created
                ))
            }
        }
    }

    let snapshot = match history.current() {
        Some(snapshot) => snapshot,
        None => return Ok(Response::initial_validation(true)),
    };
    Ok(handle_reset(history.session(), history.serial(), snapshot, created))
}

fn handle_delta(
    session: u64, from_serial: Serial, to_serial: Serial,
    delta: Arc<PayloadDelta>, created: DateTime<Utc>,
) -> Response {
    let (mut writer, response) = ResponseBuilder::ok().content_type(
        ContentType::JSON
    ).stream_frames();
    tokio::spawn(async move {
        let _ = write_delta(
            session, from_serial, to_serial, &delta, created, &mut writer
        ).await;
    });
    response
}

fn handle_reset(
    session: u64, to_serial: Serial, snapshot: Arc<PayloadSnapshot>,
    created: DateTime<Utc>,
) -> Response {
    let (mut writer, response) = ResponseBuilder::ok().content_type(
        ContentType::JSON
    ).stream_frames();
    tokio::spawn(async move {
        let _ = write_snapshot(
            session, to_serial, &snapshot, created, &mut writer
        ).await;
    });
    response
}


//------------ handle_notify_get_or_head -------------------------------------

pub async fn handle_notify_get_or_head(
    req: Request,
    history: &SharedHistory,
    notify: &NotifySender,
) -> Result<Response, Request> {
    if req.uri().path() != "/json-delta/notify" {
        return Err(req)
    }

    let wait = match need_wait(&req, history) {
        Ok(wait) => wait,
        Err(resp) => return Ok(resp),
    };

    if wait {
        notify.subscribe().recv().await;
    }

    if req.is_head() {
        Ok(
            ResponseBuilder::ok().content_type(ContentType::JSON).empty()
        )
    }
    else {
        let (session, serial) = history.read().session_and_serial();
        Ok(
            ResponseBuilder::ok().content_type(ContentType::JSON).body(
                JsonBuilder::build(|json| {
                    json.member_raw("session", session);
                    json.member_raw("serial", serial);
                })
            )
        )
    }
}

#[allow(clippy::result_large_err)]
fn need_wait(
    req: &Request,
    history: &SharedHistory,
) -> Result<bool, Response> {
    let version = match version_from_query(req.uri().query())? {
        Some(version) => version,
        None => return Ok(false),
    };

    Ok(history.read().session_and_serial() == version)
}


//------------ write_delta and write_snapshot --------------------------------

async fn write_delta(
    session: u64, from_serial: Serial, to_serial: Serial,
    delta: &PayloadDelta, created: DateTime<Utc>,
    target: &mut FrameWriter
) -> Result<(), io::Error> {
    write!(target, "\
        {{\
        \n  \"reset\": false,\
        \n  \"session\": \"{}\",\
        \n  \"serial\": {},\
        \n  \"fromSerial\": {},\
        \n  \"generated\": {},\
        \n  \"generatedTime\": \"{}\",\
        \n  \"announced\": [",
        session, to_serial, from_serial,
        created.timestamp(), format_iso_date(created),
    )?;

    let mut first = true;

    for origin in delta.announced_origins() {
        append_delimiter(&mut first, target)?;
        append_origin(origin, target).await?;
    }

    for key in delta.announced_router_keys() {
        append_delimiter(&mut first, target)?;
        append_router_key(key, target).await?;
    }

    for aspa in delta.announced_aspas() {
        append_delimiter(&mut first, target)?;
        append_aspa(aspa, target).await?;
    }

    write!(target, "\
        \n  ],\
        \n  \"withdrawn\": [",
    )?;

    let mut first = true;

    for origin in delta.withdrawn_origins() {
        append_delimiter(&mut first, target)?;
        append_origin(origin, target).await?;
    }

    for key in delta.withdrawn_router_keys() {
        append_delimiter(&mut first, target)?;
        append_router_key(key, target).await?;
    }

    for aspa in delta.withdrawn_aspas() {
        append_delimiter(&mut first, target)?;
        append_aspa(aspa, target).await?;
    }

    write!(target, "\n  ]\n}}\n")?;
    target.finalize().await
}


async fn write_snapshot(
    session: u64,
    to_serial: Serial,
    snapshot: &PayloadSnapshot,
    created: DateTime<Utc>,
    target: &mut FrameWriter
) -> Result<(), io::Error> {
    write!(target, "\
        {{\
        \n  \"reset\": true,\
        \n  \"session\": \"{}\",\
        \n  \"serial\": {},\
        \n  \"generated\": {},\
        \n  \"generatedTime\": \"{}\",\
        \n  \"announced\": [",
        session, to_serial,
        created.timestamp(), format_iso_date(created),
    )?;

    let mut first = true;

    for (origin, _) in snapshot.origins() {
        append_delimiter(&mut first, target)?;
        append_origin(origin, target).await?;
    }

    for (key, _) in snapshot.router_keys() {
        append_delimiter(&mut first, target)?;
        append_router_key(key, target).await?;
    }

    for (aspa, _) in snapshot.aspas() {
        append_delimiter(&mut first, target)?;
        append_aspa(aspa, target).await?;
    }

    write!(target, "\n  ]\n}}\n")?;
    target.finalize().await

}


fn append_delimiter(
    first: &mut bool, target: &mut FrameWriter
) -> Result<(), io::Error> {
    if *first {
        *first = false;
    }
    else {
        write!(target, ",")?;
    }
    Ok(())
}


async fn append_origin(
    origin: RouteOrigin, target: &mut FrameWriter
) -> Result<(), io::Error> {
    write!(target, "\
        \n    {{\
        \n        \"type\": \"routeOrigin\",\
        \n        \"asn\": \"{}\",\
        \n        \"prefix\": \"{}/{}\",\
        \n        \"maxLength\": {}\
        \n    }}",
        origin.asn,
        origin.prefix.addr(), origin.prefix.prefix_len(),
        origin.prefix.resolved_max_len()
    )?;
    target.flush().await
}

async fn append_router_key(
    key: &RouterKey, target: &mut FrameWriter
) -> Result<(), io::Error> {
    write!(target, "\
        \n    {{\
        \n        \"type\": \"routerKey\",\
        \n        \"keyIdentifier\": \"{}\",\
        \n        \"asn\": \"{}\",\
        \n        \"keyInfo\": \"{}\"
        \n    }}",
        key.key_identifier,
        key.asn,
        key.key_info,
    )?;
    target.flush().await
}

async fn append_aspa(
    aspa: &Aspa, target: &mut FrameWriter
) -> Result<(), io::Error> {
    write!(target, "\
        \n  {{\
        \n      \"type\": \"aspa\",
        \n      \"customerAsn\": \"{}\",\
        \n      \"providerAsns\": [",
        aspa.customer,
    )?;
    let mut first_aspa = true;
    for asn in aspa.providers.iter() {
        if first_aspa {
            write!(target, "\"{asn}\"")?;
            first_aspa = false
        }
        else {
            write!(target, ", \"{asn}\"")?;
        }
    }
    write!(target, "]\n\n    }}")?;
    target.flush().await
}


//------------ Helpers -------------------------------------------------------

#[allow(clippy::result_large_err)]
fn version_from_query(
    query: Option<&str>
) -> Result<Option<(u64, Serial)>, Response> {
    let query = match query {
        Some(query) => query,
        None => return Ok(None)
    };
    let mut session = None;
    let mut serial = None;

    for (key, value) in form_urlencoded::parse(query.as_ref()) {
        if key == "session" {
            if session.is_some() {
                return Err(Response::bad_request(
                    true, "duplicate 'session' argument in query"
                ));
            }
            session = Some(u64::from_str(&value).map_err(|_| {
                Response::bad_request(
                    true, "invalid 'session' argument in query"
                )
            })?);
        }
        else if key == "serial" {
            if serial.is_some() {
                return Err(Response::bad_request(
                    true, "duplicate 'serial' argument in query"
                ));
            }
            serial = Some(Serial::from_str(&value).map_err(|_| {
                Response::bad_request(
                    true, "invalid 'serial' argument in query"
                )
            })?);
        }
        else {
            return Err(Response::bad_request(
                true, format_args!("unexpected argument '{key}' in query")
            ));
        }
    }
    match (session, serial) {
        (Some(session), Some(serial)) => Ok(Some((session, serial))),
        (None, None) => Ok(None),
        (Some(_), None) => {
            Err(Response::bad_request(
                true, "missing 'serial' argument in query"
            ))
        }
        (None, Some(_)) => {
            Err(Response::bad_request(
                true, "missing 'session' argument in query"
            ))
        }
    }
}

