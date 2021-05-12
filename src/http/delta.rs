//! Handles endpoints related to output of payload deltas.

use std::convert::Infallible;
use std::io::Write;
use std::str::FromStr;
use std::sync::Arc;
use futures::stream;
use hyper::{Body, Request, Response};
use rpki::rtr::Serial;
use crate::payload::{
    PayloadDelta, PayloadSnapshot, RouteOrigin, SharedHistory
};
use super::errors::{bad_request, initial_validation};

//------------ handle_get ----------------------------------------------------

pub fn handle_get(
    req: &Request<Body>,
    history: &SharedHistory,
) -> Option<Response<Body>> {
    if req.uri().path() != "/json-delta" {
        return None
    }
    let history = history.read();

    if !history.is_active() {
        return Some(initial_validation())
    }

    let version = match version_from_query(req.uri().query()) {
        Ok(version) => version,
        Err(response) => return Some(response)
    };

    if let Some((session, serial)) = version {
        if session == history.session() {
            if let Some(delta) = history.delta_since(serial) {
                return Some(handle_delta(
                    session, serial, history.serial(), delta
                ))
            }
        }
    }

    let snapshot = match history.current() {
        Some(snapshot) => snapshot,
        None => return Some(initial_validation()),
    };
    Some(handle_reset(history.session(), history.serial(), snapshot))
}

fn version_from_query(
    query: Option<&str>
) -> Result<Option<(u64, Serial)>, Response<Body>> {
    let query = match query {
        Some(query) => query,
        None => return Ok(None)
    };
    let mut session = None;
    let mut serial = None;

    for (key, value) in form_urlencoded::parse(query.as_ref()) {
        if key == "session" {
            if session.is_some() {
                return Err(bad_request());
            }
            session = Some(u64::from_str(&value).map_err(|_| bad_request())?);
        }
        else if key == "serial" {
            if serial.is_some() {
                return Err(bad_request());
            }
            serial = Some(Serial::from_str(&value).map_err(|_| bad_request())?);
        }
        else {
            return Err(bad_request());
        }
    }
    match (session, serial) {
        (Some(session), Some(serial)) => Ok(Some((session, serial))),
        (None, None) => Ok(None),
        _ => Err(bad_request())
    }
}

fn handle_delta(
    session: u64, from_serial: Serial, to_serial: Serial,
    delta: Arc<PayloadDelta>
) -> Response<Body> {
    Response::builder()
    .header("Content-Type", "application/json")
    .body(Body::wrap_stream(stream::iter(
        DeltaStream::new(session, from_serial, to_serial, delta)
        .map(Result::<_, Infallible>::Ok)
    )))
    .unwrap()
}

fn handle_reset(
    session: u64, to_serial: Serial, snapshot: Arc<PayloadSnapshot>
) -> Response<Body> {
    Response::builder()
    .header("Content-Type", "application/json")
    .body(Body::wrap_stream(stream::iter(
        SnapshotStream::new(session, to_serial, snapshot)
        .map(Result::<_, Infallible>::Ok)
    )))
    .unwrap()
}


//------------ DeltaStream ---------------------------------------------------

/// An iterator as the foundation for streaming a delta.
///
/// The iterator produces segments of roughly 64k size. This can be converted
/// into a async stream and then used with Tokio’s `Body::wrap_stream`.
struct DeltaStream {
    /// The header of the output.
    ///
    /// This is set to some when a new value is created and then taken out on
    /// the very first iteration.
    header: Option<Vec<u8>>,

    /// The delta we work on.
    ///
    /// This is set to `None` to fuse the iterator.
    delta: Option<Arc<PayloadDelta>>,

    /// The position of the next item in the delta.
    ///
    /// If this is `Ok(_)`, we are working with the announced origins. If this
    /// is `Err(_)` we are working with the withdrawn origins.
    pos: Result<usize, usize>,
}

impl DeltaStream {
    /// Creats a new delta stream.
    fn new(
        session: u64, from_serial: Serial, to_serial: Serial,
        delta: Arc<PayloadDelta>
    ) -> Self {
        let mut vec = Vec::new();
        Self::append_header(&mut vec, session, from_serial, to_serial);
        DeltaStream {
            header: Some(vec),
            delta: Some(delta),
            pos: Ok(0),
        }
    }

    /// Appends the delta header to the provided vec.
    fn append_header(
        vec: &mut Vec<u8>,
        session: u64, from_serial: Serial, to_serial: Serial,
    ) {
        write!(vec, "\
            {{
            \n  \"reset\": false,\
            \n  \"session\": \"{}\",\
            \n  \"serial\": {},\
            \n  \"fromSerial\": {},\
            \n  \"announced\": [",
            session, to_serial, from_serial
        ).unwrap()
    }

    /// Appends the separator between announced and withdrawn to the vec.
    fn append_separator(
        vec: &mut Vec<u8>,
    ) {
        write!(vec, "\
            \n  ],\
            \n  \"withdrawn\": [",
        ).unwrap()
    }

    /// Appends an origin to the vec.
    fn append_origin(
        vec: &mut Vec<u8>,
        origin: RouteOrigin,
        first: bool
    ) {
        if !first {
            vec.push(b',')
        }
        write!(vec, "\
            \n    {{ \"asn\": \"{} \", \"prefix\": \"{}/{}\", \
                     \"maxLength\": {} }}",
            origin.as_id(),
            origin.address(), origin.address_length(),
            origin.max_length()
        ).unwrap()
    }

    /// Appends the footer to the vec.
    fn append_footer(vec: &mut Vec<u8>) {
        vec.extend_from_slice(b"\n  ]\n}\n");
    }
}

impl Iterator for DeltaStream {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        let delta = self.delta.as_ref()?;
        let mut vec = self.header.take().unwrap_or_else(Vec::new);
        loop {
            if vec.len() > 64000 {
                return Some(vec)
            }
            match self.pos {
                Ok(pos) => {
                    match delta.announced_origins().get(pos) {
                        Some(origin) => {
                            Self::append_origin(
                                &mut vec, *origin, pos == 0,
                            );
                            self.pos = Ok(pos + 1);
                        }
                        None => {
                            Self::append_separator(&mut vec);
                            self.pos = Err(0);
                        }
                    }
                }
                Err(pos) => {
                    match delta.withdrawn_origins().get(pos) {
                        Some(origin) => {
                            Self::append_origin(
                                &mut vec, *origin, pos == 0,
                            );
                            self.pos = Err(pos + 1);
                        }
                        None => break
                    }
                }
            }
        }

        self.delta = None;
        Self::append_footer(&mut vec);
        Some(vec)
    }
}


//------------ SnapshotStream ------------------------------------------------

/// An iterator as the foundation for streaming a snapshot.
///
/// This fairly similar to [`DeltaStream`] only simpler.
struct SnapshotStream {
    /// The header of the output.
    ///
    /// This is set to some when a new value is created and then taken out on
    /// the very first iteration.
    header: Option<Vec<u8>>,

    /// The snapshot we work on.
    ///
    /// This is set to `None` to fuse the iterator.
    snapshot: Option<Arc<PayloadSnapshot>>,

    /// The position of the next item in the delta.
    pos: usize,
}

impl SnapshotStream {
    /// Creates a new snapshot stream.
    fn new(
        session: u64, to_serial: Serial, snapshot: Arc<PayloadSnapshot>
    ) -> Self {
        let mut vec = Vec::new();
        Self::append_header(&mut vec, session, to_serial);
        SnapshotStream {
            header: Some(vec),
            snapshot: Some(snapshot),
            pos: 0
        }
    }

    /// Appends the snapshot header to the vec.
    fn append_header(
        vec: &mut Vec<u8>,
        session: u64, to_serial: Serial,
    ) {
        write!(vec, "\
            {{\
            \n  \"reset\": true,\
            \n  \"session\": \"{}\",\
            \n  \"serial\": {},\
            \n  \"announced\": [",
            session, to_serial,
        ).unwrap()
    }
}

impl Iterator for SnapshotStream {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        let snapshot = self.snapshot.as_ref()?;
        let mut vec = self.header.take().unwrap_or_else(Vec::new);
        loop {
            if vec.len() > 64000 {
                return Some(vec)
            }
            match snapshot.origins().get(self.pos) {
                Some(&(origin, _)) => {
                    DeltaStream::append_origin(
                        &mut vec, origin, self.pos == 0,
                    );
                    self.pos += 1;
                }
                None => {
                    break
                }
            }
        }

        self.snapshot = None;
        DeltaStream::append_footer(&mut vec);
        Some(vec)
    }
}

