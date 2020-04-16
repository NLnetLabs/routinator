//! The HTTP server.
//!
//! The module provides all functionality exposed by the HTTP server to
//! those interested. The only public item, [`http_listener`] creates all
//! necessary networking services based on the current configuration and
//! returns a future that drives the server.
//!
//! [`http_listener`]: fn.http_listener.html

use std::convert::Infallible;
use std::fmt::Write;
use std::future::Future;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use chrono::{Duration, Utc};
use clap::crate_version;
use futures::stream;
use futures::future::select_all;
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use hyper::service::{make_service_fn, service_fn};
use log::error;
use rpki::resources::AsId;
use crate::output;
use crate::config::Config;
use crate::metrics::Metrics;
use crate::operation::Error;
use crate::origins::{AddressOrigins, AddressPrefix, OriginsHistory};
use crate::output::OutputFormat;
//use crate::utils::finish_all;
use crate::validity::RouteValidity;


//------------ http_listener -------------------------------------------------

/// Returns a future for all HTTP server listeners.
///
/// Which servers these are, if any, is determined by `config`. The data 
/// is taken from `history`. As a consequence, if you need new
/// data to be exposed, add it to [`OriginsHistory`] somehow.
///
/// [`OriginsHistory`]: ../origins/struct.OriginsHistory.html
pub fn http_listener(
    origins: &OriginsHistory,
    config: &Config,
) -> impl Future<Output = ()> {
    _http_listener(origins.clone(), config.http_listen.clone())
}

async fn _http_listener(origins: OriginsHistory, addrs: Vec<SocketAddr>) {
    let _ = select_all(
        addrs.iter().map(|addr| {
            tokio::spawn(single_http_listener(*addr, origins.clone()))
        })
    ).await;
}

/// Returns a future for a single HTTP listener.
///
/// The future will never resolve unless an error happens that breaks the
/// listener, in which case it will print an error and resolve the error case.
/// It will listen bind a Hyper server onto `addr` and produce any data
/// served from `origins`.
async fn single_http_listener(
    addr: SocketAddr,
    origins: OriginsHistory,
) {
    let make_service = make_service_fn(|_conn| {
        let origins = origins.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let origins = origins.clone();
                async move { handle_request(req, &origins).await }
            }))
        }
    });

    if let Err(err) = Server::bind(&addr).serve(make_service).await {
        error!("HTTP server error: {}", err);
    }
}


async fn handle_request(
    req: Request<Body>,
    origins: &OriginsHistory,
) -> Result<Response<Body>, Infallible> {
    if *req.method() != Method::GET {
        return Ok(method_not_allowed())
    }
    Ok(match req.uri().path() {
        "/bird" => vrps(origins, req.uri().query(), OutputFormat::Bird1),
        "/bird2" => vrps(origins, req.uri().query(), OutputFormat::Bird2),
        "/csv" => vrps(origins, req.uri().query(), OutputFormat::Csv),
        "/json" => vrps(origins, req.uri().query(), OutputFormat::Json),
        "/metrics" => metrics(origins),
        "/openbgpd" => {
            vrps(origins, req.uri().query(), OutputFormat::Openbgpd)
        }
        "/rpsl" => vrps(origins, req.uri().query(), OutputFormat::Rpsl),
        "/status" => status(origins),
        "/validity" => validity_query(origins, req.uri().query()),
        "/version" => version(),
        path if path.starts_with("/api/v1/validity/") => {
            validity_path(origins, &path[17..])
        }
        _ => not_found()
    })
}


fn metrics(origins: &OriginsHistory) -> Response<Body> {
    match origins.metrics() {
        Some(metrics) => metrics_active(origins, &metrics),
        None => {
            Response::builder()
            .status(503)
            .header("Content-Type", "text/plain")
            .body("Initial validation ongoing. Please wait.".into())
            .unwrap()
        }
    }
}

fn metrics_active(
    origins: &OriginsHistory,
    metrics: &Metrics
) -> Response<Body> {
    let mut res = String::new();

    // valid_roas 
    writeln!(res,
        "# HELP routinator_valid_roas number of valid ROAs seen\n\
         # TYPE routinator_valid_roas gauge"
    ).unwrap();
    for tal in metrics.tals() {
        writeln!(res,
            "routinator_valid_roas{{tal=\"{}\"}} {}",
            tal.tal.name(), tal.roas
        ).unwrap();
    }

    // vrps_total
    writeln!(res,
        "\n\
         # HELP routinator_vrps_total total number of VRPs seen\n\
         # TYPE routinator_vrps_total gauge"
    ).unwrap();
    for tal in metrics.tals() {
        writeln!(res,
            "routinator_vrps_total{{tal=\"{}\"}} {}",
            tal.tal.name(), tal.vrps
        ).unwrap();
    }

    // last_update_start, last_update_done, last_update_duration
    let (start, done, duration) = origins.update_times();
    write!(res,
        "\n\
        # HELP routinator_last_update_start seconds since last update \
            started\n\
        # TYPE routinator_last_update_start gauge\n\
        routinator_last_update_start {}\n\
        \n\
        # HELP routinator_last_update_duration duration in seconds of \
            last update\n\
        # TYPE routinator_last_update_duration gauge\n\
        routinator_last_update_duration {}\n\
        \n\
        # HELP routinator_last_update_done seconds since last update \
            finished\n\
        # TYPE routinator_last_update_done gauge\n\
        routinator_last_update_done ",

        start.elapsed().as_secs(),
        duration.map(|duration| duration.as_secs()).unwrap_or(0),
    ).unwrap();
    match done {
        Some(instant) => {
            writeln!(res, "{}", instant.elapsed().as_secs()).unwrap();
        }
        None => {
            writeln!(res, "Nan").unwrap();
        }
    }

    // serial
    writeln!(res,
        "\n\
        # HELP routinator_serial current RTR serial number\n\
        # TYPE routinator_serial gauge\n\
        routinator_serial {}",

        origins.serial()
    ).unwrap();

    // rsync_status
    writeln!(res, "
        \n\
        # HELP routinator_rsync_status exit status of rsync command\n\
        # TYPE routinator_rsync_status gauge"
    ).unwrap();
    for metrics in metrics.rsync() {
        writeln!(
            res,
            "routinator_rsync_status{{uri=\"{}\"}} {}",
            metrics.module,
            match metrics.status {
                Ok(status) => status.code().unwrap_or(-1),
                Err(_) => -1
            }
        ).unwrap();
    }

    // rsync_duration
    writeln!(res, "
        \n\
        # HELP routinator_rsync_duration duration of rsync in seconds\n\
        # TYPE routinator_rsync_duration gauge"
    ).unwrap();
    for metrics in metrics.rsync() {
        if let Ok(duration) = metrics.duration {
            writeln!(
                res,
                "routinator_rsync_duration{{uri=\"{}\"}} {:.3}",
                metrics.module,
                duration.as_secs() as f64
                + f64::from(duration.subsec_millis()) / 1000.
            ).unwrap();
        }
    }

    // rrdp_status
    writeln!(res, "
        \n\
        # HELP routinator_rrdp_status status code for getting \
            notification file\n\
        # TYPE routinator_rrdp_status gauge"
    ).unwrap();
    for metrics in metrics.rrdp() {
        writeln!(
            res,
            "routinator_rrdp_status{{uri=\"{}\"}} {}",
            metrics.notify_uri,
            metrics.notify_status.map(|code| {
                code.as_u16() as i16
            }).unwrap_or(-1),
        ).unwrap();
    }

    // rrdp_duration
    writeln!(res, "
        \n\
        # HELP routinator_rrdp_duration duration of rrdp in seconds\n\
        # TYPE routinator_rrdp_duration gauge"
    ).unwrap();
    for metrics in metrics.rrdp() {
        if let Ok(duration) = metrics.duration {
            writeln!(
                res,
                "routinator_rrdp_duration{{uri=\"{}\"}} {:.3}",
                metrics.notify_uri,
                duration.as_secs() as f64
                + f64::from(duration.subsec_millis()) / 1000.
            ).unwrap();
        }
    }

    Response::builder()
        .header("Content-Type", "text/plain; version=0.0.4")
        .body(res.into())
        .unwrap()
}

fn status(origins: &OriginsHistory) -> Response<Body> {
    match origins.metrics() {
        Some(metrics) => status_active(origins, &metrics),
        None => {
            Response::builder()
            .header("Content-Type", "text/plain")
            .body("Initial validation ongoing. Please wait.".into())
            .unwrap()
        }
    }
}

fn status_active(
    origins: &OriginsHistory,
    metrics: &Metrics
) -> Response<Body> {
    let mut res = String::new();
    let (start, done, duration) = origins.update_times();
    let start = Duration::from_std(start.elapsed()).unwrap();
    let done = done.map(|done|
        Duration::from_std(done.elapsed()).unwrap()
    );
    let duration = duration.map(|duration| 
        Duration::from_std(duration).unwrap()
    );
    let now = Utc::now();

    // serial
    writeln!(res, "serial: {}", origins.serial()).unwrap();

    // last-update-start-at and -ago
    writeln!(res, "last-update-start-at:  {}", now - start).unwrap();
    writeln!(res, "last-update-start-ago: {}", start).unwrap();

    // last-update-dona-at and -ago
    if let Some(done) = done {
        writeln!(res, "last-update-done-at:   {}", now - done).unwrap();
        writeln!(res, "last-update-done-ago:  {}", done).unwrap();
    }
    else {
        writeln!(res, "last-update-done-at:   -").unwrap();
        writeln!(res, "last-update-done-ago:  -").unwrap();
    }

    // last-update-duration
    if let Some(duration) = duration {
        writeln!(res, "last-update-duration:  {}", duration).unwrap();
    }
    else {
        writeln!(res, "last-update-duration:  -").unwrap();
    }

    // valid-roas
    writeln!(res, "valid-roas: {}",
        metrics.tals().iter().map(|tal| tal.roas).sum::<u32>()
    ).unwrap();

    // valid-roas-per-tal
    write!(res, "valid-roas-per-tal: ").unwrap();
    for tal in metrics.tals() {
        write!(res, "{}={} ", tal.tal.name(), tal.roas).unwrap();
    }
    writeln!(res).unwrap();

    // vrps
    writeln!(res, "vrps: {}",
        metrics.tals().iter().map(|tal| tal.vrps).sum::<u32>()
    ).unwrap();

    // vrps-per-tal
    write!(res, "vrps-per-tal: ").unwrap();
    for tal in metrics.tals() {
        write!(res, "{}={} ", tal.tal.name(), tal.vrps).unwrap();
    }
    writeln!(res).unwrap();

    // rsync_status
    writeln!(res, "rsync-durations:").unwrap();
    for metrics in metrics.rsync() {
        write!(
            res,
            "   {}: status={}",
            metrics.module,
            match metrics.status {
                Ok(status) => status.code().unwrap_or(-1),
                Err(_) => -1
            }
        ).unwrap();
        if let Ok(duration) = metrics.duration {
            writeln!(
                res,
                ", duration={:.3}s",
                duration.as_secs() as f64
                + f64::from(duration.subsec_millis()) / 1000.
            ).unwrap();
        }
        else {
            writeln!(res).unwrap()
        }
    }

    // rrdp_status
    writeln!(res, "rrdp-durations:").unwrap();
    for metrics in metrics.rrdp() {
        write!(
            res,
            "   {}: status={}",
            metrics.notify_uri,
            metrics.notify_status.map(|code| {
                code.as_u16() as i16
            }).unwrap_or(-1),
        ).unwrap();
        if let Ok(duration) = metrics.duration {
            writeln!(
                res,
                ", duration={:.3}s",
                duration.as_secs() as f64
                + f64::from(duration.subsec_millis()) / 1000.
            ).unwrap();
        }
        else {
            writeln!(res).unwrap()
        }
    }


    Response::builder()
    .header("Content-Type", "text/plain")
    .body(res.into())
    .unwrap()
}

fn validity_path(origins: &OriginsHistory, path: &str) -> Response<Body> {
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

fn validity_query(
    origins: &OriginsHistory,
    query: Option<&str>
) -> Response<Body> {
    let current = match validity_check(origins) {
        Ok(current) => current,
        Err(resp) => return resp
    };
    let mut asn = None;
    let mut prefix = None;
    for (key, value) in query_iter(query) {
        if key == "asn" {
            asn = value
        }
        else if key == "prefix" {
            prefix = value
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
    validity(asn, prefix, current)
}

fn validity_check(
    origins: &OriginsHistory
) -> Result<Arc<AddressOrigins>, Response<Body>> {
    match origins.current() {
        Some(origins) => Ok(origins),
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
    asn: &str, prefix: &str, current: Arc<AddressOrigins>
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
        .into_json()
        .into()
    ).unwrap()
}

fn version() -> Response<Body> {
    Response::builder()
    .header("Content-Type", "text/plain")
    .body(crate_version!().into())
    .unwrap()
}

fn vrps(
    origins: &OriginsHistory,
    query: Option<&str>,
    format: OutputFormat
) -> Response<Body> {
    let (current, metrics) = match origins.current_and_metrics() {
        Some(some) => some, 
        None => {
            return Response::builder()
                .status(503)
                .header("Content-Type", "text/plain")
                .body("Initial validation ongoing. Please wait.".into())
                .unwrap()
        }
    };

    let filters = match output_filters(query) {
        Ok(filters) => filters,
        Err(_) => return bad_request(),
    };
    let stream = format.stream(
        current, filters, metrics
    );

    Response::builder()
    .header("Content-Type", format.content_type())
    .header("content-length", stream.output_len())
    .body(Body::wrap_stream(stream::iter(
        stream.map(Result::<_, Infallible>::Ok)
    )))
    .unwrap()
}

fn bad_request() -> Response<Body> {
    Response::builder()
    .status(StatusCode::BAD_REQUEST)
    .header("Content-Type", "text/plain")
    .body("Bad Request".into())
    .unwrap()
}

fn method_not_allowed() -> Response<Body> {
    Response::builder()
    .status(StatusCode::METHOD_NOT_ALLOWED)
    .header("Content-Type", "text/plain")
    .body("Method Not Allowed".into())
    .unwrap()
}

fn not_found() -> Response<Body> {
    Response::builder()
    .status(StatusCode::NOT_FOUND)
    .header("Content-Type", "text/plain")
    .body("Not Found".into())
    .unwrap()
}

/// Produces the output filters from a query string.
fn output_filters(
    query: Option<&str>
) -> Result<Option<Vec<output::Filter>>, Error> {
    let mut query = match query {
        Some(query) => query,
        None => return Ok(None)
    };
    let mut res = Vec::new();
    while !query.is_empty() {
        // Take out one pair.
        let (part, rest) = match query.find('&') {
            Some(idx) => (&query[..idx], &query[idx + 1..]),
            None => (query, "")
        };
        query = rest;

        // Split the pair.
        let equals = match part.find('=') {
            Some(equals) => equals,
            None => return Err(Error)
        };
        let key = &part[..equals];
        let value = &part[equals + 1..];

        if key == "filter-prefix" {
            match AddressPrefix::from_str(value) {
                Ok(some) => res.push(output::Filter::Prefix(some)),
                Err(_) => return Err(Error)
            }
        }
        else if key == "filter-asn" {
            let asn = match AsId::from_str(value) {
                Ok(asn) => asn,
                Err(_) => match u32::from_str(value) {
                    Ok(asn) => asn.into(),
                    Err(_) => return Err(Error)
                }
            };
            res.push(output::Filter::As(asn))
        }
        else {
            return Err(Error)
        }
    }
    if res.is_empty() {
        Ok(None)
    }
    else {
        Ok(Some(res))
    }
}


fn query_iter<'a>(
    query: Option<&'a str>
) -> impl Iterator<Item=(&'a str, Option<&'a str>)> + 'a {
    let query = query.unwrap_or("");
    query.split('&').map(|item| {
        let mut item = item.splitn(2, '=');
        let key = item.next().unwrap();
        let value = item.next();
        (key, value)
    })
}
