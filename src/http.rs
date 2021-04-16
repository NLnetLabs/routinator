//! The HTTP server.
//!
//! The module provides all functionality exposed by the HTTP server to
//! those interested. The only public item, [`http_listener`] creates all
//! necessary networking services based on the current configuration and
//! returns a future that drives the server.
//!
//! [`http_listener`]: fn.http_listener.html

use std::io;
use std::convert::Infallible;
use std::fmt::Write;
use std::future::Future;
use std::net::TcpListener as StdListener;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};
use chrono::{DateTime, Duration, Utc};
use chrono::format::{Item, Fixed, Numeric, Pad};
use clap::{crate_name, crate_version};
use futures::stream;
use futures::pin_mut;
use futures::future::{pending, select_all};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use hyper::header::HeaderValue;
use hyper::server::accept::Accept;
use hyper::service::{make_service_fn, service_fn};
use log::error;
use rpki::repository::resources::AsId;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use crate::config::Config;
use crate::error::ExitError;
use crate::metrics::{ServerMetrics, PublicationMetrics, VrpMetrics};
use crate::output;
use crate::output::OutputFormat;
use crate::payload::{AddressPrefix, PayloadSnapshot, SharedHistory};
use crate::process::LogOutput;
use crate::utils::JsonBuilder;
use crate::validity::RouteValidity;


//------------ http_listener -------------------------------------------------

/// Returns a future for all HTTP server listeners.
pub fn http_listener(
    origins: SharedHistory,
    metrics: Arc<ServerMetrics>,
    log: Option<Arc<LogOutput>>,
    config: &Config,
) -> Result<impl Future<Output = ()>, ExitError> {
    let mut listeners = Vec::new();
    for addr in &config.http_listen {
        // Binding needs to have happened before dropping privileges
        // during detach. So we do this here synchronously.
        let listener = match StdListener::bind(addr) {
            Ok(listener) => listener,
            Err(err) => {
                error!("Fatal: error listening on {}: {}", addr, err);
                return Err(ExitError::Generic);
            }
        };
        if let Err(err) = listener.set_nonblocking(true) {
            error!("Fatal: error switching {} to nonblocking: {}", addr, err);
            return Err(ExitError::Generic);
        }
        listeners.push(listener);
    }
    Ok(_http_listener(origins, metrics, log, listeners))
}

async fn _http_listener(
    origins: SharedHistory,
    metrics: Arc<ServerMetrics>,
    log: Option<Arc<LogOutput>>,
    listeners: Vec<StdListener>
) {
    if listeners.is_empty() {
        pending::<()>().await;
    }
    else {
        let _ = select_all(
            listeners.into_iter().map(|listener| {
                tokio::spawn(single_http_listener(
                    listener, origins.clone(), metrics.clone(), log.clone()
                ))
            })
        ).await;
    }
}

/// Returns a future for a single HTTP listener.
///
/// The future will never resolve unless an error happens that breaks the
/// listener, in which case it will print an error and resolve the error case.
/// It will listen bind a Hyper server onto `addr` and produce any data
/// served from `origins`.
async fn single_http_listener(
    listener: StdListener,
    origins: SharedHistory,
    metrics: Arc<ServerMetrics>,
    log: Option<Arc<LogOutput>>,
) {
    let make_service = make_service_fn(|_conn| {
        let origins = origins.clone();
        let metrics = metrics.clone();
        let log = log.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let origins = origins.clone();
                let metrics = metrics.clone();
                let log = log.clone();
                async move {
                    handle_request(
                        req, &origins, &metrics,
                        log.as_ref().map(|x| x.as_ref())
                    ).await
                }
            }))
        }
    });
    let listener = HttpAccept {
        sock: match TcpListener::from_std(listener) {
            Ok(listener) => listener,
            Err(err) => {
                error!("Failed on HTTP listener: {}", err);
                return
            }
        },
        metrics: metrics.clone(),
    };
    if let Err(err) = Server::builder(listener).serve(make_service).await {
        error!("HTTP server error: {}", err);
    }
}


//------------ handle_request ------------------------------------------------

async fn handle_request(
    req: Request<Body>,
    origins: &SharedHistory,
    metrics: &ServerMetrics,
    log: Option<&LogOutput>,
) -> Result<Response<Body>, Infallible> {
    metrics.inc_http_requests();
    if *req.method() != Method::GET {
        return Ok(method_not_allowed())
    }
    if let Some(format) = OutputFormat::from_path(req.uri().path()) {
        Ok(vrps(&req, origins, format))
    }
    else {
        Ok(match req.uri().path() {
            "/log" => handle_log(log),
            "/metrics" => handle_metrics(origins, metrics),
            "/status" => handle_status(origins, metrics),
            "/api/v1/status" => handle_api_status(origins, metrics),
            "/validity" => handle_validity_query(origins, req.uri().query()),
            "/version" => handle_version(),
            path if path.starts_with("/api/v1/validity/") => {
                handle_validity_path(origins, &path[17..])
            }
            #[cfg(feature = "ui")]
            _ => self::ui::process_request(req),
            #[cfg(not(feature = "ui"))]
            _ => not_found()
        })
    }
}


//------------ handle_metrics ------------------------------------------------

fn handle_metrics(
    history: &SharedHistory,
    server_metrics: &ServerMetrics,
) -> Response<Body> {
    let (metrics, serial, start, done, duration) = {
        let history = history.read();
        (
            match history.metrics() {
                Some(metrics) => metrics,
                None => {
                    return Response::builder()
                    .header("Content-Type", "text/plain")
                    .body("Initial validation ongoing. Please wait.".into())
                    .unwrap()
                }
            },
            history.serial(),
            history.last_update_start(),
            history.last_update_done(),
            history.last_update_duration(),
        )
    };
    let mut res = String::new();

    // valid_roas 
    writeln!(res,
        "# HELP routinator_valid_roas number of valid ROAs seen\n\
         # TYPE routinator_valid_roas gauge"
    ).unwrap();
    for tal in &metrics.tals {
        writeln!(res,
            "routinator_valid_roas{{tal=\"{}\"}} {}",
            tal.name(), tal.publication.valid_roas
        ).unwrap();
    }

    // vrps_total
    writeln!(res,
        "\n\
         # HELP routinator_vrps_total number of valid VRPs per TAL\n\
         # TYPE routinator_vrps_total gauge"
    ).unwrap();
    for tal in &metrics.tals {
        writeln!(res,
            "routinator_vrps_total{{tal=\"{}\"}} {}",
            tal.name(), tal.vrps.valid
        ).unwrap();
    }

    // vrps_final
    writeln!(res,
        "\n\
        # HELP routinator_vrps_final final number of valid VRPs\n\
        # TYPE routinator_vrps_final gauge\n\
        routinator_vrps_final {}",
        metrics.vrps.contributed,
    ).unwrap();

    // vrps_unsafe
    writeln!(res,
        "\n\
         # HELP routinator_vrps_unsafe \
                VRPs overlapping with rejected CAs\n\
         # TYPE routinator_vrps_unsafe gauge"
    ).unwrap();
    for tal in &metrics.tals {
        writeln!(res,
            "routinator_vrps_unsafe{{tal=\"{}\"}} {}",
            tal.name(), tal.vrps.marked_unsafe
        ).unwrap();
    }

    // vrps_filtered_locally
    writeln!(res,
        "\n\
         # HELP routinator_vrps_filtered_locally \
                VRPs filtered based on local exceptions\n\
         # TYPE routinator_vrps_filtered_locally gauge"
    ).unwrap();
    for tal in &metrics.tals {
        writeln!(res,
            "routinator_vrps_filtered_locally{{tal=\"{}\"}} {}",
            tal.name(), tal.vrps.locally_filtered
        ).unwrap();
    }

    // vrps_duplicate
    writeln!(res,
        "\n\
         # HELP routinator_vrps_duplicate number of duplicate VRPs per TAL\n\
         # TYPE routinator_vrps_duplicate gauge"
    ).unwrap();
    for tal in &metrics.tals {
        writeln!(res,
            "routinator_vrps_duplicate{{tal=\"{}\"}} {}",
            tal.name(), tal.vrps.duplicate
        ).unwrap();
    }

    // vrps_added_locally
    writeln!(res,
        "\n\
         # HELP routinator_vrps_added_locally \
                VRPs added from local exceptions\n\
         # TYPE routinator_vrps_added_locally gauge"
    ).unwrap();
    writeln!(res,
        "routinator_vrps_added_locally {}",
        metrics.local.contributed
    ).unwrap();

    // stale_objects
    writeln!(res,
        "\n\
        # HELP routinator_stale_count number of stale manifests and CRLs\n\
        # TYPE routinator_stale_count gauge\n\
        routinator_stale_count {}",
        metrics.publication.stale_objects(),
    ).unwrap();

    // last_update_start, last_update_done, last_update_duration
    let now = Utc::now();
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

        now.signed_duration_since(start).num_seconds(),
        duration.map(|duration| { duration.as_secs() }).unwrap_or(0),
    ).unwrap();
    match done {
        Some(instant) => {
            writeln!(res, "{}",
                now.signed_duration_since(instant).num_seconds()
            ).unwrap();
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
        serial
    ).unwrap();

    // rsync_status
    writeln!(res,
        "\n\
        # HELP routinator_rsync_status exit status of rsync command\n\
        # TYPE routinator_rsync_status gauge"
    ).unwrap();
    for metrics in &metrics.rsync {
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
    writeln!(res,
        "\n\
        # HELP routinator_rsync_duration duration of rsync in seconds\n\
        # TYPE routinator_rsync_duration gauge"
    ).unwrap();
    for metrics in &metrics.rsync {
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
    writeln!(res,
        "\n\
        # HELP routinator_rrdp_status combined status code for repository \
            update requests\n\
        # TYPE routinator_rrdp_status gauge"
    ).unwrap();
    for metrics in &metrics.rrdp {
        writeln!(
            res,
            "routinator_rrdp_status{{uri=\"{}\"}} {}",
            metrics.notify_uri,
            metrics.status().into_i16()
        ).unwrap();
    }

    // rrdp_notification_status
    writeln!(res,
        "\n\
        # HELP routinator_rrdp_notification_status status code for getting \
            notification file\n\
        # TYPE routinator_rrdp_notification_status gauge"
    ).unwrap();
    for metrics in &metrics.rrdp {
        writeln!(
            res,
            "routinator_rrdp_notification_status{{uri=\"{}\"}} {}",
            metrics.notify_uri,
            metrics.notify_status.into_i16(),
        ).unwrap();
    }

    // rrdp_payload_status
    writeln!(res,
        "\n\
        # HELP routinator_rrdp_payload_status status code(s) for getting \
            payload file(s)\n\
        # TYPE routinator_rrdp_payload_status gauge"
    ).unwrap();
    for metrics in &metrics.rrdp {
        writeln!(
            res,
            "routinator_rrdp_payload_status{{uri=\"{}\"}} {}",
            metrics.notify_uri,
            metrics.payload_status.map(|status| {
                status.into_i16()
            }).unwrap_or(0),
        ).unwrap();
    }

    // rrdp_duration
    writeln!(res,
        "\n\
        # HELP routinator_rrdp_duration duration of rrdp in seconds\n\
        # TYPE routinator_rrdp_duration gauge"
    ).unwrap();
    for metrics in &metrics.rrdp {
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

    // rrdp_serial
    writeln!(res,
        "\n\
        # HELP routinator_rrdp_serial serial number of last RRDP update\n\
        # TYPE routinator_rrdp_serial gauge"
    ).unwrap();
    for metrics in &metrics.rrdp {
        if let Some(serial) = metrics.serial {
            writeln!(
                res,
                "routinator_rrdp_serial{{uri=\"{}\"}} {}",
                metrics.notify_uri,
                serial
            ).unwrap();
        }
    }

    // rtr_connections
    writeln!(res,
        "\n\
        # HELP routinator_rtr_connections total number of RTR connections\n\
        # TYPE routinator_rtr_connections counter"
    ).unwrap();
    writeln!(res,
        "routinator_rtr_connections {}", server_metrics.rtr_conn_open()
    ).unwrap();

    // rtr_current_connections
    writeln!(res,
        "\n\
        # HELP routinator_rtr_current_connections currently open RTR \
                                                  connections\n\
        # TYPE routinator_rtr_current_connections gauge"
    ).unwrap();
    writeln!(res,
        "routinator_rtr_current_connections {}",
        server_metrics.rtr_conn_open() - server_metrics.rtr_conn_close()
    ).unwrap();

    // rtr_bytes_read
    writeln!(res,
        "\n\
        # HELP routinator_rtr_bytes_read number of bytes read via RTR\n\
        # TYPE routinator_rtr_bytes_read counter"
    ).unwrap();
    writeln!(res,
        "routinator_rtr_bytes_read {}", server_metrics.rtr_bytes_read()
    ).unwrap();

    // rtr_bytes_written
    writeln!(res,
        "\n\
        # HELP routinator_rtr_bytes_written number of bytes written via RTR\n\
        # TYPE routinator_rtr_bytes_written counter"
    ).unwrap();
    writeln!(res,
        "routinator_rtr_bytes_written {}", server_metrics.rtr_bytes_written()
    ).unwrap();

    // http_connections
    writeln!(res,
        "\n\
        # HELP routinator_http_connections total number of HTTP connections\n\
        # TYPE routinator_http_connections counter"
    ).unwrap();
    writeln!(res,
        "routinator_http_connections {}", server_metrics.http_conn_open()
    ).unwrap();

    // http_current_connections
    writeln!(res,
        "\n\
        # HELP routinator_http_current_connections currently open HTTP \
                                                  connections\n\
        # TYPE routinator_http_current_connections gauge"
    ).unwrap();
    writeln!(res,
        "routinator_http_current_connections {}",
        server_metrics.http_conn_open() - server_metrics.http_conn_close()
    ).unwrap();

    // http_bytes_read
    writeln!(res,
        "\n\
        # HELP routinator_http_bytes_read number of bytes read via HTTP\n\
        # TYPE routinator_http_bytes_read counter"
    ).unwrap();
    writeln!(res,
        "routinator_http_bytes_read {}", server_metrics.http_bytes_read()
    ).unwrap();

    // http_bytes_written
    writeln!(res,
        "\n\
        # HELP routinator_http_bytes_written number of bytes written via HTTP\n\
        # TYPE routinator_http_bytes_written counter"
    ).unwrap();
    writeln!(res,
        "routinator_http_bytes_written {}", server_metrics.http_bytes_written()
    ).unwrap();

    // http_requests
    writeln!(res,
        "\n\
        # HELP routinator_http_requests number of bytes written via HTTP\n\
        # TYPE routinator_http_requests counter"
    ).unwrap();
    writeln!(res,
        "routinator_http_requests {}", server_metrics.http_requests()
    ).unwrap();


    Response::builder()
        .header("Content-Type", "text/plain; version=0.0.4")
        .body(res.into())
        .unwrap()
}


//------------ handle_status -------------------------------------------------

fn handle_status(
    history: &SharedHistory,
    server_metrics: &ServerMetrics,
) -> Response<Body> {
    let (metrics, serial, start, done, duration) = {
        let history = history.read();
        (
            match history.metrics() {
                Some(metrics) => metrics,
                None => {
                    return Response::builder()
                    .header("Content-Type", "text/plain")
                    .body("Initial validation ongoing. Please wait.".into())
                    .unwrap()
                }
            },
            history.serial(),
            history.last_update_start(),
            history.last_update_done(),
            history.last_update_duration(),
        )
    };
    let mut res = String::new();
    let now = Utc::now();
    let start = now.signed_duration_since(start);
    let done = done.map(|done|
        now.signed_duration_since(done)
    );
    let duration = duration.map(|duration| 
        Duration::from_std(duration).unwrap()
    );
    let now = Utc::now();

    // version
    writeln!(res,
        concat!("version: ", crate_name!(), "/", crate_version!())
    ).unwrap();

    // serial
    writeln!(res, "serial: {}", serial).unwrap();

    // last-update-start-at and -ago
    writeln!(res, "last-update-start-at:  {}", now - start).unwrap();
    writeln!(res, "last-update-start-ago: {}", start).unwrap();

    // last-update-done-at and -ago
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
    writeln!(
        res, "valid-roas: {}", metrics.publication.valid_roas
    ).unwrap();

    // valid-roas-per-tal
    write!(res, "valid-roas-per-tal: ").unwrap();
    for tal in &metrics.tals {
        write!(res, "{}={} ", tal.name(), tal.publication.valid_roas).unwrap();
    }
    writeln!(res).unwrap();

    // vrps
    writeln!(res, "vrps: {}", metrics.vrps.valid).unwrap();

    // vrps-per-tal
    write!(res, "vrps-per-tal: ").unwrap();
    for tal in &metrics.tals {
        write!(res, "{}={} ", tal.name(), tal.vrps.valid).unwrap();
    }
    writeln!(res).unwrap();

    // unsafe-filtered-vrps
    writeln!(res, "unsafe-vrps: {}", metrics.vrps.marked_unsafe).unwrap();

    // unsafe-vrps-per-tal
    write!(res, "unsafe-filtered-vrps-per-tal: ").unwrap();
    for tal in &metrics.tals {
        write!(res, "{}={} ",tal.name(), tal.vrps.marked_unsafe).unwrap();
    }
    writeln!(res).unwrap();

    // locally-filtered-vrps
    writeln!(res, "locally-filtered-vrps: {}",
        metrics.vrps.locally_filtered
    ).unwrap();

    // locally-filtered-vrps-per-tal
    write!(res, "locally-filtered-vrps-per-tal: ").unwrap();
    for tal in &metrics.tals {
        write!(res, "{}={} ",
            tal.name(), tal.vrps.locally_filtered
        ).unwrap();
    }
    writeln!(res).unwrap();

    // duplicate-vrps-per-tal
    write!(res, "duplicate-vrps-per-tal: ").unwrap();
    for tal in &metrics.tals {
        write!(res, "{}={} ", tal.name(), tal.vrps.duplicate).unwrap();
    }
    writeln!(res).unwrap();

    // locally-added-vrps
    writeln!(
        res, "locally-added-vrps: {}", metrics.local.contributed
    ).unwrap();

    // final-vrps
    writeln!(res, "final-vrps: {}", metrics.vrps.contributed).unwrap();

    // final-vrps-per-tal
    write!(res, "final-vrps-per-tal: ").unwrap();
    for tal in &metrics.tals {
        write!(res, "{}={} ", tal.name(), tal.vrps.contributed).unwrap();
    }
    writeln!(res).unwrap();

    // stale-count
    writeln!(
        res, "stale-count: {}", metrics.publication.stale_objects()
    ).unwrap();

    // rsync_status
    writeln!(res, "rsync-durations:").unwrap();
    for metrics in &metrics.rsync {
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
    for metrics in &metrics.rrdp {
        write!(
            res,
            "   {}: status={}, notification-status={}, payload-status={}",
            metrics.notify_uri,
            metrics.status().into_i16(),
            metrics.notify_status.into_i16(),
            metrics.payload_status.map(|status| {
                status.into_i16()
            }).unwrap_or(0),
        ).unwrap();
        if let Ok(duration) = metrics.duration {
            write!(
                res,
                ", duration={:.3}s",
                duration.as_secs_f64()
                + f64::from(duration.subsec_millis()) / 1000.
            ).unwrap();
        }
        if let Some(serial) = metrics.serial {
            write!(res, ", serial={}", serial).unwrap()
        }
        writeln!(res).unwrap()
    }

    // rtr
    writeln!(res,
        "rtr-connections: {} current, {} total",
        server_metrics.rtr_conn_open() - server_metrics.rtr_conn_close(),
        server_metrics.rtr_conn_open()
    ).unwrap();
    writeln!(res,
        "rtr-data: {} bytes sent, {} bytes received",
        server_metrics.rtr_bytes_written(),
        server_metrics.rtr_bytes_read()
    ).unwrap();

    // http
    writeln!(res,
        "http-connections: {} current, {} total",
        server_metrics.http_conn_open() - server_metrics.http_conn_close(),
        server_metrics.http_conn_open()
    ).unwrap();
    writeln!(res,
        "http-data: {} bytes sent, {} bytes received",
        server_metrics.http_bytes_written(),
        server_metrics.http_bytes_read()
    ).unwrap();
    writeln!(res,
        "http-requests: {} ",
        server_metrics.http_requests()
    ).unwrap();

    Response::builder()
    .header("Content-Type", "text/plain")
    .body(res.into())
    .unwrap()
}


//------------ handle_api_status ---------------------------------------------

fn handle_api_status(
    history: &SharedHistory,
    server_metrics: &ServerMetrics,
) -> Response<Body> {
    let (metrics, serial, start, done, duration) = {
        let history = history.read();
        (
            match history.metrics() {
                Some(metrics) => metrics,
                None => {
                    return Response::builder()
                        .status(503)
                        .header("Content-Type", "text/plain")
                        .body("Initial validation ongoing. Please wait.".into())
                        .unwrap()
                }
            },
            history.serial(),
            history.last_update_start(),
            history.last_update_done(),
            history.last_update_duration(),
        )
    };
    let now = Utc::now();

    let res = JsonBuilder::build(|target| {
        target.member_str("version",
            concat!(crate_name!(), "/", crate_version!())
        );
        target.member_raw("serial", serial);
        target.member_str("now", now.format("%+"));
        target.member_str("lastUpdateStart", start.format("%+"));
        if let Some(done) = done {
            target.member_str("lastUpdateDone", done.format("%+"));
        }
        else {
            target.member_raw("lastUpdateDone", "null");
        }
        if let Some(duration) = duration {
            target.member_raw("lastUpdateDuration",
                format_args!("{:.3}", duration.as_secs_f32())
            );
        }
        else {
            target.member_raw("lastUpdateDuration", "null");
        }

        target.member_object("tals", |target| {
            for tal in &metrics.tals {
                target.member_object(tal.tal.name(), |target| {
                    json_vrp_metrics(target, &tal.vrps);
                    json_publication_metrics(
                        target, &tal.publication
                    );
                });
            }
        });

        target.member_object("repositories", |target| {
            for repo in &metrics.repositories {
                target.member_object(&repo.uri, |target| {
                    if repo.uri.starts_with("https://") {
                        target.member_str("type", "RRDP");
                    }
                    else if repo.uri.starts_with("rsync://") {
                        target.member_str("type", "rsync");
                    }
                    else {
                        target.member_str("type", "other");
                    }
                    json_vrp_metrics(target, &repo.vrps);
                    json_publication_metrics(
                        target, &repo.publication
                    );
                })
            }
        });

        target.member_raw("vrpsAddedLocally", metrics.local.contributed);

        target.member_object("rsync", |target| {
            for metrics in &metrics.rsync {
                target.member_object(&metrics.module, |target| {
                    target.member_raw("status", 
                        match metrics.status {
                            Ok(status) => status.code().unwrap_or(-1),
                            Err(_) => -1
                        }
                    );
                    match metrics.duration {
                        Ok(duration) => {
                            target.member_raw("duration",
                                format_args!("{:.3}", duration.as_secs_f32())
                            );
                        }
                        Err(_) => target.member_raw("duration", "null")
                    }
                })
            }
        });

        target.member_object("rrdp", |target| {
            for metrics in &metrics.rrdp {
                target.member_object(&metrics.notify_uri, |target| {
                    target.member_raw(
                        "status",
                        metrics.status().into_i16(),
                    );
                    target.member_raw(
                        "notifyStatus",
                        metrics.notify_status.into_i16(),
                    );
                    target.member_raw(
                        "payloadStatus",
                        metrics.payload_status.map(|status| {
                            status.into_i16()
                        }).unwrap_or(0)
                    );
                    match metrics.duration {
                        Ok(duration) => {
                            target.member_raw("duration",
                                format_args!("{:.3}", duration.as_secs_f32())
                            );
                        }
                        Err(_) => target.member_raw("duration", "null")
                    }
                    match metrics.serial {
                        Some(serial) => {
                            target.member_raw("serial", serial);
                        }
                        None => target.member_raw("serial", "null")
                    }
                    match metrics.session {
                        Some(session) => {
                            target.member_str("session", session);
                        }
                        None => target.member_raw("session", "null")
                    }
                    target.member_raw("delta",
                        if metrics.snapshot_reason.is_none() { "true" }
                        else { "false" }
                    );
                    if let Some(reason) = metrics.snapshot_reason {
                        target.member_str("snapshot_reason", reason.code())
                    }
                    else {
                        target.member_raw("snapshot_reason", "null");
                    }
                })
            }
        });

        target.member_object("rtr", |target| {
            target.member_raw(
                "totalConnections", server_metrics.rtr_conn_open()
            );
            target.member_raw(
                "currentConnections",
                server_metrics.rtr_conn_open() - server_metrics.rtr_conn_close()
            );
            target.member_raw(
                "bytesRead", server_metrics.rtr_bytes_read()
            );
            target.member_raw(
                "bytesWritten", server_metrics.rtr_bytes_written()
            );
        });

        target.member_object("http", |target| {
            target.member_raw(
                "totalConnections", server_metrics.http_conn_open()
            );
            target.member_raw(
                "currentConnections",
                server_metrics.http_conn_open()
                - server_metrics.http_conn_close()
            );
            target.member_raw(
                "requests", server_metrics.http_requests()
            );
            target.member_raw(
                "bytesRead", server_metrics.http_bytes_read()
            );
            target.member_raw(
                "bytesWritten", server_metrics.http_bytes_written()
            );
        });
    });
   
    Response::builder()
        .header("Content-Type", "application/json")
        .body(res.into())
        .unwrap()
}

fn json_publication_metrics(
    target: &mut JsonBuilder, metrics: &PublicationMetrics
) {
    target.member_raw("validPublicationPoints", metrics.valid_points);
    target.member_raw("rejectedPublicationPoints", metrics.rejected_points);
    target.member_raw("validManifests", metrics.valid_manifests);
    target.member_raw("invalidManifests", metrics.invalid_manifests);
    target.member_raw("staleManifests", metrics.stale_manifests);
    target.member_raw("missingManifests", metrics.missing_manifests);
    target.member_raw("validCRLs", metrics.valid_crls);
    target.member_raw("invalidCRLs", metrics.invalid_crls);
    target.member_raw("staleCRLs", metrics.stale_crls);
    target.member_raw("strayCRLs", metrics.stray_crls);
    target.member_raw("validCACerts", metrics.valid_ca_certs);
    target.member_raw("validEECerts", metrics.valid_ee_certs);
    target.member_raw("invalidCerts", metrics.invalid_certs);
    target.member_raw("validROAs", metrics.valid_roas);
    target.member_raw("invalidROAs", metrics.invalid_roas);
    target.member_raw("validGBRs", metrics.valid_gbrs);
    target.member_raw("invalidGBRs", metrics.invalid_gbrs);
    target.member_raw("otherObjects", metrics.others);
}

fn json_vrp_metrics(target: &mut JsonBuilder, vrps: &VrpMetrics) {
    target.member_raw("vrpsTotal", vrps.valid);
    target.member_raw("vrpsUnsafe", vrps.marked_unsafe);
    target.member_raw("vrpsLocallyFiltered", vrps.locally_filtered);
    target.member_raw("vrpsDuplicate", vrps.duplicate);
    target.member_raw("vrpsFinal", vrps.contributed);
}


//------------ handle_log ----------------------------------------------------

fn handle_log(log: Option<&LogOutput>) -> Response<Body> {
    Response::builder()
    .header("Content-Type", "text/plain;charset=UTF-8")
    .body(
        if let Some(log) = log {
            log.get_output().into()
        }
        else {
            Body::empty()
        }
    )
    .unwrap()
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
        .into_json()
        .into()
    ).unwrap()
}


//------------ handle_version ------------------------------------------------

fn handle_version() -> Response<Body> {
    Response::builder()
    .header("Content-Type", "text/plain")
    .body(crate_version!().into())
    .unwrap()
}


//------------ handle_vrps ---------------------------------------------------

/// Produces a response listing VRPs.
fn vrps(
    req: &Request<Body>,
    history: &SharedHistory,
    format: OutputFormat,
) -> Response<Body> {
    let (session, serial, created, snapshot, metrics) = {
        let history = history.read();
        (
            history.session(),
            history.serial(),
            history.created(),
            history.current(),
            history.metrics()
        )
    };
    let (snapshot, metrics, created) = match (snapshot, metrics, created) {
        (Some(snapshot), Some(metrics), Some(created)) => {
            (snapshot, metrics, created)
        }
        _ => {
            return Response::builder()
                .status(503)
                .header("Content-Type", "text/plain")
                .body("Initial validation ongoing. Please wait.".into())
                .unwrap()
        }
    };

    let etag = format!("\"{:x}-{}\"", session, serial);

    if let Some(response) = maybe_not_modified(req, &etag, created) {
        return response
    }

    let selection = match output::Selection::from_query(req.uri().query()) {
        Ok(selection) => selection,
        Err(_) => return bad_request(),
    };
    let stream = format.stream(snapshot, selection, metrics);

    let builder = Response::builder()
        .header("Content-Type", format.content_type())
        .header("ETag", etag)
        .header("Last-Modified", format_http_date(&created));

    builder.body(Body::wrap_stream(stream::iter(
        stream.map(Result::<_, Infallible>::Ok)
    )))
    .unwrap()
}

/// Returns a 304 Not Modified response if appropriate.
///
/// If either the etag or the completion time are referred to by the request,
/// returns the reponse. If a new response needs to be generated, returns
/// `None`.
fn maybe_not_modified(
    req: &Request<Body>,
    etag: &str,
    done: DateTime<Utc>,
) -> Option<Response<Body>> {
    // First, check If-None-Match.
    for value in req.headers().get_all("If-None-Match").iter() {
        // Skip ill-formatted values. By being lazy here we may falsely
        // return a full response, so this should be fine.
        let value = match value.to_str() {
            Ok(value) => value,
            Err(_) => continue
        };
        let value = value.trim();
        if value == "*" {
            return Some(not_modified(etag, done))
        }
        for tag in EtagsIter(value) {
            if tag.trim() == etag {
                return Some(not_modified(etag, done))
            }
        }
    }

    // Now, the If-Modified-Since header.
    if let Some(value) = req.headers().get("If-Modified-Since") {
        if let Some(date) = parse_http_date(value) {
            if date >= done {
                return Some(not_modified(etag, done))
            }
        }
    }

    None
}

/// Returns the 304 Not Modified response.
fn not_modified(etag: &str, done: DateTime<Utc>) -> Response<Body> {
    Response::builder()
    .status(304)
    .header("ETag", etag)
    .header("Last-Modified", format_http_date(&done))
    .body(Body::empty()).unwrap()
}


//------------ Error Responses -----------------------------------------------

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


//------------ Wrapped sockets for metrics -----------------------------------

struct HttpAccept {
    sock: TcpListener,
    metrics: Arc<ServerMetrics>,
}

impl Accept for HttpAccept {
    type Conn = HttpStream;
    type Error = io::Error;

    fn poll_accept(
        mut self: Pin<&mut Self>,
        cx: &mut Context
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        let sock = &mut self.sock;
        pin_mut!(sock);
        match sock.poll_accept(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok((sock, _addr))) => {
                self.metrics.inc_http_conn_open();
                Poll::Ready(Some(Ok(HttpStream {
                    sock,
                    metrics: self.metrics.clone()
                })))
            }
            Poll::Ready(Err(err)) => {
                Poll::Ready(Some(Err(err)))
            }
        }
    }
}


struct HttpStream {
    sock: TcpStream,
    metrics: Arc<ServerMetrics>,
}

impl AsyncRead for HttpStream {
    fn poll_read(
        mut self: Pin<&mut Self>, cx: &mut Context, buf: &mut ReadBuf
    ) -> Poll<Result<(), io::Error>> {
        let len = buf.filled().len();
        let sock = &mut self.sock;
        pin_mut!(sock);
        let res = sock.poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = res {
            self.metrics.inc_http_bytes_read(
                (buf.filled().len().saturating_sub(len)) as u64
            )    
        }
        res
    }
}

impl AsyncWrite for HttpStream {
    fn poll_write(
        mut self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]
    ) -> Poll<Result<usize, io::Error>> {
        let sock = &mut self.sock;
        pin_mut!(sock);
        let res = sock.poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = res {
            self.metrics.inc_http_bytes_written(n as u64)
        }
        res
    }

    fn poll_flush(
        mut self: Pin<&mut Self>, cx: &mut Context
    ) -> Poll<Result<(), io::Error>> {
        let sock = &mut self.sock;
        pin_mut!(sock);
        sock.poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>, cx: &mut Context
    ) -> Poll<Result<(), io::Error>> {
        let sock = &mut self.sock;
        pin_mut!(sock);
        sock.poll_shutdown(cx)
    }
}

impl Drop for HttpStream {
    fn drop(&mut self) {
        self.metrics.inc_http_conn_close()
    }
}


//------------ Parsing Etags -------------------------------------------------

/// An iterator over the etags in an If-Not-Match header value.
///
/// This does not handle the "*" value.
///
/// One caveat: The iterator stops when it encounters bad formatting which
/// makes this indistinguishable from reaching the end of a correctly
/// formatted value. As a consequence, we will 304 a request that has the
/// right tag followed by garbage.
struct EtagsIter<'a>(&'a str);

impl<'a> Iterator for EtagsIter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        // Skip white space and check if we are done.
        self.0 = self.0.trim_start();
        if self.0.is_empty() {
            return None
        }

        // We either have to have a lone DQUOTE or one prefixed by W/
        let prefix_len = if self.0.starts_with('"') {
            1
        }
        else if self.0.starts_with("W/\"") {
            3
        }
        else {
            return None
        };

        // Find the end of the tag which is after the next DQUOTE.
        let end = match self.0[prefix_len..].find('"') {
            Some(index) => index + prefix_len + 1,
            None => return None
        };

        let res = &self.0[0..end];

        // Move past the second DQUOTE and any space.
        self.0 = self.0[end..].trim_start();

        // If we have a comma, skip over that and any space.
        if self.0.starts_with(',') {
            self.0 = self.0[1..].trim_start();
        }

        Some(res)
    }
}


//------------ Parsing and Constructing HTTP Dates ---------------------------

/// Definition of the preferred date format (aka IMF-fixdate).
///
/// The definition allows for relaxed parsing: It accepts additional white
/// space and ignores case for textual representations. It does, however,
/// construct the correct representation when formatting.
const IMF_FIXDATE: &[Item<'static>] = &[
    Item::Space(""),
    Item::Fixed(Fixed::ShortWeekdayName),
    Item::Space(""),
    Item::Literal(","),
    Item::Space(" "),
    Item::Numeric(Numeric::Day, Pad::Zero),
    Item::Space(" "),
    Item::Fixed(Fixed::ShortMonthName),
    Item::Space(" "),
    Item::Numeric(Numeric::Year, Pad::Zero),
    Item::Space(" "),
    Item::Numeric(Numeric::Hour, Pad::Zero),
    Item::Literal(":"),
    Item::Numeric(Numeric::Minute, Pad::Zero),
    Item::Literal(":"),
    Item::Numeric(Numeric::Second, Pad::Zero),
    Item::Space(" "),
    Item::Literal("GMT"),
    Item::Space(""),
];

/// Definition of the obsolete RFC850 date format..
const RFC850_DATE: &[Item<'static>] = &[
    Item::Space(""),
    Item::Fixed(Fixed::LongWeekdayName),
    Item::Space(""),
    Item::Literal(","),
    Item::Space(" "),
    Item::Numeric(Numeric::Day, Pad::Zero),
    Item::Literal("-"),
    Item::Fixed(Fixed::ShortMonthName),
    Item::Literal("-"),
    Item::Numeric(Numeric::YearMod100, Pad::Zero),
    Item::Space(" "),
    Item::Numeric(Numeric::Hour, Pad::Zero),
    Item::Literal(":"),
    Item::Numeric(Numeric::Minute, Pad::Zero),
    Item::Literal(":"),
    Item::Numeric(Numeric::Second, Pad::Zero),
    Item::Space(" "),
    Item::Literal("GMT"),
    Item::Space(""),
];

/// Definition of the obsolete asctime date format.
const ASCTIME_DATE: &[Item<'static>] = &[
    Item::Space(""),
    Item::Fixed(Fixed::ShortWeekdayName),
    Item::Space(" "),
    Item::Fixed(Fixed::ShortMonthName),
    Item::Space(" "),
    Item::Numeric(Numeric::Day, Pad::Space),
    Item::Space(" "),
    Item::Numeric(Numeric::Hour, Pad::Zero),
    Item::Literal(":"),
    Item::Numeric(Numeric::Minute, Pad::Zero),
    Item::Literal(":"),
    Item::Numeric(Numeric::Second, Pad::Zero),
    Item::Space(" "),
    Item::Numeric(Numeric::Year, Pad::Zero),
    Item::Space(""),
];

fn parse_http_date(date: &HeaderValue) -> Option<DateTime<Utc>> {
    use chrono::format::{Parsed, parse};

    // All formats are ASCII-only, so if we can’t turn the value into a
    // string, it ain’t a valid date.
    let date = date.to_str().ok()?;

    let mut parsed = Parsed::new();
    if parse(&mut parsed, date, IMF_FIXDATE.iter()).is_err() {
        parsed = Parsed::new();
        if parse(&mut parsed, date, RFC850_DATE.iter()).is_err() {
            parsed = Parsed::new();
            if parse(&mut parsed, date, ASCTIME_DATE.iter()).is_err() {
                return None
            }
        }
    }
    parsed.to_datetime_with_timezone(&Utc).ok()
}

fn format_http_date(date: &DateTime<Utc>) -> String {
    date.format_with_items(IMF_FIXDATE.iter()).to_string()
}


//============ Routinator UI =================================================

#[cfg(feature = "ui")]
mod ui {
    use hyper::{Body, Request, Response};

    macro_rules! assets {
        (
            $(
                ( $path:expr => $( $ext:ident ),*  ),
            )*
        )
        => {
            pub fn process_request(req: Request<Body>) -> Response<Body> {
                match req.uri().path() {
                    "/" => {
                        serve(
                            include_bytes!(
                                "../contrib/routinator-ui/index.html"
                            ),
                            self::content_types::html
                        )
                    }
                    $(
                        $(
                            concat!("/ui/", $path, ".", stringify!($ext)) => {
                                serve(
                                    include_bytes!(
                                        concat!(
                                            "../contrib/routinator-ui/",
                                            $path, ".",
                                            stringify!($ext)
                                        )
                                    ),
                                    self::content_types::$ext
                                )
                            }
                        )*
                    )*
                    _ => super::not_found()
                }
            }
        }
    }

    assets!(
        ("favicon" => ico),
        ("css/app" => css),
        ("fonts/element-icons" => ttf, woff),
        ("fonts/lato-latin-100" => woff, woff2),
        ("fonts/lato-latin-300" => woff, woff2),
        ("fonts/lato-latin-400" => woff, woff2),
        ("fonts/lato-latin-700" => woff, woff2),
        ("fonts/lato-latin-900" => woff, woff2),
        ("fonts/lato-latin-100italic" => woff, woff2),
        ("fonts/lato-latin-300italic" => woff, woff2),
        ("fonts/lato-latin-400italic" => woff, woff2),
        ("fonts/lato-latin-700italic" => woff, woff2),
        ("fonts/lato-latin-900italic" => woff, woff2),
        ("fonts/source-code-pro-latin-200" => woff, woff2),
        ("fonts/source-code-pro-latin-200" => woff, woff2),
        ("fonts/source-code-pro-latin-300" => woff, woff2),
        ("fonts/source-code-pro-latin-400" => woff, woff2),
        ("fonts/source-code-pro-latin-500" => woff, woff2),
        ("fonts/source-code-pro-latin-600" => woff, woff2),
        ("fonts/source-code-pro-latin-700" => woff, woff2),
        ("fonts/source-code-pro-latin-900" => woff, woff2),
        ("img/afrinic" => svg),
        ("img/apnic" => svg),
        ("img/arin" => svg),
        ("img/blue" => svg),
        ("img/lacnic" => svg),
        ("img/ripencc" => svg),
        ("img/routinator_logo_white" => svg),
        ("img/welcome" => svg),
        ("js/app" => js),
    );

    fn serve(data: &'static [u8], ctype: &'static [u8]) -> Response<Body> {
        Response::builder()
        .header("Content-Type", ctype)
        .body(data.into())
        .unwrap()
    }

    #[allow(non_upper_case_globals)]
    mod content_types {
        pub const css: &[u8] = b"text/css";
        pub const html: &[u8] = b"text/html";
        pub const ico: &[u8] = b"image/x-icon";
        pub const js: &[u8] = b"application/javascript";
        pub const svg: &[u8] = b"image/svg+xml";
        pub const ttf: &[u8] = b"font/ttf";
        pub const woff: &[u8] = b"font/woff";
        pub const woff2: &[u8] = b"font/woff2";
    }
}


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn etags_iter() {
        assert_eq!(
            EtagsIter("\"foo\", \"bar\", \"ba,zz\"").collect::<Vec<_>>(),
            ["\"foo\"", "\"bar\"", "\"ba,zz\""]
        );
        assert_eq!(
            EtagsIter("\"foo\", W/\"bar\" , \"ba,zz\", ").collect::<Vec<_>>(),
            ["\"foo\"", "W/\"bar\"", "\"ba,zz\""]
        );
    }

    #[test]
    fn test_parse_http_date() {
        let date = DateTime::<Utc>::from_utc(
            chrono::naive::NaiveDate::from_ymd(
                1994, 11, 6
            ).and_hms(8, 49, 37),
            Utc
        );

        assert_eq!(
            parse_http_date(
                &HeaderValue::from_static("Sun, 06 Nov 1994 08:49:37 GMT")
            ),
            Some(date)
        );
        assert_eq!(
            parse_http_date(
                &HeaderValue::from_static("Sunday, 06-Nov-94 08:49:37 GMT")
            ),
            Some(date)
        );
        assert_eq!(
            parse_http_date(
                &HeaderValue::from_static("Sun Nov  6 08:49:37 1994")
            ),
            Some(date)
        );
    }
}

