//! Handling of endpoints related to the status.

use std::cmp;
use chrono::{DateTime, Duration, Utc};
use clap::{crate_name, crate_version};
use hyper::{Body, Method, Request};
use crate::metrics::{
    HttpServerMetrics, PayloadMetrics, PublicationMetrics,
    RtrClientMetrics, SharedRtrServerMetrics, VrpMetrics,
};
use crate::payload::SharedHistory;
use crate::utils::fmt::WriteOrPanic;
use crate::utils::json::JsonBuilder;
use super::response::{ContentType, Response, ResponseBuilder};


//------------ handle_get ----------------------------------------------------

pub async fn handle_get_or_head(
    req: &Request<Body>,
    history: &SharedHistory,
    http: &HttpServerMetrics,
    rtr: &SharedRtrServerMetrics,
) -> Option<Response> {
    let head = *req.method() == Method::HEAD;
    match req.uri().path() {
        "/status" => Some(handle_status(head, history, http, rtr).await),
        "/api/v1/status" => {
            Some(handle_api_status(head, history, http, rtr).await)
        },
        "/version" => Some(handle_version(head)),
        _ => None
    }
}


//------------ handle_status -------------------------------------------------

async fn handle_status(
    head: bool,
    history: &SharedHistory,
    server_metrics: &HttpServerMetrics,
    rtr_metrics: &SharedRtrServerMetrics,
) -> Response {
    let (metrics, serial, start, done, duration, unsafe_vrps) = {
        let history = history.read();
        (
            match history.metrics() {
                Some(metrics) => metrics,
                None => return Response::initial_validation(),
            },
            history.serial(),
            history.last_update_start(),
            history.last_update_done(),
            history.last_update_duration(),
            history.unsafe_vrps(),
        )
    };

    if head {
        return ResponseBuilder::ok().content_type(ContentType::TEXT).empty();
    }

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
    );

    // serial
    writeln!(res, "serial: {}", serial);

    // last-update-start-at and -ago
    writeln!(res, "last-update-start-at:  {}", now - start);
    writeln!(res, "last-update-start-ago: {}", start);

    // last-update-done-at and -ago
    if let Some(done) = done {
        writeln!(res, "last-update-done-at:   {}", now - done);
        writeln!(res, "last-update-done-ago:  {}", done);
    }
    else {
        writeln!(res, "last-update-done-at:   -");
        writeln!(res, "last-update-done-ago:  -");
    }

    // last-update-duration
    if let Some(duration) = duration {
        writeln!(res, "last-update-duration:  {}", duration);
    }
    else {
        writeln!(res, "last-update-duration:  -");
    }

    // valid-roas
    writeln!(
        res, "valid-roas: {}", metrics.publication.valid_roas
    );

    // valid-roas-per-tal
    write!(res, "valid-roas-per-tal: ");
    for tal in &metrics.tals {
        write!(res, "{}={} ", tal.name(), tal.publication.valid_roas);
    }
    writeln!(res);

    // vrps
    writeln!(res, "vrps: {}", metrics.payload.vrps().valid);

    // vrps-per-tal
    write!(res, "vrps-per-tal: ");
    for tal in &metrics.tals {
        write!(res, "{}={} ", tal.name(), tal.payload.vrps().valid);
    }
    writeln!(res);

    if unsafe_vrps.log() {
        // unsafe-filtered-vrps
        writeln!(res,
            "unsafe-vrps: {}",
            metrics.payload.vrps().marked_unsafe
        );

        // unsafe-vrps-per-tal
        write!(res, "unsafe-filtered-vrps-per-tal: ");
        for tal in &metrics.tals {
            write!(res,
                "{}={} ",
                tal.name(),
                tal.payload.vrps().marked_unsafe
            );
        }
        writeln!(res);
    }

    // locally-filtered-vrps
    writeln!(res,
        "locally-filtered-vrps: {}",
        metrics.payload.vrps().locally_filtered
    );

    // locally-filtered-vrps-per-tal
    write!(res, "locally-filtered-vrps-per-tal: ");
    for tal in &metrics.tals {
        write!(res, "{}={} ",
            tal.name(), tal.payload.vrps().locally_filtered
        );
    }
    writeln!(res);

    // duplicate-vrps-per-tal
    write!(res, "duplicate-vrps-per-tal: ");
    for tal in &metrics.tals {
        write!(
            res, "{}={} ", tal.name(), tal.payload.vrps().duplicate
        );
    }
    writeln!(res);

    // locally-added-vrps
    writeln!(
        res, "locally-added-vrps: {}", metrics.local.vrps().contributed
    );

    // final-vrps
    writeln!(res,
        "final-vrps: {}",
        metrics.payload.vrps().contributed
    );

    // final-vrps-per-tal
    write!(res, "final-vrps-per-tal: ");
    for tal in &metrics.tals {
        write!(
            res, "{}={} ", tal.name(), tal.payload.vrps().contributed
        );
    }
    writeln!(res);

    // stale-count
    writeln!(
        res, "stale-count: {}", metrics.publication.stale_objects()
    );

    // rsync_status
    writeln!(res, "rsync-durations:");
    for metrics in &metrics.rsync {
        write!(
            res,
            "   {}: status={}",
            metrics.module,
            match metrics.status {
                Ok(status) => status.code().unwrap_or(-1),
                Err(_) => -1
            }
        );
        if let Ok(duration) = metrics.duration {
            writeln!(
                res,
                ", duration={:.3}s",
                duration.as_secs() as f64
                + f64::from(duration.subsec_millis()) / 1000.
            );
        }
        else {
            writeln!(res)
        }
    }

    // rrdp_status
    writeln!(res, "rrdp-durations:");
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
        );
        if let Ok(duration) = metrics.duration {
            write!(
                res,
                ", duration={:.3}s",
                duration.as_secs_f64()
                + f64::from(duration.subsec_millis()) / 1000.
            );
        }
        if let Some(serial) = metrics.serial {
            write!(res, ", serial={}", serial)
        }
        writeln!(res)
    }

    let detailed_rtr = rtr_metrics.detailed();
    let rtr_metrics = rtr_metrics.read().await;

    // rtr
    writeln!(res,
        "rtr-connections: {} current",
        rtr_metrics.current_connections(),
    );
    writeln!(res,
        "rtr-data: {} bytes sent, {} bytes received",
        rtr_metrics.bytes_written(),
        rtr_metrics.bytes_read()
    );

    if detailed_rtr {
        // rtr-clients
        writeln!(res, "rtr-clients:");
        rtr_metrics.fold_clients(
            RtrClientStatus::default(), RtrClientStatus::fold
        ).for_each(|(addr, data)| {
            write!(res, "    {}: connections={}, ", addr, data.connections);
            if let Some(serial) = data.serial {
                write!(res, "serial={}, ", serial);
            }
            else {
                write!(res, "serial=N/A, ");
            }
            if let Some(update) = data.updated {
                let update = Utc::now() - update;
                write!(
                    res,
                    "updated-ago={}.{:03}s, ",
                    update.num_seconds(), update.num_milliseconds() % 1000
                );
            }
            else {
                write!(res, "updated=N/A, ");
            }
            if let Some(update) = data.last_reset {
                let update = Utc::now() - update;
                write!(
                    res,
                    "last-reset-ago={}.{:03}s, ",
                    update.num_seconds(), update.num_milliseconds() % 1000
                );
            }
            else {
                write!(res, "last-reset=N/A, ");
            }
            writeln!(res,
                "reset-queries={}, serial-queries={}, read={}, written={}",
                data.reset_queries, data.serial_queries,
                data.bytes_read, data.bytes_written,
            );
        });
    }

    // http
    writeln!(res,
        "http-connections: {} current, {} total",
        server_metrics.conn_open() - server_metrics.conn_close(),
        server_metrics.conn_open()
    );
    writeln!(res,
        "http-data: {} bytes sent, {} bytes received",
        server_metrics.bytes_written(),
        server_metrics.bytes_read()
    );
    writeln!(res,
        "http-requests: {} ",
        server_metrics.requests()
    );

    ResponseBuilder::ok().content_type(ContentType::TEXT).body(res)
}


//------------ handle_api_status ---------------------------------------------

async fn handle_api_status(
    head: bool,
    history: &SharedHistory,
    server_metrics: &HttpServerMetrics,
    rtr_metrics: &SharedRtrServerMetrics,
) -> Response {
    let (metrics, serial, start, done, duration) = {
        let history = history.read();
        (
            match history.metrics() {
                Some(metrics) => metrics,
                None => return Response::initial_validation()
            },
            history.serial(),
            history.last_update_start(),
            history.last_update_done(),
            history.last_update_duration(),
        )
    };

    if head {
        return ResponseBuilder::ok().content_type(ContentType::JSON).empty();
    }

    let now = Utc::now();
    let detailed_rtr = rtr_metrics.detailed();
    let rtr_metrics = rtr_metrics.read().await;

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
                    json_payload_metrics(target, &tal.payload);
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
                    json_payload_metrics(target, &repo.payload);
                    json_publication_metrics(
                        target, &repo.publication
                    );
                })
            }
        });

        target.member_raw(
            "vrpsAddedLocally",
            metrics.local.vrps().contributed
        );

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
                    if !metrics.status().is_not_modified() {
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
                    }
                })
            }
        });

        target.member_object("rtr", |target| {
            target.member_raw(
                "currentConnections",
                rtr_metrics.current_connections()
            );
            target.member_raw(
                "bytesRead", rtr_metrics.bytes_read()
            );
            target.member_raw(
                "bytesWritten", rtr_metrics.bytes_written()
            );

            if detailed_rtr {
                target.member_object("clients", |target| {
                    rtr_metrics.fold_clients(
                        RtrClientStatus::default(), RtrClientStatus::fold
                   ).for_each(
                        |(addr, data)| {
                            target.member_object(addr, |target| {
                                target.member_raw(
                                    "connections", data.connections
                                );
                                if let Some(serial) = data.serial {
                                    target.member_raw("serial", serial);
                                }
                                else {
                                    target.member_raw("serial", "null");
                                }
                                if let Some(update) = data.updated {
                                    target.member_str(
                                        "updated",
                                        update.format("%+")
                                    );
                                }
                                else {
                                    target.member_raw("updated", "null");
                                }
                                if let Some(update) = data.last_reset {
                                    target.member_str(
                                        "lastReset",
                                        update.format("%+")
                                    );
                                }
                                else {
                                    target.member_raw("lastReset", "null");
                                }
                                target.member_raw(
                                    "resetQueries", data.reset_queries
                                );
                                target.member_raw(
                                    "serialQueries", data.serial_queries
                                );
                                target.member_raw(
                                    "read", data.bytes_read
                                );
                                target.member_raw(
                                    "written", data.bytes_written
                                );
                            })
                        }
                    );
                });
            }
        });

        target.member_object("http", |target| {
            target.member_raw(
                "totalConnections", server_metrics.conn_open()
            );
            target.member_raw(
                "currentConnections",
                server_metrics.conn_open()
                - server_metrics.conn_close()
            );
            target.member_raw(
                "requests", server_metrics.requests()
            );
            target.member_raw(
                "bytesRead", server_metrics.bytes_read()
            );
            target.member_raw(
                "bytesWritten", server_metrics.bytes_written()
            );
        });
    });
   
    ResponseBuilder::ok().content_type(ContentType::JSON).body(res)
}

fn json_publication_metrics(
    target: &mut JsonBuilder, metrics: &PublicationMetrics
) {
    target.member_raw("validPublicationPoints", metrics.valid_points);
    target.member_raw("rejectedPublicationPoints", metrics.rejected_points);
    target.member_raw("validManifests", metrics.valid_manifests);
    target.member_raw("invalidManifests", metrics.invalid_manifests);
    target.member_raw("prematureManifests", metrics.premature_manifests);
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
    target.member_raw("invalidASPAs", metrics.invalid_aspas);
    target.member_raw("validASPAs", metrics.valid_aspas);
    target.member_raw("invalidGBRs", metrics.invalid_gbrs);
    target.member_raw("otherObjects", metrics.others);
}

fn json_payload_metrics(target: &mut JsonBuilder, payload: &PayloadMetrics) {
    target.member_raw("vrpsTotal", payload.vrps().valid);
    target.member_raw("vrpsUnsafe", payload.vrps().marked_unsafe);
    target.member_raw("vrpsLocallyFiltered", payload.vrps().locally_filtered);
    target.member_raw("vrpsDuplicate", payload.vrps().duplicate);
    target.member_raw("vrpsFinal", payload.vrps().contributed);
    target.member_object("payload", |target| {
        target.member_object("routeOriginsIPv4", |target| {
            json_vrps_metrics(target, &payload.v4_origins, true)
        });
        target.member_object("routeOriginsIPv6", |target| {
            json_vrps_metrics(target, &payload.v6_origins, true)
        });
        target.member_object("routerKeys", |target| {
            json_vrps_metrics(target, &payload.router_keys, false)
        });
        target.member_object("aspas", |target| {
            target.member_raw("total", payload.aspas.valid);
            target.member_raw("totalIPv4", payload.aspas.valid_v4);
            target.member_raw("totalIPv6", payload.aspas.valid_v6);
            // XXX locallyFiltered: We don’t do filtering yet.
            target.member_raw("duplicate", payload.aspas.duplicate);
            target.member_raw("final", payload.aspas.duplicate);
        })
    });
}

fn json_vrps_metrics(
    target: &mut JsonBuilder,
    vrps: &VrpMetrics,
    include_unsafe: bool,
) {
    target.member_raw("total", vrps.valid);
    if include_unsafe {
        target.member_raw("unsafe", vrps.marked_unsafe);
    }
    target.member_raw("locallyFiltered", vrps.locally_filtered);
    target.member_raw("duplicate", vrps.duplicate);
    target.member_raw("final", vrps.contributed);
}


//------------ handle_version ------------------------------------------------

fn handle_version(head: bool) -> Response {
    let res = ResponseBuilder::ok().content_type(ContentType::TEXT);
    if head {
        res.empty()
    }
    else {
        res.body(crate_version!())
    }
}


//------------ RtrClientStatus -----------------------------------------------

// Helper struct to keep RTR client data.
#[derive(Clone, Default)]
struct RtrClientStatus {
    connections: usize,
    serial: Option<u32>,
    updated: Option<DateTime<Utc>>,
    last_reset: Option<DateTime<Utc>>,
    reset_queries: u32,
    serial_queries: u32,
    bytes_read: u64,
    bytes_written: u64,
}

impl RtrClientStatus {
    fn fold(&mut self, client: &RtrClientMetrics) {
        if client.is_open() {
            self.connections += 1;
        }
        self.serial = match (
            self.serial, client.serial().map(u32::from)
        ) {
            (Some(left), Some(right)) => Some(cmp::max(left, right)),
            (Some(left), None) => Some(left),
            (None, Some(right)) => Some(right),
            (None, None) => None
        };
        self.updated = match (self.updated, client.updated()) {
            (Some(left), Some(right)) => Some(cmp::max(left, right)),
            (Some(left), None) => Some(left),
            (None, Some(right)) => Some(right),
            (None, None) => None
        };
        self.last_reset = match
            (self.last_reset, client.last_reset())
        {
            (Some(left), Some(right)) => Some(cmp::max(left, right)),
            (Some(left), None) => Some(left),
            (None, Some(right)) => Some(right),
            (None, None) => None
        };
        self.reset_queries += client.reset_queries();
        self.serial_queries += client.serial_queries();
        self.bytes_read += client.bytes_read();
        self.bytes_written += client.bytes_written();
    }
}

