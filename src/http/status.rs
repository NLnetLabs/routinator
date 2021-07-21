//! Handling of endpoints related to the status.

use std::cmp;
use std::fmt::Write;
use chrono::{Duration, Utc};
use clap::{crate_name, crate_version};
use hyper::{Body, Request, Response};
use crate::metrics::{
    HttpServerMetrics, PublicationMetrics, SharedRtrServerMetrics, VrpMetrics
};
use crate::payload::SharedHistory;
use crate::utils::json::JsonBuilder;
use super::errors::initial_validation;


//------------ handle_get ----------------------------------------------------

pub async fn handle_get(
    req: &Request<Body>,
    history: &SharedHistory,
    http: &HttpServerMetrics,
    rtr: &SharedRtrServerMetrics,
) -> Option<Response<Body>> {
    match req.uri().path() {
        "/status" => Some(handle_status(history, http, rtr).await),
        "/api/v1/status" => Some(handle_api_status(history, http, rtr).await),
        "/version" => Some(handle_version()),
        _ => None
    }
}


//------------ handle_status -------------------------------------------------

async fn handle_status(
    history: &SharedHistory,
    server_metrics: &HttpServerMetrics,
    rtr_metrics: &SharedRtrServerMetrics,
) -> Response<Body> {
    let (metrics, serial, start, done, duration) = {
        let history = history.read();
        (
            match history.metrics() {
                Some(metrics) => metrics,
                None => return initial_validation(),
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

    let detailed_rtr = rtr_metrics.detailed();
    let rtr_metrics = rtr_metrics.read().await;

    // rtr
    writeln!(res,
        "rtr-connections: {} current",
        rtr_metrics.current_connections(),
    ).unwrap();
    writeln!(res,
        "rtr-data: {} bytes sent, {} bytes received",
        rtr_metrics.bytes_written(),
        rtr_metrics.bytes_read()
    ).unwrap();

    if detailed_rtr {
        // rtr-clients
        writeln!(res, "rtr-clients:").unwrap();
        rtr_metrics.fold_clients(
            // connections, serial, update, read, written
            (0, None, None, 0, 0),
            |data, client| {
                if client.is_open() {
                    data.0 += 1
                }
                data.1 = match (
                    data.1, client.serial().map(u32::from)
                ) {
                    (Some(left), Some(right)) => Some(cmp::max(left, right)),
                    (Some(left), None) => Some(left),
                    (None, Some(right)) => Some(right),
                    (None, None) => None
                };
                data.2 = match (data.2, client.updated()) {
                    (Some(left), Some(right)) => Some(cmp::max(left, right)),
                    (Some(left), None) => Some(left),
                    (None, Some(right)) => Some(right),
                    (None, None) => None
                };
                data.3 += client.bytes_read();
                data.4 += client.bytes_written();
            }
        ).for_each(|(addr, (conns, serial, update, read, written))| {
            write!(res, "    {}: connections={}, ", addr, conns).unwrap();
            if let Some(serial) = serial {
                write!(res, "serial={}, ", serial).unwrap();
            }
            else {
                write!(res, "serial=N/A, ").unwrap();
            }
            if let Some(update) = update {
                let update = Utc::now() - update;
                write!(
                    res,
                    "updated-ago={}.{:03}s, ",
                    update.num_seconds(), update.num_milliseconds() % 1000
                ).unwrap();
            }
            else {
                write!(res, "updated=N/A, ").unwrap();
            }
            writeln!(res, "read={}, written={}", read, written).unwrap();
        });
    }

    // http
    writeln!(res,
        "http-connections: {} current, {} total",
        server_metrics.conn_open() - server_metrics.conn_close(),
        server_metrics.conn_open()
    ).unwrap();
    writeln!(res,
        "http-data: {} bytes sent, {} bytes received",
        server_metrics.bytes_written(),
        server_metrics.bytes_read()
    ).unwrap();
    writeln!(res,
        "http-requests: {} ",
        server_metrics.requests()
    ).unwrap();

    Response::builder()
    .header("Content-Type", "text/plain")
    .body(res.into())
    .unwrap()
}


//------------ handle_api_status ---------------------------------------------

async fn handle_api_status(
    history: &SharedHistory,
    server_metrics: &HttpServerMetrics,
    rtr_metrics: &SharedRtrServerMetrics,
) -> Response<Body> {
    let (metrics, serial, start, done, duration) = {
        let history = history.read();
        (
            match history.metrics() {
                Some(metrics) => metrics,
                None => return initial_validation()
            },
            history.serial(),
            history.last_update_start(),
            history.last_update_done(),
            history.last_update_duration(),
        )
    };

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
                        // connections, serial, update, read, written
                        (0, None, None, 0, 0),
                        |data, client| {
                            if client.is_open() {
                                data.0 += 1
                            }
                            data.1 = match (
                                data.1,
                                client.serial().map(u32::from)
                            ) {
                                (Some(left), Some(right)) => {
                                    Some(cmp::max(left, right))
                                }
                                (Some(left), None) => Some(left),
                                (None, Some(right)) => Some(right),
                                (None, None) => None
                            };
                            data.2 = match (data.2, client.updated()) {
                                (Some(left), Some(right)) => {
                                    Some(cmp::max(left, right))
                                }
                                (Some(left), None) => Some(left),
                                (None, Some(right)) => Some(right),
                                (None, None) => None
                            };
                            data.3 += client.bytes_read();
                            data.4 += client.bytes_written();
                        }
                    ).for_each(
                        |(addr, (conns, serial, update, read, written))| {
                            target.member_object(addr, |target| {
                                target.member_raw("connections", conns);
                                if let Some(serial) = serial {
                                    target.member_raw("serial", serial);
                                }
                                else {
                                    target.member_raw("serial", "null");
                                }
                                if let Some(update) = update {
                                    target.member_str(
                                        "updated",
                                        update.format("%+")
                                    );
                                }
                                else {
                                    target.member_raw("updated", "null");
                                }
                                target.member_raw("read", read);
                                target.member_raw("written", written);
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


//------------ handle_version ------------------------------------------------

fn handle_version() -> Response<Body> {
    Response::builder()
    .header("Content-Type", "text/plain")
    .body(crate_version!().into())
    .unwrap()
}

