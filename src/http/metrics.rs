//! Handling of the metrics endpoint.

use std::{cmp, fmt};
use std::fmt::Write;
use chrono::Utc;
use hyper::{Body, Method, Request};
use crate::config::FilterPolicy;
use crate::metrics::{
    HttpServerMetrics, Metrics, PayloadMetrics, PublicationMetrics,
    RrdpRepositoryMetrics, RsyncModuleMetrics, SharedRtrServerMetrics,
    VrpMetrics
};
use crate::payload::SharedHistory;
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
        "/metrics" => Some(handle_metrics(head, history, http, rtr).await),
        _ => None
    }
}


//------------ handle_metrics ------------------------------------------------

async fn handle_metrics(
    head: bool,
    history: &SharedHistory,
    http: &HttpServerMetrics,
    rtr: &SharedRtrServerMetrics,
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
        return ResponseBuilder::ok()
            .content_type(ContentType::PROMETHEUS)
            .empty()
    }

    let mut target = Target::default();

    // Update times.
    let now = Utc::now();
    target.single(
        Metric::new(
            "last_update_start",
            "seconds since the start of the last update",
            MetricType::Gauge,
        ),
        now.signed_duration_since(start).num_seconds()   
    );

    let metric = Metric::new(
        "last_update_duration",
        "duration of the last update in seconds",
        MetricType::Gauge,
    );
    match duration {
        Some(duration) => target.single(metric, duration.as_secs()),
        None => target.single(metric, "NaN")
    }

    let metric = Metric::new(
        "last_update_done",
        "seconds since the end of the last update",
        MetricType::Gauge,
    );
    match done {
        Some(instant) => {
            target.single(
                metric, 
                now.signed_duration_since(instant).num_seconds()
            )
        }
        None => target.single(metric, "NaN")
    }

    // Serial number.
    target.single(
        Metric::new(
            "serial", "current RTR serial number", MetricType::Gauge
        ),
        serial
    );

    // Per-TA metrics.
    pub_point_metrics(
        &mut target, Group::Ta,
        metrics.tals.iter().map(|m| (m.tal.name(), &m.publication))
    );
    object_metrics(
        &mut target, Group::Ta,
        metrics.tals.iter().map(|m| (m.tal.name(), &m.publication))
    );
    vrp_metrics(
        &mut target, Group::Ta, unsafe_vrps,
        metrics.tals.iter().map(|m| (m.tal.name(), m.payload.vrps()))
    );
    payload_metrics(
        &mut target, Group::Ta, unsafe_vrps,
        metrics.tals.iter().map(|m| (m.tal.name(), &m.payload))
    );

    // Per-repository metrics.
    pub_point_metrics(
        &mut target, Group::Repository,
        metrics.repositories.iter().map(|m| (m.uri.as_ref(), &m.publication))
    );
    object_metrics(
        &mut target, Group::Repository,
        metrics.repositories.iter().map(|m| (m.uri.as_ref(), &m.publication))
    );
    vrp_metrics(
        &mut target, Group::Repository, unsafe_vrps,
        metrics.repositories.iter().map(|m| (m.uri.as_ref(), m.payload.vrps()))
    );
    payload_metrics(
        &mut target, Group::Repository, unsafe_vrps,
        metrics.repositories.iter().map(|m| (m.uri.as_ref(), &m.payload))
    );

    // Locally added VRPs
    target.single(
        Metric::new(
            "vrps_added_locally",
            "VRPs added from local exceptions",
            MetricType::Gauge
        ),
        metrics.local.vrps().contributed
    );

    // Collector metrics.
    rrdp_metrics(&mut target, &metrics.rrdp);
    rsync_metrics(&mut target, &metrics.rsync);

    // Server metrics.
    rtr_metrics(&mut target, rtr).await;
    http_metrics(&mut target, http);

    //  Deprecated metrics.
    deprecated_metrics(&mut target, &metrics, unsafe_vrps);

    target.into_response()
}

fn pub_point_metrics<'a>(
    target: &mut Target, group: Group,
    metrics: impl Iterator<Item = (&'a str, &'a PublicationMetrics)>
) {
    let metric = Metric::with_prefix(
        group.prefix(), "publication_points_total",
        ("publication points per ", group.help()),
        MetricType::Gauge
    );
    target.header(metric);
    for (name, metrics) in metrics {
        target.multi(metric).label(group.label(), name)
            .label("state", "valid")
            .value(metrics.valid_points);
        target.multi(metric).label(group.label(), name)
            .label("state", "rejected")
            .value(metrics.rejected_points);
    }
}

fn object_metrics<'a>(
    target: &mut Target, group: Group,
    metrics: impl Iterator<Item = (&'a str, &'a PublicationMetrics)>
) {
    let metric = Metric::with_prefix(
        group.prefix(), "objects_total",
        ("VRPs per ", group.help()),
        MetricType::Gauge
    );
    target.header(metric);
    for (name, metrics) in metrics {
        target.multi(metric).label(group.label(), name)
            .label("type", "manifest")
            .label("state", "valid")
            .value(metrics.valid_manifests);
        target.multi(metric).label(group.label(), name)
            .label("type", "manifest")
            .label("state", "invalid")
            .value(metrics.invalid_manifests);
        target.multi(metric).label(group.label(), name)
            .label("type", "manifest")
            .label("state", "premature")
            .value(metrics.premature_manifests);
        target.multi(metric).label(group.label(), name)
            .label("type", "manifest")
            .label("state", "stale")
            .value(metrics.stale_manifests);
        target.multi(metric).label(group.label(), name)
            .label("type", "manifest")
            .label("state", "missing")
            .value(metrics.missing_manifests);

        target.multi(metric).label(group.label(), name)
            .label("type", "crl")
            .label("state", "valid")
            .value(metrics.valid_crls);
        target.multi(metric).label(group.label(), name)
            .label("type", "crl")
            .label("state", "invalid")
            .value(metrics.invalid_crls);
        target.multi(metric).label(group.label(), name)
            .label("type", "crl")
            .label("state", "stale")
            .value(metrics.stale_crls);
        target.multi(metric).label(group.label(), name)
            .label("type", "crl")
            .label("state", "stray")
            .value(metrics.stray_crls);

        target.multi(metric).label(group.label(), name)
            .label("type", "ca_cert")
            .label("state", "valid")
            .value(metrics.valid_ca_certs);
        target.multi(metric).label(group.label(), name)
            .label("type", "router_cert")
            .label("state", "valid")
            .value(metrics.valid_router_certs);
        target.multi(metric).label(group.label(), name)
            .label("type", "cert")
            .label("state", "invalid")
            .value(metrics.invalid_certs);

        target.multi(metric).label(group.label(), name)
            .label("type", "roa")
            .label("state", "valid")
            .value(metrics.valid_roas);
        target.multi(metric).label(group.label(), name)
            .label("type", "roa")
            .label("state", "invalid")
            .value(metrics.invalid_roas);

        #[cfg(feature = "aspa")] {
            target.multi(metric).label(group.label(), name)
                .label("type", "aspa")
                .label("state", "valid")
                .value(metrics.valid_aspas);
            target.multi(metric).label(group.label(), name)
                .label("type", "aspa")
                .label("state", "invalid")
                .value(metrics.invalid_aspas);
        }

        target.multi(metric).label(group.label(), name)
            .label("type", "gbr")
            .label("state", "valid")
            .value(metrics.valid_gbrs);
        target.multi(metric).label(group.label(), name)
            .label("type", "gbr")
            .label("state", "invalid")
            .value(metrics.invalid_gbrs);

        target.multi(metric).label(group.label(), name)
            .label("type", "other")
            .label("state", "invalid")
            .value(metrics.others);
    }
}

fn vrp_metrics<'a>(
    target: &mut Target, group: Group, unsafe_vrps: FilterPolicy,
    metrics: impl Iterator<Item = (&'a str, &'a VrpMetrics)>
) {
    let valid_metric = Metric::with_prefix(
        group.prefix(), "valid_vrps_total",
        ("overall number of VRPs per ", group.help()),
        MetricType::Gauge
    );
    let unsafe_metric = Metric::with_prefix(
        group.prefix(), "unsafe_vrps_total",
        (
            "number of VRPs overlapping with rejected publication points per ",
            group.help()
        ),
        MetricType::Gauge
    );
    let filtered_metric = Metric::with_prefix(
        group.prefix(), "locally_filtered_vrps_total",
        ("number of VRPs filtered out by local exceptions per ", group.help()),
        MetricType::Gauge
    );
    let duplicate_metric = Metric::with_prefix(
        group.prefix(), "duplicate_vrps_total",
        ("number of duplicate VRPs per ", group.help()),
        MetricType::Gauge
    );
    let contributed_metric = Metric::with_prefix(
        group.prefix(), "contributed_vrps_total",
        ("number of VRPs contributed to the final set per ", group.help()),
        MetricType::Gauge
    );

    target.header(valid_metric);
    if unsafe_vrps.log() {
        target.header(unsafe_metric);
    }
    target.header(filtered_metric);
    target.header(duplicate_metric);
    target.header(contributed_metric);
    for (name, metrics) in metrics {
        target.multi(valid_metric).label(group.label(), name)
            .value(metrics.valid);
        if unsafe_vrps.log() {
            target.multi(unsafe_metric).label(group.label(), name)
                .value(metrics.marked_unsafe);
        }
        target.multi(filtered_metric).label(group.label(), name)
            .value(metrics.locally_filtered);
        target.multi(duplicate_metric).label(group.label(), name)
            .value(metrics.duplicate);
        target.multi(contributed_metric).label(group.label(), name)
            .value(metrics.contributed);
    }
}

fn payload_metrics<'a>(
    target: &mut Target, group: Group, unsafe_vrps: FilterPolicy,
    metrics: impl Iterator<Item = (&'a str, &'a PayloadMetrics)>
) {
    let valid_metric = Metric::with_prefix(
        group.prefix(), "valid_payload_total",
        ("overall number of payload elements per ", group.help()),
        MetricType::Gauge
    );
    let unsafe_metric = Metric::with_prefix(
        group.prefix(), "unsafe_payload_total",
        (
            "payload items overlapping with rejected publication points per ",
            group.help()
        ),
        MetricType::Gauge
    );
    let filtered_metric = Metric::with_prefix(
        group.prefix(), "locally_filtered_payload_total",
        (
            "number of payload items filtered out by local exceptions per ",
            group.help()
        ),
        MetricType::Gauge
    );
    let duplicate_metric = Metric::with_prefix(
        group.prefix(), "duplicate_payload_total",
        ("number of duplicate payload items per ", group.help()),
        MetricType::Gauge
    );
    let contributed_metric = Metric::with_prefix(
        group.prefix(), "contributed_payload_total",
        (
            "number of payload items contributed to the final set per ",
            group.help()
        ),
        MetricType::Gauge
    );

    target.header(valid_metric);
    if unsafe_vrps.log() {
        target.header(unsafe_metric);
    }
    target.header(filtered_metric);
    target.header(duplicate_metric);
    target.header(contributed_metric);

    for (name, metrics) in metrics {
        let types = [
            ("route_origins_ipv4", &metrics.v4_origins),
            ("route_origins_ipv6", &metrics.v6_origins),
            ("router_keys", &metrics.router_keys),
        ];

        for (type_name, metrics) in &types {
            target.multi(valid_metric)
                .label(group.label(), name)
                .label("type", type_name)
                .value(metrics.valid);
            if unsafe_vrps.log() {
                target.multi(unsafe_metric)
                    .label(group.label(), name)
                    .label("type", type_name)
                    .value(metrics.marked_unsafe);
            }
            target.multi(filtered_metric)
                .label(group.label(), name)
                .label("type", type_name)
                .value(metrics.locally_filtered);
            target.multi(duplicate_metric)
                .label(group.label(), name)
                .label("type", type_name)
                .value(metrics.duplicate);
            target.multi(contributed_metric)
                .label(group.label(), name)
                .label("type", type_name)
                .value(metrics.contributed);
        }

        #[cfg(feature = "aspa")] {
            target.multi(valid_metric)
                .label(group.label(), name)
                .label("type", "aspas")
                .value(metrics.aspas.valid);
            target.multi(duplicate_metric)
                .label(group.label(), name)
                .label("type", "aspas")
                .value(metrics.aspas.duplicate);
            target.multi(contributed_metric)
                .label(group.label(), name)
                .label("type", "aspas")
                .value(metrics.aspas.contributed);
        }
    }
}

fn rrdp_metrics(target: &mut Target, metrics: &[RrdpRepositoryMetrics]) {
    let status = Metric::new(
        "rrdp_status",
        "combined status code for RRDP update requests",
        MetricType::Gauge
    );
    target.header(status);
    let notify_status = Metric::new(
        "rrdp_notification_status",
        "status code for getting the RRDP notification file",
        MetricType::Gauge
    );
    target.header(notify_status);
    let payload_status = Metric::new(
        "rrdp_payload_status",
        "status code for getting RRDP payload files",
        MetricType::Gauge
    );
    target.header(payload_status);
    let duration = Metric::new(
        "rrdp_duration",
        "duration of RRDP update in seconds",
        MetricType::Gauge
    );
    target.header(duration);
    let serial = Metric::new(
        "rrdp_serial_info",
        "serial number of the last RRDP update",
        MetricType::Gauge
    );
    target.header(serial);

    for rrdp in metrics {
        target.multi(status).label("uri", &rrdp.notify_uri).value(
            rrdp.status().into_i16()
        );
        target.multi(notify_status).label("uri", &rrdp.notify_uri).value(
            rrdp.notify_status.into_i16()
        );
        target.multi(payload_status).label("uri", &rrdp.notify_uri).value(
            rrdp.payload_status.map(|status| status.into_i16()).unwrap_or(0)
        );
        if let Ok(value) = rrdp.duration {
            target.multi(duration).label("uri", &rrdp.notify_uri).value(
                format_args!(
                    "{}.{:03}",
                    value.as_secs(),
                    value.subsec_millis(),
                )
            )
        }
        if let Some(value) = rrdp.serial {
            target.multi(serial).label("uri", &rrdp.notify_uri).value(value)
        }
    }
}

fn rsync_metrics(target: &mut Target, metrics: &[RsyncModuleMetrics]) {
    let status = Metric::new(
        "rsync_status", "exit status of the rsync command", MetricType::Gauge
    );
    target.header(status);
    let duration = Metric::new(
        "rsync_duration",
        "duration of the rsync command in seconds",
        MetricType::Gauge
    );
    target.header(duration);

    for rsync in metrics {
        target.multi(status).label("uri", &rsync.module).value(
            match rsync.status {
                Ok(status) => status.code().unwrap_or(-1),
                Err(_) => -1
            }
        );
        if let Ok(value) = rsync.duration {
            target.multi(duration).label("uri", &rsync.module).value(
                format_args!(
                    "{}.{:03}",
                    value.as_secs(),
                    value.subsec_millis(),
                )
            );
        }
    }
}

async fn rtr_metrics(target: &mut Target, metrics: &SharedRtrServerMetrics) {
    let detailed = metrics.detailed();
    let metrics = metrics.read().await;

    target.single(
        Metric::new(
            "rtr_current_connections",
            "number of currently open RTR connections",
            MetricType::Gauge
        ),
        metrics.current_connections()
    );
    target.single(
        Metric::new(
            "rtr_bytes_read",
            "total number of bytes read from RTR connections",
            MetricType::Counter
        ),
        metrics.bytes_read()
    );
    target.single(
        Metric::new(
            "rtr_bytes_written",
            "total number of bytes written to RTR connections",
            MetricType::Counter
        ),
        metrics.bytes_written()
    );

    if detailed {
        let item = Metric::new(
            "rtr_client_connections",
            "number of currently open connections per client address",
            MetricType::Gauge
        );
        target.header(item);
        metrics.fold_clients(0, |count, client| {
            if client.is_open() {
                *count += 1
            }
        }).for_each(|(addr, count)| {
            target.multi(item).label("addr", addr).value(count)
        });

        let item = Metric::new(
            "rtr_client_serial",
            "last serial seen by a client address",
            MetricType::Gauge
        );
        target.header(item);
        metrics.fold_clients(None, |serial, client| {
            *serial = match (*serial, client.serial().map(u32::from)) {
                (Some(left), Some(right)) => Some(cmp::max(left, right)),
                (Some(left), None) => Some(left),
                (None, Some(right)) => Some(right),
                (None, None) => None
            };
        }).for_each(|(addr, count)| {
            match count {
                Some(count) => {
                    target.multi(item).label("addr", addr).value(count);
                }
                None => {
                    target.multi(item).label("addr", addr).value(-1);
                }
            }
        });

        let item = Metric::new(
            "rtr_client_last_update_seconds",
            "seconds since last update by a client address",
            MetricType::Gauge
        );
        target.header(item);
        metrics.fold_clients(None, |update, client| {
            *update = match (*update, client.updated()) {
                (Some(left), Some(right)) => Some(cmp::max(left, right)),
                (Some(left), None) => Some(left),
                (None, Some(right)) => Some(right),
                (None, None) => None
            };
        }).for_each(|(addr, update)| {
            match update {
                Some(update) => {
                    let duration = Utc::now() - update;
                    target.multi(item).label("addr", addr).value(
                        format_args!(
                            "{}.{:03}",
                            duration.num_seconds(),
                            duration.num_milliseconds() % 1000,
                        )
                    );
                }
                None => {
                    target.multi(item).label("addr", addr).value(-1)
                }
            }
        });

        let item = Metric::new(
            "rtr_client_last_reset_seconds",
            "seconds since last cache reset by a client address",
            MetricType::Gauge
        );
        target.header(item);
        metrics.fold_clients(None, |update, client| {
            *update = match (*update, client.last_reset()) {
                (Some(left), Some(right)) => Some(cmp::max(left, right)),
                (Some(left), None) => Some(left),
                (None, Some(right)) => Some(right),
                (None, None) => None
            };
        }).for_each(|(addr, update)| {
            match update {
                Some(update) => {
                    let duration = Utc::now() - update;
                    target.multi(item).label("addr", addr).value(
                        format_args!(
                            "{}.{:03}",
                            duration.num_seconds(),
                            duration.num_milliseconds() % 1000,
                        )
                    );
                }
                None => {
                    target.multi(item).label("addr", addr).value(-1)
                }
            }
        });

        let item = Metric::new(
            "rtr_client_reset_queries",
            "number of of reset queries by a client address",
            MetricType::Counter,
        );
        target.header(item);
        metrics.fold_clients(0, |count, client| {
            *count += client.reset_queries();
        }).for_each(|(addr, count)| {
            target.multi(item).label("addr", addr).value(count)
        });

        let item = Metric::new(
            "rtr_client_serial_queries",
            "number of of serial queries by a client address",
            MetricType::Counter,
        );
        target.header(item);
        metrics.fold_clients(0, |count, client| {
            *count += client.serial_queries();
        }).for_each(|(addr, count)| {
            target.multi(item).label("addr", addr).value(count)
        });

        let item = Metric::new(
            "rtr_client_reset_queries",
            "number of of reset queries by a client address",
            MetricType::Counter,
        );
        target.header(item);
        metrics.fold_clients(0, |count, client| {
            *count += client.reset_queries();
        }).for_each(|(addr, count)| {
            target.multi(item).label("addr", addr).value(count)
        });

        let item = Metric::new(
            "rtr_client_read_bytes",
            "number of bytes read from a client address",
            MetricType::Counter,
        );
        target.header(item);
        metrics.fold_clients(0, |count, client| {
            *count += client.bytes_read();
        }).for_each(|(addr, count)| {
            target.multi(item).label("addr", addr).value(count)
        });

        let item = Metric::new(
            "rtr_client_written_bytes",
            "number of bytes written to a client address",
            MetricType::Counter
        );
        target.header(item);
        metrics.fold_clients(0, |count, client| {
            *count += client.bytes_written();
        }).for_each(|(addr, count)| {
            target.multi(item).label("addr", addr).value(count)
        });
    }
}

fn http_metrics(target: &mut Target, metrics: &HttpServerMetrics) {
    target.single(
        Metric::new(
            "http_connections",
            "total number of HTTP connections opened",
            MetricType::Counter
        ),
        metrics.conn_open()
    );
    target.single(
        Metric::new(
            "http_current_connections",
            "number of currently open HTTP connections",
            MetricType::Gauge
        ),
        metrics.conn_open() - metrics.conn_close()
    );
    target.single(
        Metric::new(
            "http_bytes_read",
            "number of bytes read from HTTP connections",
            MetricType::Counter
        ),
        metrics.bytes_read()
    );
    target.single(
        Metric::new(
            "http_bytes_written",
            "number of bytes written to HTTP connections",
            MetricType::Counter
        ),
        metrics.bytes_written()
    );
    target.single(
        Metric::new(
            "http_requests",
            "number of HTTP requests received",
            MetricType::Counter
        ),
        metrics.requests()
    );
}

fn deprecated_metrics(
    target: &mut Target, metrics: &Metrics, unsafe_vrps: FilterPolicy,
) {
    // Old-style per-TAL metrics.
    let valid_roas = Metric::new(
        "valid_roas", "number of valid ROAs seen", MetricType::Gauge
    );
    target.header(valid_roas);
    let total_vrps = Metric::new(
        "total_vrps", "number of valid VRPs per TAL", MetricType::Gauge
    );
    target.header(total_vrps);
    let vrps_unsafe = Metric::new(
        "vrps_unsafe",
        "VRPs overlapping with rejected publication points",
        MetricType::Gauge
    );
    target.header(vrps_unsafe);
    let vrps_filtered = Metric::new(
        "vrps_filtered_locally",
        "VRPs filtered based on local exceptions",
        MetricType::Gauge
    );
    target.header(vrps_filtered);
    let vrps_duplicate = Metric::new(
        "vrps_duplicate",
        "number of duplicate VRPs per TAL",
        MetricType::Gauge
    );
    target.header(vrps_duplicate);
    for tal in &metrics.tals {
        let name = tal.tal.name();
        let vrps = tal.payload.vrps();
        target.multi(valid_roas).label("tal", name).value(
            tal.publication.valid_roas
        );
        target.multi(total_vrps).label("tal", name).value(
            vrps.valid
        );
        if unsafe_vrps.log() {
            target.multi(vrps_unsafe).label("tal", name).value(
                vrps.marked_unsafe
            );
        }
        target.multi(vrps_filtered).label("tal", name).value(
            vrps.locally_filtered
        );
        target.multi(vrps_duplicate).label("tal", name).value(
            vrps.duplicate
        );
    }

    target.single(
        Metric::new(
            "vrps_final", "final number of VRPs", MetricType::Gauge
        ),
        metrics.payload.vrps().contributed
    );

    // Overall number of stale objects
    target.single(
        Metric::new(
            "stale_objects",
            "total number of stale manifests and CRLs",
            MetricType::Gauge
        ),
        metrics.publication.stale_objects()
    );
}


//------------ Target --------------------------------------------------------

#[derive(Clone, Debug, Default)]
struct Target {
    buf: String,
}

impl Target {
    pub fn into_response(self) -> Response {
        ResponseBuilder::ok().content_type(ContentType::PROMETHEUS)
        .body(self.buf)
    }

    pub fn single(&mut self, metric: Metric, value: impl fmt::Display) {
        metric.header(self);
        metric.single(self, value);
    }

    pub fn header(&mut self, metric: Metric) {
        metric.header(self)
    }
    
    pub fn multi(&mut self, metric: Metric) -> LabelValue {
        metric.multi(self)
    }
}


//------------ Metric --------------------------------------------------------

#[derive(Clone, Copy, Debug)]
struct Metric {
    prefix: &'static str,
    name: &'static str,
    help: (&'static str, &'static str),
    mtype: MetricType,
}

impl Metric {
    pub fn new(
        name: &'static str, help: &'static str, mtype: MetricType
    ) -> Self {
        Metric {
            prefix: "",
            name,
            help: (help, ""),
            mtype
        }
    }

    pub fn with_prefix(
        prefix: &'static str,
        name: &'static str,
        help: (&'static str, &'static str),
        mtype: MetricType
    ) -> Self {
        Metric {
            prefix, name, help, mtype
        }
    }

    pub fn header(self, target: &mut Target) {
        writeln!(&mut target.buf,
            "# HELP routinator{}_{} {}{}\n\
             # TYPE routinator{}_{} {}",
            self.prefix, self.name, self.help.0, self.help.1,
            self.prefix, self.name, self.mtype,
        ).expect("writing to string");
    }

    fn single(self, target: &mut Target, value: impl fmt::Display) {
        writeln!(&mut target.buf,
            "routinator{}_{} {}",
            self.prefix, self.name, value
        ).expect("writing to string");
    }

    fn multi(self, target: &mut Target) -> LabelValue {
        LabelValue::new(self, target)
    }
}


//------------ LabelValue ----------------------------------------------------

struct LabelValue<'a> {
    target: &'a mut Target,
    first: bool,
}

impl<'a> LabelValue<'a> {
    fn new(metric: Metric, target: &'a mut Target) -> Self {
        write!(
            &mut target.buf, "routinator{}_{}{{", metric.prefix, metric.name
        ).expect("writing to string");
        LabelValue { target, first: true }
    }

    pub fn label(mut self, name: &str, value: impl fmt::Display) -> Self {
        if self.first {
            self.first = false;
        }
        else {
            self.target.buf.push_str(", ");
        }
        write!(
            &mut self.target.buf, "{}=\"{}\"", name, value
        ).expect("writing to string");
        self
    }

    pub fn value(self, value: impl fmt::Display) {
        writeln!(
            &mut self.target.buf, "}} {}", value
        ).expect("writing to string");
    }
}


//------------ MetricType ----------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum MetricType {
    Counter,
    Gauge,
    /* Not currently used:
    Histogram,
    Summary,
    */
}

impl fmt::Display for MetricType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(
            match *self {
                MetricType::Counter => "counter",
                MetricType::Gauge => "gauge",
                /*
                MetricType::Histogram => "histogram",
                MetricType::Summary => "summary",
                */
            }
        )
    }
}


//------------ Group ---------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum Group {
    Repository,
    Ta,
}

impl Group {
    pub fn prefix(self) -> &'static str {
        match self {
            Group::Repository => "_repository",
            Group::Ta => "_ta",
        }
    }

    pub fn help(self) -> &'static str {
        match self {
            Group::Repository => "repository",
            Group::Ta => "trust anchor",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Group::Repository => "uri",
            Group::Ta => "name",
        }
    }
}

