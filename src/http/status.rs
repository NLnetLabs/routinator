//! Handling of endpoints related to the status.

use std::{cmp, fmt};
use std::fmt::Write;
use chrono::{Duration, Utc};
use clap::{crate_name, crate_version};
use hyper::{Body, Request, Response};
use crate::metrics::{
    HttpServerMetrics, PublicationMetrics, SharedRtrServerMetrics, VrpMetrics
};
use crate::payload::SharedHistory;
use crate::utils::JsonBuilder;
use super::errors::initial_validation;


//------------ handle_get ----------------------------------------------------

pub async fn handle_get(
    req: &Request<Body>,
    history: &SharedHistory,
    http: &HttpServerMetrics,
    rtr: &SharedRtrServerMetrics,
) -> Option<Response<Body>> {
    match req.uri().path() {
        "/metrics" => Some(handle_metrics(history, http, rtr).await),
        "/status" => Some(handle_status(history, http, rtr).await),
        "/api/v1/status" => Some(handle_api_status(history, http, rtr).await),
        "/version" => Some(handle_version()),
        _ => None
    }
}


//------------ handle_metrics ------------------------------------------------

async fn handle_metrics(
    history: &SharedHistory,
    server_metrics: &HttpServerMetrics,
    rtr_metrics: &SharedRtrServerMetrics,
) -> Response<Body> {
    use PrometheusType::*;

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

    let mut res = PrometheusMetrics::new();

    // Per-TAL metrics.
    //
    // For historical reasons, they don’t include a "_tal_" portion in the
    // name.
    res.publication_headers("per TAL");
    res.vrp_headers("per TAL");
    for tal in &metrics.tals {
        res.publication_values("tal", &tal.name(), &tal.publication);
        res.vrp_values("tal", &tal.name(), &tal.vrps);
    }

    const VRPS_ADDED_LOCALLY: &str = "vrps_added_locally";
    res.header(
        VRPS_ADDED_LOCALLY, Gauge,
        "VRPs added from local exceptions"
    );
    res.single(VRPS_ADDED_LOCALLY, metrics.local.contributed);

    const STALE_OBJECTS: &str = "stale_objects";
    res.header(
        STALE_OBJECTS, Gauge,
        "total number of stale manifests and CRLs"
    );
    res.single(STALE_OBJECTS, metrics.publication.stale_objects());

    // Per-repository metrics.
    res.set_prefix("routinator_repo");
    res.publication_headers("per repository");
    res.vrp_headers("per repository");
    for repo in &metrics.repositories {
        res.publication_values("uri", &repo.uri, &repo.publication);
        res.vrp_values("uri", &repo.uri, &repo.vrps);
    }
    res.set_prefix("routinator");

    // Update times.
    //
    let now = Utc::now();
    const LAST_UPDATE_START: &str = "last_update_start";
    res.header(
        LAST_UPDATE_START, Gauge,
        "seconds since last update started"
    );
    res.single(
        LAST_UPDATE_START,
        now.signed_duration_since(start).num_seconds()
    );

    const LAST_UPDATE_DURATION: &str = "last_update_duration";
    res.header(
        LAST_UPDATE_DURATION, Gauge,
        "duration of last update in seconds"
    );
    res.single(
        LAST_UPDATE_DURATION, 
        duration.map(|duration| { duration.as_secs() }).unwrap_or(0)
    );

    const LAST_UPDATE_DONE: &str = "last_update_done";
    res.header(
        LAST_UPDATE_DONE, Gauge,
        "seconds since last update finished",
    );
    match done {
        Some(instant) => {
            res.single(
                LAST_UPDATE_DONE,
                now.signed_duration_since(instant).num_seconds()
            );
        }
        None => {
            res.single(
                LAST_UPDATE_DONE, "NaN"
            );
        }
    }

    // Serial number.
    const SERIAL: &str = "serial";
    res.header(
        SERIAL, Gauge,
        "current RTR serial number"
    );
    res.single(SERIAL, serial);


    // RRDP collector metrics.
    //
    const RRDP_STATUS: &str = "rrdp_status";
    const RRDP_NOTIFICATION_STATUS: &str = "rrdp_notification_status";
    const RRDP_PAYLOAD_STATUS: &str = "rrdp_payload_status";
    const RRDP_DURATION: &str = "rrdp_duration";
    const RRDP_SERIAL: &str = "rrdp_serial";
    res.header(
        RRDP_STATUS, Gauge,
        "combined status code for RRDP update requests"
    );
    res.header(
        RRDP_NOTIFICATION_STATUS, Gauge,
        "status code for getting RRDP notification file"
    );
    res.header(
        RRDP_PAYLOAD_STATUS, Gauge,
        "status code for getting RRDP payload file(s)"
    );
    res.header(
        RRDP_DURATION, Gauge,
        "duration of RRDP update in seconds"
    );
    res.header(
        RRDP_SERIAL, Gauge,
        "serial number of last RRDP update"
    );
    for rrdp in &metrics.rrdp {
        res.multi(
            RRDP_STATUS, "uri", &rrdp.notify_uri, rrdp.status().into_i16()
        );
        res.multi(
            RRDP_NOTIFICATION_STATUS, "uri", &rrdp.notify_uri,
            rrdp.notify_status.into_i16()
        );
        res.multi(
            RRDP_PAYLOAD_STATUS, "uri", &rrdp.notify_uri,
            rrdp.payload_status.map(|status| {
                status.into_i16()
            }).unwrap_or(0),
        );
        if let Ok(duration) = rrdp.duration {
            res.multi(
                RRDP_DURATION, "uri", &rrdp.notify_uri,
                format_args!(
                    "{}.{:03}",
                    duration.as_secs(),
                    duration.subsec_millis(),
                )
            );
        }
        if let Some(serial) = rrdp.serial {
            res.multi(
                RRDP_SERIAL, "uri", &rrdp.notify_uri, serial
            );
        }
    }

    // Rsync collector metrics
    //
    const RSYNC_STATUS: &str = "rsync_status";
    const RSYNC_DURATION: &str = "rsync_duration";
    res.header(
        RSYNC_STATUS, Gauge,
        "exit status of rsync command"
    );
    res.header(
        RSYNC_DURATION, Gauge,
        "duration of rsync command in seconds"
    );
    for rsync in &metrics.rsync {
        res.multi(
            RSYNC_STATUS, "uri", &rsync.module, 
            match rsync.status {
                Ok(status) => status.code().unwrap_or(-1),
                Err(_) => -1
            }
        );
        if let Ok(duration) = rsync.duration {
            res.multi(
                RSYNC_DURATION, "uri", &rsync.module, 
                format_args!(
                    "{}.{:03}",
                    duration.as_secs(),
                    duration.subsec_millis(),
                )
            );
        }
    }

    // RTR server metrics.
    //
    let detailed_rtr = rtr_metrics.detailed();
    let rtr_metrics = rtr_metrics.read().await;

    const RTR_CURRENT_CONNECTIONS: &str = "rtr_current_connections";
    res.header(
        RTR_CURRENT_CONNECTIONS, Gauge,
        "number of currently open RTR connections"
    );
    res.single(
        RTR_CURRENT_CONNECTIONS, 
        rtr_metrics.current_connections()
    );

    const RTR_BYTES_READ: &str = "rtr_bytes_read";
    res.header(
        RTR_BYTES_READ, Counter,
        "total number of bytes read from RTR connections"
    );
    res.single(RTR_BYTES_READ, rtr_metrics.bytes_read());

    const RTR_BYTES_WRITTEN: &str = "rtr_bytes_written";
    res.header(
        RTR_BYTES_WRITTEN, Counter,
        "total number of bytes written to RTR connections"
    );
    res.single(RTR_BYTES_WRITTEN, rtr_metrics.bytes_written());

    if detailed_rtr {
        const RTR_CLIENT_CONNECTIONS: &str = "rtr_client_connections";
        res.header(
            RTR_CLIENT_CONNECTIONS, Gauge,
            "number of current connections per client address"
        );
        rtr_metrics.fold_clients(0, |count, client| {
            if client.is_open() {
                *count += 1
            }
        }).for_each(|(addr, count)| {
            res.multi(
                RTR_CLIENT_CONNECTIONS, "addr", addr, count
            );
        });

        const RTR_CLIENT_SERIAL: &str = "rtr_client_serial";
        res.header(
            RTR_CLIENT_SERIAL, Gauge,
            "last serial seen by client address"
        );
        rtr_metrics.fold_clients(None, |serial, client| {
            *serial = match (*serial, client.serial().map(u32::from)) {
                (Some(left), Some(right)) => Some(cmp::max(left, right)),
                (Some(left), None) => Some(left),
                (None, Some(right)) => Some(right),
                (None, None) => None
            };
        }).for_each(|(addr, count)| {
            match count {
                Some(count) => {
                    res.multi(RTR_CLIENT_SERIAL, "addr", addr, count);
                }
                None => {
                    res.multi(RTR_CLIENT_SERIAL, "addr", addr, -1);
                }
            }
        });

        const RTR_CLIENT_LAST_UPDATE: &str = "rtr_client_last_update_seconds";
        res.header(
            RTR_CLIENT_LAST_UPDATE, Gauge,
            "seconds since last update by client address",
        );
        rtr_metrics.fold_clients(None, |update, client| {
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
                    res.multi(
                        RTR_CLIENT_LAST_UPDATE,
                        "addr", addr,
                        format_args!(
                            "{}.{:03}",
                            duration.num_seconds(),
                            duration.num_milliseconds() % 1000,
                        )
                    );
                }
                None => {
                    res.multi(
                        RTR_CLIENT_LAST_UPDATE,
                        "addr", addr,
                        -1
                    )
                }
            }
        });

        const RTR_CLIENT_READ: &str = "rtr_client_read_bytes";
        res.header(
            RTR_CLIENT_READ, Counter,
            "number of bytes read from a client address"
        );
        rtr_metrics.fold_clients(0, |count, client| {
            *count += client.bytes_read();
        }).for_each(|(addr, count)| {
            res.multi(
                RTR_CLIENT_READ, "addr", addr, count
            );
        });

        const RTR_CLIENT_WRITTEN: &str = "rtr_client_written_bytes";
        res.header(
            RTR_CLIENT_WRITTEN, Counter,
            "number of bytes written to a client address"
        );
        rtr_metrics.fold_clients(0, |count, client| {
            *count += client.bytes_written();
        }).for_each(|(addr, count)| {
            res.multi(
                RTR_CLIENT_WRITTEN, "addr", addr, count
            );
        });

    }

    // HTTP server metrics.
    //
    const HTTP_CONNECTIONS: &str = "http_connections";
    res.header(
        HTTP_CONNECTIONS, Counter,
        "total number of HTTP connections opened"
    );
    res.single(HTTP_CONNECTIONS, server_metrics.conn_open());

    const HTTP_CURRENT_CONNECTIONS: &str = "http_current_connections";
    res.header(
        HTTP_CURRENT_CONNECTIONS, Gauge,
        "number of currently open HTTP connections"
    );
    res.single(
        HTTP_CURRENT_CONNECTIONS,
        server_metrics.conn_open() - server_metrics.conn_close()
    );

    const HTTP_BYTES_READ: &str = "http_bytes_read";
    res.header(
        HTTP_BYTES_READ, Counter,
        "number of bytes read from HTTP connections"
    );
    res.single("http_bytes_read", server_metrics.bytes_read());

    const HTTP_BYTES_WRITTEN: &str = "http_bytes_written";
    res.header(
        HTTP_BYTES_WRITTEN, Counter,
        "number of bytes written to HTTP connections"
    );
    res.single(HTTP_BYTES_WRITTEN, server_metrics.bytes_written());

    const HTTP_REQUESTS: &str = "http_requests";
    res.header(
        HTTP_REQUESTS, Counter,
        "number of received HTTP requests"
    );
    res.single(HTTP_REQUESTS, server_metrics.requests());

    res.into_response()
}


#[derive(Default)]
struct PrometheusMetrics {
    target: String,
    prefix: &'static str,
}

impl PrometheusMetrics {
    const VALID_POINTS: &'static str = "valid_points";
    const REJECTED_POINTS: &'static str = "rejected_points";
    const VALID_MANIFESTS: &'static str = "valid_manifests";
    const INVALID_MANIFESTS: &'static str = "invalid_manifests";
    const STALE_MANIFESTS: &'static str = "stale_manifests";
    const MISSING_MANIFESTS: &'static str = "missing_manifests";
    const VALID_CRLS: &'static str = "valid_crls";
    const INVALID_CRLS: &'static str = "invalid_crls";
    const STALE_CRLS: &'static str = "stale_crls";
    const STRAY_CRLS: &'static str = "stray_crls";
    const VALID_CA_CERTS: &'static str = "valid_ca_certs";
    const VALID_EE_CERTS: &'static str = "valid_ee_certs";
    const INVALID_CERTS: &'static str = "invalid_certs";
    const VALID_ROAS: &'static str = "valid_roas";
    const INVALID_ROAS: &'static str = "invalid_roas";
    const VALID_GBRS: &'static str = "valid_gbrs";
    const INVALID_GBRS: &'static str = "invalid_gbrs";
    const OTHER_OBJECTS: &'static str = "other_objects";

    fn publication_headers(&mut self, group: &str) {
        use PrometheusType::*;

        self.header(
            Self::VALID_POINTS, Gauge,
            format_args!("valid publication points {}", group)
        );
        self.header(
            Self::REJECTED_POINTS, Gauge,
            format_args!("rejected publication points {}", group)
        );
        self.header(
            Self::VALID_MANIFESTS, Gauge,
            format_args!("valid manifests {}", group)
        );
        self.header(
            Self::INVALID_MANIFESTS, Gauge,
            format_args!("invalid manifests {}", group)
        );
        self.header(
            Self::STALE_MANIFESTS, Gauge,
            format_args!("stale manifests {}", group)
        );
        self.header(
            Self::MISSING_MANIFESTS, Gauge,
            format_args!("missing manifests {}", group)
        );
        self.header(
            Self::VALID_CRLS, Gauge,
            format_args!("valid CRLs {}", group)
        );
        self.header(
            Self::INVALID_CRLS, Gauge,
            format_args!("invalid CRLs {}", group)
        );
        self.header(
            Self::STALE_CRLS, Gauge,
            format_args!("stale CRLs {}", group)
        );
        self.header(
            Self::STRAY_CRLS, Gauge,
            format_args!("stray CRLs {}", group)
        );
        self.header(
            Self::VALID_CA_CERTS, Gauge,
            format_args!("valid CA certificates {}", group)
        );
        self.header(
            Self::VALID_EE_CERTS, Gauge,
            format_args!("valid router certificates {}", group)
        );
        self.header(
            Self::INVALID_CERTS, Gauge,
            format_args!("invalid certificate files {}", group)
        );
        self.header(
            Self::VALID_ROAS, Gauge,
            format_args!("valid ROAs {}", group)
        );
        self.header(
            Self::INVALID_ROAS, Gauge,
            format_args!("invalid ROAs {}", group)
        );
        self.header(
            Self::VALID_GBRS, Gauge,
            format_args!("valid GBRs {}", group)
        );
        self.header(
            Self::INVALID_GBRS, Gauge,
            format_args!("invalid GBRs {}", group)
        );
        self.header(
            Self::OTHER_OBJECTS, Gauge,
            format_args!("other objects {}", group)
        );
    }

    fn publication_values(
        &mut self, label_name: &str, label_value: &impl fmt::Display,
        publication: &PublicationMetrics
    ) {
        self.multi(
            Self::VALID_POINTS, label_name, label_value,
            publication.valid_points
        );
        self.multi(
            Self::REJECTED_POINTS, label_name, label_value,
            publication.rejected_points
        );
        self.multi(
            Self::VALID_MANIFESTS, label_name, label_value,
            publication.valid_manifests
        );
        self.multi(
            Self::INVALID_MANIFESTS, label_name, label_value,
            publication.invalid_manifests
        );
        self.multi(
            Self::STALE_MANIFESTS, label_name, label_value,
            publication.stale_manifests
        );
        self.multi(
            Self::MISSING_MANIFESTS, label_name, label_value,
            publication.missing_manifests
        );
        self.multi(
            Self::VALID_CRLS, label_name, label_value,
            publication.valid_crls
        );
        self.multi(
            Self::INVALID_CRLS, label_name, label_value,
            publication.invalid_crls
        );
        self.multi(
            Self::STALE_CRLS, label_name, label_value,
            publication.stale_crls
        );
        self.multi(
            Self::STRAY_CRLS, label_name, label_value,
            publication.stray_crls
        );
        self.multi(
            Self::VALID_CA_CERTS, label_name, label_value,
            publication.valid_ca_certs
        );
        self.multi(
            Self::VALID_EE_CERTS, label_name, label_value,
            publication.valid_ee_certs
        );
        self.multi(
            Self::INVALID_CERTS, label_name, label_value,
            publication.invalid_certs
        );
        self.multi(
            Self::VALID_ROAS, label_name, label_value,
            publication.valid_roas
        );
        self.multi(
            Self::INVALID_ROAS, label_name, label_value,
            publication.invalid_roas
        );
        self.multi(
            Self::VALID_GBRS, label_name, label_value,
            publication.valid_gbrs
        );
        self.multi(
            Self::INVALID_GBRS, label_name, label_value,
            publication.invalid_gbrs
        );
        self.multi(
            Self::OTHER_OBJECTS, label_name, label_value,
            publication.others
        );
    }

    const VRPS_TOTAL: &'static str = "vrps_total";
    const VRPS_UNSAFE: &'static str = "vrps_unsafe";
    const VRPS_FILTERED_LOCALLY: &'static str = "vrps_filtered_locally";
    const VRPS_DUPLICATE: &'static str = "vrps_duplicate";
    const VRPS_FINAL: &'static str = "vrps_final";

    fn vrp_headers(&mut self, group: &str) {
        use PrometheusType::*;

        self.header(
            Self::VRPS_TOTAL, Gauge,
            format_args!("total number of encountered valid VRPs {}", group)
        );
        self.header(
            Self::VRPS_UNSAFE, Gauge,
            format_args!(
                "VRPs overlapping with rejected publication points  {}",
                group
            )
        );
        self.header(
            Self::VRPS_FILTERED_LOCALLY, Gauge,
            format_args!("VRPs filtered out by local exceptions {}", group)
        );
        self.header(
            Self::VRPS_DUPLICATE, Gauge,
            format_args!("duplicate VRPs {}", group)
        );
        self.header(
            Self::VRPS_FINAL, Gauge,
            format_args!("VRPs contributed to the final set {}", group)
        );
    }

    fn vrp_values(
        &mut self, label_name: &str, label_value: &impl fmt::Display,
        vrps: &VrpMetrics
    ) {
        self.multi(
            Self::VRPS_TOTAL, label_name, label_value, vrps.valid
        );
        self.multi(
            Self::VRPS_UNSAFE, label_name, label_value, vrps.marked_unsafe
        );
        self.multi(
            Self::VRPS_FILTERED_LOCALLY, label_name, label_value,
            vrps.locally_filtered
        );
        self.multi(
            Self::VRPS_DUPLICATE, label_name, label_value, vrps.duplicate
        );
        self.multi(
            Self::VRPS_FINAL, label_name, label_value, vrps.contributed
        );
    }
}

impl PrometheusMetrics {
    fn new() -> Self {
        PrometheusMetrics {
            target: String::new(),
            prefix: "routinator"
        }
    }

    fn set_prefix(&mut self, prefix: &'static str) {
        self.prefix = prefix
    }

    fn into_response(self) -> Response<Body> {
        Response::builder()
        .header("Content-Type", "text/plain; version=0.0.4")
        .body(self.target.into())
        .expect("finalizing HTTP response")
    }

    fn header(
        &mut self,
        name: &str,
        ptype: PrometheusType,
        help: impl fmt::Display
    ) {
        writeln!(&mut self.target,
            "# HELP {}_{} {}\n# TYPE {}_{} {}",
            self.prefix, name, help, self.prefix, name, ptype
        ).expect("writing to string");
    }

    fn single(&mut self, name: &str, value: impl fmt::Display) {
        writeln!(&mut self.target,
            "{}_{} {}",
            self.prefix, name, value
        ).expect("writing to string");
    }

    fn multi(&mut self,
        name: &str,
        label_name: &str,
        label_value: impl fmt::Display,
        value: impl fmt::Display
    ) {
        writeln!(
            &mut self.target,
            "{}_{}{{{}=\"{}\"}} {}",
            self.prefix, name,
            label_name, label_value,
            value,
        ).expect("writing to string");
    }
}


//------------ PrometheusType ------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum PrometheusType {
    Counter,
    Gauge,
    /* Not currently used:
    Histogram,
    Summary,
    */
}

impl fmt::Display for PrometheusType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(
            match *self {
                PrometheusType::Counter => "counter",
                PrometheusType::Gauge => "gauge",
                /*
                PrometheusType::Histogram => "histogram",
                PrometheusType::Summary => "summary",
                */
            }
        )
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

