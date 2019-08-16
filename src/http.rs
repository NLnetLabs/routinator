//! The HTTP server.
//!
//! The module provides all functionality exposed by the HTTP server to
//! those interested. The only public item, [`http_listener`] creates all
//! necessary networking services based on the current configuration and
//! returns a future that drives the server.
//!
//! [`http_listener`]: fn.http_listener.html

use std::fmt::Write;
use std::net::SocketAddr;
use std::str::FromStr;
use chrono::{Duration, Utc};
use clap::crate_version;
use futures::{future, stream};
use futures::future::{Future, FutureResult};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use log::error;
use rpki::resources::AsId;
use unwrap::unwrap;
use crate::output;
use crate::config::Config;
use crate::operation::Error;
use crate::origins::{AddressPrefix, OriginsHistory};
use crate::output::OutputFormat;
use crate::utils::finish_all;
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
) -> impl Future<Item = (), Error = ()> {
    finish_all(
        config.http_listen.iter().map(|addr| {
            single_http_listener(*addr, origins.clone())
        })
    )
}

/// Returns a future for a single HTTP listener.
///
/// The future will never resolve unless an error happens that breaks the
/// listener, in which case it will print an error and resolve the error case.
/// It will listen bind a Hyper server onto `addr` and produce any data
/// served from `origins`.
fn single_http_listener(
    addr: SocketAddr,
    origins: OriginsHistory,
) -> impl Future<Item=(), Error=()> {
    Server::bind(&addr)
    .serve(Service { origins })
    .map_err(|err| {
        error!("HTTP server error: {}", err);
    })
}


//------------ Service -------------------------------------------------------

/// A Hyper service for our HTTP server.
///
/// The only state we need is the `origins` with our data. The `Service`
/// impl dispatches incoming requests according to their path to dedicated
/// methods.
#[derive(Clone)]
struct Service {
    origins: OriginsHistory,
}


//--- MakeService and Service

impl<Ctx> hyper::service::MakeService<Ctx> for Service {
    type ReqBody = Body;
    type ResBody = Body;
    type Service = Self;
    type Error = hyper::Error;
    type MakeError = hyper::Error;
    type Future = FutureResult<Self, hyper::Error>;

    fn make_service(&mut self, _ctx: Ctx) -> Self::Future {
        future::ok(self.clone())
    }
}

impl hyper::service::Service for Service {
    type ReqBody = Body;
    type ResBody = Body;
    type Error = hyper::Error;
    type Future = FutureResult<Response<Body>, hyper::Error>;

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        future::ok(
            if *req.method() != Method::GET {
                self.method_not_allowed()
            }
            else {
                match req.uri().path() {
                    "/csv" => self.vrps(req.uri().query(), OutputFormat::Csv),
                    "/json" => {
                        self.vrps(req.uri().query(), OutputFormat::Json)
                    }
                    "/metrics" => self.metrics(),
                    "/openbgpd" => {
                        self.vrps(req.uri().query(), OutputFormat::Openbgpd)
                    }
                    "/rpsl" => {
                        self.vrps(req.uri().query(), OutputFormat::Csv)
                    }
                    "/status" => self.status(),
                    "/validity" => self.validity_query(req.uri().query()),
                    "/version" => self.version(),
                    path if path.starts_with("/api/v1/validity/") => {
                        self.validity_path(&path[17..])
                    }
                    _ => self.not_found()
                }
            }
        )
    }
}


/// # Methods for Endpoints
///
impl Service {
    fn metrics(&self) -> Response<Body> {
        let mut res = String::new();
        let metrics = self.origins.current_metrics();

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

        // last_update_state, last_update_done, last_update_duration
        let (start, done, duration) = self.origins.update_times();
        unwrap!(write!(res,
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
        ));
        match done {
            Some(instant) => {
                unwrap!(writeln!(res, "{}", instant.elapsed().as_secs()));
            }
            None => {
                unwrap!(writeln!(res, "Nan"));
            }
        }

        // serial
        unwrap!(writeln!(res,
            "\n\
            # HELP routinator_serial current RTR serial number\n\
            # TYPE routinator_serial gauge\n\
            routinator_serial {}",

            self.origins.serial()
        ));

        // rsync_status
        unwrap!(writeln!(res, "
            \n\
            # HELP routinator_rsync_status exit status of rsync command\n\
            # TYPE routinator_rsync_status gauge"
        ));
        for metrics in metrics.rsync() {
            unwrap!(writeln!(
                res,
                "routinator_rsync_status{{uri=\"{}\"}} {}",
                metrics.module,
                match metrics.status {
                    Ok(status) => status.code().unwrap_or(-1),
                    Err(_) => -1
                }
            ));
        }

        // rsync_duration
        unwrap!(writeln!(res, "
            \n\
            # HELP routinator_rsync_duration duration of rsync in seconds\n\
            # TYPE routinator_rsync_duration gauge"
        ));
        for metrics in metrics.rsync() {
            if let Ok(duration) = metrics.duration {
                unwrap!(writeln!(
                    res,
                    "routinator_rsync_duration{{uri=\"{}\"}} {:.3}",
                    metrics.module,
                    duration.as_secs() as f64
                    + f64::from(duration.subsec_millis()) / 1000.
                ));
            }
        }

        // rrdp_status
        unwrap!(writeln!(res, "
            \n\
            # HELP routinator_rrdp_status status code for getting \
                notification file\n\
            # TYPE routinator_rrdp_status gauge"
        ));
        for metrics in metrics.rrdp() {
            unwrap!(writeln!(
                res,
                "routinator_rrdp_status{{uri=\"{}\"}} {}",
                metrics.notify_uri,
                metrics.notify_status.map(|code| {
                    code.as_u16() as i16
                }).unwrap_or(-1),
            ));
        }

        // rrdp_duration
        unwrap!(writeln!(res, "
            \n\
            # HELP routinator_rrdp_duration duration of rsync in seconds\n\
            # TYPE routinator_rrdo_duration gauge"
        ));
        for metrics in metrics.rrdp() {
            if let Ok(duration) = metrics.duration {
                unwrap!(writeln!(
                    res,
                    "routinator_rrdp_duration{{uri=\"{}\"}} {:.3}",
                    metrics.notify_uri,
                    duration.as_secs() as f64
                    + f64::from(duration.subsec_millis()) / 1000.
                ));
            }
        }

        unwrap!(
            Response::builder()
            .header("Content-Type", "text/plain; version=0.0.4")
            .body(res.into())
        )
    }

    fn status(&self) -> Response<Body> {
        let mut res = String::new();
        let (start, done, duration) = self.origins.update_times();
        let start = unwrap!(Duration::from_std(start.elapsed()));
        let done = done.map(|done|
            unwrap!(Duration::from_std(done.elapsed()))
        );
        let duration = duration.map(|duration| 
            unwrap!(Duration::from_std(duration))
        );
        let now = Utc::now();

        // serial
        unwrap!(writeln!(res, "serial: {}", self.origins.serial()));

        // last-update-start-at and -ago
        unwrap!(writeln!(res, "last-update-start-at:  {}", now - start));
        unwrap!(writeln!(res, "last-update-start-ago: {}", start));

        // last-update-dona-at and -ago
        if let Some(done) = done {
            unwrap!(writeln!(res, "last-update-done-at:   {}", now - done));
            unwrap!(writeln!(res, "last-update-done-ago:  {}", done));
        }
        else {
            unwrap!(writeln!(res, "last-update-done-at:   -"));
            unwrap!(writeln!(res, "last-update-done-ago:  -"));
        }

        // last-update-duration
        if let Some(duration) = duration {
            unwrap!(writeln!(res, "last-update-duration:  {}", duration));
        }
        else {
            unwrap!(writeln!(res, "last-update-duration:  -"));
        }

        let metrics = self.origins.current_metrics();
        // valid-roas
        unwrap!(writeln!(res, "valid-roas: {}",
            metrics.tals().iter().map(|tal| tal.roas).sum::<u32>()
        ));

        // valid-roas-per-tal
        unwrap!(write!(res, "valid-roas-per-tal: "));
        for tal in metrics.tals() {
            unwrap!(write!(res, "{}={} ", tal.tal.name(), tal.roas));
        }
        unwrap!(writeln!(res, ""));

        // vrps
        unwrap!(writeln!(res, "vrps: {}",
            metrics.tals().iter().map(|tal| tal.vrps).sum::<u32>()
        ));

        // vrps-per-tal
        unwrap!(write!(res, "vrps-per-tal: "));
        for tal in metrics.tals() {
            unwrap!(write!(res, "{}={} ", tal.tal.name(), tal.vrps));
        }
        unwrap!(writeln!(res, ""));

        // rsync_status
        unwrap!(writeln!(res, "rsync-durations:"));
        for metrics in metrics.rsync() {
            unwrap!(write!(
                res,
                "   {}: status={}",
                metrics.module,
                match metrics.status {
                    Ok(status) => status.code().unwrap_or(-1),
                    Err(_) => -1
                }
            ));
            if let Ok(duration) = metrics.duration {
                unwrap!(writeln!(
                    res,
                    ", duration={:.3}s",
                    duration.as_secs() as f64
                    + f64::from(duration.subsec_millis()) / 1000.
                ));
            }
            else {
                unwrap!(writeln!(res, ""))
            }
        }

        unwrap!(
            Response::builder()
            .header("Content-Type", "text/plain")
            .body(res.into())
        )
    }

    fn validity_path(&self, path: &str) -> Response<Body> {
        let mut path = path.splitn(2, '/');
        let asn = match path.next() {
            Some(asn) => asn,
            None => return self.bad_request()
        };
        let prefix = match path.next() {
            Some(prefix) => prefix,
            None => return self.bad_request()
        };
        self.validity(asn, prefix)
    }

    fn validity_query(&self, query: Option<&str>) -> Response<Body> {
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
                return self.bad_request()
            }
        }
        let asn = match asn {
            Some(asn) => asn,
            None => return self.bad_request()
        };
        let prefix = match prefix {
            Some(prefix) => prefix,
            None => return self.bad_request()
        };
        self.validity(asn, prefix)
    }

    fn validity(&self, asn: &str, prefix: &str) -> Response<Body> {
        let asn = match AsId::from_str(asn) {
            Ok(asn) => asn,
            Err(_) => return self.bad_request()
        };
        let prefix = match AddressPrefix::from_str(prefix) {
            Ok(prefix) => prefix,
            Err(_) => return self.bad_request()
        };
        unwrap!(
            Response::builder()
            .header("Content-Type", "application/json")
            .body(
                RouteValidity::new(prefix, asn, &self.origins.current())
                .into_json()
                .into()
            )
        )
    }

    fn version(&self) -> Response<Body> {
        unwrap!(
            Response::builder()
            .header("Content-Type", "text/plain")
            .body(crate_version!().into())
        )
    }

    fn vrps(
        &self,
        query: Option<&str>,
        format: OutputFormat
    ) -> Response<Body> {
        let filters = match Self::output_filters(query) {
            Ok(filters) => filters,
            Err(_) => return self.bad_request(),
        };
        let stream = format.stream(
            self.origins.current(), filters, self.origins.current_metrics()
        );

        unwrap!(
            Response::builder()
            .header("Content-Type", format.content_type())
            .header("content-length", stream.output_len())
            .body(Body::wrap_stream(stream::iter_ok::<_, hyper::Error>(stream)))
        )
    }

    fn bad_request(&self) -> Response<Body> {
        unwrap!(
            Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header("Content-Type", "text/plain")
            .body("Bad Request".into())
        )
    }

    fn method_not_allowed(&self) -> Response<Body> {
        unwrap!(
            Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header("Content-Type", "text/plain")
            .body("Method Not Allowed".into())
        )
    }

    fn not_found(&self) -> Response<Body> {
        unwrap!(
            Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("Content-Type", "text/plain")
            .body("Not Found".into())
        )
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
}


fn query_iter<'a>(
    query: Option<&'a str>
) -> impl Iterator<Item=(&'a str, Option<&'a str>)> + 'a {
    let query = query.unwrap_or("");
    query.split('&').map(|item| {
        let mut item = item.splitn(2, '=');
        let key = unwrap!(item.next());
        let value = item.next();
        (key, value)
    })
}

