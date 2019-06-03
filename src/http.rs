//! The HTTP server
//!
//! The module provides all functionality to expose HTTP endpoints to
//! those interested. The only public item, [`http_listener`] creates all
//! necessary networking services based on the current configuration.
//!
//! [`http_listener`]: fn.http_listener.html

use std::{cmp, io, mem};
use std::fmt::Write as FmtWrite;
use std::io::Write;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use chrono::Duration;
use chrono::offset::Utc;
use futures::{Async, Future, IntoFuture, Stream};
use rpki::resources::AsId;
use tokio::io::{AsyncRead, WriteAll, write_all};
use tokio::net::{TcpListener, TcpStream};
use crate::output;
use crate::config::Config;
use crate::operation::Error;
use crate::origins::{AddressOrigins, AddressPrefix, OriginsHistory};
use crate::output::OutputFormat;
use crate::utils::finish_all;


//------------ http_listener -------------------------------------------------

/// Returns a future for all HTTP server listeners.
///
/// Which servers these are, if any, is determined by `config`. The data 
/// taken from `history`. As a consequence, if you need new
/// data to be exposed, add it to [`OriginsHistory`] somehow.
///
/// [`OriginsHistory`]: ../origins/struct.OriginsHistory.html
pub fn http_listener(
    history: OriginsHistory,
    config: &Config,
) -> impl Future<Item= (), Error = ()> {
    finish_all(
        config.http_listen.iter().map(|addr| {
            single_http_listener(*addr, history.clone())
        })
    )
}

/// Returns a future for a single HTTP listener.
///
/// The future will never resolve unless an error happens that breaks the
/// listener, in which case it will print an error and resolve the error case.
/// It will listen on `addr` for incoming connection. Each new connection will
/// be handled via a brand new `HttpConnection`.
fn single_http_listener(
    addr: SocketAddr,
    history: OriginsHistory,
) -> impl Future<Item=(), Error=()> {
    TcpListener::bind(&addr).into_future()
    .then(move |res| {
        match res {
            Ok(some) => {
                info!("HTTP monitor: Listening on {}.", addr);
                Ok(some)
            }
            Err(err) => {
                error!("Failed to bind HTTP monitor to {}: {}", addr, err);
                Err(())
            }
        }
    })
    .and_then(move |listener| {
        listener.incoming()
        .map_err(|err| {
            error!("Failed to accept HTTP monitor connection: {}", err)
        })
        .for_each(move |sock| {
            tokio::spawn(
                HttpConnection::new(sock, history.clone())
            )
        })
    })
}


//------------ HttpConnection ------------------------------------------------

/// The future for a HTTP monitor connection.
///
/// The future will read and parse an HTTP request, produce a response and
/// send it out, close the socket, and resolve successfully. An error will
/// be returned if an IO error happens only. If an error happens further up,
/// it will try to send a 500 response back.
#[allow(clippy::large_enum_variant)]
enum HttpConnection {
    /// Phase 1: Read a request.
    Read(ReadRequest),

    /// Phase 2: Send a response.
    Response(Response),

    /// Phase 3: Done.
    Done
}

impl HttpConnection {
    /// Creates a new connection for a socket and the history.
    pub fn new(
        sock: TcpStream,
        origins: OriginsHistory,
    ) -> Self {
        HttpConnection::Read(ReadRequest::new(sock, origins))
    }

    /// Returns whether the connection has arrived at the ‘done’ state.
    fn is_done(&self) -> bool {
        match *self {
            HttpConnection::Done => true,
            _ => false
        }
    }
}

impl Future for HttpConnection {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
        while !self.is_done() {
            *self = match *self {
                HttpConnection::Read(ref mut fut) => {
                    HttpConnection::Response(try_ready!(
                        fut.poll().map_err(|_| ())
                    ))
                }
                HttpConnection::Response(ref mut fut) => {
                    try_ready!(fut.poll().map_err(|_| ()));
                    HttpConnection::Done
                }
                HttpConnection::Done => panic!("polling resolved future")
            };
        }
        Ok(Async::Ready(()))
    }
}


//------------ ReadRequest ---------------------------------------------------

/// A future that reads a request and turns it into a response.
///
/// The future will keep reading from the socket until it either successfully
/// parses an HTTP request or runs out of space as it internally uses a fixed
/// size buffer of 1024 bytes for the message - enough for our purposes. In
/// either case it will resolve into a response to send back, which will be a
/// 500 error if anything goes wrong.
struct ReadRequest {
    /// The socket to read from.
    ///
    /// If this becomes `None`, we are done.
    sock: Option<TcpStream>,

    /// The history to generate responses from.
    ///
    /// Like `sock`, this will be turned into `None` when we are done.
    origins: Option<OriginsHistory>,

    /// The read buffer.
    buf: [u8; 1024],

    /// The current position in the read buffer.
    read: usize
}

impl ReadRequest {
    fn new(sock: TcpStream, origins: OriginsHistory) -> Self {
        ReadRequest {
            sock: Some(sock),
            origins: Some(origins),
            buf: unsafe { mem::uninitialized() },
            read: 0
        }
    }
}

impl Future for ReadRequest {
    type Item = Response;
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
        loop {
            let read = try_ready!(
                self.sock.as_mut().expect("polling resolved future)")
                    .poll_read(&mut self.buf[self.read..])
            );
            if read == 0 {
                return Err(
                    io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "closed by peer"
                    )
                )
            }
            self.read += read;
            let mut headers = [httparse::EMPTY_HEADER; 16];
            let mut req = httparse::Request::new(&mut headers);
            match req.parse(&self.buf[..self.read]) {
                Ok(res) if res.is_partial() => {
                    if self.read >= self.buf.len() {
                        return Ok(Async::Ready(
                            Response::error(self.sock.take().unwrap())
                        ))    
                    }
                    // else we continue reading another fragment.
                }
                Ok(_) => {
                    return Ok(Async::Ready(Response::from_request(
                        self.sock.take().unwrap(),
                        self.origins.take().unwrap(),
                        &req
                    )))
                }
                Err(_) => {
                    return Ok(Async::Ready(
                        Response::error(self.sock.take().unwrap())
                    ))    
                }
            }
        }
    }
}


//------------ Response ------------------------------------------------------

/// A future sending a response back to the client.
///
/// This type collects all possible types of responses.
enum Response {
    /// A response returning static content.
    Static(WriteAll<TcpStream, &'static [u8]>),

    /// A response returning dynamic content.
    Vec(WriteAll<TcpStream, Vec<u8>>),

    /// A response returning a list of VRPs.
    ///
    /// These lists are too big to create a temporary buffer first, so we
    /// have a type that smartly sends them out in chunks.
    Vrp(VrpResponse),
}

impl Response {
    /// Produces the correct response for the given request.
    fn from_request(
        sock: TcpStream,
        origins: OriginsHistory,
        req: &httparse::Request
    ) -> Self {
        if req.method != Some("GET") {
            return Self::method_not_allowed(sock)
        }
        if let Some(path) = req.path {
            let (path, query) = match path.find('?') {
                Some(idx) => (&path[..idx], &path[idx + 1..]),
                None => (path, "")
            };
            match path {
                "/csv" => {
                    VrpResponse::response(
                        sock, origins, query, OutputFormat::Csv
                    )
                }
                "/json" => {
                    VrpResponse::response(
                        sock, origins, query, OutputFormat::Json
                    )
                }
                "/metrics" => {
                    Self::metrics(sock, origins)
                }
                "/openbgpd" => {
                    VrpResponse::response(
                        sock, origins, query, OutputFormat::Openbgpd
                    )
                }
                "/rpsl" => {
                    VrpResponse::response(
                        sock, origins, query, OutputFormat::Rpsl
                    )
                }
                "/status" => Self::status(sock, origins),
                "/version" => Self::text(sock, crate_version!()),
                _ => Self::not_found(sock),
            }
        }
        else {
            Self::not_found(sock)
        }
    }

    /// Produces the response for the `/metrics` path.
    fn metrics(sock: TcpStream, origins: OriginsHistory) -> Self {
        let mut res = String::new();

        // valid_roas 
        writeln!(res,
            "# HELP valid_roas number of valid ROAs seen\n\
             # TYPE valid_roas gauge"
        ).unwrap();
        origins.current_metrics(|item| {
            for tal in item.tals() {
                writeln!(res,
                    "valid_roas{{tal=\"{}\"}} {}",
                    tal.tal.name(), tal.roas
                ).unwrap();
            }
        });

        // vrps_total
        writeln!(res,
            "\n\
             # HELP vrps_total total number of VRPs seen\n\
             # TYPE vrps_total gauge"
        ).unwrap();
        origins.current_metrics(|item| {
            for tal in item.tals() {
                writeln!(res,
                    "vrps_total{{tal=\"{}\"}} {}",
                    tal.tal.name(), tal.vrps
                ).unwrap();
            }
        });

        // last_update_state, last_update_done, last_update_duration
        let (start, done, duration) = origins.update_times();
        unwrap!(write!(res,
            "\n\
            # HELP last_update_start seconds since last update started\n\
            # TYPE gauge\n\
            last_update_start {}\n\
            \n\
            # HELP last_update_duration duration in seconds of last update\n\
            # TYPE gauge\n\
            last_update_duration {}\n\
            \n\
            # HELP last_update_done seconds since last update finished\n\
            # TYPE gauge\n\
            last_update_done ",
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
        unwrap!(write!(res,
            "\n\
            # HELP serial current RTR serial number\n\
            # TYPE gauge\n\
            serial {}",
            origins.serial()
        ));

        Self::from_content(
            sock, "200 OK", "text/plain; version=0.0.4",
            &res
        )
    }

    /// Produces a response for the `/status` path.
    fn status(sock: TcpStream, origins: OriginsHistory) -> Self {
        let mut res = String::new();
        let (start, done, duration) = origins.update_times();
        let start = unwrap!(Duration::from_std(start.elapsed()));
        let done = done.map(|done|
            unwrap!(Duration::from_std(done.elapsed()))
        );
        let duration = duration.map(|duration| 
            unwrap!(Duration::from_std(duration))
        );
        let now = Utc::now();

        // serial
        unwrap!(writeln!(res, "serial: {}", origins.serial()));

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

        origins.current_metrics(|metrics| {
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

        });

        Self::from_content(
            sock, "200 OK", "text/plain; version=0.0.4",
            &res
        )
    }

    /// Produces a response returning some plain text.
    fn text<T: AsRef<str> + ?Sized>(sock: TcpStream, text: &T) -> Self {
        Self::from_content(
            sock,
            "200 OK",
            "text/plain;charset=utf-8",
            text.as_ref().as_bytes()
        )
    }

    /// Produces the response for some content.
    ///
    /// Assembles the response in a newly allocated buffer before sending.
    /// The response will be sent to `sock`. It will have the status code
    /// `status` which must be both the numerical code and the reason phrase.
    /// The content type of the response will be set to `content_type`. The
    /// content will be taken from content.
    fn from_content<T: AsRef<[u8]> + ?Sized>(
        sock: TcpStream,
        status: &'static str,
        content_type: &'static str,
        content: &T
    ) -> Self {
        let content = content.as_ref();
        let mut res = Vec::with_capacity(
            status.len() + content_type.len() + content.len()
            + 12 // for content length -- should be enough
            + 11 + 16 + 18 + 2 // Presumably, the compiler is smart enough ...
        ); 
        write!(&mut res, 
            "HTTP/1.1 {}\r\n\
             Content-Type: {}\r\n\
             Content-Length: {}\r\n\
             \r\n",
            status,
            content_type,
            content.len(),
        ).unwrap();
        res.extend_from_slice(content);
        Response::Vec(write_all(sock, res))
    }

    /// Produces a 500 Internal Server Error response.
    fn error(sock: TcpStream) -> Self {
        Response::Static(write_all(sock, &ERROR_500))
    }

    /// Produces a 400 Bad Request response.
    fn bad_request(sock: TcpStream) -> Self {
        Response::Static(write_all(sock, &ERROR_400))
    }

    /// Produces a 404 Not Found response.
    fn not_found(sock: TcpStream) -> Self {
        Response::Static(write_all(sock, &ERROR_404))
    }

    /// Produces a 405 Method Not Allowed response.
    fn method_not_allowed(sock: TcpStream) -> Self {
        Response::Static(write_all(sock, &ERROR_405))
    }
}

impl Future for Response {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<()>, io::Error> {
        match *self {
            Response::Static(ref mut fut) => {
                let _ = try_ready!(fut.poll());
            }
            Response::Vec(ref mut fut) => {
                let _ = try_ready!(fut.poll());
            }
            Response::Vrp(ref mut fut) => {
                try_ready!(fut.poll());
            }
        };
        Ok(Async::Ready(()))
    }
}


//------------ VrpResponse --------------------------------------------------

/// A response providing the VRP output.
///
/// This will send out the list of VRPs in chunks of 1000 entries.
struct VrpResponse {
    write: WriteAll<TcpStream, Vec<u8>>,
    origins: Arc<AddressOrigins>,
    next_id: usize,
    format: OutputFormat,
    filters: Option<Vec<output::Filter>>,
}

impl VrpResponse {
    /// Creates a new VRP response.
    ///
    /// The response will be sent to the socket `sock`. The list will be the
    /// current list from `origins`. It will be formatted in `format`.
    pub fn response(
        sock: TcpStream,
        origins: OriginsHistory,
        query: &str,
        format: OutputFormat
    ) -> Response {
        let filters = match Self::output_filters(query) {
            Ok(filters) => filters,
            Err(_) => return Response::bad_request(sock),
        };
        // We’ll start out with the HTTP header which we can assemble
        // already. For the length, we have our magical `GetLength` type.
        let origins = origins.current();
        let header = format!("\
            HTTP/1.1 200 OK\r\n\
            Content-Type: {}\r\n\
            Content-Length: {}\r\n\
            \r\n",
            format.content_type(),
            GetLength::get(|w| unwrap!(
                format.output(&origins, filters.as_ref().map(AsRef::as_ref), w)
            ))
        ).into_bytes();
        Response::Vrp(VrpResponse {
            write: write_all(sock, header),
            origins,
            next_id: 0,
            format,
            filters
        })
    }

    /// Produces the output filters from a query string.
    fn output_filters(
        mut query: &str
    ) -> Result<Option<Vec<output::Filter>>, Error> {
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
                match AsId::from_str(value) {
                    Ok(some) => res.push(output::Filter::As(some)),
                    Err(_) => return Err(Error)
                }
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

    /// Creates the next batch of VRPs.
    ///
    /// Returns a buffer with the new batch or `None` if we are done. The
    /// first batch will include the header, the last batch will include the
    /// footer.
    fn next_batch(&mut self) -> Option<Vec<u8>> {
        if self.next_id == self.origins.len() {
            return None
        }
        let end = cmp::min(self.next_id + 1000, self.origins.len());
        let filters = self.filters.as_ref().map(AsRef::as_ref);
        let mut target = Vec::new();
        if self.next_id == 0 {
            self.format.output_header(&self.origins, &mut target).unwrap();
            unwrap!(self.format.output_origin(
                &self.origins[0], filters, true, &mut target
            ));
            self.next_id = 1;
        }
        for addr in &self.origins[self.next_id..end] {
            unwrap!(self.format.output_origin(
                addr, filters, false, &mut target
            ));
        }
        if end == self.origins.len() {
            self.format.output_footer(&self.origins, &mut target).unwrap();
        }
        self.next_id = end;
        Some(target)
    }
}

impl Future for VrpResponse {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
        loop {
            let (sock, _) = try_ready!(self.write.poll());
            if let Some(batch) = self.next_batch() {
                self.write = write_all(sock, batch)
            }
            else {
                return Ok(Async::Ready(()))
            }
        }
    }
}


//------------ GetLength -----------------------------------------------------

/// A writer that adds up the length of whatever has been written.
#[derive(Clone, Copy, Debug, Default)]
struct GetLength(usize);

impl GetLength {
    /// Returns the length of what’s been written in the closure.
    ///
    /// The closure receives a writer it should write to.
    pub fn get<F: FnOnce(&mut Self)>(op: F) -> usize {
        let mut target = Self::default();
        op(&mut target);
        target.0
    }
}

impl io::Write for GetLength {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        self.0 += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        Ok(())
    }
}


//------------ Constants -----------------------------------------------------

/// The literal content of a 404 error.
const ERROR_400: &[u8] = b"\
    HTTP/1.1 400 Bad Request\r\n\
    Content-Type: text/plain\r\n\
    Content-Length: 11\r\n\
    \r\n\
    Bad Request";

/// The literal content of a 404 error.
const ERROR_404: &[u8] = b"\
    HTTP/1.1 404 Not Found\r\n\
    Content-Type: text/plain\r\n\
    Content-Length: 9\r\n\
    \r\n\
    Not Found";

/// The literal content of a 405 error.
const ERROR_405: &[u8] = b"\
    HTTP/1.1 405 Method Not Allowed\r\n\
    Content-Type: text/plain\r\n\
    Content-Length: 18\r\n\
    \r\n\
    Method Not Allowed";

/// The literal content of a 500 error.
const ERROR_500: &[u8] = b"\
    HTTP/1.1 500 Internal Server Error\r\n\
    Content-Type: text/plain\r\n\
    Content-Length: 21\r\n\
    \r\n\
    Internal Server Error";

