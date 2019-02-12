//! Everything regarding monitoring.
//!
//! The module provides all functionality to expose monitoring endpoints to
//! those interested. The only public item, [`monitor_listener`] creates all
//! necessary networking services based on the current configuration.
//!
//! [`monitor_listener`]: fn.monitor_listener.html

use std::{cmp, io, mem};
use std::net::SocketAddr;
use std::sync::Arc;
use futures::future;
use futures::{Async, Future, IntoFuture, Stream};
use tokio::io::{AsyncRead, WriteAll, write_all};
use tokio::net::{TcpListener, TcpStream};
use crate::config::Config;
use crate::output::OutputFormat;
use crate::origins::{OriginsHistory, AddressOrigins};


//------------ monitor_listener ----------------------------------------------

/// Returns a future for all monitoring server listeners.
///
/// Which servers these are, if any, is determined by `config`. The data for
/// monitoring is taken from `history`. As a consequence, if you need new
/// data to be exposed, add it to [`OriginsHistory`] somehow.
///
/// [`OriginsHistory`]: ../origins/struct.OriginsHistory.html
pub fn monitor_listener(
    history: OriginsHistory,
    config: &Config,
) -> impl Future<Item= (), Error = ()> {
    if config.http_listen.is_empty() {
        future::Either::A(future::empty())
    }
    else {
        future::Either::B(
            future::select_all(
                config.http_listen.iter().map(|addr| {
                    http_listener(*addr, history.clone())
                })
            ).then(|_| Ok(()))
        )
    }
}

/// Returns a future for a single HTTP listener.
///
/// The future will never resolve unless an error happens that breaks the
/// listener, in which case it will print an error and resolve the error case.
/// It will listen on `addr` for incoming connection. Each new connection will
/// be handled via a brand new `HttpConnection`.
fn http_listener(
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
        match self {
            &HttpConnection::Done => true,
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
                    let _ = try_ready!(fut.poll().map_err(|_| ()));
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
            self.read += try_ready!(
                self.sock.as_mut().expect("polling resolved future)")
                    .poll_read(&mut self.buf[self.read..])
            );
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
enum Response {
    Static(WriteAll<TcpStream, &'static [u8]>),
    Vec(WriteAll<TcpStream, Vec<u8>>),
    Vrp(VrpResponse),
}

impl Response {
    fn from_request(
        sock: TcpStream,
        origins: OriginsHistory,
        req: &httparse::Request
    ) -> Self {
        if let Some(path) = req.path {
            match path {
                "/csv" => VrpResponse::new(sock, origins, OutputFormat::Csv),
                "/json" => VrpResponse::new(sock, origins, OutputFormat::Json),
                "/metrics" => Self::metrics(sock, origins),
                "/openbgpd" => {
                    VrpResponse::new(sock, origins, OutputFormat::Openbgpd)
                }
                "/rpsl" => VrpResponse::new(sock, origins, OutputFormat::Rpsl),
                "/status" => Self::text(sock, "fine"),
                "/version" => Self::text(sock, crate_version!()),
                _ => Self::not_found(sock),
            }
        }
        else {
            Self::error(sock)
        }
    }

    fn metrics(sock: TcpStream, origins: OriginsHistory) -> Self {
        Self::from_content(
            sock, "200", "text/plain; version=0.0.4",
            &format!(
                "# HELP vrps_total total number of VRPs seen\n\
                 # TYPE vrps_total gauge\n\
                 vrps_total {}\n",
                origins.current().len()
            )
        )
    }

    fn text<T: AsRef<str> + ?Sized>(sock: TcpStream, text: &T) -> Self {
        Self::from_content(sock, "200", "text/plain;charset=utf-8", text)
    }

    fn not_found(sock: TcpStream) -> Self {
        Self::from_content(sock, "404", "text/plain", "not found")
    }

    fn from_content<T: AsRef<str> + ?Sized>(
        sock: TcpStream,
        status: &'static str,
        content_type: &'static str,
        content: &T
    ) -> Self {
        let content = content.as_ref();
        let output = format!("\
            HTTP/1.1 {} OK\r\n\
            Content-Type: {}\r\n\
            Content-Length: {}\r\n\
            \r\n\
            {}",
            status,
            content_type,
            content.len(),
            content
        );
        Response::Vec(write_all(sock, output.into_bytes()))
    }

    fn error(sock: TcpStream) -> Self {
        Response::Static(write_all(sock, &ERROR_500))
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
                let _  = try_ready!(fut.poll());
            }
        };
        Ok(Async::Ready(()))
    }
}


//------------ VrpResponse --------------------------------------------------

/// A response providing the VRP output.
struct VrpResponse {
    write: WriteAll<TcpStream, Vec<u8>>,
    origins: Arc<AddressOrigins>,
    next_id: usize,
    format: OutputFormat,
}

impl VrpResponse {
    pub fn new(
        sock: TcpStream,
        origins: OriginsHistory,
        format: OutputFormat
    ) -> Response {
        let origins = origins.current();
        let header = format!("\
            HTTP/1.1 200 OK\r\n\
            Content-Type: text/plain;charset=utf-8\r\n\
            Content-Length: {}\r\n\
            \r\n",
            GetLength::get(|w| format.output(&origins, w).unwrap())
        ).into_bytes();
        Response::Vrp(VrpResponse {
            write: write_all(sock, header),
            origins,
            next_id: 0,
            format
        })
    }

    fn next_batch(&mut self) -> Option<Vec<u8>> {
        if self.next_id == self.origins.len() {
            return None
        }
        let end = cmp::min(self.next_id + 1000, self.origins.len());
        let mut target = Vec::new();
        if self.next_id == 0 {
            self.format.output_header(&self.origins, &mut target).unwrap();
            self.format.output_origin(&self.origins[0], true, &mut target)
                .unwrap();
            self.next_id = 1;
        }
        for addr in &self.origins[self.next_id..end] {
            self.format.output_origin(addr, false, &mut target).unwrap();
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

#[derive(Clone, Copy, Debug, Default)]
struct GetLength(usize);

impl GetLength {
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

const ERROR_500: &[u8] = b"\
    HTTP/1.1 500 Internal Server Error\r\n\
    Content-Type: text/plain\r\n\
    Content-Length: 21\r\n\
    \r\n\
    Internal Server Error";

