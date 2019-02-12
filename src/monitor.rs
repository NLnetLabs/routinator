//! Everything regarding monitoring.
//!

use std::{cmp, io};
use std::net::SocketAddr;
use std::sync::Arc;
use futures::future;
use futures::{Async, Future, IntoFuture, Stream};
use tokio::io::{AsyncRead, WriteAll, write_all};
use tokio::net::{TcpListener, TcpStream};
use crate::config::Config;
use crate::output::OutputFormat;
use crate::origins::{OriginsHistory, AddressOrigins};


//------------ Constants -----------------------------------------------------

const ERROR_500: &[u8] = b"\
    HTTP/1.1 500 Internal Server Error\r\n\
    Content-Type: text/plain\r\n\
    Content-Length: 21\r\n\
    \r\n\
    Internal Server Error";


//------------ monitor_listener ----------------------------------------------

/// Returns a future for all the monitoring server listeners we support.
pub fn monitor_listener(
    history: OriginsHistory,
    config: &Config,
) -> impl Future<Item=(), Error=()> {
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
enum HttpConnection {
    Read(ReadRequest),
    Response(Response),
    Done
}

impl HttpConnection {
    /// Creates a new connection for a socket.
    pub fn new(
        sock: TcpStream,
        origins: OriginsHistory,
    ) -> Self {
        HttpConnection::Read(ReadRequest {
            sock: Some(sock),
            origins: Some(origins),
            buf: [0; 1024],
            read: 0
        })
    }

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

struct ReadRequest {
    sock: Option<TcpStream>,
    origins: Option<OriginsHistory>,
    buf: [u8; 1024],
    read: usize
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

struct Response(Box<Future<Item=(), Error=io::Error> + 'static + Send>);

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
                "/openbgpd" => {
                    VrpResponse::new(sock, origins, OutputFormat::Openbgpd)
                }
                "/rpsl" => VrpResponse::new(sock, origins, OutputFormat::Rpsl),
                "/status" => Self::text(sock, "200", "fine"),
                _ => Self::text(sock, "404", "not found"),
            }
        }
        else {
            Self::error(sock)
        }
    }

    fn text<T: AsRef<str> + ?Sized>(
        sock: TcpStream, status: &'static str, text: &T
    ) -> Self {
        let text = text.as_ref();
        let output = format!("\
            HTTP/1.1 {} OK\r\n\
            Content-Type: text/plain;charset=utf-8\r\n\
            Content-Length: {}\r\n\
            \r\n\
            {}",
            status,
            text.len(),
            text
        );
        Self::write_all(sock, output)
    }

    fn error(sock: TcpStream) -> Self {
        Self::write_all(sock, &ERROR_500)
    }

    fn write_all<T: AsRef<[u8]> + 'static + Send>(
        sock: TcpStream, t: T
    ) -> Self {
        Self(Box::new(write_all(sock, t).map(|_| ())))
    }
}

impl Future for Response {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<()>, io::Error> {
        self.0.poll()
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
        Response(Box::new(VrpResponse {
            write: write_all(sock, header),
            origins,
            next_id: 0,
            format
        }))
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
pub struct GetLength(usize);

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

