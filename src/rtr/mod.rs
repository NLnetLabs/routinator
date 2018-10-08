//! The RPKI to Router Protocol.
//!
//! See RFC 8210 for all the details.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;
use futures::future;
use futures::{Async, Future, IntoFuture, Stream};
use tokio;
use tokio::io::{AsyncRead, AsyncWrite, Read, Write, write_all};
use tokio::net::{TcpListener, TcpStream};
use super::config::Config;
use super::repository::Repository;
use super::origins::{AddressOrigin, OriginsHistory, OriginsDiff};

pub mod pdu; // XXX Remove pub.


//------------ rtr_listener --------------------------------------------------

pub fn rtr_listener(
    repo: Repository,
    history: OriginsHistory,
    config: &'static Config,
) -> impl Future<Item=(), Error=()> {
    let session = session_id();
    future::select_all(
        config.rtr_listen.iter().map(|addr| {
            single_listener(
                *addr, session, repo.clone(), history.clone(), config
            )
        })
    ).then(|_| Ok(()))
}

fn session_id() -> u16 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH).unwrap()
        .as_secs() as u16
}

fn single_listener(
    addr: SocketAddr,
    session: u16,
    repo: Repository,
    history: OriginsHistory,
    config: &'static Config,
) -> impl Future<Item=(), Error=()> {
    TcpListener::bind(&addr).into_future()
    .map_err(move |err| error!("Failed to bind RTR listener {}: {}", addr, err))
    .and_then(move |listener| {
        listener.incoming()
        .map_err(|err| error!("Failed to accept connection: {}", err))
        .for_each(move |sock| {
            tokio::spawn(
                Connection::start(
                    sock, session, repo.clone(), history.clone(), config
                )
            )
        })
    })
}


//------------ Connection ----------------------------------------------------

#[derive(Debug)]
struct Connection {
    sock: TcpStream,
    version: Option<u8>,
    session: u16,
    repo: Repository,
    history: OriginsHistory,
    config: &'static Config,
}

impl Connection {
    fn start(
        sock: TcpStream,
        session: u16,
        repo: Repository,
        history: OriginsHistory,
        config: &'static Config,
    ) -> impl Future<Item=(), Error=()> {
        future::loop_fn(
            Connection {
                sock,
                version: None,
                session,
                repo,
                history,
                config
            },
            |connection| {
                connection.step()
                .map_err(|_| ())
                .and_then(|connection| {
                    Ok(future::Loop::Continue(connection))
                })
            }
        )
    }

    fn step(self) -> impl Future<Item=Self, Error=io::Error> {
        Query::read(self)
        .and_then(|(conn, query)| {
            match query {
                Query::Serial { session, serial } => {
                    let diff = if session == conn.session {
                        conn.history.get(serial)
                    }
                    else {
                        None
                    };
                    match diff {
                        Some(diff) => {
                            future::Either::A(future::Either::A(
                                conn.send_diff(diff)
                            ))
                        }
                        None => {
                            future::Either::A(future::Either::B(
                                conn.send_reset()
                            ))
                        }
                    }
                }
                Query::Reset => {
                    future::Either::B(future::Either::A(conn.send_full()))
                }
                Query::Error(err) => {
                    future::Either::B(future::Either::B(
                        conn.send_error(err)
                    ))
                }
            }
        })
    }

    fn send_reset(self) -> impl Future<Item=Connection, Error=io::Error> {
        pdu::CacheReset::new(self.version.unwrap_or(0))
        .write(self)
        .map(|(conn, _)| conn)
    }

    fn send_diff(
        self,
        diff: Arc<OriginsDiff>,
    ) -> impl Future<Item=Connection, Error=io::Error> {
        pdu::CacheResponse::new(self.version.unwrap_or(0), self.session)
        .write(self)
        .and_then(move |(conn, _)| {
            conn.send_origin_set(diff, true, |diff| diff.announce())
        })
        .and_then(move |(conn, diff)| {
            conn.send_origin_set(diff, false, |diff| diff.withdraw())
        })
        .and_then(move |(conn, diff)| conn.send_eod(diff.serial()))
    }

    fn send_full(
        self
    ) -> impl Future<Item=Connection, Error=io::Error> {
        let (current, serial) = self.history.current_and_serial();
        pdu::CacheResponse::new(self.version(), self.session).write(self)
        .and_then(move |(conn, _)| {
            conn.send_origin_set(current, true, |x| x.as_ref().as_ref())
        })
        .and_then(move |(conn, _)| conn.send_eod(serial))
    }

    fn send_origin_set<T, F>(
        self,
        diff: T,
        announce: bool,
        set: F
    ) -> impl Future<Item=(Connection, T), Error=io::Error>
    where F: Fn(&T) -> &[AddressOrigin] {
        future::loop_fn(
            (self, diff, 0),
            move |(conn, diff, idx)| {
                let prefix = set(&diff).get(idx).map(|origin| {
                    pdu::Prefix::new(
                        conn.version.unwrap_or(0),
                        if announce { 1 } else { 0 },
                        origin
                    )
                });
                match prefix {
                    Some(prefix) => {
                        future::Either::A(
                            prefix.write(conn)
                            .map(move |(conn, _)| {
                                future::Loop::Continue((conn, diff, idx + 1))
                            })
                        )
                    }
                    None => {
                        future::Either::B(
                            Ok(future::Loop::Break((conn, diff)))
                            .into_future()
                        )
                    }
                }
            }
        )
    }

    fn send_eod(
        self,
        serial: u32
    ) -> impl Future<Item=Connection, Error=io::Error> {
        pdu::EndOfData::new(
            self.version.unwrap_or(0),
            self.session, 
            serial,
            self.config.refresh.as_secs() as u32,
            self.config.retry.as_secs() as u32,
            self.config.expire.as_secs() as u32
        ).write(self).map(|(conn, _)| conn)
    }

    fn send_error<E: AsRef<[u8]> + Send>(
        self,
        error: E,
    ) -> impl Future<Item=Connection, Error=io::Error> {
        write_all(self, error).map(|(conn, _)| conn)
        .then(|_| Err(io::Error::new(io::ErrorKind::Other, "query error")))
    }

    fn version(&self) -> u8 {
        self.version.unwrap_or(0)
    }
}

impl Read for Connection {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        self.sock.read(buf)
    }
}

impl AsyncRead for Connection { }

impl Write for Connection {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        self.sock.write(buf)
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        self.sock.flush()
    }
}

impl AsyncWrite for Connection {
    fn shutdown(&mut self) -> Result<Async<()>, io::Error> {
        AsyncWrite::shutdown(&mut self.sock)
    }
}

//------------ Query ---------------------------------------------------------

#[allow(dead_code)]
enum Query {
    Serial {
        session: u16,
        serial: u32,
    },
    Reset,
    Error(pdu::BoxedError),
}

#[allow(dead_code)]
impl Query {
    fn read(
        connection: Connection
    ) -> impl Future<Item=(Connection, Self), Error=io::Error> {
        pdu::Header::read(connection)
        .and_then(|(mut connection, header)| {
            if let Some(version) = connection.version {
                if version != header.version() {
                    return future::Either::A(
                        Ok((
                            connection,
                            Query::Error(
                                pdu::Error::new(
                                    header.version(),
                                    8,
                                    header,
                                    "version switched during connection"
                                ).boxed()
                            )
                        )).into_future()
                    )
                }
            }
            else {
                if header.version() > 1 {
                    return future::Either::A(
                        Ok((
                            connection,
                            Query::Error(
                                pdu::Error::new(
                                    header.version(),
                                    4,
                                    header,
                                    "only versions 0 and 1 supported"
                                ).boxed()
                            )
                        )).into_future()
                    )
                }
                else {
                    connection.version = Some(header.version())
                }
            }
            future::Either::B(Self::read_data(connection, header))
        })
    }

    fn read_data(
        mut connection: Connection,
        header: pdu::Header,
    ) -> impl Future<Item=(Connection, Self), Error=io::Error> {
        if let Some(version) = connection.version {
            if version != header.version() {
                return future::Either::B(future::Either::B(
                    Ok((
                        connection,
                        Query::Error(
                            pdu::Error::new(
                                header.version(),
                                8,
                                header,
                                "version switched during connection"
                            ).boxed()
                        )
                    )).into_future()
                ))
            }
        }
        else {
            if header.version() > 1 {
                return future::Either::B(future::Either::B(
                    Ok((
                        connection,
                        Query::Error(
                            pdu::Error::new(
                                header.version(),
                                4,
                                header,
                                "only versions 0 and 1 supported"
                            ).boxed()
                        )
                    )).into_future()
                ))
            }
            else {
                connection.version = Some(header.version())
            }
        }

        match header.pdu() {
            pdu::SerialQuery::PDU => {
                if header.length() != pdu::SerialQuery::LEN {
                    future::Either::B(future::Either::B(
                        Ok((
                            connection,
                            Query::Error(
                                pdu::Error::new(
                                    header.version(),
                                    3,
                                    header,
                                    "invalid length"
                                ).boxed()
                            )
                        )).into_future()
                    ))
                }
                else {
                    future::Either::A(
                        pdu::SerialQueryPayload::read(connection)
                        .and_then(move |(connection, payload)| {
                            Ok((
                                connection,
                                Query::Serial {
                                    session: header.session(),
                                    serial: payload.serial()
                                }
                            ))
                        })
                    )
                }
            }
            pdu::ResetQuery::PDU => {
                if header.length() != pdu::ResetQuery::LEN {
                    future::Either::B(future::Either::B(
                        Ok((
                            connection,
                            Query::Error(
                                pdu::Error::new(
                                    header.version(),
                                    3,
                                    header,
                                    "invalid length"
                                ).boxed()
                            )
                        )).into_future()
                    ))
                }
                else {
                    future::Either::B(future::Either::A(
                        Ok((connection, Query::Reset)).into_future()
                    ))
                }
            }
            _ => {
                future::Either::B(future::Either::B(
                    Ok((
                        connection,
                        Query::Error(
                            pdu::Error::new(
                                header.version(),
                                3,
                                header,
                                "expected Serial Query or Reset Query"
                            ).boxed()
                        )
                    )).into_future()
                ))
            }
        }
    }
}

