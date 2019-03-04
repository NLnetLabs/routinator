//! Reading an RTR query from a client.

use std::io;
use futures::{Async, Future, Stream};
use tokio::io::{AsyncRead, ReadExact};
use super::{notify, pdu};
use super::serial::Serial;


//------------ Query and Input -----------------------------------------------

pub enum Query {
    Serial {
        session: u16,
        serial: Serial,
    },
    Reset,
    Error(pdu::BoxedError),
}

pub enum Input {
    Query(Query),
    Notify
}


//------------ InputStream ---------------------------------------------------

pub struct InputStream<A> {
    query: QueryStream<A>,
    notify: notify::NotifyReceiver,
}

impl<A: AsyncRead> InputStream<A> {
    pub fn new(sock: A, notify: notify::NotifyReceiver) -> Self {
        InputStream {
            query: QueryStream::new(sock),
            notify
        }
    }

    pub fn version(&self) -> u8 {
        self.query.version()
    }
}

impl<A: AsyncRead> Stream for InputStream<A> {
    type Item = Input;
    type Error = ();

    fn poll(&mut self) -> Result<Async<Option<Self::Item>>, Self::Error> {
        match self.query.poll() {
            Ok(Async::NotReady) => { }
            Ok(Async::Ready(Some(query))) => {
                return Ok(Async::Ready(Some(Input::Query(query))))
            }
            Ok(Async::Ready(None)) => return Ok(Async::Ready(None)),
            Err(err) => {
                debug!("RTR read error: {}", err);
                return Err(())
            }
        }
        match self.notify.poll() {
            Ok(Async::Ready(Some(()))) => {
                Ok(Async::Ready(Some(Input::Notify)))
            }
            _ => Ok(Async::NotReady)
        }
    }
}


//------------ QueryStream ---------------------------------------------------

pub struct QueryStream<A> {
    state: State<A>,
    version: Option<u8>,
}

enum State<A> {
    Header(ReadExact<A, pdu::Header>),
    SerialQuery(pdu::Header, ReadExact<A, pdu::SerialQueryPayload>),
    Done,
}

impl<A: AsyncRead> QueryStream<A> {
    pub fn new(sock: A) -> Self {
        QueryStream {
            state: State::Header(pdu::Header::read(sock)),
            version: None,
        }
    }

    pub fn version(&self) -> u8 {
        match self.version {
            Some(version) => version,
            None => 0
        }
    }

    fn check_version(
        version: Option<u8>,
        header: pdu::Header
    ) -> Option<Query> {
        if let Some(current) = version {
            if current != header.version() {
                Some(Query::Error(
                    pdu::Error::new(
                        header.version(),
                        8,
                        header,
                        "version switched during connection"
                    ).boxed()
                ))
            }
            else {
                None
            }
        }
        else if header.version() > 1 {
            Some(Query::Error(
                pdu::Error::new(
                    header.version(),
                    4,
                    header,
                    "only versions 0 and 1 supported"
                ).boxed()
            ))
        }
        else {
            None
        }
    }

    fn start_state(sock: A) -> State<A> {
        State::Header(pdu::Header::read(sock))
    }

    fn read_data(
        sock: A,
        header: pdu::Header
    ) -> (State<A>, Result<Async<Option<Query>>, io::Error>) { 
        match header.pdu() {
            pdu::SERIAL_QUERY_PDU => {
                debug!("RTR: Got serial query.");
                match Self::check_length(header, pdu::SERIAL_QUERY_LEN) {
                    Ok(()) => {
                        (
                            State::SerialQuery(
                                header, pdu::SerialQueryPayload::read(sock)
                            ),
                            Ok(Async::NotReady)
                        )
                    }
                    Err(err) => {
                        debug!("RTR: ... with bad length");
                        (
                            Self::start_state(sock),
                            Ok(Async::Ready(Some(err)))
                        )
                    }
                }
            }
            pdu::ResetQuery::PDU => {
                debug!("RTR: Got reset query.");
                match Self::check_length(header, pdu::ResetQuery::LEN) {
                    Ok(()) => {
                        (
                            Self::start_state(sock),
                            Ok(Async::Ready(Some(Query::Reset)))
                        )
                    }
                    Err(err) => {
                        debug!("RTR: ... with bad length");
                        (
                            Self::start_state(sock),
                            Ok(Async::Ready(Some(err)))
                        )
                    }
                }
            }
            pdu => {
                debug!("RTR: Got query with PDU {}.", pdu);
                (
                    Self::start_state(sock),
                    Ok(Async::Ready(Some(Query::Error(
                        pdu::Error::new(
                            header.version(),
                            3,
                            header,
                            "expected Serial Query or Reset Query"
                        ).boxed()
                    ))))
                )
            }
        }
    }

    fn check_length(header: pdu::Header, expected: u32) -> Result<(), Query> {
        if header.length() != expected {
            Err(Query::Error(
                pdu::Error::new(
                    header.version(),
                    3,
                    header,
                    "invalid length"
                ).boxed()
            ))
        }
        else {
            Ok(())
        }
    }
}

impl<A: AsyncRead> Stream for QueryStream<A> {
    type Item = Query;
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<Option<Self::Item>>, Self::Error> {
        loop {
            let (state, res) = match self.state {
                State::Header(ref mut fut) => {
                    let (sock, header) = try_ready!(fut.poll());
                    debug!("RTR: read a header.");
                    if let Some(err) = Self::check_version(self.version,
                                                           header) {
                        (State::Done, Ok(Async::Ready(Some(err))))
                    }
                    else {
                        self.version = Some(header.version());
                        Self::read_data(sock, header)
                    }
                }
                State::SerialQuery(header, ref mut fut) => {
                    let (sock, payload) = try_ready!(fut.poll());
                    debug!("RTR: read the serial query payload.");
                    (
                        State::Header(pdu::Header::read(sock)),
                        Ok(Async::Ready(Some(Query::Serial {
                            session: header.session(),
                            serial: payload.serial()
                        })))
                    )
                }
                State::Done => return Ok(Async::Ready(None))
            };
            self.state = state;
            match res {
                Ok(Async::NotReady) => { }
                _ => return res
            }
        }
    }
}

