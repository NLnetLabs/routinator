//! Sending messages to the RTR client.

use std::io;
use std::sync::Arc;
use futures::{Async, Future};
use tokio::io::{AsyncWrite, WriteAll};
use ::config::Config;
use ::origins::{AddressOrigins, OriginsDiff};
use super::pdu;


//------------ Sender --------------------------------------------------------

pub enum Sender<A> {
    Notify(WriteAll<A, pdu::SerialNotify>),
    Reset(WriteAll<A, pdu::CacheReset>),
    Diff(Wrapped<A, SendDiff>),
    Full(Wrapped<A, SendFull>),
    Error(WriteAll<A, pdu::BoxedError>),
}

impl<A: AsyncWrite> Sender<A> {
    pub fn notify(sock: A, version: u8, session: u16, serial: u32) -> Self {
        Sender::Notify(
            pdu::SerialNotify::new(version, session, serial).write(sock)
        )
    }

    pub fn reset(sock: A, version: u8) -> Self {
        Sender::Reset(pdu::CacheReset::new(version).write(sock))
    }

    pub fn diff(
        sock: A,
        version: u8,
        session: u16,
        diff: Arc<OriginsDiff>,
        config: &Config,
    ) -> Self {
        Sender::Diff(Wrapped::new(
            sock, version, session, diff.serial(),
            SendDiff::new(version, diff),
            config
        ))
    }

    pub fn full(
        sock: A,
        version: u8,
        session: u16,
        serial: u32,
        current: Arc<AddressOrigins>,
        config: &Config,
    ) -> Self {
        Sender::Full(Wrapped::new(
            sock, version, session, serial,
            SendFull::new(version, current),
            config
        ))
    }

    pub fn error(sock: A, error: pdu::BoxedError) -> Self {
        Sender::Error(error.write(sock))
    }

    fn real_poll(&mut self) -> Result<Async<A>, io::Error> {
        match *self {
            Sender::Notify(ref mut fut) => {
                let (sock, _) = try_ready!(fut.poll());
                Ok(Async::Ready(sock))
            }
            Sender::Reset(ref mut fut) => {
                let (sock, _) = try_ready!(fut.poll());
                Ok(Async::Ready(sock))
            }
            Sender::Diff(ref mut fut) => {
                Ok(Async::Ready(try_ready!(fut.poll())))
            }
            Sender::Full(ref mut fut) => {
                Ok(Async::Ready(try_ready!(fut.poll())))
            }
            Sender::Error(ref mut fut) => {
                try_ready!(fut.poll());
                // Force the connection to close.
                Err(io::Error::new(io::ErrorKind::Other, ""))
            }
        }
    }
}

impl<A: AsyncWrite> Future for Sender<A> {
    type Item = A;
    type Error = ();

    fn poll(&mut self) -> Result<Async<A>, ()> {
        self.real_poll().map_err(|err| {
            debug!("RTR write error: {}", err);
            ()
        })
    }
}


//------------ Wrapped ---------------------------------------------------

pub enum Wrapped<A, D> {
    Head(WriteAll<A, pdu::CacheResponse>, Option<(D, pdu::EndOfData)>),
    Middle(WriteAll<A, pdu::Prefix>, D, Option<pdu::EndOfData>),
    Tail(WriteAll<A, pdu::EndOfData>),
}

impl<A: AsyncWrite, D> Wrapped<A, D> {
    fn new(
        sock: A,
        version: u8,
        session: u16,
        serial: u32,
        iter: D,
        config: &Config
    ) -> Self {
        Wrapped::Head(
            pdu::CacheResponse::new(version, session).write(sock),
            Some((
                iter,
                pdu::EndOfData::new(
                    version, session, serial,
                    config.refresh.as_secs() as u32,
                    config.retry.as_secs() as u32,
                    config.expire.as_secs() as u32
                )
            ))
        )
    }
}


impl<A, D> Future for Wrapped<A, D>
where A: AsyncWrite, D: Iterator<Item=pdu::Prefix> {
    type Item = A;
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
        loop {
            *self = match *self {
                Wrapped::Head(ref mut fut, ref mut next) => {
                    let (sock, _) = try_ready!(fut.poll());
                    let (mut iter, tail) = next.take().unwrap();
                    match iter.next() {
                        Some(pdu) => {
                            Wrapped::Middle(
                                pdu.write(sock), iter, Some(tail)
                            )
                        }
                        None => Wrapped::Tail(tail.write(sock))
                    }
                }
                Wrapped::Middle(ref mut fut, ref mut iter, ref mut nx) => {
                    let (sock, _) = try_ready!(fut.poll());
                    match iter.next() {
                        Some(pdu) => {
                            *fut = pdu.write(sock);
                            continue;
                        }
                        None => {
                            let tail = nx.take().unwrap();
                            Wrapped::Tail(tail.write(sock))
                        }
                    }
                }
                Wrapped::Tail(ref mut fut) => {
                    let (sock, _) = try_ready!(fut.poll());
                    return Ok(Async::Ready(sock))
                }
            }
        }
    }
}


//------------ SendDiff ------------------------------------------------------

pub struct SendDiff {
    version: u8,
    diff: Arc<OriginsDiff>,
    announce: bool,
    next_idx: usize,
}

impl SendDiff {
    fn new(version: u8, diff: Arc<OriginsDiff>) -> Self {
        SendDiff {
            version,
            diff,
            announce: true,
            next_idx: 0
        }
    }
}

impl Iterator for SendDiff {
    type Item = pdu::Prefix;

    fn next(&mut self) -> Option<Self::Item> {
        if self.announce {
            if self.next_idx >= self.diff.announce().len() {
                self.announce = false;
                self.next_idx = 1; // We return the 0th item right away.
                self.diff.withdraw().first().map(|orig| {
                    pdu::Prefix::new(self.version, 0, orig)
                })
            }
            else {
                let res = &self.diff.announce()[self.next_idx];
                self.next_idx += 1;
                Some(pdu::Prefix::new(self.version, 1, res))
            }
        }
        else {
            if self.next_idx >= self.diff.withdraw().len() {
                None
            }
            else {
                let res = &self.diff.withdraw()[self.next_idx];
                self.next_idx += 1;
                Some(pdu::Prefix::new(self.version, 0, res))
            }
        }
    }
}


//------------ SendFull ------------------------------------------------------

pub struct SendFull {
    version: u8,
    origins: Arc<AddressOrigins>,
    next_idx: usize,
}

impl SendFull {
    pub fn new(version: u8, origins: Arc<AddressOrigins>) -> Self {
        SendFull {
            version, origins,
            next_idx: 0
        }
    }
}

impl Iterator for SendFull {
    type Item = pdu::Prefix;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(res ) = self.origins.get(self.next_idx) {
            self.next_idx += 1;
            Some(pdu::Prefix::new(self.version, 1, res))
        }
        else {
            None
        }
    }
}

