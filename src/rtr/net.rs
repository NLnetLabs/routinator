//! Listener and connections.

use std::mem;
use std::net::SocketAddr;
use std::time::SystemTime;
use futures::future;
use futures::{Async, Future, IntoFuture, Stream};
use tokio;
use tokio::io::{AsyncRead, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use ::config::Config;
use ::origins::OriginsHistory;
use super::send::Sender;
use super::query::{Input, InputStream, Query};
use super::notify::{Dispatch, NotifyReceiver, NotifySender};


//------------ rtr_listener --------------------------------------------------

pub fn rtr_listener(
    history: OriginsHistory,
    config: &'static Config,
) -> (NotifySender, impl Future<Item=(), Error=()>) {
    let session = session_id();
    let (dispatch, dispatch_fut) = Dispatch::new();
    let fut = dispatch_fut.select(
        future::select_all(
            config.rtr_listen.iter().map(|addr| {
                single_listener(
                    *addr, session, history.clone(),
                    dispatch.clone(), config
                )
            })
        ).then(|_| Ok(()))
    ).then(|_| Ok(()));
    (dispatch.get_sender(), fut)
}

fn session_id() -> u16 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH).unwrap()
        .as_secs() as u16
}

fn single_listener(
    addr: SocketAddr,
    session: u16,
    history: OriginsHistory,
    mut dispatch: Dispatch,
    config: &'static Config,
) -> impl Future<Item=(), Error=()> {
    TcpListener::bind(&addr).into_future()
    .map_err(move |err| error!("Failed to bind RTR listener {}: {}", addr, err))
    .and_then(move |listener| {
        listener.incoming()
        .map_err(|err| error!("Failed to accept connection: {}", err))
        .for_each(move |sock| {
            let notify = dispatch.get_receiver();
            tokio::spawn(
                Connection::new(
                    sock, session, history.clone(), notify,
                    config
                )
            )
        })
    })
}


//------------ Connection ----------------------------------------------------

struct Connection {
    input: InputStream<ReadHalf<TcpStream>>,
    output: OutputState,
    session: u16,
    history: OriginsHistory,
    config: &'static Config,
}

enum OutputState {
    Idle(WriteHalf<TcpStream>),
    Sending(Sender<WriteHalf<TcpStream>>),
    Done
}

impl Connection {
    pub fn new(
        sock: TcpStream,
        session: u16,
        history: OriginsHistory,
        notify: NotifyReceiver,
        config: &'static Config,
    ) -> Self {
        let (read, write) = sock.split();
        Connection {
            input: InputStream::new(read, notify),
            output: OutputState::Idle(write),
            session, history, config
        }
    }

    fn send(&mut self, input: Input) {
        let sock = match mem::replace(&mut self.output, OutputState::Done) {
            OutputState::Idle(sock) => sock,
            _ => panic!("illegal output state"),
        };
        let send = match input {
            Input::Query(Query::Serial { session, serial }) => {
                let diff = if session == self.session {
                    self.history.get(serial)
                }
                else { None };
                match diff {
                    Some(diff) => {
                        Sender::diff(
                            sock, self.input.version(), session, diff,
                            self.config
                        ) 
                    }
                    None => {
                        Sender::reset(sock, self.input.version())
                    }
                }
            }
            Input::Query(Query::Reset) => {
                let (current, serial) = self.history.current_and_serial();
                Sender::full(
                    sock, self.input.version(), self.session, serial, current,
                    self.config
                )
            }
            Input::Query(Query::Error(err)) => Sender::error(sock, err),
            Input::Notify => {
                let serial = self.history.serial();
                Sender::notify(
                    sock, self.input.version(),self.session, serial
                )
            }
        };
        self.output = OutputState::Sending(send);
    }
}

impl Future for Connection {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
        loop {
            let next = match self.output {
                OutputState::Sending(ref mut send) => {
                    let sock = try_ready!(send.poll());
                    Err(sock)
                }
                OutputState::Idle(_) => {
                    // We need to wait for input.
                    println!("waiting");
                    match try_ready!(self.input.poll()) {
                        Some(input) => Ok(input),
                        None => return Ok(Async::Ready(()))
                    }
                }
                OutputState::Done => panic!("illegal output state")
            };
            match next {
                Err(sock) => {
                    println!("Going idle");
                    self.output = OutputState::Idle(sock);
                }
                Ok(input) => {
                    self.send(input)
                }
            }
        }
    }
}

