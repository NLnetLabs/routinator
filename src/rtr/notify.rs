//! Sending of cache update notifications.

use std::sync::{Arc, Mutex};
use futures::{Async, Future, Poll, Stream};
use futures::sync::mpsc::{channel, Receiver, Sender};
use slab::Slab;


//------------ NotifySender --------------------------------------------------

#[derive(Clone, Debug)]
pub struct NotifySender {
    tx: Sender<Message>,
}

impl NotifySender {
    pub fn notify(&mut self) {
        // Each sender gets one guaranteed message. Since we only ever send
        // notify messages, if we can’t queue a message, there’s already an
        // unprocessed notification and we are fine.
        let _ = self.tx.try_send(Message::Notify);
    }
}


//------------ NotifyReceiver ------------------------------------------------

#[derive(Debug)]
pub struct NotifyReceiver {
    rx: Option<Receiver<()>>,
    tx: Sender<Message>,
    id: usize,
}

impl Stream for NotifyReceiver {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        match self.rx {
            None => return Ok(Async::NotReady),
            Some(ref mut rx) => {
                match rx.poll() {
                    Err(_) => { }
                    res => return res
                }
            }
        }
        self.rx = None;
        Ok(Async::NotReady)
    }
}

impl Drop for NotifyReceiver {
    fn drop(&mut self) {
        let _ = self.tx.try_send(Message::Close(self.id));
    }
}


//------------ Dispatch ------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Dispatch(Arc<Mutex<DispatchInner>>);

#[derive(Clone, Debug)]
struct DispatchInner {
    connections: Slab<Sender<()>>,
    tx: Sender<Message>,
}

impl Dispatch {
    pub fn new() -> (Self, DispatchFuture) {
        let (tx, rx) = channel(0);
        let dispatch = Dispatch(Arc::new(Mutex::new(
            DispatchInner {
                connections: Slab::new(),
                tx,
            }
        )));
        let fut = DispatchFuture {
            dispatch: dispatch.clone(),
            rx: Some(rx)
        };
        (dispatch, fut)
    }

    pub fn get_sender(&self) -> NotifySender {
        NotifySender {
            tx: self.0.lock().unwrap().tx.clone()
        }
    }

    pub fn get_receiver(&mut self) -> NotifyReceiver {
        let (tx, rx) = channel(0);
        let mut inner = self.0.lock().unwrap();
        NotifyReceiver {
            rx: Some(rx),
            tx: inner.tx.clone(),
            id: inner.connections.insert(tx),
        }
    }

    fn notify(&mut self) {
        self.0.lock().unwrap().connections.retain(|_, tx| {
            match tx.try_send(()) {
                Ok(()) => true,
                Err(err) => !err.is_disconnected()
            }
        })
    }

    fn close(&mut self, id: usize) {
        let _ = self.0.lock().unwrap().connections.remove(id);
    }
}


//------------ DispatchFuture ------------------------------------------------

pub struct DispatchFuture {
    dispatch: Dispatch,
    rx: Option<Receiver<Message>>,
}

impl Future for DispatchFuture {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            let msg = match self.rx {
                None => return Ok(Async::NotReady),
                Some(ref mut rx) => {
                    match rx.poll() {
                        Ok(Async::NotReady) => return Ok(Async::NotReady),
                        Ok(Async::Ready(Some(msg))) => Some(msg),
                        _ => None
                    }
                }
            };
            match msg {
                Some(Message::Notify) => self.dispatch.notify(),
                Some(Message::Close(id)) => self.dispatch.close(id),
                None => {
                    self.rx = None;
                }
            }
        }
    }
}


//------------ Message -------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum Message {
    // Send a new notification, please.
    Notify,

    // The connection with the given index is done.
    Close(usize),
}

