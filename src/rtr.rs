/// Support for the RPKI-to-Router Protocol.

use std::future::Future;
use std::net::SocketAddr;
use futures::future::select_all;
use log::error;
use rpki_rtr::server::{Dispatch, DispatchRunner, NotifySender, Server};
use tokio::net::TcpListener;
use crate::config::Config;
use crate::origins::OriginsHistory;


pub fn rtr_listener<'a>(
    history: OriginsHistory,
    config: &Config
) -> (NotifySender, impl Future<Output = ()>) {
    let dispatch_rnr = DispatchRunner::new();
    let dispatch = dispatch_rnr.dispatch();
    let sender = dispatch.get_sender();
    let addrs = config.rtr_listen.clone();
    (sender, _rtr_listener(history, dispatch, addrs))
}

async fn _rtr_listener(
    origins: OriginsHistory,
    dispatch: Dispatch,
    addrs: Vec<SocketAddr>,
) {
    let _ = select_all(
        addrs.iter().map(|addr| {
            tokio::spawn(single_rtr_listener(
                *addr, origins.clone(), dispatch.clone()
            ))
        })
    );
}

async fn single_rtr_listener(
    addr: SocketAddr,
    origins: OriginsHistory,
    dispatch: Dispatch,
) {
    let mut listener = match TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(err) => {
            error!("Fatal error listening on {}: {}", addr, err);
            return 
        }
    };
    let listener = listener.incoming();
    if Server::new(listener, dispatch, origins.clone()).run().await.is_err() {
        error!("Fatal error listening on {}.", addr);
    }
}

