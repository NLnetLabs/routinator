/// Support for the RPKI-to-Router Protocol.

use std::future::Future;
use std::net::SocketAddr;
use futures::future::{pending, select_all};
use log::error;
use rpki_rtr::server::{NotifySender, Server};
use tokio::net::TcpListener;
use crate::config::Config;
use crate::origins::OriginsHistory;


pub fn rtr_listener(
    history: OriginsHistory,
    config: &Config
) -> (NotifySender, impl Future<Output = ()>) {
    let sender = NotifySender::new();
    let addrs = config.rtr_listen.clone();
    (sender.clone(), _rtr_listener(history, sender, addrs))
}

async fn _rtr_listener(
    origins: OriginsHistory,
    sender: NotifySender,
    addrs: Vec<SocketAddr>,
) {
    if addrs.is_empty() {
        pending::<()>().await;
    }
    else {
        let _ = select_all(
            addrs.iter().map(|addr| {
                tokio::spawn(single_rtr_listener(
                    *addr, origins.clone(), sender.clone()
                ))
            })
        ).await;
    }
}

async fn single_rtr_listener(
    addr: SocketAddr,
    origins: OriginsHistory,
    sender: NotifySender,
) {
    let mut listener = match TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(err) => {
            error!("Fatal error listening on {}: {}", addr, err);
            return 
        }
    };
    let listener = listener.incoming();
    if Server::new(listener, sender, origins.clone()).run().await.is_err() {
        error!("Fatal error listening on {}.", addr);
    }
}

