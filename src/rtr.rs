/// Support for the RPKI-to-Router Protocol.

use std::io;
use std::future::Future;
use std::net::TcpListener as StdListener;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use futures::pin_mut;
use futures::future::{pending, select_all};
use tokio_stream::Stream;
use log::error;
use rpki::rtr::server::{NotifySender, Server, Socket};
use rpki::rtr::state::State;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use crate::config::Config;
use crate::error::ExitError;
use crate::metrics::{SharedRtrServerMetrics, RtrClientMetrics};
use crate::payload::SharedHistory;


pub fn rtr_listener(
    history: SharedHistory,
    metrics: SharedRtrServerMetrics,
    config: &Config
) -> Result<(NotifySender, impl Future<Output = ()>), ExitError> {
    let sender = NotifySender::new();

    let mut listeners = Vec::new();
    for addr in &config.rtr_listen {
        // Binding needs to have happened before dropping privileges
        // during detach. So we do this here synchronously.
        let listener = match StdListener::bind(addr) {
            Ok(listener) => listener,
            Err(err) => {
                error!("Fatal error listening on {}: {}", addr, err);
                return Err(ExitError::Generic);
            }
        };
        if let Err(err) = listener.set_nonblocking(true) {
            error!("Fatal: error switching {} to nonblocking: {}", addr, err);
            return Err(ExitError::Generic);
        }
        listeners.push(listener);
    }
    Ok((sender.clone(), _rtr_listener(
        history, metrics, sender, listeners, config.rtr_tcp_keepalive,
    )))
}

async fn _rtr_listener(
    origins: SharedHistory,
    metrics: SharedRtrServerMetrics,
    sender: NotifySender,
    listeners: Vec<StdListener>,
    keepalive: Option<Duration>,
) {
    if listeners.is_empty() {
        pending::<()>().await;
    }
    else {
        let _ = select_all(
            listeners.into_iter().map(|listener| {
                tokio::spawn(single_rtr_listener(
                    listener, origins.clone(), metrics.clone(),
                    sender.clone(), keepalive,
                ))
            })
        ).await;
    }
}

async fn single_rtr_listener(
    listener: StdListener,
    origins: SharedHistory,
    metrics: SharedRtrServerMetrics,
    sender: NotifySender,
    _keepalive: Option<Duration>,
) {
    let listener = RtrListener {
        sock: match TcpListener::from_std(listener) {
            Ok(listener) => listener,
            Err(err) => {
                error!("Fatal error on RTR listener: {}", err);
                return;
            }
        },
        metrics,
        //keepalive,
    };
    if Server::new(listener, sender, origins.clone()).run().await.is_err() {
        error!("Fatal error listening for RTR connections.");
    }
}


struct RtrListener {
    sock: TcpListener,
    metrics: SharedRtrServerMetrics,

    // XXX Regression in Tokio 1.0: no more setting keepalive times.
    //keepalive: Option<Duration>,
}

impl Stream for RtrListener {
    type Item = Result<RtrStream, io::Error>;

    fn poll_next(
        mut self: Pin<&mut Self>, cx: &mut Context
    ) -> Poll<Option<Self::Item>> {
        let sock = &mut self.sock;
        pin_mut!(sock);

        match sock.poll_accept(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok((sock, addr))) => {
                let metrics = Arc::new(RtrClientMetrics::new(addr.ip()));

                let server_metrics = self.metrics.clone();
                let client_metrics = metrics.clone();
                tokio::spawn(async move {
                    server_metrics.add_client(client_metrics).await
                });

                Poll::Ready(Some(Ok(RtrStream { sock, metrics })))
            }
            Poll::Ready(Err(err)) => {
                Poll::Ready(Some(Err(err)))
            }
        }
    }
}

struct RtrStream {
    sock: TcpStream,
    metrics: Arc<RtrClientMetrics>,
}

impl Socket for RtrStream {
    fn update(&self, state: State, _reset: bool) {
        self.metrics.update_now(state.serial());
    }
}

impl AsyncRead for RtrStream {
    fn poll_read(
        mut self: Pin<&mut Self>, cx: &mut Context, buf: &mut ReadBuf
    ) -> Poll<Result<(), io::Error>> {
        let len = buf.filled().len();
        let sock = &mut self.sock;
        pin_mut!(sock);
        let res = sock.poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = res {
            self.metrics.inc_bytes_read(
                (buf.filled().len().saturating_sub(len)) as u64
            )    
        }
        res
    }
}

impl AsyncWrite for RtrStream {
    fn poll_write(
        mut self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]
    ) -> Poll<Result<usize, io::Error>> {
        let sock = &mut self.sock;
        pin_mut!(sock);
        let res = sock.poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = res {
            self.metrics.inc_bytes_written(n as u64)
        }
        res
    }

    fn poll_flush(
        mut self: Pin<&mut Self>, cx: &mut Context
    ) -> Poll<Result<(), io::Error>> {
        let sock = &mut self.sock;
        pin_mut!(sock);
        sock.poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>, cx: &mut Context
    ) -> Poll<Result<(), io::Error>> {
        let sock = &mut self.sock;
        pin_mut!(sock);
        sock.poll_shutdown(cx)
    }
}

impl Drop for RtrStream {
    fn drop(&mut self) {
        self.metrics.close()
    }
}

