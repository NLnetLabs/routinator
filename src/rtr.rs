/// Support for the RPKI-to-Router Protocol.

use std::io;
use std::future::Future;
use std::net::{SocketAddr, TcpListener as StdListener};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use futures::{pin_mut, ready, StreamExt, TryStreamExt, TryFuture};
use futures::future::{pending, select_all};
use log::error;
use pin_project_lite::pin_project;
use rpki::rtr::server::{NotifySender, Server, Socket};
use rpki::rtr::state::State;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{Accept, TlsAcceptor};
use tokio_rustls::server::TlsStream;
use tokio_stream::wrappers::TcpListenerStream;
use crate::config::Config;
use crate::error::ExitError;
use crate::metrics::{SharedRtrServerMetrics, RtrClientMetrics};
use crate::payload::SharedHistory;
use crate::utils::tls;


//------------ Listener Functions --------------------------------------------

pub fn rtr_listener(
    history: SharedHistory,
    metrics: SharedRtrServerMetrics,
    config: &Config
) -> Result<(NotifySender, impl Future<Output = ()>), ExitError> {
    let sender = NotifySender::new();

    // Binding needs to have happened before dropping privileges
    // during detach. So we do this here synchronously.
    let mut listeners = Vec::new();
    for addr in &config.rtr_listen {
        listeners.push((*addr, bind(addr)?));
    }
    let mut tls_listeners = Vec::new();
    if !config.rtr_tls_listen.is_empty() {
        let key_path = match config.rtr_tls_key.as_ref() {
            Some(path) => path.as_ref(),
            None => {
                error!("Missing rtr-tls-key option for RTR TLS server.");
                return Err(ExitError::Generic)
            }
        };
        let cert_path = match config.rtr_tls_cert.as_ref() {
            Some(path) => path.as_ref(),
            None => {
                error!("Missing rtr-tls-cert option for RTR TLS server.");
                return Err(ExitError::Generic)
            }
        };
        let tls_config = tls::create_server_config(
            "RTR", key_path, cert_path
        ).map(Arc::new)?;
        for addr in &config.rtr_tls_listen {
            tls_listeners.push(
                (tls_config.clone(), *addr, bind(addr)?)
            );
        }
    }
    Ok((sender.clone(), _rtr_listener(
        history, metrics, sender,
        listeners, tls_listeners,
        config.rtr_tcp_keepalive,
    )))
}

async fn _rtr_listener(
    origins: SharedHistory,
    metrics: SharedRtrServerMetrics,
    sender: NotifySender,
    listeners: Vec<(SocketAddr, StdListener)>,
    tls_listeners: Vec<(Arc<tls::ServerConfig>, SocketAddr, StdListener)>,
    keepalive: Option<Duration>,
) {
    if listeners.is_empty() && tls_listeners.is_empty() {
        pending::<()>().await;
        return;
    }

    let _ = select_all(
        listeners.into_iter().map(|(addr, listener)| {
            tokio::spawn(single_rtr_listener(
                addr, listener, origins.clone(), metrics.clone(),
                sender.clone(), keepalive,
            ))
        }).chain(
            tls_listeners.into_iter().map(|(tls, addr, listener)| {
                tokio::spawn(single_rtr_tls_listener(
                    tls, addr, listener,
                    origins.clone(), metrics.clone(), sender.clone(),
                    keepalive,
                ))
            })
        )
    ).await;
}

async fn single_rtr_listener(
    addr: SocketAddr,
    listener: StdListener,
    origins: SharedHistory,
    server_metrics: SharedRtrServerMetrics,
    sender: NotifySender,
    keepalive: Option<Duration>,
) {
    let listener = match TcpListener::from_std(listener) {
        Ok(listener) => listener,
        Err(err) => {
            error!("Fatal error listening on {}: {}", addr, err);
            return;
        }
    };
    let listener = TcpListenerStream::new(listener).and_then(|sock| async {
        RtrStream::new(sock, keepalive, server_metrics.clone())
    }).boxed();
    if Server::new(listener, sender, origins.clone()).run().await.is_err() {
        error!("Fatal error listening for RTR connections.");
    }
}

async fn single_rtr_tls_listener(
    tls: Arc<tls::ServerConfig>,
    addr: SocketAddr,
    listener: StdListener,
    origins: SharedHistory,
    server_metrics: SharedRtrServerMetrics,
    sender: NotifySender,
    keepalive: Option<Duration>,
) {
    let listener = match TcpListener::from_std(listener) {
        Ok(listener) => listener,
        Err(err) => {
            error!("Fatal error listening on {}: {}", addr, err);
            return;
        }
    };
    let acceptor = TlsAcceptor::from(tls);
    let listener = TcpListenerStream::new(listener).and_then(|sock| async {
        RtrStream::new(
            sock, keepalive, server_metrics.clone()
        ).map(|stream| RtrTlsStream::new(&acceptor, stream))
    }).boxed();
    if Server::new(listener, sender, origins.clone()).run().await.is_err() {
        error!("Fatal error listening for RTR connections.");
    }
}

fn bind(addr: &SocketAddr) -> Result<StdListener, ExitError> {
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
    Ok(listener)
}


//------------ RtrStream ----------------------------------------------------

/// A wrapper around a stream socket that takes care of updating metrics.
struct RtrStream {
    sock: TcpStream,
    metrics: Arc<RtrClientMetrics>,
}

impl RtrStream {
    fn new(
        sock: TcpStream,
        _keepalive: Option<Duration>,
        server_metrics: SharedRtrServerMetrics,
    ) -> Result<Self, io::Error> {
        let metrics = Arc::new(RtrClientMetrics::new(sock.local_addr()?.ip()));
        let client_metrics = metrics.clone();
        tokio::spawn(async move {
            server_metrics.add_client(client_metrics).await
        });
        Ok(RtrStream { sock, metrics})
    }
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


//----------- RtrTlsStream ---------------------------------------------------

pin_project! {
    #[project = RtrTlsStreamProj]
    enum RtrTlsStream {
        Accept { #[pin] fut: Accept<RtrStream> },
        Stream { #[pin] fut: TlsStream<RtrStream> },
        Empty,
    }
}

impl RtrTlsStream {
    fn new(acceptor: &TlsAcceptor, sock: RtrStream) -> Self {
        Self::Accept { fut: acceptor.accept(sock) }
    }

    fn poll_accept(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Pin<&mut Self>, io::Error>> {
        match self.as_mut().project() {
            RtrTlsStreamProj::Accept { fut } => {
                match ready!(fut.try_poll(cx)) {
                    Ok(fut) => {
                        self.set(Self::Stream { fut });
                        Poll::Ready(Ok(self))
                    }
                    Err(err) => {
                        self.set(Self::Empty);
                        Poll::Ready(Err(err))
                    }
                }
            }
            RtrTlsStreamProj::Stream { .. } => Poll::Ready(Ok(self)),
            RtrTlsStreamProj::Empty => panic!("polling a concluded future")
        }
    }
}

impl rpki::rtr::server::Socket for RtrTlsStream { }

impl AsyncRead for RtrTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>
    ) -> Poll<Result<(), io::Error>> {
        let mut this = match ready!(self.poll_accept(cx)) {
            Ok(this) => this,
            Err(err) => return Poll::Ready(Err(err))
        };
        match this.as_mut().project() {
            RtrTlsStreamProj::Stream { fut } => {
                fut.poll_read(cx, buf)
            }
            _ => unreachable!()
        }
    }
}

impl AsyncWrite for RtrTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8]
    ) -> Poll<Result<usize, io::Error>> {
        let mut this = match ready!(self.poll_accept(cx)) {
            Ok(this) => this,
            Err(err) => return Poll::Ready(Err(err))
        };
        match this.as_mut().project() {
            RtrTlsStreamProj::Stream { fut } => {
                fut.poll_write(cx, buf)
            }
            _ => unreachable!()
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>
    ) -> Poll<Result<(), io::Error>> {
        let mut this = match ready!(self.poll_accept(cx)) {
            Ok(this) => this,
            Err(err) => return Poll::Ready(Err(err))
        };
        match this.as_mut().project() {
            RtrTlsStreamProj::Stream { fut } => {
                fut.poll_flush(cx)
            }
            _ => unreachable!()
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>
    ) -> Poll<Result<(), io::Error>> {
        let mut this = match ready!(self.poll_accept(cx)) {
            Ok(this) => this,
            Err(err) => return Poll::Ready(Err(err))
        };
        match this.as_mut().project() {
            RtrTlsStreamProj::Stream { fut } => {
                fut.poll_shutdown(cx)
            }
            _ => unreachable!()
        }
    }
}

