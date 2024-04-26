//! The HTTP listener.

use std::io;
use std::future::Future;
use std::net::{SocketAddr, TcpListener as StdListener};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use futures::pin_mut;
use futures::future::{pending, select_all};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use log::error;
use rpki::rtr::server::NotifySender;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use crate::config::Config;
use crate::error::ExitError;
use crate::metrics::{HttpServerMetrics, SharedRtrServerMetrics};
use crate::payload::SharedHistory;
use crate::process::LogOutput;
use crate::utils::{net, tls};
use crate::utils::tls::MaybeTlsTcpStream;
use super::dispatch::State;


//------------ http_listener -------------------------------------------------

/// Returns a future for all HTTP server listeners.
pub fn http_listener(
    origins: SharedHistory,
    rtr_metrics: SharedRtrServerMetrics,
    log: Option<Arc<LogOutput>>,
    config: &Config,
    notify: NotifySender,
) -> Result<impl Future<Output = ()>, ExitError> {
    let state = Arc::new(
        State::new(config, origins, rtr_metrics, log, notify)
    );

    // Binding needs to have happened before dropping privileges
    // during detach. So we do this here synchronously.
    let mut listeners = Vec::new();
    for addr in &config.http_listen {
        listeners.push((*addr, None, net::bind(addr)?));
    }
    if !config.http_tls_listen.is_empty() {
        let tls_config = create_tls_config(config)?;
        for addr in &config.http_tls_listen {
            listeners.push(
                (*addr, Some(tls_config.clone()), net::bind(addr)?)
            );
        }
    }
    Ok(_http_listener(state, listeners))
}

fn create_tls_config(
    config: &Config
) -> Result<Arc<tls::ServerConfig>, ExitError> {
    let key_path = match config.http_tls_key.as_ref() {
        Some(path) => path.as_ref(),
        None => {
            error!("Missing http-tls-key option for HTTP TLS server.");
            return Err(ExitError::Generic)
        }
    };
    let cert_path = match config.http_tls_cert.as_ref() {
        Some(path) => path.as_ref(),
        None => {
            error!("Missing http-tls-cert option for HTTP TLS server.");
            return Err(ExitError::Generic)
        }
    };
    tls::create_server_config("HTTP", key_path, cert_path).map(Arc::new)
}

async fn _http_listener(
    state: Arc<State>,
    listeners: Vec<(SocketAddr, Option<Arc<tls::ServerConfig>>, StdListener)>,
) {
    // If there are no listeners, just never return.
    if listeners.is_empty() {
        pending::<()>().await;
        return;
    }

    let _ = select_all(
        listeners.into_iter().map(|(addr, tls_config, listener)| {
            tokio::spawn(single_http_listener(
                addr, tls_config, listener, state.clone(),
            ))
        })
    ).await;
}

/// Returns a future for a single HTTP listener.
///
/// The future will never resolve unless an error happens that breaks the
/// listener, in which case it will print an error and resolve the error case.
/// It will listen bind a Hyper server onto `addr` and produce any data
/// served from `origins`.
async fn single_http_listener(
    addr: SocketAddr,
    tls_config: Option<Arc<tls::ServerConfig>>,
    listener: StdListener,
    state: Arc<State>,
) {
    let listener = HttpAccept {
        sock: match TcpListener::from_std(listener) {
            Ok(listener) => listener,
            Err(err) => {
                error!("Failed on listening on {}: {}", addr,err);
                return
            }
        },
        tls: tls_config.map(Into::into),
        metrics: state.metrics().clone(),
    };
    loop {
        let stream = match listener.accept().await {
            Ok(some) => some,
            Err(err) => {
                error!("Fatal error in HTTP server {}: {}", addr, err);
                break;
            }
        };
        let service_state = state.clone();
        tokio::task::spawn(async move {
            let _ = hyper_util::server::conn::auto::Builder::new(
                TokioExecutor::new()
            ).serve_connection(
                TokioIo::new(stream),
                service_fn(move |req| {
                    let state = service_state.clone();
                    async move {
                        state.handle_request(req.into()).await.into_hyper()
                    }
                })
            ).await;
        });
    }
}


//------------ Wrapped sockets for metrics -----------------------------------

struct HttpAccept {
    sock: TcpListener,
    tls: Option<TlsAcceptor>,
    metrics: Arc<HttpServerMetrics>,
}

impl HttpAccept {
    async fn accept(&self) -> Result<HttpStream, io::Error> {
        let (sock, _) = self.sock.accept().await?;
        self.metrics.inc_conn_open();
        Ok(HttpStream {
            sock: MaybeTlsTcpStream::new(sock, self.tls.as_ref()),
            metrics: self.metrics.clone()
        })
    }
}

/*
impl Accept for HttpAccept {
    type Conn = HttpStream;
    type Error = io::Error;

    fn poll_accept(
        mut self: Pin<&mut Self>,
        cx: &mut Context
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        let sock = &mut self.sock;
        pin_mut!(sock);
        match sock.poll_accept(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok((sock, _addr))) => {
                self.metrics.inc_conn_open();
                Poll::Ready(Some(Ok(HttpStream {
                    sock: MaybeTlsTcpStream::new(sock, self.tls.as_ref()),
                    metrics: self.metrics.clone()
                })))
            }
            Poll::Ready(Err(err)) => {
                Poll::Ready(Some(Err(err)))
            }
        }
    }
}
*/


struct HttpStream {
    sock: MaybeTlsTcpStream,
    metrics: Arc<HttpServerMetrics>,
}

impl AsyncRead for HttpStream {
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

impl AsyncWrite for HttpStream {
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

impl Drop for HttpStream {
    fn drop(&mut self) {
        self.metrics.inc_conn_close()
    }
}

