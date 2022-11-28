//! The HTTP listener.

use std::io;
use std::convert::Infallible;
use std::future::Future;
use std::net::{SocketAddr, TcpListener as StdListener};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use futures::pin_mut;
use futures::future::{pending, select_all};
use hyper::Server;
use hyper::server::accept::Accept;
use hyper::service::{make_service_fn, service_fn};
use log::error;
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
use super::handle_request;


//------------ http_listener -------------------------------------------------

/// Returns a future for all HTTP server listeners.
pub fn http_listener(
    origins: SharedHistory,
    rtr_metrics: SharedRtrServerMetrics,
    log: Option<Arc<LogOutput>>,
    config: &Config,
) -> Result<impl Future<Output = ()>, ExitError> {
    let metrics = Arc::new(HttpServerMetrics::default());

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
    Ok(_http_listener(origins, metrics, rtr_metrics, log, listeners))
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
    origins: SharedHistory,
    metrics: Arc<HttpServerMetrics>,
    rtr_metrics: SharedRtrServerMetrics,
    log: Option<Arc<LogOutput>>,
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
                addr, tls_config, listener,
                origins.clone(), metrics.clone(),
                rtr_metrics.clone(), log.clone(),
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
    origins: SharedHistory,
    metrics: Arc<HttpServerMetrics>,
    rtr_metrics: SharedRtrServerMetrics,
    log: Option<Arc<LogOutput>>,
) {
    let make_service = make_service_fn(|_conn| {
        let origins = origins.clone();
        let metrics = metrics.clone();
        let rtr_metrics = rtr_metrics.clone();
        let log = log.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let origins = origins.clone();
                let metrics = metrics.clone();
                let rtr_metrics = rtr_metrics.clone();
                let log = log.clone();
                async move {
                    Ok::<_, Infallible>(handle_request(
                        req, &origins, &metrics, &rtr_metrics,
                        log.as_ref().map(|x| x.as_ref())
                    ).await.into_hyper())
                }
            }))
        }
    });
    let listener = HttpAccept {
        sock: match TcpListener::from_std(listener) {
            Ok(listener) => listener,
            Err(err) => {
                error!("Failed on listening on {}: {}", addr,err);
                return
            }
        },
        tls: tls_config.map(Into::into),
        metrics: metrics.clone(),
    };
    if let Err(err) = Server::builder(listener).serve(make_service).await {
        error!("Fatal error in HTTP server {}: {}", addr, err);
    }
}


//------------ Wrapped sockets for metrics -----------------------------------

struct HttpAccept {
    sock: TcpListener,
    tls: Option<TlsAcceptor>,
    metrics: Arc<HttpServerMetrics>,
}

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

