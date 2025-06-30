//! Support for the RPKI-to-Router Protocol.

use std::io;
use std::future::Future;
use std::net::{SocketAddr, TcpListener as StdListener};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use futures::{pin_mut, Stream};
use futures::future::{pending, select_all};
use log::error;
use rpki::rtr::server::{NotifySender, Server, Socket};
use rpki::rtr::state::State;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use crate::config::Config;
use crate::error::ExitError;
use crate::metrics::{SharedRtrServerMetrics, RtrClientMetrics};
use crate::payload::SharedHistory;
use crate::utils::{net, tls};
use crate::utils::tls::MaybeTlsTcpStream;


//------------ rtr_listener --------------------------------------------------

/// Returns a future for all RTR listeners.
pub fn rtr_listener(
    history: SharedHistory,
    metrics: SharedRtrServerMetrics,
    config: &Config,
    sender: NotifySender,
    extra_listener: Option<StdListener>,
) -> Result<impl Future<Output = ()>, ExitError> {
    // Binding needs to have happened before dropping privileges
    // during detach. So we do this here synchronously.
    let mut listeners = Vec::new();
    if let Some(extra) = extra_listener {
        listeners.push((String::from("systemd socket"), None, extra));
    }
    for addr in &config.rtr_listen {
        listeners.push((format!("{addr}"), None, net::bind(addr)?));
    }
    if !config.rtr_tls_listen.is_empty() {
        let tls_config = create_tls_config(config)?;
        for addr in &config.rtr_tls_listen {
            listeners.push((
                format!("{addr}"),
                Some(tls_config.clone()),
                net::bind(addr)?
            ));
        }
    }
    Ok(_rtr_listener(
        history, metrics, sender, listeners, config.rtr_tcp_keepalive,
    ))
}

fn create_tls_config(
    config: &Config
) -> Result<Arc<tls::ServerConfig>, ExitError> {
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
    tls::create_server_config("RTR", key_path, cert_path).map(Arc::new)
}

async fn _rtr_listener(
    origins: SharedHistory,
    metrics: SharedRtrServerMetrics,
    sender: NotifySender,
    listeners: Vec<(String, Option<Arc<tls::ServerConfig>>, StdListener)>,
    keepalive: Option<Duration>,
) {
    // If there are no listeners, just never return.
    if listeners.is_empty() {
        pending::<()>().await;
        return;
    }

    let _ = select_all(
        listeners.into_iter().map(|(addr, tls, listener)| {
            tokio::spawn(single_rtr_listener(
                addr, tls, listener, origins.clone(), metrics.clone(),
                sender.clone(), keepalive,
            ))
        })
    ).await;
}

async fn single_rtr_listener(
    addr: String,
    tls: Option<Arc<tls::ServerConfig>>,
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
    let tls = tls.map(TlsAcceptor::from);
    let listener = RtrListener {
        tcp: listener, tls, keepalive, server_metrics
    };
    if let Err(err) = Server::new(
        listener, sender, origins.clone()
    ).run().await {
        error!("Fatal error in RTR server {}: {}", addr, err);
    }
}


//------------ RtrListener --------------------------------------------------

/// A wrapper around an TCP listener that produces RTR streams.
struct RtrListener {
    tcp: TcpListener,
    tls: Option<TlsAcceptor>,
    keepalive: Option<Duration>,
    server_metrics: SharedRtrServerMetrics,
}

impl Stream for RtrListener {
    type Item = Result<RtrStream, io::Error>;

    fn poll_next(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        match self.tcp.poll_accept(ctx) {
            Poll::Ready(Ok((sock, addr))) => {
                match RtrStream::new(
                    sock, addr,
                    self.tls.as_ref(), self.keepalive,
                    self.server_metrics.clone()
                ) {
                    Ok(stream) => Poll::Ready(Some(Ok(stream))),
                    Err(_) => Poll::Pending,
                }
            }
            Poll::Ready(Err(err)) => Poll::Ready(Some(Err(err))),
            Poll::Pending => Poll::Pending,
        }
    }
}

//------------ RtrStream ----------------------------------------------------

/// A wrapper around a stream socket that takes care of updating metrics.
struct RtrStream {
    sock: MaybeTlsTcpStream,
    metrics: Arc<RtrClientMetrics>,
}

impl RtrStream {
    #[allow(clippy::redundant_async_block)] // False positive
    fn new(
        sock: TcpStream,
        addr: SocketAddr,
        tls: Option<&TlsAcceptor>,
        keepalive: Option<Duration>,
        server_metrics: SharedRtrServerMetrics,
    ) -> Result<Self, io::Error> {
        if let Some(duration) = keepalive {
            Self::set_keepalive(&sock, duration)?
        }
        let metrics = Arc::new(RtrClientMetrics::new(addr.ip()));
        let client_metrics = metrics.clone();
        tokio::spawn(async move {
            server_metrics.add_client(client_metrics).await
        });
        Ok(RtrStream {
            sock: MaybeTlsTcpStream::new(sock, tls),
            metrics
        })
    }

    #[cfg(unix)]
    fn set_keepalive(
        sock: &TcpStream, duration: Duration
    ) -> Result<(), io::Error>{
        use nix::sys::socket::{setsockopt, sockopt};

        (|fd, duration: Duration| {
            setsockopt(fd, sockopt::KeepAlive, &true)?;

            // The attributes are copied from the definitions in
            // nix::sys::socket::sockopt. Let’s hope they never change.

            #[cfg(any(target_os = "ios", target_os = "macos"))]
            setsockopt(
                fd, sockopt::TcpKeepAlive,
                &u32::try_from(duration.as_secs()).unwrap_or(u32::MAX)
            )?;

            #[cfg(any(
                target_os = "android",
                target_os = "dragonfly",
                target_os = "freebsd",
                target_os = "linux",
            ))]
            setsockopt(
                fd, sockopt::TcpKeepIdle,
                &u32::try_from(duration.as_secs()).unwrap_or(u32::MAX)
            )?;

            #[cfg(not(target_os = "openbsd"))]
            setsockopt(
                fd, sockopt::TcpKeepInterval,
                &u32::try_from(duration.as_secs()).unwrap_or(u32::MAX)
            )?;

            Ok(())
        })(sock, duration).map_err(|err: nix::errno::Errno| {
            io::Error::other(err)
        })
    }

    #[cfg(not(unix))]
    fn set_keepalive(
        _sock: &TcpStream, _duration: Duration
    ) -> Result<(), io::Error>{
        Ok(())
    }
}

impl Socket for RtrStream {
    fn update(&self, state: State, reset: bool) {
        self.metrics.update_now(state.serial(), reset);
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

