//! Utility functions for dealing with TLS.

use std::io;
use std::fs::File;
use std::path::Path;
use std::pin::Pin;
use std::task::{Context, Poll};
use log::error;
use futures::{pin_mut, ready, TryFuture};
use futures::future::Either;
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::{Accept, TlsAcceptor};
use tokio_rustls::rustls::{Certificate, PrivateKey};
use tokio_rustls::server::TlsStream;
use crate::error::ExitError;

pub use tokio_rustls::rustls::ServerConfig;


//------------ create_server_config -----------------------------------------

/// Creates the TLS server config.
///
/// The service this config is for should be given through `service`. This is
/// used for logging.
pub fn create_server_config(
    service: &str, key_path: &Path, cert_path: &Path
) -> Result<ServerConfig, ExitError> {
    let certs = rustls_pemfile::certs(
        &mut io::BufReader::new(
            File::open(cert_path).map_err(|err| {
                error!(
                    "Failed to open TLS certificate file '{}': {}.",
                    cert_path.display(), err
                );
                ExitError::Generic
            })?
        )
    ).map_err(|err| {
        error!(
            "Failed to read TLS certificate file '{}': {}.",
            cert_path.display(), err
        );
        ExitError::Generic
    }).map(|mut certs| {
        certs.drain(..).map(Certificate).collect()
    })?;

    let key = rustls_pemfile::pkcs8_private_keys(
        &mut io::BufReader::new(
            File::open(key_path).map_err(|err| {
                error!(
                    "Failed to open TLS key file '{}': {}.",
                    key_path.display(), err
                );
                ExitError::Generic
            })?
        )
    ).map_err(|err| {
        error!(
            "Failed to read TLS key file '{}': {}.",
            key_path.display(), err
        );
        ExitError::Generic
    }).and_then(|mut certs| {
        if certs.is_empty() {
            error!(
                "TLS key file '{}' does not contain any usable keys.",
                key_path.display()
            );
            return Err(ExitError::Generic)
        }
        if certs.len() != 1 {
            error!(
                "TLS key file '{}' contains multiple keys.",
                key_path.display()
            );
            return Err(ExitError::Generic)
        }
        Ok(PrivateKey(certs.pop().unwrap()))
    })?;

    ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| {
            error!("Failed to create {} TLS server config: {}", service, err);
            ExitError::Generic
        })
}


//------------ TlsTcpStream --------------------------------------------------

pin_project! {
    /// A TLS stream that behaves like a regular TCP stream.
    ///
    /// Specifically, `AsyncRead` and `AsyncWrite` will return `Poll::NotReady`
    /// until the TLS accept machinery has concluded.
    #[project = TlsTcpStreamProj]
    enum TlsTcpStream {
        /// The TLS handshake is going on.
        Accept { #[pin] fut: Accept<TcpStream> },

        /// We have a working TLS stream.
        Stream { #[pin] fut: TlsStream<TcpStream> },

        /// TLS handshake has failed.
        ///
        /// Because hyper still wants to do a clean flush and shutdown, we
        /// need to still work in this state. For read and write, we just
        /// keep returning the clean shutdown indiciation of zero length
        /// operations.
        Empty,
    }
}

impl TlsTcpStream {
    fn new(sock: TcpStream, tls: &TlsAcceptor) -> Self {
        Self::Accept { fut: tls.accept(sock) }
    }

    fn poll_accept(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Pin<&mut Self>, io::Error>> {
        match self.as_mut().project() {
            TlsTcpStreamProj::Accept { fut } => {
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
            _ => Poll::Ready(Ok(self)),
        }
    }
}

impl AsyncRead for TlsTcpStream {
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
            TlsTcpStreamProj::Stream { fut } => {
                fut.poll_read(cx, buf)
            }
            TlsTcpStreamProj::Empty => { Poll::Ready(Ok(())) }
            _ => unreachable!()
        }
    }
}

impl AsyncWrite for TlsTcpStream {
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
            TlsTcpStreamProj::Stream { fut } => {
                fut.poll_write(cx, buf)
            }
            TlsTcpStreamProj::Empty => { Poll::Ready(Ok(0)) }
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
            TlsTcpStreamProj::Stream { fut } => {
                fut.poll_flush(cx)
            }
            TlsTcpStreamProj::Empty => { Poll::Ready(Ok(())) }
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
            TlsTcpStreamProj::Stream { fut } => {
                fut.poll_shutdown(cx)
            }
            TlsTcpStreamProj::Empty => { Poll::Ready(Ok(())) }
            _ => unreachable!()
        }
    }
}


//------------ MaybeTlsTcpStream ---------------------------------------------

/// A TCP stream that may or may not use TLS.
pub struct MaybeTlsTcpStream {
    sock: Either<TcpStream, TlsTcpStream>,
}

impl MaybeTlsTcpStream {
    /// Creates a new stream.
    ///
    /// If `tls` is some, the stream will be a TLS stream, otherwise it
    /// will be a plain TCP stream.
    pub fn new(sock: TcpStream, tls: Option<&TlsAcceptor>) -> Self {
        MaybeTlsTcpStream {
            sock: match tls {
                Some(tls) => Either::Right(TlsTcpStream::new(sock, tls)),
                None => Either::Left(sock)
            }
        }
    }
}

impl AsyncRead for MaybeTlsTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>, cx: &mut Context, buf: &mut ReadBuf
    ) -> Poll<Result<(), io::Error>> {
        match self.sock {
            Either::Left(ref mut sock) => {
                pin_mut!(sock);
                sock.poll_read(cx, buf)
            }
            Either::Right(ref mut sock) => {
                pin_mut!(sock);
                sock.poll_read(cx, buf)
            }
        }
    }
}


impl AsyncWrite for MaybeTlsTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]
    ) -> Poll<Result<usize, io::Error>> {
        match self.sock {
            Either::Left(ref mut sock) => {
                pin_mut!(sock);
                sock.poll_write(cx, buf)
            }
            Either::Right(ref mut sock) => {
                pin_mut!(sock);
                sock.poll_write(cx, buf)
            }
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>, cx: &mut Context
    ) -> Poll<Result<(), io::Error>> {
        match self.sock {
            Either::Left(ref mut sock) => {
                pin_mut!(sock);
                sock.poll_flush(cx)
            }
            Either::Right(ref mut sock) => {
                pin_mut!(sock);
                sock.poll_flush(cx)
            }
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>, cx: &mut Context
    ) -> Poll<Result<(), io::Error>> {
        match self.sock {
            Either::Left(ref mut sock) => {
                pin_mut!(sock);
                sock.poll_shutdown(cx)
            }
            Either::Right(ref mut sock) => {
                pin_mut!(sock);
                sock.poll_shutdown(cx)
            }
        }
    }
}

