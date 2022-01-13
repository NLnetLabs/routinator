//! Utility functions for dealing with TLS.

use std::io;
use std::fs::File;
use std::path::Path;
use log::error;
use tokio_rustls::rustls::{Certificate, PrivateKey};
use crate::error::ExitError;

pub use tokio_rustls::rustls::ServerConfig;


/// Creates the TLS server config.
///
/// The service this config is for should be given through `service`. This is
/// used for logging.
pub fn create_server_config(
    service: &str, key_path: &Path, cert_path: &Path
) -> Result<ServerConfig, ExitError> {
    let certs = rustls_pemfile::certs(
        &mut io::BufReader::new(
            File::open(&cert_path).map_err(|err| {
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
            File::open(&key_path).map_err(|err| {
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

