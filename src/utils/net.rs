//! Utility functions related to networking.

use std::net::{SocketAddr, TcpListener as StdListener};
use log::error;
use crate::error::ExitError;


pub fn bind(addr: &SocketAddr) -> Result<StdListener, ExitError> {
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

