//! The RPKI to Router Protocol.
//!
//! This module implements the server side of the RTR protocol as specified
//! in RFC 6810 for version 0 and RFC 8210 for version 1. The server
//! implements both version and leaves it to a connecting client to pick one.
//! For version 1, we don’t implement router keys for BGPSEC.
//!
//! The server is implemented as a future. It is returned by `rtr_listener`.
//! This function also returns the sending end of a channel that can be used
//! to inform the server that an update of the RPKI data is available.

pub use self::net::rtr_listener;
pub use self::notify::NotifySender;
pub use self::serial::Serial;

mod pdu;
mod net;
mod notify;
mod query;
mod send;
mod serial;

