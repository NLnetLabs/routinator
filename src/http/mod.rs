//! The HTTP server.
//!
//! The module provides all functionality exposed by the HTTP server to
//! those interested. The only public item, [`http_listener`] creates all
//! necessary networking services based on the current configuration and
//! returns a future that drives the server.

pub use self::listener::http_listener;
pub use self::response::ContentType;

// First, a bit of scaffolding. `dispatch` contains the state needs is
// necessary for answering requests and dispatches to the specific handlers.
// `listener` contains all the logic to actually handle connections etc.
mod dispatch;
mod listener;

// The following module helps making responses.
mod response;

// Finally, these modules actually handle requests.
mod delta;
mod log;
mod metrics;
mod payload;
mod status;
mod ui;
mod validity;

