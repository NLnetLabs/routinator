//! Handling of endpoints related to the UI.
//!
//! The frontend is served on BASE_DIR by including all web resources (html,
//! css, js) from a single vec of structs; each struct holds a bytes array
//! that represents a single file from the web resources.
#![cfg(feature = "ui")]

use bytes::Bytes;
use hyper::{Body, Request, Response, StatusCode};

// Sensible settings for BASE_URL are either:
// "/"   => just route everything from the domain-name without further ado, or
// "/ui" => the default prodution setting in the Vue App, this means that all
//          request URLs should either start with `/ui`.
//
// Note that this setting MUST correspond with the environment variable
// VUE_APP_BASE_DIR in the Vue App (set by the .env.* files in routinator-ui).
//
// CATCH_ALL_URL is the path of the asset, that all unknown URLs starting with
// BASE_URL will be redirected to. All other URLs will return a 404.
const BASE_URL: &str = "/ui";
const CATCH_ALL_URL: &str = "index.html";

pub fn handle_get(req: &Request<Body>) -> Option<Response<Body>> {
    if req.uri().path() == "/" {
        return Some(
            Response::builder()
            .status(StatusCode::MOVED_PERMANENTLY)
            .header("Content-Type", "text/plain")
            .header("Location", "/ui/")
            .body(Bytes::from("Moved permanently to /ui/").into())
            .unwrap()
        )
    }

    let req_path = std::path::Path::new(req.uri().path());
    if let Ok(p) = req_path.strip_prefix(BASE_URL) {
        match routinator_ui::endpoints::ui_resource(p) {
            Some(endpoint) => {
                Some(serve(endpoint.content, endpoint.content_type))
            }
            None => {
                // In order to have the frontend handle all routing and
                // queryparams under BASE_URL, all unknown URLs that start
                // with BASE_URL will route to CATCH_ALL_URL.
                //
                // Note that we could be smarter about this and do a
                // (somewhat convoluted) regex on the requested URL to figure
                // out if it makes sense as a search prefix url.
                if let Some(default) =
                    routinator_ui::endpoints::ui_resource(
                        std::path::Path::new(CATCH_ALL_URL)
                    )
                {
                    Some(serve(default.content, default.content_type))
                } else {
                    // if CATCH_ALL_URL is not defined in ui_resources
                    // we'll return a 404
                    Some(super::not_found())
                }
            }
        }
    } else {
        // This is the last handler in the chain, so if the requested URL did
        // not start with BASE_URL, we're returning 404.
        Some(super::not_found())
    }
}

/// Creates the response from data and the content type.
fn serve(data: &'static [u8], ctype: &'static [u8]) -> Response<Body> {
    Response::builder()
        .header("Content-Type", ctype)
        .body(data.into())
        .unwrap()
}

