//! Handling of endpoints related to the UI.
//!
//! The frontend is served on BASE_DIR by including all web resources (html,
//! css, js) from a single vec of structs; each struct holds a bytes array
//! that represents a single file from the web resources.
#![cfg(feature = "ui")]

use std::path::Path;
use super::request::Request;
use super::response::{ContentType, Response, ResponseBuilder};
use self::assets::{ASSETS, Asset};

/// Sensible settings for BASE_URL are either:
/// * `"/"`: just route everything from the domain-name without further ado,
///   or
/// * `"/ui"`: the default prodution setting in the UI App, this means that
///   all request URLs should start with `/ui`.
const BASE_URL: &str = "/ui";

/// The path of the asset, that all unknown URLs starting with
/// BASE_URL will be redirected to. All other URLs will return a 404.
const CATCH_ALL_URL: &str = "index.html";

pub fn handle_get_or_head(req: Request) -> Result<Response, Request> {
    let head = req.is_head();
    if req.uri().path() == "/" {
        return Ok(Response::moved_permanently("/ui/"))
    }

    let req_path = Path::new(req.uri().path());
    if let Ok(p) = req_path.strip_prefix(BASE_URL) {
        match get_asset(p) {
            Some(asset) => Ok(serve(head, asset)),
            None => {
                // In order to have the frontend handle all routing and
                // queryparams under BASE_URL, all unknown URLs that start
                // with BASE_URL will route to CATCH_ALL_URL.
                //
                // Note that we could be smarter about this and do a
                // (somewhat convoluted) regex on the requested URL to figure
                // out if it makes sense as a search prefix url.
                if let Some(default) = get_asset(Path::new(CATCH_ALL_URL)) {
                    Ok(serve(head, default))
                }
                else {
                    // if CATCH_ALL_URL is not defined in ui_resources
                    // we'll return a 404
                    Ok(Response::not_found(false))
                }
            }
        }
    } else {
        // This is the last handler in the chain, so if the requested URL did
        // not start with BASE_URL, we're returning 404.
        Ok(Response::not_found(false))
    }
}

fn get_asset(path: &Path) -> Option<&Asset> {
    let path = path.to_str()?;
    ASSETS.iter().find(|asset| asset.path == path)
}

/// Creates the response from data and the content type.
fn serve(head: bool, asset: &Asset) -> Response {
    let res = ResponseBuilder::ok().content_type(
        ContentType::external(asset.media_type.as_bytes())
    );
    if head {
        res.empty()
    }
    else {
        res.body(asset.content)
    }
}



mod assets {
    include!(concat!(env!("OUT_DIR"), "/ui_assets.rs"));
}

