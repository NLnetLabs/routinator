//! Various error responses.

use hyper::{Body, Response, StatusCode};


pub fn bad_request() -> Response<Body> {
    Response::builder()
    .status(StatusCode::BAD_REQUEST)
    .header("Content-Type", "text/plain")
    .body("Bad Request".into())
    .unwrap()
}

pub fn initial_validation() -> Response<Body> {
    Response::builder()
    .status(StatusCode::SERVICE_UNAVAILABLE)
    .header("Content-Type", "text/plain")
    .body("Initial validation ongoing. Please wait.".into())
    .unwrap()
}

pub fn method_not_allowed() -> Response<Body> {
    Response::builder()
    .status(StatusCode::METHOD_NOT_ALLOWED)
    .header("Content-Type", "text/plain")
    .body("Method Not Allowed".into())
    .unwrap()
}

pub fn not_found() -> Response<Body> {
    Response::builder()
    .status(StatusCode::NOT_FOUND)
    .header("Content-Type", "text/plain")
    .body("Not Found".into())
    .unwrap()
}

