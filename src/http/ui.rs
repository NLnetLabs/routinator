//! Handling of endpoints related to the UI.
//!
#![cfg(feature = "ui")]


use hyper::{Body, Request, Response};

macro_rules! assets {
    (
        $(
            ( $path:expr => $( $ext:ident ),*  ),
        )*
    )
    => {
        pub fn handle_get(req: &Request<Body>) -> Option<Response<Body>> {
            match req.uri().path() {
                "/" => {
                    Some(serve(
                        include_bytes!(
                            "../../contrib/routinator-ui/index.html"
                        ),
                        self::content_types::html
                    ))
                }
                $(
                    $(
                        concat!("/ui/", $path, ".", stringify!($ext)) => {
                            Some(serve(
                                include_bytes!(
                                    concat!(
                                        "../../contrib/routinator-ui/",
                                        $path, ".",
                                        stringify!($ext)
                                    )
                                ),
                                self::content_types::$ext
                            ))
                        }
                    )*
                )*
                _ => None
            }
        }
    }
}

assets!(
    ("favicon" => ico),
    ("css/app" => css),
    ("fonts/element-icons" => ttf, woff),
    ("fonts/lato-latin-100" => woff, woff2),
    ("fonts/lato-latin-300" => woff, woff2),
    ("fonts/lato-latin-400" => woff, woff2),
    ("fonts/lato-latin-700" => woff, woff2),
    ("fonts/lato-latin-900" => woff, woff2),
    ("fonts/lato-latin-100italic" => woff, woff2),
    ("fonts/lato-latin-300italic" => woff, woff2),
    ("fonts/lato-latin-400italic" => woff, woff2),
    ("fonts/lato-latin-700italic" => woff, woff2),
    ("fonts/lato-latin-900italic" => woff, woff2),
    ("fonts/source-code-pro-latin-200" => woff, woff2),
    ("fonts/source-code-pro-latin-200" => woff, woff2),
    ("fonts/source-code-pro-latin-300" => woff, woff2),
    ("fonts/source-code-pro-latin-400" => woff, woff2),
    ("fonts/source-code-pro-latin-500" => woff, woff2),
    ("fonts/source-code-pro-latin-600" => woff, woff2),
    ("fonts/source-code-pro-latin-700" => woff, woff2),
    ("fonts/source-code-pro-latin-900" => woff, woff2),
    ("img/afrinic" => svg),
    ("img/apnic" => svg),
    ("img/arin" => svg),
    ("img/blue" => svg),
    ("img/lacnic" => svg),
    ("img/ripencc" => svg),
    ("img/routinator_logo_white" => svg),
    ("img/welcome" => svg),
    ("js/app" => js),
);

fn serve(data: &'static [u8], ctype: &'static [u8]) -> Response<Body> {
    Response::builder()
    .header("Content-Type", ctype)
    .body(data.into())
    .unwrap()
}

#[allow(non_upper_case_globals)]
mod content_types {
    pub const css: &[u8] = b"text/css";
    pub const html: &[u8] = b"text/html";
    pub const ico: &[u8] = b"image/x-icon";
    pub const js: &[u8] = b"application/javascript";
    pub const svg: &[u8] = b"image/svg+xml";
    pub const ttf: &[u8] = b"font/ttf";
    pub const woff: &[u8] = b"font/woff";
    pub const woff2: &[u8] = b"font/woff2";
}
