use std::{fs, io};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use log::{error, warn};
use reqwest::{header, redirect};
use reqwest::{Certificate, Proxy, StatusCode};
use reqwest::blocking::{Client, ClientBuilder, RequestBuilder, Response};
use rpki::uri;
use crate::config::Config;
use crate::error::Fatal;
use crate::utils::date::{format_http_date, parse_http_date};


//------------ HttpClient ----------------------------------------------------

/// The HTTP client for updating RRDP repositories.
#[derive(Debug)]
pub struct HttpClient {
    /// The (blocking) reqwest client.
    ///
    /// This will be of the error variant until `ignite` has been called. Yes,
    /// that is not ideal but 
    client: Result<Client, Option<ClientBuilder>>,

    /// The base directory for storing copies of responses if that is enabled.
    response_dir: Option<PathBuf>,

    /// The timeout for requests.
    timeout: Option<Duration>,
}

impl HttpClient {
    /// Creates a new, not-yet-ignited client based on the config.
    pub fn new(config: &Config) -> Result<Self, Fatal> {

        // Deal with the reqwest’s TLS features by defining a creator
        // function for the two cases.
        #[cfg(not(feature = "native-tls"))]
        fn create_builder() -> ClientBuilder {
            Client::builder().use_rustls_tls()
        }

        #[cfg(feature = "native-tls")]
        fn create_builder() -> ClientBuilder {
            Client::builder().use_native_tls()
        }

        let mut builder = create_builder();
        builder = builder.user_agent(&config.rrdp_user_agent);
        builder = builder.tcp_keepalive(config.rrdp_tcp_keepalive);
        builder = builder.timeout(None); // Set per request.
        builder = builder.gzip(true);
        builder = builder.redirect(
            redirect::Policy::custom(Self::redirect_policy)
        );
        if let Some(timeout) = config.rrdp_connect_timeout {
            builder = builder.connect_timeout(timeout);
        }
        if let Some(addr) = config.rrdp_local_addr {
            builder = builder.local_address(addr)
        }
        for path in &config.rrdp_root_certs {
            builder = builder.add_root_certificate(
                Self::load_cert(path)?
            );
        }
        for proxy in &config.rrdp_proxies {
            let proxy = match Proxy::all(proxy) {
                Ok(proxy) => proxy,
                Err(err) => {
                    error!(
                        "Invalid rrdp-proxy '{}': {}", proxy, err
                    );
                    return Err(Fatal)
                }
            };
            builder = builder.proxy(proxy);
        }
        Ok(HttpClient {
            client: Err(Some(builder)),
            response_dir: config.rrdp_keep_responses.clone(),
            timeout: config.rrdp_timeout,
        })
    }

    /// Ignites the client.
    ///
    /// This _must_ be called before any other methods can be called. It must
    /// be called after any potential fork on Unix systems because it spawns
    /// threads.
    pub fn ignite(&mut self) -> Result<(), Fatal> {
        let builder = match self.client.as_mut() {
            Ok(_) => return Ok(()),
            Err(builder) => match builder.take() {
                Some(builder) => builder,
                None => {
                    error!("Previously failed to initialize HTTP client.");
                    return Err(Fatal)
                }
            }
        };
        let client = match builder.build() {
            Ok(client) => client,
            Err(err) => {
                error!("Failed to initialize HTTP client: {}.", err);
                return Err(Fatal)
            }
        };
        self.client = Ok(client);
        Ok(())
    }

    /// Loads a WebPKI trusted certificate.
    fn load_cert(path: &Path) -> Result<Certificate, Fatal> {
        let mut file = match fs::File::open(path) {
            Ok(file) => file,
            Err(err) => {
                error!(
                    "Cannot open rrdp-root-cert file '{}': {}'",
                    path.display(), err
                );
                return Err(Fatal);
            }
        };
        let mut data = Vec::new();
        if let Err(err) = io::Read::read_to_end(&mut file, &mut data) {
            error!(
                "Cannot read rrdp-root-cert file '{}': {}'",
                path.display(), err
            );
            return Err(Fatal);
        }
        Certificate::from_pem(&data).map_err(|err| {
            error!(
                "Cannot decode rrdp-root-cert file '{}': {}'",
                path.display(), err
            );
            Fatal
        })
    }

    /// Returns a reference to the reqwest client.
    ///
    /// # Panics
    ///
    /// The method panics if the client hasn’t been ignited yet.
    fn client(&self) -> &Client {
        self.client.as_ref().expect("HTTP client has not been ignited")
    }

    /// Performs an HTTP GET request for the given URI.
    ///
    /// If keeping responses is enabled, the response is written to a file
    /// corresponding to the URI. If the resource behind the URI changes over
    /// time and this change should be tracked, set `multi` to `true` to
    /// include the current time in the file name.
    pub fn response(
        &self,
        uri: &uri::Https,
        multi: bool,
    ) -> Result<HttpResponse, reqwest::Error> {
        self._response(uri, self.client().get(uri.as_str()), multi)
    }

    pub fn conditional_response(
        &self,
        uri: &uri::Https,
        etag: Option<&Bytes>,
        last_modified: Option<DateTime<Utc>>,
        multi: bool,
    ) -> Result<HttpResponse, reqwest::Error> {
        let mut request = self.client().get(uri.as_str());
        if let Some(etag) = etag {
            request = request.header(
                header::IF_NONE_MATCH, etag.as_ref()
            );
        }
        if let Some(last_modified) = last_modified {
            request = request.header(
                header::IF_MODIFIED_SINCE,
                format_http_date(last_modified)
            );
        }
        self._response(uri, request, multi)
    }

    /// Creates a response from a request builder.
    fn _response(
        &self,
        uri: &uri::Https,
        mut request: RequestBuilder,
        multi: bool
    ) -> Result<HttpResponse, reqwest::Error> {
        if let Some(timeout) = self.timeout {
            request = request.timeout(timeout);
        }
        request.send().and_then(|response| {
            response.error_for_status()
        }).map(|response| {
            HttpResponse::create(response, uri, &self.response_dir, multi)
        })
    }

    /*
    /// Requests, parses, and returns the given RRDP notification file.
    ///
    /// The value referred to by `status` will be updated to the received
    /// status code or `HttpStatus::Error` if the request failed.
    ///
    /// Returns the notification file on success.
    pub fn notification_file(
        &self,
        uri: &uri::Https,
        state: Option<&RepositoryState>,
        status: &mut HttpStatus,
    ) -> Result<Option<Notification>, Failed> {
        let mut request = self.client().get(uri.as_str());
        if let Some(state) = state {
            if let Some(etag) = state.etag.as_ref() {
                request = request.header(
                    header::IF_NONE_MATCH, etag.as_ref()
                );
            }
            if let Some(ts) = state.last_modified_ts {
                if let Some(datetime) = Utc.timestamp_opt(ts, 0).single() {
                    request = request.header(
                        header::IF_MODIFIED_SINCE,
                        format_http_date(datetime)
                    );
                }
            }
        }
        let response = match self._response(uri, request, true) {
            Ok(response) => {
                *status = response.status().into();
                response
            }
            Err(err) => {
                warn!("RRDP {}: {}", uri, err);
                *status = HttpStatus::Error;
                return Err(Failed)
            }
        };

        if response.status() == StatusCode::NOT_MODIFIED {
            Ok(None)
        }
        else if response.status() != StatusCode::OK {
            warn!(
                "RRDP {}: Getting notification file failed with status {}",
                uri, response.status()
            );
            Err(Failed)
        }
        else {
            Notification::from_response(uri, response).map(Some)
        }
    }
    */

    /// The redirect policy.
    ///
    /// We allow up to 10 redirects (reqwest’s default policy) but only if
    /// the origin stays the same.
    fn redirect_policy(attempt: redirect::Attempt) -> redirect::Action {
        if attempt.previous().len() > 9 {
            return attempt.stop();
        }
        let orig = match attempt.previous().first() {
            Some(url) => url,
            None => return attempt.follow() // Shouldn’t happen?
        };
        let new = attempt.url();
        let orig = (orig.scheme(), orig.host(), orig.port());
        let new = (new.scheme(), new.host(), new.port());
        if orig == new {
            attempt.follow()
        }
        else {
            attempt.stop()
        }
    }
}


//------------ HttpResponse --------------------------------------------------

/// Wraps a reqwest response for added features.
pub struct HttpResponse {
    /// The wrapped reqwest response.
    response: Response,

    /// A file to also store read data into.
    file: Option<fs::File>,
}

impl HttpResponse {
    /// Creates a new response wrapping a reqwest reponse.
    ///
    /// If `response_dir` is some path, the response will also be written to
    /// a file under this directory based on `uri`. Each URI component
    /// starting with the authority will be a directory name. If `multi` is
    /// `false` the last component will be the file name. If `multi` is
    /// `true` the last component will be a directory, too, and the file name
    /// will be the ISO timestamp of the current time.
    pub fn create(
        response: Response,
        uri: &uri::Https,
        response_dir: &Option<PathBuf>,
        multi: bool
    ) -> Self {
        HttpResponse {
            response,
            file: response_dir.as_ref().and_then(|base| {
                Self::open_file(base, uri, multi)
            })
        }
    }

    /// Opens the file mirroring file.
    ///
    /// See [`create`][Self::create] for the rules.
    fn open_file(
        base: &Path, uri: &uri::Https, multi: bool
    ) -> Option<fs::File> {
        let path = base.join(&uri.as_str()[8..]);
        let path = if multi {
            path.join(Utc::now().to_rfc3339())
        }
        else {
            path
        };

        let parent = match path.parent() {
            Some(parent) => parent,
            None => {
                warn!(
                    "Cannot keep HTTP response; \
                    URI translated into a bad path '{}'",
                    path.display()
                );
                return None
            }
        };
        if let Err(err) = fs::create_dir_all(parent) {
            warn!(
                "Cannot keep HTTP response; \
                creating directory {} failed: {}",
                parent.display(), err
            );
            return None
        }
        match fs::File::create(&path) {
            Ok(file) => Some(file),
            Err(err) => {
                warn!(
                    "Cannot keep HTTP response; \
                    creating file {} failed: {}",
                    path.display(), err
                );
                None
            }
        }
    }

    /// Returns the value of the content length header if present.
    pub fn content_length(&self) -> Option<u64> {
        self.response.content_length()
    }

    /// Copies the full content of the response to the given writer.
    pub fn copy_to<W: io::Write + ?Sized>(
        &mut self, w: &mut W
    ) -> Result<u64, io::Error> {
        // We cannot use the reqwest response’s `copy_to` impl because we need
        // to use our own `io::Read` impl which sneaks in the copying to file
        // if necessary.
        io::copy(self, w)
    }

    /// Returns the status code of the response.
    pub fn status(&self) -> StatusCode {
        self.response.status()
    }

    /// Returns the value of the ETag header if present.
    ///
    /// The returned value is the complete content. That is, it includes the
    /// quotation marks and a possible `W/` prefix.
    ///
    /// The method quietly returns `None` if the content of a header is
    /// malformed or if there is more than one occurence of the header.
    ///
    /// The method returns a `Bytes` value as there is a good chance the
    /// tag is short enough to be be inlined.
    pub fn etag(&self) -> Option<Bytes> {
        let mut etags = self.response.headers()
            .get_all(header::ETAG)
            .into_iter();
        let etag = etags.next()?;
        if etags.next().is_some() {
            return None
        }
        Self::parse_etag(etag.as_bytes())
    }

    /// Parses the ETag value.
    ///
    /// This is a separate function to make testing easier.
    fn parse_etag(etag: &[u8]) -> Option<Bytes> {
        // The tag starts with an optional case-sensitive `W/` followed by
        // `"`. Let’s remember where the actual tag starts.
        let start = if etag.starts_with(b"W/\"") {
            3
        }
        else if etag.first() == Some(&b'"') {
            1
        }
        else {
            return None
        };

        // We need at least one more character. Empty tags are allowed.
        if etag.len() <= start {
            return None
        }

        // The tag ends with a `"`.
        if etag.last() != Some(&b'"') {
            return None
        }

        Some(Bytes::copy_from_slice(etag))
    }

    /// Returns the value of the Last-Modified header if present.
    ///
    /// The method quietly returns `None` if the content of a header is
    /// malformed or if there is more than one occurence of the header.
    pub fn last_modified(&self) -> Option<DateTime<Utc>> {
        let mut iter = self.response.headers()
            .get_all(header::LAST_MODIFIED)
            .into_iter();
        let value = iter.next()?;
        if iter.next().is_some() {
            return None
        }
        parse_http_date(value.to_str().ok()?)
    }
}


//--- Read

impl io::Read for HttpResponse {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        let res = self.response.read(buf)?;
        if let Some(file) = self.file.as_mut() {
            file.write_all(&buf[..res])?;
        }
        Ok(res)
    }
}


//------------ HttpStatus ----------------------------------------------------

/// The result of an HTTP request.
#[derive(Clone, Copy, Debug)]
pub enum HttpStatus {
    /// A response was received with the given status code.
    Response(StatusCode),

    /// The repository URI was rejected.
    Rejected,

    /// An error happened.
    Error
}

impl HttpStatus {
    pub fn into_i16(self) -> i16 {
        match self {
            HttpStatus::Response(code) => code.as_u16() as i16,
            HttpStatus::Rejected => -2,
            HttpStatus::Error => -1,
        }
    }

    pub fn is_not_modified(self) -> bool {
        matches!(
            self,
            HttpStatus::Response(code) if code == StatusCode::NOT_MODIFIED
        )
    }

    pub fn is_success(self) -> bool {
        matches!(
            self,
            HttpStatus::Response(code) if code.is_success()
        )
    }
}

impl From<StatusCode> for HttpStatus {
    fn from(code: StatusCode) -> Self {
        HttpStatus::Response(code)
    }
}

