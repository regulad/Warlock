// SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
//! The client, for `warlockctl`, Warlock's tests and other programs. Any
//! HTTP client on the pipe works as well (`api/openapi.yaml`).
//!
//! Each call opens its own connection, as locks need: a lock lasts as long
//! as its [`Lines`] (and so its connection) is kept. Needs a Tokio runtime.

use std::fmt;
use std::io;
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes, BytesMut};
use http::{Method, Request, StatusCode, header};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::net::windows::named_pipe::ClientOptions;

use crate::types::*;

/// What can go wrong.
#[derive(Debug)]
pub enum ClientError {
    /// Opening the pipe failed: Warlock isn't running, or we may not use it.
    Connect(io::Error),
    /// HTTP failed.
    Http(hyper::Error),
    /// Warlock answered with an error.
    Api { status: StatusCode, message: String },
    /// The JSON wasn't what was expected.
    Json(serde_json::Error),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::Connect(e) if e.kind() == io::ErrorKind::NotFound => {
                write!(f, "Warlock isn't running (no pipe)")
            }
            ClientError::Connect(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                write!(f, "not allowed to use Warlock: run as an administrator or join the warlock-users group")
            }
            ClientError::Connect(e) => write!(f, "can't reach Warlock: {e}"),
            ClientError::Http(e) => write!(f, "HTTP: {e}"),
            ClientError::Api { status, message } => write!(f, "{status}: {message}"),
            ClientError::Json(e) => write!(f, "unexpected JSON: {e}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<hyper::Error> for ClientError {
    fn from(e: hyper::Error) -> Self {
        ClientError::Http(e)
    }
}

impl From<serde_json::Error> for ClientError {
    fn from(e: serde_json::Error) -> Self {
        ClientError::Json(e)
    }
}

/// `ERROR_PIPE_BUSY`: every instance is taken; one is about to be made.
const PIPE_BUSY: i32 = 231;

/// A client of the API on one pipe.
#[derive(Clone, Debug)]
pub struct Client {
    pipe: String,
}

impl Client {
    /// A client of the pipe `name` (normally [`crate::PIPE`]).
    pub fn new(name: impl Into<String>) -> Self {
        Self { pipe: name.into() }
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<http::Response<Incoming>, ClientError> {
        let deadline = Instant::now() + Duration::from_secs(5);
        let pipe = loop {
            match ClientOptions::new().open(&self.pipe) {
                Ok(p) => break p,
                Err(e) if e.raw_os_error() == Some(PIPE_BUSY) && Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(e) => return Err(ClientError::Connect(e)),
            }
        };
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(pipe)).await?;
        tokio::spawn(connection);
        let mut request = Request::builder().method(method).uri(path).header(header::HOST, "warlock");
        if body.is_some() {
            request = request.header(header::CONTENT_TYPE, "application/json");
        }
        let request = request.body(Full::new(Bytes::from(body.unwrap_or_default()))).expect("a valid request");
        Ok(sender.send_request(request).await?)
    }

    /// Sends a request and reads the whole response: status and JSON. For
    /// the contract tests, which check raw JSON.
    pub async fn raw(
        &self,
        method: Method,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<(StatusCode, Value), ClientError> {
        let response = self.send(method, path, body.map(<[u8]>::to_vec)).await?;
        let status = response.status();
        let bytes = response.into_body().collect().await?.to_bytes();
        Ok((status, serde_json::from_slice(&bytes)?))
    }

    /// A request whose response is a JSON Lines stream, as raw JSON values.
    pub async fn raw_stream(&self, method: Method, path: &str, body: Option<&[u8]>) -> Result<Lines, ClientError> {
        let response = self.send(method, path, body.map(<[u8]>::to_vec)).await?;
        let status = response.status();
        if !status.is_success() {
            let bytes = response.into_body().collect().await?.to_bytes();
            return Err(api_error(status, &bytes));
        }
        Ok(Lines { body: response.into_body(), buf: BytesMut::new() })
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, ClientError> {
        let response = self.send(Method::GET, path, None).await?;
        let status = response.status();
        let bytes = response.into_body().collect().await?.to_bytes();
        if !status.is_success() {
            return Err(api_error(status, &bytes));
        }
        Ok(serde_json::from_slice(&bytes)?)
    }

    async fn lock(&self, path: &str, body: &impl Serialize) -> Result<Lines, ClientError> {
        self.raw_stream(Method::POST, path, Some(&serde_json::to_vec(body)?)).await
    }

    /// `GET /v1/info`.
    pub async fn info(&self) -> Result<Info, ClientError> {
        self.get("/v1/info").await
    }

    /// `GET /v1/peers`.
    pub async fn peers(&self) -> Result<Vec<Peer>, ClientError> {
        self.get("/v1/peers").await
    }

    /// `GET /v1/peers/{address}`.
    pub async fn peer(&self, address: &str) -> Result<Peer, ClientError> {
        self.get(&format!("/v1/peers/{address}")).await
    }

    /// `GET /v1/advertising`.
    pub async fn advertising(&self) -> Result<Vec<AdvertisedType>, ClientError> {
        self.get("/v1/advertising").await
    }

    /// `GET /v1/holds`.
    pub async fn holds(&self) -> Result<Vec<Hold>, ClientError> {
        self.get("/v1/holds").await
    }

    /// `POST /v1/advertising`: advertises `service_type` for as long as the
    /// returned stream is kept. Its lines are [`AdvertisingState`]s.
    pub async fn advertise(&self, service_type: &str) -> Result<Lines, ClientError> {
        self.lock("/v1/advertising", &AdvertiseRequest { service_type: service_type.into() }).await
    }

    /// `POST /v1/holds`: holds AWDL active for as long as the returned stream
    /// is kept. Its lines are [`HoldState`]s.
    pub async fn hold(&self, reason: &str) -> Result<Lines, ClientError> {
        self.lock("/v1/holds", &HoldRequest { reason: reason.into() }).await
    }

    /// `GET /v1/events`. Its lines are [`Event`]s.
    pub async fn events(&self) -> Result<Lines, ClientError> {
        self.raw_stream(Method::GET, "/v1/events", None).await
    }
}

fn api_error(status: StatusCode, body: &[u8]) -> ClientError {
    let message = serde_json::from_slice::<Error>(body)
        .map(|e| e.message)
        .unwrap_or_else(|_| String::from_utf8_lossy(body).into_owned());
    ClientError::Api { status, message }
}

/// A JSON Lines response, read a line at a time. Dropping it closes the
/// connection, which releases a lock.
pub struct Lines {
    body: Incoming,
    buf: BytesMut,
}

impl Lines {
    /// The next line as raw JSON; `None` when the stream ends (Warlock
    /// stopped, for a lock).
    pub async fn next_value(&mut self) -> Option<Result<Value, ClientError>> {
        loop {
            if let Some(end) = self.buf.iter().position(|&b| b == b'\n') {
                let line = self.buf.split_to(end + 1);
                if line.len() == 1 {
                    continue;
                }
                return Some(serde_json::from_slice(&line[..end]).map_err(ClientError::from));
            }
            match self.body.frame().await? {
                Ok(frame) => {
                    if let Ok(mut data) = frame.into_data() {
                        while data.has_remaining() {
                            let chunk = data.chunk();
                            self.buf.extend_from_slice(chunk);
                            let n = chunk.len();
                            data.advance(n);
                        }
                    }
                }
                Err(e) => return Some(Err(e.into())),
            }
        }
    }

    /// The next line as `T`.
    pub async fn next<T: DeserializeOwned>(&mut self) -> Option<Result<T, ClientError>> {
        Some(self.next_value().await?.and_then(|v| serde_json::from_value(v).map_err(ClientError::from)))
    }
}
