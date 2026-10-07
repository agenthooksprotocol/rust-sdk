//! Bounded JSON-lines framing only; does not launch or supervise subprocesses.
use crate::{
    server::{Authenticator, Handler, Server},
    transport::{Request, Response},
};
use std::{
    collections::BTreeMap,
    io::{self, BufRead, Write},
};
/// EOF between frames is clean; an unterminated final frame is rejected.
pub fn read_frame(reader: &mut impl BufRead, max_bytes: usize) -> io::Result<Option<Vec<u8>>> {
    let mut frame = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if frame.is_empty() {
                Ok(None)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unterminated frame",
                ))
            };
        }
        let newline = available.iter().position(|b| *b == b'\n');
        let count = newline.unwrap_or(available.len());
        if frame.len().saturating_add(count) > max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame too large",
            ));
        }
        frame.extend_from_slice(&available[..count]);
        reader.consume(count + usize::from(newline.is_some()));
        if newline.is_some() {
            return Ok(Some(frame));
        }
    }
}
/// Credentials must come from trusted transport configuration, never message fields.
pub async fn dispatch<H: Handler, A: Authenticator>(
    server: &Server<H, A>,
    frame: Vec<u8>,
    authorization: Option<String>,
) -> Response {
    let mut headers = BTreeMap::from([("content-type".into(), "application/json".into())]);
    if let Some(value) = authorization {
        headers.insert("authorization".into(), value);
    }
    server
        .handle(Request {
            method: "POST".into(),
            uri: String::new(),
            headers,
            body: frame,
        })
        .await
}
/// Preserve JSON error bodies irrespective of HTTP status. Empty successful
/// notification acknowledgments emit no frame. Diagnostics are never accepted.
pub fn write_frame(
    writer: &mut impl Write,
    response: &Response,
    max_bytes: usize,
) -> io::Result<()> {
    if matches!(response.status, 202 | 204) && response.body.is_empty() {
        return Ok(());
    }
    if response.body.len() > max_bytes
        || response.body.contains(&b'\n')
        || !serde_json::from_slice::<serde_json::Value>(&response.body)
            .is_ok_and(|value| value.is_object())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid response frame",
        ));
    }
    writer.write_all(&response.body)?;
    writer.write_all(b"\n")?;
    writer.flush()
}
