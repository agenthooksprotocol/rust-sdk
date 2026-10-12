//! Bounded JSON-lines framing only; does not launch or supervise subprocesses.
use crate::{
    server::{Authenticator, Server},
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
///
/// A notification (a frame without `id`) always yields an empty 204, whatever
/// the outcome, so it can never produce an output frame. A request rejected
/// before JSON-RPC processing (credentials, size) yields a JSON-RPC error.
pub async fn dispatch<A: Authenticator>(
    server: &Server<A>,
    frame: Vec<u8>,
    authorization: Option<String>,
) -> Response {
    let mut headers = BTreeMap::from([("content-type".into(), "application/json".into())]);
    if let Some(value) = authorization {
        headers.insert("authorization".into(), value);
    }
    let notification = serde_json::from_slice::<serde_json::Value>(&frame)
        .is_ok_and(|message| crate::server::is_notification(&message));
    let response = server
        .handle(Request {
            method: "POST".into(),
            uri: String::new(),
            headers,
            body: frame.clone(),
        })
        .await;
    if notification {
        return Response {
            status: 204,
            ..Default::default()
        };
    }
    crate::server::frame_rejection(&frame, response)
}
/// Preserve JSON-RPC error bodies irrespective of HTTP status. Empty successful
/// notification acknowledgments emit no frame. Diagnostics and objects that are
/// not JSON-RPC responses (no `id` member) are never written.
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
            .is_ok_and(|value| value.get("id").is_some())
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
