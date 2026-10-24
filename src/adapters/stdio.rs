//! Bounded JSON-lines framing only; does not launch or supervise subprocesses.
use crate::{
    server::{Authenticator, RequestHandler, RpcError},
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
    server: &impl RequestHandler<A>,
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
/// Discard the rest of an oversized line, through its newline or EOF.
fn skip_line(reader: &mut impl BufRead) -> io::Result<()> {
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(());
        }
        let newline = available.iter().position(|b| *b == b'\n');
        let count = newline.map_or(available.len(), |at| at + 1);
        reader.consume(count);
        if newline.is_some() {
            return Ok(());
        }
    }
}
/// Error frame for a line rejected before dispatch (too large to read).
fn oversized_frame() -> Response {
    crate::server::rpc_error(&serde_json::Value::Null, RpcError::InvalidRequest)
}
/// Replacement for a reply that cannot be framed (for example, too large).
fn unframeable(response: &Response) -> Response {
    let id = serde_json::from_slice::<serde_json::Value>(&response.body)
        .ok()
        .and_then(|body| body.get("id").cloned())
        .unwrap_or_default();
    crate::server::rpc_error(&id, RpcError::Internal)
}
/// Serve one JSON-RPC frame per line from `input` until EOF, writing replies
/// to `output`. Notifications never produce a frame.
///
/// Malformed JSON gets a `-32700` frame and a line over `max_frame_bytes` gets
/// a `-32600` frame, both with id `null`; serving then continues with the next
/// line. A reply too large to frame is replaced by a `-32603` error. I/O errors
/// and an unterminated final line end the loop with an error.
///
/// Reads are blocking, which suits a dedicated stdio backend process driven by
/// any executor, such as `futures::executor::block_on`. On Tokio, prefer
/// [`serve_tokio`] (feature `tokio-process`).
pub async fn serve<A: Authenticator>(
    server: &impl RequestHandler<A>,
    mut input: impl BufRead,
    mut output: impl Write,
    authorization: Option<String>,
    max_frame_bytes: usize,
) -> io::Result<()> {
    loop {
        let response = match read_frame(&mut input, max_frame_bytes) {
            Ok(Some(frame)) => dispatch(server, frame, authorization.clone()).await,
            Ok(None) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                skip_line(&mut input)?;
                oversized_frame()
            }
            Err(error) => return Err(error),
        };
        match write_frame(&mut output, &response, max_frame_bytes) {
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                write_frame(&mut output, &unframeable(&response), max_frame_bytes)?
            }
            result => result?,
        }
    }
}
/// [`serve`] over Tokio async I/O, for example `tokio::io::stdin()` wrapped in
/// a `BufReader` and `tokio::io::stdout()`. Semantics are identical.
#[cfg(feature = "tokio-process")]
pub async fn serve_tokio<A: Authenticator>(
    server: &impl RequestHandler<A>,
    input: impl tokio::io::AsyncBufRead + Unpin,
    mut output: impl tokio::io::AsyncWrite + Unpin,
    authorization: Option<String>,
    max_frame_bytes: usize,
) -> io::Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
    // Bound each line read; one byte past the limit marks an oversized frame.
    let limit = u64::try_from(max_frame_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut input = input;
    loop {
        let mut line = Vec::new();
        let read = (&mut input)
            .take(limit)
            .read_until(b'\n', &mut line)
            .await?;
        if read == 0 {
            return Ok(());
        }
        let terminated = line.last() == Some(&b'\n');
        if terminated {
            line.pop();
        }
        let response = if line.len() > max_frame_bytes {
            if !terminated {
                // Discard the remainder of the oversized line.
                let mut rest = Vec::new();
                input.read_until(b'\n', &mut rest).await?;
            }
            oversized_frame()
        } else if !terminated {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unterminated frame",
            ));
        } else {
            dispatch(server, line, authorization.clone()).await
        };
        let mut frame = Vec::new();
        match write_frame(&mut frame, &response, max_frame_bytes) {
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                write_frame(&mut frame, &unframeable(&response), max_frame_bytes)?
            }
            result => result?,
        }
        if !frame.is_empty() {
            output.write_all(&frame).await?;
            output.flush().await?;
        }
    }
}
