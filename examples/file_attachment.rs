//! Send a file through an application-owned hook boundary without staging handles.
//! Run: cargo run --example file_attachment -- path/to/report.pdf
use agenthooksprotocol::{
    Attachment, Hooks,
    adapters::registered::ManagedBackend,
    body::{BodyChunkFuture, BodyError, BodyStream},
    client::{HookError, LocalFuture},
    ergonomic_inputs::user_message_outbound_sources::message_payload,
    hooks::{Capabilities, EventGrant, HooksOptions},
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, io::Read, path::PathBuf, sync::Arc, time::Duration};

// This standalone example uses blocking file I/O. In an async application use
// the runtime's file reader/offload facility in your BodyStream implementation.
struct FileSource {
    path: PathBuf,
    file: Option<std::fs::File>,
}
impl BodyStream for FileSource {
    fn next_chunk(&mut self) -> BodyChunkFuture<'_> {
        Box::pin(async move {
            if self.file.is_none() {
                self.file = Some(
                    std::fs::File::open(&self.path).map_err(|e| BodyError::Read(e.to_string()))?,
                );
            }
            let mut chunk = vec![0; 8192];
            let count = self
                .file
                .as_mut()
                .unwrap()
                .read(&mut chunk)
                .map_err(|e| BodyError::Read(e.to_string()))?;
            chunk.truncate(count);
            Ok(if count == 0 { None } else { Some(chunk) })
        })
    }
}
struct Audit;
impl ManagedBackend for Audit {
    fn call(&self, request: Value, _: Duration) -> LocalFuture<'_, Result<Value, HookError>> {
        Box::pin(async move {
            Ok(
                json!({"jsonrpc":"2.0","id":request["id"],"result":{"protocolVersion":"draft","effects":[]}}),
            )
        })
    }
    fn shutdown(&self) -> LocalFuture<'_, Result<(), HookError>> {
        Box::pin(async { Ok(()) })
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = PathBuf::from(std::env::args_os().nth(1).ok_or("supply a file path")?);
    futures::executor::block_on(async move {
        let options = HooksOptions::new(
            "urn:example:document-assistant",
            BTreeMap::from([(
                "user.message.outbound".into(),
                EventGrant::intercept(Capabilities::none()),
            )]),
        )
        .with_backend("org.example.audit", Arc::new(Audit));
        let hooks = Hooks::new(
            json!({"protocolVersion":"draft","hooks":[{
                "id":"org.example.audit", "transport":{"type":"stdio","command":"host-owned","lifecycle":"persistent"},
                "subscriptions":[{"events":["user.message.outbound"],"mode":"intercept","timeoutMs":1000,
                    "failurePolicy":"fail-closed","content":{"default":"metadata"}}]
            }]}),
            options,
        )?;
        let result = hooks
            .event(
                json!({"type":"user.message.outbound","message":{"channel":"chat","payload":[{
                    "id":"report", "kind":"content","category":"content","role":"assistant",
                    "mediaType":"application/pdf","selection":"metadata"
                }]}}),
            )
            .attachment(message_payload(
                0,
                Attachment::lazy(FileSource { path, file: None }),
            ))
            .await?;
        hooks.shutdown().await?;
        drop(hooks);
        // The metadata-only audit never opened the file. The result now owns it.
        let bytes = result.content.read("/message/payload/0").await?;
        println!("File ready for application delivery: {} bytes", bytes.len());
        Ok(())
    })
}
