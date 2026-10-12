//! Application policy without any network runtime.
use agenthooksprotocol::server::*;
use serde_json::json;

pub struct Credentials;
impl Authenticator for Credentials {
    fn authenticate(&self, authorization: Option<&str>) -> Result<Principal, String> {
        // Demonstration only: production applications install their credential verifier.
        if authorization != Some("Bearer local-demo") {
            return Err("invalid credential".into());
        }
        Ok(Principal {
            subject: "local-demo-user".into(),
        })
    }
}
pub fn handlers() -> HandlerSet {
    let mut handlers = HandlerSet::default();
    handlers.intercept.tool_before = Some(std::sync::Arc::new(|ctx, _event| {
        Box::pin(async move {
            assert_eq!(ctx.principal.subject, "local-demo-user");
            Ok(ctx.reply())
        })
    }));
    handlers.observe.tool_before = Some(std::sync::Arc::new(|ctx, _event| {
        Box::pin(async move {
            assert_eq!(ctx.principal.subject, "local-demo-user");
            Ok(())
        })
    }));
    handlers
}
pub fn request_body() -> Vec<u8> {
    serde_json::to_vec(&json!({"jsonrpc":"2.0","id":"evt_demo","method":"hooks/intercept","params":{"protocolVersion":"draft","event":{"id":"evt_demo","source":"urn:example:demo","type":"tool.before","time":"2026-08-24T08:51:14Z","session":{"id":"sess_demo","cwd":"/repo","workspaceRoots":["/repo"]},"tool":{"name":"Bash","kind":"shell","input":{"command":"echo hello"},"origin":"native"},"call":{"id":"call_demo"},"path":"example"},"capabilities":{"effects":["deny"]}}})).unwrap()
}
#[allow(dead_code)]
fn main() {
    let server = Server {
        handlers: handlers(),
        authenticator: Credentials,
        max_body_bytes: 65536,
    };
    let response = futures::executor::block_on(agenthooksprotocol::adapters::stdio::dispatch(
        &server,
        request_body(),
        Some("Bearer local-demo".into()),
    ));
    assert_eq!(response.status, 200);
    println!("{}", String::from_utf8(response.body).unwrap());
}
