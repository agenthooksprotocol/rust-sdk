//! Run with --features reqwest,axum. Uses an actual loopback HTTP socket.
#[path = "neutral_server.rs"]
mod demo;
use agenthooksprotocol::{
    adapters,
    server::Server,
    transport::{Http, Request},
};
use std::{collections::BTreeMap, sync::Arc};
#[tokio::main(flavor = "current_thread")]
async fn main() {
    let server = Arc::new(Server {
        handler: demo::Policy,
        authenticator: demo::Credentials,
        max_body_bytes: 65536,
    });
    let app = axum::Router::new().route(
        "/hooks",
        axum::routing::post(move |request| {
            let server = server.clone();
            async move { adapters::axum::handle(&server, request).await }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let uri = format!("http://{}/hooks", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let http = adapters::reqwest::ReqwestHttp::with_options(65536, true).unwrap();
    let response = http
        .send(Request {
            method: "POST".into(),
            uri: uri.clone(),
            headers: BTreeMap::from([
                ("content-type".into(), "application/json".into()),
                ("authorization".into(), "Bearer local-demo".into()),
            ]),
            body: demo::request_body(),
        })
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&response.body).unwrap()["id"],
        "evt_demo"
    );
    #[derive(serde::Serialize, serde::Deserialize)]
    struct ShellInput {
        command: String,
    }
    let wire: serde_json::Value = serde_json::from_slice(&demo::request_body()).unwrap();
    let client = agenthooksprotocol::client::Client::new(
        agenthooksprotocol::client::ToolContext::new(wire["params"]["event"].clone()),
    )
    .with_subscription(agenthooksprotocol::client::Subscription::intercept(
        "http-policy",
        agenthooksprotocol::client::FailurePolicy::Closed,
        adapters::http_hook::HttpHook {
            http,
            endpoint: uri,
            authorization: "Bearer local-demo".into(),
        },
    ));
    let result = client
        .tool_before(ShellInput {
            command: "echo typed".into(),
        })
        .await
        .unwrap();
    assert_eq!(result.input.unwrap().command, "echo typed");
    assert!(result.outcome.failures.is_empty());
    // Permission is still an application concern. This example executes no shell command.
    task.abort();
    println!("Correlated interception over loopback HTTP succeeded");
}
