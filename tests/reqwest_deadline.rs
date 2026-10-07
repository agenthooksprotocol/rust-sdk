#![cfg(all(feature = "reqwest", feature = "axum"))]
use agenthooksprotocol::{
    adapters::reqwest::ReqwestHttp,
    transport::{Http, Request},
};
use std::time::Duration;

#[tokio::test]
async fn explicit_http_deadline_bounds_permanently_pending_io() {
    let app = axum::Router::new().route(
        "/pending",
        axum::routing::post(|| async { futures::future::pending::<&'static str>().await }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let uri = format!("http://{}/pending", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    assert!(ReqwestHttp::with_timeout(1024, true, Duration::ZERO).is_err());
    let http = ReqwestHttp::with_timeout(1024, true, Duration::from_millis(50)).unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        http.send(Request {
            method: "POST".into(),
            uri,
            ..Request::default()
        }),
    )
    .await
    .expect("the adapter's own deadline must finish first");
    assert!(result.is_err());
    server.abort();
    let _ = server.await;
}
