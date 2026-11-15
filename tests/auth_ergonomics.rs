#![cfg(feature = "reqwest")]

use agenthooksprotocol::{
    adapters::registered::{
        AuthChallenge, AuthContext, AuthProvider, AuthPurpose, BackendOptions, BearerCredential,
        HeaderContext, HeaderResolver, HeaderSource, ManagedBackend, from_registration,
    },
    auth::{AuthBinding, AuthErrorCode, AuthProviders, AuthRecovery, BearerAuth, OAuthFlow},
    client::{HookError, LocalFuture},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
};

const TIMEOUT: Duration = Duration::from_secs(3);
fn request() -> Value {
    json!({"jsonrpc":"2.0","id":"caps","method":"hooks/capabilities","params":{"protocolVersion":"draft"}})
}
fn oauth() -> Value {
    json!({"type":"oauth","flow":"client_credentials","resource":"https://resource.example/hooks",
        "issuer":"https://issuer.example","clientId":"client","clientSecretRef":"oauth-secret"})
}
fn backend(
    endpoint: &str,
    binding: Option<Value>,
    provider: Arc<dyn AuthProvider>,
    explicit: bool,
) -> Arc<dyn ManagedBackend> {
    let mut registration =
        json!({"id":"org.example.auth","transport":{"type":"http","url":endpoint}});
    if let Some(binding) = binding {
        registration["authentication"] = binding;
    }
    if explicit {
        registration["transport"]["headers"] = json!({"Authorization":"Bearer explicit-only"});
    }
    from_registration(
        &registration,
        &BackendOptions {
            auth_provider: Some(provider),
            allow_loopback_http: true,
            ..Default::default()
        },
    )
    .unwrap()
}
async fn listener() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/hooks", listener.local_addr().unwrap());
    (listener, endpoint)
}
// Close each response so a retry must cross the real HTTP boundary again.
async fn respond(listener: &TcpListener, status: u16) -> (String, Vec<u8>) {
    let (socket, _) = listener.accept().await.unwrap();
    let mut reader = BufReader::new(socket);
    let mut headers = String::new();
    let mut size = 0;
    loop {
        let mut line = String::new();
        assert_ne!(reader.read_line(&mut line).await.unwrap(), 0);
        if line == "\r\n" {
            break;
        }
        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            size = value.trim().parse().unwrap();
        }
        headers.push_str(&line.to_ascii_lowercase());
    }
    let mut body = vec![0; size];
    reader.read_exact(&mut body).await.unwrap();
    reader.get_mut().write_all(format!("HTTP/1.1 {status} Rejected\r\nWWW-Authenticate: Bearer error=\"invalid_token\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    (headers, body)
}
#[derive(Clone, Copy)]
enum Outcome {
    Token,
    None,
    Error,
    AfterChallenge,
    SecretClassified,
}
struct Provider {
    outcome: Outcome,
    contexts: Mutex<Vec<AuthContext>>,
    challenges: Mutex<Vec<AuthChallenge>>,
}
impl Provider {
    fn new(outcome: Outcome) -> Arc<Self> {
        Arc::new(Self {
            outcome,
            contexts: Mutex::new(Vec::new()),
            challenges: Mutex::new(Vec::new()),
        })
    }
}
impl AuthProvider for Provider {
    fn credential(
        &self,
        context: AuthContext,
    ) -> LocalFuture<'_, Result<Option<BearerCredential>, HookError>> {
        Box::pin(async move {
            self.contexts.lock().unwrap().push(context);
            match self.outcome {
                Outcome::None => Ok(None),
                Outcome::Error => Err(HookError::authentication(
                    AuthErrorCode::InteractionRequired,
                )),
                Outcome::SecretClassified => Err(HookError::new(
                    "secret-token callback?code=secret response-body",
                )
                .classified(
                    agenthooksprotocol::generated::DeliveryDiagnosticCode::ProtocolRejection,
                )),
                Outcome::AfterChallenge if self.challenges.lock().unwrap().is_empty() => Ok(None),
                _ => Ok(Some(BearerCredential {
                    token: "oauth-only".into(),
                    attempt_id: "generation-1".into(),
                })),
            }
        })
    }
    fn challenge(
        &self,
        _: AuthContext,
        challenge: AuthChallenge,
    ) -> LocalFuture<'_, Result<(), HookError>> {
        Box::pin(async move {
            self.challenges.lock().unwrap().push(challenge);
            Ok(())
        })
    }
}
fn credentials() -> BearerAuth {
    BearerAuth::from_credentials(BTreeMap::from([(
        "bearer-secret".into(),
        "bearer-only".into(),
    )]))
}
#[tokio::test]
async fn mixed_bearer_oauth() {
    let (listener, endpoint) = listener().await;
    let provider = Provider::new(Outcome::Token);
    let routes = Arc::new(
        AuthProviders::builder()
            .bearer(credentials())
            .oauth(provider.clone())
            .build(),
    );
    let bearer = backend(
        &endpoint,
        Some(json!({"type":"bearer","tokenRef":"bearer-secret"})),
        routes.clone(),
        false,
    );
    let oauth_backend = backend(&endpoint, Some(oauth()), routes, false);
    tokio::time::timeout(TIMEOUT, async {
        let (result, (headers, _)) =
            tokio::join!(bearer.call(request(), TIMEOUT), respond(&listener, 403));
        assert!(result.is_err());
        assert!(headers.contains("authorization: bearer bearer-only\r\n"));
        assert!(provider.contexts.lock().unwrap().is_empty());
        let (result, (headers, _)) = tokio::join!(
            oauth_backend.call(request(), TIMEOUT),
            respond(&listener, 403)
        );
        assert!(result.is_err());
        assert!(headers.contains("authorization: bearer oauth-only\r\n"));
    })
    .await
    .unwrap();
    let contexts = provider.contexts.lock().unwrap();
    assert_eq!(contexts.len(), 1);
    let target = contexts[0].target().unwrap();
    assert_eq!(target.backend_id(), "org.example.auth");
    assert_eq!(target.destination().as_str(), endpoint);
    assert_eq!(target.purpose(), AuthPurpose::Event);
    assert!(
        matches!(target.binding(), AuthBinding::OAuth { flow: OAuthFlow::ClientCredentials, resource } if resource == "https://resource.example/hooks")
    );
}
#[tokio::test]
async fn explicit_authorization() {
    let (listener, endpoint) = listener().await;
    let provider = Provider::new(Outcome::Error);
    let routes = Arc::new(
        AuthProviders::builder()
            .bearer(credentials())
            .oauth(provider.clone())
            .unbound(provider.clone())
            .build(),
    );
    let backend = backend(&endpoint, Some(oauth()), routes, true);
    tokio::time::timeout(TIMEOUT, async {
        let (_, (headers, _)) =
            tokio::join!(backend.call(json!({"jsonrpc":"2.0","id":"config","method":"hooks/configuration","params":{"protocolVersion":"draft"}}), TIMEOUT), respond(&listener, 401));
        assert!(headers.contains("authorization: bearer explicit-only\r\n"));
    })
    .await
    .unwrap();
    assert!(provider.contexts.lock().unwrap().is_empty());
    assert!(provider.challenges.lock().unwrap().is_empty());
}
async fn no_network(binding: Value, routes: Arc<dyn AuthProvider>) -> HookError {
    let (listener, endpoint) = listener().await;
    let backend = backend(&endpoint, Some(binding), routes, false);
    let error = tokio::time::timeout(TIMEOUT, backend.call(request(), TIMEOUT))
        .await
        .unwrap()
        .unwrap_err();
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err(),
        "authentication failure must not send an anonymous request"
    );
    error
}
#[tokio::test]
async fn missing_bearer_secret() {
    let fallback = Provider::new(Outcome::Token);
    let routes = Arc::new(
        AuthProviders::builder()
            .bearer(credentials())
            .oauth(fallback.clone())
            .unbound(fallback.clone())
            .build(),
    );
    let error = no_network(json!({"type":"bearer","tokenRef":"missing-secret"}), routes).await;
    assert_eq!(
        error.auth_code(),
        Some(AuthErrorCode::CredentialUnavailable)
    );
    assert!(fallback.contexts.lock().unwrap().is_empty());
    assert!(fallback.challenges.lock().unwrap().is_empty());
    assert!(!format!("{error:?} {error}").contains("missing-secret"));
}
#[tokio::test]
async fn oauth_no_credential() {
    let provider = Provider::new(Outcome::None);
    let fallback = Provider::new(Outcome::Token);
    let routes = Arc::new(
        AuthProviders::builder()
            .bearer(credentials())
            .oauth(provider.clone())
            .unbound(fallback.clone())
            .build(),
    );
    let error = no_network(oauth(), routes).await;
    assert_eq!(
        error.auth_code(),
        Some(AuthErrorCode::CredentialUnavailable)
    );
    assert_eq!(provider.contexts.lock().unwrap().len(), 1);
    assert!(fallback.contexts.lock().unwrap().is_empty());
}
#[tokio::test]
async fn redaction() {
    let provider = Provider::new(Outcome::Error);
    let error = no_network(
        oauth(),
        Arc::new(AuthProviders::builder().oauth(provider).build()),
    )
    .await;
    let expected = HookError::authentication(AuthErrorCode::InteractionRequired);
    assert_eq!(error.auth_code(), expected.auth_code());
    let recovery: Option<AuthRecovery> = error.auth_recovery();
    assert_eq!(recovery, expected.auth_recovery());
    assert_eq!(error.to_string(), expected.to_string());
    let public = format!("{error:?} {error}");
    for secret in [
        "oauth-secret",
        "oauth-only",
        "issuer.example",
        "resource.example",
    ] {
        assert!(!public.contains(secret));
    }
}
#[tokio::test]
async fn unconfigured_challenge() {
    let (listener, endpoint) = listener().await;
    let provider = Provider::new(Outcome::AfterChallenge);
    let backend = backend(
        &endpoint,
        None,
        Arc::new(AuthProviders::builder().unbound(provider.clone()).build()),
        false,
    );
    tokio::time::timeout(TIMEOUT, async {
        let server = async {
            let first = respond(&listener, 401).await;
            assert!(!first.0.contains("authorization:"));
            let second = respond(&listener, 403).await;
            assert!(second.0.contains("authorization: bearer oauth-only\r\n"));
            assert_eq!(first.1, second.1);
        };
        let (result, ()) = tokio::join!(backend.call(request(), TIMEOUT), server);
        assert!(result.is_err());
    })
    .await
    .unwrap();
    let contexts = provider.contexts.lock().unwrap();
    assert_eq!(contexts.len(), 2);
    assert!(matches!(
        contexts[0].target().unwrap().binding(),
        AuthBinding::Unbound
    ));
    let challenges = provider.challenges.lock().unwrap();
    assert_eq!(challenges.len(), 1);
    assert_eq!(challenges[0].attempt_id, None);
    assert_eq!(challenges[0].status, 401);
}
struct Resolver(Mutex<Vec<HeaderContext>>);
impl HeaderResolver for Resolver {
    fn resolve(&self, context: HeaderContext) -> LocalFuture<'_, Result<String, HookError>> {
        Box::pin(async move {
            self.0.lock().unwrap().push(context);
            Ok("resolved-only".into())
        })
    }
}
#[tokio::test]
async fn async_bearer_resolver_reuses_header_context() {
    let (listener, endpoint) = listener().await;
    let resolver = Arc::new(Resolver(Mutex::new(Vec::new())));
    let routes = Arc::new(
        AuthProviders::builder()
            .bearer(BearerAuth::new(resolver.clone()))
            .build(),
    );
    let backend = backend(
        &endpoint,
        Some(json!({"type":"bearer","tokenRef":"resolver-ref"})),
        routes,
        false,
    );
    tokio::time::timeout(TIMEOUT, async {
        let (_, (headers, _)) =
            tokio::join!(backend.call(request(), TIMEOUT), respond(&listener, 403));
        assert!(headers.contains("authorization: bearer resolved-only\r\n"));
    })
    .await
    .unwrap();
    let contexts = resolver.0.lock().unwrap();
    assert_eq!(contexts.len(), 1);
    assert_eq!(contexts[0].backend_id, "org.example.auth");
    assert_eq!(contexts[0].destination, endpoint);
    assert_eq!(contexts[0].purpose, AuthPurpose::Event);
    assert!(
        matches!(&contexts[0].source, HeaderSource::Reference(reference) if reference == "resolver-ref")
    );
}

#[tokio::test]
async fn classified_provider_error_has_no_secret_cause_chain() {
    let error = no_network(
        oauth(),
        Arc::new(
            AuthProviders::builder()
                .oauth(Provider::new(Outcome::SecretClassified))
                .build(),
        ),
    )
    .await;
    assert_eq!(
        error.code(),
        agenthooksprotocol::generated::DeliveryDiagnosticCode::ProtocolRejection
    );
    assert_eq!(error.auth_code(), Some(AuthErrorCode::ProviderFailed));
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(&error);
    while let Some(cause) = current {
        let public = format!("{cause:?} {cause}");
        for secret in ["secret-token", "callback?code=secret", "response-body"] {
            assert!(!public.contains(secret));
        }
        current = cause.source();
    }
}

#[tokio::test]
async fn typed_targets_preserve_exact_identity_and_both_oauth_flows() {
    for (wire, expected) in [
        ("authorization_code_pkce", OAuthFlow::AuthorizationCodePkce),
        ("client_credentials", OAuthFlow::ClientCredentials),
    ] {
        let (listener, endpoint) = listener().await;
        let provider = Provider::new(Outcome::Token);
        let binding = json!({"type":"oauth","flow":wire,"resource":"opaque:RESOURCE/a%2Fb?aud=Exact",
            "issuer":"https://ISSUER.example:443/tenant/", "clientId":"exact-client",
            "clientSecretRef":"exact-secret-ref", "scopes":["second", "first"]});
        let backend = backend(
            &endpoint,
            Some(binding),
            Arc::new(AuthProviders::builder().oauth(provider.clone()).build()),
            false,
        );
        tokio::time::timeout(TIMEOUT, async {
            let (_, (headers, _)) =
                tokio::join!(backend.call(request(), TIMEOUT), respond(&listener, 403));
            assert!(headers.contains("authorization: bearer oauth-only\r\n"));
        })
        .await
        .unwrap();
        let contexts = provider.contexts.lock().unwrap();
        let target = contexts[0].target().unwrap();
        assert!(
            matches!(target.binding(), AuthBinding::OAuth {flow, resource} if *flow == expected && resource == "opaque:RESOURCE/a%2Fb?aud=Exact")
        );
        assert_eq!(target.issuer(), Some("https://ISSUER.example:443/tenant/"));
        assert_eq!(target.client_id(), Some("exact-client"));
        assert_eq!(target.client_secret_ref(), Some("exact-secret-ref"));
        assert_eq!(target.scopes(), ["second", "first"]);
    }
}

#[tokio::test]
async fn malformed_binding_never_reaches_provider_or_network() {
    for binding in [
        json!({"type":"bearer","tokenRef":"a","tokenEnv":"B"}),
        json!({"type":"oauth","flow":"client_credentials","resource":"opaque", "issuer":"https://issuer.example", "clientId":"client", "scopes":["duplicate", "duplicate"]}),
    ] {
        let (listener, endpoint) = listener().await;
        let provider = Provider::new(Outcome::Token);
        let registration = json!({"id":"malformed","transport":{"type":"http","url":endpoint},"authentication":binding});
        let result = from_registration(
            &registration,
            &BackendOptions {
                auth_provider: Some(Arc::new(
                    AuthProviders::builder()
                        .bearer(credentials())
                        .oauth(provider.clone())
                        .unbound(provider.clone())
                        .build(),
                )),
                allow_loopback_http: true,
                ..Default::default()
            },
        );
        let error = match result {
            Ok(backend) => tokio::time::timeout(TIMEOUT, backend.call(request(), TIMEOUT))
                .await
                .unwrap()
                .unwrap_err(),
            Err(error) => error,
        };
        assert_eq!(error.auth_code(), Some(AuthErrorCode::InvalidConfiguration));
        assert!(provider.contexts.lock().unwrap().is_empty());
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn effectful_no_replay() {
    let (listener, endpoint) = listener().await;
    let provider = Provider::new(Outcome::AfterChallenge);
    let backend = backend(
        &endpoint,
        None,
        Arc::new(AuthProviders::builder().unbound(provider.clone()).build()),
        false,
    );
    let request = json!({"jsonrpc":"2.0","id":"evt_demo","method":"hooks/intercept","params":{"protocolVersion":"draft","event":{"id":"evt_demo","harness":{"name":"test","version":"1"},"source":"urn:example:demo","type":"tool.before","time":"2026-08-24T08:51:14Z","session":{"id":"sess_demo","cwd":"/repo","workspaceRoots":["/repo"]},"tool":{"name":"Bash","kind":"shell","input":{"command":"echo hello"},"origin":"native"},"call":{"id":"call_demo"},"path":"example"},"capabilities":{"effects":["deny"]}}});
    tokio::time::timeout(TIMEOUT, async {
        let (result, (headers, _)) =
            tokio::join!(backend.call(request, TIMEOUT), respond(&listener, 401));
        assert!(result.is_err());
        assert!(!headers.contains("authorization:"));
    })
    .await
    .unwrap();
    assert_eq!(provider.contexts.lock().unwrap().len(), 1);
    assert_eq!(provider.challenges.lock().unwrap().len(), 1);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err(),
        "effectful delivery must not be replayed after challenge"
    );
}
