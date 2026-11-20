//! Additive, explicit authentication composition for registration transports.
//!
//! Installing a legacy `AuthProvider` still gives that provider full ownership.
//! Use `AuthProviders` to opt into binding-based routing instead. This module
//! performs no discovery, opens no browser, and owns no background tasks.
use crate::{
    adapters::registered::{
        AuthChallenge, AuthContext, AuthProvider, AuthPurpose, BearerCredential, HeaderContext,
        HeaderResolver, HeaderSource,
    },
    client::{HookError, LocalFuture},
};
use std::{collections::BTreeMap, sync::Arc};

#[cfg(any(feature = "reqwest", feature = "managed-oauth", test))]
pub(crate) mod challenge;

/// Optional host-driven PKCE and client-credentials OAuth implementation.
#[cfg(feature = "managed-oauth")]
pub mod managed;

/// Safe, stable authentication classifications, independent of protocol diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthErrorCode {
    InvalidConfiguration,
    UnsupportedBinding,
    CredentialUnavailable,
    InteractionRequired,
    AccessDenied,
    RefreshRejected,
    DiscoveryFailed,
    UntrustedDestination,
    ProviderFailed,
}
impl AuthErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidConfiguration => "invalid_configuration",
            Self::UnsupportedBinding => "unsupported_binding",
            Self::CredentialUnavailable => "credential_unavailable",
            Self::InteractionRequired => "interaction_required",
            Self::AccessDenied => "access_denied",
            Self::RefreshRejected => "refresh_rejected",
            Self::DiscoveryFailed => "discovery_failed",
            Self::UntrustedDestination => "untrusted_destination",
            Self::ProviderFailed => "provider_failed",
        }
    }
    pub const fn recovery(self) -> AuthRecovery {
        match self {
            Self::InteractionRequired | Self::RefreshRejected => AuthRecovery::Login,
            Self::CredentialUnavailable
            | Self::InvalidConfiguration
            | Self::UnsupportedBinding
            | Self::UntrustedDestination => AuthRecovery::Configure,
            Self::AccessDenied => AuthRecovery::None,
            Self::ProviderFailed | Self::DiscoveryFailed => AuthRecovery::Retry,
        }
    }
}
/// Guidance only: never permission to replay an effectful request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthRecovery {
    None,
    Configure,
    Login,
    Retry,
}
impl AuthRecovery {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Configure => "configure",
            Self::Login => "login",
            Self::Retry => "retry",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OAuthFlow {
    AuthorizationCodePkce,
    ClientCredentials,
}

/// Normalized known binding. Intentionally not Debug: references are host-private.
#[derive(Clone)]
#[non_exhaustive]
pub enum AuthBinding {
    Unbound,
    Bearer(HeaderSource),
    OAuth { flow: OAuthFlow, resource: String },
}
/// Owned request-local view, not a credential cache key. The full destination,
/// backend and purpose remain distinct; hosts must add their credential namespace.
/// OAuth resource and issuer strings retain their exact configured identity.
#[derive(Clone)]
#[non_exhaustive]
pub struct AuthTarget {
    backend_id: String,
    destination: url::Url,
    purpose: AuthPurpose,
    binding: AuthBinding,
    issuer: Option<String>,
    client_id: Option<String>,
    client_secret_ref: Option<String>,
    scopes: Vec<String>,
}
impl AuthTarget {
    pub fn backend_id(&self) -> &str {
        &self.backend_id
    }
    pub fn destination(&self) -> &url::Url {
        &self.destination
    }
    pub fn purpose(&self) -> AuthPurpose {
        self.purpose
    }
    pub fn binding(&self) -> &AuthBinding {
        &self.binding
    }
    pub fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }
    pub fn client_id(&self) -> Option<&str> {
        self.client_id.as_deref()
    }
    pub fn client_secret_ref(&self) -> Option<&str> {
        self.client_secret_ref.as_deref()
    }
    /// The preset's optional `scopes`: the client's requested scopes, never required.
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }
}
impl AuthContext {
    /// Validate and normalize without network access or secret resolution.
    /// This is not destination trust approval; transports/hosts retain that duty.
    pub fn target(&self) -> Result<AuthTarget, HookError> {
        let invalid = || HookError::authentication(AuthErrorCode::InvalidConfiguration);
        if self.backend_id.trim().is_empty() {
            return Err(invalid());
        }
        let destination = url::Url::parse(&self.destination).map_err(|_| invalid())?;
        if !matches!(destination.scheme(), "https" | "http")
            || destination.host_str().is_none()
            || !destination.username().is_empty()
            || destination.password().is_some()
            || destination.fragment().is_some()
        {
            return Err(invalid());
        }
        let mut target = AuthTarget {
            backend_id: self.backend_id.clone(),
            destination,
            purpose: self.purpose,
            binding: AuthBinding::Unbound,
            issuer: None,
            client_id: None,
            client_secret_ref: None,
            scopes: Vec::new(),
        };
        if let Some(auth) = &self.authentication {
            let required = |key: &str| {
                auth[key]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .ok_or_else(invalid)
            };
            target.binding = match auth["type"].as_str() {
                Some("bearer") => {
                    let source = match (auth.get("tokenRef"), auth.get("tokenEnv")) {
                        (Some(_), None) => HeaderSource::Reference(required("tokenRef")?),
                        (None, Some(_)) => {
                            let name = required("tokenEnv")?;
                            if !name.bytes().enumerate().all(|(i, b)| {
                                b == b'_'
                                    || b.is_ascii_alphabetic()
                                    || (i > 0 && b.is_ascii_digit())
                            }) {
                                return Err(invalid());
                            }
                            HeaderSource::Environment(name)
                        }
                        _ => return Err(invalid()),
                    };
                    AuthBinding::Bearer(source)
                }
                Some("oauth") => {
                    let flow = match auth["flow"].as_str() {
                        Some("authorization_code_pkce") => OAuthFlow::AuthorizationCodePkce,
                        Some("client_credentials") => OAuthFlow::ClientCredentials,
                        _ => {
                            return Err(HookError::authentication(
                                AuthErrorCode::UnsupportedBinding,
                            ));
                        }
                    };
                    let issuer = required("issuer")?;
                    let issuer_url = url::Url::parse(&issuer).map_err(|_| invalid())?;
                    if issuer_url.scheme() != "https"
                        || issuer_url.host_str().is_none()
                        || !issuer_url.username().is_empty()
                        || issuer_url.password().is_some()
                        || issuer_url.fragment().is_some()
                    {
                        return Err(invalid());
                    }
                    target.issuer = Some(issuer);
                    target.client_id = Some(required("clientId")?);
                    if auth.get("clientSecretRef").is_some() {
                        target.client_secret_ref = Some(required("clientSecretRef")?);
                    }
                    if let Some(scopes) = auth.get("scopes") {
                        for scope in scopes.as_array().ok_or_else(invalid)? {
                            let scope = scope
                                .as_str()
                                .filter(|s| !s.is_empty())
                                .ok_or_else(invalid)?;
                            if target.scopes.iter().any(|s| s == scope) {
                                return Err(invalid());
                            }
                            target.scopes.push(scope.to_owned());
                        }
                    }
                    AuthBinding::OAuth {
                        flow,
                        resource: required("resource")?,
                    }
                }
                _ => return Err(HookError::authentication(AuthErrorCode::UnsupportedBinding)),
            };
        }
        Ok(target)
    }
}

/// Bearer-only adapter using the existing host header/secret resolver contract.
/// Tokens are resolved at dispatch time and are never used as attempt identifiers.
#[non_exhaustive]
pub struct BearerAuth {
    resolver: Arc<dyn HeaderResolver>,
}
impl BearerAuth {
    pub fn new(resolver: Arc<dyn HeaderResolver>) -> Self {
        Self { resolver }
    }
    /// References use this snapshot; environment access requires an explicit tokenEnv.
    pub fn from_credentials(credentials: BTreeMap<String, String>) -> Self {
        Self::new(Arc::new(Credentials(credentials)))
    }
}
struct Credentials(BTreeMap<String, String>);
impl HeaderResolver for Credentials {
    fn resolve(&self, context: HeaderContext) -> LocalFuture<'_, Result<String, HookError>> {
        Box::pin(async move {
            let value = match context.source {
                HeaderSource::Reference(key) => self.0.get(&key).cloned(),
                HeaderSource::Environment(key) => std::env::var(key).ok(),
            };
            value.ok_or_else(|| HookError::authentication(AuthErrorCode::CredentialUnavailable))
        })
    }
}
impl AuthProvider for BearerAuth {
    fn credential(
        &self,
        context: AuthContext,
    ) -> LocalFuture<'_, Result<Option<BearerCredential>, HookError>> {
        Box::pin(async move {
            let target = context.target()?;
            let AuthBinding::Bearer(source) = target.binding else {
                return Err(HookError::authentication(AuthErrorCode::UnsupportedBinding));
            };
            let token = self
                .resolver
                .resolve(HeaderContext {
                    backend_id: context.backend_id,
                    destination: context.destination,
                    purpose: context.purpose,
                    deadline: context.deadline,
                    source,
                })
                .await
                .map_err(sanitize_provider_error)?;
            if token.is_empty() || !token.bytes().all(|b| b.is_ascii_graphic()) {
                return Err(HookError::authentication(
                    AuthErrorCode::CredentialUnavailable,
                ));
            }
            // This provider never refreshes or invalidates, so needs no generation identity.
            Ok(Some(BearerCredential {
                token,
                attempt_id: "static-bearer".into(),
            }))
        })
    }
    fn challenge(
        &self,
        _: AuthContext,
        _: AuthChallenge,
    ) -> LocalFuture<'_, Result<(), HookError>> {
        Box::pin(async { Err(HookError::authentication(AuthErrorCode::AccessDenied)) })
    }
}

/// Explicit binding router. No route is selected by catching provider errors.
/// Immutable routes send a challenge back to the same owner without a global registry.
#[non_exhaustive]
pub struct AuthProviders {
    bearer: Option<Arc<dyn AuthProvider>>,
    oauth: Option<Arc<dyn AuthProvider>>,
    unbound: Option<Arc<dyn AuthProvider>>,
}
#[derive(Default)]
#[non_exhaustive]
pub struct AuthProvidersBuilder {
    bearer: Option<Arc<dyn AuthProvider>>,
    oauth: Option<Arc<dyn AuthProvider>>,
    unbound: Option<Arc<dyn AuthProvider>>,
}
impl AuthProvidersBuilder {
    pub fn bearer(mut self, provider: BearerAuth) -> Self {
        self.bearer = Some(Arc::new(provider));
        self
    }
    pub fn bearer_provider(mut self, provider: Arc<dyn AuthProvider>) -> Self {
        self.bearer = Some(provider);
        self
    }
    pub fn oauth(mut self, provider: Arc<dyn AuthProvider>) -> Self {
        self.oauth = Some(provider);
        self
    }
    /// Host discovery provider. Initially may return None, then handle a 401.
    pub fn unbound(mut self, provider: Arc<dyn AuthProvider>) -> Self {
        self.unbound = Some(provider);
        self
    }
    pub fn build(self) -> AuthProviders {
        AuthProviders {
            bearer: self.bearer,
            oauth: self.oauth,
            unbound: self.unbound,
        }
    }
}
impl AuthProviders {
    pub fn builder() -> AuthProvidersBuilder {
        AuthProvidersBuilder::default()
    }
    fn route(&self, context: &AuthContext) -> Result<Option<&Arc<dyn AuthProvider>>, HookError> {
        let target = context.target()?;
        let provider = match target.binding() {
            AuthBinding::Unbound => return Ok(self.unbound.as_ref()),
            AuthBinding::Bearer(_) => self.bearer.as_ref(),
            AuthBinding::OAuth { .. } => self.oauth.as_ref(),
        };
        provider
            .map(Some)
            .ok_or_else(|| HookError::authentication(AuthErrorCode::UnsupportedBinding))
    }
}
impl AuthProvider for AuthProviders {
    fn credential(
        &self,
        context: AuthContext,
    ) -> LocalFuture<'_, Result<Option<BearerCredential>, HookError>> {
        Box::pin(async move {
            let Some(provider) = self.route(&context)? else {
                return Ok(None);
            };
            let bound = context.authentication.is_some();
            let credential = provider
                .credential(context)
                .await
                .map_err(sanitize_provider_error)?;
            if bound && credential.is_none() {
                return Err(HookError::authentication(
                    AuthErrorCode::CredentialUnavailable,
                ));
            }
            Ok(credential)
        })
    }
    fn challenge(
        &self,
        context: AuthContext,
        challenge: AuthChallenge,
    ) -> LocalFuture<'_, Result<(), HookError>> {
        Box::pin(async move {
            match self.route(&context)? {
                Some(provider) => provider
                    .challenge(context, challenge)
                    .await
                    .map_err(sanitize_provider_error),
                None => Err(HookError::authentication(AuthErrorCode::UnsupportedBinding)),
            }
        })
    }
    fn preparations(&self, context: &AuthContext) -> u64 {
        match self.route(context) {
            Ok(Some(provider)) => provider.preparations(context),
            _ => 0,
        }
    }
}
/// Only typed safe classifications cross a provider boundary, never arbitrary
/// messages, attached settlements, or source chains from a third-party provider.
pub(crate) fn sanitize_provider_error(error: HookError) -> HookError {
    HookError::authentication(error.auth_code().unwrap_or(AuthErrorCode::ProviderFailed))
        .classified(error.code())
        .with_required_scopes(error.required_scopes())
        .unscoped_if(error.is_unscoped())
        .request_not_sent_if(error.is_request_not_sent())
}
/// RFC 6749 section 3.3 scope-token grammar.
pub(crate) fn valid_scope(scope: &str) -> bool {
    !scope.is_empty()
        && scope
            .bytes()
            .all(|b| b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_backend_identity_fails_closed() {
        let context = AuthContext {
            backend_id: String::new(),
            authentication: None,
            destination: "https://api.example/hooks".into(),
            purpose: AuthPurpose::Event,
            deadline: std::time::Instant::now(),
        };
        assert_eq!(
            context.target().err().unwrap().auth_code(),
            Some(AuthErrorCode::InvalidConfiguration)
        );
    }

    #[test]
    fn canonical_recovery_guidance() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("auth/managed/tests/sdk-auth-lifecycle.json"))
                .unwrap();
        let codes = [
            AuthErrorCode::InvalidConfiguration,
            AuthErrorCode::UnsupportedBinding,
            AuthErrorCode::CredentialUnavailable,
            AuthErrorCode::InteractionRequired,
            AuthErrorCode::AccessDenied,
            AuthErrorCode::RefreshRejected,
            AuthErrorCode::DiscoveryFailed,
            AuthErrorCode::UntrustedDestination,
            AuthErrorCode::ProviderFailed,
        ];
        assert_eq!(vectors["recovery"].as_array().unwrap().len(), codes.len());
        for vector in vectors["recovery"].as_array().unwrap() {
            let code = codes
                .iter()
                .find(|code| code.as_str() == vector["code"])
                .unwrap();
            assert_eq!(
                code.recovery().as_str(),
                vector["recovery"],
                "{}",
                code.as_str()
            );
        }
    }
}
