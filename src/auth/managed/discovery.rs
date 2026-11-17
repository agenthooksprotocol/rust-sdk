//! Strict, policy-gated MCP 2025-11-25 OAuth discovery.
use super::{EndpointUse, ManagedOAuth, OperationBudget, ResourceMetadata, TrustedMetadata};
use crate::{
    auth::{AuthBinding, AuthErrorCode, AuthTarget, OAuthFlow, challenge::Challenge},
    client::HookError,
};
use serde::{Deserialize, Serialize};
use url::Url;

fn failed() -> HookError {
    HookError::authentication(AuthErrorCode::DiscoveryFailed)
}

fn https(value: &str, issuer: bool) -> Result<Url, HookError> {
    let url = Url::parse(value).map_err(|_| failed())?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || issuer && url.query().is_some()
    {
        return Err(failed());
    }
    Ok(url)
}

fn resource_identifier(value: &str) -> Result<Url, HookError> {
    https(value, false)
}

pub(super) fn validate_resource(
    identifier: &str,
    destination: &Url,
    configured: Option<&str>,
) -> Result<(), HookError> {
    let resource = resource_identifier(identifier)?;
    if configured.is_some_and(|expected| expected != identifier) {
        return Err(failed());
    }
    let destination = https(destination.as_str(), false)?;
    let path = resource.path();
    let covered = destination.path() == path
        || destination
            .path()
            .strip_prefix(path)
            .is_some_and(|suffix| path.ends_with('/') || suffix.starts_with('/'));
    if resource.origin() != destination.origin()
        || !covered
        || resource
            .query()
            .is_some_and(|query| Some(query) != destination.query())
    {
        return Err(failed());
    }
    Ok(())
}

fn at_path(base: &Url, path: &str) -> Url {
    let mut url = base.clone();
    url.set_path(path);
    url.set_query(None);
    url.set_fragment(None);
    url
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) enum ResourceMetadataSource {
    Challenge,
    WellKnown,
}
/// Persist the retrieval provenance, not just an untrusted metadata location.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct ResourceMetadataHint {
    pub(super) url: String,
    pub(super) expected_resource: String,
    pub(super) source: ResourceMetadataSource,
}

fn resource_locations(resource: &Url) -> Vec<ResourceMetadataHint> {
    let mut candidates = Vec::new();
    if resource.path() != "/" || resource.query().is_some() {
        let suffix = if resource.path() == "/" {
            ""
        } else {
            resource.path()
        };
        let mut url = at_path(
            resource,
            &format!("/.well-known/oauth-protected-resource{suffix}"),
        );
        // RFC 9728 section 3.1 inserts the suffix before the path AND query.
        url.set_query(resource.query());
        candidates.push(ResourceMetadataHint {
            url: url.to_string(),
            expected_resource: resource.as_str().to_owned(),
            source: ResourceMetadataSource::WellKnown,
        });
    }
    candidates.push(ResourceMetadataHint {
        url: at_path(resource, "/.well-known/oauth-protected-resource").to_string(),
        expected_resource: resource.origin().ascii_serialization(),
        source: ResourceMetadataSource::WellKnown,
    });
    candidates
}

fn issuer_locations(issuer: &Url) -> Vec<Url> {
    let path = issuer.path();
    if path == "/" || path.is_empty() {
        vec![
            at_path(issuer, "/.well-known/oauth-authorization-server"),
            at_path(issuer, "/.well-known/openid-configuration"),
        ]
    } else {
        // No origin-root fallback for path-bearing issuers: MCP specifies three locations.
        vec![
            at_path(
                issuer,
                &format!("/.well-known/oauth-authorization-server{path}"),
            ),
            at_path(issuer, &format!("/.well-known/openid-configuration{path}")),
            at_path(
                issuer,
                &format!(
                    "{}/.well-known/openid-configuration",
                    path.trim_end_matches('/')
                ),
            ),
        ]
    }
}

async fn fetch<T: serde::de::DeserializeOwned>(
    owner: &ManagedOAuth,
    urls: &[Url],
    endpoint: EndpointUse,
    budget: OperationBudget,
) -> Result<(T, String), HookError> {
    for url in urls {
        let request = oauth2::http::Request::builder()
            .method("GET")
            .uri(url.as_str())
            .header("Accept", "application/json")
            .header("MCP-Protocol-Version", "2025-11-25")
            .body(Vec::new())
            .map_err(|_| failed())?;
        let response = owner.checked_send(request, endpoint, budget).await?;
        if matches!(response.status().as_u16(), 404 | 405) {
            continue;
        }
        if !response.status().is_success() || response.body().len() > 1024 * 1024 {
            return Err(failed().transient_if(response.status().is_server_error()));
        }
        let metadata = serde_json::from_slice(response.body()).map_err(|_| failed())?;
        return Ok((metadata, url.as_str().to_owned()));
    }
    Err(failed())
}

/// A current challenge (even without `resource_metadata`) overrides a saved hint.
fn resource_candidates(
    resource: &Url,
    challenge: Option<&Challenge>,
    saved_hint: Option<&ResourceMetadataHint>,
) -> Result<Vec<ResourceMetadataHint>, HookError> {
    if let Some(explicit) = challenge.and_then(|c| c.resource_metadata.as_ref()) {
        return Ok(vec![ResourceMetadataHint {
            url: https(explicit, false)?.to_string(),
            expected_resource: resource.as_str().to_owned(),
            source: ResourceMetadataSource::Challenge,
        }]);
    }
    let locations = resource_locations(resource);
    if challenge.is_none()
        && let Some(hint) = saved_hint
    {
        https(&hint.url, false)?;
        let valid_source = match hint.source {
            ResourceMetadataSource::Challenge => hint.expected_resource == resource.as_str(),
            ResourceMetadataSource::WellKnown => locations.contains(hint),
        };
        if !valid_source {
            return Err(failed());
        }
        // Network and trust checks still run; the saved hint carries no authority.
        return Ok(vec![hint.clone()]);
    }
    Ok(locations)
}

pub(super) fn validate_saved_source(
    destination: &Url,
    identifier: &str,
    hint: Option<&ResourceMetadataHint>,
) -> Result<(), HookError> {
    let hint = hint.ok_or_else(failed)?;
    resource_candidates(destination, None, Some(hint))?;
    validate_resource_source(identifier, hint)?;
    validate_resource(identifier, destination, None)
}

/// Exact identity, except that an origin root may be spelled with or without
/// its RFC 3986-equivalent trailing slash (`https://host` and `https://host/`).
fn validate_resource_source(
    identifier: &str,
    hint: &ResourceMetadataHint,
) -> Result<(), HookError> {
    let root = |value: &str| {
        Url::parse(value)
            .ok()
            .filter(|url| url.path() == "/" && url.query().is_none())
            .map(|url| url.origin().ascii_serialization())
    };
    if identifier != hint.expected_resource
        && (root(identifier).is_none() || root(identifier) != root(&hint.expected_resource))
    {
        return Err(failed());
    }
    Ok(())
}

fn reject_reserved_query(url: &Url) -> Result<(), HookError> {
    if url.query_pairs().any(|(key, _)| {
        matches!(
            key.as_ref(),
            "client_id"
                | "client_secret"
                | "redirect_uri"
                | "response_type"
                | "scope"
                | "state"
                | "code_challenge"
                | "code_challenge_method"
                | "resource"
                | "grant_type"
                | "code"
                | "refresh_token"
                | "code_verifier"
                | "access_token"
        )
    }) {
        return Err(failed());
    }
    Ok(())
}

#[derive(Deserialize)]
struct IssuerMetadata {
    issuer: String,
    authorization_endpoint: Option<String>,
    token_endpoint: String,
    #[serde(default)]
    grant_types_supported: Vec<String>,
    #[serde(default = "default_auth_methods")]
    token_endpoint_auth_methods_supported: Vec<String>,
    #[serde(default)]
    code_challenge_methods_supported: Vec<String>,
    #[serde(default)]
    authorization_response_iss_parameter_supported: bool,
}
fn default_auth_methods() -> Vec<String> {
    vec!["client_secret_basic".to_owned()]
}

/// Returns trusted metadata, its retrieval provenance and the scopes to request.
pub(super) async fn discover(
    owner: &ManagedOAuth,
    target: &AuthTarget,
    challenge: Option<&Challenge>,
    saved_hint: Option<&ResourceMetadataHint>,
    cached_issuer: Option<&str>,
    required: &[String],
    budget: OperationBudget,
) -> Result<(TrustedMetadata, Option<ResourceMetadataHint>, Vec<String>), HookError> {
    let resource_url = https(target.destination().as_str(), false)?;
    let (metadata, hint) = match target.binding() {
        AuthBinding::OAuth { resource, .. } => {
            validate_resource(resource, &resource_url, Some(resource))?;
            let issuer = target.issuer().ok_or_else(failed)?;
            https(issuer, true)?;
            // Presets identify the principal; PRM is only needed to learn an unbound one.
            (
                ResourceMetadata::new(resource.clone(), vec![issuer.to_owned()]),
                None,
            )
        }
        AuthBinding::Unbound => {
            let candidates = resource_candidates(&resource_url, challenge, saved_hint)?;
            let urls = candidates
                .iter()
                .map(|candidate| https(&candidate.url, false))
                .collect::<Result<Vec<_>, _>>()?;
            let (metadata, fetched_url): (ResourceMetadata, _) =
                fetch(owner, &urls, EndpointUse::ResourceMetadata, budget).await?;
            let hint = candidates
                .into_iter()
                .find(|candidate| candidate.url == fetched_url)
                .ok_or_else(failed)?;
            // Exact retrieval-source identity precedes all use of untrusted metadata.
            validate_resource_source(&metadata.resource, &hint)?;
            validate_resource(&metadata.resource, &resource_url, None)?;
            (metadata, Some(hint))
        }
        _ => return Err(failed()),
    };
    if metadata.authorization_servers.is_empty() {
        return Err(failed());
    }
    for issuer in &metadata.authorization_servers {
        https(issuer, true)?;
    }
    let decision = owner.select(target, &metadata, required)?;
    let (issuer, scopes) = (decision.issuer, decision.scopes);
    // Validated metadata naming another issuer is a move, never a transient outage.
    let moved = cached_issuer.is_some_and(|cached| cached != issuer);
    let metadata = issuer_metadata(owner, target, metadata.resource, issuer, budget)
        .await
        .map_err(|error| {
            if moved {
                error.transient_if(false)
            } else {
                error
            }
        })?;
    Ok((metadata, hint, scopes))
}

/// Fetch, validate and approve the authorization-server metadata of a trusted issuer.
pub(super) async fn issuer_metadata(
    owner: &ManagedOAuth,
    target: &AuthTarget,
    resource: String,
    issuer: String,
    budget: OperationBudget,
) -> Result<TrustedMetadata, HookError> {
    let issuer_url = https(&issuer, true)?;
    let (as_metadata, _): (IssuerMetadata, _) = fetch(
        owner,
        &issuer_locations(&issuer_url),
        EndpointUse::IssuerMetadata,
        budget,
    )
    .await?;
    if as_metadata.issuer != issuer {
        return Err(failed());
    }
    let token = https(&as_metadata.token_endpoint, false)?;
    reject_reserved_query(&token)?;
    owner.check_url(&token, EndpointUse::Token, budget).await?;
    if let Some(endpoint) = &as_metadata.authorization_endpoint {
        reject_reserved_query(&https(endpoint, false)?)?;
        owner
            .check_url(&https(endpoint, false)?, EndpointUse::Authorization, budget)
            .await?;
    }
    #[allow(unreachable_patterns)] // Also compiled by the external validation harness.
    match owner.config.flow {
        OAuthFlow::ClientCredentials => {
            if !as_metadata
                .grant_types_supported
                .iter()
                .any(|g| g == "client_credentials")
            {
                return Err(failed());
            }
        }
        OAuthFlow::AuthorizationCodePkce => {
            if as_metadata.authorization_endpoint.is_none()
                || !as_metadata
                    .code_challenge_methods_supported
                    .iter()
                    .any(|m| m == "S256")
                || (!as_metadata.grant_types_supported.is_empty()
                    && !as_metadata
                        .grant_types_supported
                        .iter()
                        .any(|g| g == "authorization_code"))
            {
                return Err(failed());
            }
        }
        _ => return Err(failed()),
    }
    let metadata = TrustedMetadata {
        resource,
        issuer,
        authorization_endpoint: as_metadata.authorization_endpoint,
        token_endpoint: as_metadata.token_endpoint,
        grant_types_supported: as_metadata.grant_types_supported,
        token_endpoint_auth_methods_supported: as_metadata.token_endpoint_auth_methods_supported,
        code_challenge_methods_supported: as_metadata.code_challenge_methods_supported,
        authorization_response_iss_parameter_supported: as_metadata
            .authorization_response_iss_parameter_supported,
    };
    owner.approve_metadata(target, &metadata)?;
    Ok(metadata)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_resource_identity_preserves_trailing_slash_and_query() {
        for resource in [
            "https://api.example/api/",
            "https://api.example/api/?audience=hooks",
        ] {
            let destination = Url::parse(resource).unwrap();
            assert!(validate_resource(resource, &destination, Some(resource)).is_ok());
            assert!(
                validate_resource(resource, &destination, Some("https://api.example/api")).is_err()
            );
        }
        let destination = Url::parse("https://api.example/api/?audience=other").unwrap();
        assert!(
            validate_resource(
                "https://api.example/api/?audience=hooks",
                &destination,
                Some("https://api.example/api/?audience=hooks"),
            )
            .is_err()
        );
    }

    #[test]
    fn resource_identifiers_cover_only_same_origin_path_segments() {
        for (resource, destination) in [
            ("https://api.example/api", "https://api.example/api"),
            (
                "https://api.example/api",
                "https://api.example/api/hooks?delivery=1",
            ),
            ("https://api.example/api/", "https://api.example/api/hooks"),
            ("https://api.example/", "https://api.example/api/hooks"),
            (
                "https://api.example:443/api",
                "https://api.example/api/hooks",
            ),
        ] {
            assert!(
                validate_resource(resource, &Url::parse(destination).unwrap(), None).is_ok(),
                "{resource} must cover {destination}"
            );
        }
        for (resource, destination) in [
            ("https://api.example/api", "https://api.example/apievil"),
            ("https://api.example/api/", "https://api.example/api"),
            ("https://api.example/api", "https://api.example/api%2Fhooks"),
            ("https://api.example/api", "https://api.example/API/hooks"),
            (
                "https://api.example/api",
                "https://api.example/api/../other",
            ),
            ("https://api.example/api", "https://evil.example/api/hooks"),
            (
                "https://api.example/api",
                "https://api.example.evil/api/hooks",
            ),
            (
                "https://api.example/api",
                "https://api.example:444/api/hooks",
            ),
            ("https://api.example/api", "http://api.example/api/hooks"),
            (
                "https://api.example/api?x=1",
                "https://api.example/api/hooks",
            ),
            ("https://api.example/api?", "https://api.example/api/hooks"),
            (
                "https://user@api.example/api",
                "https://api.example/api/hooks",
            ),
            (
                "https://api.example/api#frag",
                "https://api.example/api/hooks",
            ),
            (
                "https://api.example/api",
                "https://user@api.example/api/hooks",
            ),
            (
                "https://api.example/api",
                "https://api.example/api/hooks#frag",
            ),
        ] {
            assert!(
                validate_resource(resource, &Url::parse(destination).unwrap(), None).is_err(),
                "{resource} must not cover {destination}"
            );
        }
    }

    #[test]
    fn configured_resource_requires_exact_identifier_and_destination_coverage() {
        let destination = Url::parse("https://api.example/api/hooks").unwrap();
        assert!(
            validate_resource(
                "https://api.example/api",
                &destination,
                Some("https://api.example/api")
            )
            .is_ok()
        );
        for discovered in [
            "https://api.example/",
            "https://api.example/api/",
            "https://api.example:443/api",
        ] {
            assert!(
                validate_resource(discovered, &destination, Some("https://api.example/api"))
                    .is_err()
            );
        }
        assert!(
            validate_resource(
                "https://api.example/other",
                &destination,
                Some("https://api.example/other")
            )
            .is_err()
        );
    }

    fn strings(urls: Vec<Url>) -> Vec<String> {
        urls.into_iter().map(|url| url.to_string()).collect()
    }

    #[test]
    fn exact_mcp_issuer_order_without_invented_root_fallback() {
        assert_eq!(
            strings(issuer_locations(
                &https("https://as.example/tenant", true).unwrap()
            )),
            [
                "https://as.example/.well-known/oauth-authorization-server/tenant",
                "https://as.example/.well-known/openid-configuration/tenant",
                "https://as.example/tenant/.well-known/openid-configuration",
            ]
        );
        assert_eq!(
            strings(issuer_locations(
                &https("https://as.example", true).unwrap()
            )),
            [
                "https://as.example/.well-known/oauth-authorization-server",
                "https://as.example/.well-known/openid-configuration",
            ]
        );
    }

    #[test]
    fn resource_locations_bind_exact_path_query_and_root_identities() {
        let resource = https("https://mcp.example/public/mcp?x=1", false).unwrap();
        let locations = resource_locations(&resource);
        assert_eq!(locations.len(), 2);
        assert_eq!(
            locations[0].url,
            "https://mcp.example/.well-known/oauth-protected-resource/public/mcp?x=1"
        );
        assert_eq!(locations[0].expected_resource, resource.as_str());
        assert_eq!(
            locations[1].url,
            "https://mcp.example/.well-known/oauth-protected-resource"
        );
        assert_eq!(locations[1].expected_resource, "https://mcp.example");
        let root = resource_locations(&https("https://mcp.example/", false).unwrap());
        assert_eq!(root.len(), 1);
        assert_eq!(root[0].expected_resource, "https://mcp.example");
        let trailing = resource_locations(&https("https://mcp.example/api/", false).unwrap());
        assert_eq!(
            trailing[0].url,
            "https://mcp.example/.well-known/oauth-protected-resource/api/"
        );
        assert_eq!(trailing[0].expected_resource, "https://mcp.example/api/");
    }

    #[test]
    fn saved_hint_retains_source_identity_and_never_overrides_current_challenge() {
        let resource = https("https://mcp.example/rpc?x=1", false).unwrap();
        let saved = ResourceMetadataHint {
            url: "https://metadata.example/nonstandard".into(),
            expected_resource: resource.as_str().into(),
            source: ResourceMetadataSource::Challenge,
        };
        let bare = Challenge::default();
        assert!(resource_candidates(&resource, None, Some(&saved)).unwrap() == vec![saved.clone()]);
        assert!(
            resource_candidates(&resource, Some(&bare), Some(&saved)).unwrap()
                == resource_locations(&resource)
        );
        let challenge = Challenge {
            resource_metadata: Some("https://current.example/meta".into()),
            ..Default::default()
        };
        let current = resource_candidates(&resource, Some(&challenge), Some(&saved)).unwrap();
        assert_eq!(current[0].url, "https://current.example/meta");
        assert_eq!(current[0].expected_resource, resource.as_str());
        assert!(matches!(
            current[0].source,
            ResourceMetadataSource::Challenge
        ));
        let mut invalid = saved.clone();
        invalid.expected_resource = "https://mcp.example".into();
        assert!(resource_candidates(&resource, None, Some(&invalid)).is_err());
        invalid = saved.clone();
        invalid.source = ResourceMetadataSource::WellKnown;
        assert!(resource_candidates(&resource, None, Some(&invalid)).is_err());
        invalid = saved.clone();
        invalid.url = "http://insecure.example".into();
        assert!(resource_candidates(&resource, None, Some(&invalid)).is_err());
        for valid in resource_locations(&resource) {
            assert!(
                resource_candidates(&resource, None, Some(&valid)).unwrap() == vec![valid.clone()]
            );
            let mut invalid = valid;
            invalid.expected_resource.push('/');
            assert!(resource_candidates(&resource, None, Some(&invalid)).is_err());
        }
    }

    #[test]
    fn covering_parent_cannot_impersonate_an_exact_metadata_source() {
        let resource = https("https://mcp.example/api/hooks?x=1", false).unwrap();
        assert!(validate_saved_source(&resource, resource.as_str(), None).is_err());
        let challenge = Challenge {
            resource_metadata: Some("https://metadata.example/meta".into()),
            ..Default::default()
        };
        let mut sources = resource_candidates(&resource, Some(&challenge), None).unwrap();
        sources.extend(resource_locations(&resource));
        for hint in sources {
            assert!(validate_resource(&hint.expected_resource, &resource, None).is_ok());
            assert!(validate_resource_source(&hint.expected_resource, &hint).is_ok());
            assert!(validate_saved_source(&resource, &hint.expected_resource, Some(&hint)).is_ok());
            let root = hint.expected_resource == "https://mcp.example";
            for covering in ["https://mcp.example/", "https://mcp.example/api"]
                .into_iter()
                .filter(|covering| !(root && *covering == "https://mcp.example/"))
            {
                assert!(validate_resource(covering, &resource, None).is_ok());
                assert!(validate_resource_source(covering, &hint).is_err());
                assert!(validate_saved_source(&resource, covering, Some(&hint)).is_err());
            }
            // Even a URI-equivalent trailing slash/default port is not an exact identity.
            assert!(
                validate_resource_source("https://mcp.example:443/api/hooks?x=1", &hint).is_err()
            );
        }
    }

    #[test]
    fn origin_root_accepts_both_trailing_slash_spellings() {
        for destination in ["https://mcp.example/", "https://mcp.example/api"] {
            let destination = https(destination, false).unwrap();
            let root = resource_locations(&destination).pop().unwrap();
            let challenge = Challenge {
                resource_metadata: Some("https://mcp.example/meta".into()),
                ..Default::default()
            };
            let explicit = resource_candidates(&destination, Some(&challenge), None).unwrap();
            for identifier in ["https://mcp.example", "https://mcp.example/"] {
                assert!(validate_resource_source(identifier, &root).is_ok());
                assert!(validate_saved_source(&destination, identifier, Some(&root)).is_ok());
                if destination.path() == "/" {
                    assert!(validate_resource_source(identifier, &explicit[0]).is_ok());
                }
            }
            assert!(validate_resource_source("https://mcp.example/?x", &root).is_err());
            assert!(validate_resource_source("https://mcp.example:444/", &root).is_err());
        }
    }

    #[test]
    fn issuer_response_support_defaults_false_and_preserves_advertisement() {
        let mut value = serde_json::json!({
            "issuer": "https://as.example",
            "token_endpoint": "https://as.example/token"
        });
        let metadata: IssuerMetadata = serde_json::from_value(value.clone()).unwrap();
        assert!(!metadata.authorization_response_iss_parameter_supported);
        value["authorization_response_iss_parameter_supported"] = true.into();
        let metadata: IssuerMetadata = serde_json::from_value(value.clone()).unwrap();
        assert!(metadata.authorization_response_iss_parameter_supported);
        value["authorization_response_iss_parameter_supported"] = "true".into();
        assert!(serde_json::from_value::<IssuerMetadata>(value).is_err());
    }

    #[test]
    fn reject_invalid_issuer_and_endpoint_forms() {
        for value in [
            "http://as.example",
            "https://user@as.example",
            "https://as.example/#frag",
            "https://as.example/?query",
        ] {
            assert!(https(value, true).is_err(), "{value}");
        }
        assert!(https("https://as.example/token?audience=x", false).is_ok());
    }
}
