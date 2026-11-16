//! Strict, policy-gated MCP 2025-11-25 OAuth discovery.
use super::{
    EndpointUse, ManagedOAuth, OperationBudget, ResourceMetadata, TrustDecision, TrustedMetadata,
};
use crate::{
    auth::{AuthBinding, AuthErrorCode, AuthTarget, OAuthFlow},
    client::HookError,
};
use serde::Deserialize;
use url::Url;

fn failed() -> HookError {
    HookError::authentication(AuthErrorCode::DiscoveryFailed)
}
fn denied() -> HookError {
    HookError::authentication(AuthErrorCode::AccessDenied)
}

#[derive(Default, Debug, PartialEq, Eq)]
struct Challenge {
    resource_metadata: Option<String>,
    scopes: Vec<String>,
}

fn token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// Split only outside quoted strings; a quoted-pair can escape a comma or quote.
fn challenge_parts(header: &str) -> Result<Vec<&str>, HookError> {
    let mut parts = Vec::new();
    let (mut start, mut quoted, mut escaped) = (0, false, false);
    for (index, byte) in header.bytes().enumerate() {
        if escaped {
            escaped = false;
        } else if quoted && byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            quoted = !quoted;
        } else if !quoted && byte == b',' {
            parts.push(header[start..index].trim());
            start = index + 1;
        }
        if byte < 0x20 && byte != b'\t' || byte == 0x7f {
            return Err(failed());
        }
    }
    if quoted || escaped {
        return Err(failed());
    }
    parts.push(header[start..].trim());
    Ok(parts)
}

fn parameter(value: &str) -> Result<String, HookError> {
    let value = value.trim();
    if value.starts_with('"') {
        if !value.ends_with('"') || value.len() < 2 {
            return Err(failed());
        }
        let mut result = String::new();
        let mut escaped = false;
        for ch in value[1..value.len() - 1].chars() {
            if escaped {
                result.push(ch);
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                return Err(failed());
            } else {
                result.push(ch);
            }
        }
        if escaped {
            return Err(failed());
        }
        Ok(result)
    } else if !value.is_empty() && value.bytes().all(token) {
        Ok(value.to_owned())
    } else {
        Err(failed())
    }
}

fn parse_challenge(header: Option<&str>) -> Result<Challenge, HookError> {
    let mut result = Challenge::default();
    let Some(header) = header else {
        return Ok(result);
    };
    let (mut bearer, mut scope_seen, mut metadata_seen) = (false, false, false);
    for part in challenge_parts(header)? {
        if part.is_empty() {
            return Err(failed());
        }
        let end = part.bytes().take_while(|b| token(*b)).count();
        if end == 0 {
            return Err(failed());
        }
        let rest = part[end..].trim_start();
        let param = if rest.starts_with('=') {
            part
        } else {
            bearer = part[..end].eq_ignore_ascii_case("bearer");
            rest
        };
        if !bearer || param.is_empty() {
            continue;
        }
        let (name, value) = param.split_once('=').ok_or_else(failed)?;
        let name = name.trim();
        if name.is_empty() || !name.bytes().all(token) {
            return Err(failed());
        }
        let value = parameter(value)?;
        if name.eq_ignore_ascii_case("resource_metadata") {
            if metadata_seen || value.is_empty() {
                return Err(failed());
            }
            metadata_seen = true;
            result.resource_metadata = Some(value);
        } else if name.eq_ignore_ascii_case("scope") {
            if scope_seen {
                return Err(failed());
            }
            scope_seen = true;
            if value.is_empty() || !value.bytes().all(|b| b == b' ' || scope_byte(b)) {
                return Err(failed());
            }
            result.scopes = value
                .split(' ')
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect();
        }
    }
    Ok(result)
}

pub(super) fn challenge_scopes(header: Option<&str>) -> Result<Vec<String>, HookError> {
    Ok(parse_challenge(header)?.scopes)
}

fn scope_byte(byte: u8) -> bool {
    byte == 0x21 || (0x23..=0x5b).contains(&byte) || (0x5d..=0x7e).contains(&byte)
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

// Resource identifiers cannot contain a query; request destinations may.
fn resource_identifier(value: &str) -> Result<Url, HookError> {
    let resource = https(value, false)?;
    if resource.query().is_some() {
        return Err(failed());
    }
    Ok(resource)
}

fn validate_resource(
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
    if resource.origin() != destination.origin() || !covered {
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

fn resource_locations(resource: &Url) -> Vec<Url> {
    let mut urls = Vec::new();
    if resource.path() != "/" && !resource.path().is_empty() {
        urls.push(at_path(
            resource,
            &format!("/.well-known/oauth-protected-resource{}", resource.path()),
        ));
    }
    urls.push(at_path(resource, "/.well-known/oauth-protected-resource"));
    urls
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
            return Err(failed());
        }
        let metadata = serde_json::from_slice(response.body()).map_err(|_| failed())?;
        return Ok((metadata, url.as_str().to_owned()));
    }
    Err(failed())
}

fn resource_candidates(
    resource: &Url,
    current_header: Option<&str>,
    challenge: &Challenge,
    saved_hint: Option<&str>,
) -> Result<Vec<Url>, HookError> {
    if let Some(explicit) = &challenge.resource_metadata {
        return Ok(vec![https(explicit, false)?]);
    }
    if current_header.is_none() {
        if let Some(hint) = saved_hint.and_then(|hint| https(hint, false).ok()) {
            // This is only a discovery location, not a trust grant: fetch rechecks policy.
            return Ok(vec![hint]);
        }
    }
    Ok(resource_locations(resource))
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

pub(super) async fn discover(
    owner: &ManagedOAuth,
    target: &AuthTarget,
    challenge: Option<&str>,
    saved_hint: Option<&str>,
    saved_scopes: &[String],
    budget: OperationBudget,
) -> Result<(TrustedMetadata, Option<String>), HookError> {
    let current_header = challenge;
    let mut challenge = parse_challenge(current_header)?;
    challenge.scopes.extend_from_slice(saved_scopes);
    challenge.scopes.sort();
    challenge.scopes.dedup();
    let configured_resource = match target.binding() {
        AuthBinding::OAuth { resource, .. } => Some(resource.as_str()),
        AuthBinding::Unbound => None,
        _ => return Err(failed()),
    };
    if let Some(resource) = configured_resource {
        resource_identifier(resource)?;
    }
    // Well-known discovery follows the actual endpoint path, not an audience alias.
    let resource_url = https(target.destination().as_str(), false)?;
    let urls = resource_candidates(&resource_url, current_header, &challenge, saved_hint)?;
    let (metadata, hint): (ResourceMetadata, _) =
        fetch(owner, &urls, EndpointUse::ResourceMetadata, budget).await?;
    if metadata.authorization_servers.is_empty() {
        return Err(failed());
    }
    validate_resource(
        &metadata.resource,
        target.destination(),
        configured_resource,
    )?;
    for issuer in &metadata.authorization_servers {
        https(issuer, true)?;
    }
    let TrustDecision { issuer, mut scopes } =
        owner.policy.select(target, &metadata, &challenge.scopes)?;
    scopes.sort();
    scopes.dedup();
    if !metadata.authorization_servers.contains(&issuer)
        || target.issuer().is_some_and(|required| required != issuer)
    {
        return Err(denied());
    }
    let required = owner
        .config
        .requested_scopes
        .iter()
        .chain(target.scopes())
        .chain(&challenge.scopes);
    if scopes.iter().any(|scope| {
        scope.is_empty()
            || !scope.bytes().all(scope_byte)
            || !owner.config.allowed_scopes.contains(scope)
    }) || required.into_iter().any(|scope| !scopes.contains(scope))
    {
        return Err(denied());
    }
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
        resource: metadata.resource,
        issuer,
        authorization_endpoint: as_metadata.authorization_endpoint,
        token_endpoint: as_metadata.token_endpoint,
        scopes,
        grant_types_supported: as_metadata.grant_types_supported,
        token_endpoint_auth_methods_supported: as_metadata.token_endpoint_auth_methods_supported,
        code_challenge_methods_supported: as_metadata.code_challenge_methods_supported,
        authorization_response_iss_parameter_supported: as_metadata
            .authorization_response_iss_parameter_supported,
    };
    owner.approve_metadata(target, &metadata)?;
    Ok((metadata, Some(hint)))
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn exposed_challenge_scopes_use_strict_parser() {
        assert_eq!(
            challenge_scopes(Some(r#"Bearer scope="read write""#)).unwrap(),
            ["read", "write"]
        );
        assert!(challenge_scopes(None).unwrap().is_empty());
        assert!(challenge_scopes(Some(r#"Bearer scope="read", scope="write""#)).is_err());
    }

    #[test]
    fn bearer_case_quotes_escapes_and_other_challenges() {
        let parsed = parse_challenge(Some(r#"Basic realm="ignored, realm", bEaReR ReSoUrCe_MeTaDaTa="https://resource.example/meta?x=a,b", scope="read write", error_description="say \"hello\"", Digest realm="other""#)).unwrap();
        assert_eq!(
            parsed.resource_metadata.as_deref(),
            Some("https://resource.example/meta?x=a,b")
        );
        assert_eq!(parsed.scopes, ["read", "write"]);
        assert_eq!(
            parse_challenge(Some("Basic realm=example")).unwrap(),
            Challenge::default()
        );
    }

    #[test]
    fn duplicate_recognized_parameters_are_ambiguous_even_across_bearer_challenges() {
        for header in [
            r#"Bearer scope="read", Scope="read""#,
            r#"Bearer resource_metadata="https://a", Bearer resource_metadata="https://a""#,
            r#"Bearer scope="read", Bearer scope="write""#,
            r#"Bearer scope="unterminated"#,
            r#"Bearer resource_metadata="""#,
            "Bearer scope=read\n",
        ] {
            assert!(parse_challenge(Some(header)).is_err(), "{header}");
        }
    }

    #[test]
    fn escaped_parameter_values_are_unescaped() {
        assert_eq!(parameter(r#""a\\b\"c""#).unwrap(), "a\\b\"c");
        assert!(parameter(r#""a"garbage""#).is_err());
        assert!(parse_challenge(Some(r#"Bearer scope="bad\\scope""#)).is_err());
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
    fn resource_locations_keep_path_and_drop_query() {
        assert_eq!(
            strings(resource_locations(
                &https("https://mcp.example/public/mcp?x=1", false).unwrap()
            )),
            [
                "https://mcp.example/.well-known/oauth-protected-resource/public/mcp",
                "https://mcp.example/.well-known/oauth-protected-resource",
            ]
        );
        assert_eq!(
            resource_locations(&https("https://mcp.example/", false).unwrap()).len(),
            1
        );
    }

    #[test]
    fn saved_hint_is_only_used_without_a_current_challenge() {
        let resource = https("https://mcp.example/rpc", false).unwrap();
        let saved = Some("https://metadata.example/nonstandard");
        let absent = Challenge::default();
        assert_eq!(
            strings(resource_candidates(&resource, None, &absent, saved).unwrap()),
            ["https://metadata.example/nonstandard"]
        );
        assert_eq!(
            resource_candidates(&resource, Some("Bearer"), &absent, saved).unwrap(),
            resource_locations(&resource)
        );
        let header = r#"Bearer resource_metadata="https://current.example/meta""#;
        let challenge = parse_challenge(Some(header)).unwrap();
        assert_eq!(
            strings(resource_candidates(&resource, Some(header), &challenge, saved).unwrap()),
            ["https://current.example/meta"]
        );
        assert_eq!(
            resource_candidates(&resource, None, &absent, Some("http://insecure.example")).unwrap(),
            resource_locations(&resource)
        );
        let invalid = parse_challenge(Some(
            r#"Bearer resource_metadata="http://insecure.example""#,
        ))
        .unwrap();
        assert!(resource_candidates(&resource, Some("Bearer"), &invalid, saved).is_err());
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
