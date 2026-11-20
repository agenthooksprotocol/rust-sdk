//! Strict RFC 9110/6750 `WWW-Authenticate` parsing shared by transports and providers.
//! Unknown schemes and padded token68 credentials are skipped; malformed or
//! ambiguous Bearer auth-params fail closed.

#[derive(Default, Debug, PartialEq, Eq)]
pub(crate) struct Challenge {
    /// Exactly one Bearer challenge was present.
    pub(crate) bearer: bool,
    pub(crate) resource_metadata: Option<String>,
    pub(crate) scopes: Vec<String>,
    pub(crate) insufficient_scope: bool,
}

/// The header failed to parse; callers map this to their own safe classification.
#[derive(Debug)]
pub(crate) struct Malformed;

fn token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// Split only outside quoted strings; a quoted-pair can escape a comma or quote.
fn parts(header: &str) -> Result<Vec<&str>, Malformed> {
    let mut parts = Vec::new();
    let (mut start, mut quoted, mut escaped) = (0, false, false);
    for (index, byte) in header.bytes().enumerate() {
        if byte < 0x20 && byte != b'\t' || byte == 0x7f {
            return Err(Malformed);
        }
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
    }
    if quoted || escaped {
        return Err(Malformed);
    }
    parts.push(header[start..].trim());
    Ok(parts)
}

fn parameter(value: &str) -> Result<String, Malformed> {
    let value = value.trim();
    if let Some(quoted) = value.strip_prefix('"') {
        let inner = quoted.strip_suffix('"').ok_or(Malformed)?;
        let mut result = String::new();
        let mut escaped = false;
        for ch in inner.chars() {
            if escaped {
                result.push(ch);
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                return Err(Malformed);
            } else {
                result.push(ch);
            }
        }
        if escaped {
            return Err(Malformed);
        }
        Ok(result)
    } else if !value.is_empty() && value.bytes().all(token) {
        Ok(value.to_owned())
    } else {
        Err(Malformed)
    }
}

/// Strict: a malformed `scope` value is malformed too.
pub(crate) fn parse(header: &str) -> Result<Challenge, Malformed> {
    parse_with(header, true)
}

fn parse_with(header: &str, strict_scope: bool) -> Result<Challenge, Malformed> {
    let mut result = Challenge::default();
    if header.is_empty() {
        return Ok(result);
    }
    let (mut bearer, mut scheme_seen) = (false, false);
    let mut seen = Vec::new();
    for part in parts(header)? {
        let end = part.bytes().take_while(|b| token(*b)).count();
        if end == 0 {
            return Err(Malformed);
        }
        let rest = part[end..].trim_start();
        let param = if rest.starts_with('=') {
            if !scheme_seen {
                return Err(Malformed);
            }
            part
        } else {
            // A new scheme must be separated from its credentials. Unknown
            // credentials can be token68 (including trailing '=' padding), not
            // necessarily auth-params; do not parse them as Bearer parameters.
            if end < part.len() && !part.as_bytes()[end].is_ascii_whitespace() {
                return Err(Malformed);
            }
            scheme_seen = true;
            bearer = part[..end].eq_ignore_ascii_case("bearer");
            // Two Bearer challenges are ambiguous. Bearer takes auth-params
            // only (RFC 6750), so a token68 after it is a bad auth-param.
            if bearer {
                if result.bearer {
                    return Err(Malformed);
                }
                result.bearer = true;
            }
            rest
        };
        if !bearer || param.is_empty() {
            continue;
        }
        let (name, value) = param.split_once('=').ok_or(Malformed)?;
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() || !name.bytes().all(token) || seen.contains(&name) {
            return Err(Malformed);
        }
        let value = parameter(value)?;
        match name.as_str() {
            "resource_metadata" if value.is_empty() => return Err(Malformed),
            "resource_metadata" => result.resource_metadata = Some(value),
            "error" => result.insufficient_scope = value == "insufficient_scope",
            // Strict: RFC 6749 scope tokens separated by exactly one space.
            "scope" if strict_scope => {
                if !value.split(' ').all(super::valid_scope) {
                    return Err(Malformed);
                }
                result.scopes = value.split(' ').map(str::to_owned).collect();
            }
            _ => {}
        }
        seen.push(name);
    }
    Ok(result)
}

/// A 403 goes to the provider when its header is exactly one Bearer challenge
/// with `error="insufficient_scope"`; the provider validates its `scope`.
#[cfg(any(feature = "reqwest", test))]
pub(crate) fn insufficient_scope(header: &str) -> bool {
    parse_with(header, false)
        .is_ok_and(|challenge| challenge.bearer && challenge.insufficient_scope)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(header: &str) -> Challenge {
        parse(header).unwrap()
    }

    #[test]
    fn bearer_case_quotes_escapes_and_other_challenges() {
        let challenge = parsed(
            r#"Basic realm="ignored, realm", bEaReR ReSoUrCe_MeTaDaTa="https://resource.example/meta?x=a,b", scope="read write", error_description="say \"hello\"", Digest realm="other""#,
        );
        assert_eq!(
            challenge.resource_metadata.as_deref(),
            Some("https://resource.example/meta?x=a,b")
        );
        assert_eq!(challenge.scopes, ["read", "write"]);
        assert_eq!(parsed("Basic realm=example"), Challenge::default());
        assert_eq!(parsed(""), Challenge::default());
        assert!(
            parsed("NewScheme abc==, bEaReR realm=\"a,b\", error=\"insufficient_scope\"")
                .insufficient_scope
        );
        assert!(!parsed("Basic error=\"insufficient_scope\"").insufficient_scope);
    }

    #[test]
    fn unknown_schemes_with_padded_token68_do_not_hide_following_bearer() {
        for credentials in ["abc=", "abc==", "/+abc==", "a-b._~+/==="] {
            let challenge = parsed(&format!(
                "Negotiate {credentials}, Bearer scope=\"read\", resource_metadata=\"https://api.example/meta\", Other {credentials}"
            ));
            assert_eq!(challenge.scopes, ["read"]);
            assert_eq!(
                challenge.resource_metadata.as_deref(),
                Some("https://api.example/meta")
            );
        }
        assert_eq!(parsed("Unknown /+abc=="), Challenge::default());
    }

    #[test]
    fn insufficient_scope_requires_an_unambiguous_bearer_error() {
        assert!(parsed("Unknown abc==, Bearer error=insufficient_scope").insufficient_scope);
        for header in [
            "",
            "Bearer",
            "Bearer error=invalid_token",
            "Unknown error=insufficient_scope",
        ] {
            assert!(!parsed(header).insufficient_scope, "{header}");
        }
    }

    #[test]
    fn malformed_or_ambiguous_bearer_parameters_fail_closed() {
        for header in [
            "Bearer scope=read==",
            r#"Bearer realm="a", Bearer error="insufficient_scope""#,
            "Bearer, Bearer",
            "Bearer/scope=read",
            "scope=read, Bearer",
            "Bearer error=invalid_token, ERROR=insufficient_scope",
            "Bearer error=insufficient_scope, error=invalid_token",
            "Bearer extension=one, extension=two",
            "Bearer scope=read, Unknown abc==, Bearer scope=write",
            r#"Bearer scope="read", Scope="read""#,
            r#"Bearer resource_metadata="https://a", Bearer resource_metadata="https://a""#,
            r#"Bearer scope="unterminated"#,
            r#"Bearer resource_metadata="""#,
            r#"Bearer scope="bad\\scope""#,
            "Bearer scope=read\n",
            r#"Bearer scope="""#,
            r#"Bearer scope=" ""#,
            r#"Bearer scope="read  write""#,
            r#"Bearer scope=" read""#,
            r#"Bearer scope="read ""#,
            "Bearer scope=\"read\twrite\"",
        ] {
            assert!(parse(header).is_err(), "{header}");
        }
    }

    #[test]
    fn bearer_token68_is_a_bad_auth_param() {
        for header in [
            "Bearer scope",
            "Bearer scope=",
            "Bearer abc==",
            "Bearer a-b._~+/===",
        ] {
            assert!(parse(header).is_err(), "{header}");
        }
        assert!(!parsed("Basic realm=x").bearer);
        assert!(parsed("Bearer").bearer);
    }

    #[test]
    fn escaped_parameter_values_are_unescaped() {
        assert_eq!(parameter(r#""a\\b\"c""#).unwrap(), "a\\b\"c");
        assert!(parameter(r#""a"garbage""#).is_err());
    }
}
