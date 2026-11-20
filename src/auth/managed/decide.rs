//! The scope decision (contract section 2) and error classification (section
//! 4). Every entry point calls `configuration` and `operation` before any
//! network request and `grant` once the stored grant is known; token exchanges
//! end in `covered`. No other code decides scopes, attaches scopes to an
//! error or chooses a scope-related error code.
use super::{Mode, OAuthClientConfig, SavedToken, now, subset, union, valid_scope, within};
use crate::{
    adapters::registered::BearerCredential,
    auth::{AuthErrorCode, OAuthFlow, challenge::Challenge},
    client::HookError,
};

/// A rejected request's challenge: its status and `WWW-Authenticate` value.
#[derive(Clone, Copy)]
pub(super) struct Rejection<'a> {
    pub(super) status: u16,
    pub(super) header: &'a str,
}

/// An operation that passed steps 1 to 4.
pub(super) struct Operation {
    /// R = H ∪ E ∪ Ch, deduplicated and sorted.
    pub(super) required: Vec<String>,
    /// P′ = a 401's `scope` ∩ C: requested by this operation's
    /// client-credentials acquisition only, never stored or required.
    pub(super) hint: Vec<String>,
    /// A 403 `insufficient_scope` (step 5 applies).
    pub(super) step_up: bool,
    /// A 401: the rejected generation is retired (step 3).
    pub(super) unauthorized: bool,
    /// The parsed challenge, for discovery (`resource_metadata`).
    pub(super) challenge: Option<Challenge>,
}

/// What to do with the stored grant (steps 5 to 9).
pub(super) enum Step {
    Use(BearerCredential),
    Refresh,
    /// A client-credentials acquisition requesting these scopes.
    Acquire(Vec<String>),
    /// A PKCE login requesting these scopes (`prepare` only).
    Login(Vec<String>),
    Fail(HookError),
}

fn denied() -> HookError {
    HookError::authentication(AuthErrorCode::AccessDenied)
}
fn invalid() -> HookError {
    HookError::authentication(AuthErrorCode::InvalidConfiguration)
}

/// Step 1. S ⊄ C, a present preset `scopes` ≠ S, or an invalid scope token in
/// S, C, H, E or the preset fail `invalid_configuration`, with no scopes.
pub(super) fn configuration(
    config: &OAuthClientConfig,
    preset: Option<&[String]>,
    explicit: &[String],
) -> Result<(), HookError> {
    let tokens = [
        &config.requested_scopes[..],
        &config.allowed_scopes,
        &config.required_scopes,
        explicit,
        preset.unwrap_or_default(),
    ];
    if !tokens
        .iter()
        .all(|set| set.iter().all(|scope| valid_scope(scope)))
        || !subset(&config.requested_scopes, &config.allowed_scopes)
        || preset.is_some_and(|preset| union(preset, &[]) != union(&config.requested_scopes, &[]))
    {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
thread_local! {
    /// Calls of `operation` on this thread, for the entry-point routing test.
    pub(super) static DECISIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Steps 2 to 4 (step 0's retirement runs first, in `challenge`): the
/// challenge's form, the 401 hint, R and the ceiling. Pure: no I/O.
pub(super) fn operation(
    config: &OAuthClientConfig,
    explicit: &[String],
    rejection: Option<Rejection<'_>>,
) -> Result<Operation, HookError> {
    #[cfg(test)]
    DECISIONS.with(|count| count.set(count.get() + 1));
    let ceiling = &config.allowed_scopes;
    let host = union(&config.required_scopes, explicit);
    let mut operation = Operation {
        required: host.clone(),
        hint: Vec::new(),
        step_up: false,
        unauthorized: false,
        challenge: None,
    };
    if let Some(rejection) = rejection {
        // Unparseable or ambiguous, including a malformed `scope`.
        let mut parsed = crate::auth::challenge::parse(rejection.header).map_err(|_| denied())?;
        match rejection.status {
            401 => {
                operation.hint = union(&within(ceiling, &parsed.scopes), &[]);
                parsed.scopes.clear();
                parsed.insufficient_scope = false;
                operation.unauthorized = true;
            }
            403 if parsed.bearer && parsed.insufficient_scope => {
                if parsed.scopes.is_empty() && host.is_empty() {
                    return Err(denied());
                }
                operation.required = union(&host, &parsed.scopes);
                operation.step_up = true;
            }
            _ => return Err(denied()),
        }
        operation.challenge = Some(parsed);
    }
    // Step 4: decided locally, before any authorization-server request.
    if !subset(&operation.required, ceiling) {
        return Err(HookError::scoped(
            AuthErrorCode::AccessDenied,
            &operation.required,
        ));
    }
    Ok(operation)
}

/// Steps 5 to 9 against the stored grant's token. `sent` is the generation
/// whose token the rejected request carried; `can_refresh` whether this
/// client can refresh. Pure: no I/O.
pub(super) fn grant(
    config: &OAuthClientConfig,
    operation: &Operation,
    mode: Mode,
    token: Option<&SavedToken>,
    sent: Option<&str>,
    can_refresh: bool,
) -> Step {
    let ceiling = &config.allowed_scopes;
    let required = &operation.required;
    let covers = |token: &SavedToken| subset(required, &within(ceiling, &token.scopes));
    let usable = |token: &SavedToken| {
        !token.access_rejected
            && token
                .expires_at
                .is_none_or(|expiry| expiry > now().saturating_add(30))
            && covers(token)
    };
    let credential = |token: &SavedToken| {
        Step::Use(BearerCredential {
            token: token.access_token.clone(),
            attempt_id: token.generation.clone(),
        })
    };
    // Step 5: the server disagrees with our record.
    if operation.step_up
        && let Some(token) = token
        && covers(token)
    {
        if sent.is_none_or(|sent| sent == token.generation) {
            return Step::Fail(HookError::scoped(AuthErrorCode::AccessDenied, required));
        }
        if usable(token) {
            return credential(token);
        }
    }
    // Step 6.
    if let Some(token) = token.filter(|token| usable(token)) {
        return credential(token);
    }
    // Step 7: a refresh cannot broaden a grant.
    if can_refresh
        && config.flow == OAuthFlow::AuthorizationCodePkce
        && let Some(token) = token
        && token.refresh_token.is_some()
        && covers(token)
    {
        return Step::Refresh;
    }
    let previous = token.map_or(&[][..], |token| &token.scopes);
    let requested = |hint: &[String]| {
        let wanted = [&config.requested_scopes[..], required, hint].concat();
        union(previous, &within(ceiling, &wanted))
    };
    match (config.flow, mode) {
        // Step 8.
        (OAuthFlow::ClientCredentials, _) => Step::Acquire(requested(&operation.hint)),
        // Step 9.
        (_, Mode::Prepare) => Step::Login(requested(&[])),
        _ => Step::Fail(HookError::scoped(
            AuthErrorCode::InteractionRequired,
            required,
        )),
    }
}

/// Steps 7 and 8 (and completion step 7): a recorded grant that does not
/// cover R within the current ceiling fails `access_denied` carrying R.
pub(super) fn covered(
    granted: &[String],
    ceiling: &[String],
    required: &[String],
) -> Result<(), HookError> {
    if subset(required, &within(ceiling, granted)) {
        Ok(())
    } else {
        Err(HookError::scoped(AuthErrorCode::AccessDenied, required))
    }
}

/// Section 4: the only classification of errors crossing a managed OAuth
/// boundary. The code is kept (`provider_failed` when it has none), scopes
/// only when the SDK's own decision attached them, and never `login_ended`.
pub(crate) fn classify(error: HookError) -> HookError {
    let scoped = error.is_scoped();
    let code = error.auth_code().unwrap_or(AuthErrorCode::ProviderFailed);
    let mut classified = if scoped {
        HookError::scoped(code, error.required_scopes())
    } else {
        HookError::authentication(code)
    };
    classified = classified
        .classified(error.code())
        .request_not_sent_if(error.is_request_not_sent());
    classified
}
