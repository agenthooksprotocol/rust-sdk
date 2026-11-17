//! Host-owned security dependencies; this example performs no implicit I/O.
use agenthooksprotocol::{
    adapters::registered::AuthContext,
    auth::{
        OAuthFlow,
        managed::{
            CredentialStore, ManagedOAuth, OAuthClientConfig, OAuthNetwork, OAuthPolicy,
            OperationBudget, Preparation,
        },
    },
    client::HookError,
};
use std::{sync::Arc, time::Instant};

pub async fn prepare_login(
    context: AuthContext,
    deadline: Instant,
    network: Arc<dyn OAuthNetwork>,
    policy: Arc<dyn OAuthPolicy>,
    store: Arc<dyn CredentialStore>,
) -> Result<(ManagedOAuth, Preparation), HookError> {
    let config = OAuthClientConfig::new(
        "account-a",
        "registered-client",
        OAuthFlow::AuthorizationCodePkce,
    )
    .redirect_uri("https://app.example/oauth/callback")
    .scopes(vec!["hooks".into()], vec!["hooks".into()]);
    let oauth = ManagedOAuth::new(config, network, policy, store)?;
    let prepared = oauth
        .prepare(context, OperationBudget::until(deadline))
        .await?;
    Ok((oauth, prepared))
}

fn main() {}
