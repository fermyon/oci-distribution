//! Types for working with registry auth tokens

use crate::reference::Reference;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// A token granted during the OAuth2-like workflow for OCI registries.
#[derive(Deserialize, Clone)]
#[serde(untagged)]
#[serde(rename_all = "snake_case")]
pub enum RegistryToken {
    /// Token value
    Token {
        /// The string value of the token
        token: String,
    },
    /// AccessToken value
    AccessToken {
        /// The string value of the access_token
        access_token: String,
    },
}

impl fmt::Debug for RegistryToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted = String::from("<redacted>");
        match self {
            RegistryToken::Token { .. } => {
                f.debug_struct("Token").field("token", &redacted).finish()
            }
            RegistryToken::AccessToken { .. } => f
                .debug_struct("AccessToken")
                .field("access_token", &redacted)
                .finish(),
        }
    }
}

/// Type of registry auth token
#[derive(Debug, Clone)]
pub enum RegistryTokenType {
    /// Bearer token type
    Bearer(RegistryToken),
    /// Basic auth token type
    Basic(String, String),
}

impl RegistryToken {
    /// Returns the bearer token in a form suitable to use for an Authorization header
    pub fn bearer_token(&self) -> String {
        format!("Bearer {}", self.token())
    }
    /// Returns the token value
    pub fn token(&self) -> &str {
        match self {
            RegistryToken::Token { token } => token,
            RegistryToken::AccessToken { access_token } => access_token,
        }
    }
}

/// Desired operation for registry authentication
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum RegistryOperation {
    /// Authenticate for push operations
    Push,
    /// Authenticate for pull operations
    Pull,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TokenCacheKey {
    registry: String,
    repository: String,
    operation: RegistryOperation,
}

struct TokenCacheValue {
    token: RegistryTokenType,
    expiration: u64,
}

/// A cache to hold authentication tokens
#[derive(Default, Clone)]
pub struct TokenCache {
    // (registry, repository, scope) -> (token, expiration)
    tokens: Arc<RwLock<BTreeMap<TokenCacheKey, TokenCacheValue>>>,
}

impl TokenCache {
    /// Insert a token corresponding to reference and operation keys
    pub async fn insert(
        &self,
        reference: &Reference,
        op: RegistryOperation,
        token: RegistryTokenType,
    ) {
        let expiration = match token {
            RegistryTokenType::Basic(_, _) => u64::MAX,
            RegistryTokenType::Bearer(ref t) => {
                let token_str = t.token();
                match jwt::Token::<
                        jwt::header::Header,
                        jwt::claims::Claims,
                        jwt::token::Unverified,
                    >::parse_unverified(token_str)
                    {
                        Ok(token) => token.claims().registered.expiration.unwrap_or(u64::MAX),
                        Err(jwt::Error::NoClaimsComponent) => {
                            // the token doesn't have a claim that states a
                            // value for the expiration. We assume it has a 60
                            // seconds validity as indicated here:
                            // https://docs.docker.com/registry/spec/auth/token/#requesting-a-token
                            // > (Optional) The duration in seconds since the token was issued
                            // > that it will remain valid. When omitted, this defaults to 60 seconds.
                            // > For compatibility with older clients, a token should never be returned
                            // > with less than 60 seconds to live.
                            let now = SystemTime::now();
                            let epoch = now
                                .duration_since(UNIX_EPOCH)
                                .expect("Time went backwards")
                                .as_secs();
                            let expiration = epoch + 60;
                            debug!(?token, "Cannot extract expiration from token's claims, assuming a 60 seconds validity");
                            expiration
                        },
                        Err(error) => {
                            warn!(?error, "Invalid bearer token");
                            return;
                        }
                    }
            }
        };
        let registry = reference.resolve_registry().to_string();
        let repository = reference.repository().to_string();
        debug!(%registry, %repository, ?op, %expiration, "Inserting token");
        self.tokens.write().await.insert(
            TokenCacheKey {
                registry,
                repository,
                operation: op,
            },
            TokenCacheValue { token, expiration },
        );
    }

    pub(crate) async fn get(
        &self,
        reference: &Reference,
        op: RegistryOperation,
    ) -> Option<RegistryTokenType> {
        let registry = reference.resolve_registry().to_string();
        let repository = reference.repository().to_string();
        let key = TokenCacheKey {
            registry,
            repository,
            operation: op,
        };
        match self.tokens.read().await.get(&key) {
            Some(TokenCacheValue {
                ref token,
                expiration,
            }) => {
                let now = SystemTime::now();
                let epoch = now
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_secs();
                if epoch > *expiration {
                    debug!(%key.registry, %key.repository, ?key.operation, %expiration, miss=false, expired=true, "Fetching token");
                    None
                } else {
                    debug!(%key.registry, %key.repository, ?key.operation, %expiration, miss=false, expired=false, "Fetching token");
                    Some(token.clone())
                }
            }
            None => {
                debug!(%key.registry, %key.repository, ?key.operation, miss = true, "Fetching token");
                None
            }
        }
    }
}
