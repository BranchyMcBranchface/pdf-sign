// Copyright 2023 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use chrono::{DateTime, Utc};
use openidconnect::core::CoreIdToken;
use serde::Deserialize;

use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD as base64};

use crate::errors::SigstoreError;

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    Single(String),
    Multiple(Vec<String>),
}

impl Audience {
    fn contains_sigstore(&self) -> bool {
        match self {
            Audience::Single(aud) => aud == "sigstore",
            Audience::Multiple(list) => list.iter().any(|aud| aud == "sigstore"),
        }
    }
}

/// Flexible deserialization helper for timestamp fields.
/// Accepts both Unix timestamp (seconds) and ISO 8601 strings.
mod flexible_timestamp {
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Timestamp {
            Seconds(i64),
            String(String),
        }

        match Timestamp::deserialize(deserializer)? {
            Timestamp::Seconds(secs) => {
                Ok(DateTime::<Utc>::from_timestamp(secs, 0).ok_or_else(|| {
                    serde::de::Error::custom("invalid timestamp")
                })?)
            }
            Timestamp::String(s) => {
                DateTime::parse_from_rfc3339(&s)
                    .map(|dt| dt.with_timezone(&Utc))
                    .map_err(serde::de::Error::custom)
            }
        }
    }

    pub mod option {
        use chrono::{DateTime, Utc};
        use serde::{Deserialize, Deserializer};

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
        where
            D: Deserializer<'de>,
        {
            Option::<i64>::deserialize(deserializer)?.map_or(Ok(None), |secs| {
                DateTime::<Utc>::from_timestamp(secs, 0)
                    .ok_or_else(|| serde::de::Error::custom("invalid timestamp"))
                    .map(Some)
            })
        }
    }
}

#[derive(Deserialize)]
pub struct Claims {
    pub aud: Audience,
    #[serde(deserialize_with = "flexible_timestamp::deserialize")]
    pub exp: DateTime<Utc>,
    #[serde(deserialize_with = "flexible_timestamp::option::deserialize")]
    #[serde(default)]
    pub nbf: Option<DateTime<Utc>>,
    #[serde(default)]
    pub email: Option<String>,
}

pub type UnverifiedClaims = Claims;

/// A Sigstore token.
pub struct IdentityToken {
    original_token: String,
    claims: UnverifiedClaims,
}

impl IdentityToken {
    /// Returns the **unverified** claim set for the token.
    ///
    /// The [UnverifiedClaims] returned from this method should not be used to enforce security
    /// invariants.
    pub fn unverified_claims(&self) -> &UnverifiedClaims {
        &self.claims
    }

    /// Returns whether or not this token is within its self-stated validity period.
    pub fn in_validity_period(&self) -> bool {
        let now = Utc::now();

        if let Some(nbf) = self.claims.nbf {
            nbf <= now && now < self.claims.exp
        } else {
            now < self.claims.exp
        }
    }
}

impl TryFrom<&str> for IdentityToken {
    type Error = SigstoreError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let parts: [&str; 3] = value.split('.').collect::<Vec<_>>().try_into().or(Err(
            SigstoreError::IdentityTokenError("Malformed JWT".into()),
        ))?;

        let claims_bytes = base64
            .decode(parts[1])
            .or(Err(SigstoreError::IdentityTokenError(
                "Malformed JWT: Unable to decode claims".into(),
            )))?;
        
        // Debug: log the raw claims JSON
        let claims_str = String::from_utf8_lossy(&claims_bytes);
        tracing::debug!("JWT claims payload (raw): {}", claims_str);
        
        let claims: Claims = serde_json::from_slice(&claims_bytes).or_else(|e| {
            tracing::error!("Failed to parse claims: {}", e);
            tracing::error!("Claims JSON: {}", claims_str);
            Err(SigstoreError::IdentityTokenError(format!(
                "Malformed JWT: claims JSON malformed - {}",
                e
            )))
        })?;
        
        if !claims.aud.contains_sigstore() {
            return Err(SigstoreError::IdentityTokenError(
                "Not a Sigstore JWT".into(),
            ));
        }

        Ok(IdentityToken {
            original_token: value.to_owned(),
            claims,
        })
    }
}

impl From<CoreIdToken> for IdentityToken {
    fn from(value: CoreIdToken) -> Self {
        value
            .to_string()
            .as_str()
            .try_into()
            .expect("Token conversion failed")
    }
}

impl std::fmt::Display for IdentityToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.original_token.clone())
    }
}
