// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

use async_trait::async_trait;
use dropshot::{RequestContext, ServerContext};
use hex::FromHexError;
use hmac_ext::Hmac;
use http::header::ToStrError;
use sha2::Sha256;
use thiserror::Error;

use crate::hmac::HmacSignatureVerifier;

#[derive(Debug)]
pub struct GitHubWebhookVerification;

#[derive(Debug, Error)]
pub enum GitHubWebhookVerificationError {
    #[error("Failed to find key to verify requests with")]
    FailedToFindKey,
    #[error("Incoming request did not include a signature header")]
    RequestIsMissingSignature,
    #[error("Failed to decode signature header {0}")]
    FailedToDecodeHeader(#[from] FromHexError),
    #[error("Failed to parse signature header {0}")]
    FailedToParseHeader(#[from] ToStrError),
}

#[async_trait]
impl HmacSignatureVerifier for GitHubWebhookVerification {
    type Algo = Hmac<Sha256>;
    type Error = GitHubWebhookVerificationError;

    async fn key<Context: ServerContext>(
        _: &RequestContext<Context>,
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(std::env::var("GITHUB_WEBHOOK_KEY")
            .map(|key| key.into_bytes())
            .map_err(|_| {
                tracing::warn!("Failed to find webhook key for verifying GitHub webhooks");
                GitHubWebhookVerificationError::FailedToFindKey
            })?)
    }

    async fn signature<Context: ServerContext>(
        rqctx: &RequestContext<Context>,
    ) -> Result<Vec<u8>, Self::Error> {
        let signature = rqctx
            .request
            .headers()
            .get("X-Hub-Signature-256")
            .ok_or(GitHubWebhookVerificationError::RequestIsMissingSignature)
            .and_then(|header_value| Ok(header_value.to_str()?))
            .and_then(|header| {
                tracing::debug!(?header, "Found GitHub signature header");
                Ok(hex::decode(header.trim_start_matches("sha256="))?)
            })
            .map_err(|err| {
                tracing::info!(?err, "GitHub webhook is missing a well-formed signature");
                err
            })?;

        Ok(signature)
    }
}
