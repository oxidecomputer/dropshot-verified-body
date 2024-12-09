// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

use async_trait::async_trait;
use digest::KeyInit;
use dropshot::{
    ApiEndpointBodyContentType, ClientErrorStatusCode, ExclusiveExtractor, ExtractorMetadata, HttpError, RequestContext, ServerContext, TypedBody, UntypedBody
};
use hmac_ext::Mac;
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use std::{borrow::Cow, error::Error, marker::PhantomData};
use tracing::instrument;

/// A request body that has been verified by an HMAC verifier `T`.
#[derive(Debug)]
pub struct HmacVerifiedBody<T, BodyType> {
    audit: HmacVerifiedBodyAudit<T, BodyType>,
}

impl<T, BodyType> HmacVerifiedBody<T, BodyType>
where
    BodyType: FromBytes<HttpError>,
{
    /// Attempts to deserialize the request body into the specified `BodyType`. Returns a
    /// [`BAD_REQUEST`](http::status::StatusCode::BAD_REQUEST) [`HttpError`](dropshot::HttpError) if the deserialization of `BodyType` fails
    pub fn into_inner(self) -> Result<BodyType, HttpError> {
        self.audit.into_inner()
    }
}

/// A request body that performs the HMAC verification specified by the verifier `T`, but does not
/// fail extraction when verification fails. The [`HmacVerifiedBodyAudit`] can be queried to determine
/// if verification failed.
#[derive(Debug)]
pub struct HmacVerifiedBodyAudit<T, BodyType> {
    body: UntypedBody,
    _body_type: PhantomData<BodyType>,
    content_type: ApiEndpointBodyContentType,
    verified: bool,
    _verifier: PhantomData<T>,
}

impl<T, BodyType> HmacVerifiedBodyAudit<T, BodyType>
where
    BodyType: FromBytes<HttpError>,
{
    /// Returns that status of if this body passed verification
    pub fn verified(&self) -> bool {
        self.verified
    }

    /// Attempts to deserialize the request body into the specified `BodyType`. Returns a
    /// [`BAD_REQUEST`](http::status::StatusCode::BAD_REQUEST) [`HttpError`](dropshot::HttpError) if the deserialization of `BodyType` fails.
    pub fn into_inner(self) -> Result<BodyType, HttpError> {
        BodyType::from_bytes(self.body.as_bytes(), &self.content_type)
    }
}

/// A trait to be used to implement various HMAC verification strategies. By default a strategy
/// must implement two functions, one to provide the secret to the verifier, and one to extract
/// the signature to check from a request. Additionally, a strategy can implement a custom function
/// for extracting the materials from a request that should be signed.
#[async_trait]
pub trait HmacSignatureVerifier {
    type Algo: Mac + KeyInit;
    type Error: Error + Send + Sync;

    /// Provides the key to be used in signature verification.
    async fn key<Context: ServerContext>(
        rqctx: &RequestContext<Context>,
    ) -> Result<Vec<u8>, Self::Error>;

    /// Provides the signature that should be tested.
    async fn signature<Context: ServerContext>(
        rqctx: &RequestContext<Context>,
    ) -> Result<Vec<u8>, Self::Error>;

    /// Provides the content that should be signed. By default this provides the request body content.
    async fn content<'a, 'b, Context: ServerContext>(
        _rqctx: &'a RequestContext<Context>,
        body: &'b UntypedBody,
    ) -> Result<Cow<'b, [u8]>, Self::Error> {
        Ok(Cow::Borrowed(body.as_bytes()))
    }
}

/// Extracting an [`HmacVerifiedBody`] will return an [`UNAUTHORIZED`](http::status::StatusCode::UNAUTHORIZED) [`HttpError`](dropshot::HttpError) if verification fails.
/// An [`INTERNAL_SERVER_ERROR`](http::status::StatusCode::INTERNAL_SERVER_ERROR) will be returned if verification can not be performed due to a
/// the verifier `T` failing to supply a key or content,
#[async_trait]
impl<T, BodyType> ExclusiveExtractor for HmacVerifiedBody<T, BodyType>
where
    T: HmacSignatureVerifier + Send + Sync,
    BodyType: FromBytes<HttpError>,
{
    async fn from_request<Context: ServerContext>(
        rqctx: &RequestContext<Context>,
        request: hyper::Request<dropshot::Body>,
    ) -> Result<HmacVerifiedBody<T, BodyType>, HttpError> {
        let audit = HmacVerifiedBodyAudit::<T, BodyType>::from_request(rqctx, request).await?;

        tracing::debug!(?audit.verified, "Computed HMAC audit result");

        if audit.verified() {
            Ok(HmacVerifiedBody { audit })
        } else {
            Err(unauthorized())
        }
    }

    fn metadata(body_content_type: ApiEndpointBodyContentType) -> ExtractorMetadata {
        HmacVerifiedBodyAudit::<T, BodyType>::metadata(body_content_type)
    }
}

/// An [`INTERNAL_SERVER_ERROR`](http::status::StatusCode::INTERNAL_SERVER_ERROR) will be returned if verification can not be performed due to
/// the verifier `T` failing to supply a key or content,
#[async_trait]
impl<T, BodyType> ExclusiveExtractor for HmacVerifiedBodyAudit<T, BodyType>
where
    T: HmacSignatureVerifier + Send + Sync,
    BodyType: FromBytes<HttpError>,
{
    #[instrument(skip(rqctx, request), fields(request_id = rqctx.request_id, uri = ?request.uri()))]
    async fn from_request<Context: ServerContext>(
        rqctx: &RequestContext<Context>,
        request: hyper::Request<dropshot::Body>,
    ) -> Result<HmacVerifiedBodyAudit<T, BodyType>, HttpError> {
        let body = UntypedBody::from_request(rqctx, request).await?;
        let content = T::content(rqctx, &body)
            .await
            .map_err(|_| internal_error())?;
        let key = T::key(rqctx).await.map_err(|_| internal_error())?;

        let signature = T::signature(rqctx).await;
        let mac = <T::Algo as Mac>::new_from_slice(&key);

        let verified = match (signature, mac) {
            (Ok(signature), Ok(mut mac)) => {
                mac.update(&content);
                let verified = mac.verify_slice(&signature).is_ok();

                if !verified {
                    tracing::info!(?signature, "Failed to verify signature",);
                } else {
                    tracing::info!("Successfully verified signature",);
                }

                verified
            }
            (signature_res, mac_res) => {
                tracing::info!(
                    ?signature_res, mac_error = ?mac_res.err(),
                    "Unable to test signature"
                );
                false
            }
        };

        Ok(HmacVerifiedBodyAudit {
            body,
            _body_type: PhantomData,
            content_type: rqctx.endpoint.body_content_type.clone(),
            verified,
            _verifier: PhantomData,
        })
    }

    fn metadata(body_content_type: ApiEndpointBodyContentType) -> ExtractorMetadata {
        // The HMAC extractor is a wrapper around an inner type that does not perform any
        // alterations on the body content. Therefore we can use the metadata of the inner
        // type, as that is what we expect users to submit
        BodyType::metadata(body_content_type)
    }
}

/// Trait that defines for a given type how to construct that type from a byte slice, as well
/// as how the type ought to be described via an OpenAPI spec
pub trait FromBytes<E>: Send + Sync {
    fn from_bytes(bytes: &[u8], body_content_type: &ApiEndpointBodyContentType) -> Result<Self, E>
    where
        Self: Sized;
    fn metadata(body_content_type: ApiEndpointBodyContentType) -> ExtractorMetadata;
}

/// Provide an implementation of from_bytes for anything that can be deserialized from a JSON
/// payload. The JsonSchema bounds allows piggybacking on [`TypedBody`](dropshot::TypedBody) for generating OpenAPI data.
impl<T> FromBytes<HttpError> for T
where
    T: DeserializeOwned + JsonSchema + Send + Sync + 'static,
{
    fn from_bytes(
        bytes: &[u8],
        body_content_type: &ApiEndpointBodyContentType,
    ) -> Result<Self, HttpError>
    where
        Self: Sized,
    {
        match body_content_type {
            ApiEndpointBodyContentType::Json => serde_json::from_slice(bytes).map_err(|e| {
                HttpError::for_bad_request(None, format!("Failed to parse body: {}", e))
            }),
            _ => Err(HttpError::for_bad_request(
                None,
                "Unsupported content type".to_string(),
            )),
        }
    }

    fn metadata(body_content_type: ApiEndpointBodyContentType) -> ExtractorMetadata {
        TypedBody::<Self>::metadata(body_content_type)
    }
}

pub fn unauthorized() -> HttpError {
    HttpError::for_client_error(None, ClientErrorStatusCode::UNAUTHORIZED, "".to_string())
}

pub fn internal_error() -> HttpError {
    HttpError::for_internal_error("".to_string())
}
