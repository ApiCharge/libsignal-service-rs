//! Direct HTTP registration methods on PushService.
//!
//! These bypass the WebSocket framing used by the existing SignalWebSocket
//! registration methods. Signal's registration API accepts plain REST calls;
//! the WebSocket path was broken because `/v1/websocket/` rejects credentials
//! for accounts that don't exist yet.
//!
//! See: https://github.com/whisperfish/presage/issues/371

use libsignal_protocol::IdentityKey;
use reqwest::Method;
use serde::Serialize;

use super::{HttpAuthOverride, ReqwestExt};
use crate::{
    configuration::Endpoint,
    push_service::{PushService, ServiceError},
    utils::serde_base64,
    websocket::{
        account::AccountAttributes,
        registration::{
            DeviceActivationRequest, RegistrationMethod,
            RegistrationSessionMetadataResponse, VerificationTransport,
            VerifyAccountResponse,
        },
    },
};

impl PushService {
    /// POST /v1/verification/session — create a new verification session.
    pub async fn create_verification_session(
        &self,
        number: &str,
        push_token: Option<&str>,
        mcc: Option<&str>,
        mnc: Option<&str>,
    ) -> Result<RegistrationSessionMetadataResponse, ServiceError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            number: &'a str,
            push_token: Option<&'a str>,
            mcc: Option<&'a str>,
            mnc: Option<&'a str>,
            push_token_type: Option<&'a str>,
        }

        self.request(
            Method::POST,
            Endpoint::service("/v1/verification/session"),
            HttpAuthOverride::Unidentified,
        )?
        .json(&Body {
            number,
            push_token_type: push_token.map(|_| "fcm"),
            push_token,
            mcc,
            mnc,
        })
        .send()
        .await?
        .service_error_for_status()
        .await?
        .json()
        .await
        .map_err(Into::into)
    }

    /// PATCH /v1/verification/session/{id} — update session with captcha/push challenge.
    pub async fn patch_verification_session(
        &self,
        session_id: &str,
        push_token: Option<&str>,
        mcc: Option<&str>,
        mnc: Option<&str>,
        captcha: Option<&str>,
        push_challenge: Option<&str>,
    ) -> Result<RegistrationSessionMetadataResponse, ServiceError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            captcha: Option<&'a str>,
            push_token: Option<&'a str>,
            push_challenge: Option<&'a str>,
            mcc: Option<&'a str>,
            mnc: Option<&'a str>,
            push_token_type: Option<&'a str>,
        }

        self.request(
            Method::PATCH,
            Endpoint::service(format!("/v1/verification/session/{session_id}")),
            HttpAuthOverride::Unidentified,
        )?
        .json(&Body {
            captcha,
            push_token_type: push_token.map(|_| "fcm"),
            push_token,
            mcc,
            mnc,
            push_challenge,
        })
        .send()
        .await?
        .service_error_for_status()
        .await?
        .json()
        .await
        .map_err(Into::into)
    }

    /// POST /v1/verification/session/{id}/code — request a verification code (SMS or voice).
    pub async fn request_verification_code(
        &self,
        session_id: &str,
        client: &str,
        transport: VerificationTransport,
    ) -> Result<RegistrationSessionMetadataResponse, ServiceError> {
        #[derive(Serialize)]
        struct Body<'a> {
            transport: VerificationTransport,
            client: &'a str,
        }

        self.request(
            Method::POST,
            Endpoint::service(format!(
                "/v1/verification/session/{session_id}/code"
            )),
            HttpAuthOverride::Unidentified,
        )?
        .json(&Body { transport, client })
        .send()
        .await?
        .service_error_for_status()
        .await?
        .json()
        .await
        .map_err(Into::into)
    }

    /// PUT /v1/verification/session/{id}/code — submit the verification code.
    pub async fn submit_verification_code(
        &self,
        session_id: &str,
        verification_code: &str,
    ) -> Result<RegistrationSessionMetadataResponse, ServiceError> {
        #[derive(Serialize)]
        struct Body<'a> {
            code: &'a str,
        }

        self.request(
            Method::PUT,
            Endpoint::service(format!(
                "/v1/verification/session/{session_id}/code"
            )),
            HttpAuthOverride::Unidentified,
        )?
        .json(&Body {
            code: verification_code,
        })
        .send()
        .await?
        .service_error_for_status()
        .await?
        .json()
        .await
        .map_err(Into::into)
    }

    /// POST /v1/registration — register the account (submit keys + attributes).
    pub async fn submit_registration_request(
        &self,
        registration_method: RegistrationMethod<'_>,
        account_attributes: AccountAttributes,
        skip_device_transfer: bool,
        aci_identity_key: &IdentityKey,
        pni_identity_key: &IdentityKey,
        device_activation_request: DeviceActivationRequest,
    ) -> Result<VerifyAccountResponse, ServiceError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            session_id: Option<&'a str>,
            recovery_password: Option<&'a str>,
            account_attributes: AccountAttributes,
            skip_device_transfer: bool,
            every_signed_key_valid: bool,
            #[serde(with = "serde_base64")]
            pni_identity_key: Vec<u8>,
            #[serde(with = "serde_base64")]
            aci_identity_key: Vec<u8>,
            #[serde(flatten)]
            device_activation_request: DeviceActivationRequest,
        }

        self.request(
            Method::POST,
            Endpoint::service("/v1/registration"),
            HttpAuthOverride::NoOverride,
        )?
        .json(&Body {
            session_id: registration_method.session_id(),
            recovery_password: registration_method.recovery_password(),
            account_attributes,
            skip_device_transfer,
            aci_identity_key: aci_identity_key.serialize().into(),
            pni_identity_key: pni_identity_key.serialize().into(),
            device_activation_request,
            every_signed_key_valid: true,
        })
        .send()
        .await?
        .service_error_for_status()
        .await?
        .json()
        .await
        .map_err(Into::into)
    }
}
