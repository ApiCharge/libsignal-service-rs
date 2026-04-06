use crate::utils::serde_base64;
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use libsignal_core::{Aci, ServiceIdKind};
use reqwest::Method;

use crate::content::ServiceError;

use super::{Identified, SignalWebSocket, Unidentified};

// ── Authenticated username operations (reserve + confirm) ───────

impl SignalWebSocket<Identified> {
    /// Reserve a username. Submits up to 20 hashes; Signal returns the first available.
    pub async fn reserve_username(
        &mut self,
        username_hashes: &[Vec<u8>],
    ) -> Result<Vec<u8>, ServiceError> {
        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct ReserveRequest {
            username_hashes: Vec<String>,
        }

        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct ReserveResponse {
            username_hash: String,
        }

        let body = ReserveRequest {
            username_hashes: username_hashes
                .iter()
                .map(|h| BASE64_URL_SAFE_NO_PAD.encode(h))
                .collect(),
        };

        let response: ReserveResponse = self
            .http_request(Method::PUT, "/v1/accounts/username_hash/reserve")?
            .send_json(&body)
            .await?
            .service_error_for_status()
            .await?
            .json()
            .await?;

        BASE64_URL_SAFE_NO_PAD
            .decode(&response.username_hash)
            .map_err(|_| ServiceError::InvalidFrame {
                reason: "invalid base64 in reserve response",
            })
    }

    /// Confirm a previously reserved username with a zero-knowledge proof.
    pub async fn confirm_username(
        &mut self,
        username_hash: &[u8],
        zk_proof: &[u8],
    ) -> Result<(), ServiceError> {
        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct ConfirmRequest {
            username_hash: String,
            zk_proof: String,
        }

        let body = ConfirmRequest {
            username_hash: BASE64_URL_SAFE_NO_PAD.encode(username_hash),
            zk_proof: BASE64_URL_SAFE_NO_PAD.encode(zk_proof),
        };

        self.http_request(Method::PUT, "/v1/accounts/username_hash/confirm")?
            .send_json(&body)
            .await?
            .service_error_for_status()
            .await?;

        Ok(())
    }
}

// ── Unauthenticated username lookups ────────────────────────────

impl SignalWebSocket<Unidentified> {
    pub async fn look_up_username(
        &mut self,
        username: &usernames::Username,
    ) -> Result<Option<Aci>, ServiceError> {
        self.look_up_username_hash(&username.hash()).await
    }

    // Based on libsignal-net
    pub async fn look_up_username_hash(
        &mut self,
        hash: &[u8],
    ) -> Result<Option<Aci>, ServiceError> {
        #[derive(serde::Deserialize)]
        struct UsernameHashResponse {
            uuid: String,
        }

        let response = self
            .http_request(
                Method::GET,
                format!(
                    "/v1/accounts/username_hash/{}",
                    BASE64_URL_SAFE_NO_PAD.encode(hash)
                ),
            )?
            .send()
            .await?;

        if response.status() == 404 {
            tracing::debug!("username not found");
            return Ok(None);
        }

        let result: UsernameHashResponse =
            response.service_error_for_status().await?.json().await?;

        Ok(Some(
            Aci::parse_from_service_id_string(&result.uuid).ok_or_else(
                || ServiceError::InvalidAddressType(ServiceIdKind::Aci),
            )?,
        ))
    }

    // Based on libsignal-net
    pub async fn look_up_username_link(
        &mut self,
        uuid: uuid::Uuid,
        entropy: &[u8; usernames::constants::USERNAME_LINK_ENTROPY_SIZE],
    ) -> Result<Option<usernames::Username>, ServiceError> {
        #[derive(serde::Deserialize)]
        struct UsernameLinkResponse {
            #[serde(rename = "usernameLinkEncryptedValue")]
            #[serde(with = "serde_base64")]
            encrypted_username: Vec<u8>,
        }

        let response = self
            .http_request(
                Method::GET,
                format!("/v1/accounts/username_link/{uuid}",),
            )?
            .send()
            .await?;

        if response.status() == 404 {
            tracing::debug!("username link not found");
            return Ok(None);
        }

        let result: UsernameLinkResponse =
            response.service_error_for_status().await?.json().await?;

        let plaintext_username =
            usernames::decrypt_username(entropy, &result.encrypted_username)
                .map_err(|_e| {
                    tracing::error!(error=%_e, "undecryptable username");
                    ServiceError::InvalidFrame {
                        reason: "undecryptable username link",
                    }
                })?;

        let validated_username = usernames::Username::new(&plaintext_username).map_err(|e| {
            // Exhaustively match UsernameError to make sure there's nothing we shouldn't log.
            #[allow(clippy::let_unit_value)]
            let _username_error_carries_no_information_that_would_be_bad_to_log = match e {
                usernames::UsernameError::MissingSeparator
                | usernames::UsernameError::NicknameCannotBeEmpty
                | usernames::UsernameError::NicknameCannotStartWithDigit
                | usernames::UsernameError::BadNicknameCharacter
                | usernames::UsernameError::NicknameTooShort
                | usernames::UsernameError::NicknameTooLong
                | usernames::UsernameError::DiscriminatorCannotBeEmpty
                | usernames::UsernameError::DiscriminatorCannotBeZero
                | usernames::UsernameError::DiscriminatorCannotBeSingleDigit
                | usernames::UsernameError::DiscriminatorCannotHaveLeadingZeros
                | usernames::UsernameError::BadDiscriminatorCharacter
                | usernames::UsernameError::DiscriminatorTooLarge => {}
            };
            tracing::warn!(error=%e, "username link decrypted to an invalid username");
            tracing::debug!(error=%e,
                "username link decrypted to '{plaintext_username}', which is not valid"
            );
            // The user didn't ever type this username, so the precise way in which it's invalid
            // isn't important. Treat this equivalent to having found garbage data in the link. This
            // simplifies error handling for callers.
            ServiceError::InvalidFrame {
                reason: "undecryptable username link",
            }
        })?;

        Ok(Some(validated_username))
    }
}
