use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use crypto_primitives::aes::{Aes256Key, InitializationVector};
use crypto_primitives::key::GenericAesKey;
use rand_core::{OsRng, RngCore};
use secrecy::ExposeSecret;
use tutasdk::bindings::rest_client::{
    encode_query_params, HttpMethod, RestClient, RestClientOptions,
};
use tutasdk::bindings::suspendable_rest_client::SuspensionBehavior;
use tutasdk::crypto::crypto_facade::create_auth_verifier;
use tutasdk::crypto::generate_key_from_passphrase;
use tutasdk::CLIENT_VERSION;

use super::json::{
    create_session_body, parse_pending, parse_salt_response, parse_session_response, salt_query,
    second_factor_body, second_factor_query, ChallengeType,
};
use crate::domain::Error;
use crate::ports::session::{NewSession, SessionRequest};

/// Pre-session adapter for Tuta. Handles the unauthenticated login flow
/// (salt fetch, session creation, second-factor handling).
pub struct TutaPreSession {
    rest: Arc<dyn RestClient>,
    base_url: String,
}

/// Which error a 401/403 response should map to, depending on the auth phase.
#[derive(Clone, Copy)]
enum AuthFailure {
    Login,
    SecondFactor,
}

impl TutaPreSession {
    pub fn new(rest: Arc<dyn RestClient>, base_url: String) -> Self {
        Self { rest, base_url }
    }

    /// Execute the full pre-session login flow and return a `NewSession`.
    pub async fn create(&self, request: SessionRequest) -> crate::domain::Result<NewSession> {
        let SessionRequest {
            mail_address,
            password,
            totp,
        } = request;

        // Step 1: Fetch salt
        let salt_query_json = salt_query(&mail_address);
        let salt_query_encoded =
            encode_query_params([("_body".as_bytes(), salt_query_json.as_slice())]);
        let salt_url = format!(
            "{}/rest/sys/saltservice{}",
            self.base_url, salt_query_encoded
        );
        let salt_headers = self.common_headers(false);
        let salt_data = self
            .request_json(
                HttpMethod::GET,
                &salt_url,
                None,
                salt_headers,
                AuthFailure::Login,
                "salt request",
            )
            .await?;
        let salt_resp = parse_salt_response(&salt_data)?;

        // Step 2: Check KDF version
        if salt_resp.kdf_version != 1 {
            return Err(Error::BcryptUnsupported);
        }

        // Step 3: Derive key from passphrase, then zeroize the passphrase as
        // soon as the KDF no longer needs it.
        let key = generate_key_from_passphrase(password.expose_secret(), salt_resp.salt);
        drop(password);

        // Step 4: Create auth verifier
        let verifier = create_auth_verifier(key.clone());

        // Step 5: Generate access key (32 random bytes) and base64-encode it
        let mut access_key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut access_key_bytes);
        let access_key_b64 = BASE64_STANDARD.encode(access_key_bytes);

        // Step 6: Create session
        let session_body =
            create_session_body(&mail_address, &verifier, &access_key_b64, "tuta-bridge");
        let session_url = format!("{}/rest/sys/sessionservice", self.base_url);
        let mut session_headers = self.common_headers(true);
        session_headers.insert("v".to_string(), "158".to_string());
        let session_data = self
            .request_json(
                HttpMethod::POST,
                &session_url,
                Some(session_body),
                session_headers,
                AuthFailure::Login,
                "session request",
            )
            .await?;
        let mut session_resp = parse_session_response(&session_data)?;

        // Step 7: Handle challenges. Only TOTP (type 1) is supported; any other
        // challenge type is rejected immediately.
        let session_id = super::json::session_id_from_access_token(&session_resp.access_token)?;
        let mut need_poll = false;

        for challenge in &session_resp.challenges {
            match challenge {
                ChallengeType::Totp => {
                    let code = (totp)()?;
                    let totp_body = second_factor_body(&session_id, &code);
                    let totp_url = format!("{}/rest/sys/secondfactorauthservice", self.base_url);
                    let mut totp_headers = self.common_headers(true);
                    totp_headers.insert("v".to_string(), "158".to_string());
                    self.request_json(
                        HttpMethod::POST,
                        &totp_url,
                        Some(totp_body),
                        totp_headers,
                        AuthFailure::SecondFactor,
                        "second factor request",
                    )
                    .await?;
                    need_poll = true;
                }
                ChallengeType::Other(_) => {
                    return Err(Error::Unsupported(
                        "second factor type not supported".into(),
                    ));
                }
            }
        }

        // Step 8: Poll for approval
        if need_poll {
            self.poll_second_factor(&session_resp.access_token).await?;
        }

        // Step 9: Build encrypted passphrase key
        let access_key = Aes256Key::from_bytes(&access_key_bytes)
            .map_err(|_| Error::Login("invalid access key".into()))?;
        let mut random_iv_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut random_iv_bytes);
        let iv = InitializationVector::from_arr(random_iv_bytes);
        let encrypted_passphrase_key =
            GenericAesKey::Aes256(access_key).encrypt_key(&GenericAesKey::Aes256(key), iv);

        // Step 10: Return NewSession
        Ok(NewSession {
            user_id: std::mem::take(&mut session_resp.user_id),
            access_token: std::mem::take(&mut session_resp.access_token),
            encrypted_passphrase_key,
        })
    }

    /// Poll the second-factor auth service until approval is confirmed or timeout.
    async fn poll_second_factor(&self, access_token: &str) -> crate::domain::Result<()> {
        let query_json = second_factor_query(access_token);
        let query_encoded = encode_query_params([("_body".as_bytes(), query_json.as_slice())]);

        for _ in 0..120 {
            let url = format!(
                "{}/rest/sys/secondfactorauthservice{}",
                self.base_url, query_encoded
            );
            let headers = self.common_headers(false);
            let data = self
                .request_json(
                    HttpMethod::GET,
                    &url,
                    None,
                    headers,
                    AuthFailure::SecondFactor,
                    "second factor poll",
                )
                .await?;
            if !parse_pending(&data)? {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }

        Err(Error::SecondFactor("timed out waiting for approval".into()))
    }

    /// Build common request headers.
    fn common_headers(&self, with_content_type: bool) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("cv".to_string(), CLIENT_VERSION.to_string());
        // Every sys service call carries the service model version. SaltService
        // rejects a missing `v` with 400 before authentication.
        headers.insert("v".to_string(), "158".to_string());
        if with_content_type {
            headers.insert("Content-Type".to_string(), "application/json".to_string());
        }
        headers
    }

    /// Execute an HTTP request and return the response body as bytes.
    ///
    /// A 401/403 maps to the phase-specific auth error; other non-2xx statuses
    /// map to `Error::Network` with the status code.
    async fn request_json(
        &self,
        method: HttpMethod,
        url: &str,
        body: Option<Vec<u8>>,
        headers: HashMap<String, String>,
        failure: AuthFailure,
        phase: &'static str,
    ) -> crate::domain::Result<Vec<u8>> {
        let options = RestClientOptions {
            headers,
            body,
            suspension_behavior: Some(SuspensionBehavior::Suspend),
        };
        let response = self
            .rest
            .request_binary(url.to_string(), method, options)
            .await
            .map_err(|_| Error::Network("request failed".into()))?;

        if response.status == 401 || response.status == 403 {
            return Err(match failure {
                AuthFailure::Login => Error::Login("authentication failed".into()),
                AuthFailure::SecondFactor => Error::SecondFactor("second factor rejected".into()),
            });
        }

        if response.status < 200 || response.status >= 300 {
            return Err(Error::Network(format!(
                "{} failed with status {}",
                phase, response.status
            )));
        }

        Ok(response.body.unwrap_or_default())
    }
}
