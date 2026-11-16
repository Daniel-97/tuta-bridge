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
    debug: bool,
}

/// Which error a 401/403 response should map to, depending on the auth phase.
#[derive(Clone, Copy)]
enum AuthFailure {
    Login,
    SecondFactor,
}

/// Print a short, opt-in diagnostic line for an HTTP response.
///
/// Enabled only by `TUTA_BRIDGE_DEBUG_HTTP=1`. The URL query (which contains
/// `_body` with the mail address/verifier) is never printed; only the path,
/// status, and recognized error fields from a JSON response.
fn debug_http(
    enabled: bool,
    phase: &str,
    method: &str,
    url: &str,
    status: u32,
    body: Option<&[u8]>,
) {
    if !enabled {
        return;
    }
    let path = url.split('?').next().unwrap_or(url);
    let detail = body
        .map(describe_error_body)
        .unwrap_or_else(|| "<empty body>".to_string());
    eprintln!("http debug: {phase} {method} {path} -> {status}; {detail}");
}

fn describe_error_body(body: &[u8]) -> String {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        let text = String::from_utf8_lossy(body);
        let truncated: String = text.chars().take(500).collect();
        return format!("<non-json> {truncated}");
    };

    let redacted = redact_json(value);
    let compact =
        serde_json::to_string(&redacted).unwrap_or_else(|_| "<unprintable json>".to_string());
    let truncated: String = compact.chars().take(2000).collect();
    truncated
}

/// Redact values that could carry credentials or account identifiers. The
/// server's error code/message remain visible for diagnosis.
fn redact_json(value: serde_json::Value) -> serde_json::Value {
    const SENSITIVE: &[&str] = &[
        "password",
        "passphrase",
        "authverifier",
        "accesstoken",
        "encryptedpassphrasekey",
        "mailaddress",
        "salt",
        "accesskey",
        "totp",
        "otpcode",
        "session",
    ];
    match value {
        serde_json::Value::Object(map) => {
            let redacted = map
                .into_iter()
                .map(|(key, value)| {
                    let lower = key.to_ascii_lowercase();
                    if SENSITIVE.contains(&lower.as_str()) {
                        (key, serde_json::Value::String("<redacted>".to_string()))
                    } else {
                        (key, redact_json(value))
                    }
                })
                .collect();
            serde_json::Value::Object(redacted)
        }
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(redact_json).collect())
        }
        other => other,
    }
}

impl TutaPreSession {
    pub fn new(rest: Arc<dyn RestClient>, base_url: String, debug: bool) -> Self {
        Self {
            rest,
            base_url,
            debug,
        }
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
        let method_label = format!("{method:?}");
        let response = self
            .rest
            .request_binary(url.to_string(), method, options)
            .await
            .map_err(|_| Error::Network("request failed".into()))?;

        debug_http(
            self.debug,
            phase,
            &method_label,
            url,
            response.status,
            response.body.as_deref(),
        );

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

#[cfg(test)]
mod tests {
    use super::describe_error_body;

    #[test]
    fn describes_json_error_fields_without_the_raw_body() {
        let body = br#"{"errorCode":"invalid","message":"bad request","other":"ignored"}"#;
        let text = describe_error_body(body);
        assert!(text.contains(r#""errorCode":"invalid""#));
        assert!(text.contains(r#""message":"bad request""#));
        assert!(text.contains(r#""other":"ignored""#));
    }

    #[test]
    fn redacts_sensitive_json_values() {
        let body = br#"{"message":"bad request","mailAddress":"a@b.c","accessToken":"tok","nested":{"password":"pw"}}"#;
        let text = describe_error_body(body);
        assert!(text.contains(r#""message":"bad request""#));
        assert!(!text.contains("a@b.c"));
        assert!(!text.contains("tok"));
        assert!(!text.contains("pw"));
        assert!(text.contains("<redacted>"));
    }

    #[test]
    fn describes_non_json_body_with_a_truncated_prefix() {
        let text = describe_error_body(b"<html>oops</html>");
        assert!(text.starts_with("<non-json>"));
        assert!(text.contains("<html>oops</html>"));
    }
}
