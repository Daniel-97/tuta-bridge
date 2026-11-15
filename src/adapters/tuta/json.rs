use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::json;
use tutasdk::{crypto::sha256, util::BASE64_EXT};

use crate::domain::Error;

/// Decoded salt response from the Tuta salt service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaltResponse {
    pub salt: [u8; 16],
    pub kdf_version: i64,
}

/// Decoded create-session response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionResponse {
    pub access_token: String,
    pub user_id: String,
    pub challenges: Vec<ChallengeType>,
}

/// Type of second-factor challenge presented by the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChallengeType {
    Totp,
    Other(i64),
}

/// Composite identifier for a Tuta session (list id + element id).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionId {
    pub list_id: String,
    pub element_id: String,
}

/// Build the JSON body for the salt service request.
pub fn salt_query(mail_address: &str) -> Vec<u8> {
    let v = json!({
        "418": "0",
        "419": mail_address,
    });
    serde_json::to_vec(&v).expect("salt query serialization cannot fail")
}

/// Build the JSON body for the create-session request.
pub fn create_session_body(
    mail_address: &str,
    auth_verifier: &str,
    access_key: &str,
    client_identifier: &str,
) -> Vec<u8> {
    let v = json!({
        "1212": "0",
        "1213": mail_address,
        "1214": auth_verifier,
        "1215": client_identifier,
        "1216": access_key,
        "1217": null,
        "1417": null,
        "1218": null,
    });
    serde_json::to_vec(&v).expect("create session body serialization cannot fail")
}

/// Parse the salt service response.
pub fn parse_salt_response(data: &[u8]) -> crate::domain::Result<SaltResponse> {
    let v: serde_json::Value =
        serde_json::from_slice(data).map_err(|_| Error::Login("invalid salt response".into()))?;
    let salt_b64 = v
        .get("422")
        .and_then(|s| s.as_str())
        .ok_or_else(|| Error::Login("invalid salt response".into()))?;
    let salt_bytes = base64::engine::general_purpose::STANDARD
        .decode(salt_b64)
        .map_err(|_| Error::Login("invalid salt response".into()))?;
    if salt_bytes.len() != 16 {
        return Err(Error::Login("invalid salt response".into()));
    }
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&salt_bytes);

    let kdf_version = v
        .get("2133")
        .and_then(|s| s.as_str())
        .and_then(|s| s.parse::<i64>().ok())
        .ok_or_else(|| Error::Login("invalid salt response".into()))?;

    Ok(SaltResponse { salt, kdf_version })
}

/// Parse the create-session response.
pub fn parse_session_response(data: &[u8]) -> crate::domain::Result<SessionResponse> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|_| Error::Login("invalid session response".into()))?;

    let access_token = v
        .get("1221")
        .and_then(|s| s.as_str())
        .ok_or_else(|| Error::Login("invalid session response".into()))?
        .to_string();

    let user_id = v
        .get("1223")
        .and_then(|s| s.as_str())
        .ok_or_else(|| Error::Login("invalid session response".into()))?
        .to_string();

    let challenges_arr = v
        .get("1222")
        .and_then(|a| a.as_array())
        .ok_or_else(|| Error::Login("invalid session response".into()))?;

    let mut challenges = Vec::new();
    for c in challenges_arr {
        let ty = c
            .get("1189")
            .and_then(|s| s.as_str())
            .and_then(|s| s.parse::<i64>().ok())
            .ok_or_else(|| Error::Login("invalid session response".into()))?;
        match ty {
            1 => challenges.push(ChallengeType::Totp),
            other => challenges.push(ChallengeType::Other(other)),
        }
    }

    Ok(SessionResponse {
        access_token,
        user_id,
        challenges,
    })
}

/// Derive the session id (list id + element id) from an access token.
pub fn session_id_from_access_token(token: &str) -> crate::domain::Result<SessionId> {
    let bytes = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| Error::Login("invalid access token".into()))?;
    if bytes.len() < 9 {
        return Err(Error::Login("invalid access token".into()));
    }
    let list_id = BASE64_EXT.encode(&bytes[..9]);
    let hash = sha256(&bytes[9..]);
    let element_id = URL_SAFE_NO_PAD.encode(hash);
    Ok(SessionId {
        list_id,
        element_id,
    })
}

/// Build the JSON body for the second-factor authentication request.
pub fn second_factor_body(session_id: &SessionId, code: &str) -> Vec<u8> {
    let v = json!({
        "542": "0",
        "1230": "1",
        "1231": null,
        "1232": [&session_id.list_id, &session_id.element_id],
        "1243": code,
        "1905": null,
    });
    serde_json::to_vec(&v).expect("second factor body serialization cannot fail")
}

/// Build the JSON body for the second-factor-auth-get query.
pub fn second_factor_query(access_token: &str) -> Vec<u8> {
    let v = json!({
        "1234": "0",
        "1235": access_token,
    });
    serde_json::to_vec(&v).expect("second factor query serialization cannot fail")
}

/// Parse the second-factor pending response. Returns true if a second factor
/// is still pending.
pub fn parse_pending(data: &[u8]) -> crate::domain::Result<bool> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|_| Error::Login("invalid pending response".into()))?;
    let val = v
        .get("1238")
        .and_then(|s| s.as_str())
        .ok_or_else(|| Error::Login("invalid pending response".into()))?;
    Ok(val == "1")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: &str = r#"{"421":"0","422":"AAECAwQFBgcICQoLDA0ODw==","2133":"1"}"#;
    const SESSION: &str = r#"{"1220":"0","1221":"tok_abc","1222":[{"1188":"0","1189":"1","1247":{"1239":"x"}}],"1223":"userid"}"#;

    #[test]
    fn parses_salt_and_session() {
        let salt = parse_salt_response(SALT.as_bytes()).unwrap();
        assert_eq!(salt.kdf_version, 1);
        assert_eq!(salt.salt[0], 0);
        let s = parse_session_response(SESSION.as_bytes()).unwrap();
        assert_eq!(s.access_token, "tok_abc");
        assert_eq!(s.challenges, vec![ChallengeType::Totp]);
    }

    #[test]
    fn request_bodies_use_string_numbers_and_base64() {
        let v: serde_json::Value = serde_json::from_slice(&salt_query("A@B.C")).unwrap();
        assert_eq!(v["418"], "0");
        assert_eq!(v["419"], "A@B.C");

        let v: serde_json::Value = serde_json::from_slice(&create_session_body(
            "a@b.c",
            "verifier",
            "AAECAw==",
            "tuta-bridge",
        ))
        .unwrap();
        assert_eq!(v["1212"], "0");
        assert_eq!(v["1214"], "verifier");
        assert_eq!(v["1215"], "tuta-bridge");
        assert_eq!(v["1216"], "AAECAw==");
        assert!(v["1217"].is_null());

        let v: serde_json::Value = serde_json::from_slice(&second_factor_body(
            &SessionId {
                list_id: "L".into(),
                element_id: "E".into(),
            },
            "123456",
        ))
        .unwrap();
        assert_eq!(v["1230"], "1");
        assert_eq!(v["1243"], "123456");
        assert_eq!(v["1232"], serde_json::json!(["L", "E"]));
    }

    #[test]
    fn session_id_is_derived_like_the_clients() {
        let token = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let id = session_id_from_access_token(token).unwrap();
        assert!(!id.list_id.is_empty());
        assert!(!id.element_id.is_empty());
    }

    #[test]
    fn parses_pending() {
        assert!(parse_pending(br#"{"1237":"0","1238":"1"}"#).unwrap());
        assert!(!parse_pending(br#"{"1237":"0","1238":"0"}"#).unwrap());
    }
}
