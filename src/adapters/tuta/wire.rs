//! Decrypt a `MailDetailsBlob` fetched from the blob server.
//!
//! Blob elements are not regular list entities: they are stored in an archive
//! and served by the blob server as encrypted server-model JSON. The SDK does
//! not expose a loader for them, so this module decrypts the fields needed by
//! the MIME renderer with the mail's session key.
//!
//! Which values are ciphertext follows the `encrypted` flag of the pinned
//! type model (`tutanota.json`), not the name of the type:
//!
//! | type                 | id   | field             | wire form          |
//! |----------------------|------|-------------------|--------------------|
//! | MailDetails          | 1284 | sentDate          | plain number string |
//! | Body                 | 1275 | text              | encrypted          |
//! | Body                 | 1276 | compressedText    | encrypted, LZ4     |
//! | Header               | 1271 | headers           | encrypted          |
//! | Header               | 1272 | compressedHeaders | encrypted, LZ4     |
//! | MailAddress          | 94   | name              | encrypted          |
//! | MailAddress          | 95   | address           | plain string       |
//! | EncryptedMailAddress | 614  | name              | encrypted          |
//! | EncryptedMailAddress | 615  | address           | encrypted          |

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use crypto_primitives::key::GenericAesKey;
use serde_json::{Map, Value};
use tutasdk::date::DateTime;
use tutasdk::entities::entity_facade::EntityFacadeImpl;
use tutasdk::entities::generated::tutanota::{
    Body, EncryptedMailAddress, Header, MailAddress, MailDetails, Recipients,
};

use crate::domain::{Error, Result};

/// Decrypt the `details` aggregation of a `MailDetailsBlob` wire object.
pub fn decrypt_mail_details(raw: &Value, key: &GenericAesKey) -> Result<MailDetails> {
    let blob = raw
        .as_object()
        .ok_or_else(|| Error::Message("mail details parse failed".into()))?;
    let details =
        nested(blob, "1305").ok_or_else(|| Error::Message("mail details parse failed".into()))?;

    let sent_at = plain_number(details.get("1284")).unwrap_or(0);
    let body = nested(details, "1288")
        .map(|body| parse_body(body, key))
        .unwrap_or(Body {
            _id: None,
            text: None,
            compressedText: None,
            _errors: Default::default(),
        });
    let headers = nested(details, "1287").and_then(|headers| parse_headers(headers, key));
    let recipients = nested(details, "1286")
        .map(|recipients| parse_recipients(recipients, key))
        .unwrap_or(Recipients {
            _id: None,
            toRecipients: Vec::new(),
            ccRecipients: Vec::new(),
            bccRecipients: Vec::new(),
        });
    let reply_tos = array_objects(details.get("1285"))
        .iter()
        .filter_map(|address| parse_encrypted_address(address, key))
        .collect();

    Ok(MailDetails {
        _id: None,
        sentDate: DateTime::from_millis(sent_at.max(0) as u64),
        authStatus: 0,
        replyTos: reply_tos,
        recipients,
        headers,
        body,
    })
}

fn parse_body(body: &Map<String, Value>, key: &GenericAesKey) -> Body {
    Body {
        _id: None,
        text: decrypt_string(body.get("1275"), key),
        compressedText: decrypt_compressed(body.get("1276"), key),
        _errors: Default::default(),
    }
}

fn parse_headers(headers: &Map<String, Value>, key: &GenericAesKey) -> Option<Header> {
    let compressed = decrypt_compressed(headers.get("1272"), key);
    let plain = decrypt_string(headers.get("1271"), key);
    if compressed.is_none() && plain.is_none() {
        return None;
    }
    Some(Header {
        _id: None,
        headers: plain,
        compressedHeaders: compressed,
        _errors: Default::default(),
    })
}

fn parse_recipients(recipients: &Map<String, Value>, key: &GenericAesKey) -> Recipients {
    Recipients {
        _id: None,
        toRecipients: parse_address_list(recipients.get("1279"), key),
        ccRecipients: parse_address_list(recipients.get("1280"), key),
        bccRecipients: parse_address_list(recipients.get("1281"), key),
    }
}

fn parse_address_list(value: Option<&Value>, key: &GenericAesKey) -> Vec<MailAddress> {
    array_objects(value)
        .iter()
        .filter_map(|address| {
            let name = decrypt_string(address.get("94"), key).unwrap_or_default();
            let address = plain_string(address.get("95"))?;
            Some(MailAddress {
                _id: None,
                name,
                address,
                contact: None,
                _errors: Default::default(),
            })
        })
        .collect()
}

fn parse_encrypted_address(
    address: &Map<String, Value>,
    key: &GenericAesKey,
) -> Option<EncryptedMailAddress> {
    let name = decrypt_string(address.get("614"), key).unwrap_or_default();
    let address = decrypt_string(address.get("615"), key)?;
    Some(EncryptedMailAddress {
        _id: None,
        name,
        address,
        _errors: Default::default(),
    })
}

fn first_object(value: Option<&Value>) -> Option<&Map<String, Value>> {
    match value? {
        Value::Object(map) => Some(map),
        Value::Array(items) => items.first()?.as_object(),
        _ => None,
    }
}

fn nested<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a Map<String, Value>> {
    first_object(map.get(key))
}

fn array_objects(value: Option<&Value>) -> Vec<&Map<String, Value>> {
    match value {
        Some(Value::Array(items)) => items.iter().filter_map(Value::as_object).collect(),
        Some(Value::Object(map)) => vec![map],
        _ => Vec::new(),
    }
}

fn decrypt_bytes(value: Option<&Value>, key: &GenericAesKey) -> Option<Vec<u8>> {
    let encoded = value?.as_str()?;
    if encoded.is_empty() {
        return None;
    }
    let ciphertext = BASE64_STANDARD.decode(encoded).ok()?;
    key.decrypt_data(&ciphertext).ok()
}

fn decrypt_string(value: Option<&Value>, key: &GenericAesKey) -> Option<String> {
    String::from_utf8(decrypt_bytes(value, key)?).ok()
}

fn decrypt_compressed(value: Option<&Value>, key: &GenericAesKey) -> Option<String> {
    let plain = decrypt_bytes(value, key)?;
    let decompressed = EntityFacadeImpl::lz4_decompress_decrypted_bytes(plain.as_slice()).ok()?;
    String::from_utf8(decompressed).ok()
}

/// Read an unencrypted string value.
fn plain_string(value: Option<&Value>) -> Option<String> {
    value?.as_str().map(str::to_string)
}

/// Read an unencrypted number or date value. Tuta JSON encodes both as
/// decimal strings; a bare JSON number is accepted as well.
fn plain_number(value: Option<&Value>) -> Option<i64> {
    match value? {
        Value::String(text) => text.parse().ok(),
        Value::Number(number) => number.as_i64(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_primitives::aes::InitializationVector;

    fn key() -> GenericAesKey {
        GenericAesKey::from_bytes(&[7u8; 32]).unwrap()
    }

    fn encrypt(value: &[u8]) -> String {
        let iv = InitializationVector::from_arr([1u8; 16]);
        BASE64_STANDARD.encode(key().encrypt_data(value, iv).unwrap())
    }

    fn encrypt_string(value: &str) -> String {
        encrypt(value.as_bytes())
    }

    fn encrypt_compressed(value: &str) -> String {
        let compressed = EntityFacadeImpl::lz4_compress_plain_bytes(value.as_bytes()).unwrap();
        encrypt(&compressed)
    }

    fn decrypt(value: &str) -> String {
        key()
            .decrypt_data(&BASE64_STANDARD.decode(value).unwrap())
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .unwrap()
    }

    #[test]
    fn decrypts_body_headers_recipients_and_threading() {
        let raw = serde_json::json!({
            "1305": [{
                "1284": "1700000000000",
                "1288": [{
                    "1275": encrypt_string("plain body"),
                    "1276": encrypt_compressed("<p>html body</p>")
                }],
                "1286": [{
                    "1279": [{"93": "aaaa", "94": encrypt_string("Ann"), "95": "ann@example.com", "96": []}],
                    "1280": [{"93": "bbbb", "94": "", "95": "cc@example.com", "96": []}],
                    "1281": [{"93": "cccc", "94": encrypt_string("Dan"), "95": "bcc@example.com", "96": []}]
                }],
                "1285": [{"614": encrypt_string("Bob"), "615": encrypt_string("bob@example.com")}],
                "1287": [{"1271": encrypt_string("Message-ID: <x@y>\r\n")}]
            }]
        });

        let details = decrypt_mail_details(&raw, &key()).unwrap();
        assert_eq!(details.sentDate.as_millis(), 1_700_000_000_000);
        assert_eq!(details.body.text.as_deref(), Some("plain body"));
        assert_eq!(
            details.body.compressedText.as_deref(),
            Some("<p>html body</p>")
        );
        assert_eq!(
            details.recipients.toRecipients[0].address,
            "ann@example.com"
        );
        assert_eq!(details.recipients.toRecipients[0].name, "Ann");
        assert_eq!(details.recipients.ccRecipients[0].address, "cc@example.com");
        assert_eq!(details.recipients.ccRecipients[0].name, "");
        assert_eq!(
            details.recipients.bccRecipients[0].address,
            "bcc@example.com"
        );
        assert_eq!(details.replyTos[0].address, "bob@example.com");
        assert_eq!(
            details.headers.unwrap().headers.as_deref(),
            Some("Message-ID: <x@y>\r\n")
        );
    }

    #[test]
    fn decrypts_encrypted_body_without_text() {
        let raw = serde_json::json!({
            "1305": [{"1284": "1", "1288": [{"1276": encrypt_compressed("<div>x</div>")}]}]
        });
        let details = decrypt_mail_details(&raw, &key()).unwrap();
        assert_eq!(details.body.compressedText.as_deref(), Some("<div>x</div>"));
        assert!(details.body.text.is_none());
    }

    #[test]
    fn encrypted_field_helper_roundtrips() {
        assert_eq!(decrypt(&encrypt_string("hello")), "hello");
    }
}
