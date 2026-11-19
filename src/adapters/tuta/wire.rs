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

/// The fixed error for a value that is present but cannot be decoded.
fn undecodable() -> Error {
    Error::Message("mail details decrypt failed".into())
}

/// Decrypt the `details` aggregation of a `MailDetailsBlob` wire object.
///
/// Fails closed: a value that is present but does not decode — wrong JSON
/// type, bad base64, failed MAC or decryption, invalid LZ4 or UTF-8 — is an
/// error, never an empty field. Otherwise a mail whose body failed to
/// decrypt would be rendered, sized, and cached as an empty message. Only
/// an absent or `null` value, and the empty string the server stores for a
/// default value, decode to "nothing".
pub fn decrypt_mail_details(raw: &Value, key: &GenericAesKey) -> Result<MailDetails> {
    let blob = raw
        .as_object()
        .ok_or_else(|| Error::Message("mail details parse failed".into()))?;
    let details =
        nested(blob, "1305").ok_or_else(|| Error::Message("mail details parse failed".into()))?;

    let sent_at = plain_number(details.get("1284"))?.unwrap_or(0);
    let body = match nested(details, "1288") {
        Some(body) => parse_body(body, key)?,
        None => Body {
            _id: None,
            text: None,
            compressedText: None,
            _errors: Default::default(),
        },
    };
    let headers = match nested(details, "1287") {
        Some(headers) => parse_headers(headers, key)?,
        None => None,
    };
    let recipients = match nested(details, "1286") {
        Some(recipients) => parse_recipients(recipients, key)?,
        None => Recipients {
            _id: None,
            toRecipients: Vec::new(),
            ccRecipients: Vec::new(),
            bccRecipients: Vec::new(),
        },
    };
    let reply_tos = array_objects(details.get("1285"))
        .into_iter()
        .map(|address| parse_encrypted_address(address, key))
        .collect::<Result<Vec<_>>>()?;

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

fn parse_body(body: &Map<String, Value>, key: &GenericAesKey) -> Result<Body> {
    Ok(Body {
        _id: None,
        text: decrypt_string(body.get("1275"), key)?,
        compressedText: decrypt_compressed(body.get("1276"), key)?,
        _errors: Default::default(),
    })
}

fn parse_headers(headers: &Map<String, Value>, key: &GenericAesKey) -> Result<Option<Header>> {
    let compressed = decrypt_compressed(headers.get("1272"), key)?;
    let plain = decrypt_string(headers.get("1271"), key)?;
    if compressed.is_none() && plain.is_none() {
        return Ok(None);
    }
    Ok(Some(Header {
        _id: None,
        headers: plain,
        compressedHeaders: compressed,
        _errors: Default::default(),
    }))
}

fn parse_recipients(recipients: &Map<String, Value>, key: &GenericAesKey) -> Result<Recipients> {
    Ok(Recipients {
        _id: None,
        toRecipients: parse_address_list(recipients.get("1279"), key)?,
        ccRecipients: parse_address_list(recipients.get("1280"), key)?,
        bccRecipients: parse_address_list(recipients.get("1281"), key)?,
    })
}

fn parse_address_list(value: Option<&Value>, key: &GenericAesKey) -> Result<Vec<MailAddress>> {
    array_objects(value)
        .into_iter()
        .map(|address| {
            Ok(MailAddress {
                _id: None,
                name: decrypt_string(address.get("94"), key)?.unwrap_or_default(),
                // A recipient without an address cannot be rendered.
                address: plain_string(address.get("95"))?.ok_or_else(undecodable)?,
                contact: None,
                _errors: Default::default(),
            })
        })
        .collect()
}

fn parse_encrypted_address(
    address: &Map<String, Value>,
    key: &GenericAesKey,
) -> Result<EncryptedMailAddress> {
    Ok(EncryptedMailAddress {
        _id: None,
        name: decrypt_string(address.get("614"), key)?.unwrap_or_default(),
        address: decrypt_string(address.get("615"), key)?.ok_or_else(undecodable)?,
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

/// Decrypt an encrypted value. `Ok(None)` only for an absent, `null`, or
/// empty-string value (the server's encoding of a default); everything else
/// either decrypts or is an error.
fn decrypt_bytes(value: Option<&Value>, key: &GenericAesKey) -> Result<Option<Vec<u8>>> {
    let encoded = match value {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(encoded)) => encoded,
        Some(_) => return Err(undecodable()),
    };
    if encoded.is_empty() {
        return Ok(None);
    }
    let ciphertext = BASE64_STANDARD.decode(encoded).map_err(|_| undecodable())?;
    key.decrypt_data(&ciphertext)
        .map(Some)
        .map_err(|_| undecodable())
}

fn decrypt_string(value: Option<&Value>, key: &GenericAesKey) -> Result<Option<String>> {
    decrypt_bytes(value, key)?
        .map(|plain| String::from_utf8(plain).map_err(|_| undecodable()))
        .transpose()
}

fn decrypt_compressed(value: Option<&Value>, key: &GenericAesKey) -> Result<Option<String>> {
    decrypt_bytes(value, key)?
        .map(|plain| {
            let decompressed = EntityFacadeImpl::lz4_decompress_decrypted_bytes(plain.as_slice())
                .map_err(|_| undecodable())?;
            String::from_utf8(decompressed).map_err(|_| undecodable())
        })
        .transpose()
}

/// Read an unencrypted string value; `Ok(None)` when absent or `null`.
fn plain_string(value: Option<&Value>) -> Result<Option<String>> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(_) => Err(undecodable()),
    }
}

/// Read an unencrypted number or date value. Tuta JSON encodes both as
/// decimal strings; a bare JSON number is accepted as well.
fn plain_number(value: Option<&Value>) -> Result<Option<i64>> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => text.parse().map(Some).map_err(|_| undecodable()),
        Some(Value::Number(number)) => number.as_i64().map(Some).ok_or_else(undecodable),
        Some(_) => Err(undecodable()),
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

    /// Ciphertext produced with a key other than the mail's session key.
    fn other_key_ciphertext(value: &str) -> String {
        let other = GenericAesKey::from_bytes(&[9u8; 32]).unwrap();
        let iv = InitializationVector::from_arr([1u8; 16]);
        BASE64_STANDARD.encode(other.encrypt_data(value.as_bytes(), iv).unwrap())
    }

    fn assert_fails_closed(raw: serde_json::Value) {
        let Err(error) = decrypt_mail_details(&raw, &key()) else {
            panic!("an undecodable value must fail the whole blob")
        };
        assert_eq!(
            error.to_string(),
            "message error: mail details decrypt failed"
        );
    }

    #[test]
    fn body_that_does_not_decrypt_is_an_error_not_an_empty_body() {
        assert_fails_closed(serde_json::json!({
            "1305": [{"1284": "1", "1288": [{"1275": other_key_ciphertext("secret body")}]}]
        }));
        assert_fails_closed(serde_json::json!({
            "1305": [{"1284": "1", "1288": [{"1276": "not base64!"}]}]
        }));
        // Decrypts, but is not valid LZ4.
        assert_fails_closed(serde_json::json!({
            "1305": [{"1284": "1", "1288": [{"1276": encrypt(&[0xf0, 0xff, 0xff, 0xff])}]}]
        }));
    }

    #[test]
    fn undecodable_headers_recipients_and_reply_tos_are_errors() {
        assert_fails_closed(serde_json::json!({
            "1305": [{"1284": "1", "1287": [{"1271": other_key_ciphertext("Subject: x")}]}]
        }));
        assert_fails_closed(serde_json::json!({
            "1305": [{"1284": "1", "1286": [{"1279": [{"94": other_key_ciphertext("Ann"), "95": "ann@example.com"}]}]}]
        }));
        assert_fails_closed(serde_json::json!({
            "1305": [{"1284": "1", "1286": [{"1279": [{"94": "", "95": 7}]}]}]
        }));
        assert_fails_closed(serde_json::json!({
            "1305": [{"1284": "1", "1285": [{"614": "", "615": other_key_ciphertext("bob@example.com")}]}]
        }));
        assert_fails_closed(serde_json::json!({"1305": [{"1284": "soon"}]}));
    }

    #[test]
    fn absent_null_and_empty_values_decode_to_nothing() {
        let raw = serde_json::json!({
            "1305": [{
                "1284": "5",
                "1288": [{"1275": null, "1276": ""}],
                "1287": [{"1271": null, "1272": null}],
                "1286": [{"1279": [], "1280": [], "1281": []}],
                "1285": []
            }]
        });
        let details = decrypt_mail_details(&raw, &key()).unwrap();
        assert!(details.body.text.is_none());
        assert!(details.body.compressedText.is_none());
        assert!(details.headers.is_none());
        assert!(details.recipients.toRecipients.is_empty());
        assert!(details.replyTos.is_empty());
    }
}
