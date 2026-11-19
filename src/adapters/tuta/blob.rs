//! Attachment download and decryption for Tuta mails.
//!
//! Tuta stores attachment contents as encrypted blobs grouped into archives.
//! [`load_attachment`] resolves the file's session key, requests one read
//! token per archive, fetches each blob over the blob service, decrypts the
//! concatenated chunks, and verifies the decrypted size. The pure helpers
//! (`blob_get_body`, `blob_url`, `decrypt_chunks`) are split out so they can be
//! unit-tested without a live session.

use std::collections::HashMap;

use base64::Engine as _;
use crypto_primitives::key::GenericAesKey;
use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};
use tutasdk::bindings::rest_client::{
    encode_query_params, HttpMethod, RestClient, RestClientOptions,
};
use tutasdk::bindings::suspendable_rest_client::SuspensionBehavior;
use tutasdk::entities::generated::sys::Blob;
use tutasdk::entities::generated::tutanota::TutanotaFile;
use tutasdk::entities::Entity;
use tutasdk::util::BASE64_EXT;
use tutasdk::{GeneratedId, IdTupleGenerated, LoggedInSdk, CLIENT_VERSION};

use super::content::file_is_intact;
use crate::domain::{Attachment, Error, Result};

/// Build the JSON body for a multi-blob blob-service GET request.
///
/// The plural form (`"193"` populated, `"110"` null) returns a framed
/// multi-blob response. The singular form would return raw ciphertext but is
/// not used by the reference client.
pub fn blob_get_body(archive_id: &str, blob_ids: &[String]) -> Result<Vec<u8>> {
    let ids: Vec<serde_json::Value> = blob_ids
        .iter()
        .map(|blob_id| json!({"145": random_hex_id(), "146": blob_id}))
        .collect();
    let value = json!({
        "51": "0",
        "52": archive_id,
        "110": null,
        "193": ids,
    });
    serde_json::to_vec(&value).map_err(|_| Error::Message("attachment body build failed".into()))
}

/// Build the full URL for fetching blobs from a blob server.
pub fn blob_url(server: &str, token: &str, access_token: &str, body: &[u8]) -> String {
    let server = server.trim_end_matches('/');
    let query = encode_query_params([
        ("blobAccessToken".as_bytes(), token.as_bytes()),
        ("v".as_bytes(), "13".as_bytes()),
        ("accessToken".as_bytes(), access_token.as_bytes()),
        ("_body".as_bytes(), body),
        ("cv".as_bytes(), CLIENT_VERSION.as_bytes()),
    ]);
    format!("{}/rest/storage/blobservice{}", server, query)
}

/// Parse the framed multi-blob response into `blobId -> ciphertext`.
pub fn parse_multiple_blobs(data: &[u8]) -> Result<HashMap<String, Vec<u8>>> {
    if data.len() < 4 {
        return Err(Error::Message("invalid blob response".into()));
    }
    let count = i32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if count < 0 {
        return Err(Error::Message("invalid blob response".into()));
    }
    let mut result = HashMap::new();
    let mut offset = 4usize;
    for _ in 0..count {
        if offset + 19 > data.len() {
            return Err(Error::Message("invalid blob response".into()));
        }
        let id = BASE64_EXT.encode(&data[offset..offset + 9]);
        let size = i32::from_be_bytes([
            data[offset + 15],
            data[offset + 16],
            data[offset + 17],
            data[offset + 18],
        ]);
        if size < 0 {
            return Err(Error::Message("invalid blob response".into()));
        }
        let start = offset + 19;
        let end = start + size as usize;
        if end > data.len() {
            return Err(Error::Message("invalid blob response".into()));
        }
        result.insert(id, data[start..end].to_vec());
        offset = end;
    }
    Ok(result)
}

/// Reject blob-server URLs that could downgrade or redirect the user token.
///
/// Tuta returns these URLs in `BlobServerAccessInfo`; accept HTTPS hosts only,
/// plus loopback HTTP for local tests. No userinfo, path, query, or fragment.
pub fn validate_blob_server(server: &str) -> Result<()> {
    let error = || Error::Message("attachment load failed".into());

    if let Some(rest) = server.strip_prefix("https://") {
        if rest.is_empty() || rest.contains(['/', '?', '#', '@']) {
            return Err(error());
        }
        return Ok(());
    }

    let Some(rest) = server.strip_prefix("http://") else {
        return Err(error());
    };
    if rest.is_empty() || rest.contains(['/', '?', '#', '@']) {
        return Err(error());
    }
    let host = if rest.starts_with('[') {
        rest.find(']').map(|i| &rest[..=i]).unwrap_or(rest)
    } else {
        rest.split(':').next().unwrap_or(rest)
    };
    if host == "127.0.0.1" || host == "localhost" || host == "[::1]" {
        Ok(())
    } else {
        Err(error())
    }
}

/// Fetch a blob over the blob service and return its raw bytes.
///
/// The blob access token stays in the `blobAccessToken` query parameter built by
/// [`blob_url`]; the `accessToken` header carries the user session access token.
pub async fn fetch_blob(
    rest: &dyn RestClient,
    url: &str,
    user_access_token: &str,
) -> Result<Vec<u8>> {
    let options = RestClientOptions {
        headers: HashMap::from([
            ("accessToken".to_string(), user_access_token.to_string()),
            ("cv".to_string(), CLIENT_VERSION.to_string()),
        ]),
        body: None,
        suspension_behavior: Some(SuspensionBehavior::Suspend),
    };
    let response = rest
        .request_binary(url.to_string(), HttpMethod::GET, options)
        .await
        .map_err(|_| Error::Network("blob download failed".into()))?;
    if response.status < 200 || response.status >= 300 {
        return Err(Error::Network(format!(
            "blob download failed: status {}",
            response.status
        )));
    }
    Ok(response.body.unwrap_or_default())
}

/// Generate a fresh aggregate `_id` for storage service inputs.
/// A read token for one blob archive, with the servers that accept it.
pub struct ArchiveAccess {
    pub blob_access_token: String,
    pub servers: Vec<String>,
}

fn random_hex_id() -> String {
    let mut bytes = [0u8; 3];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Request a read token for a whole blob archive.
///
/// The storage model encodes empty aggregations (`write`) as `[]`, and the
/// `read` aggregation as an array. Sending `null` makes the server reject the
/// request with 400.
pub async fn request_archive_read_token(
    rest: &dyn RestClient,
    base_url: &str,
    user_access_token: &str,
    archive_id: &str,
) -> Result<ArchiveAccess> {
    let body = json!({
        "78": "0",
        "180": null,
        "80": [],
        "181": [{
            "176": random_hex_id(),
            "177": archive_id,
            "178": null,
            "179": [],
        }]
    });
    let url = format!("{base_url}/rest/storage/blobaccesstokenservice");
    let options = RestClientOptions {
        headers: HashMap::from([
            ("accessToken".to_string(), user_access_token.to_string()),
            ("cv".to_string(), CLIENT_VERSION.to_string()),
            ("v".to_string(), "13".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ]),
        body: Some(serde_json::to_vec(&body).expect("token body serialization cannot fail")),
        suspension_behavior: Some(SuspensionBehavior::Suspend),
    };
    let response = rest
        .request_binary(url, HttpMethod::POST, options)
        .await
        .map_err(|_| Error::Network("mail details token failed".into()))?;
    if response.status < 200 || response.status >= 300 {
        // Status only: the server's response body never enters an error
        // string, which callers print and log.
        return Err(Error::Network(format!(
            "mail details token failed: status {}",
            response.status
        )));
    }
    parse_archive_access(response.body.as_deref().unwrap_or_default())
}

/// Request a read token for the blobs referenced by one instance.
pub async fn request_instance_read_token(
    rest: &dyn RestClient,
    base_url: &str,
    user_access_token: &str,
    archive_id: &str,
    list_id: &str,
    element_id: &str,
) -> Result<ArchiveAccess> {
    let body = json!({
        "78": "0",
        "180": "1",
        "80": [],
        "181": [{
            "176": random_hex_id(),
            "177": archive_id,
            "178": list_id,
            "179": [{
                "173": random_hex_id(),
                "174": element_id,
            }],
        }]
    });
    let url = format!("{base_url}/rest/storage/blobaccesstokenservice");
    let options = RestClientOptions {
        headers: HashMap::from([
            ("accessToken".to_string(), user_access_token.to_string()),
            ("cv".to_string(), CLIENT_VERSION.to_string()),
            ("v".to_string(), "13".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ]),
        body: Some(serde_json::to_vec(&body).expect("token body serialization cannot fail")),
        suspension_behavior: Some(SuspensionBehavior::Suspend),
    };
    let response = rest
        .request_binary(url, HttpMethod::POST, options)
        .await
        .map_err(|_| Error::Message("attachment token request failed".into()))?;
    if response.status < 200 || response.status >= 300 {
        return Err(Error::Message(format!(
            "attachment token failed: status {}",
            response.status
        )));
    }
    parse_archive_access(response.body.as_deref().unwrap_or_default())
}

fn parse_archive_access(body: &[u8]) -> Result<ArchiveAccess> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|_| Error::Network("mail details token failed: invalid response".into()))?;
    let info = value
        .get("161")
        .and_then(|value| match value {
            Value::Object(map) => Some(map),
            Value::Array(items) => items.first()?.as_object(),
            _ => None,
        })
        .ok_or_else(|| Error::Network("mail details token failed: missing info".into()))?;
    let token = info
        .get("159")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Network("mail details token failed: missing token".into()))?
        .to_string();
    let servers = info
        .get("160")
        .and_then(Value::as_array)
        .map(|servers| {
            servers
                .iter()
                .filter_map(|server| server.get("156").and_then(Value::as_str))
                .map(|url| url.trim_end_matches('/').to_string())
                .collect()
        })
        .unwrap_or_default();
    Ok(ArchiveAccess {
        blob_access_token: token,
        servers,
    })
}

/// Fetch a blob element (server-model JSON) from the blob server.
///
/// Blob elements use the archive read token in the query and the user session
/// token as `accessToken`; the type model version is `v=118` for
/// `MailDetailsBlob`.
pub async fn fetch_blob_element(
    rest: &dyn RestClient,
    server: &str,
    list_id: &str,
    element_id: &str,
    blob_token: &str,
    user_access_token: &str,
) -> Result<Vec<u8>> {
    validate_blob_server(server)?;
    let query = encode_query_params([
        ("accessToken".as_bytes(), user_access_token.as_bytes()),
        ("v".as_bytes(), "118".as_bytes()),
        ("ids".as_bytes(), element_id.as_bytes()),
        ("blobAccessToken".as_bytes(), blob_token.as_bytes()),
        ("cv".as_bytes(), CLIENT_VERSION.as_bytes()),
    ]);
    let url = format!(
        "{}/rest/tutanota/maildetailsblob/{}{}",
        server.trim_end_matches('/'),
        list_id,
        query
    );
    let options = RestClientOptions {
        headers: HashMap::from([("v".to_string(), "118".to_string())]),
        body: None,
        suspension_behavior: Some(SuspensionBehavior::Suspend),
    };
    let response = rest
        .request_binary(url, HttpMethod::GET, options)
        .await
        .map_err(|_| Error::Network("mail details download failed".into()))?;
    if response.status < 200 || response.status >= 300 {
        return Err(Error::Network("mail details download failed".into()));
    }
    Ok(response.body.unwrap_or_default())
}

/// Decrypt each chunk independently and concatenate the plaintext.
pub fn decrypt_chunks(key: &GenericAesKey, chunks: &[Vec<u8>]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for chunk in chunks {
        let decrypted = key
            .decrypt_data(chunk)
            .map_err(|_| Error::Message("attachment decrypt failed".into()))?;
        out.extend_from_slice(&decrypted);
    }
    Ok(out)
}

/// Check a decrypted attachment against the size its file declares.
///
/// `TutanotaFile.size` is the encrypted blob size (it includes the AES
/// version/IV/MAC overhead), so the plaintext can only be upper-bounded
/// by it, never compared for equality. A negative declared size is invalid
/// and rejected outright; cast to `usize` it would become a huge bound and
/// disable the check.
pub fn check_attachment_size(decrypted_len: usize, declared_size: i64) -> Result<()> {
    let error = || Error::Message("attachment size mismatch".into());
    let declared = usize::try_from(declared_size).map_err(|_| error())?;
    if decrypted_len > declared {
        return Err(error());
    }
    Ok(())
}

/// Resolve the session key used to decrypt an attachment's blobs.
async fn resolve_file_session_key(
    logged: &LoggedInSdk,
    file: &TutanotaFile,
) -> Result<GenericAesKey> {
    let parsed = logged
        .instance_mapper
        .serialize_entity(file.clone())
        .map_err(|_| Error::Message("attachment key unavailable".into()))?;
    let model = logged
        .type_model_provider
        .resolve_server_type_ref(&TutanotaFile::type_ref())
        .ok_or_else(|| Error::Message("attachment key unavailable".into()))?;
    let resolved = logged
        .mail_facade()
        .get_crypto_entity_client()
        .get_crypto_facade()
        .resolve_session_key(&parsed, &model)
        .await
        .map_err(|_| Error::Message("attachment key unavailable".into()))?
        .ok_or_else(|| Error::Message("attachment key unavailable".into()))?;
    Ok(resolved.session_key)
}

/// Load a single attachment: resolve its key, download its blobs, decrypt them,
/// and verify the concatenated size.
pub async fn load_attachment(
    logged: &LoggedInSdk,
    rest: &dyn RestClient,
    user_access_token: &str,
    base_url: &str,
    id: &IdTupleGenerated,
) -> Result<Attachment> {
    let file: TutanotaFile = logged
        .mail_facade()
        .get_crypto_entity_client()
        .load(id)
        .await
        .map_err(|_| Error::Message("attachment file load failed".into()))?;

    if !file_is_intact(&file) {
        return Err(Error::Message("attachment file corrupted".into()));
    }
    // Reject an invalid declared size before any blob is downloaded.
    check_attachment_size(0, file.size)?;

    if file.blobs.is_empty() {
        return Ok(Attachment {
            name: file.name,
            mime_type: file
                .mimeType
                .unwrap_or_else(|| "application/octet-stream".into()),
            data: Vec::new(),
            cid: file.cid,
        });
    }

    // Group blobs by archive, preserving their original order.
    let mut archive_order: Vec<GeneratedId> = Vec::new();
    let mut groups: HashMap<String, Vec<&Blob>> = HashMap::new();
    for blob in &file.blobs {
        let archive_key = blob.archiveId.to_string();
        if !groups.contains_key(&archive_key) {
            archive_order.push(blob.archiveId.clone());
        }
        groups.entry(archive_key).or_default().push(blob);
    }

    let key = resolve_file_session_key(logged, &file).await?;

    let mut ciphertext_chunks: Vec<Vec<u8>> = Vec::new();
    for archive_id in &archive_order {
        let access = request_instance_read_token(
            rest,
            base_url,
            user_access_token,
            archive_id.as_str(),
            id.list_id.as_str(),
            id.element_id.as_str(),
        )
        .await?;

        let server = access
            .servers
            .first()
            .cloned()
            .ok_or_else(|| Error::Message("attachment server missing".into()))?;
        validate_blob_server(&server)
            .map_err(|_| Error::Message("attachment server invalid".into()))?;
        let token = access.blob_access_token;

        let blobs = &groups[&archive_id.to_string()];
        let ids: Vec<String> = blobs.iter().map(|blob| blob.blobId.to_string()).collect();
        let body = blob_get_body(archive_id.as_str(), &ids)?;
        let url = blob_url(&server, &token, user_access_token, &body);
        let bytes = fetch_blob(rest, &url, user_access_token).await?;
        let parsed = parse_multiple_blobs(&bytes)?;
        for blob in blobs {
            let ciphertext = parsed
                .get(blob.blobId.as_str())
                .ok_or_else(|| Error::Message("attachment blob missing".into()))?;
            ciphertext_chunks.push(ciphertext.clone());
        }
    }

    let data = decrypt_chunks(&key, &ciphertext_chunks)?;
    check_attachment_size(data.len(), file.size)?;

    Ok(Attachment {
        name: file.name,
        mime_type: file
            .mimeType
            .unwrap_or_else(|| "application/octet-stream".into()),
        data,
        cid: file.cid,
    })
}
