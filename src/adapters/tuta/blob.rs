//! Attachment download and decryption for Tuta mails.
//!
//! Tuta stores attachment contents as encrypted blobs grouped into archives.
//! [`load_attachment`] resolves the file's session key, requests one read
//! token per archive, fetches each blob over the blob service, decrypts the
//! concatenated chunks, and verifies the decrypted size. The pure helpers
//! (`blob_get_body`, `blob_url`, `decrypt_chunks`) are split out so they can be
//! unit-tested without a live session.

use std::collections::HashMap;

use crypto_primitives::key::GenericAesKey;
use serde_json::json;
use tutasdk::bindings::rest_client::{
    encode_query_params, HttpMethod, RestClient, RestClientOptions,
};
use tutasdk::bindings::suspendable_rest_client::SuspensionBehavior;
use tutasdk::entities::generated::storage::{BlobAccessTokenPostIn, BlobReadData, InstanceId};
use tutasdk::entities::generated::sys::Blob;
use tutasdk::entities::generated::tutanota::TutanotaFile;
use tutasdk::entities::Entity;
use tutasdk::services::generated::storage::BlobAccessTokenService;
use tutasdk::services::ExtraServiceParams;
use tutasdk::tutanota_constants::ArchiveDataType;
use tutasdk::{GeneratedId, IdTupleGenerated, LoggedInSdk, CLIENT_VERSION};

use super::content::file_is_intact;
use crate::domain::{Attachment, Error, Result};

/// Build the JSON body for a blob-service GET request over a single archive.
pub fn blob_get_body(archive_id: &str, blob_ids: &[String]) -> Result<Vec<u8>> {
    let blob_entries: Vec<serde_json::Value> = blob_ids
        .iter()
        .map(|id| json!({ "145": "0", "146": id }))
        .collect();
    let value = json!({
        "51": "0",
        "52": archive_id,
        "110": null,
        "193": blob_entries,
    });
    serde_json::to_vec(&value).map_err(|_| Error::Message("attachment body build failed".into()))
}

/// Build the full URL for fetching a blob from a blob server.
pub fn blob_url(server: &str, token: &str, body: &[u8]) -> String {
    let server = server.trim_end_matches('/');
    let query = encode_query_params([
        ("blobAccessToken".as_bytes(), token.as_bytes()),
        ("v".as_bytes(), "16".as_bytes()),
        ("_body".as_bytes(), body),
    ]);
    format!("{}/rest/storage/blobservice{}", server, query)
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
        return Err(Error::Network("blob download failed".into()));
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
    id: &IdTupleGenerated,
) -> Result<Attachment> {
    let file: TutanotaFile = logged
        .mail_facade()
        .get_crypto_entity_client()
        .load(id)
        .await
        .map_err(|_| Error::Message("attachment load failed".into()))?;

    if !file_is_intact(&file) {
        return Err(Error::Message("attachment load failed".into()));
    }

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
        let access = logged
            .get_service_executor()
            .post::<BlobAccessTokenService>(
                BlobAccessTokenPostIn {
                    _format: 0,
                    archiveDataType: Some(ArchiveDataType::Attachments.discriminant()),
                    write: None,
                    read: Some(BlobReadData {
                        _id: None,
                        archiveId: archive_id.clone(),
                        instanceListId: Some(id.list_id.clone()),
                        instanceIds: vec![InstanceId {
                            _id: None,
                            instanceId: Some(id.element_id.clone()),
                        }],
                    }),
                },
                ExtraServiceParams::default(),
            )
            .await
            .map_err(|_| Error::Message("attachment load failed".into()))?;

        let server = access
            .blobAccessInfo
            .servers
            .first()
            .map(|s| s.url.clone())
            .ok_or_else(|| Error::Message("attachment load failed".into()))?;
        let token = access.blobAccessInfo.blobAccessToken.clone();

        for blob in &groups[&archive_id.to_string()] {
            let body = blob_get_body(archive_id.as_str(), &[blob.blobId.to_string()])?;
            let url = blob_url(&server, &token, &body);
            let chunk = fetch_blob(rest, &url, user_access_token).await?;
            ciphertext_chunks.push(chunk);
        }
    }

    let data = decrypt_chunks(&key, &ciphertext_chunks)?;
    if data.len() != file.size as usize {
        return Err(Error::Message("attachment size mismatch".into()));
    }

    Ok(Attachment {
        name: file.name,
        mime_type: file
            .mimeType
            .unwrap_or_else(|| "application/octet-stream".into()),
        data,
        cid: file.cid,
    })
}
