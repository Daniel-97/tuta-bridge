use base64::Engine as _;
use crypto_primitives::aes::InitializationVector;
use crypto_primitives::key::GenericAesKey;
use tuta_bridge::adapters::tuta::blob::{
    blob_get_body, blob_url, check_attachment_size, decrypt_chunks, fetch_blob,
    parse_multiple_blobs, request_archive_read_token, request_instance_read_token,
    validate_blob_server,
};
use tutasdk::net::native_rest_client::NativeRestClient;
use tutasdk::util::BASE64_EXT;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[test]
fn builds_blob_get_json_and_url() {
    let body = blob_get_body("arch", &["b1".to_string()]).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["52"], "arch");
    assert!(v["110"].is_null());
    assert_eq!(v["193"][0]["146"], "b1");
    assert!(v["193"][0]["145"].is_string());

    let body = blob_get_body("arch", &["b1".to_string()]).unwrap();
    let url = blob_url("https://blob.example", "tok", "user-token", &body);
    assert!(url.starts_with("https://blob.example/rest/storage/blobservice?"));
    assert!(url.contains("blobAccessToken=tok"));
    assert!(url.contains("accessToken=user-token"));
    assert!(url.contains("v=13"));
    let trimmed = blob_url("https://blob.example/", "tok", "user", &body);
    assert!(trimmed.starts_with("https://blob.example/rest/storage/blobservice?"));
    assert!(!trimmed.contains("//rest"));
}

#[test]
fn parses_framed_multi_blob_response() {
    let id = [7u8; 9];
    let payload = b"cipher";
    let mut response = Vec::new();
    response.extend_from_slice(&1i32.to_be_bytes());
    response.extend_from_slice(&id);
    response.extend_from_slice(&[0u8; 6]);
    response.extend_from_slice(&(payload.len() as i32).to_be_bytes());
    response.extend_from_slice(payload);

    let parsed = parse_multiple_blobs(&response).unwrap();
    assert_eq!(
        parsed.get(&BASE64_EXT.encode(id)).map(Vec::as_slice),
        Some(payload.as_slice())
    );
}

#[test]
fn decrypts_concatenated_chunks() {
    let key = GenericAesKey::from_bytes(&[7u8; 32]).unwrap();
    let iv = InitializationVector::from_arr([1u8; 16]);
    let c1 = key.encrypt_data(b"hello ", iv.clone()).unwrap();
    let c2 = key.encrypt_data(b"world", iv).unwrap();
    assert_eq!(decrypt_chunks(&key, &[c1, c2]).unwrap(), b"hello world");
}

#[test]
fn blob_server_urls_are_https_or_loopback() {
    assert!(validate_blob_server("https://blob.tuta.com").is_ok());
    assert!(validate_blob_server("http://127.0.0.1:8080").is_ok());
    assert!(validate_blob_server("http://localhost:8080").is_ok());
    assert!(validate_blob_server("https://blob.tuta.com/path").is_err());
    assert!(validate_blob_server("https://user@blob.tuta.com").is_err());
    assert!(validate_blob_server("http://blob.tuta.com").is_err());
    assert!(validate_blob_server("ftp://blob.tuta.com").is_err());
}

#[tokio::test]
async fn fetches_binary_blob_with_access_token() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/storage/blobservice"))
        .and(header("accessToken", "user-token"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"cipher".to_vec()))
        .expect(1)
        .mount(&server)
        .await;

    let rest = NativeRestClient::try_new().unwrap();
    // The blob token stays in the query; the user session token goes in the header.
    let url = blob_url(&server.uri(), "blob-token", "user-token", b"{\"a\":1}");
    assert!(url.contains("blobAccessToken=blob-token"));
    assert!(url.contains("accessToken=user-token"));
    let data = fetch_blob(&rest, &url, "user-token").await.unwrap();
    assert_eq!(data, b"cipher");
}

#[tokio::test]
async fn token_errors_carry_the_status_but_never_the_response_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rest/storage/blobaccesstokenservice"))
        .respond_with(ResponseTemplate::new(400).set_body_string("SERVER-BODY a@b.c"))
        .expect(2)
        .mount(&server)
        .await;

    let rest = NativeRestClient::try_new().unwrap();
    let Err(archive) = request_archive_read_token(&rest, &server.uri(), "user-token", "arch").await
    else {
        panic!("expected an error")
    };
    assert_eq!(
        archive.to_string(),
        "network error: mail details token failed: status 400"
    );

    let Err(instance) =
        request_instance_read_token(&rest, &server.uri(), "user-token", "arch", "list", "elem")
            .await
    else {
        panic!("expected an error")
    };
    assert_eq!(
        instance.to_string(),
        "message error: attachment token failed: status 400"
    );
}

#[test]
fn attachment_size_is_bounded_by_the_declared_size() {
    assert!(check_attachment_size(0, 0).is_ok());
    assert!(check_attachment_size(10, 10).is_ok());
    assert!(check_attachment_size(10, 75).is_ok());
    assert!(check_attachment_size(11, 10).is_err());
}

#[test]
fn a_negative_declared_size_cannot_disable_the_check() {
    assert!(check_attachment_size(0, -1).is_err());
    assert!(check_attachment_size(10, -1).is_err());
    assert!(check_attachment_size(10, i64::MIN).is_err());
}
