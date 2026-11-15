use crypto_primitives::aes::InitializationVector;
use crypto_primitives::key::GenericAesKey;
use tuta_bridge::adapters::tuta::blob::{blob_get_body, blob_url, decrypt_chunks, fetch_blob};
use tutasdk::net::native_rest_client::NativeRestClient;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[test]
fn builds_blob_get_json_and_url() {
    let body = blob_get_body("arch", &["b1".into(), "b2".into()]).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["52"], "arch");
    assert_eq!(v["193"][0]["146"], "b1");
    assert!(v["110"].is_null());
    let url = blob_url("https://blob.example", "tok", b"{\"a\":1}");
    assert!(url.starts_with("https://blob.example/rest/storage/blobservice?"));
    assert!(url.contains("blobAccessToken=tok"));
    assert!(url.contains("v=16"));
}

#[test]
fn decrypts_concatenated_chunks() {
    let key = GenericAesKey::from_bytes(&[7u8; 32]).unwrap();
    let iv = InitializationVector::from_arr([1u8; 16]);
    let c1 = key.encrypt_data(b"hello ", iv.clone()).unwrap();
    let c2 = key.encrypt_data(b"world", iv).unwrap();
    assert_eq!(decrypt_chunks(&key, &[c1, c2]).unwrap(), b"hello world");
}

#[tokio::test]
async fn fetches_binary_blob_with_access_token() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/storage/blobservice"))
        .and(header("accessToken", "tok"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"cipher".to_vec()))
        .expect(1)
        .mount(&server)
        .await;

    let rest = NativeRestClient::try_new().unwrap();
    let url = blob_url(&server.uri(), "tok", b"{\"a\":1}");
    let data = fetch_blob(&rest, &url, "tok").await.unwrap();
    assert_eq!(data, b"cipher");
}
