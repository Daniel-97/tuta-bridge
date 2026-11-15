use secrecy::SecretString;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tuta_bridge::adapters::tuta::pre_session::TutaPreSession;
use tuta_bridge::ports::session::SessionRequest;
use tutasdk::net::native_rest_client::NativeRestClient;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn make_request(totp_count: Arc<AtomicUsize>, approval_count: Arc<AtomicUsize>) -> SessionRequest {
    SessionRequest {
        mail_address: "test@example.com".to_string(),
        password: SecretString::new("password123".to_string().into()),
        totp: Arc::new(move || {
            totp_count.fetch_add(1, Ordering::SeqCst);
            Ok("123456".to_string())
        }),
        on_device_approval: Arc::new(move || {
            approval_count.fetch_add(1, Ordering::SeqCst);
        }),
    }
}

#[tokio::test]
async fn creates_session_with_totp() {
    let server = MockServer::start().await;

    // Salt response
    let salt_json = r#"{"421":"0","422":"AAECAwQFBgcICQoLDA0ODw==","2133":"1"}"#;
    Mock::given(method("GET"))
        .and(path("/rest/sys/saltservice"))
        .respond_with(ResponseTemplate::new(200).set_body_string(salt_json))
        .expect(1)
        .mount(&server)
        .await;

    // Session response with TOTP challenge
    let session_json = r#"{"1220":"0","1221":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","1222":[{"1188":"0","1189":"1","1247":{"1239":"x"}}],"1223":"userid"}"#;
    Mock::given(method("POST"))
        .and(path("/rest/sys/sessionservice"))
        .respond_with(ResponseTemplate::new(200).set_body_string(session_json))
        .expect(1)
        .mount(&server)
        .await;

    // Second factor POST
    Mock::given(method("POST"))
        .and(path("/rest/sys/secondfactorauthservice"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    // Second factor GET - not pending
    let pending_json = r#"{"1237":"0","1238":"0"}"#;
    Mock::given(method("GET"))
        .and(path("/rest/sys/secondfactorauthservice"))
        .respond_with(ResponseTemplate::new(200).set_body_string(pending_json))
        .expect(1)
        .mount(&server)
        .await;

    let rest = Arc::new(NativeRestClient::try_new().unwrap());
    let pre_session = TutaPreSession::new(rest, server.uri());
    let totp_count = Arc::new(AtomicUsize::new(0));
    let approval_count = Arc::new(AtomicUsize::new(0));
    let request = make_request(totp_count.clone(), approval_count.clone());

    let result = pre_session.create(request).await.unwrap();

    assert_eq!(result.user_id, "userid");
    assert_eq!(
        result.access_token,
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    );
    assert_eq!(result.encrypted_passphrase_key.len(), 81);
    assert_eq!(totp_count.load(Ordering::SeqCst), 1);
    assert_eq!(approval_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn rejects_bcrypt() {
    let server = MockServer::start().await;

    // Salt response with KDF version 0 (bcrypt)
    let salt_json = r#"{"421":"0","422":"AAECAwQFBgcICQoLDA0ODw==","2133":"0"}"#;
    Mock::given(method("GET"))
        .and(path("/rest/sys/saltservice"))
        .respond_with(ResponseTemplate::new(200).set_body_string(salt_json))
        .expect(1)
        .mount(&server)
        .await;

    let rest = Arc::new(NativeRestClient::try_new().unwrap());
    let pre_session = TutaPreSession::new(rest, server.uri());
    let totp_count = Arc::new(AtomicUsize::new(0));
    let approval_count = Arc::new(AtomicUsize::new(0));
    let request = make_request(totp_count.clone(), approval_count.clone());

    let result = pre_session.create(request).await;

    assert!(matches!(
        result,
        Err(tuta_bridge::domain::Error::BcryptUnsupported)
    ));
}

#[tokio::test]
async fn device_approval_polls_without_totp_prompt() {
    let server = MockServer::start().await;

    // Salt response
    let salt_json = r#"{"421":"0","422":"AAECAwQFBgcICQoLDA0ODw==","2133":"1"}"#;
    Mock::given(method("GET"))
        .and(path("/rest/sys/saltservice"))
        .respond_with(ResponseTemplate::new(200).set_body_string(salt_json))
        .expect(1)
        .mount(&server)
        .await;

    // Session response with Other challenge (device approval)
    let session_json = r#"{"1220":"0","1221":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","1222":[{"1188":"0","1189":"0","1247":{"1239":"x"}}],"1223":"userid"}"#;
    Mock::given(method("POST"))
        .and(path("/rest/sys/sessionservice"))
        .respond_with(ResponseTemplate::new(200).set_body_string(session_json))
        .expect(1)
        .mount(&server)
        .await;

    // Second factor GET - pending once, then not pending
    let pending_once = r#"{"1237":"0","1238":"1"}"#;
    let not_pending = r#"{"1237":"0","1238":"0"}"#;
    Mock::given(method("GET"))
        .and(path("/rest/sys/secondfactorauthservice"))
        .respond_with(ResponseTemplate::new(200).set_body_string(pending_once))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/sys/secondfactorauthservice"))
        .respond_with(ResponseTemplate::new(200).set_body_string(not_pending))
        .mount(&server)
        .await;

    let rest = Arc::new(NativeRestClient::try_new().unwrap());
    let pre_session = TutaPreSession::new(rest, server.uri());
    let totp_count = Arc::new(AtomicUsize::new(0));
    let approval_count = Arc::new(AtomicUsize::new(0));
    let request = make_request(totp_count.clone(), approval_count.clone());

    let result = pre_session.create(request).await.unwrap();

    assert_eq!(result.user_id, "userid");
    assert_eq!(
        result.access_token,
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    );
    assert_eq!(result.encrypted_passphrase_key.len(), 81);
    assert_eq!(totp_count.load(Ordering::SeqCst), 0);
    assert!(approval_count.load(Ordering::SeqCst) >= 1);
}
