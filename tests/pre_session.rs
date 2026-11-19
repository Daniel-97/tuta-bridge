use secrecy::SecretString;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tuta_bridge::adapters::tuta::pre_session::TutaPreSession;
use tuta_bridge::domain::Error;
use tuta_bridge::ports::session::SessionRequest;
use tutasdk::net::native_rest_client::NativeRestClient;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SALT_JSON: &str = r#"{"421":"0","422":"AAECAwQFBgcICQoLDA0ODw==","2133":"1"}"#;
const SESSION_TOTP_JSON: &str = r#"{"1220":"0","1221":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","1222":[{"1188":"0","1189":"1","1247":{"1239":"x"}}],"1223":"userid"}"#;

fn make_request(totp_count: Arc<AtomicUsize>) -> SessionRequest {
    SessionRequest {
        mail_address: "test@example.com".to_string(),
        password: SecretString::new("password123".to_string().into()),
        totp: Arc::new(move || {
            totp_count.fetch_add(1, Ordering::SeqCst);
            Ok("123456".to_string())
        }),
    }
}

#[tokio::test]
async fn creates_session_with_totp() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/rest/sys/saltservice"))
        .and(header("v", "158"))
        .and(header("cv", tutasdk::CLIENT_VERSION))
        .respond_with(ResponseTemplate::new(200).set_body_string(SALT_JSON))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/rest/sys/sessionservice"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SESSION_TOTP_JSON))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/rest/sys/secondfactorauthservice"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/rest/sys/secondfactorauthservice"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"1237":"0","1238":"0"}"#))
        .expect(1)
        .mount(&server)
        .await;

    let rest = Arc::new(NativeRestClient::try_new().unwrap());
    let pre_session = TutaPreSession::new(rest, server.uri(), false);
    let totp_count = Arc::new(AtomicUsize::new(0));
    let request = make_request(totp_count.clone());

    let result = pre_session.create(request).await.unwrap();

    assert_eq!(result.user_id, "userid");
    assert_eq!(
        result.access_token,
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    );
    assert_eq!(result.encrypted_passphrase_key.len(), 81);
    assert_eq!(totp_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn rejects_bcrypt() {
    let server = MockServer::start().await;

    let salt_json = r#"{"421":"0","422":"AAECAwQFBgcICQoLDA0ODw==","2133":"0"}"#;
    Mock::given(method("GET"))
        .and(path("/rest/sys/saltservice"))
        .and(header("v", "158"))
        .and(header("cv", tutasdk::CLIENT_VERSION))
        .respond_with(ResponseTemplate::new(200).set_body_string(salt_json))
        .expect(1)
        .mount(&server)
        .await;

    let rest = Arc::new(NativeRestClient::try_new().unwrap());
    let pre_session = TutaPreSession::new(rest, server.uri(), false);
    let totp_count = Arc::new(AtomicUsize::new(0));
    let request = make_request(totp_count.clone());

    let result = pre_session.create(request).await;

    assert!(matches!(result, Err(Error::BcryptUnsupported)));
}

#[tokio::test]
async fn non_totp_challenge_is_unsupported() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/rest/sys/saltservice"))
        .and(header("v", "158"))
        .and(header("cv", tutasdk::CLIENT_VERSION))
        .respond_with(ResponseTemplate::new(200).set_body_string(SALT_JSON))
        .expect(1)
        .mount(&server)
        .await;

    // Session response with an "Other" (device approval) challenge type 0.
    let session_json = r#"{"1220":"0","1221":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","1222":[{"1188":"0","1189":"0","1247":{"1239":"x"}}],"1223":"userid"}"#;
    Mock::given(method("POST"))
        .and(path("/rest/sys/sessionservice"))
        .respond_with(ResponseTemplate::new(200).set_body_string(session_json))
        .expect(1)
        .mount(&server)
        .await;

    let rest = Arc::new(NativeRestClient::try_new().unwrap());
    let pre_session = TutaPreSession::new(rest, server.uri(), false);
    let totp_count = Arc::new(AtomicUsize::new(0));
    let request = make_request(totp_count.clone());

    let result = pre_session.create(request).await;

    assert!(matches!(result, Err(Error::Unsupported(_))));
    assert_eq!(totp_count.load(Ordering::SeqCst), 0);
    // The session that cannot be completed is cancelled, not left pending.
    let cancels = server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|request| request.method.as_str() == "DELETE")
        .count();
    assert_eq!(cancels, 1);
}

#[tokio::test]
async fn wrong_password_maps_to_login_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/rest/sys/saltservice"))
        .and(header("v", "158"))
        .and(header("cv", tutasdk::CLIENT_VERSION))
        .respond_with(ResponseTemplate::new(200).set_body_string(SALT_JSON))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/rest/sys/sessionservice"))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&server)
        .await;

    let rest = Arc::new(NativeRestClient::try_new().unwrap());
    let pre_session = TutaPreSession::new(rest, server.uri(), false);
    let totp_count = Arc::new(AtomicUsize::new(0));
    let request = make_request(totp_count.clone());

    let result = pre_session.create(request).await;

    assert!(matches!(result, Err(Error::Login(_))));
}

#[tokio::test]
async fn wrong_totp_maps_to_second_factor_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/rest/sys/saltservice"))
        .and(header("v", "158"))
        .and(header("cv", tutasdk::CLIENT_VERSION))
        .respond_with(ResponseTemplate::new(200).set_body_string(SALT_JSON))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/rest/sys/sessionservice"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SESSION_TOTP_JSON))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/rest/sys/secondfactorauthservice"))
        .respond_with(ResponseTemplate::new(403))
        .expect(1)
        .mount(&server)
        .await;

    // The pending session is cancelled, addressed by its session id.
    Mock::given(method("DELETE"))
        .and(path("/rest/sys/secondfactorauthservice"))
        .and(wiremock::matchers::body_json(serde_json::json!({
            "1756": "0",
            "1757": [["------------", "AVJ15h-g0HUcHZ9FVBx4BMiVQERVRwcQreN4bygvLaA"]],
        })))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let rest = Arc::new(NativeRestClient::try_new().unwrap());
    let pre_session = TutaPreSession::new(rest, server.uri(), false);
    let totp_count = Arc::new(AtomicUsize::new(0));
    let request = make_request(totp_count.clone());

    let result = pre_session.create(request).await;

    assert!(matches!(result, Err(Error::SecondFactor(_))));
    assert_eq!(totp_count.load(Ordering::SeqCst), 1);
}

/// An account with a security key and TOTP gets one challenge per type; the
/// TOTP one is enough to log in, whatever its position.
#[tokio::test]
async fn totp_is_used_when_offered_next_to_another_second_factor() {
    for challenges in [
        r#"[{"1188":"0","1189":"2","1247":[]},{"1188":"0","1189":"1","1247":[{"1239":"x"}]}]"#,
        r#"[{"1188":"0","1189":"1","1247":[{"1239":"x"}]},{"1188":"0","1189":"0","1247":[]}]"#,
    ] {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/rest/sys/saltservice"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SALT_JSON))
            .expect(1)
            .mount(&server)
            .await;

        let session_json = format!(
            r#"{{"1220":"0","1221":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","1222":{challenges},"1223":"userid"}}"#
        );
        Mock::given(method("POST"))
            .and(path("/rest/sys/sessionservice"))
            .respond_with(ResponseTemplate::new(200).set_body_string(session_json))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/rest/sys/secondfactorauthservice"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/rest/sys/secondfactorauthservice"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"1237":"0","1238":"0"}"#))
            .expect(1)
            .mount(&server)
            .await;

        let rest = Arc::new(NativeRestClient::try_new().unwrap());
        let pre_session = TutaPreSession::new(rest, server.uri(), false);
        let totp_count = Arc::new(AtomicUsize::new(0));

        let result = pre_session
            .create(make_request(totp_count.clone()))
            .await
            .unwrap();

        assert_eq!(result.user_id, "userid");
        assert_eq!(totp_count.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn delete_session_addresses_the_session_by_its_token() {
    let server = MockServer::start().await;
    let token = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    Mock::given(method("DELETE"))
        .and(path(
            "/rest/sys/session/------------/AVJ15h-g0HUcHZ9FVBx4BMiVQERVRwcQreN4bygvLaA",
        ))
        .and(header("accessToken", token))
        .and(header("v", "158"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let rest = Arc::new(NativeRestClient::try_new().unwrap());
    let pre_session = TutaPreSession::new(rest, server.uri(), false);
    pre_session.delete_session(token).await.unwrap();
}

#[tokio::test]
async fn delete_session_treats_an_unknown_session_as_deleted() {
    let token = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    for (status, deleted) in [(404, true), (401, true), (500, false)] {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .respond_with(ResponseTemplate::new(status))
            .mount(&server)
            .await;

        let rest = Arc::new(NativeRestClient::try_new().unwrap());
        let pre_session = TutaPreSession::new(rest, server.uri(), false);
        assert_eq!(pre_session.delete_session(token).await.is_ok(), deleted);
    }
}
