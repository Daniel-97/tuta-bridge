//! Tuta websocket event stream and event-bus helpers.
//!
//! The event-bus URL embeds the session access token as a query parameter.
//! Nothing in this module may ever log or derive that URL: `TutaEventStream`
//! deliberately has no `Debug` implementation, and every failure maps to a
//! fixed error message without echo of the URL or any account data.

use std::collections::HashSet;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tutasdk::entities::Entity;
use tutasdk::type_model_provider::TypeModelProvider;

use super::event_wire::parse_frame;
use crate::domain::{Error, EventFrame, Result};
use crate::ports::event_stream::EventStream;

/// Client version reported to the event bus.
///
/// Must match the version of the pinned Tuta SDK revision, otherwise the
/// server rejects the connection as an outdated client.
pub const TUTA_CLIENT_VERSION: &str = "369.261113.0";

/// How long the event bus may stay silent before the stream probes it.
///
/// A connection that dies without a FIN (suspend, NAT drop) never produces
/// a read error, so silence alone cannot be told from a quiet mailbox.
/// After this long without any frame the stream sends a ping; if another
/// full interval passes with still nothing — not even the pong — the
/// connection is declared dead. A half-open socket therefore surfaces
/// within two intervals.
pub const IDLE_PROBE_INTERVAL: Duration = Duration::from_secs(60);

/// Build the authenticated event-bus websocket URL.
///
/// `https://` bases become `wss://`, `http://` bases become `ws://`, and any
/// other prefix is rejected. Every query value is percent-encoded. Groups
/// keep their order; duplicate group ids are skipped. The group map is
/// omitted entirely when there are no groups.
pub fn event_url(
    base_url: &str,
    user_id: &str,
    access_token: &str,
    groups: &[(String, String)],
    model_versions: &str,
    client_version: &str,
) -> Result<String> {
    let ws_base = if let Some(rest) = base_url.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base_url.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        return Err(Error::Config("event URL requires http or https".into()));
    };

    let mut url = format!(
        "{ws_base}/event?\
         modelVersions={model_versions}&\
         clientVersion={client_version}&\
         userId={user_id}&\
         accessToken={access_token}&\
         clientName=tuta-bridge",
        model_versions = urlencoding::encode(model_versions),
        client_version = urlencoding::encode(client_version),
        user_id = urlencoding::encode(user_id),
        access_token = urlencoding::encode(access_token),
    );

    if groups.is_empty() {
        return Ok(url);
    }

    let mut seen = HashSet::with_capacity(groups.len());
    let mut group_map = String::new();
    for (group, batch) in groups {
        if !seen.insert(group.as_str()) {
            continue;
        }
        group_map.push_str(&urlencoding::encode(group));
        group_map.push('=');
        group_map.push_str(&urlencoding::encode(batch));
        group_map.push(';');
    }
    url.push_str("&groupsToLastEventBatchIds=");
    url.push_str(&group_map);
    Ok(url)
}

/// The `Sys.Tutanota` model versions the event bus handshake must report.
///
/// Returns `None` when either app model is missing; both are always present
/// in the SDK's pinned client models.
///
/// Takes the provider rather than the models themselves because the SDK does
/// not re-export `ApplicationModels` publicly; the provider's client models
/// are the same values the rest of the SDK uses.
pub fn model_versions(provider: &TypeModelProvider) -> Option<String> {
    let sys_app = tutasdk::entities::generated::sys::User::type_ref().app;
    let tutanota_app = tutasdk::entities::generated::tutanota::Mail::type_ref().app;
    let models = provider.client_app_models.as_ref();
    let sys = models.apps.get(&sys_app)?;
    let tutanota = models.apps.get(&tutanota_app)?;
    Some(format!("{}.{}", sys.version, tutanota.version))
}

/// Whether a membership group receives event-bus batches.
///
/// Only the mailing-list group type is excluded; it exists to broadcast
/// membership changes that the bridge does not track.
pub fn is_event_group(group_type: Option<i64>) -> bool {
    !matches!(group_type, Some(2))
}

/// Map a websocket close code to the error the processor must act on.
///
/// Authentication and session close codes are fatal for the session: the
/// caller must run login again. A rejected client version is fatal too,
/// but needs an SDK update instead of a login. Rate limiting and every
/// other close are reconnectable network errors. `None` is a close
/// without a code.
pub fn close_error(code: Option<u16>) -> Error {
    match code {
        Some(4403 | 4440 | 4470 | 4471 | 4472) => {
            Error::Login("event stream not authorized; run login again".into())
        }
        Some(4474) => Error::Unsupported(
            "event stream client version rejected; update the bridge SDK pin".into(),
        ),
        Some(4429) => Error::Network("event stream rate limited".into()),
        _ => Error::Network("event stream closed".into()),
    }
}

/// A connected Tuta event-bus websocket.
///
/// Deliberately not `Debug`: the URL that created this stream carries the
/// access token, which must never end up in logs or errors.
pub struct TutaEventStream {
    socket: WebSocketStream<MaybeTlsStream<TcpStream>>,
    /// Silence tolerated before a probe, and again before giving up.
    idle: Duration,
    /// A ping was sent and nothing has been received since.
    probing: bool,
}

impl TutaEventStream {
    /// Open the event-bus websocket.
    ///
    /// Failures — DNS, TLS, handshake rejection — map to one fixed network
    /// error that never includes the URL.
    pub async fn connect(url: &str) -> Result<Self> {
        Self::connect_with_idle(url, IDLE_PROBE_INTERVAL).await
    }

    /// [`Self::connect`] with an explicit idle-probe interval.
    pub async fn connect_with_idle(url: &str, idle: Duration) -> Result<Self> {
        let (socket, _response) = tokio_tungstenite::connect_async(url)
            .await
            .map_err(|_| Error::Network("event stream connect failed".into()))?;
        Ok(Self {
            socket,
            idle,
            probing: false,
        })
    }
}

#[async_trait::async_trait]
impl EventStream for TutaEventStream {
    async fn next_frame(&mut self) -> Result<EventFrame> {
        loop {
            let received = match tokio::time::timeout(self.idle, self.socket.next()).await {
                Ok(received) => received,
                // Silence. The first quiet interval sends a probe; a second
                // one without any frame means nobody is on the other end.
                Err(_) if self.probing => {
                    return Err(Error::Network("event stream timed out".into()));
                }
                Err(_) => {
                    self.socket
                        .send(Message::Ping(Vec::new()))
                        .await
                        .map_err(|_| Error::Network("event stream disconnected".into()))?;
                    self.probing = true;
                    continue;
                }
            };
            // Any frame at all — the pong included — proves the peer is alive.
            self.probing = false;
            let Some(message) = received else {
                return Err(close_error(None));
            };
            let message = match message {
                Ok(message) => message,
                Err(_) => return Err(Error::Network("event stream disconnected".into())),
            };
            match message {
                Message::Text(text) => return parse_frame(&text),
                Message::Ping(payload) => {
                    self.socket
                        .send(Message::Pong(payload))
                        .await
                        .map_err(|_| Error::Network("event stream disconnected".into()))?;
                }
                Message::Close(frame) => {
                    return Err(close_error(frame.map(|frame| u16::from(frame.code))));
                }
                // Binary payloads and stray pongs carry no event data.
                Message::Binary(_) | Message::Pong(_) | Message::Frame(_) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tutasdk::bindings::file_client::{FileClient, FileClientError};
    use tutasdk::bindings::rest_client::{
        HttpMethod, RestClient, RestClientError, RestClientOptions, RestResponse,
    };
    use tutasdk::type_model_provider::TypeModelProvider;

    use super::{close_error, event_url, is_event_group, model_versions};
    use crate::domain::Error;

    /// Test-only REST client: the type-model provider never calls it when
    /// only client models are read.
    struct NoopRestClient;

    #[async_trait::async_trait]
    impl RestClient for NoopRestClient {
        async fn request_binary(
            &self,
            _url: String,
            _method: HttpMethod,
            _options: RestClientOptions,
        ) -> std::result::Result<RestResponse, RestClientError> {
            Err(RestClientError::Unknown)
        }
    }

    /// Test-only file client: the type-model provider never calls it when
    /// only client models are read.
    struct NoopFileClient;

    #[async_trait::async_trait]
    impl FileClient for NoopFileClient {
        async fn persist_content(
            &self,
            _name: String,
            _content: Vec<u8>,
        ) -> std::result::Result<(), FileClientError> {
            Err(FileClientError::Unknown)
        }

        async fn read_content(
            &self,
            _name: String,
        ) -> std::result::Result<Vec<u8>, FileClientError> {
            Err(FileClientError::Unknown)
        }
    }

    /// Build a provider whose client app models carry the given versions.
    fn provider_with_model_versions(sys: &str, tutanota: &str) -> TypeModelProvider {
        let mut provider = TypeModelProvider::new(
            Arc::new(NoopRestClient),
            Arc::new(NoopFileClient),
            String::new(),
        );
        let models = provider.client_app_models.to_mut();
        for model in models.apps.values_mut() {
            match model.name.to_string().as_str() {
                "sys" => model.version = sys.to_string(),
                "tutanota" => model.version = tutanota.to_string(),
                _ => {}
            }
        }
        provider
    }

    #[test]
    fn builds_authenticated_event_url() {
        let url = event_url(
            "https://app.tuta.com",
            "user1",
            "a+b/c=",
            &[
                ("group1".into(), "batch1".into()),
                ("group2".into(), "batch2".into()),
            ],
            "158.118",
            "369.261113.0",
        )
        .unwrap();
        assert!(url.starts_with("wss://app.tuta.com/event?"));
        assert!(url.contains("modelVersions=158.118"));
        assert!(url.contains("clientVersion=369.261113.0"));
        assert!(url.contains("userId=user1"));
        assert!(url.contains("accessToken=a%2Bb%2Fc%3D"));
        assert!(url.contains("clientName=tuta-bridge"));
        assert!(url.contains("groupsToLastEventBatchIds=group1=batch1;group2=batch2;"));
    }

    #[test]
    fn loopback_uses_plain_websocket_and_omits_empty_groups() {
        let url = event_url("http://127.0.0.1:9000", "u", "t", &[], "1.2", "3.4").unwrap();
        assert!(url.starts_with("ws://127.0.0.1:9000/event?"));
        assert!(!url.contains("groupsToLastEventBatchIds"));
    }

    #[test]
    fn auth_and_session_close_codes_are_fatal() {
        assert!(matches!(close_error(Some(4403)), Error::Login(_)));
        assert!(matches!(close_error(Some(4440)), Error::Login(_)));
        assert!(matches!(close_error(Some(4470)), Error::Login(_)));
        assert!(matches!(close_error(None), Error::Network(_)));
    }

    #[test]
    fn rate_limit_and_unknown_close_codes_are_network_errors() {
        assert!(matches!(close_error(Some(4429)), Error::Network(_)));
        assert!(matches!(close_error(Some(4471)), Error::Login(_)));
        assert!(matches!(close_error(Some(4472)), Error::Login(_)));
        assert!(matches!(close_error(Some(1000)), Error::Network(_)));
    }

    #[test]
    fn rejected_client_version_is_fatal_unsupported() {
        match close_error(Some(4474)) {
            Error::Unsupported(message) => assert_eq!(
                message,
                "event stream client version rejected; update the bridge SDK pin"
            ),
            other => panic!("expected an unsupported error, got {other:?}"),
        }
    }

    #[test]
    fn model_versions_join_sys_and_tutanota() {
        let provider = provider_with_model_versions("158", "118");
        assert_eq!(model_versions(&provider).as_deref(), Some("158.118"));
    }

    #[test]
    fn model_versions_require_both_apps() {
        let mut provider = provider_with_model_versions("158", "118");
        let models = provider.client_app_models.to_mut();
        models
            .apps
            .retain(|_, model| model.name.to_string() != "tutanota");
        assert_eq!(model_versions(&provider), None);
    }

    #[test]
    fn is_event_group_skips_only_mailing_lists() {
        assert!(!is_event_group(Some(2)));
        assert!(is_event_group(None));
        assert!(is_event_group(Some(0)));
        assert!(is_event_group(Some(5)));
    }

    #[test]
    fn event_url_keeps_group_order_and_skips_duplicates() {
        let url = event_url(
            "https://app.tuta.com",
            "u",
            "t",
            &[
                ("group1".into(), "batch1".into()),
                ("group1".into(), "batch2".into()),
                ("group2".into(), "batch3".into()),
            ],
            "1.2",
            "3.4",
        )
        .unwrap();
        assert!(url.contains("groupsToLastEventBatchIds=group1=batch1;group2=batch3;"));
        assert!(!url.contains("batch2"));
    }

    #[test]
    fn event_url_rejects_non_http_prefixes() {
        let error = event_url("ftp://app.tuta.com", "u", "t", &[], "1.2", "3.4").unwrap_err();
        assert!(matches!(error, Error::Config(_)));
    }
}
