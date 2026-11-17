//! Loopback-only integration tests for the Tuta event stream.
//!
//! A fake websocket server accepts one connection and replays scripted
//! frames; no real Tuta server is ever contacted and the access token in
//! the URL is a dummy value.

use futures_util::SinkExt;
use std::future::Future;
use tokio::net::TcpListener;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use tuta_bridge::adapters::tuta::event_stream::{event_url, TutaEventStream};
use tuta_bridge::domain::{EntityOperation, Error, EventFrame};
use tuta_bridge::ports::event_stream::EventStream;

type ServerSocket = WebSocketStream<tokio::net::TcpStream>;

/// A valid `entityUpdate` batch with one Mail creation and one
/// MailSetEntry deletion. The real server sends every `NumberString` field
/// as a JSON string, so this mirrors the actual wire shape.
const BATCH_JSON: &str = r#"{"1484":"0","1485":"batch1","1486":"group1","2557":"7","2558":"hash","1487":[{"463":"u1","464":"tutanota","466":"list1","467":"mail1","624":"0","2556":"97","2617":null,"2701":null,"2618":null},{"463":"u2","464":"tutanota","466":"list1","467":"entry1","624":"2","2556":"1450","2617":null,"2701":null,"2618":null}]}"#;

/// Start a loopback websocket server on a random port that runs `script`
/// on the first accepted connection, and return its base URL.
async fn loopback_server<F, Fut>(script: F) -> String
where
    F: FnOnce(ServerSocket) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let socket = accept_async(stream).await.unwrap();
        script(socket).await;
    });
    format!("http://{addr}")
}

/// Connect the stream to the loopback server with a dummy token and no
/// group markers.
async fn connect(url: &str) -> TutaEventStream {
    let url = event_url(url, "user1", "token", &[], "1.2", "3.4").unwrap();
    TutaEventStream::connect(&url).await.unwrap()
}

async fn send_batch_and_close(mut socket: ServerSocket) {
    socket
        .send(Message::Text(format!("entityUpdate;{BATCH_JSON}")))
        .await
        .unwrap();
    socket.close(None).await.unwrap();
}

async fn send_fatal_close(mut socket: ServerSocket) {
    socket
        .send(Message::Close(Some(CloseFrame {
            code: CloseCode::from(4403),
            reason: "".into(),
        })))
        .await
        .unwrap();
}

#[tokio::test]
async fn delivers_event_batches_from_the_server() {
    let base = loopback_server(send_batch_and_close).await;
    let mut stream = connect(&base).await;

    let EventFrame::Batch(batch) = stream.next_frame().await.unwrap() else {
        panic!("expected an event batch");
    };
    assert_eq!(batch.batch_id, "batch1");
    assert_eq!(batch.owner_group_id, "group1");
    assert_eq!(batch.events.len(), 2);
    assert_eq!(batch.events[0].type_id, 97);
    assert_eq!(batch.events[0].list_id, "list1");
    assert_eq!(batch.events[0].element_id, "mail1");
    assert_eq!(batch.events[0].operation, EntityOperation::Create);
    assert_eq!(batch.events[1].type_id, 1450);
    assert_eq!(batch.events[1].element_id, "entry1");
    assert_eq!(batch.events[1].operation, EntityOperation::Delete);

    // The server closes after the batch; the stream must report that close
    // as a reconnectable network error.
    assert!(matches!(stream.next_frame().await, Err(Error::Network(_))));
}

#[tokio::test]
async fn auth_close_code_maps_to_a_login_error() {
    let base = loopback_server(send_fatal_close).await;
    let mut stream = connect(&base).await;

    let Err(Error::Login(message)) = stream.next_frame().await else {
        panic!("expected a login error");
    };
    assert_eq!(message, "event stream not authorized; run login again");
}
