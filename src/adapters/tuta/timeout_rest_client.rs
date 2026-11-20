//! A deadline around every REST exchange.
//!
//! The SDK's native REST client has no timeout of its own: a connection that
//! stalls (suspend, NAT drop, an unresponsive server) leaves `login`, `sync`,
//! `dump`, or an IMAP `FETCH` waiting forever. [`TimeoutRestClient`] wraps any
//! [`RestClient`] and turns an exchange that does not finish in time into the
//! same `NetworkError` a dropped connection produces, so callers need no new
//! error path.
//!
//! The native client reads the whole response body inside `request_binary`,
//! so the deadline covers the complete exchange, download included. That is
//! why blob downloads get their own, much longer budget.

use std::sync::Arc;
use std::time::Duration;

use tutasdk::bindings::rest_client::{
    HttpMethod, RestClient, RestClientError, RestClientOptions, RestResponse,
};

/// Budget for one ordinary REST exchange (entities, services, tokens).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Budget for one blob-service download.
///
/// One request returns every blob of an attachment in a single response, so
/// it can carry tens of megabytes: ten minutes lets a 25 MiB attachment
/// through at roughly 0.35 Mbit/s.
pub const BLOB_TIMEOUT: Duration = Duration::from_secs(600);

/// Path of the blob service, whose downloads use [`BLOB_TIMEOUT`].
const BLOB_SERVICE_PATH: &str = "/rest/storage/blobservice";

/// A [`RestClient`] that bounds how long one exchange may take.
pub struct TimeoutRestClient {
    inner: Arc<dyn RestClient>,
    request_timeout: Duration,
    blob_timeout: Duration,
}

impl TimeoutRestClient {
    /// Wrap `inner` with the production budgets.
    pub fn new(inner: Arc<dyn RestClient>) -> Self {
        Self::with_timeouts(inner, REQUEST_TIMEOUT, BLOB_TIMEOUT)
    }

    /// Wrap `inner` with explicit budgets.
    pub fn with_timeouts(
        inner: Arc<dyn RestClient>,
        request_timeout: Duration,
        blob_timeout: Duration,
    ) -> Self {
        Self {
            inner,
            request_timeout,
            blob_timeout,
        }
    }

    /// The budget for `url`: the blob budget for blob-service downloads, the
    /// ordinary one for everything else. Only the path is inspected; the
    /// query (which carries tokens) is cut off first.
    fn timeout_for(&self, url: &str) -> Duration {
        let path = url.split(['?', '#']).next().unwrap_or(url);
        if path.ends_with(BLOB_SERVICE_PATH) {
            self.blob_timeout
        } else {
            self.request_timeout
        }
    }
}

#[async_trait::async_trait]
impl RestClient for TimeoutRestClient {
    async fn request_binary(
        &self,
        url: String,
        method: HttpMethod,
        options: RestClientOptions,
    ) -> Result<RestResponse, RestClientError> {
        let budget = self.timeout_for(&url);
        match tokio::time::timeout(budget, self.inner.request_binary(url, method, options)).await {
            Ok(result) => result,
            // Dropping the inner future abandons the exchange.
            Err(_) => Err(RestClientError::NetworkError),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    /// Answers 200 after `delay`.
    struct SlowRestClient {
        delay: Duration,
    }

    #[async_trait::async_trait]
    impl RestClient for SlowRestClient {
        async fn request_binary(
            &self,
            _url: String,
            _method: HttpMethod,
            _options: RestClientOptions,
        ) -> Result<RestResponse, RestClientError> {
            tokio::time::sleep(self.delay).await;
            Ok(RestResponse {
                status: 200,
                headers: HashMap::new(),
                body: None,
            })
        }
    }

    fn options() -> RestClientOptions {
        RestClientOptions {
            headers: HashMap::new(),
            body: None,
            suspension_behavior: None,
        }
    }

    fn client(delay_ms: u64, request_ms: u64, blob_ms: u64) -> TimeoutRestClient {
        TimeoutRestClient::with_timeouts(
            Arc::new(SlowRestClient {
                delay: Duration::from_millis(delay_ms),
            }),
            Duration::from_millis(request_ms),
            Duration::from_millis(blob_ms),
        )
    }

    #[tokio::test]
    async fn a_stalled_exchange_becomes_a_network_error() {
        let result = client(5_000, 20, 20)
            .request_binary(
                "https://app.tuta.com/rest/sys/saltservice?_body=x".into(),
                HttpMethod::GET,
                options(),
            )
            .await;
        assert!(matches!(result, Err(RestClientError::NetworkError)));
    }

    #[tokio::test]
    async fn an_exchange_within_budget_passes_through() {
        let response = client(1, 5_000, 5_000)
            .request_binary(
                "https://app.tuta.com/rest/sys/saltservice".into(),
                HttpMethod::GET,
                options(),
            )
            .await
            .unwrap();
        assert_eq!(response.status, 200);
    }

    #[tokio::test]
    async fn blob_downloads_get_the_longer_budget() {
        // 100 ms of work: over the ordinary budget, inside the blob one.
        let slow = client(100, 20, 5_000);
        let blob = slow
            .request_binary(
                "https://blob.tuta.com/rest/storage/blobservice?blobAccessToken=t".into(),
                HttpMethod::GET,
                options(),
            )
            .await;
        assert_eq!(blob.unwrap().status, 200);

        let other = slow
            .request_binary(
                "https://blob.tuta.com/rest/tutanota/maildetailsblob/list?x=/rest/storage/blobservice"
                    .into(),
                HttpMethod::GET,
                options(),
            )
            .await;
        assert!(matches!(other, Err(RestClientError::NetworkError)));
    }
}
