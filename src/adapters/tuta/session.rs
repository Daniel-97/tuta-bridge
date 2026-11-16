use std::sync::Arc;

use tutasdk::bindings::rest_client::RestClient;
use tutasdk::entities::generated::sys::CloseSessionServicePost;
use tutasdk::login::{CredentialType, Credentials};
use tutasdk::services::generated::sys::CloseSessionService;
use tutasdk::services::ExtraServiceParams;
use tutasdk::{CustomId, GeneratedId, IdTupleCustom, LoggedInSdk, Sdk};

use super::json::session_id_from_access_token;
use super::mail_source::TutaMailSource;
use super::pre_session::TutaPreSession;
use crate::domain::{AccountInfo, Error, Result, StoredCredentials};
use crate::ports::mail_source::MailSource;
use crate::ports::session::{NewSession, Session, SessionFactory, SessionRequest};

/// Factory that creates and resumes Tuta sessions.
pub struct TutaSessionFactory {
    pre: TutaPreSession,
    sdk: Sdk,
    rest: Arc<dyn RestClient>,
    // Retained for composition symmetry with the pre-session.
    #[allow(dead_code)]
    base_url: String,
}

impl TutaSessionFactory {
    pub fn new(sdk: Sdk, rest: Arc<dyn RestClient>, base_url: String, debug: bool) -> Self {
        let pre = TutaPreSession::new(Arc::clone(&rest), base_url.clone(), debug);
        Self {
            pre,
            sdk,
            rest,
            base_url,
        }
    }
}

#[async_trait::async_trait]
impl SessionFactory for TutaSessionFactory {
    async fn create(&self, request: SessionRequest) -> Result<NewSession> {
        self.pre.create(request).await
    }

    async fn resume(&self, credentials: &StoredCredentials) -> Result<Box<dyn Session>> {
        let creds = Credentials {
            login: credentials.login.clone(),
            user_id: GeneratedId(credentials.user_id.clone()),
            access_token: credentials.access_token.clone(),
            encrypted_passphrase_key: credentials.encrypted_passphrase_key.clone(),
            credential_type: CredentialType::Internal,
        };
        let logged = self
            .sdk
            .login(creds)
            .await
            .map_err(|_| Error::Login("session resume failed".into()))?;

        let info = AccountInfo {
            mail_address: credentials.login.clone(),
            user_id: credentials.user_id.clone(),
        };
        let mail = TutaMailSource::new(
            Arc::clone(&logged),
            Arc::clone(&self.rest),
            credentials.access_token.clone(),
            self.base_url.clone(),
        );

        Ok(Box::new(TutaSession {
            logged,
            rest: Arc::clone(&self.rest),
            info,
            access_token: credentials.access_token.clone(),
            mail,
        }))
    }
}

/// A resumed Tuta session.
pub struct TutaSession {
    logged: Arc<LoggedInSdk>,
    // Used by Task 12/13 for content and attachments.
    #[allow(dead_code)]
    rest: Arc<dyn RestClient>,
    info: AccountInfo,
    access_token: String,
    mail: TutaMailSource,
}

#[async_trait::async_trait]
impl Session for TutaSession {
    fn account(&self) -> AccountInfo {
        self.info.clone()
    }

    fn mail(&self) -> &dyn MailSource {
        &self.mail
    }

    async fn close(&self) -> Result<()> {
        let session_id = session_id_from_access_token(&self.access_token)?;
        let session_id = IdTupleCustom::new(
            GeneratedId(session_id.list_id),
            CustomId(session_id.element_id),
        );
        self.logged
            .get_service_executor()
            .post::<CloseSessionService>(
                CloseSessionServicePost {
                    _format: 0,
                    accessToken: self.access_token.clone(),
                    sessionId: session_id,
                },
                ExtraServiceParams::default(),
            )
            .await
            .map_err(|_| Error::Network("failed to close session".into()))
    }
}
