use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use tutasdk::bindings::rest_client::RestClient;
use tutasdk::entities::generated::sys::CloseSessionServicePost;
use tutasdk::login::{CredentialType, Credentials};
use tutasdk::services::generated::sys::CloseSessionService;
use tutasdk::services::ExtraServiceParams;
use tutasdk::{CustomId, GeneratedId, IdTupleCustom, LoggedInSdk, Sdk};

use super::event_lookup::TutaEventLookup;
use super::event_stream::{
    event_url, is_event_group, model_versions, TutaEventStream, TUTA_CLIENT_VERSION,
};
use super::generated_id::timestamp_to_generated_id;
use super::json::session_id_from_access_token;
use super::mail_source::TutaMailSource;
use super::pre_session::TutaPreSession;
use crate::domain::{AccountInfo, Error, Result, StoredCredentials};
use crate::ports::event_stream::EventHandles;
use crate::ports::mail_source::MailSource;
use crate::ports::session::{NewSession, Session, SessionFactory, SessionRequest};

/// Factory that creates and resumes Tuta sessions.
pub struct TutaSessionFactory {
    pre: TutaPreSession,
    sdk: Sdk,
    rest: Arc<dyn RestClient>,
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

    async fn discard(&self, access_token: &str) -> Result<()> {
        self.pre.delete_session(access_token).await
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
        let mail = Arc::new(TutaMailSource::new(
            Arc::clone(&logged),
            Arc::clone(&self.rest),
            credentials.access_token.clone(),
            self.base_url.clone(),
        ));

        Ok(Box::new(TutaSession {
            logged,
            rest: Arc::clone(&self.rest),
            info,
            access_token: credentials.access_token.clone(),
            base_url: self.base_url.clone(),
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
    base_url: String,
    /// The mail source, shared with the IMAP backend by `serve`.
    mail: Arc<TutaMailSource>,
}

#[async_trait::async_trait]
impl Session for TutaSession {
    fn account(&self) -> AccountInfo {
        self.info.clone()
    }

    fn mail(&self) -> &dyn MailSource {
        self.mail.as_ref()
    }

    fn shared_mail(&self) -> Arc<dyn MailSource> {
        Arc::clone(&self.mail) as Arc<dyn MailSource>
    }

    fn event_groups(&self) -> Vec<String> {
        let user = self.logged.get_user();
        let mut seen: HashSet<&str> = HashSet::new();
        let mut groups = Vec::with_capacity(user.memberships.len() + 1);
        for membership in user
            .memberships
            .iter()
            // The TS client chains userGroup unconditionally and a user group is never type 2, so filtering it here is equivalent.
            .chain(std::iter::once(&user.userGroup))
        {
            if !is_event_group(membership.groupType) {
                continue;
            }
            let group = membership.group.0.as_str();
            if seen.insert(group) {
                groups.push(group.to_string());
            }
        }
        groups
    }

    async fn events(
        &self,
        last_batches: &HashMap<String, String>,
        now_ms: i64,
    ) -> Result<EventHandles> {
        let fallback = timestamp_to_generated_id(now_ms.saturating_sub(5_000).max(0));
        let groups: Vec<(String, String)> = self
            .event_groups()
            .into_iter()
            .map(|group| {
                let batch = last_batches
                    .get(&group)
                    .cloned()
                    .unwrap_or_else(|| fallback.clone());
                (group, batch)
            })
            .collect();
        let versions = model_versions(self.logged.type_model_provider.as_ref())
            .ok_or_else(|| Error::Config("event model versions unavailable".into()))?;
        let url = event_url(
            &self.base_url,
            &self.info.user_id,
            &self.access_token,
            &groups,
            &versions,
            TUTA_CLIENT_VERSION,
        )?;
        let stream = TutaEventStream::connect(&url).await?;
        Ok(EventHandles {
            stream: Box::new(stream),
            lookup: Arc::new(TutaEventLookup::new(Arc::clone(&self.logged))),
        })
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
