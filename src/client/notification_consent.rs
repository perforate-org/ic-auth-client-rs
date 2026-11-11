//! Whether Internet Identity may send notifications to this application.
//!
//! Port of upstream `src/client/notification-consent.ts` (v11.1). Consent is
//! asked of the signer over the ICRC-25 channel and recorded at the canister;
//! the client forwards both.
//!
//! Three pieces live here, mirroring upstream:
//!
//! - [`request_notification_consent`] --- the free function that asks the
//!   signer (a ceremony) and maps its refusals;
//! - [`NotificationConsent`] --- the canister-backed service object that reads
//!   and withdraws what was recorded, signed as the session;
//! - the inline Candid IDL of the two canister methods, behind
//!   [`NotificationConsentService`] so a test can answer without a replica.

use std::sync::Arc;

use async_trait::async_trait;
use candid::{CandidType, Deserialize};
use ic_agent::Agent;
use ic_agent::export::Principal;
use ic_agent::identity::DelegatedIdentity;

use crate::client::error::AuthClientError;
use crate::client::options::NotificationConsentStatus;
use crate::client::platform::PlatformBounds;
use crate::client::transport::SignerError;
use crate::delegation_chain::DelegationChain;
use crate::signer::Signer;

/// The method Internet Identity answers with the user's decision about being
/// notified.
///
/// Named for its provider because a JSON-RPC method travels over a transport
/// shared with other signers, unlike a canister method.
///
/// Upstream `notification-consent.ts:15`. The name is owned by the signer layer
/// and re-exported here so callers see both halves of the feature in one place.
pub const NOTIFICATION_CONSENT_METHOD: &str = crate::signer::NOTIFICATION_CONSENT_METHOD;

/// The code Internet Identity denies a `prompt: 'none'` request with.
///
/// Upstream `notification-consent.ts:18`.
pub const INTERACTION_REQUIRED_CODE: i64 = 3002;

/// JSON-RPC's own code for a method the receiver does not implement.
///
/// Upstream `notification-consent.ts:21`.
pub const METHOD_NOT_FOUND_CODE: i64 = -32601;

/// The canister method that reports this application's notification consent.
///
/// Upstream `notification-consent.ts:114-118`.
pub(crate) const II_NOTIFICATION_CONSENT_STATUS_METHOD: &str = "app_notification_consent_status";

/// The canister method that withdraws this application's notification consent.
///
/// Upstream `notification-consent.ts:119-123`.
pub(crate) const II_NOTIFICATION_CONSENT_REVOKE_METHOD: &str = "app_revoke_notification_consent";

/// What the canister answers a consent call with on failure.
///
/// Upstream `NotificationConsentError` (`notification-consent.ts:94`).
#[derive(CandidType, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ConsentError {
    /// The session this call signs with does not exist at the canister.
    NoSuchSession,
    /// The canister failed to read or write, with its own explanation.
    InternalCanisterError(String),
}

/// What the canister records about consent.
///
/// Upstream `Status` (`notification-consent.ts:112`).
#[derive(CandidType, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsentStatus {
    /// Whether consent is granted.
    pub is_granted: bool,
}

/// What `app_notification_consent_status` answers.
///
/// Upstream `Result<{ is_granted: boolean }>` (`notification-consent.ts:99,112-118`).
#[derive(CandidType, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ConsentStatusResult {
    /// The consent that is recorded.
    Ok(ConsentStatus),
    /// Why it could not be read.
    Err(ConsentError),
}

/// What `app_revoke_notification_consent` answers.
///
/// Upstream `Result<null>` (`notification-consent.ts:100,119-123`).
#[derive(CandidType, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ConsentRevokeResult {
    /// The consent is withdrawn (which it is whether or not it was granted).
    Ok(()),
    /// Why it could not be withdrawn.
    Err(ConsentError),
}

/// Asks the user, through the identity provider, whether this application may
/// notify them.
///
/// Port of upstream `requestNotificationConsent` (`notification-consent.ts:63-91`).
///
/// A refusal is an answer: it comes back as `granted: false` rather than as an
/// error, because the user decided and the application has something to render.
///
/// # Errors
///
/// - [`AuthClientError::NotificationsUnsupported`] where the provider does not
///   send notifications at all (`-32601`);
/// - [`AuthClientError::InteractionRequired`] where the request asked not to
///   render (`3002`, `prompt: 'none'`);
/// - [`AuthClientError::Other`] carrying the provider's own message for any
///   other JSON-RPC refusal;
/// - [`AuthClientError::Signer`] for a failure before a refusal (a transport or
///   protocol failure).
pub async fn request_notification_consent(
    signer: &Signer,
    derivation_origin: Option<&str>,
) -> Result<NotificationConsentStatus, AuthClientError> {
    signer
        .request_notification_consent(derivation_origin)
        .await
        .map_err(map_signer_error)
}

/// Turns the signer's failure into the client's error, per upstream's
/// `notification-consent.ts:76-84`.
fn map_signer_error(error: SignerError) -> AuthClientError {
    match error {
        SignerError::Refused {
            code,
            message,
            data: _,
        } => match code {
            METHOD_NOT_FOUND_CODE => AuthClientError::NotificationsUnsupported,
            // Upstream carries `response.error.message` as the interaction
            // reason (`notification-consent.ts:80-82`).
            INTERACTION_REQUIRED_CODE => AuthClientError::InteractionRequired {
                reason: Some(message),
            },
            // Anything else is the provider's message, as-is.
            _ => AuthClientError::Other(message),
        },
        other => AuthClientError::Signer(other),
    }
}

/// The two Internet Identity methods an application makes about its own
/// consent.
///
/// Port of upstream `NotificationConsentService` (`notification-consent.ts:98-101`).
/// Behind a trait so that a test can answer without a replica.
#[async_trait(?Send)]
pub trait NotificationConsentService: PlatformBounds {
    /// Reads the consent recorded for the caller's session. A query.
    async fn app_notification_consent_status(&self)
    -> Result<ConsentStatusResult, AuthClientError>;

    /// Withdraws the consent recorded for the caller's session. An update.
    async fn app_revoke_notification_consent(&self)
    -> Result<ConsentRevokeResult, AuthClientError>;
}

/// An [`NotificationConsentService`] behind an `Arc`.
pub type SharedNotificationConsentService = Arc<dyn NotificationConsentService>;

/// The canister-backed [`NotificationConsentService`]: the calls are signed as
/// the session, which is what Internet Identity authorises them by.
struct CanisterNotificationConsentService {
    agent: Agent,
    canister_id: Principal,
}

#[async_trait(?Send)]
impl NotificationConsentService for CanisterNotificationConsentService {
    async fn app_notification_consent_status(
        &self,
    ) -> Result<ConsentStatusResult, AuthClientError> {
        let reply = self
            .agent
            .query(&self.canister_id, II_NOTIFICATION_CONSENT_STATUS_METHOD)
            .call()
            .await
            .map_err(|error| AuthClientError::Agent(error.to_string()))?;
        candid::decode_one(&reply).map_err(|error| {
            AuthClientError::Agent(format!(
                "Internet Identity answered {II_NOTIFICATION_CONSENT_STATUS_METHOD} with something that is not a notification-consent result: {error}"
            ))
        })
    }

    async fn app_revoke_notification_consent(
        &self,
    ) -> Result<ConsentRevokeResult, AuthClientError> {
        let reply = self
            .agent
            .update(&self.canister_id, II_NOTIFICATION_CONSENT_REVOKE_METHOD)
            .call_and_wait()
            .await
            .map_err(|error| AuthClientError::Agent(error.to_string()))?;
        candid::decode_one(&reply).map_err(|error| {
            AuthClientError::Agent(format!(
                "Internet Identity answered {II_NOTIFICATION_CONSENT_REVOKE_METHOD} with something that is not a notification-consent result: {error}"
            ))
        })
    }
}

/// What a [`NotificationConsent`] call-specific failure prefix reports.
///
/// Upstream `notification-consent.ts:131-138`.
const STATUS_FAILED: &str = "Internet Identity could not report this notification consent";

/// What a [`NotificationConsent::revoke`] failure prefix reports.
const REVOKE_FAILED: &str = "Internet Identity could not withdraw this notification consent";

/// Turns a canister failure into the client's error: the one terminal error
/// becomes [`AuthClientError::SessionGone`], the other a plain failure carrying
/// the canister's own explanation.
///
/// Upstream `unwrap` (`notification-consent.ts:131-138`).
fn consent_error(failed: &str, error: ConsentError) -> AuthClientError {
    match error {
        ConsentError::NoSuchSession => AuthClientError::SessionGone,
        // A candid variant, so interpolating it directly would throw the
        // canister's own explanation away.
        ConsentError::InternalCanisterError(detail) => {
            if detail.is_empty() {
                AuthClientError::Other(failed.to_string())
            } else {
                AuthClientError::Other(format!("{failed}: {detail}"))
            }
        }
    }
}

/// Unwraps a status answer.
fn unwrap_consent_status(
    result: ConsentStatusResult,
) -> Result<NotificationConsentStatus, AuthClientError> {
    match result {
        ConsentStatusResult::Ok(status) => Ok(NotificationConsentStatus {
            granted: status.is_granted,
        }),
        ConsentStatusResult::Err(error) => Err(consent_error(STATUS_FAILED, error)),
    }
}

/// Unwraps a revoke answer.
fn unwrap_consent_revoke(result: ConsentRevokeResult) -> Result<(), AuthClientError> {
    match result {
        ConsentRevokeResult::Ok(()) => Ok(()),
        ConsentRevokeResult::Err(error) => Err(consent_error(REVOKE_FAILED, error)),
    }
}

/// Refuses a chain that is not a session for `canister_id`.
///
/// Port of `assertChainReaches` (`session/session-minter.ts:249-277`). Targets
/// restrict what the chain's final key may call, and the effective restriction
/// is the intersection of the hops that name any: what is refused is a chain no
/// hop restricts, one that names nothing, and one whose restrictions do not
/// come out as this canister alone.
fn assert_chain_reaches(
    chain: &DelegationChain,
    canister_id: Principal,
) -> Result<(), AuthClientError> {
    let restricting: Vec<&Vec<Principal>> = chain
        .delegations
        .iter()
        .filter_map(|hop| hop.delegation.targets.as_ref())
        .collect();

    let failure = |what: String| {
        AuthClientError::Other(format!(
            "A session chain must be restricted to {}, but {what}",
            canister_id.to_text()
        ))
    };

    if restricting.is_empty() {
        return Err(failure("no hop of this one names any canister".to_string()));
    }
    if restricting.iter().any(|targets| targets.is_empty()) {
        return Err(failure("a hop of this one names nothing".to_string()));
    }
    let mut elsewhere: Vec<String> = Vec::new();
    for targets in restricting {
        for target in targets {
            if *target != canister_id {
                let text = target.to_text();
                if !elsewhere.contains(&text) {
                    elsewhere.push(text);
                }
            }
        }
    }
    if !elsewhere.is_empty() {
        return Err(failure(format!(
            "this one also names {}",
            elsewhere.join(", ")
        )));
    }
    Ok(())
}

/// The options a [`NotificationConsent`] is built from.
///
/// Port of upstream `NotificationConsentOptions` (`notification-consent.ts:140-155`),
/// with the agent options reduced to a host, as elsewhere in this crate.
#[derive(Clone)]
pub struct NotificationConsentOptions {
    /// The key the session chain delegates to. Signs the calls made here.
    pub session_key: Arc<dyn ic_agent::identity::Identity>,

    /// The chain proving those calls come from the session. Restricted to the
    /// Internet Identity canister.
    pub session_chain: DelegationChain,

    /// The canister these calls go to.
    pub canister_id: Principal,

    /// The IC host the agent talks to.
    pub host: String,
}

impl std::fmt::Debug for NotificationConsentOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NotificationConsentOptions")
            .field("canister_id", &self.canister_id)
            .field("host", &self.host)
            .field("session_chain", &self.session_chain)
            .finish_non_exhaustive()
    }
}

/// Reads and withdraws an application's consent, at the Internet Identity
/// canister.
///
/// Port of upstream `NotificationConsent` (`notification-consent.ts:158-214`).
pub struct NotificationConsent {
    service: SharedNotificationConsentService,
}

impl std::fmt::Debug for NotificationConsent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NotificationConsent")
            .finish_non_exhaustive()
    }
}

impl NotificationConsent {
    /// Builds the calls as the session.
    ///
    /// Port of upstream `NotificationConsent.create` (`notification-consent.ts:172-183`):
    /// the chain must be restricted to this canister, and the agent signs as the
    /// session rather than as the application --- Internet Identity authorises
    /// both methods by the principal the session signs with.
    ///
    /// # Errors
    ///
    /// - [`AuthClientError::Other`] when the chain is not a session for
    ///   `canister_id` (upstream's `assertChainReaches`);
    /// - [`AuthClientError::Agent`] when the agent cannot be built.
    pub async fn create(options: NotificationConsentOptions) -> Result<Self, AuthClientError> {
        assert_chain_reaches(&options.session_chain, options.canister_id)?;
        // Upstream's `DelegationIdentity.fromDelegation` attaches the chain
        // without re-verifying it; the replica is what checks it.
        let identity = DelegatedIdentity::new_unchecked(
            options.session_chain.public_key.clone(),
            Box::new(options.session_key),
            options.session_chain.delegations.clone(),
        );
        // `AgentBuilder::with_url` unwraps its own parse, so a host that is
        // not a URL would panic; refuse it as an error instead.
        url::Url::parse(&options.host).map_err(|error| {
            AuthClientError::Agent(format!("the IC host is not a URL: {error}"))
        })?;
        let agent = Agent::builder()
            .with_url(options.host)
            .with_boxed_identity(Box::new(identity))
            .build()
            .map_err(|error| AuthClientError::Agent(error.to_string()))?;
        Ok(Self {
            service: Arc::new(CanisterNotificationConsentService {
                agent,
                canister_id: options.canister_id,
            }),
        })
    }

    /// Builds the service object over an existing service, which is how a test
    /// answers without a replica.
    #[cfg(test)]
    pub(crate) fn from_service(service: SharedNotificationConsentService) -> Self {
        Self { service }
    }

    /// Whether this application may notify the signed-in user.
    ///
    /// A query, so the answer is uncertified: it is what a control is painted
    /// from, not something to rest a decision on.
    ///
    /// Port of upstream `status` (`notification-consent.ts:191-197`).
    ///
    /// # Errors
    ///
    /// [`AuthClientError::SessionGone`] when the canister no longer knows the
    /// session; [`AuthClientError::Other`] when the canister fails and
    /// [`AuthClientError::Agent`] when the call itself fails.
    pub async fn status(&self) -> Result<NotificationConsentStatus, AuthClientError> {
        unwrap_consent_status(self.service.app_notification_consent_status().await?)
    }

    /// Withdraws this application's consent to notify the signed-in user.
    ///
    /// Idempotent at the canister: consent that is already withdrawn is `Ok`.
    ///
    /// Port of upstream `revoke` (`notification-consent.ts:199-213`).
    ///
    /// # Errors
    ///
    /// [`AuthClientError::SessionGone`] when the canister no longer knows the
    /// session; [`AuthClientError::Other`] when the write fails, which is
    /// raised rather than dropped --- an application that told a user it had
    /// turned notifications off should be able to find out that it had not.
    pub async fn revoke(&self) -> Result<(), AuthClientError> {
        unwrap_consent_revoke(self.service.app_revoke_notification_consent().await?)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use futures::executor::block_on;
    use ic_agent::identity::{Delegation, SignedDelegation};
    use serde_json::json;

    use super::*;
    use crate::client::error::AuthClientErrorKind;
    use crate::signer::test_utils::FakeTransport;
    use crate::signer::{Signer, SignerOptions};

    fn signer(transport: &FakeTransport) -> Signer {
        Signer::new(SignerOptions {
            transport: transport.shared(),
            derivation_origin: None,
        })
    }

    #[test]
    fn sends_the_provider_method_and_reports_what_it_granted() {
        block_on(async {
            let transport = FakeTransport::new();
            transport.on_result(NOTIFICATION_CONSENT_METHOD, json!({ "granted": true }));
            let signer = signer(&transport);

            let status = request_notification_consent(&signer, None).await.unwrap();

            assert_eq!(status, NotificationConsentStatus { granted: true });
            assert_eq!(
                transport.methods(),
                vec![NOTIFICATION_CONSENT_METHOD.to_string()]
            );
            assert_eq!(transport.requests().len(), 1);
        });
    }

    #[test]
    fn sends_an_empty_params_object_where_the_application_has_no_derivation_origin() {
        block_on(async {
            let transport = FakeTransport::new();
            transport.on_result(NOTIFICATION_CONSENT_METHOD, json!({ "granted": true }));
            let signer = signer(&transport);

            request_notification_consent(&signer, None).await.unwrap();

            assert_eq!(transport.last_request().unwrap().params, Some(json!({})));
        });
    }

    #[test]
    fn passes_the_derivation_origin_the_application_signs_in_under() {
        block_on(async {
            let transport = FakeTransport::new();
            transport.on_result(NOTIFICATION_CONSENT_METHOD, json!({ "granted": true }));
            let signer = signer(&transport);

            request_notification_consent(&signer, Some("https://app.example.com"))
                .await
                .unwrap();

            assert_eq!(
                transport.last_request().unwrap().params,
                Some(json!({ "icrc95DerivationOrigin": "https://app.example.com" }))
            );
        });
    }

    #[test]
    fn reports_a_refusal_as_an_answer_rather_than_a_failure() {
        block_on(async {
            let transport = FakeTransport::new();
            transport.on_result(NOTIFICATION_CONSENT_METHOD, json!({ "granted": false }));
            let signer = signer(&transport);

            let status = request_notification_consent(&signer, None).await.unwrap();

            assert_eq!(status, NotificationConsentStatus { granted: false });
        });
    }

    #[test]
    fn names_a_provider_that_does_not_notify_at_all() {
        block_on(async {
            let transport = FakeTransport::new();
            transport.on_error(
                NOTIFICATION_CONSENT_METHOD,
                METHOD_NOT_FOUND_CODE,
                "This Internet Identity does not send notifications",
                None,
            );
            let signer = signer(&transport);

            let error = request_notification_consent(&signer, None)
                .await
                .unwrap_err();

            assert_eq!(error.kind(), AuthClientErrorKind::NotificationsUnsupported);
        });
    }

    #[test]
    fn names_a_request_that_asked_not_to_render() {
        block_on(async {
            let transport = FakeTransport::new();
            transport.on_error(
                NOTIFICATION_CONSENT_METHOD,
                INTERACTION_REQUIRED_CODE,
                "Interaction required",
                None,
            );
            let signer = signer(&transport);

            let error = request_notification_consent(&signer, None)
                .await
                .unwrap_err();

            assert_eq!(error.kind(), AuthClientErrorKind::InteractionRequired);
            assert_eq!(
                error.to_string(),
                "interaction required: Interaction required"
            );
        });
    }

    #[test]
    fn passes_any_other_error_through_as_its_message() {
        block_on(async {
            let transport = FakeTransport::new();
            transport.on_error(NOTIFICATION_CONSENT_METHOD, -32602, "bad params", None);
            let signer = signer(&transport);

            let error = request_notification_consent(&signer, None)
                .await
                .unwrap_err();

            assert_eq!(error.kind(), AuthClientErrorKind::Other);
            assert_eq!(error.to_string(), "bad params");
        });
    }

    #[test]
    fn propagates_a_failure_before_a_refusal_as_a_signer_error() {
        let error = map_signer_error(SignerError::Timeout);
        assert_eq!(error.kind(), AuthClientErrorKind::Signer);
    }

    #[test]
    fn maps_the_two_refusal_codes_to_their_own_kinds() {
        let unsupported = map_signer_error(SignerError::Refused {
            code: METHOD_NOT_FOUND_CODE,
            message: "nope".to_string(),
            data: None,
        });
        assert_eq!(
            unsupported.kind(),
            AuthClientErrorKind::NotificationsUnsupported
        );

        let interaction = map_signer_error(SignerError::Refused {
            code: INTERACTION_REQUIRED_CODE,
            message: "Interaction required".to_string(),
            data: Some(json!({ "reason": "from data" })),
        });
        assert!(matches!(
            interaction,
            AuthClientError::InteractionRequired { reason: Some(reason) }
                if reason == "Interaction required"
        ));
    }

    // --- the canister result shapes ---------------------------------------

    #[test]
    fn candid_idl_mirrors_upstream() {
        let status_type = <ConsentStatusResult as CandidType>::ty().to_string();
        assert!(
            status_type.contains("Ok : record { is_granted : bool }"),
            "{status_type}"
        );
        assert!(status_type.contains("NoSuchSession"), "{status_type}");
        assert!(
            status_type.contains("InternalCanisterError : text"),
            "{status_type}"
        );

        // `Ok` carries `null`, which candid renders as a nullary variant field.
        let revoke_type = <ConsentRevokeResult as CandidType>::ty().to_string();
        assert!(revoke_type.contains("Ok"), "{revoke_type}");
        assert!(revoke_type.contains("Err : variant"), "{revoke_type}");
        assert!(
            revoke_type.contains("InternalCanisterError : text"),
            "{revoke_type}"
        );

        let bytes = candid::encode_one(ConsentStatusResult::Ok(ConsentStatus { is_granted: true }))
            .unwrap();
        let decoded: ConsentStatusResult = candid::decode_one(&bytes).unwrap();
        assert_eq!(
            decoded,
            ConsentStatusResult::Ok(ConsentStatus { is_granted: true })
        );

        let bytes = candid::encode_one(ConsentRevokeResult::Ok(())).unwrap();
        let decoded: ConsentRevokeResult = candid::decode_one(&bytes).unwrap();
        assert_eq!(decoded, ConsentRevokeResult::Ok(()));

        let bytes =
            candid::encode_one(ConsentStatusResult::Err(ConsentError::NoSuchSession)).unwrap();
        let decoded: ConsentStatusResult = candid::decode_one(&bytes).unwrap();
        assert_eq!(
            decoded,
            ConsentStatusResult::Err(ConsentError::NoSuchSession)
        );
    }

    #[test]
    fn unwraps_a_canister_status_result() {
        assert_eq!(
            unwrap_consent_status(ConsentStatusResult::Ok(ConsentStatus { is_granted: true }))
                .unwrap(),
            NotificationConsentStatus { granted: true }
        );
        assert_eq!(
            unwrap_consent_status(ConsentStatusResult::Ok(ConsentStatus { is_granted: false }))
                .unwrap(),
            NotificationConsentStatus { granted: false }
        );
        assert_eq!(
            unwrap_consent_status(ConsentStatusResult::Err(ConsentError::NoSuchSession))
                .unwrap_err()
                .kind(),
            AuthClientErrorKind::SessionGone
        );
        assert_eq!(
            unwrap_consent_status(ConsentStatusResult::Err(
                ConsentError::InternalCanisterError("storage is full".to_string())
            ))
            .unwrap_err()
            .to_string(),
            "Internet Identity could not report this notification consent: storage is full"
        );
        assert_eq!(
            unwrap_consent_status(ConsentStatusResult::Err(
                ConsentError::InternalCanisterError(String::new())
            ))
            .unwrap_err()
            .to_string(),
            "Internet Identity could not report this notification consent"
        );
    }

    #[test]
    fn unwraps_a_canister_revoke_result() {
        assert!(unwrap_consent_revoke(ConsentRevokeResult::Ok(())).is_ok());
        assert_eq!(
            unwrap_consent_revoke(ConsentRevokeResult::Err(ConsentError::NoSuchSession))
                .unwrap_err()
                .kind(),
            AuthClientErrorKind::SessionGone
        );
        assert_eq!(
            unwrap_consent_revoke(ConsentRevokeResult::Err(
                ConsentError::InternalCanisterError("out of cycles".to_string())
            ))
            .unwrap_err()
            .to_string(),
            "Internet Identity could not withdraw this notification consent: out of cycles"
        );
    }

    // --- the service object over a fake service ---------------------------

    struct FakeService {
        status: Mutex<Option<ConsentStatusResult>>,
        revoke: Mutex<Option<ConsentRevokeResult>>,
        status_calls: Mutex<usize>,
        revoke_calls: Mutex<usize>,
    }

    impl FakeService {
        fn new(status: ConsentStatusResult, revoke: ConsentRevokeResult) -> Arc<Self> {
            Arc::new(Self {
                status: Mutex::new(Some(status)),
                revoke: Mutex::new(Some(revoke)),
                status_calls: Mutex::new(0),
                revoke_calls: Mutex::new(0),
            })
        }
    }

    #[async_trait(?Send)]
    impl NotificationConsentService for FakeService {
        async fn app_notification_consent_status(
            &self,
        ) -> Result<ConsentStatusResult, AuthClientError> {
            *self.status_calls.lock().unwrap() += 1;
            Ok(self.status.lock().unwrap().clone().unwrap())
        }

        async fn app_revoke_notification_consent(
            &self,
        ) -> Result<ConsentRevokeResult, AuthClientError> {
            *self.revoke_calls.lock().unwrap() += 1;
            Ok(self.revoke.lock().unwrap().clone().unwrap())
        }
    }

    fn consent(service: Arc<FakeService>) -> NotificationConsent {
        NotificationConsent::from_service(service)
    }

    #[test]
    fn status_reports_what_the_canister_recorded() {
        let service = FakeService::new(
            ConsentStatusResult::Ok(ConsentStatus { is_granted: true }),
            ConsentRevokeResult::Ok(()),
        );
        let consent = consent(service.clone());
        let status = block_on(consent.status()).unwrap();
        assert_eq!(status, NotificationConsentStatus { granted: true });
        assert_eq!(*service.status_calls.lock().unwrap(), 1);
    }

    #[test]
    fn status_turns_no_such_session_into_the_one_terminal_error() {
        let service = FakeService::new(
            ConsentStatusResult::Err(ConsentError::NoSuchSession),
            ConsentRevokeResult::Ok(()),
        );
        let error = block_on(consent(service).status()).unwrap_err();
        assert_eq!(error.kind(), AuthClientErrorKind::SessionGone);
    }

    #[test]
    fn status_carries_the_canisters_own_explanation() {
        let service = FakeService::new(
            ConsentStatusResult::Err(ConsentError::InternalCanisterError(
                "storage is full".to_string(),
            )),
            ConsentRevokeResult::Ok(()),
        );
        let error = block_on(consent(service).status()).unwrap_err();
        assert_eq!(
            error.to_string(),
            "Internet Identity could not report this notification consent: storage is full"
        );
    }

    #[test]
    fn revoke_resolves_where_the_canister_withdrew_the_consent() {
        let service = FakeService::new(
            ConsentStatusResult::Ok(ConsentStatus { is_granted: true }),
            ConsentRevokeResult::Ok(()),
        );
        let consent = consent(service.clone());
        block_on(consent.revoke()).unwrap();
        assert_eq!(*service.revoke_calls.lock().unwrap(), 1);
    }

    #[test]
    fn revoke_turns_no_such_session_into_the_one_terminal_error() {
        let service = FakeService::new(
            ConsentStatusResult::Ok(ConsentStatus { is_granted: true }),
            ConsentRevokeResult::Err(ConsentError::NoSuchSession),
        );
        let error = block_on(consent(service).revoke()).unwrap_err();
        assert_eq!(error.kind(), AuthClientErrorKind::SessionGone);
    }

    #[test]
    fn revoke_raises_a_failed_write_rather_than_dropping_it() {
        let service = FakeService::new(
            ConsentStatusResult::Ok(ConsentStatus { is_granted: true }),
            ConsentRevokeResult::Err(ConsentError::InternalCanisterError(
                "out of cycles".to_string(),
            )),
        );
        let error = block_on(consent(service).revoke()).unwrap_err();
        assert_eq!(
            error.to_string(),
            "Internet Identity could not withdraw this notification consent: out of cycles"
        );
    }

    // --- the session guard ------------------------------------------------

    fn test_canister() -> Principal {
        Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap()
    }

    fn chain(targets: impl IntoIterator<Item = Option<Vec<Principal>>>) -> DelegationChain {
        DelegationChain {
            delegations: targets
                .into_iter()
                .enumerate()
                .map(|(index, targets)| SignedDelegation {
                    delegation: Delegation {
                        pubkey: vec![index as u8 + 1; 32],
                        expiration: 1_700_000_000_000_000_000,
                        targets,
                        permissions: None,
                    },
                    signature: vec![0; 64],
                })
                .collect(),
            public_key: vec![9; 32],
        }
    }

    #[test]
    fn refuses_a_chain_no_hop_restricts() {
        let error = assert_chain_reaches(&chain([None]), test_canister()).unwrap_err();
        assert_eq!(
            error.to_string(),
            "A session chain must be restricted to rdmx6-jaaaa-aaaaa-aaadq-cai, but no hop of this one names any canister"
        );
    }

    #[test]
    fn refuses_a_chain_that_names_nothing() {
        let error = assert_chain_reaches(
            &chain([Some(vec![test_canister()]), Some(Vec::new())]),
            test_canister(),
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "A session chain must be restricted to rdmx6-jaaaa-aaaaa-aaadq-cai, but a hop of this one names nothing"
        );
    }

    #[test]
    fn refuses_a_chain_that_also_names_elsewhere() {
        let elsewhere = Principal::from_text("aaaaa-aa").unwrap();
        let error = assert_chain_reaches(
            &chain([Some(vec![test_canister(), elsewhere])]),
            test_canister(),
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "A session chain must be restricted to rdmx6-jaaaa-aaaaa-aaadq-cai, but this one also names aaaaa-aa"
        );
    }

    #[test]
    fn accepts_a_chain_restricted_to_the_canister() {
        assert!(
            assert_chain_reaches(&chain([Some(vec![test_canister()])]), test_canister()).is_ok()
        );
        // A hop with no targets imposes nothing, so one restricting hop is
        // enough to confine the key.
        assert!(
            assert_chain_reaches(&chain([None, Some(vec![test_canister()])]), test_canister())
                .is_ok()
        );
    }

    #[test]
    fn create_refuses_a_host_that_is_not_a_url() {
        block_on(async {
            let options = NotificationConsentOptions {
                session_key: Arc::new(ic_agent::identity::AnonymousIdentity),
                session_chain: chain([Some(vec![test_canister()])]),
                canister_id: test_canister(),
                host: "not a url".to_string(),
            };
            let error = NotificationConsent::create(options).await.unwrap_err();
            assert_eq!(error.kind(), AuthClientErrorKind::Agent);
        });
    }

    #[cfg(feature = "native")]
    #[test]
    fn the_consent_objects_are_send_and_sync_on_native() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NotificationConsent>();
        assert_send_sync::<NotificationConsentOptions>();
        assert_send_sync::<ConsentStatusResult>();
    }

    #[test]
    fn create_refuses_a_chain_that_is_not_a_session_for_the_canister() {
        block_on(async {
            let options = NotificationConsentOptions {
                session_key: Arc::new(ic_agent::identity::AnonymousIdentity),
                session_chain: chain([None]),
                canister_id: test_canister(),
                host: "https://icp-api.io".to_string(),
            };
            let error = NotificationConsent::create(options).await.unwrap_err();
            assert!(error.to_string().contains("names any canister"));
        });
    }
}
