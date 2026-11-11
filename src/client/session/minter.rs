//! Mints app delegations from the Internet Identity canister.
//!
//! Port of upstream `session/session-minter.ts`. The session chain this crate
//! holds is restricted to the identity canister, so it is useless for the
//! application's own calls; what an application signs with is minted here, from
//! the session, and replaced as it ages.
//!
//! The three methods are written out as a small hand-written Candid interface
//! rather than generated, because the crate carries no Internet Identity
//! declarations and generating them for three methods would mean carrying the
//! whole interface.
//!
//! # Candid
//!
//! ```candid
//! type SessionKey = vec nat8;
//! type Timestamp  = nat64;
//! type AppSessionError = variant {
//!   NoSuchSession;
//!   NoSuchDelegation;
//!   InternalCanisterError : text;
//! };
//! type CandidDelegation = record {
//!   pubkey      : SessionKey;
//!   expiration  : Timestamp;
//!   targets     : opt vec principal;
//!   permissions : opt text;
//! };
//! service : {
//!   app_prepare_delegation : (record { session_key : SessionKey }) ->
//!     (variant { Ok : record { user_key : SessionKey; expiration : Timestamp }; Err : AppSessionError });
//!   app_get_delegation : (record { session_key : SessionKey; expiration : Timestamp }) ->
//!     (variant { Ok : record { delegation : CandidDelegation; signature : SessionKey }; Err : AppSessionError }) query;
//!   app_revoke_session : () -> (variant { Ok : null; Err : AppSessionError });
//! }
//! ```

use std::sync::Arc;

use async_trait::async_trait;
use candid::{CandidType, Deserialize};
use ic_agent::export::Principal;
use ic_agent::identity::{
    DelegatedIdentity, Delegation, DelegationPermissions, Identity, SignedDelegation,
};

use crate::client::platform::PlatformBounds;
use crate::client::session::app_delegation_source::{
    AppDelegationSource, NoSuchDelegationError, SessionError, SessionGoneError,
};
use crate::client::session::{
    II_SESSION_GET_DELEGATION_METHOD, II_SESSION_PREPARE_METHOD, II_SESSION_REVOKE_METHOD,
};
use crate::delegation_chain::DelegationChain;

/// The identity canister's answer to a session call: either a value or one of
/// the three session errors.
pub type AppResult<T> = Result<T, AppSessionError>;

/// The error variant Internet Identity answers session calls with.
#[derive(Debug, Clone, PartialEq, Eq, CandidType, Deserialize)]
pub enum AppSessionError {
    /// The canister has no session behind the caller.
    NoSuchSession,
    /// The canister signed nothing for the key and expiration asked for.
    NoSuchDelegation,
    /// The canister failed to answer for its own reasons.
    InternalCanisterError(String),
}

/// The argument to `app_prepare_delegation`.
#[derive(Debug, Clone, PartialEq, Eq, CandidType, Deserialize)]
pub struct PrepareDelegationArgs {
    /// The key the app delegation is for.
    pub session_key: Vec<u8>,
}

/// What `app_prepare_delegation` returns on success.
#[derive(Debug, Clone, PartialEq, Eq, CandidType, Deserialize)]
pub struct PreparedDelegation {
    /// The account key the delegation is rooted at.
    pub user_key: Vec<u8>,
    /// The expiration the canister will sign for.
    pub expiration: u64,
}

/// The argument to `app_get_delegation`.
#[derive(Debug, Clone, PartialEq, Eq, CandidType, Deserialize)]
pub struct GetDelegationArgs {
    /// The key the app delegation is for.
    pub session_key: Vec<u8>,
    /// Exactly what `app_prepare_delegation` returned.
    pub expiration: u64,
}

/// A delegation as the canister carries it, before it is turned into the
/// `ic-agent` representation.
#[derive(Debug, Clone, PartialEq, Eq, CandidType, Deserialize)]
pub struct CandidDelegation {
    /// The delegated-to key.
    pub pubkey: Vec<u8>,
    /// Nanoseconds since the epoch after which this delegation is invalid.
    pub expiration: u64,
    /// The canisters this delegation may call, where restricted.
    pub targets: Option<Vec<Principal>>,
    /// The kinds of request this delegation permits, where restricted.
    pub permissions: Option<String>,
}

/// What `app_get_delegation` returns on success.
#[derive(Debug, Clone, PartialEq, Eq, CandidType, Deserialize)]
pub struct SignedAppDelegation {
    /// The delegation the canister signed.
    pub delegation: CandidDelegation,
    /// The canister's signature over it.
    pub signature: Vec<u8>,
}

/// The three canister calls a mint and a revoke rest on.
///
/// A trait rather than a concrete actor so the retry policy, the error mapping
/// and the chain assembly can be tested without a replica.
#[async_trait(?Send)]
pub trait SessionService: PlatformBounds {
    /// `app_prepare_delegation` (update).
    async fn prepare_delegation(
        &self,
        session_key: &[u8],
    ) -> Result<AppResult<PreparedDelegation>, SessionError>;

    /// `app_get_delegation` (query).
    async fn get_delegation(
        &self,
        session_key: &[u8],
        expiration: u64,
    ) -> Result<AppResult<SignedAppDelegation>, SessionError>;

    /// `app_revoke_session` (update).
    async fn revoke_session(&self) -> Result<AppResult<()>, SessionError>;
}

/// Unwraps a canister result, turning the one terminal error into
/// [`SessionGoneError`], the retryable one into [`NoSuchDelegationError`], and
/// everything else into a retryable failure that keeps the canister's own
/// explanation.
pub fn unwrap_session_result<T>(result: AppResult<T>) -> Result<T, SessionError> {
    match result {
        Ok(value) => Ok(value),
        Err(AppSessionError::NoSuchSession) => Err(SessionGoneError.into()),
        Err(AppSessionError::NoSuchDelegation) => Err(NoSuchDelegationError.into()),
        Err(AppSessionError::InternalCanisterError(detail)) => {
            let message = if detail.is_empty() {
                "Internet Identity could not mint a delegation".to_string()
            } else {
                format!("Internet Identity could not mint a delegation: {detail}")
            };
            Err(SessionError::Retryable(message))
        }
    }
}

/// Assembles the one-hop chain an app signs its calls with, rooted at the
/// account's own key.
pub fn app_delegation_chain(user_key: &[u8], signed: &SignedAppDelegation) -> DelegationChain {
    let delegation = Delegation {
        pubkey: signed.delegation.pubkey.clone(),
        expiration: signed.delegation.expiration,
        targets: signed.delegation.targets.clone(),
        permissions: permissions_from_candid(signed.delegation.permissions.as_deref()),
    };
    DelegationChain::new(
        vec![SignedDelegation {
            delegation,
            signature: signed.signature.clone(),
        }],
        user_key.to_vec(),
    )
}

/// Maps the canister's `permissions` text onto `ic-agent`'s typed permissions.
///
/// The Candid field is an optional text because Internet Identity is free to
/// name a permission this crate does not know; such a value cannot be carried by
/// `ic-agent`'s enum, so it is dropped rather than failing the mint. The two
/// values v10 defines — `queries` (read-only) and `all` — are preserved.
fn permissions_from_candid(value: Option<&str>) -> Option<DelegationPermissions> {
    match value {
        Some("queries") => Some(DelegationPermissions::Queries),
        Some("all") => Some(DelegationPermissions::All),
        _ => None,
    }
}

/// Refuses a chain that is not a session for `canister_id`.
///
/// Targets restrict what the chain's final key may call, and the effective
/// restriction is the intersection of the hops that name any: a hop with no
/// targets imposes nothing, so one restricting hop is enough to confine the key.
/// Internet Identity names the canister on both of its hops, and the
/// intersection is what is checked, so a hop that stopped naming it would still
/// leave the chain confined by the other.
///
/// So what is refused is a chain no hop restricts, which the session key could
/// otherwise sign any call with, and one whose restrictions do not come out as
/// this canister alone.
pub fn assert_chain_reaches(
    chain: &DelegationChain,
    canister_id: Principal,
) -> Result<(), SessionError> {
    let restricting: Vec<&Vec<Principal>> = chain
        .delegations
        .iter()
        .filter_map(|signed| signed.delegation.targets.as_ref())
        .collect();

    if restricting.is_empty() {
        return Err(SessionError::InvalidChain(format!(
            "A session chain must be restricted to {}, but no hop of this one names any canister",
            canister_id.to_text()
        )));
    }
    // An empty list names nothing rather than naming this canister, and a chain
    // that can call nothing is not a session either.
    if restricting.iter().any(|hop| hop.is_empty()) {
        return Err(SessionError::InvalidChain(format!(
            "A session chain must be restricted to {}, but a hop of this one names nothing",
            canister_id.to_text()
        )));
    }

    let mut elsewhere: Vec<String> = Vec::new();
    for hop in restricting {
        for target in hop {
            if *target != canister_id {
                let text = target.to_text();
                if !elsewhere.contains(&text) {
                    elsewhere.push(text);
                }
            }
        }
    }
    if !elsewhere.is_empty() {
        return Err(SessionError::InvalidChain(format!(
            "A session chain must be restricted to {}, but this one also names {}",
            canister_id.to_text(),
            elsewhere.join(", ")
        )));
    }
    Ok(())
}

/// The canister calls, over an `ic-agent` agent that signs as the session.
struct AgentSessionService {
    agent: ic_agent::Agent,
    canister_id: Principal,
}

impl AgentSessionService {
    async fn call_update<T: CandidType + for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        arg: Vec<u8>,
    ) -> Result<AppResult<T>, SessionError> {
        let reply = self
            .agent
            .update(&self.canister_id, method)
            .with_arg(arg)
            .call_and_wait()
            .await
            .map_err(|error| SessionError::Retryable(format!("agent error: {error}")))?;
        candid::decode_one(&reply)
            .map_err(|error| SessionError::Retryable(format!("candid decode error: {error}")))
    }

    async fn call_query<T: CandidType + for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        arg: Vec<u8>,
    ) -> Result<AppResult<T>, SessionError> {
        let reply = self
            .agent
            .query(&self.canister_id, method)
            .with_arg(arg)
            .call()
            .await
            .map_err(|error| SessionError::Retryable(format!("agent error: {error}")))?;
        candid::decode_one(&reply)
            .map_err(|error| SessionError::Retryable(format!("candid decode error: {error}")))
    }
}

#[async_trait(?Send)]
impl SessionService for AgentSessionService {
    async fn prepare_delegation(
        &self,
        session_key: &[u8],
    ) -> Result<AppResult<PreparedDelegation>, SessionError> {
        let arg = candid::encode_one(PrepareDelegationArgs {
            session_key: session_key.to_vec(),
        })
        .map_err(|error| SessionError::Retryable(format!("candid encode error: {error}")))?;
        self.call_update(II_SESSION_PREPARE_METHOD, arg).await
    }

    async fn get_delegation(
        &self,
        session_key: &[u8],
        expiration: u64,
    ) -> Result<AppResult<SignedAppDelegation>, SessionError> {
        let arg = candid::encode_one(GetDelegationArgs {
            session_key: session_key.to_vec(),
            expiration,
        })
        .map_err(|error| SessionError::Retryable(format!("candid encode error: {error}")))?;
        self.call_query(II_SESSION_GET_DELEGATION_METHOD, arg).await
    }

    async fn revoke_session(&self) -> Result<AppResult<()>, SessionError> {
        self.call_update(II_SESSION_REVOKE_METHOD, Vec::new()).await
    }
}

/// Mints app delegations by asking the Internet Identity canister for one.
pub struct SessionMinter {
    service: Arc<dyn SessionService>,
    canister_id: Principal,
}

impl std::fmt::Debug for SessionMinter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionMinter")
            .field("canister_id", &self.canister_id.to_text())
            .finish()
    }
}

impl SessionMinter {
    /// Builds a minter over the session's own key and chain.
    ///
    /// The agent signs as the session, which is what a mint call rests on: the
    /// chain is restricted to the identity canister, so it can call nothing
    /// else. `host` is the IC endpoint the agent talks to.
    pub fn create(
        session_key: Arc<dyn Identity>,
        session_chain: DelegationChain,
        canister_id: Principal,
        host: Option<String>,
    ) -> Result<Self, SessionError> {
        assert_chain_reaches(&session_chain, canister_id)?;

        // The session's own key is the leaf the chain authorises; the agent
        // presents the whole chain on every call. `new_unchecked` because the
        // chain is signed by the identity canister itself (a canister
        // signature) and verifying it would need a root key this client does
        // not own — upstream trusts what the signer handed it in the same way.
        let to: Box<dyn Identity> = Box::new(session_key);
        let delegated = DelegatedIdentity::new_unchecked(
            session_chain.public_key.clone(),
            to,
            session_chain.delegations.clone(),
        );
        let url = host.unwrap_or_else(|| "https://icp-api.io".to_string());
        let agent = ic_agent::Agent::builder()
            .with_url(url)
            // Last, so no agent option can replace the session these calls are
            // made as.
            .with_identity(delegated)
            .build()
            .map_err(|error| SessionError::Retryable(format!("agent error: {error}")))?;

        Ok(Self {
            service: Arc::new(AgentSessionService { agent, canister_id }),
            canister_id,
        })
    }

    /// Builds a minter over a service, for tests and for hosts that mint on the
    /// application's behalf.
    pub fn with_service(service: Arc<dyn SessionService>, canister_id: Principal) -> Self {
        Self {
            service,
            canister_id,
        }
    }

    /// The canister these calls go to.
    pub fn canister_id(&self) -> Principal {
        self.canister_id
    }

    /// Prepares and fetches an app delegation, once more if the fetch finds
    /// nothing signed for what the prepare handed out.
    ///
    /// The pair is two calls, and only the first of them is an update: an
    /// expiration the canister will not sign for is one this session no longer
    /// holds, and the answer is to prepare again rather than to sign in again.
    /// Attempted a second time and no further — a third would be pursuing
    /// something other than the race this covers.
    pub async fn mint(&self, app_public_key: &[u8]) -> Result<DelegationChain, SessionError> {
        match self.mint_once(app_public_key).await {
            Err(SessionError::NoSuchDelegation(_)) => self.mint_once(app_public_key).await,
            other => other,
        }
    }

    async fn mint_once(&self, app_public_key: &[u8]) -> Result<DelegationChain, SessionError> {
        let prepared =
            unwrap_session_result(self.service.prepare_delegation(app_public_key).await?)?;

        let signed = unwrap_session_result(
            self.service
                .get_delegation(
                    app_public_key,
                    // Exactly what was prepared. A different value is a
                    // different signature.
                    prepared.expiration,
                )
                .await?,
        )?;

        Ok(app_delegation_chain(&prepared.user_key, &signed))
    }

    /// Ends the session at the canister.
    ///
    /// Idempotent at the canister: a session that is already gone is `Ok`,
    /// because the caller wanted it gone and it is gone. What comes back as an
    /// error is the canister failing to write, and it is raised rather than
    /// dropped — an application that told a user it signed them out of their
    /// apps should be able to find out that it did not.
    pub async fn revoke(&self) -> Result<(), SessionError> {
        unwrap_session_result(self.service.revoke_session().await?)?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl AppDelegationSource for SessionMinter {
    async fn mint(&self, app_public_key: &[u8]) -> Result<DelegationChain, SessionError> {
        SessionMinter::mint(self, app_public_key).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use ic_agent::identity::Delegation;

    const II_TEXT: &str = "rdmx6-jaaaa-aaaaa-aaadq-cai";
    const OTHER_TEXT: &str = "rrkah-fqaaa-aaaaa-aaaaq-cai";

    fn ii() -> Principal {
        Principal::from_text(II_TEXT).unwrap()
    }

    fn other() -> Principal {
        Principal::from_text(OTHER_TEXT).unwrap()
    }

    fn chain(hops: &[Option<Vec<Principal>>]) -> DelegationChain {
        DelegationChain::new(
            hops.iter()
                .enumerate()
                .map(|(index, targets)| SignedDelegation {
                    delegation: Delegation {
                        pubkey: vec![index as u8; 44],
                        expiration: 1_700_000_000_000_000_000,
                        targets: targets.clone(),
                        permissions: None,
                    },
                    signature: vec![1],
                })
                .collect(),
            vec![9u8; 44],
        )
    }

    fn signed(permissions: Option<&str>, targets: Option<Vec<Principal>>) -> SignedAppDelegation {
        SignedAppDelegation {
            delegation: CandidDelegation {
                pubkey: vec![7u8; 44],
                expiration: 1_700_000_000_000_000_000,
                targets,
                permissions: permissions.map(str::to_string),
            },
            signature: vec![1, 2, 3],
        }
    }

    #[test]
    fn unwrap_returns_the_value() {
        let value: AppResult<u32> = Ok(42);
        assert_eq!(unwrap_session_result(value).unwrap(), 42);
    }

    #[test]
    fn unwrap_turns_no_such_session_into_the_one_terminal_error() {
        let error = unwrap_session_result::<u32>(Err(AppSessionError::NoSuchSession)).unwrap_err();
        assert!(error.is_gone());
        assert!(matches!(error, SessionError::Gone(SessionGoneError)));
    }

    #[test]
    fn unwrap_keeps_no_such_delegation_apart_from_a_session_that_is_gone() {
        let error =
            unwrap_session_result::<u32>(Err(AppSessionError::NoSuchDelegation)).unwrap_err();
        assert!(error.is_no_such_delegation());
        assert!(!error.is_gone());
        assert_eq!(
            error.to_string(),
            "Internet Identity signed no delegation for this key and expiration"
        );
    }

    #[test]
    fn unwrap_keeps_the_canister_explanation_for_other_failures() {
        let error = unwrap_session_result::<u32>(Err(AppSessionError::InternalCanisterError(
            "out of cycles".into(),
        )))
        .unwrap_err();
        assert!(!error.is_gone());
        assert!(matches!(error, SessionError::Retryable(_)));
        assert!(error.to_string().contains("out of cycles"));
    }

    #[test]
    fn the_app_chain_is_rooted_at_the_account_key_the_canister_returned() {
        let user_key = vec![9u8; 44];
        let chain = app_delegation_chain(&user_key, &signed(None, None));
        assert_eq!(chain.public_key, user_key);
        assert_eq!(chain.delegations.len(), 1);
        assert_eq!(
            chain.delegations[0].delegation.expiration,
            1_700_000_000_000_000_000
        );
    }

    #[test]
    fn the_app_chain_carries_targets_and_permissions() {
        let chain = app_delegation_chain(&[9u8; 44], &signed(Some("queries"), Some(vec![ii()])));
        assert_eq!(
            chain.delegations[0].delegation.permissions,
            Some(DelegationPermissions::Queries)
        );
        assert_eq!(chain.delegations[0].delegation.targets, Some(vec![ii()]));

        let unrestricted = app_delegation_chain(&[9u8; 44], &signed(None, None));
        assert_eq!(unrestricted.delegations[0].delegation.targets, None);
        assert_eq!(unrestricted.delegations[0].delegation.permissions, None);
    }

    #[test]
    fn assert_chain_reaches_accepts_a_chain_restricted_to_the_canister() {
        assert!(assert_chain_reaches(&chain(&[Some(vec![ii()])]), ii()).is_ok());
        assert!(assert_chain_reaches(&chain(&[Some(vec![ii()]), Some(vec![ii()])]), ii()).is_ok());
    }

    #[test]
    fn assert_chain_reaches_accepts_the_shape_the_identity_provider_issues() {
        assert!(assert_chain_reaches(&chain(&[None, Some(vec![ii()])]), ii()).is_ok());
    }

    #[test]
    fn assert_chain_reaches_refuses_an_unrestricted_chain() {
        let error = assert_chain_reaches(&chain(&[None]), ii()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("no hop of this one names any canister")
        );
    }

    #[test]
    fn assert_chain_reaches_refuses_a_hop_naming_nothing() {
        let error = assert_chain_reaches(&chain(&[Some(vec![])]), ii()).unwrap_err();
        assert!(error.to_string().contains("names nothing"));

        // Even beside a hop that names the canister: folding every hop's targets
        // into one list would let the good hop cover for it.
        let error =
            assert_chain_reaches(&chain(&[Some(vec![ii()]), Some(vec![])]), ii()).unwrap_err();
        assert!(error.to_string().contains("must be restricted to"));
    }

    #[test]
    fn assert_chain_reaches_refuses_a_chain_naming_another_canister() {
        let error = assert_chain_reaches(&chain(&[Some(vec![ii(), other()])]), ii()).unwrap_err();
        assert!(error.to_string().contains(&other().to_text()));

        let error = assert_chain_reaches(&chain(&[Some(vec![other()])]), ii()).unwrap_err();
        assert!(error.to_string().contains("restricted to"));
        assert!(error.to_string().contains(&other().to_text()));
    }

    #[test]
    fn candid_round_trips_the_three_calls() {
        // The shapes the canister sees, encoded and decoded through candid, so a
        // field name or type that drifted would fail here rather than at a
        // replica.
        let args = PrepareDelegationArgs {
            session_key: vec![1, 2, 3],
        };
        let encoded = candid::encode_one(&args).unwrap();
        let decoded: PrepareDelegationArgs = candid::decode_one(&encoded).unwrap();
        assert_eq!(decoded, args);

        let prepared: AppResult<PreparedDelegation> = Ok(PreparedDelegation {
            user_key: vec![9; 44],
            expiration: 1_700_000_000_000_000_000,
        });
        let encoded = candid::encode_one(&prepared).unwrap();
        let decoded: AppResult<PreparedDelegation> = candid::decode_one(&encoded).unwrap();
        assert_eq!(decoded, prepared);

        let got: AppResult<SignedAppDelegation> = Ok(signed(Some("queries"), None));
        let encoded = candid::encode_one(&got).unwrap();
        let decoded: AppResult<SignedAppDelegation> = candid::decode_one(&encoded).unwrap();
        assert_eq!(decoded, got);

        let refused: AppResult<()> = Err(AppSessionError::InternalCanisterError(
            "out of cycles".into(),
        ));
        let encoded = candid::encode_one(&refused).unwrap();
        let decoded: AppResult<()> = candid::decode_one(&encoded).unwrap();
        assert_eq!(decoded, refused);
    }

    /// A canister stand-in: each method pops the next answer.
    #[derive(Default)]
    struct FakeService {
        prepare: Mutex<VecDeque<AppResult<PreparedDelegation>>>,
        get: Mutex<VecDeque<AppResult<SignedAppDelegation>>>,
        revoke: Mutex<VecDeque<AppResult<()>>>,
        prepare_calls: Mutex<u32>,
        get_calls: Mutex<u32>,
        get_expirations: Mutex<Vec<u64>>,
    }

    impl FakeService {
        fn with_answers(
            prepare: Vec<AppResult<PreparedDelegation>>,
            get: Vec<AppResult<SignedAppDelegation>>,
            revoke: Vec<AppResult<()>>,
        ) -> Self {
            Self {
                prepare: Mutex::new(prepare.into()),
                get: Mutex::new(get.into()),
                revoke: Mutex::new(revoke.into()),
                ..Default::default()
            }
        }

        fn prepare_calls(&self) -> u32 {
            *self.prepare_calls.lock().unwrap()
        }

        fn get_calls(&self) -> u32 {
            *self.get_calls.lock().unwrap()
        }
    }

    #[async_trait(?Send)]
    impl SessionService for FakeService {
        async fn prepare_delegation(
            &self,
            _session_key: &[u8],
        ) -> Result<AppResult<PreparedDelegation>, SessionError> {
            *self.prepare_calls.lock().unwrap() += 1;
            Ok(self
                .prepare
                .lock()
                .unwrap()
                .pop_front()
                .expect("a prepared answer"))
        }

        async fn get_delegation(
            &self,
            _session_key: &[u8],
            expiration: u64,
        ) -> Result<AppResult<SignedAppDelegation>, SessionError> {
            *self.get_calls.lock().unwrap() += 1;
            self.get_expirations.lock().unwrap().push(expiration);
            Ok(self
                .get
                .lock()
                .unwrap()
                .pop_front()
                .expect("a signed answer"))
        }

        async fn revoke_session(&self) -> Result<AppResult<()>, SessionError> {
            Ok(self
                .revoke
                .lock()
                .unwrap()
                .pop_front()
                .expect("a revoke answer"))
        }
    }

    fn prepared(expiration: u64) -> AppResult<PreparedDelegation> {
        Ok(PreparedDelegation {
            user_key: vec![9u8; 44],
            expiration,
        })
    }

    #[test]
    fn mint_prepares_again_when_the_canister_signed_nothing() {
        let service = Arc::new(FakeService::with_answers(
            vec![prepared(1), prepared(2)],
            vec![
                Err(AppSessionError::NoSuchDelegation),
                Ok(signed(None, None)),
            ],
            vec![],
        ));
        let minter = SessionMinter::with_service(service.clone(), ii());
        let chain = futures::executor::block_on(minter.mint(&[7u8; 44])).unwrap();

        // The whole pair again, not just the fetch: a new expiration is the
        // point.
        assert_eq!(service.prepare_calls(), 2);
        assert_eq!(service.get_calls(), 2);
        // The fetch used exactly what the prepare handed out.
        assert_eq!(*service.get_expirations.lock().unwrap(), vec![1, 2]);
        assert_eq!(chain.public_key, vec![9u8; 44]);
    }

    #[test]
    fn mint_gives_up_after_the_second_attempt() {
        let service = Arc::new(FakeService::with_answers(
            vec![prepared(1), prepared(2)],
            vec![
                Err(AppSessionError::NoSuchDelegation),
                Err(AppSessionError::NoSuchDelegation),
            ],
            vec![],
        ));
        let minter = SessionMinter::with_service(service.clone(), ii());
        let error = futures::executor::block_on(minter.mint(&[7u8; 44])).unwrap_err();
        assert!(error.is_no_such_delegation());
        assert_eq!(service.prepare_calls(), 2);
    }

    #[test]
    fn mint_does_not_retry_a_session_that_is_gone() {
        let service = Arc::new(FakeService::with_answers(
            vec![Err(AppSessionError::NoSuchSession)],
            vec![Ok(signed(None, None))],
            vec![],
        ));
        let minter = SessionMinter::with_service(service.clone(), ii());
        let error = futures::executor::block_on(minter.mint(&[7u8; 44])).unwrap_err();
        assert!(error.is_gone());
        assert_eq!(service.prepare_calls(), 1);
    }

    #[test]
    fn revoke_raises_a_canister_refusal() {
        let service = Arc::new(FakeService::with_answers(
            vec![],
            vec![],
            vec![Err(AppSessionError::InternalCanisterError(
                "could not write".into(),
            ))],
        ));
        let minter = SessionMinter::with_service(service, ii());
        let error = futures::executor::block_on(minter.revoke()).unwrap_err();
        assert!(error.to_string().contains("could not write"));
    }

    #[test]
    fn revoke_treats_a_session_already_gone_as_success() {
        let service = Arc::new(FakeService::with_answers(vec![], vec![], vec![Ok(())]));
        let minter = SessionMinter::with_service(service, ii());
        assert!(futures::executor::block_on(minter.revoke()).is_ok());
    }

    #[test]
    fn create_refuses_a_chain_that_does_not_reach_the_canister() {
        let key: Arc<dyn Identity> =
            Arc::new(ic_agent::identity::BasicIdentity::from_raw_key(&[1u8; 32]));
        let error = SessionMinter::create(key, chain(&[None]), ii(), None).unwrap_err();
        assert!(matches!(error, SessionError::InvalidChain(_)));
    }
}
