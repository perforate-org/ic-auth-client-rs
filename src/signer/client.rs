//! The signer client: one channel to one signer, JSON-RPC over it.
//!
//! Port of the request/response core of `@icp-sdk/signer` 6.1.0's `Signer`
//! (`signer.ts:250-652`), reduced to what `@icp-sdk/auth` v11.2.0 uses: open a
//! channel, send a request, decode the result, close the channel
//! (`auth-client.ts:572-582,813,887,1216`; `session/session-delegation.ts:109`;
//! `notification-consent.ts:67`).
//!
//! Deliberate differences from upstream, all consequences of the request/
//! response [`Channel`](crate::client::transport::Channel) seam this crate uses
//! instead of upstream's event listeners:
//!
//! - Upstream schedules a close 200 ms after the last in-flight request and
//!   lets the channel be reused meanwhile (`signer.ts:323-335`). Here the caller
//!   closes explicitly with [`Signer::close`]; concurrent requests still share
//!   one channel, and a channel the transport reports closed is replaced
//!   automatically. There is no timer to leak and no platform task to spawn.
//! - Upstream supports caller-supplied request transforms and a promise of a
//!   request (`signer.ts:252-284`). Neither is part of this crate's auth-client
//!   surface: the local request is built synchronously, and the ICRC-95
//!   derivation origin is the only transform.
//!
//! There is **no permission handshake**: upstream's `Signer` sends nothing
//! before a request. The ICRC-25 permission methods exist only as typed helpers
//! the auth client never calls (`signer.ts:583,611`), and the ICRC-29 status
//! heartbeat belongs to the window transport's channel establishment
//! (`web/heartbeat/client.ts`), not to this layer. The only thing cached here is
//! the channel itself, exactly like upstream's `#channel` field.

use std::sync::Arc;

use futures::lock::Mutex;
use serde_json::Value;

use crate::client::options::{NotificationConsentStatus, SignedAttributes};
use crate::client::transport::{SharedChannel, SharedTransport, SignerError};
use crate::delegation_chain::DelegationChain;

use super::protocol;

/// Options for a [`Signer`].
///
/// Port of upstream `SignerOptions` (`signer.ts:229-251`) restricted to the two
/// fields the auth client sets (`auth-client.ts:572-582`).
#[derive(Clone)]
pub struct SignerOptions {
    /// The transport that establishes the channel to the signer.
    pub transport: SharedTransport,

    /// The ICRC-95 derivation origin attached to **every** request.
    ///
    /// Upstream passes `options.derivationOrigin?.toString()`, which the signer
    /// installs as a transform (`signer.ts:181-185,290-295`).
    pub derivation_origin: Option<String>,
}

/// The parameters of an [`Signer::request_session_delegation`] request.
///
/// Port of `SessionDelegationParams` (`session/session-delegation.ts:63-68`),
/// with the same optional bounds: an unset bound is omitted so the provider's
/// own default applies rather than a number this crate invented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionDelegationParams<'a> {
    /// The session's DER-encoded public key the chain must delegate to.
    pub session_public_key: &'a [u8],
    /// The requested maximum lifetime, in nanoseconds.
    pub max_time_to_live: Option<u64>,
    /// The requested maximum idle time, in nanoseconds.
    pub max_time_to_idle: Option<u64>,
    /// The ICRC-95 derivation origin for this request.
    pub derivation_origin: Option<&'a str>,
}

/// The parameters of an [`Signer::request_attributes`] request.
///
/// Port of the `{ keys, nonce }` payload of `AuthClient.requestAttributes`
/// (`auth-client.ts:1216-1223`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeRequest {
    /// The attribute keys to request.
    pub keys: Vec<String>,
    /// The nonce issued by the relying party's canister.
    pub nonce: Vec<u8>,
}

/// The shared state of a signer client.
///
/// Behind an `Arc` so a [`Signer`] can be cloned and driven from two places ---
/// the auth client issues a session-delegation request concurrently with an
/// attribute request (`auth-client.ts:978,1216`), and both must share one
/// channel.
struct Inner {
    transport: SharedTransport,
    derivation_origin: Option<String>,
    channel: Mutex<Option<SharedChannel>>,
}

/// A client for one signer.
///
/// One instance is a view on a single channel: requests are serialised by the
/// transport into the signer's call order, and the channel is established on the
/// first request and reused until it is closed.
pub struct Signer {
    inner: Arc<Inner>,
}

impl Clone for Signer {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Signer").finish_non_exhaustive()
    }
}

impl Signer {
    /// A signer that talks over `options.transport`.
    pub fn new(options: SignerOptions) -> Self {
        Self {
            inner: Arc::new(Inner {
                transport: options.transport,
                derivation_origin: options.derivation_origin,
                channel: Mutex::new(None),
            }),
        }
    }

    /// Asks the identity provider for a session, and returns the chain it
    /// signed.
    ///
    /// Port of `requestSessionDelegation` (`session-delegation.ts:104-141`):
    /// encodes the request, sends it, and decodes the returned chain. The chain
    /// is re-checked against the request: it must terminate at
    /// `request.session_public_key`, and when `max_time_to_live` is set its
    /// earliest expiration must not exceed it.
    ///
    /// A `3002` refusal is an ordinary [`SignerError::Refused`] whose
    /// [`is_interaction_required`](SignerError::is_interaction_required) is
    /// true; the reason Internet Identity gave is in
    /// [`refusal_reason`](SignerError::refusal_reason).
    pub async fn request_session_delegation(
        &self,
        request: SessionDelegationParams<'_>,
    ) -> Result<DelegationChain, SignerError> {
        let params = protocol::session_delegation_params(
            request.session_public_key,
            request.max_time_to_live,
            request.max_time_to_idle,
            request.derivation_origin,
        );
        let result = self
            .rpc(protocol::SESSION_DELEGATION_METHOD, Some(params))
            .await?;
        protocol::parse_session_delegation(
            result,
            request.session_public_key,
            request.max_time_to_live,
            crate::client::now::now_ns(),
        )
    }

    /// Asks the identity provider for signed identity attributes.
    ///
    /// Port of `AuthClient.requestAttributes`'s signer call
    /// (`auth-client.ts:1216-1243`): `{keys, nonce}` out, `{data, signature}`
    /// in, both base64 on the wire.
    pub async fn request_attributes(
        &self,
        request: AttributeRequest,
    ) -> Result<SignedAttributes, SignerError> {
        let params = protocol::attributes_params(&request.keys, &request.nonce);
        let result = self.rpc(protocol::ATTRIBUTES_METHOD, Some(params)).await?;
        protocol::parse_attributes(result)
    }

    /// Asks the user whether this application may notify them.
    ///
    /// Port of `requestNotificationConsent` (`notification-consent.ts:63-91`):
    /// the params object is always present (empty without a derivation origin).
    ///
    /// The two refusal codes are left on the [`SignerError::Refused`] value for
    /// the caller to interpret: `-32601` means this provider does not send
    /// notifications ([`is_method_not_found`](SignerError::is_method_not_found))
    /// and `3002` means a ceremony was needed
    /// ([`is_interaction_required`](SignerError::is_interaction_required)).
    pub async fn request_notification_consent(
        &self,
        derivation_origin: Option<&str>,
    ) -> Result<NotificationConsentStatus, SignerError> {
        let params = protocol::notification_consent_params(derivation_origin);
        let result = self
            .rpc(protocol::NOTIFICATION_CONSENT_METHOD, Some(params))
            .await?;
        protocol::parse_notification_consent(result)
    }

    /// Closes the channel, releasing the signer window where this end owns it.
    ///
    /// Port of upstream `closeChannel` (`signer.ts:340-343`), used by the auth
    /// client's `dispose` and by a channel steal (`auth-client.ts:813,887`).
    /// With an establishment in flight there is nothing to close yet, and this
    /// returns without waiting for it, as upstream's `#channel` is still unset
    /// there.
    pub async fn close(&self) {
        let Some(mut cached) = self.inner.channel.try_lock() else {
            // A concurrent request is establishing the channel; it does not
            // exist yet, so there is nothing this call could close.
            return;
        };
        let channel = cached.take();
        drop(cached);
        if let Some(channel) = channel {
            // Upstream awaits `close()` and lets a failure propagate; this
            // signature is infallible, and a channel that cannot close is one
            // the transport has already given up on.
            let _ = channel.close().await;
        }
    }

    /// Sends one request and returns its result, or the signer's refusal.
    ///
    /// Port of `sendRequest` + `#rpc` (`signer.ts:252-400,607-644`): the
    /// derivation-origin transform is applied to the request, the channel is
    /// opened (or reused), and an error response becomes a refusal. The id is
    /// checked against the response because the JSON-RPC contract is that a
    /// response answers exactly the request it echoes.
    async fn rpc(&self, method: &str, params: Option<Value>) -> Result<Value, SignerError> {
        let params =
            protocol::with_derivation_origin(params, self.inner.derivation_origin.as_deref());
        let request = protocol::request(method, params);
        let id = request
            .id
            .clone()
            .expect("a request built by this module always carries an id");

        let channel = self.channel().await?;
        let response = match channel.send(request).await {
            Ok(response) => response,
            Err(error) => {
                // A send failing because the channel closed leaves nothing to
                // reuse; forget it so the next request establishes a new one.
                if channel.is_closed() {
                    self.forget(&channel).await;
                }
                return Err(error);
            }
        };
        if channel.is_closed() {
            self.forget(&channel).await;
        }
        if response.id() != &id {
            return Err(SignerError::Protocol(format!(
                "the signer answered request {id}, but the response carries id {}",
                response.id()
            )));
        }
        response.into_result()
    }

    /// The live channel, establishing one if there is none.
    ///
    /// Port of `openChannel` (`signer.ts:299-334`): a live channel is reused;
    /// a transport failure is the caller's error.
    ///
    /// The establishment is done while holding the cache lock so that
    /// concurrent requests share **one** establishment --- upstream memoises the
    /// promise for the same reason (a second window must not be opened, and the
    /// redirect transport must not start a second flow).
    async fn channel(&self) -> Result<SharedChannel, SignerError> {
        let mut cached = self.inner.channel.lock().await;
        if let Some(channel) = cached.as_ref()
            && !channel.is_closed()
        {
            return Ok(Arc::clone(channel));
        }
        let channel = self.inner.transport.establish_channel().await?;
        *cached = Some(Arc::clone(&channel));
        Ok(channel)
    }

    /// Drops `channel` from the cache, if it is still the cached channel.
    ///
    /// Only a channel that closed itself is forgotten; a concurrent request
    /// that already replaced it must not lose its replacement.
    async fn forget(&self, channel: &SharedChannel) {
        let mut cached = self.inner.channel.lock().await;
        if cached
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, channel))
        {
            *cached = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use futures::executor::block_on;
    use serde_json::{Value, json};

    use super::protocol::{
        ATTRIBUTES_METHOD, NOTIFICATION_CONSENT_METHOD, SESSION_DELEGATION_METHOD,
    };
    use super::*;
    use crate::signer::protocol;
    use crate::signer::test_utils::FakeTransport;

    fn signer(transport: &FakeTransport) -> Signer {
        Signer::new(SignerOptions {
            transport: transport.shared(),
            derivation_origin: None,
        })
    }

    fn signer_with_origin(transport: &FakeTransport, origin: &str) -> Signer {
        Signer::new(SignerOptions {
            transport: transport.shared(),
            derivation_origin: Some(origin.to_string()),
        })
    }

    /// A delegation response whose leaf is `leaf` and whose only hop expires
    /// far in the future, so lifetime checks need an explicit bound.
    fn delegation_result(leaf: &[u8], expiration: u64) -> Value {
        let leaf = crate::client::base64::to_base64(leaf);
        json!({
            "publicKey": crate::client::base64::to_base64(&[1, 2, 3]),
            "signerDelegation": [{
                "delegation": {
                    "pubkey": leaf,
                    "expiration": expiration.to_string(),
                    "targets": ["aaaaa-aa"],
                },
                "signature": "BwgJ",
            }],
        })
    }

    fn attributes(keys: &[&str], nonce: &[u8]) -> AttributeRequest {
        AttributeRequest {
            keys: keys.iter().map(|key| key.to_string()).collect(),
            nonce: nonce.to_vec(),
        }
    }

    // --- request flow ------------------------------------------------------

    #[test]
    fn session_delegation_is_sent_and_decoded() {
        let transport = FakeTransport::new();
        // The requested lifetime is 30 minutes, so the fake signer must answer
        // with a chain that expires inside it (plus the five-minute skew).
        transport.on_result(
            SESSION_DELEGATION_METHOD,
            delegation_result(&[4, 5, 6], crate::client::now::now_ns() + 1_800_000_000_000),
        );
        let signer = signer(&transport);

        let chain = block_on(signer.request_session_delegation(SessionDelegationParams {
            session_public_key: &[4, 5, 6],
            max_time_to_live: Some(1_800_000_000_000),
            max_time_to_idle: None,
            derivation_origin: None,
        }))
        .expect("the fake signer answers");

        assert_eq!(chain.public_key, vec![1, 2, 3]);
        assert_eq!(chain.delegations[0].delegation.pubkey, vec![4, 5, 6]);
        assert_eq!(
            transport.methods(),
            vec![SESSION_DELEGATION_METHOD.to_string()]
        );

        let request = transport.last_request().expect("a request was recorded");
        assert_eq!(request.jsonrpc, "2.0");
        assert!(request.id.is_some(), "the id is mandatory on the wire");
        let params = request.params.expect("params are present");
        assert_eq!(params["sessionPublicKey"], json!("BAUG"));
        assert_eq!(params["maxTimeToLive"], json!("1800000000000"));
        assert!(params.get("maxTimeToIdle").is_none());
        assert!(params.get("icrc95DerivationOrigin").is_none());
    }

    #[test]
    fn attributes_are_sent_and_decoded() {
        let transport = FakeTransport::new();
        transport.on_result(
            ATTRIBUTES_METHOD,
            json!({ "data": "AQID", "signature": "BAUG" }),
        );
        let signer = signer(&transport);

        let signed =
            block_on(signer.request_attributes(attributes(&["email", "name"], &[9, 8, 7])))
                .expect("the fake signer answers");
        assert_eq!(signed.data, vec![1, 2, 3]);
        assert_eq!(signed.signature, vec![4, 5, 6]);

        let request = transport.last_request().expect("a request was recorded");
        assert_eq!(request.method, ATTRIBUTES_METHOD);
        assert_eq!(
            request.params.expect("params are present"),
            json!({ "keys": ["email", "name"], "nonce": "CQgH" })
        );
    }

    #[test]
    fn notification_consent_sends_an_empty_object_and_reads_the_answer() {
        let transport = FakeTransport::new();
        transport.on_result(NOTIFICATION_CONSENT_METHOD, json!({ "granted": false }));
        let signer = signer(&transport);

        let status = block_on(signer.request_notification_consent(None)).expect("answered");
        // A refusal is an answer, not an error.
        assert!(!status.granted);
        assert_eq!(
            transport.last_request().expect("a request").params,
            Some(json!({}))
        );
    }

    #[test]
    fn the_derivation_origin_is_attached_to_every_request() {
        let transport = FakeTransport::new();
        transport.on_result(NOTIFICATION_CONSENT_METHOD, json!({ "granted": true }));
        let signer = signer_with_origin(&transport, "https://rp.example");

        block_on(signer.request_notification_consent(None)).expect("answered");
        assert_eq!(
            transport.last_request().expect("a request").params,
            Some(json!({ "icrc95DerivationOrigin": "https://rp.example" }))
        );
    }

    #[test]
    fn a_requests_own_derivation_origin_is_used_when_the_signer_has_none() {
        let transport = FakeTransport::new();
        transport.on_result(
            SESSION_DELEGATION_METHOD,
            delegation_result(&[4, 5, 6], 1_900_000_000_000_000_000),
        );
        let signer = signer(&transport);

        block_on(signer.request_session_delegation(SessionDelegationParams {
            session_public_key: &[4, 5, 6],
            max_time_to_live: None,
            max_time_to_idle: None,
            derivation_origin: Some("https://request.example"),
        }))
        .expect("answered");
        assert_eq!(
            transport.last_request().expect("a request").params.unwrap()["icrc95DerivationOrigin"],
            json!("https://request.example")
        );
    }

    #[test]
    fn the_signers_derivation_origin_wins_over_the_requests_own() {
        // Upstream applies the transform after the request is built
        // (`signer.ts:181-185`), so the signer-level value overwrites.
        let transport = FakeTransport::new();
        transport.on_result(
            SESSION_DELEGATION_METHOD,
            delegation_result(&[4, 5, 6], 1_900_000_000_000_000_000),
        );
        let signer = signer_with_origin(&transport, "https://signer.example");

        block_on(signer.request_session_delegation(SessionDelegationParams {
            session_public_key: &[4, 5, 6],
            max_time_to_live: None,
            max_time_to_idle: None,
            derivation_origin: Some("https://request.example"),
        }))
        .expect("answered");
        assert_eq!(
            transport.last_request().expect("a request").params.unwrap()["icrc95DerivationOrigin"],
            json!("https://signer.example")
        );
    }

    // --- handshake and channel caching -------------------------------------

    #[test]
    fn no_handshake_is_sent_before_the_first_request() {
        // Upstream's `Signer` sends nothing of its own: no
        // `icrc25_request_permissions`, no `icrc29_status` (that is the window
        // transport's heartbeat). The first and only message is the caller's.
        let transport = FakeTransport::new();
        transport.on_result(NOTIFICATION_CONSENT_METHOD, json!({ "granted": true }));
        let signer = signer(&transport);

        block_on(signer.request_notification_consent(None)).expect("answered");
        assert_eq!(
            transport.methods(),
            vec![NOTIFICATION_CONSENT_METHOD.to_string()],
            "a permission or status handshake on the signer channel would show up here"
        );
        assert_eq!(transport.establish_count(), 1);
    }

    #[test]
    fn one_channel_serves_every_request() {
        let transport = FakeTransport::new();
        transport.on_result(NOTIFICATION_CONSENT_METHOD, json!({ "granted": true }));
        transport.on_result(
            ATTRIBUTES_METHOD,
            json!({ "data": "AQID", "signature": "BAUG" }),
        );
        let signer = signer(&transport);

        block_on(async {
            signer.request_notification_consent(None).await.unwrap();
            signer
                .request_attributes(attributes(&["email"], &[1]))
                .await
                .unwrap();
            signer.request_notification_consent(None).await.unwrap();
        });
        assert_eq!(transport.establish_count(), 1);
        assert!(!transport.channel_closed(), "the channel is still open");
    }

    #[test]
    fn concurrent_requests_share_one_establishment() {
        // A second establishment would open a second signer window (window
        // flow) or start a second redirect (URL flow), so concurrent requests
        // must wait on the one in flight.
        let transport = FakeTransport::new();
        transport.yield_on_establish();
        transport.on_result(NOTIFICATION_CONSENT_METHOD, json!({ "granted": true }));
        transport.on_result(
            ATTRIBUTES_METHOD,
            json!({ "data": "AQID", "signature": "BAUG" }),
        );
        let signer = signer(&transport);

        let (consent, signed) = block_on(async {
            futures::join!(
                signer.request_notification_consent(None),
                signer.request_attributes(attributes(&["email"], &[1])),
            )
        });
        consent.expect("consent answered");
        signed.expect("attributes answered");
        assert_eq!(transport.establish_count(), 1);
        assert_eq!(
            transport.methods().len(),
            2,
            "both requests went over the one channel"
        );
    }

    #[test]
    fn close_releases_the_channel_and_the_next_request_reopens_it() {
        let transport = FakeTransport::new();
        transport.on_result(NOTIFICATION_CONSENT_METHOD, json!({ "granted": true }));
        let signer = signer(&transport);

        block_on(signer.request_notification_consent(None)).expect("answered");
        block_on(signer.close());
        assert!(transport.channel_closed());
        assert_eq!(transport.establish_count(), 1);

        block_on(signer.request_notification_consent(None)).expect("answered again");
        assert_eq!(transport.establish_count(), 2);
    }

    #[test]
    fn a_channel_closed_underneath_is_replaced() {
        let transport = FakeTransport::new();
        transport.on_result(NOTIFICATION_CONSENT_METHOD, json!({ "granted": true }));
        let signer = signer(&transport);

        block_on(signer.request_notification_consent(None)).expect("answered");
        transport.force_close();

        block_on(signer.request_notification_consent(None)).expect("answered after re-open");
        assert_eq!(transport.establish_count(), 2);
    }

    #[test]
    fn close_without_a_channel_does_nothing() {
        let transport = FakeTransport::new();
        let signer = signer(&transport);
        block_on(signer.close());
        assert_eq!(transport.establish_count(), 0);
    }

    // --- error mapping -----------------------------------------------------

    #[test]
    fn method_not_found_is_recognisable_on_consent() {
        // `-32601` is how an Internet Identity without notification support
        // answers (`notification-consent.ts:21,77-79`).
        let transport = FakeTransport::new();
        transport.on_error(
            NOTIFICATION_CONSENT_METHOD,
            -32601,
            "Method not found",
            None,
        );
        let signer = signer(&transport);

        let error = block_on(signer.request_notification_consent(None)).unwrap_err();
        assert!(error.is_method_not_found(), "{error}");
        assert!(!error.is_interaction_required());
        assert!(matches!(error, SignerError::Refused { code: -32601, .. }));
    }

    #[test]
    fn interaction_required_is_recognisable_and_keeps_the_reason() {
        // `3002` is a `prompt:'none'` denial (`session-delegation.ts:14-32`).
        let transport = FakeTransport::new();
        transport.on_error(
            SESSION_DELEGATION_METHOD,
            3002,
            "User interaction required",
            Some(json!({ "reason": "login_required" })),
        );
        let signer = signer(&transport);

        let error = block_on(signer.request_session_delegation(SessionDelegationParams {
            session_public_key: &[4, 5, 6],
            max_time_to_live: None,
            max_time_to_idle: None,
            derivation_origin: None,
        }))
        .unwrap_err();
        assert!(error.is_interaction_required(), "{error}");
        assert!(!error.is_method_not_found());
        assert_eq!(error.refusal_reason().as_deref(), Some("login_required"));
    }

    #[test]
    fn other_refusals_keep_their_code_and_message() {
        let transport = FakeTransport::new();
        transport.on_error(ATTRIBUTES_METHOD, 4001, "Consent denied", None);
        let signer = signer(&transport);

        let error = block_on(signer.request_attributes(attributes(&["email"], &[1]))).unwrap_err();
        assert!(!error.is_interaction_required());
        assert!(!error.is_method_not_found());
        match error {
            SignerError::Refused {
                code,
                message,
                data,
            } => {
                assert_eq!(code, 4001);
                assert_eq!(message, "Consent denied");
                assert!(data.is_none());
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_channel_closed_before_a_response_is_the_callers_error() {
        // Upstream rejects with `NETWORK_ERROR` "Channel was closed before a
        // response was received" (`signer.ts:337-345`); this crate's channel
        // reports the same situation as `ChannelClosed`.
        let transport = FakeTransport::new();
        transport.on_close(ATTRIBUTES_METHOD);
        let signer = signer(&transport);

        let error = block_on(signer.request_attributes(attributes(&["email"], &[1]))).unwrap_err();
        assert!(matches!(error, SignerError::ChannelClosed), "{error:?}");
        assert_eq!(transport.establish_count(), 1);

        // The next request opens a fresh channel rather than reusing the dead one.
        transport.on_result(
            ATTRIBUTES_METHOD,
            json!({ "data": "AQID", "signature": "BAUG" }),
        );
        block_on(signer.request_attributes(attributes(&["email"], &[1]))).expect("recovered");
        assert_eq!(transport.establish_count(), 2);
    }

    #[test]
    fn a_closed_signer_window_is_the_callers_error() {
        let transport = FakeTransport::new();
        transport.on_window_closed(SESSION_DELEGATION_METHOD);
        let signer = signer(&transport);

        let error = block_on(signer.request_session_delegation(SessionDelegationParams {
            session_public_key: &[4, 5, 6],
            max_time_to_live: None,
            max_time_to_idle: None,
            derivation_origin: None,
        }))
        .unwrap_err();
        assert!(matches!(error, SignerError::WindowClosed), "{error:?}");
    }

    #[test]
    fn a_transport_failure_to_establish_is_the_callers_error_and_is_not_cached() {
        // Upstream wraps an establishment failure as `NETWORK_ERROR` and does
        // not memoise the failure (`signer.ts:299-334`).
        let transport = FakeTransport::new();
        transport.fail_establish("the signer window could not be opened");
        let signer = signer(&transport);

        let error = block_on(signer.request_notification_consent(None)).unwrap_err();
        match error {
            SignerError::Transport(message) => {
                assert!(message.contains("could not be opened"), "{message}");
            }
            other => panic!("expected a transport error, got {other:?}"),
        }
        assert_eq!(transport.establish_count(), 1);

        transport.allow_establish();
        transport.on_result(NOTIFICATION_CONSENT_METHOD, json!({ "granted": true }));
        block_on(signer.request_notification_consent(None)).expect("retried");
        assert_eq!(transport.establish_count(), 2);
    }

    #[test]
    fn a_mismatched_response_id_is_a_protocol_error() {
        let transport = FakeTransport::new();
        transport.on_result(NOTIFICATION_CONSENT_METHOD, json!({ "granted": true }));
        transport.answer_with_the_wrong_id();
        let signer = signer(&transport);

        let error = block_on(signer.request_notification_consent(None)).unwrap_err();
        assert!(matches!(error, SignerError::Protocol(_)), "{error:?}");
    }

    #[test]
    fn a_malformed_delegation_surfaces_as_invalid_delegation() {
        let transport = FakeTransport::new();
        transport.on_result(
            SESSION_DELEGATION_METHOD,
            json!({ "publicKey": "AQID", "signerDelegation": [] }),
        );
        let signer = signer(&transport);

        let error = block_on(signer.request_session_delegation(SessionDelegationParams {
            session_public_key: &[4, 5, 6],
            max_time_to_live: None,
            max_time_to_idle: None,
            derivation_origin: None,
        }))
        .unwrap_err();
        assert!(
            matches!(error, SignerError::InvalidDelegation(_)),
            "{error:?}"
        );
    }

    #[test]
    fn a_chain_for_another_leaf_is_refused_at_the_client() {
        let transport = FakeTransport::new();
        transport.on_result(
            SESSION_DELEGATION_METHOD,
            delegation_result(&[9, 9, 9], 1_900_000_000_000_000_000),
        );
        let signer = signer(&transport);

        let error = block_on(signer.request_session_delegation(SessionDelegationParams {
            session_public_key: &[4, 5, 6],
            max_time_to_live: None,
            max_time_to_idle: None,
            derivation_origin: None,
        }))
        .unwrap_err();
        assert!(
            matches!(error, SignerError::InvalidDelegation(_)),
            "{error:?}"
        );
    }

    // Keep the protocol constants exercised from here too, so a rename shows up
    // in this module's tests as well as the wire goldens.
    #[test]
    fn method_names_match_upstream() {
        assert_eq!(SESSION_DELEGATION_METHOD, "ii_session_delegation");
        assert_eq!(ATTRIBUTES_METHOD, "ii-icrc3-attributes");
        assert_eq!(NOTIFICATION_CONSENT_METHOD, "ii_notification_consent");
        assert_eq!(protocol::ICRC29_STATUS_METHOD, "icrc29_status");
        assert_eq!(
            protocol::ICRC25_REQUEST_PERMISSIONS_METHOD,
            "icrc25_request_permissions"
        );
    }
}
