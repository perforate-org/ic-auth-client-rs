# §11 — Test-derived acceptance criteria

Upstream has **7,697 lines** of tests across 22 files (`tests/client/**`). They are the
authority for "did the port reproduce the behaviour". This file lists them by area with
what each asserts, so the Lead can port them as Rust tests. Line numbers are test
declaration lines.

Upstream test stack: Vitest + jsdom + `fake-indexeddb` (`package.json:45-49`). Two
hand-written doubles carry most of the protocol coverage and are worth porting first:

| Double | Models | Source |
| --- | --- | --- |
| `FakeTransport` | in-memory ICRC-25 `Channel`; records requests; handler chain; notification semantics; close/response listeners | `tests/client/fake-transport.ts:35-119` |
| `FakeUrlTransport` | static cross-load journal for `memoize`, plus "respond" vs "navigate away" loads; models the real `UrlTransport`'s replay | `tests/client/fake-url-transport.ts:42-160` |

Also ported wholesale from `auth-client.test.ts:42-114,267-340`:

- a mocked `SessionMinter` that roots every app delegation at a known account key;
- a mocked SSO service with a scripted Candid answer;
- a Web Locks stand-in (`stubLocks`) that implements steal semantics;
- `spyStorage` (records every credential write), `stateFor(chain)`, and
  `encodeDelegationChainResponse(chain)`.

## 11.1 Client lifecycle / status / restore (`tests/client/auth-client.test.ts`)

| Test (line) | Asserts | Rust test target |
| --- | --- | --- |
| `should initialize with an AnonymousIdentity` (`:343`) | fresh client is signed out and anonymous | `client::new_is_signed_out` |
| `stops claiming a sign-in it has nothing left to restore` (`:350`) | a record with no usable credential → drops the claim | `client::restore_drops_unbacked_record` |
| `carries when the sign-in ends, in every case where a record exists` (`:402`) | `expired` keeps `principal`/`expiresAtMs` for every record shape | `status::expired_carries_principal` |
| `carries the account in every case where a record exists` (`:445`) | every non-signed-out state names the principal | `status::every_record_names_account` |
| `is not authenticated by a record this origin does not hold` (`:466`) | `signed-in-elsewhere` is not authenticated | `status::signed_in_elsewhere_is_not_authenticated` |
| `keeps two clients under one origin apart when they are namespaced` (`:488`) | namespace separates all slots | `slots::namespace_separates_clients` |
| `keeps a namespaced sign-in wholly inside its namespace` (`:509`) | no bare-slot writes from a namespaced client | `slots::namespaced_client_writes_only_its_slots` |
| `reports a denied silent request as one needing a ceremony` (`:534`) | 3002 → `InteractionRequiredError` | `signin::interaction_required` |
| `leaves any other denial an ordinary error` (`:555`) | other codes are not `InteractionRequired` | `signin::other_denial_is_plain_error` |
| `refuses half of an identity provider, which would mint against mainnet` (`:575`) | provider pair required | `options::half_provider_rejected` |
| `refuses the identity provider as a bare URL, which it used to be` (`:594`) | string/URL → `TypeError` | `options::bare_provider_rejected` |
| `restores again after a failed restore, rather than replaying the failure` (`:607`) | `init` memo clears on rejection | `client::init_retries_after_failure` |
| `releases the identity it replaces, so a discarded one stops minting` (`:637`) | `install_identity` disposes the previous session identity | `client::replacing_identity_disposes_it` |
| `names no session bounds of its own` (`:653`) | no TTL/TTI invented by the client | `signin::no_default_bounds` |
| `answers with the same status object until something changes` (`:1893`) | stable status value | `status::stable_until_change` (JS-only nuance; document) |
| `flips to expired without a write, and holds that answer too` (`:1912`) | lazy expiry, no store write | `status::lazy_expiry_no_write` |
| `tells a subscriber when who is signed in here changes` (`:1932`) | subscribe fires after status is readable | `subscribe::fires_after_status_update` |
| `hands a subscriber the identity of its own sign-in` (`:1960`) | `getIdentity` in a listener waits for commit | `subscribe::identity_waits_for_commit` |
| `hands a subscriber the identity of a peer's sign-in` (`:1974`) | same for a peer's write | `subscribe::peer_identity_waits` |
| `picks up a sign-in a peer client made with its stores` (`:1828`) | shared state store → peer notification | `subscribe::peer_signin` |
| `does not re-hydrate off its own ceremony writes` (`:1852`) | own writes do not re-trigger restore | `restore::ignores_own_writes` |
| `collapses a burst of record changes into one further restore` (`:1868`) | coalescing | `restore::coalesces_burst` |
| `mints on the page load that restores a session, before any request` (`:1755`) | restore mints an app delegation | `restore::mints_on_load` |
| `mints when the tab comes back, if one is due` (`:1783`) | foreground refresh | `refresh::foreground` |
| `mints when the user does something, if one is due` (`:1803`) | activity refresh | `refresh::activity` |
| `mints once for a burst of activity, not once per event` (`:1995`) | single-flight + threshold | `refresh::burst_is_one_mint` |
| `does not refresh the identity a ceremony is in the middle of replacing` (`:2028`) | interactions guard | `refresh::stands_down_for_ceremony` |
| `installs nothing when disposed while the restore is in flight` (`:2058`) | dispose during restore | `dispose::during_restore` |
| `refuses an identity rather than an anonymous one when a record it cannot act on stands` (`:2080`) | `SessionNotHeldError` | `identity::session_not_held` |
| `stays silent when the restore itself fails` (`:2110`) | background refresh swallows failures | `refresh::silent_failure` |
| `costs nothing to glance at a tab whose delegation is healthy` (`:2124`) | healthy credential → no mint | `refresh::healthy_is_free` |
| `hooks nothing when foreground refresh is turned off` (`:2137`) | `disableBrowserActivity` | `refresh::disabled_hooks_nothing` |
| `publishes the sign-in as ended when a refused mint finds the record naming it` (`:2158`) | `expire` path | `teardown::expire_on_refused_mint` |
| `leaves nothing behind when the session a ceremony obtained is refused` (`:2185`) | ceremony refusal leaves no record | `signin::refused_session_leaves_nothing` |
| `hands back the anonymous identity for a record whose session ended` (`:2199`) | expired → anonymous, no throw | `identity::expired_returns_anonymous` |
| `keeps a record a sibling has moved on, and stops claiming it` (`:2214`) | `drop` not `end` | `teardown::drop_not_end` |
| `drops the app credential too when the state names another account` (`:2246`) | app slot cleared on mismatch | `teardown::drops_app_on_mismatch` |
| `refuses to hand out an identity this origin cannot act with` (`:2277`) | `SessionNotHeld` guard | `identity::refuses_unactionable` |
| `clears the state storage on sign-out` (`:2302`) | state removed | `signout::clears_state` |
| `should remain anonymous with a key but no delegation` (`:2490`) | key without chain is not a session | `restore::key_without_chain` |
| `should clear storage when the delegation has expired` (`:2506`) | expired chain clears credentials | `restore::expired_chain` |
| `restores in a worker once the state store has loaded` (`:2372`) | `ready()` gate | `worker::ready` |
| `reads as signed in in a worker once ready` (`:2396`) | worker status | `worker::status` |
| `changes nothing shared in a worker` (`:2424`) | read-only enforcement | `worker::read_only` |
| `stops acting with a session a page ended, in a worker` (`:2443`) | worker follows page teardown | `worker::follows_page` |
| `stops acting with a restored session once its record is removed` (`:2472`) | live record removal | `worker::record_removed` |
| `should restore an existing Ed25519Key and delegation` (`:2352`) | legacy data migration | `restore::legacy_ed25519` |

## 11.2 Sign-in (`auth-client.test.ts:973-1500`)

| Test (line) | Asserts | Rust test target |
| --- | --- | --- |
| `should return the authenticated identity` (`:974`) | non-anonymous identity | `signin::returns_identity` |
| `should propagate signer errors from the delegation request` (`:981`) | signer error message surfaces | `signin::propagates_signer_error` |
| `fails the sign-in when the session granted has nothing left to mint against` (`:989`) | 1 ms session → `SessionGoneError`, nothing recorded | `signin::refuses_dead_session` |
| `asks for a session, carrying maxTimeToLive and no targets` (`:1012`) | method, `sessionPublicKey`, ns string TTL, **no targets** | `signin::request_shape` |
| `carries maxTimeToIdle where the application asked for one` (`:1033`) | `maxTimeToIdle` string | `signin::ttl_idle` |
| `omits maxTimeToIdle where it did not` (`:1044`) | absent, not defaulted | `signin::omits_idle` |
| `should forward derivationOrigin on every request as icrc95DerivationOrigin` (`:1057`) | transform applies to sign-in too | `signin::derivation_origin` |
| `should persist the key and its delegation as one record after sign-in` (`:1067`) | one `session` write with both halves | `signin::persists_credential` |
| `should generate a fresh key for each sign-in` (`:1079`) | two sign-ins, two keys | `signin::fresh_key_per_signin` |
| `should report the user as authenticated after sign-in` (`:1093`) | status flips | `signin::authenticated_after` |
| `reports a sign-in to another default client in the page at once` (`:1103`) | shared state store notifies peers | `signin::peers_notified` |
| `should report the user as not authenticated after sign-out` (`:1117`) | sign-out flips status | `signout::unauthenticated` |
| `records the account and the expiry in the supplied state storage` (`:1126`) | state record shape | `signin::state_record` |
| `names who is signed in synchronously, from the state` (`:1138`) | `getPrincipal` sync | `principal::sync_from_state` |
| `names nobody when no record exists` (`:1151`) | `None` | `principal::none_when_signed_out` |
| `names nobody for a session that has expired, and agrees with isAuthenticated` (`:1160`) | expired → `None` | `principal::none_when_expired` |
| `never disagrees with isAuthenticated` (`:1182`) | property over states | `principal::agrees_with_auth` |
| `answers isAuthenticated from the state storage and not from the delegation` (`:1201`) | state is the source | `status::from_state` |
| `restores a session and adopts the app credential rather than minting again` (`:1214`) | adoption | `restore::adopts_app_credential` |
| `mints on a load that finds no app credential, which is where the account comes from` (`:1239`) | mint on restore | `restore::mints_without_app` |
| `drops a session the state no longer names, as a sibling signing in elsewhere leaves it` (`:1269`) | state wins | `restore::state_wins` |
| `does not restore a session the state does not back, and drops it` (`:1301`) | no state → end session | `restore::no_state_ends` |
| `mints inside the ceremony, so the identity it returns already holds one` (`:1328`) | mint before return | `signin::mints_in_ceremony` |
| `records the account the mint reported, not the session chain it was signed with` (`:1347`) | account = mint root | `signin::account_from_mint` |
| `refuses a session chain issued to a different key` (`:1362`) | leaf-key check | `signin::refuses_foreign_chain` |
| `replaces the app credential rather than clearing it while signing in` (`:1379`) | overwrite, never empty | `signin::promote_overwrites` |
| `leaves the shared app credential alone when a ceremony fails` (`:1402`) | pending slot isolation | `signin::failure_leaves_app` |
| `ends the session at the canister when signing out` (`:1421`) | `app_revoke_session` called | `signout::revokes_session` |
| `asks for no lock before the signer window is open` (`:1436`) | lock order | `signin::lock_after_window` |
| `signs the device out and still raises a revoke the canister refused` (`:1472`) | wipe completes, error raised after | `signout::revoke_failure_raised_after_wipe` |
| `carries the configured canister and agent options to the minter` (`:1501`) | provider pair + agentOptions | `signin::passes_provider` |
| `takes the mint lock away on sign-out instead of queueing on it` (`:1516`) | steal semantics | `signout::steals_mint_lock` |
| `does not touch the mint lock on sign-out where no other tab can read the store` (`:1545`) | lock only when shared | `signout::no_lock_when_unshared` |
| `a sign-out is not undone by the sign-in it interrupted` (`:1574`) | supersede guard before writes | `signin::superseded_by_signout` |
| `a disposed client finishes no ceremony and writes nothing` (`:1619`) | dispose mid-ceremony | `dispose::mid_ceremony` |
| `disposing releases the locks it holds rather than taking any` (`:1653`) | release not steal | `dispose::releases_locks` |
| `supersedes the earlier of two sign-ins on one client` (`:1669`) | `SupersededError` | `signin::second_supersedes_first` |
| `the later of two sign-ins wins, and the earlier writes nothing` (`:1703`) | last writer wins | `signin::later_wins` |
| `clears both credentials on sign-out, not just the session` (`:1740`) | session + app | `signout::clears_both` |

## 11.3 `requestAttributes` (`auth-client.test.ts:2522-2642`)

Covered in `attributes-notifications-sso.md` §5.3. Rust target:
`attributes::*` (8 tests) + `redirect::nonce_journaled` + `redirect::nonce_replayed`.

## 11.4 Notification consent (`auth-client.test.ts:2644-2705`, `notification-consent.test.ts`)

| Test (line) | Asserts | Rust test target |
| --- | --- | --- |
| `should ask the provider and report what the user allowed` (`auth-client.test.ts:2645`) | method + granted | `consent::granted` |
| `should ask under the derivation origin it signs in under` (`:2655`) | `icrc95DerivationOrigin` | `consent::derivation_origin` |
| `should report a refusal rather than throwing` (`:2665`) | `granted:false` resolves | `consent::refusal_is_answer` |
| `should refuse to read a status without a session` (`:2672`) | `SessionGoneError` | `consent::status_requires_session` |
| `should refuse to withdraw without a session` (`:2678`) | `SessionGoneError` | `consent::revoke_requires_session` |
| `should refuse a session that ran out while the page stayed open` (`:2684`) | `isDelegationValid` check | `consent::expired_session_refused` |
| `sends the provider method and reports what it granted` (`notification-consent.test.ts:55`) | wire shape | `consent::request_shape` |
| `sends no derivation origin where the application has none` (`:65`) | `params:{}` | `consent::empty_params` |
| `passes the derivation origin…` (`:73`) | param present | `consent::derivation_param` |
| `reports a refusal as an answer` (`:83`) | – | `consent::refusal` |
| `names a provider that does not notify at all` (`:89`) | -32601 | `consent::unsupported` |
| `names a request that asked not to render` (`:97`) | 3002 | `consent::interaction_required` |
| `passes any other error through` (`:103`) | message | `consent::other_error` |
| `refuses a response that says nothing about consent` (`:109`) | non-boolean | `consent::invalid_result` |
| `reports what the canister recorded` (`:119`) | query decode | `consent::canister_status` |
| `turns NoSuchSession into the one terminal error` (`:129,163`) | `SessionGoneError` | `consent::no_such_session` |
| `carries the canister's own explanation` (`:139`) | `InternalCanisterError` text | `consent::internal_error_text` |
| `resolves where the canister withdrew the consent` (`:155`) | update ok | `consent::revoke_ok` |
| `raises a failed write rather than dropping it` (`:173`) | revoke failure | `consent::revoke_failure` |
| `refuses a chain that is not a session for the canister` (`:189`) | `assertChainReaches` | `consent::chain_scope` |

## 11.5 SSO (`sso.test.ts`, `auth-client.test.ts:2849-2964`)

| Test (line) | Asserts | Rust test target |
| --- | --- | --- |
| `normalizeSsoDomain` accept table (`sso.test.ts:12-24`) | 9 accepted inputs → outputs | `sso::normalize_accepts` |
| reject table (`:26-51`) | 23 rejected inputs | `sso::normalize_rejects` |
| `quotes the value in its error, cut to 100 characters` (`:53`) | message formatting | `sso::error_quoting` |
| `names every problem it finds` (`:61`) | aggregated reasons | `sso::error_lists_all` |
| `checks once as soon as it is built, then reads the status` (`:111`) | update then query | `sso::check_then_poll` |
| `reports available without a name` (`:122`) | `opt none` | `sso::available_no_name` |
| `reports unavailable with the time…` (`:128`) | `retryAfter` from ns | `sso::unavailable_retry_after` |
| `reports the reason…` (`:137`) | `reason` | `sso::unavailable_reason` |
| `reports unavailable without retryAfter when a retry cannot help` (`:150`) | absent field | `sso::unavailable_no_retry` |
| `polls the query with a backoff while pending, and checks only once` (`:156`) | 500→1000→2000 ms | `sso::backoff` |
| `stops polling on a final answer` (`:172`) | timer stops | `sso::stops_on_final` |
| `checks again once pending for the abandon window` (`:183`) | 120 s recheck | `sso::recheck_after_abandon` |
| `retries a status read that failed` (`:194`) | read failure retried | `sso::retries_read` |
| `still reads the status when the check update fails` (`:206`) | update failure tolerated | `sso::update_failure_tolerated` |
| `builds the service again when building it failed` (`:214`) | service retry | `sso::service_retry` |
| `keeps the same object until the answer changes` (`:226`) | stable value | `sso::stable_value` |
| `treats a value that is not a domain as invalid and never calls` (`:242`) | no canister call | `sso::invalid_never_calls` |
| `checks again on refresh, through checking` (`:255`) | `refresh()` | `sso::refresh` |
| `does not check again on its own once retryAfter passes` (`:270`) | no auto-retry | `sso::no_auto_retry` |
| `never calls when disposed before its first call` (`:282`) | dispose before start | `sso::dispose_before_start` |
| `stops polling when disposed, and drops an answer already in flight` (`:290`) | late answer dropped | `sso::dispose_drops_late` |
| `ignores refresh once disposed` (`:310`) | – | `sso::refresh_after_dispose` |
| `is undefined for a client built without ssoDomain…` (`auth-client.test.ts:2862`) | `None`, no call | `client::no_sso` |
| `checks the normalized domain against the configured Internet Identity` (`:2869`) | normalized, canisterId, agentOptions | `client::sso_uses_provider` |
| `never calls Internet Identity for an invalid domain` (`:2892`) | invalid reason | `client::sso_invalid` |
| `tells subscribers when the SSO status changes` (`:2902`) | subscribe fires | `client::sso_notifies` |
| `returns the same object until the answer changes` (`:2913`) | – | `client::sso_stable` |
| `checks again on refreshSsoStatus` (`:2920`) | refresh | `client::sso_refresh` |
| `stops checking once disposed` (`:2933`) | dispose | `client::sso_dispose` |
| `signs in normally while {invalid,checking,available,unavailable}` (`:2940`) | sign-in never gated | `client::sso_does_not_gate_signin` |

## 11.6 Redirect transport (`auth-client-redirect.test.ts`, `auth-client-redirect-replay.test.ts`)

| Test (line) | Asserts | Rust test target |
| --- | --- | --- |
| `refuses a redirect where no medium can answer for the key` (`:152`) | non-durable store, no request sent | `redirect::requires_durable` |
| `refuses a redirect where the only other reader is another tab` (`:165`) | `shared` is not enough | `redirect::shared_not_durable` |
| `refuses a redirect with a shared store that keeps nothing` (`:188`) | same | `redirect::shared_memory_refused` |
| `routes sign-in through the URL transport and cleans up the pending key` (`:200`) | journal slots, pending removed | `redirect::completes_and_cleans` |
| `completes sign-in even if pending-key cleanup fails` (`:219`) | cleanup best-effort | `redirect::cleanup_failure_ok` |
| `journals a validated returnTo…` (`:235`) | absolute href journaled | `redirect::journals_return_to` |
| `journals nothing for a returnTo this origin may not navigate to` (`:252`) | `null` journaled | `redirect::journals_null_return_to` |
| `journals the derivation origin so it survives the redirect` (`:266`) | slot 0 replay | `redirect::derivation_origin_survives` |
| `derives the callback URL from the current location` (`:293`) | origin+pathname | `redirect::callback_url` |
| `reuses the session key across the redirect` (`:299`) | same `sessionPublicKey` on both loads | `redirect::reuses_session_key` |
| `refuses to finish when another sign-in took the pending slot` (`:329`) | superseded message | `redirect::superseded_pending` |
| `memoize journals a caller value and replays it` (`:352`) | producer runs once | `redirect::memoize_replays` |
| `memoizes the nonce and forwards it as base64` (`:376`) | slot 1 base64 | `redirect::nonce_journaled` |
| `reuses the memoized nonce across the redirect` (`:394`) | not re-fetched | `redirect::nonce_replayed` |
| `completes signIn and requestAttributes issued together…` (2 cases) (`replay:108-156`) | real `UrlTransport` batch + call-order slots + nonce slow only on load 1 | `redirect::real_transport_batch` (both orderings) |

## 11.7 Session layer (`session-identity.test.ts` 779 lines, `session-minter.test.ts`, `app-lock.test.ts`)

| Test (line) | Asserts | Rust test target |
| --- | --- | --- |
| `is a DelegationIdentity…` (`session-identity.test.ts:98`) | identity subtype | `session_identity::is_delegation_identity` |
| `answers for the account principal before anything is minted` (`:104`) | stable account principal | `session_identity::account_before_mint` |
| `mints on the first request and reuses it` (`:110`) | lazy mint | `session_identity::mints_once` |
| `serves concurrent requests from one mint` (`:117`) | single-flight | `session_identity::single_flight` |
| `signs with the delegation it holds` (`:123`) | signature path | `session_identity::signs` |
| `replaces the delegation on schedule when it was used` (`:129`) | timer rotation | `session_identity::rotates_on_schedule` |
| `keeps the account principal across a rotation` (`:138`) | stable principal | `session_identity::principal_stable` |
| `mints again after a failed mint` (`:151`) | failure not latched | `session_identity::retries_after_failure` |
| `lets an unused delegation lapse instead of refreshing it` (`:161`) | `current_was_used` gate | `session_identity::unused_lapses` |
| `serves a request inside the threshold and mints behind it` (`:173`) | 10–15 s window | `session_identity::serves_while_reminting` |
| `waits for a mint inside the block margin` (`:186`) | < 10 s | `session_identity::blocks_inside_margin` |
| `refresh() mints when one is due` (`:199`) | refresh | `session_identity::refresh_mints` |
| `rotates a delegation activity kept alive, though nothing signed with it` (`:210`) | refresh counts as use | `session_identity::refresh_counts_as_use` |
| `refresh() does nothing when the delegation is healthy` (`:228`) | no mint | `session_identity::refresh_noop_when_healthy` |
| `reports a gone session once, and only for NoSuchSession` (`:235`) | `onSessionGone` once | `session_identity::reports_gone_once` |
| `stops asking, and leaves the session alone, when it cannot act for it` (`:246`) | unsupported latched | `session_identity::unsupported_latched` |
| `keeps the session when a mint fails for any other reason` (`:268`) | retryable | `session_identity::keeps_session_on_other_error` |
| `does not mint against a session with nothing left` (`:278`) | session expiry | `session_identity::refuses_dead_session` |
| `refuses a delegation rooted at another account` (`:288`) | `AccountMismatch` | `session_identity::account_mismatch` |
| `refuses a delegation issued to a key it did not make` (`:301`) | leaf check | `session_identity::leaf_check` |
| `makes a fresh key for every mint` (`:310`) | key never outlives delegation | `session_identity::fresh_key_per_mint` |
| `persists what it mints` (`:319`) | store write | `session_identity::persists` |
| `adopts what the store already holds instead of minting` (`:327`) | adoption | `session_identity::adopts` |
| `mints when the store holds one too close to expiry` (`:343`) | threshold | `session_identity::mints_near_expiry` |
| `ignores a stored credential rooted at another account` (`:355`) | verify | `session_identity::ignores_foreign_credential` |
| `writes nothing when a sign-out takes the lock away mid-mint` (`:373`) | stolen signal | `session_identity::stolen_lock_discards` |
| `resolves its account key from a credential the store already holds` (`:429`) | account resolution | `session_identity::account_from_store` |
| `mints under the lock to establish an account key when the store has none` (`:456`) | account from mint | `session_identity::account_from_mint` |
| `adopts a peer credential written while it queued` (`:496`) | read inside lock | `session_identity::adopts_peer` |
| `will not adopt a credential left by another account` (`:528`) | verify | `session_identity::rejects_foreign_adopt` |
| `mints rather than adopting when no account is named` (`:563`) | `adopt = expected.is_some()` | `session_identity::mints_without_account` |
| `refuses to build against a session with nothing left` (`:587`) | create guard | `session_identity::create_refuses_dead` |
| `removes a stored credential whose delegation has run out` (`:608`) | eviction under lock | `session_identity::evicts_spent` |
| `never removes a spent credential before it holds the lock` (`:637`) | lock-free read declines only | `session_identity::no_evict_without_lock` |
| `keeps a credential it declines only for being close to expiry` (`:674`) | – | `session_identity::keeps_near_expiry` |
| `reads, writes and locks on the slot it was given` (`:699`) | slot passed through | `session_identity::uses_given_slot` |
| `takes no lock where no other tab can read the store` (`:721`) | `lockNameFor` | `session_identity::no_lock_unshared` |
| `mints while holding the lock where another tab can read the store` (`:732`) | lock when shared | `session_identity::locks_when_shared` |
| `does not let a glance at a healthy tab cancel its own rotation` (`:748`) | – | `session_identity::glance_does_not_cancel` |
| `uses a credential it minted even when it cannot be stored` (`:761`) | write failure tolerated | `session_identity::write_failure_tolerated` |
| `stops scheduling once disposed` (`:770`) | dispose clears timer | `session_identity::dispose_stops_timer` |
| `unwrapSessionResult` ×4 (`session-minter.test.ts:47-82`) | error mapping | `minter::unwrap_*` |
| `appDelegationChain` ×5 (`:84-116`) | chain construction, targets/permissions | `minter::chain_*` |
| `assertChainReaches` ×7 (`:117-183`) | scope rules | `minter::assert_chain_reaches_*` |
| `prepares again when the canister signed nothing…` (`:193`) | one retry | `minter::retries_once` |
| `gives up after the second attempt` (`:211`) | exactly two | `minter::gives_up_after_two` |
| `does not retry a session that is gone` (`:222`) | `SessionGone` not retried | `minter::no_retry_when_gone` |
| `raises a revoke the canister refused` (`:233`) | revoke error | `minter::revoke_error` |
| `treats a session already gone as a revoke that succeeded` (`:245`) | idempotent | `minter::revoke_gone_ok` |
| `withMintLock` ×7 (`app-lock.test.ts:76-212`) | run/serialise/steal/no-lock | `lock::with_mint_lock_*` |
| `stealLock` ×6 (`:213-275`) | hold/steal/release/no-lock | `lock::steal_lock_*` |

## 11.8 Storage and refresh (`credentials/*.test.ts`, `state/*.test.ts`, `foreground-refresh.test.ts`, `db*.test.ts`)

| Area | Tests | Rust target |
| --- | --- | --- |
| `MemoryCredentialStorage` (5) `credential-storage.test.ts:15-60` | flags, no copy, slots, per-instance, non-extractable | `storage::memory_*` |
| `LocalCredentialStorage` (6) `:62-111` | flags, string round-trip, serialisable key, shared prefix, prefix isolation, bad record | `storage::local_*` |
| `IdbCredentialStorage` (7) `idb-credential-storage.test.ts:29-107` | flags, one record, key-only record, non-extractable, bad record, single open, no cached failure | `storage::idb_*` |
| `SharedMemoryCredentialStorage` (13) `shared-memory-credential-storage.test.ts:67-260` | flags, replication put/drop, cold start, peer gone, stale offer, non-exportable handle, foreign message, closed, names, no locks | `storage::shared_memory_*` |
| `LocalStateStorage` (30) `local-state-storage.test.ts` | encode `<principal>\|<expiration>`, bigint, cross-tab, worker mirror, ready ordering, listener lifecycle, upgrade compat | `state::local_*` |
| `CookieStateStorage` (24) `cookie-state-storage.test.ts` | held derivation, discard vs remove, domain validation, probe, cookie events, worker | `state::cookie_*` |
| `MemoryStateStorage` (9) `memory-state-storage.test.ts` | held, isolation, change-only notification | `state::memory_*` |
| `watchForeground` (7) `foreground-refresh.test.ts:13-77` | visible/focus/pageshow, no DOM | `refresh::watch_foreground_*` |
| `watchActivity` (6) `:79-136` | every event, no throttle, no DOM | `refresh::watch_activity_*` |
| `IdbKeyVal` (3+2) `db.test.ts`, `db-recovery.test.ts` | basic kv, CryptoKeyPair, force-close recovery | `storage::db_*` |
| `slotsFor` `slots.test.ts` (27 lines) | all five names, namespace prefix | `slots::*` |

## 11.9 How to port: recommended order

1. **Pure functions first** (no DOM, no network): `normalizeSsoDomain`, `scopedKeys`,
   `slotsFor`, `sameOriginTarget`, `sameStatus`, `expiresAtMs`/`earliestExpiration`,
   `assertChainReaches`, `chainAuthorisesKey`, `appDelegationChain`, `unwrapSessionResult`,
   `requestKey` fingerprint. These are exact-value tests and give the fastest signal.
2. **Storage traits** with memory implementations; run the credential/state test tables.
3. **JSON-RPC + fake transports** (`FakeTransport`, `FakeUrlTransport` equivalents), then
   `Signer` lifecycle tests (`auth-client.test.ts:2707-2790`, `fake-transport.test.ts`).
4. **Sign-in window flow** against the fake transport; then redirect flow against the fake
   URL transport; then `auth-client-redirect-replay.test.ts` against the real journal.
5. **Session identity + minter + locks** with the mocked minter and lock stub.
6. **SSO + notification consent** with mocked canister services.
7. **Browser-only last**: real Web Locks, real IndexedDB, real `window.open`, worker mode —
   these need `wasm-bindgen-test` in a browser (the crate already has
   `wasm-bindgen-test` in dev-dependencies).

## Rust port checklist

- [ ] Port the two fake transports first; every protocol test depends on them.
- [ ] Port the mocked `SessionMinter` / SSO service / Web Locks stub as test utilities.
- [ ] Port the §11.1–§11.7 tables as named Rust tests, keeping the upstream test name as a
      doc comment so coverage is auditable.
- [ ] Assert *messages*, not just outcomes, for: `ii_session_delegation`,
      `ii-icrc3-attributes`, `ii_notification_consent`, `icrc29_status`.
- [ ] Assert *nothing is written* in the failure/supersede/dispose cases — upstream does,
      and it is where ports usually diverge.
- [ ] Keep the browser-only cases (worker mode, real locks, real IDB) as
      `wasm-bindgen-test` behind `wasm-js`.
