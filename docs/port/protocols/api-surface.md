# §1 — Public API surface of `@icp-sdk/auth` v11.2.0

Two entry points exist. The root entry point **throws on import**:

```ts
// src/index.ts:1-3
throw new Error(
  'There are no exports in the root module of this package. Import from submodules instead. …',
);
```

So `@icp-sdk/auth/client` is the only usable surface (package.json:17-27 maps
`.` and `./client` to `dist/esm/client/index.js`).

## 1.1 Re-export graph

`src/client/index.ts:5-38` is the complete list. `export *` at line 5 means every
export of `auth-client.ts` is public.

| Export | Kind | Defined at |
| --- | --- | --- |
| `AuthClient` | class | `src/client/auth-client.ts:388` |
| `AuthClientBaseOptions` | interface | `auth-client.ts:78-231` |
| `AuthClientCreateOptions` | type (union) | `auth-client.ts:239-271` |
| `AuthClientSignInOptions` | interface | `auth-client.ts:276-300` |
| `SignedAttributes` | interface | `auth-client.ts:302-305` |
| `SessionStatus` | type (union) | `auth-client.ts:324-332` |
| `SessionNotHeldError` | class | `auth-client.ts:342-349` |
| `SupersededError` | class | `auth-client.ts:381-386` |
| `OpenIdProvider` | type | `auth-client.ts:62` |
| `OPENID_PROVIDER_URLS` | const | `auth-client.ts:64-68` |
| `scopedKeys` | function (2 overloads) | `auth-client.ts:1921-1971` |
| `Credential`, `CredentialStorage` | types | `credentials/credential-storage.ts:12-20,32-56` |
| `IdbCredentialStorage` | class | `credentials/idb-credential-storage.ts:20` |
| `LocalCredentialStorage` | class | `credentials/local-credential-storage.ts:19` |
| `MemoryCredentialStorage` | class | `credentials/memory-credential-storage.ts:15` |
| `SharedMemoryCredentialStorage`, `DEFAULT_SHARED_MEMORY_NAME` | class, const | `credentials/shared-memory-credential-storage.ts:78,5` |
| `DB_VERSION`, `DBCreateOptions`, `IdbKeyVal` | const, type, class | `db.ts:4,49-53,59` |
| `watchActivity`, `watchForeground` | functions | `foreground-refresh.ts:72,17` |
| `NotificationConsent` | class | `notification-consent.ts:158` |
| `NotificationConsentOptions`, `NotificationConsentService`, `NotificationConsentStatus` | types | `notification-consent.ts:140-155,98-101,30-32` |
| `NotificationsUnsupportedError` | class | `notification-consent.ts:41-46` |
| `requestNotificationConsent` | function | `notification-consent.ts:63-91` |
| `AppDelegationSource` | type | `session/app-delegation-source.ts:56-66` |
| `SessionGoneError` | class | `session/app-delegation-source.ts:12-17` |
| `InteractionRequiredError` | class | `session/session-delegation.ts:33-50` |
| `requestSessionDelegation` | function | `session/session-delegation.ts:103-148` |
| `SessionIdentity`, `SessionIdentityOptions` | class, type | `session/session-identity.ts:241,190-225` |
| `SessionMinter`, `SessionMinterOptions` | class, type | `session/session-minter.ts:133,115-130` |
| `SsoStatus` | type | `sso.ts:128-132` |
| `CookieStateStorage`, `CookieStateStorageOptions` | class, type | `state/cookie-state-storage.ts:59,30-41` |
| `LocalStateStorage` | class | `state/local-state-storage.ts:38` |
| `MemoryStateStorage` | class | `state/memory-state-storage.ts:10` |
| `SessionState`, `StateStorage` | types | `state/state-storage.ts:11-27,40-112` |

**Deliberately *not* exported from `index.ts`** (module-internal but importable by
deep path; a Rust port should treat them as internal):

`normalizeSsoDomain`, `SsoStatusChecker`, `SsoDomainService`, `SSO_POLL_MIN_MS`,
`SSO_POLL_MAX_MS`, `SSO_RECHECK_AFTER_MS` (`sso.ts`); `SessionUnsupportedError`,
`AccountMismatchError`, `sameKey`, `delegatesTo`, `chainAuthorisesKey`
(`session/app-delegation-source.ts`); `unwrapSessionResult`, `appDelegationChain`,
`assertChainReaches` (`session/session-minter.ts`); `withMintLock`, `stealLock`,
`stealMintLock`, `HeldLock` (`session/app-lock.ts`); `slotsFor`, `Slots`, `SLOT_NAMES`
(`slots.ts`); `readOnlyError` (`state/local-state-storage.ts`); `NoSuchDelegationError`
(`session-minter.ts:91-96`).

## 1.2 Exact TypeScript signatures

### 1.2.1 `AuthClient` class (`auth-client.ts:388-1864`)

```ts
export class AuthClient {
  constructor(options: AuthClientCreateOptions = {});       // :427
  ready(): Promise<void>;                                   // :610
  getIdentity(): Promise<Identity>;                         // :617
  isAuthenticated(): boolean;                               // :653
  getPrincipal(): Principal | undefined;                    // :678
  getStatus(): SessionStatus;                               // :688
  getSsoStatus(): SsoStatus | undefined;                    // :728
  refreshSsoStatus(): void;                                 // :742
  subscribe(listener: () => void): () => void;              // :782
  dispose(): void;                                          // :798
  signIn(options?: AuthClientSignInOptions): Promise<Identity>;          // :923
  signOut(options: { returnTo?: string } = {}): Promise<void>;           // :1389
  requestAttributes(params: {
    keys: string[];
    nonce: () => Promise<Uint8Array>;
  }): Promise<SignedAttributes>;                                          // :1187
  requestNotificationConsent(): Promise<NotificationConsentStatus>;       // :1265
  revokeNotificationConsent(): Promise<void>;                             // :1288
  getNotificationConsentStatus(): Promise<NotificationConsentStatus>;     // :1305
  memoize<T>(produce: () => Promise<T>): Promise<T>;                      // :1374
  memoize<T>(produce: () => T): T;                                        // :1375
}
```

There is **no `create()` static** and **no `logout()`** (`logout`→`signOut` was the
v7 breaking change, `CHANGELOG.md` under 7.0.0).

### 1.2.2 Create options (`auth-client.ts:78-271`)

`AuthClientBaseOptions` (`:78-231`):

| Field | Type | Default | Line |
| --- | --- | --- | --- |
| `credentialStorage` | `CredentialStorage` | `new IdbCredentialStorage()` | `:82`, applied `:429` |
| `namespace` | `string` | `undefined` (bare slot names) | `:94`, applied `:430` |
| `stateStorage` | `StateStorage` | shared `LocalStateStorage` per page/worker | `:102`, `:367-371,431` |
| `disableBrowserActivity` | `boolean` | `false` | `:120`, `:460-471` |
| `identityProvider` | `{ authorizeUrl: string \| URL; canisterId: Principal \| string }` | `{ authorizeUrl: 'https://id.ai/authorize', canisterId: 'rdmx6-jaaaa-aaaaa-aaadq-cai' }` | `:132-138`, `:59-60,443-446` |
| `agentOptions` | `Omit<HttpAgentOptions, 'identity'>` | `undefined` | `:146` |
| `derivationOrigin` | `string \| URL` | `undefined` | `:152` |
| `windowOpenerFeatures` | `string` | `''` (transport default) | `:158` |
| `transport` | `'window' \| 'redirect'` | `'window'` | `:182`, `:557-569` |
| `prompt` | `'none' \| 'login'` | omitted (= login) | `:199`, `:544-546` |
| `hint` | `Principal` | `undefined` | `:209`, `:547-549` |
| `resumable` | `boolean` | `stateStorage.resumable ?? false` | `:230`, `:553-555` |

`AuthClientCreateOptions` (`:239-271`) adds a mutually exclusive one-click entry point:

```ts
| { openIdProvider?: OpenIdProvider; ssoDomain?: never }
| { openIdProvider?: never;        ssoDomain?: string }
```

`openIdProvider: 'google' | 'apple' | 'microsoft'` maps to
`OPENID_PROVIDER_URLS` (`:64-68`):

| provider | URL |
| --- | --- |
| `google` | `https://accounts.google.com` |
| `apple` | `https://appleid.apple.com` |
| `microsoft` | `https://login.microsoftonline.com/{tid}/v2.0` |

### 1.2.3 Sign-in options (`auth-client.ts:276-300`)

| Field | Type | Notes |
| --- | --- | --- |
| `maxTimeToLive` | `bigint` (ns) | sent only when set (`:986`) |
| `maxTimeToIdle` | `bigint` (ns) | sent only when set (`:987`) |
| `returnTo` | `string` | same-origin `http(s)` only; journaled in redirect mode (`:953-955,1440-1451`) |

### 1.2.4 Result / state / error types

```ts
// auth-client.ts:302-305
export interface SignedAttributes { data: Uint8Array; signature: Uint8Array; }

// auth-client.ts:324-332
export type SessionStatus =
  | { state: 'signed-in';           principal: Principal; expiresAtMs: number }
  | { state: 'signed-in-elsewhere'; principal: Principal; expiresAtMs: number }
  | { state: 'expired';             principal: Principal; expiresAtMs: number }
  | { state: 'signed-out' };

// sso.ts:128-132
export type SsoStatus =
  | { state: 'checking' }
  | { state: 'available'; name?: string }
  | { state: 'invalid'; reason: string }
  | { state: 'unavailable'; retryAfter?: Date; reason?: string };

// notification-consent.ts:30-32
export interface NotificationConsentStatus { granted: boolean; }
```

Error classes, all `extends Error` with `this.name` set:

| Error | Thrown by | Line |
| --- | --- | --- |
| `SessionNotHeldError` (default message `'A sign-in exists for this domain, but this origin holds no credential for it'`) | `getIdentity()` | `auth-client.ts:342-349,645` |
| `SupersededError` (default `'A later sign-in or sign-out took over from this one'`) | sign-in superseded | `auth-client.ts:381-386,913-920` |
| `SessionGoneError` (default `'The session behind this identity no longer exists'`) | mint/revoke/consent | `session/app-delegation-source.ts:12-17` |
| `InteractionRequiredError` (`reason?: string`) | 3002 denial | `session/session-delegation.ts:33-50,119-126` |
| `NotificationsUnsupportedError` (default `'This Internet Identity does not send notifications'`) | -32601 | `notification-consent.ts:41-46,77-79` |
| `SessionUnsupportedError` (not package-exported) | read-only session | `app-delegation-source.ts:28-33` |
| `AccountMismatchError` (not package-exported) | mint roots elsewhere | `app-delegation-source.ts:42-47` |

### 1.2.5 Storage contracts

```ts
// credentials/credential-storage.ts:12-56
export interface Credential<T extends SignIdentity = SignIdentity> {
  identity: T;
  chain?: DelegationChain;         // absent only for a ceremony's pending key
}
export interface CredentialStorage<T extends SignIdentity = SignIdentity> {
  readonly shared: boolean;        // another tab of this origin reads it
  readonly durable: boolean;       // survives document teardown
  create(): Promise<T>;            // fresh key of the store's medium
  get(slot: string): Promise<Credential<T> | null>;
  set(slot: string, credential: Credential<T>): Promise<void>;
  remove(slot: string): Promise<void>;
}

// state/state-storage.ts:11-112
export interface SessionState {
  principal: Principal;
  expiration: bigint;              // ns since epoch, matches Delegation.expiration
  held: boolean;                   // derived on read, never published
}
export interface StateStorage {
  get(key: string): SessionState | null;                  // synchronous
  set(key: string, state: Omit<SessionState, 'held'>): void;
  remove(key: string): void;      // retracts shared record too
  discard(key: string): void;     // drops this origin's claim only
  readonly resumable?: boolean;
  subscribe(key: string, listener: () => void): () => void;
  readonly isReadOnly?: boolean;
  ready?(): Promise<void>;
}
```

Storage implementations and their flags:

| Class | `shared` | `durable` | key type | source |
| --- | --- | --- | --- | --- |
| `IdbCredentialStorage` | `true` | `true` | `ECDSAKeyIdentity` (non-extractable `CryptoKeyPair`) | `credentials/idb-credential-storage.ts:20-82` |
| `LocalCredentialStorage` | `true` | `true` | `Ed25519KeyIdentity` (serialisable) | `credentials/local-credential-storage.ts:19-68` |
| `MemoryCredentialStorage` | `false` | `false` | `ECDSAKeyIdentity` | `credentials/memory-credential-storage.ts:15-41` |
| `SharedMemoryCredentialStorage` | `true` | `false` | `ECDSAKeyIdentity`, `BroadcastChannel` replication | `credentials/shared-memory-credential-storage.ts:78-303` |

| State class | `resumable` | `isReadOnly` | medium | source |
| --- | --- | --- | --- | --- |
| `LocalStateStorage` | – | `!hasLocalStorage()` (worker) | `localStorage` `<principal>\|<expiration>`, IDB mirror for workers | `state/local-state-storage.ts:38-216` |
| `CookieStateStorage` | `true` | delegates to its `LocalStateStorage` | cookie `<principal>\|<expiration>`, 400-day Max-Age | `state/cookie-state-storage.ts:59-304` |
| `MemoryStateStorage` | – | – | `Map` | `state/memory-state-storage.ts:10-75` |

### 1.2.6 Session-layer signatures

```ts
// session/session-delegation.ts:103-106
export function requestSessionDelegation(
  signer: Signer,
  params: SessionDelegationParams | Promise<SessionDelegationParams>,
): Promise<DelegationChain>;

// session/session-minter.ts:115-130,133
export interface SessionMinterOptions {
  sessionKey: SignIdentity;
  sessionChain: DelegationChain;
  canisterId: Principal;
  agentOptions?: Omit<HttpAgentOptions, 'identity'>;
}
export class SessionMinter implements AppDelegationSource {
  static create(options: SessionMinterOptions): Promise<SessionMinter>;  // :140
  mint(appPublicKey: DerEncodedPublicKey): Promise<DelegationChain>;     // :161
  revoke(): Promise<void>;                                              // :180
}

// session/session-identity.ts:190-225,241
export interface SessionIdentityOptions {
  accountKey: DerEncodedPublicKey;      // constructor-only form
  sessionExpiresAtMs: number;
  source: AppDelegationSource;
  storage: CredentialStorage;
  slot: string;
  onSessionGone: () => void;
}
export class SessionIdentity extends DelegationIdentity {
  static create(options: Omit<SessionIdentityOptions, 'accountKey'> & {
    expectedAccount?: Principal;
  }): Promise<SessionIdentity>;                                        // :278
  override getDelegation(): DelegationChain;                           // :332
  override transformRequest(request: HttpAgentRequest): Promise<unknown>; // :336
  refresh(): Promise<void>;                                            // :360
  dispose(): void;                                                     // :383
}

// notification-consent.ts:63,98-101,140-155,158
export function requestNotificationConsent(
  signer: Signer, derivationOrigin?: string,
): Promise<NotificationConsentStatus>;
export interface NotificationConsentService {
  app_notification_consent_status(): Promise<Result<{ is_granted: boolean }>>;
  app_revoke_notification_consent(): Promise<Result<null>>;
}
export class NotificationConsent {
  static create(options: NotificationConsentOptions): Promise<NotificationConsent>;
  status(): Promise<NotificationConsentStatus>;
  revoke(): Promise<void>;
}

// foreground-refresh.ts:17,72
export function watchForeground(onForeground: () => void): (() => void) | undefined;
export function watchActivity(onActivity: () => void): (() => void) | undefined;
```

### 1.2.7 `scopedKeys` (`auth-client.ts:1921-1971`)

```ts
scopedKeys({ openIdProvider: 'google', keys?: readonly K[] })
  // -> `openid:${OPENID_PROVIDER_URLS[P]}:${K}[]`, default keys ['name','email','verified_email'] (:70)
scopedKeys({ ssoDomain: 'dfinity.org', keys?: readonly K[] })
  // -> `sso:${Lowercase<D>}:${K}[]`, default keys ['name','email'] (:72), domain normalized (:1961)
```
Throws `'openIdProvider and ssoDomain are mutually exclusive'` (`:1957-1959`), and
`'scopedKeys requires either openIdProvider or ssoDomain'` (`:1965-1967`).

## 1.3 Diff against the current Rust crate (`rust:src/lib.rs`, `rust:src/option.rs`)

| Upstream v11 | Rust 0.5.0-beta.0 today | Action |
| --- | --- | --- |
| `new AuthClient(options)` | `AuthClient::builder()…build()` (`rust:src/auth_client/wasm_js.rs:127,1505-1600`) | Replace builder with an options struct + `new`; keep a `bon` builder only as sugar if desired |
| `signIn()` | `login()` / `login_with_options()` (`wasm_js.rs:1140-1145`) | Rename; return `Result<Arc<dyn Identity>>` instead of callbacks |
| `signOut()` | `logout()` (`wasm_js.rs`, `native.rs:1094`) | Rename; make async (revoke call + storage wipe) |
| `getIdentity(): Promise<Identity>` | `identity(): Arc<dyn Identity>` (sync) | Make async; add `SessionNotHeldError` path |
| `getPrincipal()` | `principal() -> Result<Principal,String>` (sync) | Return `Option<Principal>`; `None` unless `signed-in` |
| `getStatus()` | — | **New**: `SessionStatus` enum |
| `isAuthenticated()` | `is_authenticated()` | Keep, but read state store not delegation |
| `ready()` | — | **New** (worker/async state load) |
| `subscribe`/`dispose` | `on_idle`/`IdleManager` (`rust:src/idle_manager.rs`) | **New**; delete idle manager |
| `requestAttributes({keys, nonce})` | — | **New** (v8 protocol) |
| notification consent ×3 | — | **New** (v11.1) |
| `getSsoStatus`/`refreshSsoStatus` | — | **New** (v11.0) |
| `memoize` | — | **New** (v8 redirect) |
| `credentialStorage` / `stateStorage` / `namespace` | `storage` + `key_type` (`rust:src/option/wasm_js.rs`) | Replace; delete `key_type` (store owns key type) |
| `identityProvider: {authorizeUrl, canisterId}` | `identity_provider: Option<String>` (`rust:src/option.rs:21`) | Replace; string/URL must `TypeError`-equivalent (`auth-client.ts:437-441`) |
| `transport`, `prompt`, `hint`, `resumable`, `agentOptions`, `ssoDomain`, `openIdProvider`, `disableBrowserActivity` | — | **New** |
| `maxTimeToLive` only | `max_time_to_live`, `allow_pin_authentication`, `custom_values`, `timeout`, `on_success`, `on_error`, `window_opener_features`, `derivation_origin` (`option.rs:19-57`) | Keep TTL/derivation/window features; drop the rest (no equivalent in v11) |
| `OPENID_PROVIDER_URLS`, `scopedKeys` | — | **New** pure functions (easy port) |

## Rust port checklist

- [ ] Replace `AuthClientBuilder` + `AuthClientLoginOptions` with `AuthClientCreateOptions`
      and `AuthClientSignInOptions` mirroring §1.2.2/1.2.3 exactly (field names, defaults).
- [ ] Make `identityProvider` a `{ authorize_url, canister_id }` pair; default to
      `https://id.ai/authorize` / `rdmx6-jaaaa-aaaaa-aaadq-cai`; reject a bare string with a
      typed error naming the new shape.
- [ ] Add `SessionStatus`, `SsoStatus`, `SignedAttributes`, `NotificationConsentStatus`
      and the error enum variants (`SessionNotHeld`, `Superseded`, `SessionGone`,
      `InteractionRequired{reason}`, `NotificationsUnsupported`).
- [ ] Add `ready()`, `get_status()`, `get_sso_status()`, `refresh_sso_status()`,
      `subscribe()`, `dispose()`, `request_attributes()`, the three notification-consent
      methods, `memoize()`.
- [ ] Split `storage` into `CredentialStorage` + `StateStorage` traits with the
      `shared`/`durable`/`resumable`/`is_read_only` capability flags; delete `key_type`.
- [ ] Delete `IdleManager` and its options; move "session ended" to `SessionStatus::Expired`.
- [ ] Port `OPENID_PROVIDER_URLS` and `scoped_keys` verbatim (pure, no I/O).
