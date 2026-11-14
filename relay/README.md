# The ICRC-167 relay pages

Two static pages that let a native application sign in over ICRC-167, plus the
allow-list the signer requires. They are the browser half of
[`NativeUrlTransport`](../src/client/transport/native_url.rs); the design is in
[`docs/port/native-icrc167.md`](../docs/port/native-icrc167.md).

The pages hold **no secrets**. The request travels in the URL fragment (never in
a request line, so neither this origin's server nor the signer's backend sees
it), the pages keep only the loopback port and a single-use token in this tab's
`sessionStorage`, and the answer is a delegation chain, which is useless without
the private key that stays in the native process.

## What to deploy

Deploy the directory at the **origin root** of a public HTTPS origin, e.g.
`https://app.example`:

| File | Served at |
| --- | --- |
| `auth/index.html` | `https://app.example/auth/` |
| `auth/callback.html` | `https://app.example/auth/callback` |
| `.well-known/ii-auth-callbacks` | `https://app.example/.well-known/ii-auth-callbacks` |
| `_headers` | (used by Netlify/Cloudflare Pages; not served) |

Then:

1. Replace `https://app.example` in `.well-known/ii-auth-callbacks` with your
   origin. It must list the callback **byte-for-byte**, same origin, no
   fragment: `{"callbacks":["https://app.example/auth/callback"]}`.
2. Serve the well-known file as `application/json`, with
   `Access-Control-Allow-Origin: *` and `Cache-Control: no-store`, and no
   redirects. The signer re-fetches it on every sign-in and fails closed.
   `_headers` does this on Netlify and Cloudflare Pages; GitHub Pages cannot set
   headers, so use a host that can (or serve it from your own server).
3. Keep the callback page a **terminal response**: it must not redirect (the
   delegation lives in its fragment; a redirect would forward it elsewhere).

## Configure the application

```rust
use ic_auth_client::client::{
    AuthClient, AuthClientCreateOptions, NativeRelayOptions,
};

let client = AuthClient::new(AuthClientCreateOptions {
    native_relay: Some(NativeRelayOptions {
        relay_origin: "https://app.example".to_string(),
        ..Default::default()
    }),
    ..Default::default()
})?;
let identity = client.sign_in(Default::default()).await?;
```

Without `native_relay` the client keeps using the identity provider's
non-browser ("CLI") flow, which needs no domain but asks the user to enable CLI
access for the app's identity.

## Keep the principal the same as the web sign-in

The relying-party origin is the **callback origin**, and the signer derives this
sign-in's principal from it. Hosting the relay on the application's own origin
therefore gives the same principal as the application's web sign-in.

If the relay lives on a different origin than the application (say
`https://auth.app.example` while the principal should derive as
`https://app.example`), set `AuthClientCreateOptions::derivation_origin` to the
application's origin and publish
`https://app.example/.well-known/ii-alternative-origins` listing the relay
origin:

```json
{"alternativeOrigins": ["https://auth.app.example"]}
```

The signer refuses a derivation origin that does not declare the relying party
("Unverified origin"), so a shared relay domain cannot impersonate an
application.

## Verify it

Locally, in a headless browser, against a scripted signer and a scripted loopback
listener (needs a ChromeDriver matching your Chrome):

```bash
python3 relay/selftest.py --chromedriver /path/to/chromedriver
# or: make relay-test CHROMEDRIVER=/path/to/chromedriver
```

It checks the fragment hand-off, the same-origin callback rule, the
one-request-per-navigation rule, and the token check. Against a real signer:

```bash
curl -s https://app.example/.well-known/ii-auth-callbacks
# then run the application with native_relay configured and sign in
```

## Known limits

- **One request per message, one tab per ceremony.** The signer does not answer
  JSON-RPC batches (measured against id.ai), so a multi-step ceremony
  (attributes, notification consent) is several navigations. They stay in one
  tab: the callback page long-polls the application for the next request and
  navigates again. A page deployed before this protocol, or a tab the user
  closed, degrades to "one new tab per step".
- **Browsers differ on the loopback report.** The callback page POSTs from a
  public HTTPS origin to `http://127.0.0.1`. Chrome and Firefox allow it (the
  transport answers the Private Network Access preflight); **Safari blocks it
  as mixed content**. For Safari the callback page navigates to a page the
  listener serves (`/icrc167/handoff`), which reports same-origin and can still
  continue the ceremony in the same tab. Nothing changes for Chrome and
  Firefox, and the pages you deploy are the same. Verified on 2026-11-15:
  Chrome 157, Firefox 158.0.1, Safari 27.2.
- **Windows may prompt for firewall access** the first time a loopback listener
  is bound.
