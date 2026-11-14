# ICRC-167 conformance probe

Answers one question before we commit to replacing the native Internet
Identity CLI flow with ICRC-167: **what exactly does `https://id.ai/authorize`
accept over its URL transport?**

The crate's v11 sign-in talks to the signer with `ii_session_delegation`, an
Internet Identity extension. Native ICRC-167 clients in the wild
([ICNativeClient](https://github.com/humandebri/ICNativeClient)) ask for a
delegation with `icrc34_delegation` instead. If the URL transport accepts
`ii_session_delegation`, switching transports is a transport-and-callback change
only; if it does not, the session chain has to be obtained through ICRC-34 and
the ceremony needs a fallback.

This directory is tooling, not part of the crate: the crate's `package.include`
leaves it out of publishes, so consumers pay nothing for it. It is kept as the
executable record of Internet Identity's ICRC-167 behaviour (see
[`docs/port/native-icrc167.md`](../../docs/port/native-icrc167.md)): re-run it
when II changes. `node --test probes/icrc167/selftest.mjs` runs in CI; the
real-identity and browser runs stay manual (they need a public HTTPS origin, a
user's consent and a ChromeDriver).

Do not commit a recorded run: results carry ephemeral keys and a live delegation
chain, and a tunnel host name is not stable. `.gitignore` ignores
`results*.json` and `*.local.json` under this directory.

## What it runs

| ID | Request | Question | Why it decides the design |
|---|---|---|---|
| E0 | *(implicit)* | Does II refuse a callback that is not in `/.well-known/ii-auth-callbacks`? | Confirms the allow-list is enforced, so the probe only ever runs on an origin that declares its callback |
| E1 | `icrc34_delegation` (`publicKey`, `maxTimeToLive` 8h) | Is ICRC-167 accepted against `id.ai`? | Baseline: transport + allow-list + fragment delivery work |
| **E2** | **`ii_session_delegation`** (`sessionPublicKey`, `maxTimeToLive` 8h) | **Does the URL transport accept the method this crate's sign-in sends?** | If yes, native sign-in reuses the whole v11 ceremony (session chain, app delegation, rotation) and only the transport is new |
| E3 | `icrc34_delegation` + `targets: [II canister]` | Is `targets` honoured by the URL transport? | Fallback: a scoped chain could stand in for the session chain. Measured: it is ignored (see findings) |
| E4 | `icrc34_delegation` + `icrc95DerivationOrigin: https://example.com` | Is derivation validated (foreign origin -> expected rejection), or silently ignored? | Decides whether a native relay page can reproduce an app's browser principal |
| E5 | `icrc34_delegation` + `icrc95DerivationOrigin` (this origin) | Control: same-origin derivation is a no-op | Confirms the derivation parameter is not breaking the baseline |

Per attempt the probe generates a fresh key pair, stores the pending request
(including the single-use `state`) in `sessionStorage`, navigates to the signer,
and on the callback reads the fragment, checks that `state` came back
unchanged, correlates the JSON-RPC ids, strips the fragment from history and
records whether the chain's leaf is the key it asked for.

## Run it

### 1. Offline self-test (no Internet Identity)

The fake signer mimics the signer's side of the transport (fragment parsing,
allow-list validation, batch answer, navigation back). Use it to confirm the
plumbing after changing the probe:

```bash
node probes/icrc167/serve.mjs --fake-signer
# open the printed URL, which is http://127.0.0.1:8787/?signer=/fake-signer.html
```

`serve.mjs` is the Node twin of `serve.py` (`serve.py` needs a working
`python3`; on macOS an Xcode-less setup may resolve it to a missing stub ---
Homebrew's `/opt/homebrew/bin/python3` works if you prefer Python).

Automated, including the error path:

```bash
node --test probes/icrc167/selftest.mjs                # protocol helpers
python3 probes/icrc167/browser-selftest.py             # real browser, fake signer
python3 probes/icrc167/browser-selftest.py --serve-with node  # ... via serve.mjs
```

`browser-selftest.py` needs a ChromeDriver matching the installed Chrome
(`--chromedriver` / `--chrome` if the defaults do not fit).

### 2. Real run against Internet Identity

Internet Identity has to fetch the allow-list from the **callback origin over
public HTTPS** (it cannot reach `127.0.0.1`), so the probe needs a public
origin. A Cloudflare quick tunnel is the shortest path:

```bash
# terminal 1: start the tunnel first so its host is known
npx cloudflared tunnel --url http://127.0.0.1:8787

# terminal 2: the probe, announcing the tunnel origin it is reached on
node probes/icrc167/serve.mjs --port 8787 --public-origin https://<tunnel-host>
```

Replace `<tunnel-host>` with the host from the tunnel output (the angle
brackets are placeholders, not shell syntax). The allow-list must name the
exact origin the browser opens, so start the tunnel first.

Open `https://<tunnel-host>/`, check the banner says the allow-list declares
this callback, then run **E1 → E5** (each asks Internet Identity for consent;
the II session is remembered, so it is a few seconds per experiment). Finish
with **Copy results JSON**.

> `npx cloudflared` downloads the tunnel binary on first use; `brew install
> cloudflared` also works. Any HTTPS tunnel is fine as long as the public origin
> passed to `--public-origin` is the one the browser opens.

### 3. Static hosting

If a tunnel is inconvenient, export a static copy and upload it to Netlify Drop
or Cloudflare Pages (both honour the `_headers` file that keeps CORS and
`no-store` on the well-known paths):

```bash
node probes/icrc167/serve.mjs --export site --public-origin https://<deployed-origin>
# drag the site/ directory onto https://app.netlify.com/drop, or push it to a
# Cloudflare Pages project
```

A project GitHub Pages site cannot be used: the allow-list must live at the
**origin root** (`/.well-known/ii-auth-callbacks`), and a project site is served
under `/ic-auth-client-rs/`. Use a custom domain or a real user site if Pages
is preferred.

### Requirements the signer enforces on the allow-list

- exact `application/json` at `/.well-known/ii-auth-callbacks`
- `Access-Control-Allow-Origin` that lets II read it (the fetch carries no
  credentials)
- no redirects, `cache: no-store` (II re-fetches every time)
- at most 8 KiB, every entry same-origin, byte-for-byte equal to the `callback`
  used in the request, no fragments
- **fail closed**: any problem and II returns no response at all

`serve.mjs` / `serve.py` and the exported `_headers` already satisfy these for
the probe origin.

## Reading the results

Each recorded experiment carries `checks`:

- `stateMatches` — the single-use `state` came back unchanged
- `idsMatch` — every request id has a response
- `hasDelegation`, `delegationCount`, `expiration`, `targets`, `permissions` —
  the returned chain's shape
- `leafMatchesAskedKey` — the chain delegates to the key the probe generated
- `errors` — signer rejections, verbatim

Interpretation for the native plan:

- **E2 succeeds** -> native sign-in can keep the v11 ceremony; implement a native
  transport + callback broker and reuse everything else (measured on 2026-11-14:
  it succeeds, with an II-scoped chain and the requested 8 hour lifetime).
- **E2 fails, E3 succeeds with a `targets` echo** -> build the session chain from
  `icrc34_delegation` instead. Measured: `targets` was ignored, so this fallback is
  not available.
- **Batches are not answered** (measured): one JSON-RPC message per navigation,
  sequential round-trips are fine. Sign-in sends a single request, so this is not
  a blocker.
- **E4 decides the principal question**: a rejection means the app domain only has
  to declare `/.well-known/ii-alternative-origins` listing the relay origin, so an
  app keeps its browser principal. An acceptance means derivation is ignored and
  the relay origin becomes the derivation basis.
  `derivation_origin` survives the switch. It needs
  `/.well-known/ii-alternative-origins` on the derivation origin declaring the
  relying-party origin (the probe serves it for its own origin; for a real app,
  `derivationOrigin` is the app's production origin, which must be the probe
  origin for this experiment to be meaningful, or the file must be adjusted).

## Report back

Please send the JSON from **Copy results JSON** together with:

- the browser/OS used,
- whether II showed its consent screen (and what it named as the app), or an
  error page instead,
- anything the browser console logged for the `id.ai` navigation.

That is enough to pick between "reuse the v11 ceremony" and the fallback
design, and to know whether the native transport can batch.

## Security notes

- Key pairs are generated per attempt and only their `sessionStorage` copies
  survive a navigation; nothing is sent anywhere except the public key in the
  signer URL.
- The probe origin can receive a delegation for the probe's own keys. Delete the
  deployment (or let the tunnel expire) after the run; the keys are useless
  afterwards anyway.
- The allow-list is a security boundary: list only the exact callback, never a
  reflecting or redirecting path.
- `state` is single-use and unguessable; the probe refuses a response whose
  `state` does not match its pending request, and records the mismatch.

## Findings from a real run (2026-11-14, id.ai)

Observed with the probe hosted on a Cloudflare quick tunnel, signed in with a
consumer Internet Identity:

- **E1 works.** `icrc34_delegation` is accepted, the response is a two-hop chain
  (canister-signed hop to a browser key, browser-signed hop to our key), and the
  leaf is the key the relying party asked for. The leaf's expiry came back as the
  30-day maximum rather than the requested 8 hours on this transport.
- **E2 works, and that is the good news for this crate.** `ii_session_delegation`
  is accepted over the URL transport and returns a chain scoped to the Internet
  Identity canister (`targets: ["rdmx6-jaaaa-aaaaa-aaadq-cai"]` on both hops) with
  **exactly the requested 8 hour lifetime**. That is the same request the v11
  browser sign-in sends, so a native transport can reuse the whole existing
  ceremony (session chain -> canister-minted app delegation -> rotation).
- **Batches are not answered.** A JSON-RPC batch (delegation + `icrc27_accounts`)
  never came back with a response: II showed its terminal "Authentication
  successful" page and never drove the callback. The probe now records that as a
  `no-message` result instead of waiting forever. Sign-in sends one request, so
  this is not a blocker, but a native transport must do one request per
  navigation. Sequential round-trips do work: every other experiment navigated
  independently and succeeded.
- **`targets` on `icrc34_delegation` was ignored**: E3 asked for
  `["rdmx6-jaaaa-aaaaa-aaadq-cai"]` and got the same unscoped chain as E1.
  `ii_session_delegation` (E2) is what produces the II-scoped chain, so the
  `icrc34_delegation` + `targets` fallback design is out.
- **Derivation is validated, not ignored.** Same-origin derivation is a no-op
  (E5 root equals E1 root), as expected. E4 asked to derive as
  `https://example.com` from a relying party it has never heard of and Internet
  Identity stopped with its **"Unverified origin --- It seems like the request
  could not be processed."** page instead of answering. So II fetches
  `https://<derivation>/.well-known/ii-alternative-origins` and only lets an
  origin derive as another when that document names the relying party.

This settles the principal question for a native design:

- **Serve the relay page on the app's own origin.** Then the relying party
  origin (determined by the callback) *is* the derivation origin, so the
  principal is byte-for-byte the one the browser sign-in produces and no
  `/.well-known/ii-alternative-origins` document is needed.
- A **shared** relay page (one domain for every app) would require each app to
  publish `/.well-known/ii-alternative-origins` naming that shared origin ---
  and the origin the user sees at the signer would be the shared one, not the
  app's.

## The design this feeds

The probe exists to settle the questions in
[`docs/port/native-icrc167.md`](../../docs/port/native-icrc167.md), which turns
its findings into the native sign-in design (relay page on the app's origin,
`NativeUrlTransport` + loopback relay, `webauth` as the fallback).
