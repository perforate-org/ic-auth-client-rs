// ICRC-167 conformance probe: protocol helpers.
//
// This file is deliberately dependency-free and side-effect-free so the same
// functions run in the browser pages and under `node --test` (see selftest.mjs).

// Bump when the shape of a recorded result changes; the probe refuses to
// render older records as current ones (they show as stale instead).
export const PROBE_SCHEMA = 3;

export const II_AUTHORIZE_URL = "https://id.ai/authorize";
export const II_CANISTER_ID = "rdmx6-jaaaa-aaaaa-aaadq-cai";

// The delegation lifetimes the probe asks for: 8 hours, in nanoseconds, which
// is Internet Identity's default for browser sign-ins.
export const TTL_8H_NS = "28800000000000";

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

const BASE64_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** Standard base64, the encoding the signer protocol uses for keys. */
export function toBase64(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i];
    const b = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const c = i + 2 < bytes.length ? bytes[i + 2] : 0;
    out += BASE64_ALPHABET[a >> 2];
    out += BASE64_ALPHABET[((a & 3) << 4) | (b >> 4)];
    out += i + 1 < bytes.length ? BASE64_ALPHABET[((b & 15) << 2) | (c >> 6)] : "=";
    out += i + 2 < bytes.length ? BASE64_ALPHABET[c & 63] : "=";
  }
  return out;
}

/** Decodes standard base64, tolerating omitted padding. Throws on garbage. */
export function fromBase64(value) {
  if (typeof value !== "string") throw new Error("not a base64 string");
  const clean = value.replace(/=+$/, "");
  if (!/^[A-Za-z0-9+/]*$/.test(clean)) throw new Error("not standard base64");
  const bytes = [];
  let buffer = 0;
  let bits = 0;
  for (const character of clean) {
    buffer = (buffer << 6) | BASE64_ALPHABET.indexOf(character);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
    }
  }
  return Uint8Array.from(bytes);
}

/** `Uint8Array` -> lower-case hex, for comparing keys across encodings. */
export function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Compares two base64 keys by their decoded bytes, not their spelling. */
export function sameKey(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  try {
    return toHex(fromBase64(a)) === toHex(fromBase64(b));
  } catch {
    return false;
  }
}

/**
 * The Ed25519 SPKI prefix, used when a caller passes a raw 32-byte key.
 * Mirrors `p256`/`ed25519-dalek` DER construction in the crate.
 */
export const ED25519_SPKI_PREFIX = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

export function ed25519DerFromRaw(raw32) {
  const der = new Uint8Array(ED25519_SPKI_PREFIX.length + raw32.length);
  der.set(ED25519_SPKI_PREFIX);
  der.set(raw32, ED25519_SPKI_PREFIX.length);
  return der;
}

// ---------------------------------------------------------------------------
// The transport
// ---------------------------------------------------------------------------

/**
 * The fragment parameters of an ICRC-167 request, form-urlencoded.
 * `URLSearchParams` is the encoding the standard points at.
 */
export function encodeFragment(fields) {
  const params = new URLSearchParams();
  for (const [name, value] of Object.entries(fields)) {
    if (value !== undefined && value !== null) params.set(name, value);
  }
  return params.toString();
}

/** Builds the signer URL a relying party navigates to. */
export function signerUrl(signer, { message, callback, state }) {
  const fragment = encodeFragment({
    message: typeof message === "string" ? message : JSON.stringify(message),
    callback,
    state,
  });
  const base = signer.replace(/#.*$/, "");
  return `${base}#${fragment}`;
}

/** Reads `message` and `state` out of a `location.hash`. */
export function parseFragment(hash) {
  const params = new URLSearchParams((hash || "").replace(/^#/, ""));
  return { message: params.get("message"), state: params.get("state") };
}

/** The origin used for the callback; `location.origin` in a browser. */
export function callbackUrlFor(origin, path = "/callback.html") {
  return new URL(path, origin).toString();
}

export function randomToken(byteCount) {
  const bytes = new Uint8Array(byteCount);
  globalThis.crypto.getRandomValues(bytes);
  return toBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ---------------------------------------------------------------------------
// The experiment matrix
// ---------------------------------------------------------------------------

/**
 * What the probe needs to learn, in order of importance:
 *
 *   E1  ICRC-167 works at all against id.ai (baseline; ICNativeClient reports
 *       that `icrc34_delegation` is accepted).
 *   E2  II's URL transport accepts `ii_session_delegation`, the method this
 *       crate's v11 sign-in sends. If it does, native sign-in can reuse the
 *       whole existing ceremony and only the transport is new.
 *   E3  Fallback: is a chain scoped to the II canister obtainable through
 *       `icrc34_delegation` `targets`? Such a chain could stand in for the
 *       session chain and still let the app mint its delegation.
 *   E4  Batch support: two requests answered in one navigation.
 *   E5  Derivation: does `icrc95DerivationOrigin` work through the URL
 *       transport (this is how an app gets its own principal).
 *
 * Every experiment carries string ids so responses correlate unambiguously.
 */
export const EXPERIMENTS = [
  {
    id: "E1",
    title: "icrc34_delegation (baseline)",
    question: "Is ICRC-167 accepted, and is the leaf the key we asked for?",
    expectation: "success",
    build: (publicKey) => [
      {
        jsonrpc: "2.0",
        id: "E1",
        method: "icrc34_delegation",
        params: { publicKey, maxTimeToLive: TTL_8H_NS },
      },
    ],
  },
  {
    id: "E2",
    title: "ii_session_delegation (the crate's v11 session flow)",
    question: "Does the URL transport accept the method our sign-in sends?",
    expectation: "success",
    build: (publicKey) => [
      {
        jsonrpc: "2.0",
        id: "E2",
        method: "ii_session_delegation",
        params: { sessionPublicKey: publicKey, maxTimeToLive: TTL_8H_NS },
      },
    ],
  },
  {
    id: "E3",
    title: "icrc34_delegation with targets: [II canister]",
    question:
      "Fallback design: is the targets parameter honoured, or ignored?",
    expectation: "success",
    build: (publicKey) => [
      {
        jsonrpc: "2.0",
        id: "E3",
        method: "icrc34_delegation",
        params: {
          publicKey,
          maxTimeToLive: TTL_8H_NS,
          targets: [II_CANISTER_ID],
        },
      },
    ],
  },
  {
    id: "E4",
    title: "derivation: an origin that does not declare us",
    question:
      "Is icrc95DerivationOrigin validated (rejected) over ICRC-167, or ignored?",
    expectation: "error",
    build: (publicKey) => [
      {
        jsonrpc: "2.0",
        id: "E4",
        method: "icrc34_delegation",
        params: {
          publicKey,
          maxTimeToLive: TTL_8H_NS,
          icrc95DerivationOrigin: "https://example.com",
        },
      },
    ],
  },
  {
    id: "E5",
    title: "derivation: this origin (control)",
    question:
      "Same-origin derivation is a no-op; the chain root should match E1's.",
    expectation: "success",
    build: (publicKey) => [
      {
        jsonrpc: "2.0",
        id: "E5",
        method: "icrc34_delegation",
        params: {
          publicKey,
          maxTimeToLive: TTL_8H_NS,
          icrc95DerivationOrigin: globalThis.location
            ? globalThis.location.origin
            : "https://probe.example",
        },
      },
    ],
  },
];

export function experimentById(id) {
  return EXPERIMENTS.find((experiment) => experiment.id === id);
}

// ---------------------------------------------------------------------------
// Response inspection
// ---------------------------------------------------------------------------

/**
 * Summarises a returned JSON-RPC message: which ids came back, whether the
 * result shape is a delegation chain, and whether the chain's leaf is the key
 * the probe asked for.
 */
export function inspectMessage(message, expectedLeaf, expectedIds) {
  const responses = Array.isArray(message) ? message : [message];
  const ids = responses.map((response) => response && response.id);
  const delegationResponses = responses.filter(
    (response) =>
      response &&
      response.result &&
      typeof response.result.publicKey === "string" &&
      Array.isArray(response.result.signerDelegation),
  );
  const delegation = delegationResponses[0];
  // `signerDelegation` is ordered root -> leaf: hop 0 is signed by the chain's
  // `publicKey`, each later hop by the previous hop's `pubkey`. The leaf (the
  // key the relying party asked for) is therefore the *last* entry -- Internet
  // Identity returns two hops (a canister-signed hop to a browser-held key,
  // then a browser-signed hop to the requested key).
  const hops = delegation
    ? delegation.result.signerDelegation.map((signed) => ({
        pubkey: signed.delegation.pubkey,
        expiration: signed.delegation.expiration,
        targets: signed.delegation.targets ?? null,
        permissions: signed.delegation.permissions ?? null,
        signatureBytes: (() => {
          try {
            return fromBase64(signed.signature).length;
          } catch {
            return null;
          }
        })(),
        delegatesToAskedKey:
          expectedLeaf === undefined
            ? undefined
            : sameKey(signed.delegation.pubkey, expectedLeaf),
      }))
    : [];
  const leaf = hops.length ? hops[hops.length - 1].pubkey : undefined;
  return {
    isBatch: Array.isArray(message),
    ids,
    idsMatch: expectedIds.every((id) => ids.includes(id)),
    errors: responses
      .filter((response) => response && response.error)
      .map((response) => ({ id: response.id, error: response.error })),
    hasDelegation: Boolean(delegation),
    chainPublicKey: delegation ? delegation.result.publicKey : undefined,
    hopCount: hops.length,
    hops,
    // What the returned identity is allowed to do: the leaf hop carries the
    // scope the signer granted, and every hop's `targets` constrains it.
    leafPubkey: leaf,
    leafMatchesAskedKey:
      leaf === undefined ? undefined : sameKey(leaf, expectedLeaf),
    hopTargets: hops.map((hop) => hop.targets),
    hopPermissions: hops.map((hop) => hop.permissions),
    targets: hops.length ? hops[hops.length - 1].targets : undefined,
    permissions: hops.length ? hops[hops.length - 1].permissions : undefined,
    expiration: hops.length ? hops[hops.length - 1].expiration : undefined,
  };
}
