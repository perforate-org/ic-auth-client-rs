// Unit tests for the probe's protocol helpers: `node --test probes/icrc167/`.
//
// They cover the parts that are easy to get subtly wrong and expensive to
// discover only after a real Internet Identity round-trip: the form encoding of
// the fragment, the byte-level key comparison, and the exact request shapes.

import assert from "node:assert/strict";
import test from "node:test";

import {
  ED25519_SPKI_PREFIX,
  EXPERIMENTS,
  II_CANISTER_ID,
  TTL_8H_NS,
  callbackUrlFor,
  ed25519DerFromRaw,
  encodeFragment,
  experimentById,
  fromBase64,
  inspectMessage,
  parseFragment,
  sameKey,
  signerUrl,
  toBase64,
  toHex,
} from "./icrc167.js";

test("base64 round-trips every byte and uses the standard alphabet", () => {
  const bytes = Uint8Array.from({ length: 256 }, (_, index) => index);
  const encoded = toBase64(bytes);
  assert.match(encoded, /^[A-Za-z0-9+/]+={0,2}$/);
  assert.deepEqual(Array.from(fromBase64(encoded)), Array.from(bytes));
  // A DER SPKI key exercises both the '+' and '/' characters on some inputs.
  assert.equal(toBase64(Uint8Array.from([0xfb, 0xff, 0xff])), "+///");
  assert.equal(toBase64(Uint8Array.from([0xff])), "/w==");
});

test("base64 decoding is strict about the alphabet", () => {
  assert.throws(() => fromBase64("AQID-_8"));
  assert.throws(() => fromBase64("AQ ID"));
  assert.deepEqual(Array.from(fromBase64("AQID")), [1, 2, 3]);
});

test("sameKey compares decoded bytes, not spelling", () => {
  assert.ok(sameKey("AQID", "AQID"));
  assert.ok(sameKey("AQID", "AQID"));
  assert.ok(!sameKey("AQID", "AQIE"));
  assert.ok(!sameKey(undefined, "AQID"));
});

test("Ed25519 DER is the SPKI prefix plus the raw key", () => {
  const der = ed25519DerFromRaw(Uint8Array.from([1, 2, 3]));
  assert.deepEqual(Array.from(der.slice(0, ED25519_SPKI_PREFIX.length)), Array.from(ED25519_SPKI_PREFIX));
  assert.equal(der.length, 12 + 3);
  assert.equal(toHex(ED25519_SPKI_PREFIX), "302a300506032b6570032100");
});

test("the fragment is form-urlencoded and round-trips through parseFragment", () => {
  const message = JSON.stringify([
    { jsonrpc: "2.0", id: "E4a", method: "icrc34_delegation", params: { publicKey: "AQID+/8=" } },
  ]);
  const callback = "https://probe.example/callback.html";
  const url = signerUrl("https://id.ai/authorize", { message, callback, state: "st ate&1" });
  assert.equal(url.slice(0, "https://id.ai/authorize#".length), "https://id.ai/authorize#");
  const hash = url.slice(url.indexOf("#"));
  assert.deepEqual(parseFragment(hash), { message, state: "st ate&1" });
  // The '+' of base64 must survive as a literal, not become a space.
  assert.equal(parseFragment(hash).message, message);
  assert.ok(parseFragment(hash).message.includes("AQID+/8="));
  assert.equal(encodeFragment({ a: "x y", b: "&" }), "a=x+y&b=%26");
});

test("signerUrl replaces an existing fragment and keeps the query", () => {
  const url = signerUrl("https://id.ai/authorize?openid=https%3A%2F%2Fappleid.apple.com#old", {
    message: "{}",
    callback: "https://probe.example/callback.html",
    state: "s",
  });
  assert.ok(url.startsWith("https://id.ai/authorize?openid="));
  assert.ok(!url.includes("#old"));
  assert.equal(url.split("#").length, 2);
});

test("callbackUrlFor is the exact declared callback", () => {
  assert.equal(callbackUrlFor("https://probe.example", "/callback.html"), "https://probe.example/callback.html");
  assert.equal(callbackUrlFor("https://probe.example/", "/callback.html"), "https://probe.example/callback.html");
});

test("the experiments use the request shapes the crate sends", () => {
  const leaf = "AQID";
  assert.deepEqual(experimentById("E2").build(leaf), [
    {
      jsonrpc: "2.0",
      id: "E2",
      method: "ii_session_delegation",
      params: { sessionPublicKey: leaf, maxTimeToLive: TTL_8H_NS },
    },
  ]);
  assert.deepEqual(experimentById("E1").build(leaf), [
    { jsonrpc: "2.0", id: "E1", method: "icrc34_delegation", params: { publicKey: leaf, maxTimeToLive: TTL_8H_NS } },
  ]);
  assert.deepEqual(experimentById("E3").build(leaf)[0].params.targets, [II_CANISTER_ID]);
  // Derivation is either validated (E4, foreign origin -> expected rejection) or
  // a no-op when it equals the callback origin (E5, control).
  assert.equal(experimentById("E4").build(leaf)[0].params.icrc95DerivationOrigin, "https://example.com");
  assert.equal(experimentById("E4").expectation, "error");
  assert.equal(experimentById("E5").build(leaf)[0].params.icrc95DerivationOrigin, "https://probe.example");
  assert.equal(EXPERIMENTS.length, 5);
  // The probe's 8 hour lifetime is what the crate's default sign-in asks for.
  assert.equal(Number(TTL_8H_NS), 8 * 60 * 60 * 1_000_000_000);
});

test("inspectMessage recognises a delegation and its leaf", () => {
  const asked = "AQID";
  const response = {
    jsonrpc: "2.0",
    id: "E1",
    result: {
      publicKey: "AQID",
      signerDelegation: [
        { delegation: { pubkey: "AQID", expiration: "1800000000000000000" }, signature: toBase64(new Uint8Array(64)) },
      ],
    },
  };
  const inspected = inspectMessage(response, asked, ["E1"]);
  assert.equal(inspected.isBatch, false);
  assert.ok(inspected.idsMatch);
  assert.ok(inspected.hasDelegation);
  assert.equal(inspected.hopCount, 1);
  assert.ok(inspected.leafMatchesAskedKey);
  assert.equal(inspected.targets, null);
  assert.equal(inspected.permissions, null);
});

test("inspectMessage takes the leaf from the last hop of a multi-hop chain", () => {
  // Internet Identity's browser transports return two hops: the first delegates
  // to a browser-held key, the second to the key the relying party asked for.
  const asked = "AQID";
  const response = {
    jsonrpc: "2.0",
    id: "E1",
    result: {
      publicKey: "MAowBQYDK2VwAyEA",
      signerDelegation: [
        { delegation: { pubkey: "AgICAgICAgICAgICAgICAg==", expiration: "2" }, signature: "AA==" },
        {
          delegation: { pubkey: asked, expiration: "3", targets: ["rdmx6-jaaaa-aaaaa-aaadq-cai"] },
          signature: "AA==",
        },
      ],
    },
  };
  const inspected = inspectMessage(response, asked, ["E1"]);
  assert.equal(inspected.hopCount, 2);
  assert.ok(inspected.leafMatchesAskedKey);
  assert.equal(inspected.leafPubkey, asked);
  assert.deepEqual(inspected.hopTargets, [null, ["rdmx6-jaaaa-aaaaa-aaadq-cai"]]);
  assert.deepEqual(inspected.hops.map((hop) => hop.expiration), ["2", "3"]);
});

test("inspectMessage reports a mismatched leaf and batch ordering", () => {
  const batch = [
    { jsonrpc: "2.0", id: "E4a", result: { publicKey: "AQID", signerDelegation: [{ delegation: { pubkey: "AQIE", expiration: "1" }, signature: "AA==" }] } },
    { jsonrpc: "2.0", id: "E4b", result: { accounts: [] } },
  ];
  const inspected = inspectMessage(batch, "AQID", ["E4a", "E4b"]);
  assert.equal(inspected.isBatch, true);
  assert.ok(inspected.idsMatch);
  assert.equal(inspected.leafMatchesAskedKey, false);
});

test("inspectMessage surfaces signer errors", () => {
  const inspected = inspectMessage(
    { jsonrpc: "2.0", id: "E2", error: { code: 3001, message: "Action aborted" } },
    "AQID",
    ["E2"],
  );
  assert.equal(inspected.hasDelegation, false);
  assert.deepEqual(inspected.errors, [{ id: "E2", error: { code: 3001, message: "Action aborted" } }]);
});
