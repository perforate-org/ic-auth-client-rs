import { AuthClient, IdbStorage, KEY_STORAGE_KEY } from "@icp-sdk/auth/client";
import { Ed25519KeyIdentity, ECDSAKeyIdentity } from "@icp-sdk/core/identity";

let wasmModule = null;
let initPromise = null;
let compatError = null;

window.compatReady = false;
window.compatError = null;

async function loadWasm() {
  try {
    const mod = await import("@ic-auth-client-wasm");
    if (
      typeof mod.compat_clear_storage !== "function" ||
      typeof mod.compat_rust_read_key_principal !== "function" ||
      typeof mod.compat_rust_write_key !== "function"
    ) {
      throw new Error(
        "compat exports not found. Build wasm with: make build-wasm-compat",
      );
    }
    wasmModule = mod;
    initPromise = mod.default();
    await initPromise;
    window.compatReady = true;
  } catch (error) {
    compatError = error;
    window.compatError = String(error);
  }
}

loadWasm();

async function jsCreateClientPrincipal(keyType) {
  const client = await AuthClient.create({ keyType });
  return client.getIdentity().getPrincipal().toText();
}

async function jsGenerateKey(keyType) {
  await AuthClient.create({ keyType });
}

async function jsStoredKeyPrincipal() {
  const storage = new IdbStorage();
  const stored = await storage.get(KEY_STORAGE_KEY);
  if (!stored) {
    throw new Error("Stored key not found");
  }
  if (typeof stored === "string") {
    const identity = Ed25519KeyIdentity.fromJSON(stored);
    return identity.getPrincipal().toText();
  }
  const identity = await ECDSAKeyIdentity.fromKeyPair(stored);
  return identity.getPrincipal().toText();
}

async function rustWriteKey(keyType) {
  if (compatError) throw compatError;
  await initPromise;
  return await wasmModule.compat_rust_write_key(keyType);
}

async function rustReadPrincipal(keyType) {
  if (compatError) throw compatError;
  await initPromise;
  return await wasmModule.compat_rust_read_key_principal(keyType ?? null);
}

async function clearStorage() {
  if (compatError) throw compatError;
  await initPromise;
  await wasmModule.compat_clear_storage();
}

window.compat = {
  ready: async () => {
    if (compatError) throw compatError;
    await initPromise;
  },
  clearStorage,
  jsCreateClientPrincipal,
  jsGenerateKey,
  jsStoredKeyPrincipal,
  rustWriteKey,
  rustReadPrincipal,
};
