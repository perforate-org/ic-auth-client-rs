import {
  AuthClient,
  type InternetIdentityAuthResponseSuccess,
} from "@icp-sdk/auth/client";
import { Ed25519PublicKey } from "@icp-sdk/core/identity";
import { Secp256k1PublicKey } from "@icp-sdk/core/identity/secp256k1";
import { Principal } from "@icp-sdk/core/principal";
import { hexToBytes } from "@noble/hashes/utils.js";

/** Query string parameter names used by the auth bridge. */
export const URL_PARAMS = {
  REDIRECT_URI: "redirectUri",
  PUBKEY: "pubkey",
  IDENTITY_PROVIDER: "identityProvider",
  MAX_TIME_TO_LIVE: "maxTimeToLive",
  ALLOW_PIN_AUTHENTICATION: "allowPinAuthentication",
  DERIVATION_ORIGIN: "derivationOrigin",
  WINDOW_OPENER_FEATURES: "windowOpenerFeatures",
  CUSTOM_VALUES: "customValues",
  KEY_TYPE: "keyType",
} as const;

/** Serialized delegation payload returned to the client. */
export type Delegation = {
  delegation: {
    expiration?: string;
    pubkey: number[];
    targets?: string[];
  };
  signature: number[];
};

/** Serialized authentication response payload. */
export type AuthResponse = {
  delegations: Delegation[];
  userPublicKey: number[];
  authnMethod: "passkey" | "pin" | "recovery";
};

/** Success callback payload for native/web clients. */
export type SuccessPayload = {
  type: "success";
  data: AuthResponse;
};

/** Error callback payload for native/web clients. */
export type ErrorPayload = { type: "error"; data: string | undefined };

/** Callback payload union used by postMessage/redirect. */
export type CallbackPayload = SuccessPayload | ErrorPayload;

/** Options passed to the auth client login call. */
export type LoginOptions = {
  identityProvider?: string;
  maxTimeToLive?: bigint;
  allowPinAuthentication?: boolean;
  derivationOrigin?: string;
  windowOpenerFeatures?: string;
  customValues?: Record<string, unknown>;
};

type KeyType = "Ed25519" | "Prime256v1" | "Secp256k1";

function parseKeyType(value: string): KeyType {
  switch (value) {
    case "Ed25519":
    case "Prime256v1":
    case "Secp256k1":
      return value;
    default:
      throw new Error(`Unsupported keyType: ${value}`);
  }
}

/** Parameters parsed from the integration redirect URL. */
export type Params = {
  redirectUri: string;
  publicKey: Uint8Array;
  keyType?: KeyType;
  identityProvider?: string;
  maxTimeToLive?: bigint;
  allowPinAuthentication?: boolean;
  derivationOrigin?: string;
  windowOpenerFeatures?: string;
  customValues?: Record<string, unknown>;
};

/** Decode a hex-encoded public key into a DER-encoded byte array. */
function createPublicKeyFromHex(pubKey: string, keyType?: KeyType): Uint8Array {
  const bytes = hexToBytes(pubKey);

  if (keyType === "Ed25519") {
    try {
      return Ed25519PublicKey.fromDer(bytes).toDer();
    } catch (e) {
      throw new Error(`Invalid Ed25519 public key format: ${e}`);
    }
  }

  if (keyType === "Secp256k1") {
    try {
      return Secp256k1PublicKey.fromDer(bytes).toDer();
    } catch (e) {
      throw new Error(`Invalid Secp256k1 public key format: ${e}`);
    }
  }

  if (keyType === "Prime256v1") {
    return bytes;
  }

  try {
    return Ed25519PublicKey.fromDer(bytes).toDer();
  } catch (ed25519Error) {
    try {
      return Secp256k1PublicKey.fromDer(bytes).toDer();
    } catch (secpError) {
      throw new Error(
        `Invalid public key format (Ed25519: ${ed25519Error}, Secp256k1: ${secpError})`,
      );
    }
  }
}

/**
 * Parse required and optional login params from a URL string.
 *
 * ---
 *
 * @example
 * ```ts
 * import { parseParams } from "@perforate/ic-auth-bridge";
 *
 * const params = parseParams(window.location.href);
 * ```
 */
export function parseParams(locationHref: string): Params {
  const url = new URL(locationHref);
  const params = url.searchParams;

  const getOptionalParam = (key: string): string | undefined => {
    const value = params.get(key);
    return value || undefined;
  };

  const getOptionalBooleanParam = (key: string): boolean | undefined => {
    const value = params.get(key);
    return value ? value === "true" : undefined;
  };

  const getOptionalBigIntParam = (key: string): bigint | undefined => {
    const value = params.get(key);
    return value ? BigInt(value) : undefined;
  };

  const getOptionalJSONParam = (
    key: string,
  ): Record<string, unknown> | undefined => {
    const value = params.get(key);
    if (!value) return undefined;

    try {
      return JSON.parse(value);
    } catch {
      throw new Error(`Invalid JSON format for parameter: ${key}`);
    }
  };

  const redirectUriParam = params.get(URL_PARAMS.REDIRECT_URI);
  const pubKey = params.get(URL_PARAMS.PUBKEY);
  const keyTypeParam = getOptionalParam(URL_PARAMS.KEY_TYPE);
  const keyType = keyTypeParam ? parseKeyType(keyTypeParam) : undefined;

  if (!redirectUriParam || !pubKey) {
    throw new Error("Missing redirect_uri or pubkey in query string");
  }

  const publicKey = createPublicKeyFromHex(pubKey, keyType);

  return {
    redirectUri: decodeURIComponent(redirectUriParam),
    publicKey,
    keyType,
    identityProvider: getOptionalParam(URL_PARAMS.IDENTITY_PROVIDER),
    maxTimeToLive: getOptionalBigIntParam(URL_PARAMS.MAX_TIME_TO_LIVE),
    allowPinAuthentication: getOptionalBooleanParam(
      URL_PARAMS.ALLOW_PIN_AUTHENTICATION,
    ),
    derivationOrigin: getOptionalParam(URL_PARAMS.DERIVATION_ORIGIN),
    windowOpenerFeatures: getOptionalParam(URL_PARAMS.WINDOW_OPENER_FEATURES),
    customValues: getOptionalJSONParam(URL_PARAMS.CUSTOM_VALUES),
  };
}

/**
 * Create an AuthClient using derived login options.
 *
 * ---
 *
 * @example
 * ```ts
 * import { createAuthClient, parseParams } from "@perforate/ic-auth-bridge";
 *
 * const params = parseParams(window.location.href);
 *
 * const authClient = await createAuthClient(params);
 * ```
 */
export async function createAuthClient(
  params: Params,
  identityProvider?: string,
) {
  return AuthClient.create({
    keyType:
      params.keyType && params.keyType !== "Ed25519" ? "ECDSA" : "Ed25519",
    loginOptions: buildLoginOptions(params, identityProvider),
  });
}

function buildLoginOptions(
  params: Params,
  identityProvider?: string,
): LoginOptions {
  return {
    identityProvider: identityProvider || params.identityProvider,
    maxTimeToLive: params.maxTimeToLive,
    allowPinAuthentication: params.allowPinAuthentication,
    derivationOrigin: params.derivationOrigin,
    windowOpenerFeatures: params.windowOpenerFeatures,
    customValues: {
      ...params.customValues,
      sessionPublicKey: new Uint8Array(params.publicKey),
    },
  };
}

/**
 * Start the login flow and route callbacks to the app.
 *
 * ---
 *
 * @example
 * ```ts
 * import { createAuthClient, parseParams, startLogin } from "@perforate/ic-auth-bridge";
 *
 * const params = parseParams(window.location.href);
 * const authClient = await createAuthClient(params);
 *
 * startLogin(authClient, params.redirectUri);
 * ```
 */
export function startLogin(
  authClient: AuthClient,
  redirectUri: string,
  windowOpenerFeatures?: string | undefined,
) {
  attachPopupCloseHandler();
  authClient.login({
    onSuccess: (response) => handleSuccess(response, redirectUri),
    onError: (error) => handleFailure(error, redirectUri),
    windowOpenerFeatures,
  });
}

function handleSuccess(
  response: InternetIdentityAuthResponseSuccess,
  redirectUri: string,
) {
  sendPostMessage(redirectUri, createSuccessPayload(response));
}

function handleFailure(error: string | undefined, redirectUri: string) {
  sendPostMessage(redirectUri, { type: "error", data: error });
}

function createSuccessPayload(
  response: InternetIdentityAuthResponseSuccess,
): SuccessPayload {
  const serialized = serializeResponse(response);
  return { type: "success", data: serialized };
}

async function sendPostMessage(redirectUri: string, payload: CallbackPayload) {
  try {
    await postToNativeCallback(redirectUri, payload);
    closeOpenerSafely();
    window.close();
  } catch (e) {
    console.error("Failed to send post message, falling back to redirect:", e);
    redirectToCallback(redirectUri, payload);
  }
}

function attachPopupCloseHandler() {
  if (!("window" in globalThis)) {
    return;
  }

  window.addEventListener("beforeunload", closeOpenerSafely, { once: true });
}

function closeOpenerSafely() {
  if (!("window" in globalThis)) {
    return;
  }

  try {
    const opener = window.opener;
    if (!opener || opener === window || opener.closed) {
      return;
    }
    opener.close();
  } catch {
    // Ignore cross-origin or permission errors.
  }
}

async function postToNativeCallback(
  redirectUri: string,
  payload: CallbackPayload,
) {
  const body = serializePayload(payload);
  await fetch(redirectUri, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body,
  });
}

function redirectToCallback(redirectUri: string, payload: CallbackPayload) {
  const url = new URL(redirectUri);
  url.searchParams.set("payload", encodePayload(payload));
  window.location.href = url.toString();
}

function serializeResponse(
  response: InternetIdentityAuthResponseSuccess,
): AuthResponse {
  return {
    authnMethod: response.authnMethod,
    userPublicKey: toBytes(response.userPublicKey),
    delegations: response.delegations.map(serializeDelegation),
  };
}

type DelegationPayload =
  InternetIdentityAuthResponseSuccess["delegations"][number];

function serializeDelegation(delegation: DelegationPayload): Delegation {
  return {
    signature: toBytes(delegation.signature),
    delegation: {
      expiration: serializeExpiration(delegation.delegation.expiration),
      pubkey: toBytes(delegation.delegation.pubkey),
      targets: serializeTargets(delegation.delegation.targets),
    },
  };
}

function serializeExpiration(
  expiration: DelegationPayload["delegation"]["expiration"],
) {
  return expiration ? expiration.toString() : undefined;
}

function serializeTargets(
  targets: DelegationPayload["delegation"]["targets"],
): string[] | undefined {
  if (!targets) {
    return undefined;
  }

  return targets.map((target) =>
    isPrincipal(target)
      ? target.toText()
      : Principal.fromUint8Array(toUint8Array(target)).toText(),
  );
}

function toBytes(
  array: Uint8Array | ArrayBuffer | ArrayLike<number> | undefined,
): number[] {
  if (!array) {
    return [];
  }
  return Array.from(toUint8Array(array));
}

function isPrincipal(value: unknown): value is Principal {
  return (
    typeof value === "object" &&
    value !== null &&
    "toText" in value &&
    typeof (value as { toText?: unknown }).toText === "function"
  );
}

function toUint8Array(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) {
    return value;
  }

  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }

  if (ArrayBuffer.isView(value)) {
    const view = value as ArrayBufferView;
    return new Uint8Array(
      view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength),
    );
  }

  return new Uint8Array(value as ArrayLike<number>);
}

function encodePayload(payload: CallbackPayload): string {
  const json = serializePayload(payload);
  const encoded = new TextEncoder().encode(json);
  let binary = "";
  encoded.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

function serializePayload(payload: CallbackPayload): string {
  return JSON.stringify(payload, (_key, value) => {
    if (typeof value === "bigint") {
      return value.toString();
    }
    return value;
  });
}

/**
 * Build window features to center a popup on the current window.
 */
export const popupCenter = ({
  width,
  height,
}: {
  width: number;
  height: number;
}): string | undefined => {
  if (!isBrowser()) {
    return undefined;
  }

  if (isNullish(window) || isNullish(window.top)) {
    return undefined;
  }

  const {
    top: { innerWidth, innerHeight },
  } = window;

  const y = innerHeight / 2 + screenY - height / 2;
  const x = innerWidth / 2 + screenX - width / 2;

  return `toolbar=no, location=no, directories=no, status=no, menubar=no, scrollbars=yes, resizable=no, copyhistory=no, width=${width}, height=${height}, top=${y}, left=${x}`;
};

const isNullish = <T>(
  argument: T | undefined | null,
): argument is undefined | null => argument === null || argument === undefined;

const isBrowser = (): boolean =>
  typeof globalThis !== "undefined" &&
  "window" in globalThis &&
  "document" in globalThis;
