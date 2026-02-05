import {
  createAuthClient,
  type Params,
  parseParams,
  popupCenter,
  startLogin as startLoginCore,
} from "@perforate/ic-auth-bridge";

/** Default identity provider fallback when not using local/dev URLs. */
const identityProvider = "https://id.ai";

const AUTH_POPUP_WIDTH = 576;
// we need to temporarily increase the height so II 2.0 in "guided mode" fits the popup
// TODO: revert to 625 after II provides a fix on their end
const AUTH_POPUP_HEIGHT = 826;

let authClient: Awaited<ReturnType<typeof createAuthClient>> | null = null;

/** Boot the page flow and handle top-level errors. */
async function main() {
  try {
    const params = parseParams(window.location.href);
    const identityProvider = params.identityProvider ?? getIdentityProvider();
    authClient = await createAuthClient(params, identityProvider);
    renderStart(params);
  } catch (error) {
    console.error("Error:", error);
    renderError(error instanceof Error ? error : new Error(String(error)));
  }
}

/** Wire up the login button and initial UI state. */
function renderStart(params: Params) {
  const button = getRequiredElement<HTMLButtonElement>("#ii-login-button");
  const errorElement = getRequiredElement<HTMLParagraphElement>("#error");

  errorElement.hidden = true;

  button.addEventListener("click", () => {
    try {
      startLogin(button, params);
    } catch (error) {
      console.error("Failed to start login:", error);
      renderError(error instanceof Error ? error : new Error(String(error)));
    }
  });
}

/** Start login flow with UI state management and error handling. */
function startLogin(button: HTMLButtonElement, params: Params) {
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  renderError(new Error(""), true);
  if (!authClient) {
    button.disabled = false;
    button.removeAttribute("aria-busy");
    renderError(
      new Error("Auth client not ready. Please refresh and try again."),
    );
    return;
  }

  startLoginCore(
    authClient,
    params.redirectUri,
    popupCenter({ height: AUTH_POPUP_HEIGHT, width: AUTH_POPUP_WIDTH }),
    {
      onSuccess: renderSuccessState,
      onError: (error) => {
        renderFailureState(error);
        if (error) {
          renderError(new Error(error));
        }
        button.disabled = false;
        button.removeAttribute("aria-busy");
      },
    },
  );
}

window.addEventListener("DOMContentLoaded", () => {
  main();
});

/** Show an error message in the UI. */
function renderError(error: Error, clearOnly = false) {
  const errorElement = getRequiredElement<HTMLParagraphElement>("#error");
  if (clearOnly) {
    errorElement.textContent = "";
    errorElement.hidden = true;
    return;
  }
  errorElement.textContent = error.message;
  errorElement.hidden = false;
}

function renderSuccessState() {
  renderResultState("Authentication Successful", "You can close this tab.");
}

function renderFailureState(error?: string) {
  renderResultState(
    "Authentication Failed",
    "Please close this tab and try again from the app.",
  );
  if (error) {
    renderError(new Error(error));
  }
}

function renderResultState(headlineText: string, messageText: string) {
  const messageElement = getRequiredElement<HTMLParagraphElement>("#message");
  const button = getRequiredElement<HTMLButtonElement>("#ii-login-button");
  const resultContainer = getRequiredElement<HTMLDivElement>("#result");
  const resultHeadline =
    getRequiredElement<HTMLParagraphElement>("#result-headline");
  const resultMessage =
    getRequiredElement<HTMLParagraphElement>("#result-message");

  button.hidden = true;
  button.style.display = "none";
  button.setAttribute("aria-hidden", "true");
  messageElement.hidden = true;
  resultHeadline.textContent = headlineText;
  resultMessage.textContent = messageText;
  resultContainer.hidden = false;
}

/** Query an element or fail fast with a clear error. */
function getRequiredElement<T extends HTMLElement>(selector: string): T {
  const element = document.querySelector<T>(selector);
  if (!element) {
    throw new Error(`Missing required element: ${selector}`);
  }
  return element;
}

/** Resolve the identity provider based on environment and browser. */
export function getIdentityProvider(): string {
  // Safeguard against server rendering
  if (typeof window !== "undefined") {
    const isLocal = import.meta.env.DFX_NETWORK !== "ic";
    // Safari does not support localhost subdomains
    const isSafari = /^((?!chrome|android).)*safari/i.test(navigator.userAgent);
    if (isLocal && isSafari) {
      return `http://localhost:4943/?canisterId=${import.meta.env.CANISTER_ID_INTERNET_IDENTITY}`;
    } else if (isLocal) {
      return `http://${import.meta.env.CANISTER_ID_INTERNET_IDENTITY}.localhost:4943`;
    }
  }
  return identityProvider;
}
