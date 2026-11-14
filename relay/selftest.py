#!/usr/bin/env python3
"""End-to-end self-test of the relay pages ([`relay/`](.)).

The Rust transport is unit-tested in
[`src/client/transport/native_url.rs`](../src/client/transport/native_url.rs);
this exercises the other half --- the two static pages a host deploys --- in a
real browser, against a scripted signer and a scripted loopback listener, so the
fragment hand-off, the same-origin checks, fragment stripping and the POST
protocol are known-good before a real Internet Identity run.

    python3 relay/selftest.py --chromedriver /path/to/chromedriver

Needs a ChromeDriver matching the installed Chrome; the defaults suit a local
Chrome for Testing download.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_DRIVER = "/tmp/chromedriver-157/chromedriver-mac-arm64/chromedriver"
DEFAULT_CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

# The hand-off page ships inside the listener (`include_str!`), so the self-test
# serves the crate's own copy. Duplicating it here would let the two drift.
HANDOFF_PAGE = HERE.parent / "src" / "client" / "transport" / "handoff.html"

SAFARI_STUB = """<script>
// Stand in for Safari, which refuses an https page reading http://127.0.0.1.
const realFetch = window.fetch;
window.fetch = (input, init) =>
  String(input).startsWith("http://127.0.0.1")
    ? Promise.reject(new TypeError("Load failed"))
    : realFetch(input, init);
</script>"""


def safari_callback_html() -> bytes:
    """The callback page as Safari runs it: its loopback fetch fails."""
    document = (HERE / "auth" / "callback.html").read_text()
    return document.replace("<body>", "<body>" + SAFARI_STUB, 1).encode()


FAKE_SIGNER = """<!doctype html>
<html><head><meta charset="utf-8"><title>Fake signer</title></head>
<body><p id="status">signing…</p><script>
(() => {
  const status = document.getElementById("status");
  const fragment = new URLSearchParams(location.hash.replace(/^#/, ""));
  history.replaceState(null, "", location.pathname);
  const callback = fragment.get("callback");
  const message = JSON.parse(fragment.get("message"));
  fetch("/.well-known/ii-auth-callbacks", { cache: "no-store" })
    .then((response) => response.json())
    .then((document) => {
      if (!document.callbacks.includes(callback)) {
        status.textContent = "callback not declared";
        return;
      }
      const response = {
        jsonrpc: "2.0",
        id: message.id,
        result: {
          publicKey: "AQID",
          signerDelegation: [{
            delegation: { pubkey: "AQID", expiration: String((Date.now() + 3600 * 1000) * 1e6) },
            signature: "AAAA",
          }],
        },
      };
      const next = new URL(callback);
      next.hash = new URLSearchParams({
        message: JSON.stringify(response),
        state: fragment.get("state"),
      }).toString();
      location.replace(next.toString());
    })
    .catch((error) => { status.textContent = String(error); });
})();
</script></body></html>"""


class RelayHandler(BaseHTTPRequestHandler):
    """Serves the relay pages, the allow-list and the fake signer."""

    origin = ""

    def log_message(self, fmt: str, *args) -> None:  # noqa: N802 - http.server API
        pass

    def respond(self, status: int, body: bytes, content_type: str, cors: bool = False) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if cors:
            self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        path = self.path.split("?")[0]
        if path in ("/auth", "/auth/"):
            self.respond(HTTPStatus.OK, (HERE / "auth" / "index.html").read_bytes(), "text/html; charset=utf-8")
            return
        if path in ("/auth/callback", "/auth/callback.html"):
            self.respond(HTTPStatus.OK, (HERE / "auth" / "callback.html").read_bytes(), "text/html; charset=utf-8")
            return
        if path in ("/auth/callback-safari", "/auth/callback-safari.html"):
            self.respond(HTTPStatus.OK, safari_callback_html(), "text/html; charset=utf-8")
            return
        if path == "/.well-known/ii-auth-callbacks":
            document = {"callbacks": [self.origin + "/auth/callback", self.origin + "/auth/callback-safari"]}
            self.respond(HTTPStatus.OK, json.dumps(document).encode(), "application/json", cors=True)
            return
        if path == "/fake-signer":
            self.respond(HTTPStatus.OK, FAKE_SIGNER.encode(), "text/html; charset=utf-8")
            return
        self.respond(HTTPStatus.NOT_FOUND, b"not found", "text/plain; charset=utf-8")


class Captured:
    """What a loopback listener received."""

    def __init__(self) -> None:
        self.payloads: list[dict] = []
        self.authorization: str | None = None
        self.cors: str | None = None
        self.event = threading.Event()


class LoopbackHandler(BaseHTTPRequestHandler):
    """Stands in for the native listener that receives the relay's report.

    Implements the two endpoints the pages use: `POST /icrc167` for one step's
    answer and `GET /icrc167/poll` for the next step of the ceremony. `script`
    holds the scripted next navigations; an empty script means "done".
    """

    captured = Captured()
    token = ""
    script: list[dict] = []

    def log_message(self, fmt: str, *args) -> None:  # noqa: N802 - http.server API
        pass

    def do_OPTIONS(self) -> None:  # noqa: N802 - http.server API
        self.send_response(HTTPStatus.NO_CONTENT)
        self.add_headers()
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802 - http.server API
        capture = type(self).captured
        authorization = self.headers.get("Authorization")
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        status = HTTPStatus.NO_CONTENT
        if self.path != "/icrc167":
            status = HTTPStatus.NOT_FOUND
        elif authorization != "Bearer " + type(self).token:
            status = HTTPStatus.UNAUTHORIZED
            capture.authorization = authorization
        else:
            capture.authorization = authorization
            capture.cors = self.headers.get("Origin")
            capture.payloads.append(json.loads(body))
            capture.event.set()
        self.send_response(status)
        self.add_headers()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        capture = type(self).captured
        authorization = self.headers.get("Authorization")
        if self.path.split("?")[0] == "/icrc167/handoff":
            # No credentials: the token is in the fragment, and the page is static.
            body = HANDOFF_PAGE.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.add_headers()
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path != "/icrc167/poll":
            status, document = HTTPStatus.NOT_FOUND, {"error": "not found"}
        elif authorization != "Bearer " + type(self).token:
            status, document = HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"}
        else:
            capture.authorization = authorization
            script = type(self).script
            if script:
                status, document = HTTPStatus.OK, {"next": script.pop(0)}
            else:
                status, document = HTTPStatus.OK, {"done": True}
        body = json.dumps(document).encode()
        self.send_response(status)
        self.add_headers()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def add_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "authorization, content-type")
        self.send_header("Access-Control-Allow-Private-Network", "true")


def serve(handler: type[BaseHTTPRequestHandler], port: int = 0) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class Driver:
    """Minimal WebDriver client (stdlib only)."""

    def __init__(self, executable: str, driver_port: int, chrome: str):
        self.process = subprocess.Popen(
            [executable, f"--port={driver_port}", "--allowed-ips=127.0.0.1"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                if http("GET", f"http://127.0.0.1:{driver_port}/status")["value"]["ready"]:
                    break
            except Exception:
                time.sleep(0.1)
        else:
            raise TimeoutError("chromedriver did not start")
        response = http(
            "POST",
            f"http://127.0.0.1:{driver_port}/session",
            {
                "capabilities": {
                    "alwaysMatch": {
                        "browserName": "chrome",
                        "goog:chromeOptions": {
                            "binary": chrome,
                            "args": [
                                "--headless=new",
                                "--no-sandbox",
                                "--disable-gpu",
                                "--disable-dev-shm-usage",
                            ],
                        },
                    }
                }
            },
        )
        self.base = f"http://127.0.0.1:{driver_port}/session/{response['value']['sessionId']}"
        self.port = driver_port

    def get(self, url: str) -> None:
        http("POST", f"{self.base}/url", {"url": url})

    def text(self, selector: str = "#status") -> str:
        return http(
            "POST",
            f"{self.base}/execute/sync",
            {
                "script": "const e = document.querySelector(arguments[0]); return e ? e.textContent : null",
                "args": [selector],
            },
        )["value"]

    def url(self) -> str:
        return http("GET", f"{self.base}/url")["value"]

    def quit(self) -> None:
        try:
            http("DELETE", self.base)
        finally:
            self.process.terminate()
            self.process.wait(timeout=20)


def http(method: str, url: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"{method} {url} -> {error.code}: {error.read()[:400]!r}") from error


def fragment(**fields: str) -> str:
    from urllib.parse import urlencode

    return urlencode(fields)


def message(request_id: str = "1") -> str:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "ii_session_delegation",
            "params": {"sessionPublicKey": "AQID", "maxTimeToLive": "28800000000000"},
        }
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--chromedriver", default=DEFAULT_DRIVER)
    parser.add_argument("--chrome", default=DEFAULT_CHROME)
    parser.add_argument("--driver-port", type=int, default=9515)
    args = parser.parse_args()

    relay_server = serve(RelayHandler)
    relay_origin = f"http://127.0.0.1:{relay_server.server_address[1]}"
    RelayHandler.origin = relay_origin

    driver = Driver(args.chromedriver, args.driver_port, args.chrome)
    try:
        # -- happy path ----------------------------------------------------
        captured = Captured()
        LoopbackHandler.captured = captured
        LoopbackHandler.token = "token-" + str(int(time.time() * 1_000_000))
        loopback = serve(LoopbackHandler)
        loopback_port = str(loopback.server_address[1])

        fields = {
            "port": loopback_port,
            "token": LoopbackHandler.token,
            "state": "state-happy",
        }
        driver.get(
            relay_origin
            + "/auth/?case=happy#"
            + fragment(
                signer=relay_origin + "/fake-signer",
                message=message("happy-1"),
                callback=relay_origin + "/auth/callback",
                **fields,
            )
        )
        if not captured.event.wait(timeout=30):
            return fail("the relay never delivered the answer", driver)
        payload = captured.payloads[0] if captured.payloads else {}
        assert payload.get("state") == "state-happy", payload
        answered = json.loads(payload.get("message", "null"))
        assert answered["id"] == "happy-1", answered
        assert len(answered["result"]["signerDelegation"]) == 1, answered
        assert "Done" in wait_for_text(driver, "Done"), driver.text()
        assert driver.url().startswith(relay_origin + "/auth/callback"), driver.url()
        print("PASS  happy path: fragment -> signer -> callback -> loopback, state and id checked")

        # -- a second step rides the same tab ------------------------------
        captured = Captured()
        LoopbackHandler.captured = captured
        LoopbackHandler.script = [
            {
                "signer": relay_origin + "/fake-signer",
                "message": message("happy-2"),
                "state": "state-happy-2",
                "callback": relay_origin + "/auth/callback",
            }
        ]
        driver.get(
            relay_origin
            + "/auth/?case=continue#"
            + fragment(
                signer=relay_origin + "/fake-signer",
                message=message("happy-1"),
                callback=relay_origin + "/auth/callback",
                port=loopback_port,
                token=LoopbackHandler.token,
                state="state-happy",
            )
        )
        if not captured.event.wait(timeout=30):
            return fail("the relay never delivered the answer", driver)
        # The page reports the first answer, polls, navigates again in the same
        # tab and reports the second one.
        deadline = time.monotonic() + 20
        while len(captured.payloads) < 2 and time.monotonic() < deadline:
            time.sleep(0.1)
        assert len(captured.payloads) == 2, captured.payloads
        assert captured.payloads[0]["state"] == "state-happy", captured.payloads
        assert captured.payloads[1]["state"] == "state-happy-2", captured.payloads
        assert "Done" in wait_for_text(driver, "Done"), driver.text()
        captured_url = driver.url()
        assert captured_url.startswith(relay_origin + "/auth/callback"), captured_url
        print("PASS  a second step navigated the same tab (long-poll continuation)")
        LoopbackHandler.script = []

        # -- Safari: the page cannot read loopback, so it navigates ----------
        # Safari refuses an https page reading http://127.0.0.1. The callback
        # page hands the answer to the listener-served page by navigation
        # instead, which posts same-origin and continues the ceremony.
        captured = Captured()
        LoopbackHandler.captured = captured
        LoopbackHandler.token = "token-safari-" + str(int(time.time() * 1_000_000))
        LoopbackHandler.script = [
            {
                "signer": relay_origin + "/fake-signer",
                "message": message("safari-2"),
                "state": "state-safari-2",
                "callback": relay_origin + "/auth/callback-safari",
            }
        ]
        driver.get(
            relay_origin
            + "/auth/?case=safari#"
            + fragment(
                signer=relay_origin + "/fake-signer",
                message=message("safari-1"),
                callback=relay_origin + "/auth/callback-safari",
                port=loopback_port,
                token=LoopbackHandler.token,
                state="state-safari",
            )
        )
        deadline = time.monotonic() + 30
        while len(captured.payloads) < 2 and time.monotonic() < deadline:
            time.sleep(0.1)
        assert len(captured.payloads) == 2, captured.payloads
        assert captured.payloads[0]["state"] == "state-safari", captured.payloads
        assert captured.payloads[1]["state"] == "state-safari-2", captured.payloads
        text = wait_for_text(driver, "Done")
        assert "Done" in (text or ""), text
        assert driver.url().startswith(
            f"http://127.0.0.1:{loopback_port}/icrc167/handoff"
        ), driver.url()
        print("PASS  a browser that cannot read loopback hands off to the served page")
        LoopbackHandler.script = []

        # -- the callback must be on the relay's origin --------------------
        driver.get(
            relay_origin
            + "/auth/?case=foreign#"
            + fragment(
                signer=relay_origin + "/fake-signer",
                message=message(),
                state="state-foreign",
                callback="https://evil.example/callback",
                port="1",
                token="x",
            )
        )
        text = wait_for_text(driver, "callback")
        assert "callback must be on this relay's origin" in (text or ""), text
        print("PASS  a foreign callback is refused before any navigation")

        # -- one request per navigation ------------------------------------
        driver.get(
            relay_origin
            + "/auth/?case=batch#"
            + fragment(
                signer=relay_origin + "/fake-signer",
                message=json.dumps([json.loads(message())]),
                state="state-batch",
                callback=relay_origin + "/auth/callback",
                port="1",
                token="x",
            )
        )
        text = wait_for_text(driver, "one ICRC-167 request")
        assert "one ICRC-167 request at a time" in (text or ""), text
        print("PASS  a batch is refused with the reason")

        # -- the relay page is not opened by hand --------------------------
        driver.get(relay_origin + "/auth/?case=hand")
        text = wait_for_text(driver, "opened by the application")
        assert "opened by the application" in (text or ""), text
        print("PASS  a hand-opened relay page explains itself")

        # -- a wrong token is not delivered --------------------------------
        captured = Captured()
        LoopbackHandler.captured = captured
        LoopbackHandler.token = "the-right-token"
        loopback2 = serve(LoopbackHandler)
        driver.get(
            relay_origin
            + "/auth/?case=token#"
            + fragment(
                signer=relay_origin + "/fake-signer",
                message=message("wrong-token"),
                state="state-token",
                callback=relay_origin + "/auth/callback",
                port=str(loopback2.server_address[1]),
                token="the-wrong-token",
            )
        )
        text = wait_for_text(driver, "refused")
        assert "refused" in (text or ""), text
        assert not captured.event.is_set(), "a wrong token must not be delivered"
        print("PASS  a wrong bearer token is refused and nothing is recorded")
    finally:
        driver.quit()
        relay_server.shutdown()
    print("all relay page checks passed")
    return 0


def wait_for_text(driver: Driver, needle: str, timeout: float = 20) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        text = driver.text() or ""
        if needle in text:
            return text
        time.sleep(0.1)
    return driver.text() or ""


def fail(message: str, driver: Driver) -> int:
    print(f"FAIL  {message} (page says {driver.text()!r})")
    driver.quit()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
