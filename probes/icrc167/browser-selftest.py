#!/usr/bin/env python3
"""End-to-end self-test of the probe against the local fake signer.

Drives the real browser flow (navigation to a signer, the signer validating the
allow-list, the fragment coming back on the callback page, the results landing
in `sessionStorage`) without touching Internet Identity, so the plumbing is
known-good before a real run.

    python3 probes/icrc167/browser-selftest.py

Needs a ChromeDriver matching the installed Chrome. Pass `--chromedriver` and
`--chrome` if they are not at the documented default paths.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_DRIVER = "/tmp/chromedriver-157/chromedriver-mac-arm64/chromedriver"
DEFAULT_CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"


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


def wait_until(predicate, timeout: float, interval: float = 0.1, label: str = "condition"):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    raise TimeoutError(f"timed out waiting for {label}")


class Driver:
    def __init__(self, executable: str, port: int, chrome: str):
        self.port = port
        self.process = subprocess.Popen(
            [executable, f"--port={port}", "--allowed-ips=127.0.0.1"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        wait_until(lambda: self._status_ok(), 30, label="chromedriver")
        response = http(
            "POST",
            f"http://127.0.0.1:{port}/session",
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
                                "--window-size=1200,900",
                            ],
                        },
                    }
                }
            },
        )
        self.session = response["value"]["sessionId"]
        self.base = f"http://127.0.0.1:{port}/session/{self.session}"

    def _status_ok(self) -> bool:
        try:
            return http("GET", f"http://127.0.0.1:{self.port}/status")["value"]["ready"]
        except Exception:
            return False

    def get(self, url: str) -> None:
        http("POST", f"{self.base}/url", {"url": url})

    def script(self, source: str):
        return http("POST", f"{self.base}/execute/sync", {"script": source, "args": []})["value"]

    def quit(self) -> None:
        try:
            http("DELETE", self.base)
        finally:
            self.process.terminate()
            self.process.wait(timeout=20)


def selftest_results(driver: Driver, url: str, expected_title_prefix: str, timeout: float) -> list:
    driver.get(url)
    # The page reads the allow-list itself before any experiment; a regression
    # there (a shadowed `document`, a missing CORS header) must fail loudly
    # here rather than only in a real Internet Identity round-trip.
    def allow_list_checked():
        try:
            status = driver.script(
                "const s = document.getElementById('allow-list-status');"
                "return s ? s.className + '|' + s.textContent : null"
            )
        except Exception:
            return None
        return status if isinstance(status, str) and status.startswith("ok|") else None

    status = wait_until(allow_list_checked, 30, interval=0.1, label="the allow-list check to pass")
    assert "declares this callback" in status, status
    title = wait_until(
        lambda: (
            lambda value: value if isinstance(value, str) and value.startswith(expected_title_prefix) else None
        )(driver.script("return document.title")),
        timeout,
        interval=0.2,
        label=f"{url} to reach title {expected_title_prefix!r}",
    )
    payload = driver.script("return document.getElementById('selftest-output').textContent")
    document = json.loads(payload)
    return title, document["results"]


# What each experiment expects from a signer that behaves like Internet Identity.
EXPECTATIONS = {"E1": "success", "E2": "success", "E3": "success", "E4": "error", "E5": "success"}


def assert_expected(result: dict) -> None:
    assert result["status"] == "response", f"{result['experiment']}: {result}"
    checks = result["checks"]
    assert checks.get("stateMatches") is True, f"{result['experiment']}: state did not round-trip"
    assert checks.get("idsMatch") is True, f"{result['experiment']}: response ids differ"
    expectation = EXPECTATIONS[result["experiment"]]
    if expectation == "error":
        assert checks["errors"], f"{result['experiment']}: expected a rejection, got {checks}"
        return
    assert checks.get("hasDelegation") is True, f"{result['experiment']}: no delegation in {checks}"
    assert checks.get("leafMatchesAskedKey") is True, f"{result['experiment']}: leaf is not the asked key"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--chromedriver", default=DEFAULT_DRIVER)
    parser.add_argument("--chrome", default=DEFAULT_CHROME)
    parser.add_argument("--serve-with", choices=["python", "node"], default="python")
    parser.add_argument("--port", type=int, default=8899)
    parser.add_argument("--driver-port", type=int, default=9515)
    args = parser.parse_args()

    if args.serve_with == "node":
        serve_command = ["node", str(HERE / "serve.mjs")]
    else:
        serve_command = [sys.executable, str(HERE / "serve.py")]
    server = subprocess.Popen(
        [*serve_command, "--port", str(args.port), "--fake-signer"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        wait_until(
            lambda: _allow_list_ready(args.port),
            30,
            label="the probe server",
        )
        driver = Driver(args.chromedriver, args.driver_port, args.chrome)
    except Exception:
        server.terminate()
        raise

    try:
        # Phase 1: the happy path through the fake signer.
        title, results = selftest_results(
            driver,
            f"http://127.0.0.1:{args.port}/?selftest=1&signer=%2Ffake-signer.html",
            "SELFTEST",
            timeout=120,
        )
        assert title == "SELFTEST PASS", f"selftest reported {title}: {json.dumps(results, indent=2)}"
        assert len(results) == 5, f"expected 5 experiments, got {len(results)}"
        for result in results:
            assert_expected(result)
        assert all(result["checks"]["isBatch"] is False for result in results), (
            "every request is a single JSON-RPC message; batches are a separate question"
        )
        print("PASS  happy path: 5 experiments, state/ids/leaf/expectation verified")

        # Phase 2: a signer that rejects must surface as an error, not a crash.
        driver.script("sessionStorage.clear()")
        title, results = selftest_results(
            driver,
            f"http://127.0.0.1:{args.port}/?selftest=1&signer=%2Ffake-signer.html%3Freject%3D1",
            "SELFTEST",
            timeout=120,
        )
        assert title.startswith("SELFTEST FAIL"), (
            f"rejecting signer should fail the positive experiments, got {title}: "
            + json.dumps(results, indent=2)
        )
        for result in results:
            errors = result["checks"]["errors"]
            assert errors and errors[0]["error"]["code"] == 3001, f"{result['experiment']}: {result}"
        print("PASS  error path: signer errors recorded, state still verified")
    finally:
        driver.quit()
        server.terminate()
        server.wait(timeout=20)
    return 0


def _allow_list_ready(port: int) -> bool:
    try:
        with urllib.request.urlopen(
            f"http://127.0.0.1:{port}/.well-known/ii-auth-callbacks", timeout=2
        ) as response:
            return response.status == 200 and "callbacks" in response.read().decode()
    except Exception:
        return False


if __name__ == "__main__":
    raise SystemExit(main())
