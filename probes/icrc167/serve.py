#!/usr/bin/env python3
"""Serves the ICRC-167 probe and the allow-list it needs.

Two things make this more than `python -m http.server`:

* the callback allow-list must live at the origin root
  (`/.well-known/ii-auth-callbacks`), which a project GitHub Pages site cannot
  serve, and it must carry CORS and `no-store` headers;
* the same origin has to be announced to the probe so the allow-list and the
  callback URL agree byte-for-byte.

Run it behind any HTTPS tunnel for a real Internet Identity run:

    python3 probes/icrc167/serve.py --public-origin https://<tunnel-host>
    npx cloudflared tunnel --url http://127.0.0.1:8787

and for an offline self-test against the local fake signer:

    python3 probes/icrc167/serve.py --fake-signer

`--export DIR` writes the static site (allow-list included) so it can be
uploaded to Netlify Drop / Cloudflare Pages instead.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
CALLBACK_PATH = "/callback.html"
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/callback.html": ("callback.html", "text/html; charset=utf-8"),
    "/fake-signer.html": ("fake-signer.html", "text/html; charset=utf-8"),
    "/icrc167.js": ("icrc167.js", "text/javascript; charset=utf-8"),
}


def allow_list(origin: str) -> dict:
    return {"callbacks": [origin + CALLBACK_PATH]}


def alternative_origins(origin: str) -> dict:
    # E5 asks II to derive as this origin; II fetches this document from the
    # derivation origin and only honours E5 if it declares the relying party.
    return {"alternativeOrigins": [origin]}


class ProbeHandler(BaseHTTPRequestHandler):
    public_origin = ""
    fake_signer = False
    server_version = "icrc167-probe/1"

    def log_message(self, fmt: str, *args) -> None:  # noqa: N802 - http.server API
        sys.stderr.write("[probe] %s %s\n" % (self.address_string(), fmt % args))
        if self.headers.get("user-agent"):
            sys.stderr.write("[probe]   user-agent: %s\n" % self.headers["user-agent"])

    # -- helpers ------------------------------------------------------------
    def write(self, status: int, body: bytes, content_type: str, cors: bool) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if cors:
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Vary", "Origin")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def write_json(self, document: dict) -> None:
        body = json.dumps(document).encode()
        self.write(HTTPStatus.OK, body, "application/json", cors=True)

    # -- routes -------------------------------------------------------------
    def do_OPTIONS(self) -> None:  # noqa: N802 - http.server API
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.end_headers()

    def do_HEAD(self) -> None:  # noqa: N802 - http.server API
        self.do_GET()

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        path = urlparse(self.path).path
        if path == "/.well-known/ii-auth-callbacks":
            return self.write_json(allow_list(self.public_origin))
        if path == "/.well-known/ii-alternative-origins":
            return self.write_json(alternative_origins(self.public_origin))
        entry = STATIC_FILES.get(path)
        if entry is None:
            body = f"not found: {path}\n".encode()
            return self.write(HTTPStatus.NOT_FOUND, body, "text/plain; charset=utf-8", cors=False)
        name, content_type = entry
        file = HERE / name
        if not file.is_file():
            body = f"missing file: {name}\n".encode()
            return self.write(HTTPStatus.NOT_FOUND, body, "text/plain; charset=utf-8", cors=False)
        self.write(HTTPStatus.OK, file.read_bytes(), content_type, cors=False)


def export_site(target: Path, public_origin: str) -> None:
    target.mkdir(parents=True, exist_ok=True)
    well_known = target / ".well-known"
    well_known.mkdir(exist_ok=True)
    for name in ("index.html", "callback.html", "fake-signer.html", "icrc167.js"):
        shutil.copyfile(HERE / name, target / name)
    headers = HERE / "_headers"
    if headers.is_file():
        shutil.copyfile(headers, target / "_headers")
    (well_known / "ii-auth-callbacks").write_text(
        json.dumps(allow_list(public_origin), indent=2) + "\n"
    )
    (well_known / "ii-alternative-origins").write_text(
        json.dumps(alternative_origins(public_origin), indent=2) + "\n"
    )
    print(f"static site written to {target}")
    print(f"  allow-list declares: {public_origin + CALLBACK_PATH}")
    print("  upload the whole directory to Netlify Drop / Cloudflare Pages")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument(
        "--public-origin",
        default=None,
        help="the HTTPS origin the browser and Internet Identity will use "
        "(default: http://127.0.0.1:<port>)",
    )
    parser.add_argument(
        "--fake-signer",
        action="store_true",
        help="make the probe default to the local fake signer (offline self-test)",
    )
    parser.add_argument(
        "--export",
        metavar="DIR",
        default=None,
        help="write a static copy (allow-list included) instead of serving",
    )
    args = parser.parse_args()

    public_origin = (args.public_origin or f"http://127.0.0.1:{args.port}").rstrip("/")
    if args.export:
        export_site(Path(args.export), public_origin)
        return 0

    ProbeHandler.public_origin = public_origin
    ProbeHandler.fake_signer = args.fake_signer
    server = ThreadingHTTPServer(("127.0.0.1", args.port), ProbeHandler)
    print(f"probe:      {public_origin}/")
    print(f"callback:   {public_origin}{CALLBACK_PATH}")
    print(f"allow-list: {public_origin}/.well-known/ii-auth-callbacks")
    if args.fake_signer:
        print(f"open:       {public_origin}/?signer=/fake-signer.html  (local fake signer)")
        print("signer:     /fake-signer.html (local)")
    else:
        print("signer:     https://id.ai/authorize  (override with ?signer=...)")
    print("Ctrl-C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
