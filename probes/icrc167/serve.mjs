#!/usr/bin/env node
// Node twin of serve.py, for machines whose `python3` is an Xcode stub or
// missing. Same routes, same headers, same `--export` output.
//
//   node probes/icrc167/serve.mjs --port 8787 --public-origin https://<tunnel-host>
//   node probes/icrc167/serve.mjs --fake-signer
//   node probes/icrc167/serve.mjs --export site --public-origin https://<host>
//
// `--public-origin` must be the HTTPS origin the browser and Internet Identity
// will use (a tunnel host), because II fetches the allow-list from it.

import { createServer } from "node:http";
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const CALLBACK_PATH = "/callback.html";

const STATIC_FILES = new Map([
  ["/", ["index.html", "text/html; charset=utf-8"]],
  ["/index.html", ["index.html", "text/html; charset=utf-8"]],
  ["/callback.html", ["callback.html", "text/html; charset=utf-8"]],
  ["/fake-signer.html", ["fake-signer.html", "text/html; charset=utf-8"]],
  ["/icrc167.js", ["icrc167.js", "text/javascript; charset=utf-8"]],
  ["/serve.mjs", ["serve.mjs", "text/javascript; charset=utf-8"]],
]);

function parseArgs(argv) {
  const options = { port: 8787, publicOrigin: null, fakeSigner: false, export: null };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    const value = () => {
      const next = argv[index + 1];
      if (next === undefined) throw new Error(`${argument} needs a value`);
      index += 1;
      return next;
    };
    switch (argument) {
      case "--port":
        options.port = Number(value());
        break;
      case "--public-origin":
        options.publicOrigin = value();
        break;
      case "--fake-signer":
        options.fakeSigner = true;
        break;
      case "--export":
        options.export = value();
        break;
      case "--help":
      case "-h":
        console.log("usage: node serve.mjs [--port 8787] [--public-origin https://host] [--fake-signer] [--export DIR]");
        process.exit(0);
        break;
      default:
        throw new Error(`unknown argument: ${argument}`);
    }
  }
  options.publicOrigin = (options.publicOrigin ?? `http://127.0.0.1:${options.port}`).replace(/\/+$/, "");
  return options;
}

function allowList(origin) {
  return { callbacks: [origin + CALLBACK_PATH] };
}

function alternativeOrigins(origin) {
  return { alternativeOrigins: [origin] };
}

function exportSite(target, origin) {
  mkdirSync(join(target, ".well-known"), { recursive: true });
  for (const name of ["index.html", "callback.html", "fake-signer.html", "icrc167.js", "_headers"]) {
    copyFileSync(join(HERE, name), join(target, name));
  }
  writeFileSync(join(target, ".well-known", "ii-auth-callbacks"), `${JSON.stringify(allowList(origin), null, 2)}\n`);
  writeFileSync(
    join(target, ".well-known", "ii-alternative-origins"),
    `${JSON.stringify(alternativeOrigins(origin), null, 2)}\n`,
  );
  console.log(`static site written to ${target}`);
  console.log(`  allow-list declares: ${origin + CALLBACK_PATH}`);
  console.log("  upload the whole directory to Netlify Drop / Cloudflare Pages");
}

function sendJson(response, document) {
  const body = Buffer.from(JSON.stringify(document));
  response.writeHead(200, {
    "Content-Type": "application/json",
    "Content-Length": body.length,
    "Cache-Control": "no-store",
    "Access-Control-Allow-Origin": "*",
    Vary: "Origin",
  });
  response.end(body);
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.export) {
    exportSite(options.export, options.publicOrigin);
    return;
  }

  const server = createServer((request, response) => {
    const url = new URL(request.url ?? "/", options.publicOrigin);
    const path = url.pathname;
    process.stderr.write(`[probe] ${request.socket.remoteAddress} ${request.method} ${path}\n`);
    if (request.headers["user-agent"]) {
      process.stderr.write(`[probe]   user-agent: ${request.headers["user-agent"]}\n`);
    }

    if (path === "/.well-known/ii-auth-callbacks") return sendJson(response, allowList(options.publicOrigin));
    if (path === "/.well-known/ii-alternative-origins") return sendJson(response, alternativeOrigins(options.publicOrigin));

    if (options.fakeSigner && path === "/" && !url.searchParams.has("signer")) {
      response.writeHead(302, { Location: "/?signer=/fake-signer.html", "Content-Length": 0 });
      response.end();
      return;
    }

    const entry = STATIC_FILES.get(path);
    if (!entry) {
      response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8", "Content-Length": 0 });
      response.end(`not found: ${path}\n`);
      return;
    }
    const [name, contentType] = entry;
    let body;
    try {
      body = readFileSync(join(HERE, name));
    } catch {
      response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      response.end(`missing file: ${name}\n`);
      return;
    }
    response.writeHead(200, {
      "Content-Type": contentType,
      "Content-Length": body.length,
      "Cache-Control": "no-store",
    });
    response.end(request.method === "HEAD" ? undefined : body);
  });

  server.listen(options.port, "127.0.0.1", () => {
    console.log(`probe:      ${options.publicOrigin}/`);
    console.log(`callback:   ${options.publicOrigin}${CALLBACK_PATH}`);
    console.log(`allow-list: ${options.publicOrigin}/.well-known/ii-auth-callbacks`);
    console.log(`signer:     ${options.fakeSigner ? "/fake-signer.html (local)" : "https://id.ai/authorize"}`);
    console.log("Ctrl-C to stop");
  });
}

try {
  main();
} catch (error) {
  console.error(`error: ${error instanceof Error ? error.message : error}`);
  process.exit(1);
}
