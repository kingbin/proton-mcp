import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { readdirSync, statSync } from "node:fs";
import { X509Certificate } from "node:crypto";
import type { PeerCertificate } from "node:tls";
import { fileURLToPath } from "node:url";
import { join, relative } from "node:path";
import { tlsOptions, guardPinnedTls, CERT_CHANGED_MESSAGE } from "../core/tls.js";
import { ConfigError } from "../core/config.js";

const FIXTURE = fileURLToPath(new URL("../../tests/fixtures/bridge-test-cert.pem", import.meta.url));
const ROOT = fileURLToPath(new URL("../../", import.meta.url));

const fakeCert = (fingerprint256: string) => ({ fingerprint256 }) as unknown as PeerCertificate;

test("tlsOptions pins the PEM: verification on, TLS 1.2+, ca set", async () => {
  const pem = await readFile(FIXTURE, "utf8");
  const o = await tlsOptions(FIXTURE);
  assert.equal(o.rejectUnauthorized, true);
  assert.equal(o.minVersion, "TLSv1.2");
  assert.equal(o.ca, pem);
  assert.equal(typeof o.checkServerIdentity, "function");
});

test("checkServerIdentity accepts the pinned fingerprint and rejects any other", async () => {
  const pem = await readFile(FIXTURE, "utf8");
  const fp = new X509Certificate(pem).fingerprint256;
  const o = await tlsOptions(FIXTURE);
  assert.equal(o.checkServerIdentity!("127.0.0.1", fakeCert(fp)), undefined);
  const bad = o.checkServerIdentity!("127.0.0.1", fakeCert(fp.replace(/^../, fp.startsWith("00") ? "11" : "00")));
  assert.ok(bad instanceof Error);
  assert.equal(bad.message, "Bridge certificate changed. Re-export it from Bridge and run: proton-mcp pin-cert <file>");
  assert.equal(CERT_CHANGED_MESSAGE, bad.message);
  const missing = o.checkServerIdentity!("127.0.0.1", {} as PeerCertificate);
  assert.ok(missing instanceof Error);
});

test("tlsOptions rejects a file that is not a certificate", async () => {
  await assert.rejects(tlsOptions(fileURLToPath(new URL("../../package.json", import.meta.url))));
});

test("guardPinnedTls refuses unpinned options and reports pin failures", async () => {
  const pinned = await tlsOptions(FIXTURE);
  for (const bad of [
    { ...pinned, rejectUnauthorized: false },
    { ...pinned, rejectUnauthorized: undefined },
    { ...pinned, ca: undefined },
    { ...pinned, checkServerIdentity: undefined },
  ]) {
    assert.throws(() => guardPinnedTls(bad, () => {}), ConfigError);
  }
  let failures = 0;
  const guarded = guardPinnedTls(pinned, () => failures++);
  assert.ok(guarded.checkServerIdentity!("127.0.0.1", fakeCert("00:11")) instanceof Error);
  assert.equal(failures, 1);
});

const SKIP_DIRS = new Set(["node_modules", "build", "tests", ".superpowers", ".git"]);
const SOURCE_EXT = /\.(ts|js|mts|cts|mjs|cjs)$/;

/** Every non-test source file in the repo, so new service folders are covered automatically. */
function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) return SKIP_DIRS.has(name) ? [] : sourceFiles(p);
    return SOURCE_EXT.test(name) ? [p] : [];
  });
}

const KEYCHAIN = join("core", "keychain.ts");
const TLS = join("core", "tls.ts");
const IMAP_STORE = join("Mail", "imapStore.ts");

const MODS = "vm|worker_threads|dns|tls|undici|http2|dgram|net|http|https";
const SPEC = `["'\`](?:node:)?(?:${MODS})(?:/[^"'\`]*)?["'\`]`;

/**
 * Patterns that must not appear in shipped source. A regex scan catches accidental
 * reintroduction; it is not a sandbox and a determined author could evade it.
 * `allow` lists the only files a pattern may appear in.
 */
const FORBIDDEN: { re: RegExp; what: string; allow?: string[]; sample: string }[] = [
  { re: /child_process/, what: "child_process", allow: [KEYCHAIN], sample: 'import { execFile } from "node:child_process";' },
  { re: /\bexecFile(Sync)?\b/, what: "execFile", allow: [KEYCHAIN], sample: "execFile(cmd, args)" },
  { re: /(?:(?<![.\w$])|\b(?:child_process|childProcess|cp)\s*\.\s*)exec(Sync)?\s*\(/, what: "exec()", sample: "cp.exec ('ls')" },
  { re: /\bspawn(Sync)?\b/, what: "spawn", sample: "spawnSync(cmd)" },
  { re: /\bfork\s*\(/, what: "fork()", sample: "fork('x.js')" },
  { re: /\beval\s*\(/, what: "eval()", sample: "eval (code)" },
  { re: /\bFunction\s*\(/, what: "Function()", sample: "Function('return this')()" },
  { re: /new\s+Function\b/, what: "new Function", sample: "new  Function" },
  { re: /\.\s*constructor\s*\(/, what: ".constructor() call", sample: "(() => 0).constructor('code')" },
  { re: /(?:(?<![.\w$])|\b(?:globalThis|window|self|global)\s*\.\s*)fetch\s*\(/, what: "fetch()", sample: "globalThis.fetch(url)" },
  { re: /\bWebSocket\b/, what: "WebSocket", sample: "new WebSocket(u)" },
  { re: /\bcreateRequire\b/, what: "createRequire", sample: 'createRequire(import.meta.url)' },
  { re: /\bprocess\s*(?:\.\s*binding\b|\[\s*["'`]binding)/, what: "process.binding", sample: 'process["binding"]("fs")' },
  { re: /\bimport\s*\(\s*(?!["'][^"'`$]*["']\s*\))/, what: "dynamic import with a non-literal argument", sample: "await import(name)" },
  { re: /rejectUnauthorized\s*[:=]\s*false/, what: "rejectUnauthorized false", sample: "rejectUnauthorized:false" },
  { re: /\[\s*["'`]rejectUnauthorized["'`]\s*\]/, what: '["rejectUnauthorized"]', sample: "o['rejectUnauthorized'] = x" },
  { re: /NODE_TLS_REJECT_UNAUTHORIZED/, what: "NODE_TLS_REJECT_UNAUTHORIZED", sample: 'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"' },
  { re: /\bcheckServerIdentity\b/, what: "checkServerIdentity", allow: [TLS], sample: "{ checkServerIdentity: () => undefined }" },
  { re: /\bshell\s*:/, what: "shell option", sample: "{ shell : true }" },
  {
    // Value imports, re-exports, requires and dynamic imports of network/VM modules: nowhere.
    re: new RegExp(
      `(?:\\bimport\\s+(?!type\\b)[^;]*?\\bfrom\\s*|\\bimport\\s*|\\bexport\\s+[^;]*?\\bfrom\\s*|\\bimport\\s*\\(\\s*|\\brequire\\s*\\(\\s*)${SPEC}`,
    ),
    what: "value import of a network/VM module",
    sample: 'import * as net from "node:net";',
  },
  {
    // Type-only imports: node:tls types in the two TLS files only, nothing else anywhere.
    re: new RegExp(`\\bimport\\s+type\\s+[^;]*?\\bfrom\\s*["'\`](?:node:)?tls["'\`]`),
    what: "type import of node:tls",
    allow: [TLS, IMAP_STORE],
    sample: 'import type { ConnectionOptions } from "node:tls";',
  },
  {
    re: new RegExp(`\\bimport\\s+type\\s+[^;]*?\\bfrom\\s*["'\`](?:node:)?(?:vm|worker_threads|dns|undici|http2|dgram|net|http|https)["'\`]`),
    what: "type import of a network/VM module",
    sample: 'import type { Socket } from "net";',
  },
];

const byWhat = (w: string) => FORBIDDEN.find((f) => f.what === w)!.re;

test("static safety patterns catch their samples, and known-safe code does not trip them", () => {
  for (const f of FORBIDDEN) assert.match(f.sample, f.re, f.what);
  const extra: [string, string][] = [
    ["exec()", "exec('ls')"],
    ["exec()", "child_process.execSync('ls')"],
    ["fetch()", "fetch('https://x')"],
    ["Function()", "new Function('a', 'return a')"],
    ["dynamic import with a non-literal argument", "import(`./${x}.js`)"],
    ["value import of a network/VM module", 'import tls from "node:tls";'],
    ["value import of a network/VM module", 'import { connect } from "tls";'],
    ["value import of a network/VM module", 'import "node:https";'],
    ["value import of a network/VM module", 'const vm = require("vm");'],
    ["value import of a network/VM module", 'await import("node:worker_threads")'],
    ["value import of a network/VM module", 'export { request } from "undici";'],
    ["value import of a network/VM module", 'import { lookup } from "node:dns/promises";'],
    ["value import of a network/VM module", 'import { type Socket, connect } from "node:net";'],
  ];
  for (const [what, src] of extra) assert.match(src, byWhat(what), `${what}: ${src}`);
  const safe: [string, string][] = [
    ["exec()", "const m = /x/.exec(s);"],
    ["exec()", "RE.exec (line)"],
    ["exec()", "execFile(cmd)"],
    ["fetch()", "for await (const m of c.fetch(uids)) {}"],
    ["fetch()", "await c.fetchOne('1')"],
    ["dynamic import with a non-literal argument", 'const { statSync } = await import("node:fs");'],
    ["value import of a network/VM module", 'import type { ConnectionOptions } from "node:tls";'],
    ["value import of a network/VM module", 'import { x } from "./net.js";'],
    ["value import of a network/VM module", 'import { z } from "zod";'],
  ];
  for (const [what, src] of safe) assert.doesNotMatch(src, byWhat(what), `${what}: ${src}`);
});

test("static safety: shipped source has none of the forbidden patterns", async () => {
  const files = sourceFiles(ROOT);
  const rels = files.map((f) => relative(ROOT, f));
  for (const must of [KEYCHAIN, TLS, IMAP_STORE, "index.ts", join("Mail", "tools.ts")]) assert.ok(rels.includes(must), must);
  assert.ok(!rels.some((r) => r.startsWith("tests") || r.startsWith("build") || r.startsWith("node_modules")));
  const hits: string[] = [];
  for (const f of files) {
    const rel = relative(ROOT, f);
    const src = await readFile(f, "utf8");
    for (const { re, what, allow } of FORBIDDEN) {
      if (!allow?.includes(rel) && re.test(src)) hits.push(`${rel}: ${what}`);
    }
  }
  assert.deepEqual(hits, []);
});
