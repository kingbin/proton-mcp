import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, readdir, rm, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const ENTRY = join(HERE, "..", "index.js");

const TOOLS = ["mail_list_mailboxes", "mail_search", "mail_read", "mail_save_attachment"];

async function withHome<T>(fn: (home: string) => Promise<T>): Promise<T> {
  const home = await mkdtemp(join(tmpdir(), "proton-mcp-home-"));
  try {
    return await fn(home);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
}

test("server with no config lists the 4 tools and every call returns the setup error", async () => {
  await withHome(async (home) => {
    const env = Object.fromEntries(Object.entries({ ...process.env, HOME: home }).filter(([, v]) => v !== undefined)) as Record<string, string>;
    const client = new Client({ name: "test", version: "0.0.0" });
    const transport = new StdioClientTransport({ command: process.execPath, args: [ENTRY], env });
    await client.connect(transport);
    try {
      const { tools } = await client.listTools();
      assert.deepEqual(tools.map((t) => t.name).sort(), [...TOOLS].sort());
      for (const t of tools) assert.equal(t.inputSchema.type, "object");
      const READ = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false };
      const SAVE = { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false };
      for (const t of tools) {
        assert.deepEqual(t.annotations, t.name === "mail_save_attachment" ? SAVE : READ, t.name);
      }
      const res = await client.callTool({ name: "mail_search", arguments: {} });
      assert.equal(res.isError, true);
      const text = (res.content as { text: string }[])[0].text;
      assert.match(text, /^SETUP: /);
      assert.ok(text.includes("Config not found"), text);
      const bad = await client.callTool({ name: "nope", arguments: {} });
      assert.equal(bad.isError, true);
    } finally {
      await client.close();
    }
  });
});

test("pin-cert on a non-PEM file exits non-zero and writes nothing", async () => {
  await withHome(async (home) => {
    const f = join(home, "junk.txt");
    await writeFile(f, "not a certificate\n");
    const r = spawnSync(process.execPath, [ENTRY, "pin-cert", f], { env: { ...process.env, HOME: home }, encoding: "utf8" });
    assert.notEqual(r.status, 0);
    assert.equal(r.stdout, "");
    await assert.rejects(readdir(join(home, ".config", "proton-mcp")));
  });
});

test("pin-cert rejects a file with two certificate blocks", async () => {
  await withHome(async (home) => {
    const block = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    const f = join(home, "two.pem");
    await writeFile(f, block + block);
    const r = spawnSync(process.execPath, [ENTRY, "pin-cert", f], { env: { ...process.env, HOME: home }, encoding: "utf8" });
    assert.notEqual(r.status, 0);
    await assert.rejects(readdir(join(home, ".config", "proton-mcp")));
  });
});

test("pin-cert accepts a real certificate, writes it 0600 and prints the fingerprint", async () => {
  await withHome(async (home) => {
    const fixtures = join(HERE, "..", "..", "tests", "fixtures");
    const files = (await readdir(fixtures)).filter((n) => n.endsWith(".pem"));
    assert.ok(files.length > 0, "needs a PEM fixture");
    const r = spawnSync(process.execPath, [ENTRY, "pin-cert", join(fixtures, files[0])], { env: { ...process.env, HOME: home }, encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /^Pinned\. SHA-256: ([0-9A-F]{2}:){31}[0-9A-F]{2}\n$/);
    const { statSync } = await import("node:fs");
    const p = join(home, ".config", "proton-mcp", "bridge-cert.pem");
    assert.equal(statSync(p).mode & 0o777, 0o600);
  });
});

test("pin-cert stores only the certificate block, never a private key", async () => {
  await withHome(async (home) => {
    const fixtures = join(HERE, "..", "..", "tests", "fixtures");
    const files = (await readdir(fixtures)).filter((n) => n.endsWith(".pem"));
    const { readFileSync } = await import("node:fs");
    const cert = readFileSync(join(fixtures, files[0]!), "utf8");
    const key = "-----BEGIN PRIVATE KEY-----\nSECRETSECRET\n-----END PRIVATE KEY-----\n";
    const f = join(home, "bundle.pem");
    await writeFile(f, key + cert + key);
    const r = spawnSync(process.execPath, [ENTRY, "pin-cert", f], { env: { ...process.env, HOME: home }, encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    const stored = readFileSync(join(home, ".config", "proton-mcp", "bridge-cert.pem"), "utf8");
    assert.ok(!stored.includes("PRIVATE KEY") && !stored.includes("SECRET"));
    assert.ok(stored.startsWith("-----BEGIN CERTIFICATE-----") && stored.trimEnd().endsWith("-----END CERTIFICATE-----"));
  });
});

test("unknown subcommand prints usage to stderr and exits 2", async () => {
  await withHome(async (home) => {
    await mkdir(home, { recursive: true });
    const r = spawnSync(process.execPath, [ENTRY, "bogus"], { env: { ...process.env, HOME: home }, encoding: "utf8" });
    assert.equal(r.status, 2);
    assert.equal(r.stdout, "");
    assert.match(r.stderr, /Usage/);
  });
});

test("doctor reports config-file trust problems and exits 1 (no Keychain or Bridge access)", async () => {
  await withHome(async (home) => {
    const dir = join(home, ".config", "proton-mcp");
    await mkdir(dir, { recursive: true });
    const { chmod } = await import("node:fs/promises");
    await writeFile(join(dir, "config.json"), "{}");
    await chmod(join(dir, "config.json"), 0o666);
    const r = spawnSync(process.execPath, [ENTRY, "doctor"], { env: { ...process.env, HOME: home }, encoding: "utf8" });
    assert.equal(r.status, 1);
    assert.match(r.stdout, /^FAIL Config directory, config\.json and bridge-cert\.pem are owned by you/m);
    assert.match(r.stdout, /config\.json is group- or world-writable; fix with: chmod 600/);
    assert.match(r.stdout, /Keychain item\n\s+Fix: skipped until the config loads/);
  });
});
