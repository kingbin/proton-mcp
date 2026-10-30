import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { audit, AUDIT_LOG_PATH } from "../core/audit.js";

test("two calls append two parseable JSON lines with whitelisted keys", async () => {
  const dir = await mkdtemp(join(tmpdir(), "audit-"));
  const logPath = join(dir, "audit.log");
  await audit({ tool: "search", mailbox: "Labels/MCP", uid: 42, ok: true }, logPath);
  await audit({ tool: "read", ok: false, code: "NOT_FOUND" }, logPath);

  const lines = (await readFile(logPath, "utf8")).trimEnd().split("\n");
  assert.equal(lines.length, 2);

  const first = JSON.parse(lines[0]);
  assert.deepEqual(Object.keys(first).sort(), ["mailbox", "ok", "tool", "ts", "uid"]);
  assert.equal(first.tool, "search");
  assert.equal(first.mailbox, "Labels/MCP");
  assert.equal(first.uid, 42);
  assert.equal(first.ok, true);
  assert.ok(!Number.isNaN(Date.parse(first.ts)));
  assert.equal(new Date(first.ts).toISOString(), first.ts);

  const second = JSON.parse(lines[1]);
  assert.deepEqual(Object.keys(second).sort(), ["code", "ok", "tool", "ts"]);
  assert.equal(second.code, "NOT_FOUND");
  assert.equal(second.ok, false);
});

test("extra properties such as subject are never written", async () => {
  const dir = await mkdtemp(join(tmpdir(), "audit-"));
  const logPath = join(dir, "audit.log");
  const entry = { tool: "read", ok: true, uid: 7, subject: "Secret subject", body: "secret body", filename: "a.pdf" };
  await audit(entry as any, logPath);

  const text = await readFile(logPath, "utf8");
  assert.ok(!text.includes("Secret subject"));
  assert.ok(!text.includes("secret body"));
  assert.ok(!text.includes("a.pdf"));
  assert.deepEqual(Object.keys(JSON.parse(text.trim())).sort(), ["ok", "tool", "ts", "uid"]);
});

test("missing parent directories are created", async () => {
  const dir = await mkdtemp(join(tmpdir(), "audit-"));
  const logPath = join(dir, "nested", "deeper", "audit.log");
  await audit({ tool: "search", ok: true }, logPath);
  const lines = (await readFile(logPath, "utf8")).trimEnd().split("\n");
  assert.equal(lines.length, 1);
});

test("an unwritable path does not throw", async () => {
  const dir = await mkdtemp(join(tmpdir(), "audit-"));
  const blocker = join(dir, "file");
  await writeFile(blocker, "not a directory");
  await assert.doesNotReject(audit({ tool: "search", ok: true }, join(blocker, "x", "audit.log")));
});

test("default path is under the home directory", () => {
  assert.equal(AUDIT_LOG_PATH.endsWith(join("Library", "Logs", "proton-mcp", "audit.log")), true);
});
