import { test } from "node:test";
import assert from "node:assert/strict";
import { chmod, mkdtemp, rename, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseConfig, loadConfig, trustProblems, isDeniedMailbox, officeStatus, ConfigError, DENIED_MAILBOXES } from "../core/config.js";

test("allowOfficeDocuments defaults to false, accepts a boolean, and doctor's status line says which", () => {
  const off = parseConfig(base());
  assert.equal(off.allowOfficeDocuments, false);
  assert.match(officeStatus(off), /^Office documents \(\.docx, \.xlsx, \.pptx\): disabled/);
  const raw = base();
  raw.allowOfficeDocuments = true;
  const on = parseConfig(raw);
  assert.equal(on.allowOfficeDocuments, true);
  assert.match(officeStatus(on), /enabled/);
  for (const bad of ["true", 1, null]) {
    const r = base();
    r.allowOfficeDocuments = bad;
    assert.throws(() => parseConfig(r), ConfigError, String(bad));
  }
});

test("Spam and Trash are denied case-insensitively in config", () => {
  for (const mb of ["spam", "SPAM", "trash", "TrAsH"]) {
    const raw = base();
    raw.mail.allowedMailboxes = ["Labels/MCP", mb];
    assert.throws(() => parseConfig(raw), (e: unknown) => e instanceof ConfigError && e.message.includes(mb), mb);
  }
  assert.equal(isDeniedMailbox("sPaM"), true);
  assert.equal(isDeniedMailbox("Labels/Spam"), false);
});

function base(): any {
  return {
    bridge: { host: "127.0.0.1", port: 1143, username: "me@proton.me" },
    mail: { allowedMailboxes: ["Labels/MCP"] },
    vault: { root: "/path/to/vault", allowedDestinations: ["Documents", "Archive"] },
  };
}

test("valid config is returned with defaults applied", () => {
  const c = parseConfig(base());
  assert.equal(c.bridge.host, "127.0.0.1");
  assert.equal(c.bridge.port, 1143);
  assert.deepEqual(c.mail.allowedMailboxes, ["Labels/MCP"]);
  assert.equal(c.vault.root, "/path/to/vault");
  assert.equal(c.maxAttachmentBytes, 26214400);
  assert.deepEqual(c.vault.allowedDestinations, ["Documents", "Archive"]);
});

test("allowedDestinations has no default: missing or empty is a ConfigError that says how to fix it", () => {
  const missing = base();
  delete missing.vault.allowedDestinations;
  assert.throws(() => parseConfig(missing), (e: unknown) => e instanceof ConfigError && /allowedDestinations/.test(e.message) && /at least one/.test(e.message));
  const empty = base();
  empty.vault.allowedDestinations = [];
  assert.throws(() => parseConfig(empty), (e: unknown) => e instanceof ConfigError && /at least one/.test(e.message));
});

test("explicit values override defaults", () => {
  const raw = base();
  raw.maxAttachmentBytes = 1000;
  raw.vault.allowedDestinations = ["Docs"];
  const c = parseConfig(raw);
  assert.equal(c.maxAttachmentBytes, 1000);
  assert.deepEqual(c.vault.allowedDestinations, ["Docs"]);
});

test("DENIED_MAILBOXES is Spam and Trash", () => {
  assert.deepEqual([...DENIED_MAILBOXES], ["Spam", "Trash"]);
});

test("non-loopback bridge hosts are rejected", () => {
  for (const host of ["192.168.1.5", "localhost.evil.com"]) {
    const raw = base();
    raw.bridge.host = host;
    assert.throws(() => parseConfig(raw), ConfigError);
  }
});

test("loopback bridge hosts are accepted", () => {
  for (const host of ["127.0.0.1", "::1"]) {
    const raw = base();
    raw.bridge.host = host;
    assert.equal(parseConfig(raw).bridge.host, host);
  }
});

test("denied mailboxes are rejected and named", () => {
  for (const mb of ["Spam", "Trash"]) {
    const raw = base();
    raw.mail.allowedMailboxes = ["Labels/MCP", mb];
    assert.throws(() => parseConfig(raw), (e: unknown) => e instanceof ConfigError && e.message.includes(mb));
  }
});

test("bad allowedDestinations entries are rejected", () => {
  for (const d of ["/abs", "a/../b", "..", ".claude", "a/.hidden", "Templates"]) {
    const raw = base();
    raw.vault.allowedDestinations = [d];
    assert.throws(() => parseConfig(raw), ConfigError, d);
  }
});

test("vault.root must be absolute", () => {
  const raw = base();
  raw.vault.root = "relative/Vault";
  assert.throws(() => parseConfig(raw), ConfigError);
});

test("CR or LF in any string is rejected", () => {
  for (const bad of ["a\nb", "a\rb"]) {
    const raw = base();
    raw.bridge.username = bad;
    assert.throws(() => parseConfig(raw), ConfigError);
    const raw2 = base();
    raw2.mail.allowedMailboxes = [bad];
    assert.throws(() => parseConfig(raw2), ConfigError);
  }
});

test("non-object input throws ConfigError", () => {
  assert.throws(() => parseConfig(null), ConfigError);
});

async function configDir(): Promise<{ dir: string; file: string; cert: string }> {
  const dir = await mkdtemp(join(tmpdir(), "proton-mcp-cfg-"));
  await chmod(dir, 0o700);
  const file = join(dir, "config.json");
  await writeFile(file, JSON.stringify(base()), { mode: 0o600 });
  return { dir, file, cert: join(dir, "bridge-cert.pem") };
}

async function configError(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (e) {
    assert.ok(e instanceof ConfigError, String(e));
    return e.message;
  }
  return "no error";
}

test("loadConfig accepts private files owned by the current user", async () => {
  const { dir, file, cert } = await configDir();
  try {
    await writeFile(cert, "pem", { mode: 0o600 });
    assert.equal((await loadConfig(file)).bridge.port, 1143);
    assert.deepEqual(await trustProblems(file), []);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("loadConfig refuses a group- or world-writable config file, directory or cert", async () => {
  const { dir, file, cert } = await configDir();
  try {
    for (const mode of [0o620, 0o602, 0o666]) {
      await chmod(file, mode);
      assert.match(await configError(loadConfig(file)), /config\.json.*group- or world-writable/);
    }
    await chmod(file, 0o600);
    await chmod(dir, 0o770);
    assert.match(await configError(loadConfig(file)), /group- or world-writable/);
    await chmod(dir, 0o700);
    await writeFile(cert, "pem", { mode: 0o600 });
    await chmod(cert, 0o666);
    assert.match(await configError(loadConfig(file)), /bridge-cert\.pem.*group- or world-writable/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("loadConfig refuses files not owned by the current user", async () => {
  const { dir, file } = await configDir();
  try {
    const other = (process.getuid?.() ?? 0) + 1;
    const problems = await trustProblems(file, other);
    assert.ok(problems.some((p: string) => /config\.json.*not owned by/.test(p)), problems.join("; "));
    assert.ok(problems.some((p: string) => /proton-mcp-cfg-.*not owned by/.test(p)), problems.join("; "));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("loadConfig refuses a symlinked config file or cert", async () => {
  const { dir, file, cert } = await configDir();
  try {
    const real = join(dir, "real.json");
    await rename(file, real);
    await symlink(real, file);
    assert.match(await configError(loadConfig(file)), /config\.json is a symlink/);
    await rm(file);
    await rename(real, file);
    const realCert = join(dir, "real.pem");
    await writeFile(realCert, "pem", { mode: 0o600 });
    await symlink(realCert, cert);
    assert.match(await configError(loadConfig(file)), /bridge-cert\.pem is a symlink/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("loadConfig refuses a symlinked config directory", async () => {
  const { dir, file } = await configDir();
  const link = `${dir}-link`;
  try {
    await symlink(dir, link);
    assert.match(await configError(loadConfig(join(link, "config.json"))), /is a symlink/);
  } finally {
    await rm(link, { force: true });
    await rm(dir, { recursive: true, force: true });
  }
});

test("a missing config still reports Config not found", async () => {
  const { dir } = await configDir();
  try {
    assert.match(await configError(loadConfig(join(dir, "nope", "config.json"))), /Config not found/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("unknown config keys are rejected (strict schema)", () => {
  const typo = base();
  typo.vault.allowedDestination = ["Documents"];
  assert.throws(() => parseConfig(typo), (e: unknown) => e instanceof ConfigError && /allowedDestination/.test(e.message));
  for (const mutate of [
    (r: any) => (r.extra = 1),
    (r: any) => (r.bridge.hostname = "127.0.0.1"),
    (r: any) => (r.mail.allowMailboxes = []),
  ]) {
    const raw = base();
    mutate(raw);
    assert.throws(() => parseConfig(raw), ConfigError);
  }
});
