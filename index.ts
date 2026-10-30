#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { X509Certificate } from "node:crypto";
import { mkdir, readFile, writeFile, chmod } from "node:fs/promises";

import { CERT_PATH, CONFIG_DIR, CONFIG_PATH, ConfigError, loadConfig, markdownStatus, officeStatus, parseConfig, trustProblems, type Config } from "./core/config.js";
import { GuardError, type MessageRef } from "./core/guards.js";
import { bridgePassword } from "./core/keychain.js";
import { tlsOptions } from "./core/tls.js";
import { errorResult, type ServerTool } from "./core/tool.js";
import { ImapStore } from "./Mail/imapStore.js";
import { mailTools } from "./Mail/tools.js";
import type { MailStore } from "./Mail/store.js";

const USAGE = "Usage: proton-mcp [pin-cert <file> | doctor]\n  (no arguments)  run the MCP server on stdio\n";

/** Message that never carries secrets; ConfigError messages from core/ are already safe. */
function setupMessage(e: unknown): string {
  if (e instanceof ConfigError || e instanceof GuardError) return e.message;
  return "Could not set up the Bridge connection. See README > Setup.";
}

/** Builds the real store on first use (keychain password + pinned TLS). Retries after a failure. */
export function lazyStore(cfg: Config): MailStore {
  let pending: Promise<ImapStore> | undefined;
  const get = (): Promise<ImapStore> => {
    if (!pending) {
      const attempt = (async () => {
        try {
          const password = await bridgePassword(cfg.bridge.username);
          const tls = await tlsOptions(CERT_PATH);
          return new ImapStore(cfg, password, tls);
        } catch (e) {
          throw new GuardError("SETUP", `${setupMessage(e)} (see README > Setup)`);
        }
      })();
      pending = attempt;
      attempt.catch(() => {
        if (pending === attempt) pending = undefined;
      });
    }
    return pending;
  };
  /** Run a store call; on SETUP (e.g. rejected password) drop the cached store so the next call re-reads the Keychain. */
  const run = async <T>(fn: (s: ImapStore) => Promise<T>): Promise<T> => {
    const attempt = get();
    try {
      return await fn(await attempt);
    } catch (e) {
      if (e instanceof GuardError && e.code === "SETUP" && pending === attempt) pending = undefined;
      throw e;
    }
  };
  return {
    listMailboxes: () => run((s) => s.listMailboxes()),
    search: (mb, c) => run((s) => s.search(mb, c)),
    read: (ref: MessageRef) => run((s) => s.read(ref)),
    attachment: (ref: MessageRef, i: number) => run((s) => s.attachment(ref, i)),
    messageIdsIn: (mb) => run((s) => s.messageIdsIn(mb)),
    uidValidity: (mb) => run((s) => s.uidValidity(mb)),
  };
}

const nullStore: MailStore = {
  listMailboxes: async () => [],
  search: async () => [],
  read: async () => {
    throw new Error("unavailable");
  },
  attachment: async () => {
    throw new Error("unavailable");
  },
  messageIdsIn: async () => new Set(),
  uidValidity: async () => "0",
};

/** Tool definitions with every call answering SETUP: <reason>. Used when the config cannot load. */
function setupErrorTools(message: string): ServerTool[] {
  const throwaway = parseConfig({
    bridge: { host: "127.0.0.1", port: 1143, username: "setup" },
    mail: { allowedMailboxes: ["Setup"] },
    vault: { root: "/setup", allowedDestinations: ["Setup"] },
  });
  return mailTools(throwaway, nullStore).map((t) => ({
    ...t,
    fn: async () => errorResult(`SETUP: ${message}`),
  }));
}

async function buildTools(): Promise<ServerTool[]> {
  try {
    const cfg = await loadConfig();
    return mailTools(cfg, lazyStore(cfg));
  } catch (e) {
    const message = e instanceof ConfigError ? e.message : "Could not load config. See README > Setup.";
    console.error(`proton-mcp: ${message}`);
    return setupErrorTools(message);
  }
}

async function runServer(): Promise<void> {
  const tools = await buildTools();
  const toolMap = new Map(tools.map((t) => [t.name, t]));

  const server = new Server({ name: "proton-mcp", version: "0.1.0" }, { capabilities: { tools: {} } });

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: tools.map((t) => ({
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema as { type: "object" },
      annotations: t.annotations,
    })),
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const t = toolMap.get(request.params.name);
    if (!t) return errorResult(`Unknown tool: ${request.params.name}`);
    try {
      return await t.fn(request.params.arguments);
    } catch {
      return errorResult("ERROR: unexpected failure");
    }
  });

  await server.connect(new StdioServerTransport());
  console.error("proton-mcp running on stdio");
}

async function pinCert(file: string | undefined): Promise<number> {
  if (!file) {
    process.stderr.write(USAGE);
    return 2;
  }
  let pem: string;
  try {
    pem = await readFile(file, "utf8");
  } catch {
    process.stderr.write(`Cannot read ${file}\n`);
    return 1;
  }
  const begins = pem.match(/-----BEGIN CERTIFICATE-----/g) ?? [];
  if (begins.length !== 1) {
    process.stderr.write(`Expected exactly one PEM certificate in ${file}, found ${begins.length}.\n`);
    return 1;
  }
  // Keep only the certificate block: the input may be a bundle that also holds a private key.
  const block = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/);
  if (!block) {
    process.stderr.write(`${file} does not contain a complete PEM certificate.\n`);
    return 1;
  }
  pem = block[0] + "\n";
  let fingerprint: string;
  try {
    fingerprint = new X509Certificate(pem).fingerprint256;
  } catch {
    process.stderr.write(`${file} does not contain a valid X.509 certificate.\n`);
    return 1;
  }
  await mkdir(CONFIG_DIR, { recursive: true, mode: 0o700 });
  await writeFile(CERT_PATH, pem, { mode: 0o600 });
  await chmod(CERT_PATH, 0o600);
  process.stdout.write(`Pinned. SHA-256: ${fingerprint}\n`);
  return 0;
}

async function doctor(): Promise<number> {
  let ok = true;
  const line = (pass: boolean, what: string, fix?: string) => {
    if (!pass) ok = false;
    console.log(`${pass ? "OK  " : "FAIL"} ${what}`);
    if (!pass && fix) console.log(`     Fix: ${fix}`);
  };

  const problems = await trustProblems(CONFIG_PATH);
  line(
    problems.length === 0,
    `Config directory, config.json and bridge-cert.pem are owned by you, not group/world-writable, not symlinks`,
    problems.join("\n          "),
  );

  let cfg: Config | undefined;
  try {
    cfg = await loadConfig();
    line(true, "Config loaded");
    console.log(`     ${officeStatus(cfg)}`);
    console.log(`     ${markdownStatus(cfg)}`);
  } catch (e) {
    line(false, "Config", `${setupMessage(e)}`);
  }

  let password: string | undefined;
  if (cfg) {
    try {
      password = await bridgePassword(cfg.bridge.username);
      line(true, `Keychain item found (service proton-mcp, account ${cfg.bridge.username})`);
    } catch (e) {
      line(false, "Keychain item", setupMessage(e));
    }
  } else {
    line(false, "Keychain item", "skipped until the config loads");
  }

  let tls: Awaited<ReturnType<typeof tlsOptions>> | undefined;
  try {
    tls = await tlsOptions(CERT_PATH);
    line(true, `Pinned certificate readable (${CERT_PATH})`);
  } catch (e) {
    line(false, "Pinned certificate", setupMessage(e));
  }

  if (cfg && password !== undefined && tls) {
    try {
      const store = new ImapStore(cfg, password, tls);
      const boxes = await store.listMailboxes();
      line(true, `Connected to Bridge on 127.0.0.1:${cfg.bridge.port}`);
      for (const mb of cfg.mail.allowedMailboxes) {
        const found = boxes.find((b) => b.path === mb);
        if (found) console.log(`     ${mb}: ${found.messages} messages`);
        else {
          ok = false;
          console.log(`     ${mb}: NOT FOUND in Bridge (check the name in config.json)`);
        }
      }
    } catch (e) {
      line(false, "Bridge connection", e instanceof Error ? e.message : "connection failed");
    }
  } else {
    line(false, "Bridge connection", "skipped until the checks above pass");
  }

  return ok ? 0 : 1;
}

async function main(): Promise<void> {
  const [cmd, arg] = process.argv.slice(2);
  switch (cmd) {
    case undefined:
      await runServer();
      return;
    case "pin-cert":
      process.exitCode = await pinCert(arg);
      return;
    case "doctor":
      process.exitCode = await doctor();
      return;
    default:
      process.stderr.write(USAGE);
      process.exitCode = 2;
  }
}

main().catch((e) => {
  console.error("proton-mcp error:", e instanceof Error ? e.message : "unexpected failure");
  process.exit(1);
});
