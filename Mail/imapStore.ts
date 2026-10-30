import type { ConnectionOptions } from "node:tls";
import { ImapFlow } from "imapflow";
import type { MailboxObject, SearchObject } from "imapflow";
import { simpleParser } from "mailparser";
import type { AddressObject, ParsedMail } from "mailparser";
import type { Config } from "../core/config.js";
import { GuardError, type MessageRef } from "../core/guards.js";
import { CERT_CHANGED_MESSAGE, CertPinError, guardPinnedTls } from "../core/tls.js";
import type { AttachmentInfo, MailStore, MessageSummary, SearchCriteria } from "./store.js";

/** Trim and strip one pair of surrounding angle brackets; empty becomes undefined. */
export function normalizeMessageId(s: string | undefined): string | undefined {
  if (s === undefined) return undefined;
  let id = s.trim();
  if (id.length >= 2 && id.startsWith("<") && id.endsWith(">")) id = id.slice(1, -1).trim();
  return id.length > 0 ? id : undefined;
}

/**
 * mailparser options used for every parse. None of them fetch anything: mailparser never
 * loads remote resources. These only skip work we don't need (cid images as data URIs,
 * text-to-HTML, linkifying).
 */
const PARSE_OPTS = { skipImageLinks: true, skipTextToHtml: true, skipTextLinks: true, maxHtmlLengthToParse: 2_000_000 } as const;

/** Largest HTML body (characters) converted to text; mailparser and plainText both stop here. */
export const MAX_HTML_CHARS = 2_000_000;

/** Largest message (RFC822.SIZE bytes) fetched and parsed. */
export const MAX_MESSAGE_BYTES = 40 * 1024 * 1024;

/** True when a message must not be fetched: over the cap, or the server reported no size. */
export function isTooLarge(size: number | undefined): boolean {
  return typeof size !== "number" || !Number.isFinite(size) || size < 0 || size > MAX_MESSAGE_BYTES;
}

/**
 * The Message-ID used for the Spam/Trash cross-check. It comes from the IMAP envelope, the same
 * source `messageIdsIn` uses. It is withheld (undefined, so the tools deny the message) when the
 * message has more than one Message-ID header or when mailparser reads a different ID than the
 * server's envelope: a parser differential must never let a Spam copy through.
 */
export function resolveMessageId(
  envelopeId: string | undefined,
  parsedId: string | undefined,
  messageIdHeaderCount: number,
): string | undefined {
  if (messageIdHeaderCount > 1) return undefined;
  const env = normalizeMessageId(envelopeId);
  if (env === undefined) return undefined;
  return normalizeMessageId(parsedId) === env ? env : undefined;
}

function messageIdHeaderCount(parsed: ParsedMail): number {
  return parsed.headerLines.filter((h) => h.key.toLowerCase() === "message-id").length;
}

/** Deadline for one store operation (connect + IMAP commands), in milliseconds. */
export const OP_TIMEOUT_MS = 30000;

/**
 * Resolve or reject with `op`, unless `ms` passes first: then run `onTimeout` (once) and reject
 * with BRIDGE_TIMEOUT. A late settle of `op` is ignored (and its rejection is still handled).
 */
export function withDeadline<T>(op: Promise<T>, ms: number, onTimeout: () => void): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    let done = false;
    const timer = setTimeout(() => {
      if (done) return;
      done = true;
      try {
        onTimeout();
      } catch {
        // Cleanup failures must not crash the process; the call still fails with BRIDGE_TIMEOUT.
      }
      reject(new GuardError("BRIDGE_TIMEOUT", "Proton Mail Bridge did not respond in time."));
    }, ms);
    op.then(
      (v) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        resolve(v);
      },
      (e: unknown) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        reject(e);
      },
    );
  });
}

/**
 * Cache key for a mailbox's contents from its read-only status, or undefined (do not cache) when
 * the server did not report UIDNEXT.
 */
export function mailboxStateKey(box: { uidValidity: bigint | number | string; uidNext?: number; exists?: number }): string | undefined {
  if (typeof box.uidNext !== "number" || typeof box.exists !== "number") return undefined;
  return `${String(box.uidValidity)}:${box.uidNext}:${box.exists}`;
}

/** Per-mailbox Message-ID sets, reused while the mailbox key is unchanged. */
export class MessageIdCache {
  private readonly entries = new Map<string, { key: string; ids: ReadonlySet<string> }>();

  /** Cached copy when `key` matches; otherwise `load`, store (if keyed) and return a copy. */
  async get(mailbox: string, key: string | undefined, load: () => Promise<Set<string>>): Promise<Set<string>> {
    const hit = this.entries.get(mailbox);
    if (key !== undefined && hit && hit.key === key) return new Set(hit.ids);
    this.entries.delete(mailbox);
    const ids = await load();
    if (key !== undefined) this.entries.set(mailbox, { key, ids: new Set(ids) });
    return new Set(ids);
  }
}

/** Node/OpenSSL verification codes meaning "the server's cert is not the one we trust". */
const CERT_ERROR_CODES = new Set([
  "BRIDGE_CERT_CHANGED",
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "SELF_SIGNED_CERT_IN_CHAIN",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "UNABLE_TO_GET_ISSUER_CERT",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "CERT_SIGNATURE_FAILURE",
  "CERT_UNTRUSTED",
  "CERT_REJECTED",
  "CERT_HAS_EXPIRED",
  "CERT_NOT_YET_VALID",
  "ERR_TLS_CERT_ALTNAME_INVALID",
]);

function isCertError(e: unknown): boolean {
  let cur: unknown = e;
  for (let depth = 0; depth < 5 && cur && typeof cur === "object"; depth++) {
    if (cur instanceof CertPinError) return true;
    const code = (cur as { code?: unknown }).code;
    if (typeof code === "string" && CERT_ERROR_CODES.has(code)) return true;
    cur = (cur as { cause?: unknown }).cause;
  }
  return false;
}

/** True when imapflow reports the server refused the credentials (not a network/TLS failure). */
export function isAuthFailure(e: unknown): boolean {
  return !!e && typeof e === "object" && (e as { authenticationFailed?: unknown }).authenticationFailed === true;
}

export const AUTH_FAILED_MESSAGE =
  "Bridge rejected the password. Update the Keychain item (see README > Setup) and restart the server.";

function addressText(a: AddressObject | AddressObject[] | undefined): string {
  if (!a) return "";
  return (Array.isArray(a) ? a : [a]).map((x) => x.text).filter(Boolean).join(", ");
}

function attachmentsOf(parsed: ParsedMail): AttachmentInfo[] {
  return parsed.attachments.map((a, index) => ({
    index,
    filename: a.filename,
    contentType: a.contentType,
    size: a.size,
  }));
}

/** IMAP SEARCH dates are day-granular; imapflow formats them in UTC. */
function searchDate(s: string): Date {
  const d = new Date(`${s}T00:00:00Z`);
  if (Number.isNaN(d.getTime())) throw new GuardError("INVALID_INPUT", "Invalid date; use YYYY-MM-DD");
  return d;
}

/**
 * Plain-text body. `parsed.text` when mailparser produced it. mailparser only converts HTML to
 * text when the HTML is the root part or sits beside a text part, so an HTML-only body inside
 * multipart/mixed (typical with attachments) comes back without `text`. In that case the
 * decoded HTML is re-parsed as a single-part text/html message so mailparser's own
 * HTML-to-text conversion runs on it. HTML itself is never returned.
 */
export async function plainText(parsed: ParsedMail): Promise<string> {
  if (typeof parsed.text === "string") return parsed.text;
  if (typeof parsed.html !== "string" || parsed.html.length === 0 || parsed.html.length > MAX_HTML_CHARS) return "";
  const b64 = Buffer.from(parsed.html, "utf8").toString("base64").replace(/.{1,76}/g, "$&\r\n");
  const single = Buffer.from(
    "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n" + b64,
    "utf8",
  );
  const reparsed = await simpleParser(single, PARSE_OPTS);
  return typeof reparsed.text === "string" ? reparsed.text : "";
}

/**
 * Read-only MailStore over Proton Mail Bridge.
 *
 * - One lazily created ImapFlow client, STARTTLS required, TLS pinned via `tls`.
 * - Calls are serialized by a promise-chain mutex. Each call runs under OP_TIMEOUT_MS; on timeout
 *   the client is dropped and the mutex released, so a hung Bridge cannot wedge the server.
 * - Every mailbox is opened with EXAMINE (`readOnly: true`); fetches use BODY.PEEK, so `\Seen`
 *   is never set. No flag, move, delete, append or expunge method is ever called.
 * - Thrown messages never carry server response text or message content.
 */
export class ImapStore implements MailStore {
  private client: ImapFlow | null = null;
  private chain: Promise<unknown> = Promise.resolve();
  private connecting: ImapFlow | null = null;
  private pinFailed = false;
  private readonly idCache = new MessageIdCache();
  private readonly tls: ConnectionOptions;
  private readonly opTimeoutMs: number;

  constructor(
    private readonly cfg: Config,
    private readonly password: string,
    tls: ConnectionOptions,
    opts: { opTimeoutMs?: number } = {},
  ) {
    this.opTimeoutMs = opts.opTimeoutMs ?? OP_TIMEOUT_MS;
    this.tls = guardPinnedTls(tls, () => {
      this.pinFailed = true;
    });
  }

  private unavailable(): GuardError {
    return new GuardError(
      "BRIDGE_UNAVAILABLE",
      `Proton Mail Bridge isn't reachable on 127.0.0.1:${this.cfg.bridge.port}. Is Bridge running?`,
    );
  }

  private drop(client: ImapFlow | null = this.client): void {
    if (!client) return;
    if (this.client === client) this.client = null;
    try {
      client.close();
    } catch {
      // already closed
    }
  }

  private async connect(): Promise<ImapFlow> {
    if (this.client?.usable) return this.client;
    this.drop();
    this.pinFailed = false;
    const client = new ImapFlow({
      host: this.cfg.bridge.host,
      port: this.cfg.bridge.port,
      secure: false,
      doSTARTTLS: true,
      tls: this.tls,
      auth: { user: this.cfg.bridge.username, pass: this.password },
      logger: false,
      connectionTimeout: 10000,
      greetingTimeout: 10000,
    });
    // Without an 'error' listener an emitted error would crash the process.
    client.on("error", () => this.drop(client));
    client.on("close", () => {
      if (this.client === client) this.client = null;
    });
    this.connecting = client;
    try {
      await client.connect();
    } catch (e) {
      this.drop(client);
      if (this.pinFailed || isCertError(e)) throw new GuardError("BRIDGE_CERT_CHANGED", CERT_CHANGED_MESSAGE);
      if (isAuthFailure(e)) throw new GuardError("SETUP", AUTH_FAILED_MESSAGE);
      throw this.unavailable();
    } finally {
      if (this.connecting === client) this.connecting = null;
    }
    this.client = client;
    return client;
  }

  /** On timeout: close whatever client is connecting or in use; the next call reconnects. */
  private abandon(): void {
    const connecting = this.connecting;
    this.connecting = null;
    this.drop(connecting);
    this.drop();
  }

  /** Serialize calls: each waits for the previous one, success, failure or timeout. */
  private withClient<T>(fn: (c: ImapFlow) => Promise<T>): Promise<T> {
    const next = this.chain.then(() => withDeadline(this.attempt(fn), this.opTimeoutMs, () => this.abandon()));
    this.chain = next.catch(() => undefined);
    return next;
  }

  private async attempt<T>(fn: (c: ImapFlow) => Promise<T>): Promise<T> {
    const c = await this.connect();
    try {
      return await fn(c);
    } catch (e) {
      if (e instanceof GuardError) throw e;
      if (!c.usable) {
        this.drop(c);
        throw this.unavailable();
      }
      throw new GuardError("IMAP_ERROR", "Proton Mail Bridge could not complete the request.");
    }
  }

  /** Open `path` read-only (EXAMINE) for the duration of `fn`. */
  private async inMailbox<T>(c: ImapFlow, path: string, fn: (box: MailboxObject) => Promise<T>): Promise<T> {
    let lock;
    try {
      lock = await c.getMailboxLock(path, { readOnly: true });
    } catch (e) {
      if (!c.usable) throw e;
      throw new GuardError("NOT_FOUND", "Mailbox not found");
    }
    try {
      const box = c.mailbox;
      if (!box) throw new GuardError("NOT_FOUND", "Mailbox not found");
      // EXAMINE should never be granted read-write; refuse if the server says it was.
      if (box.readOnly === false) throw new GuardError("IMAP_ERROR", "Mailbox did not open read-only");
      return await fn(box);
    } finally {
      lock.release();
    }
  }

  private summarize(
    mailbox: string,
    uidValidity: string,
    uid: number,
    parsed: ParsedMail,
    envelopeId: string | undefined,
    internalDate?: Date | string,
  ): MessageSummary {
    const date = parsed.date ?? (internalDate ? new Date(internalDate) : undefined);
    return {
      mailbox,
      uidValidity,
      uid,
      messageId: resolveMessageId(envelopeId, parsed.messageId, messageIdHeaderCount(parsed)),
      date: date && !Number.isNaN(date.getTime()) ? date.toISOString() : "",
      from: addressText(parsed.from),
      to: addressText(parsed.to) || undefined,
      subject: parsed.subject ?? "",
      attachments: attachmentsOf(parsed),
    };
  }

  /** Fetch and parse one message inside an open mailbox. NOT_FOUND / STALE_REF on mismatch. */
  private async load(c: ImapFlow, box: MailboxObject, ref: MessageRef): Promise<{ parsed: ParsedMail; summary: MessageSummary }> {
    const uidValidity = box.uidValidity.toString();
    if (uidValidity !== ref.uidValidity) {
      throw new GuardError("STALE_REF", "Message ref is stale (mailbox was rebuilt); search again to get a fresh ref");
    }
    const meta = await c.fetchOne(String(ref.uid), { uid: true, size: true, envelope: true, internalDate: true }, { uid: true });
    if (!meta || meta.uid !== ref.uid) throw new GuardError("NOT_FOUND", "Message not found");
    if (isTooLarge(meta.size)) throw new GuardError("TOO_LARGE", "Message is too large to read safely.");
    const msg = await c.fetchOne(String(ref.uid), { uid: true, source: true }, { uid: true });
    if (!msg || msg.uid !== ref.uid || !msg.source) throw new GuardError("NOT_FOUND", "Message not found");
    const parsed = await simpleParser(msg.source, PARSE_OPTS);
    return {
      parsed,
      summary: this.summarize(ref.mailbox, uidValidity, ref.uid, parsed, meta.envelope?.messageId, meta.internalDate),
    };
  }

  listMailboxes(): Promise<{ path: string; messages: number }[]> {
    return this.withClient(async (c) => {
      const list = await c.list({ statusQuery: { messages: true } });
      return list.map((m) => ({ path: m.path, messages: m.status?.messages ?? 0 }));
    });
  }

  search(mailbox: string, crit: SearchCriteria): Promise<MessageSummary[]> {
    return this.withClient((c) =>
      this.inMailbox(c, mailbox, async (box) => {
        const uidValidity = box.uidValidity.toString();
        if (box.exists === 0) return [];
        const query: SearchObject = {};
        if (crit.from !== undefined) query.from = crit.from;
        if (crit.subject !== undefined) query.subject = crit.subject;
        if (crit.since !== undefined) query.since = searchDate(crit.since);
        if (crit.before !== undefined) query.before = searchDate(crit.before);
        if (Object.keys(query).length === 0) query.all = true;

        const found = await c.search(query, { uid: true });
        if (!found || found.length === 0) return [];
        const uids = [...found].sort((a, b) => b - a).slice(0, Math.max(0, crit.limit));
        if (uids.length === 0) return [];

        // Small metadata first (no IMAP command may run inside a fetch loop), then one source at
        // a time, so peak memory is a single message.
        const metas: { uid: number; size?: number; envelopeId?: string; internalDate?: Date | string }[] = [];
        for await (const m of c.fetch(uids, { uid: true, size: true, envelope: true, internalDate: true }, { uid: true })) {
          metas.push({ uid: m.uid, size: m.size, envelopeId: m.envelope?.messageId, internalDate: m.internalDate });
        }
        metas.sort((a, b) => b.uid - a.uid);

        const out: MessageSummary[] = [];
        for (const meta of metas) {
          if (isTooLarge(meta.size)) continue;
          try {
            const msg = await c.fetchOne(String(meta.uid), { uid: true, source: true }, { uid: true });
            if (!msg || msg.uid !== meta.uid || !msg.source) continue;
            const parsed = await simpleParser(msg.source, PARSE_OPTS);
            const summary = this.summarize(mailbox, uidValidity, meta.uid, parsed, meta.envelopeId, meta.internalDate);
            if (crit.hasAttachment === true && summary.attachments.length === 0) continue;
            if (crit.hasAttachment === false && summary.attachments.length > 0) continue;
            out.push(summary);
          } catch {
            // One bad message must not break the whole search; if the connection died, the next fetch fails too.
            if (!c.usable) throw new GuardError("BRIDGE_UNAVAILABLE", "Connection to Bridge was lost.");
          }
        }
        return out;
      }),
    );
  }

  read(ref: MessageRef): Promise<{ summary: MessageSummary; text: string }> {
    return this.withClient((c) =>
      this.inMailbox(c, ref.mailbox, async (box) => {
        const { parsed, summary } = await this.load(c, box, ref);
        return { summary, text: await plainText(parsed) };
      }),
    );
  }

  attachment(ref: MessageRef, index: number): Promise<{ filename?: string; contentType: string; data: Buffer }> {
    return this.withClient((c) =>
      this.inMailbox(c, ref.mailbox, async (box) => {
        const { parsed } = await this.load(c, box, ref);
        const a = Number.isInteger(index) && index >= 0 ? parsed.attachments[index] : undefined;
        if (!a) throw new GuardError("NOT_FOUND", "Attachment not found");
        return { filename: a.filename, contentType: a.contentType, data: a.content };
      }),
    );
  }

  /**
   * Message-IDs in `mailbox` (read from envelopes only). Cached per mailbox and reused while the
   * read-only open reports the same UIDVALIDITY, UIDNEXT and EXISTS: any arrival bumps UIDNEXT,
   * any removal lowers EXISTS, and a rebuild changes UIDVALIDITY.
   */
  messageIdsIn(mailbox: string): Promise<Set<string>> {
    return this.withClient((c) =>
      this.inMailbox(c, mailbox, (box) =>
        this.idCache.get(mailbox, mailboxStateKey(box), async () => {
          const ids = new Set<string>();
          if (box.exists === 0) return ids;
          for await (const m of c.fetch("1:*", { uid: true, envelope: true })) {
            const id = normalizeMessageId(m.envelope?.messageId);
            if (id) ids.add(id);
          }
          return ids;
        }),
      ),
    );
  }

  uidValidity(mailbox: string): Promise<string> {
    return this.withClient((c) => this.inMailbox(c, mailbox, async (box) => box.uidValidity.toString()));
  }
}
