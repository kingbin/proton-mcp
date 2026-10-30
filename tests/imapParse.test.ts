import { test } from "node:test";
import assert from "node:assert/strict";
import { simpleParser } from "mailparser";
import {
  normalizeMessageId,
  plainText,
  resolveMessageId,
  isTooLarge,
  isAuthFailure,
  MAX_MESSAGE_BYTES,
  MAX_HTML_CHARS,
  OP_TIMEOUT_MS,
  withDeadline,
  MessageIdCache,
  mailboxStateKey,
  ImapStore,
} from "../Mail/imapStore.js";
import { GuardError } from "../core/guards.js";

test("normalizeMessageId trims and strips one pair of angle brackets", () => {
  assert.equal(normalizeMessageId("<a@b>"), "a@b");
  assert.equal(normalizeMessageId("  <a@b>  "), "a@b");
  assert.equal(normalizeMessageId("a@b"), "a@b");
  assert.equal(normalizeMessageId("<<a@b>>"), "<a@b>");
  assert.equal(normalizeMessageId("<>"), undefined);
  assert.equal(normalizeMessageId("   "), undefined);
  assert.equal(normalizeMessageId(""), undefined);
  assert.equal(normalizeMessageId(undefined), undefined);
});

const mixed = (body: string) =>
  Buffer.from(
    "From: A <a@x>\r\nSubject: hi\r\nMessage-ID: <abc@x>\r\nMIME-Version: 1.0\r\n" +
      "Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\n" + body +
      "\r\n--B\r\nContent-Type: application/pdf; name=a.pdf\r\nContent-Disposition: attachment; filename=a.pdf\r\n" +
      "Content-Transfer-Encoding: base64\r\n\r\nJVBERi0x\r\n--B--\r\n",
  );

test("plainText converts an HTML-only body inside multipart/mixed to text, never HTML", async () => {
  const parsed = await simpleParser(
    mixed('Content-Type: text/html; charset=utf-8\r\n\r\n<p>Hello <b>there</b><img src="http://evil/x.png"></p><script>x()</script>'),
  );
  assert.equal(parsed.text, undefined); // mailparser leaves text unset here; plainText must cover it
  const text = await plainText(parsed);
  assert.match(text, /Hello there/);
  assert.doesNotMatch(text, /<p>|<b>|<script>|x\(\)/);
});

test("plainText returns the text part when present, and empty string when there is no body", async () => {
  const withText = await simpleParser(mixed("Content-Type: text/plain; charset=utf-8\r\n\r\nplain body"));
  assert.equal(await plainText(withText), "plain body");
  const empty = await simpleParser(Buffer.from("Subject: x\r\nContent-Type: application/pdf\r\n\r\nJVBERi0x\r\n"));
  assert.equal(typeof (await plainText(empty)), "string");
});

test("resolveMessageId takes the envelope ID only when it agrees with the parsed one and there is one header", () => {
  assert.equal(resolveMessageId("<a@b>", "<a@b>", 1), "a@b");
  assert.equal(resolveMessageId(" <a@b> ", "a@b", 1), "a@b");
  assert.equal(resolveMessageId("<a@b>", "<spam@x>", 1), undefined);
  assert.equal(resolveMessageId("<a@b>", undefined, 1), undefined);
  assert.equal(resolveMessageId("<a@b>", "<a@b>", 2), undefined);
  assert.equal(resolveMessageId(undefined, "<a@b>", 1), undefined);
  assert.equal(resolveMessageId(undefined, undefined, 0), undefined);
});

test("isTooLarge refuses over-cap, missing and invalid sizes", () => {
  assert.equal(MAX_MESSAGE_BYTES, 40 * 1024 * 1024);
  assert.equal(isTooLarge(0), false);
  assert.equal(isTooLarge(MAX_MESSAGE_BYTES), false);
  assert.equal(isTooLarge(MAX_MESSAGE_BYTES + 1), true);
  assert.equal(isTooLarge(undefined), true);
  assert.equal(isTooLarge(Number.NaN), true);
  assert.equal(isTooLarge(-1), true);
});

test("plainText returns empty, quickly, for an HTML-only body over the conversion limit", async () => {
  const big = "<p>" + "x".repeat(MAX_HTML_CHARS + 10) + "</p>";
  const parsed = await simpleParser(mixed("Content-Type: text/html; charset=utf-8\r\n\r\n" + big));
  assert.ok(typeof parsed.html === "string" && parsed.html.length > MAX_HTML_CHARS);
  const t0 = performance.now();
  assert.equal(await plainText(parsed), "");
  assert.ok(performance.now() - t0 < 200, "should not re-parse over-limit HTML");
});

test("isAuthFailure recognises imapflow's authenticationFailed flag only", () => {
  assert.equal(isAuthFailure(Object.assign(new Error("x"), { authenticationFailed: true })), true);
  assert.equal(isAuthFailure(new Error("Connection closed")), false);
  assert.equal(isAuthFailure(Object.assign(new Error("x"), { authenticationFailed: false })), false);
  assert.equal(isAuthFailure(undefined), false);
  assert.equal(isAuthFailure("authenticationFailed"), false);
});

test("OP_TIMEOUT_MS is 30 seconds", () => {
  assert.equal(OP_TIMEOUT_MS, 30000);
});

test("withDeadline: a slow operation times out with BRIDGE_TIMEOUT and runs the cleanup once", async () => {
  let cleaned = 0;
  let lateResolve: (v: string) => void = () => {};
  const slow = new Promise<string>((r) => (lateResolve = r));
  const started = Date.now();
  await assert.rejects(withDeadline(slow, 30, () => cleaned++), (e: unknown) => {
    assert.ok(e instanceof GuardError);
    assert.equal(e.code, "BRIDGE_TIMEOUT");
    assert.equal(e.message, "Proton Mail Bridge did not respond in time.");
    return true;
  });
  assert.ok(Date.now() - started >= 25);
  assert.equal(cleaned, 1);
  lateResolve("late");
  await new Promise((r) => setTimeout(r, 5));
  assert.equal(cleaned, 1);
});

test("withDeadline: a slow operation that later rejects does not cause an unhandled rejection", async () => {
  let lateReject: (e: Error) => void = () => {};
  const slow = new Promise<string>((_r, j) => (lateReject = j));
  await assert.rejects(withDeadline(slow, 10, () => {}), GuardError);
  lateReject(new Error("late"));
  await new Promise((r) => setTimeout(r, 5));
});

test("withDeadline: fast results and errors pass through without cleanup", async () => {
  let cleaned = 0;
  assert.equal(await withDeadline(Promise.resolve(7), 1000, () => cleaned++), 7);
  await assert.rejects(withDeadline(Promise.reject(new Error("boom")), 1000, () => cleaned++), /boom/);
  assert.equal(cleaned, 0);
});

test("ImapStore releases the mutex after a timeout so the next call runs", async () => {
  const store = new ImapStore(
    { bridge: { host: "127.0.0.1", port: 1, username: "u" }, mail: { allowedMailboxes: ["A"] }, vault: { root: "/v", allowedDestinations: ["D"] }, maxAttachmentBytes: 1, allowOfficeDocuments: false, allowMarkdown: false },
    "pw",
    { ca: "x", rejectUnauthorized: true, checkServerIdentity: () => undefined },
    { opTimeoutMs: 20 },
  );
  const s = store as unknown as { connect: () => Promise<unknown>; withClient: <T>(fn: (c: unknown) => Promise<T>) => Promise<T> };
  s.connect = async () => ({ usable: true, close() {} });
  const hang = s.withClient(() => new Promise(() => {}));
  await assert.rejects(hang, (e: unknown) => e instanceof GuardError && e.code === "BRIDGE_TIMEOUT");
  assert.equal(await s.withClient(async () => "next ran"), "next ran");
});

test("withDeadline: a throwing onTimeout still rejects with BRIDGE_TIMEOUT and does not crash", async () => {
  let uncaught: unknown;
  const onUncaught = (e: unknown) => (uncaught = e);
  process.on("uncaughtException", onUncaught);
  try {
    await assert.rejects(
      withDeadline(new Promise(() => {}), 10, () => {
        throw new Error("close failed");
      }),
      (e: unknown) => e instanceof GuardError && e.code === "BRIDGE_TIMEOUT",
    );
    await new Promise((r) => setTimeout(r, 10));
    assert.equal(uncaught, undefined);
  } finally {
    process.off("uncaughtException", onUncaught);
  }
});

test("MessageIdCache: reuses a set while the mailbox key is unchanged and refetches when it changes", async () => {
  const cache = new MessageIdCache();
  let loads = 0;
  const load = (ids: string[]) => async () => {
    loads++;
    return new Set(ids);
  };
  const k1 = mailboxStateKey({ uidValidity: 7n, uidNext: 10, exists: 3 });
  assert.deepEqual([...(await cache.get("Spam", k1, load(["a"])))], ["a"]);
  assert.deepEqual([...(await cache.get("Spam", k1, load(["b"])))], ["a"]);
  assert.equal(loads, 1);
  for (const changed of [
    { uidValidity: 8n, uidNext: 10, exists: 3 },
    { uidValidity: 7n, uidNext: 11, exists: 3 },
    { uidValidity: 7n, uidNext: 10, exists: 2 },
  ]) {
    const before: number = loads;
    await cache.get("Spam", mailboxStateKey(changed), load(["c"]));
    assert.equal(loads, before + 1, JSON.stringify(changed, (_k, v) => (typeof v === "bigint" ? String(v) : v)));
  }
  // Keyed per mailbox.
  await cache.get("Trash", k1, load(["t"]));
  assert.equal(loads, 5);
});

test("MessageIdCache: callers get copies, failures and unknown keys are not cached", async () => {
  const cache = new MessageIdCache();
  let loads = 0;
  const k = mailboxStateKey({ uidValidity: 1n, uidNext: 2, exists: 1 });
  const got = await cache.get("Spam", k, async () => (loads++, new Set(["a"])));
  got.add("mutated");
  assert.deepEqual([...(await cache.get("Spam", k, async () => (loads++, new Set<string>())))], ["a"]);
  assert.equal(loads, 1);

  const fresh = new MessageIdCache();
  await assert.rejects(fresh.get("Spam", k, async () => { throw new Error("boom"); }));
  assert.deepEqual([...(await fresh.get("Spam", k, async () => new Set(["z"])))], ["z"]);

  assert.equal(mailboxStateKey({ uidValidity: 1n, uidNext: undefined, exists: 1 }), undefined);
  let uncached = 0;
  for (let i = 0; i < 2; i++) await fresh.get("Trash", undefined, async () => (uncached++, new Set()));
  assert.equal(uncached, 2);
});
