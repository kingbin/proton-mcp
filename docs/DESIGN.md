# Design

## Purpose

proton-mcp is a local MCP server that lets an AI assistant read a chosen subset of a Proton Mail mailbox and save attachments into chosen local folders. It talks to Proton Mail Bridge over IMAP on loopback. It is read-only against the mailbox by construction, and it treats both the model and the mail as untrusted.

## Layout

```
index.ts          entry point: MCP server on stdio, plus the pin-cert and doctor commands
core/             service-independent building blocks
  config.ts       config schema, file trust checks, hard-denied mailboxes
  guards.ts       GuardError, message refs, input strings, untrusted-text cleaning and wrapping
  tool.ts         tool() helper: input validation, error mapping, MCP annotations
  vault.ts        destination resolution, filename sanitising, reserved names, exclusive save
  content.ts      content checks per saveable file type, incl. the strict OOXML zip/XML check
  tls.ts          pinned-certificate TLS options and the runtime pinned-TLS guard
  keychain.ts     Bridge password from the macOS Keychain (the only child process)
  audit.ts        metadata-only audit log
Mail/             the mail service
  store.ts        the MailStore interface
  imapStore.ts    MailStore over Bridge (imapflow + mailparser)
  tools.ts        the four mail tools
tests/            node:test suites, with a fake MailStore
```

`core/` holds the shared controls (config, guards, saving, TLS, Keychain, audit). A future service would sit beside `Mail/` and reuse them.

## The MailStore seam

`Mail/tools.ts` never talks IMAP. It depends on the `MailStore` interface:

- `listMailboxes()`, `search(mailbox, criteria)`, `read(ref)`, `attachment(ref, index)`
- `messageIdsIn(mailbox)` and `uidValidity(mailbox)`, used for the safety checks

`ImapStore` implements it over Bridge. Tests use an in-memory `FakeStore`. All policy (allowlists, Spam/Trash denial, the Message-ID cross-check, output cleaning, saving) lives in the tools layer and `core/`, so it is tested without a mail server, and the store only has to be correct about reading.

## Data flow

**Startup.** `index.ts` loads the config. If loading fails (missing, untrusted file, invalid), the server still starts and every tool returns `SETUP: <what to fix>`. The real store is created lazily on the first call: it reads the Bridge password from the Keychain and the pinned certificate, then connects.

**Search.** Validate input -> check the mailbox against the allowlist -> `store.search` (newest first, capped by `limit`) -> collect Message-IDs from Spam and Trash (envelopes only, cached per mailbox state; their mail is never returned) -> drop messages with no Message-ID or one found there -> clean headers -> return opaque refs and metadata as JSON.

**Read.** Decode the ref -> check the mailbox -> check UIDVALIDITY -> `store.read` -> Message-ID cross-check -> clean headers -> clean, cap and wrap the body in untrusted markers.

**Save.** The same checks as read -> `store.attachment` -> sanitise the filename -> check reserved names, extension, size and content -> resolve the destination inside an allowed folder -> refuse if an iCloud placeholder (`.<name>.icloud`) exists -> exclusive create.

Every call writes one audit line with tool name, allowed mailbox, UID, success and error code.

The server writes only three kinds of file: saved attachments in the allowed folders, the audit log, and the pinned certificate (only when you run `pin-cert`). Whether you approve a save before it happens is up to your MCP client. The server marks the save tool as not read-only and its description asks for approval, but it cannot enforce that.

Inside `ImapStore`, calls are serialised by a promise-chain mutex and each runs under a 30-second deadline. Mailboxes are opened read-only, metadata is fetched before message bodies, bodies are fetched one at a time, and oversized messages are skipped.

## Why each control exists

| Control | Reason |
| --- | --- |
| No write methods; read-only opens; `BODY.PEEK` | A prompt-injected model cannot be trusted with mailbox changes, so the capability is absent rather than gated. |
| Mailbox allowlist; Spam and Trash denied in code (any case) | You choose what the model sees; junk and phishing never reach it, whatever the config says. |
| Message-ID cross-check | The same message can appear under an allowed label and in Spam; the label must not launder it. |
| Opaque refs with UIDVALIDITY | Refs cannot be re-pointed at another mailbox and go stale when the mailbox is rebuilt. |
| Text cleaning and untrusted markers | Mail is attacker-written. Invisible and control characters can hide instructions or forge structure; the markers tell the model where the data starts and ends. |
| Required destination list, realpath containment, dot/Templates refusal | Saves land only where you said, never in tool configuration directories or templates, even through symlinks. |
| Filename sanitising and reserved names | Attachment names are attacker-chosen; some names would be loaded as instructions by coding assistants. |
| Extension allowlist and content checks; Office opt-in | The name says nothing about the bytes. Office formats are off unless `allowOfficeDocuments` is true, because the Office check is a best-effort filter, not a sanitizer. When enabled, files must be consistent zips whose content types and relationships are allowlisted, and every XML part (found by name or content type) is scanned: Word fields against an allowlist with no nesting and only run markup inside instructions, Excel formulas (every part except Word/PowerPoint types) for DDE and dangerous functions, PowerPoint program/OLE actions; markup compatibility (mc) is refused outright (see SECURITY.md > OOXML check and Known limitations). |
| Exclusive create and iCloud placeholder check | A save never replaces an existing file. |
| Loopback host, STARTTLS, pinned certificate, runtime TLS guard | Only the local Bridge you pinned is trusted; the IMAP client cannot be built from unpinned TLS options. |
| Keychain password, single fixed `execFile` | No secret on disk and no shell. |
| Config file trust and strict schema | Other local users cannot widen access, and typos cannot silently drop settings. Processes running as you still can; the check reads mode bits, not ACLs. |
| Per-call deadline | A hung Bridge cannot wedge the server. |
| Metadata-only audit log | You can see what was called without the log becoming a copy of your mail. |
| MCP annotations | Clients can tell read-only tools from the one that writes a file. |
| Static source scan | Catches accidental reintroduction of shell, eval, network or TLS-weakening APIs anywhere outside tests. A heuristic, not a sandbox. |
| Exact pins, no install scripts, SHA-pinned CI | The code that runs is the code that was reviewed. |
