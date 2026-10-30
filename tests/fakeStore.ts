import type { MessageRef } from "../core/guards.js";
import { GuardError } from "../core/guards.js";
import type { MailStore, MessageSummary, SearchCriteria } from "../Mail/store.js";

export const UIDV = "1700000000";
export const PDF_BYTES = Buffer.from("%PDF-1.7 fake");

interface Msg {
  summary: MessageSummary;
  text: string;
  data?: Buffer;
}

function msg(mailbox: string, uid: number, messageId: string | undefined, subject: string, extra: Partial<MessageSummary> = {}, text = "body"): Msg {
  return {
    summary: {
      mailbox, uidValidity: UIDV, uid, messageId,
      date: "2026-10-01T12:00:00Z", from: "Alice <alice@example.com>", to: "user@example.com",
      subject, attachments: [], ...extra,
    },
    text,
  };
}

export class FakeStore implements MailStore {
  boxes = new Map<string, Msg[]>();
  constructor() {
    const pdf = msg("Labels/MCP", 3, "<pdf@x>", "Invoice", {
      attachments: [{ index: 0, filename: "../Invoice.PDF", contentType: "application/pdf", size: PDF_BYTES.length }],
    }, "see attached");
    pdf.data = PDF_BYTES;
    this.boxes.set("Labels/MCP", [
      msg("Labels/MCP", 1, "<plain@x>", "Hello", {}, "plain body"),
      msg("Labels/MCP", 2, "<shared-with-spam@x>", "Also in spam"),
      pdf,
      msg("Labels/MCP", 4, undefined, "No message id"),
      msg("Labels/MCP", 5, "<html@x>", "HTML only", {}, "Converted html text"),
    ]);
    this.boxes.set("Inbox", [msg("Inbox", 1, "<inbox@x>", "Inbox mail")]);
    this.boxes.set("Spam", [msg("Spam", 1, "<shared-with-spam@x>", "Spam copy")]);
    this.boxes.set("Trash", [msg("Trash", 1, "<trashed@x>", "Trashed")]);
  }

  async listMailboxes() {
    return [...this.boxes].map(([path, m]) => ({ path, messages: m.length }));
  }
  async search(mailbox: string, c: SearchCriteria) {
    return (this.boxes.get(mailbox) ?? []).map((m) => m.summary).slice(0, c.limit);
  }
  private find(ref: MessageRef): Msg {
    const m = this.boxes.get(ref.mailbox)?.find((x) => x.summary.uid === ref.uid);
    if (!m) throw new GuardError("NOT_FOUND", "Message not found");
    return m;
  }
  async read(ref: MessageRef) {
    const m = this.find(ref);
    return { summary: m.summary, text: m.text };
  }
  async attachment(ref: MessageRef, index: number) {
    const m = this.find(ref);
    const a = m.summary.attachments[index];
    if (!a || !m.data) throw new GuardError("NOT_FOUND", "Attachment not found");
    return { filename: a.filename, contentType: a.contentType, data: m.data };
  }
  async messageIdsIn(mailbox: string) {
    return new Set((this.boxes.get(mailbox) ?? []).flatMap((m) => (m.summary.messageId ? [m.summary.messageId] : [])));
  }
  async uidValidity(_mailbox: string) {
    return UIDV;
  }
}
