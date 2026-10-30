import type { MessageRef } from "../core/guards.js";

export interface AttachmentInfo {
  index: number;
  filename?: string;
  contentType: string;
  size: number;
}

export interface MessageSummary {
  mailbox: string;
  uidValidity: string;
  uid: number;
  messageId?: string;
  date: string;
  from: string;
  to?: string;
  subject: string;
  attachments: AttachmentInfo[];
}

export interface SearchCriteria {
  from?: string;
  subject?: string;
  since?: string;
  before?: string;
  hasAttachment?: boolean;
  limit: number;
}

export interface MailStore {
  listMailboxes(): Promise<{ path: string; messages: number }[]>;
  search(mailbox: string, c: SearchCriteria): Promise<MessageSummary[]>;
  read(ref: MessageRef): Promise<{ summary: MessageSummary; text: string }>;
  attachment(ref: MessageRef, index: number): Promise<{ filename?: string; contentType: string; data: Buffer }>;
  messageIdsIn(mailbox: string): Promise<Set<string>>;
  uidValidity(mailbox: string): Promise<string>;
}
