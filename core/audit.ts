import { appendFile, mkdir } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

export const AUDIT_LOG_PATH = join(homedir(), "Library", "Logs", "proton-mcp", "audit.log");

export interface AuditEntry {
  tool: string;
  mailbox?: string;
  uid?: number;
  ok: boolean;
  code?: string;
}

// Metadata only. Build a fresh object from whitelisted fields; never spread the input.
export async function audit(entry: AuditEntry, logPath: string = AUDIT_LOG_PATH): Promise<void> {
  try {
    const record: Record<string, unknown> = { ts: new Date().toISOString(), tool: entry.tool };
    if (entry.mailbox !== undefined) record.mailbox = entry.mailbox;
    if (entry.uid !== undefined) record.uid = entry.uid;
    record.ok = entry.ok;
    if (entry.code !== undefined) record.code = entry.code;

    await mkdir(dirname(logPath), { recursive: true, mode: 0o700 });
    await appendFile(logPath, JSON.stringify(record) + "\n", { mode: 0o600 });
  } catch {
    // Auditing must never break a tool call; write failures are swallowed.
  }
}
