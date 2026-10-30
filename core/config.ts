import { lstat, readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, dirname, join, isAbsolute } from "node:path";
import { z } from "zod";

export const DENIED_MAILBOXES: readonly string[] = ["Spam", "Trash"];

/** True for Spam or Trash in any letter case. */
export function isDeniedMailbox(name: string): boolean {
  const n = name.toLowerCase();
  return DENIED_MAILBOXES.some((d) => d.toLowerCase() === n);
}

export const CONFIG_DIR = join(homedir(), ".config", "proton-mcp");
export const CONFIG_PATH = join(CONFIG_DIR, "config.json");
export const CERT_PATH = join(CONFIG_DIR, "bridge-cert.pem");

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

export interface Config {
  bridge: { host: string; port: number; username: string };
  mail: { allowedMailboxes: string[] };
  vault: { root: string; allowedDestinations: string[] };
  maxAttachmentBytes: number;
  /** Save .docx/.xlsx/.pptx at all. Off by default: the Office check is a best-effort filter. */
  allowOfficeDocuments: boolean;
}

const DEFAULT_MAX_BYTES = 26214400;

const noLineBreaks = (s: string) => !/[\r\n]/.test(s);
const LB_MSG = "must not contain CR or LF";

const str = z.string().refine(noLineBreaks, LB_MSG);

const destination = str.superRefine((d, ctx) => {
  const fail = (message: string) => ctx.addIssue({ code: z.ZodIssueCode.custom, message });
  if (d.length === 0) return fail("destination must not be empty");
  if (isAbsolute(d) || d.startsWith("/") || d.startsWith("\\")) return fail(`destination "${d}" must be vault-relative`);
  const segments = d.split(/[\\/]/);
  if (segments.includes("..")) return fail(`destination "${d}" must not contain ".."`);
  if (segments.some((s) => s.startsWith("."))) return fail(`destination "${d}" must not contain a segment starting with "."`);
  if (segments[0] === "Templates") return fail(`destination "${d}" must not be Templates`);
});

const DEST_HINT =
  'must list at least one vault-relative folder that attachments may be saved into, e.g. "allowedDestinations": ["Inbox", "Documents"]';

const loopback = new Set(["127.0.0.1", "::1"]);

const schema = z.strictObject({
  bridge: z.strictObject({
    host: str.refine((h) => loopback.has(h), "bridge.host must be 127.0.0.1 or ::1"),
    port: z.number().int().min(1).max(65535),
    username: str.pipe(z.string().min(1)),
  }),
  mail: z.strictObject({
    allowedMailboxes: z
      .array(str.pipe(z.string().min(1)))
      .superRefine((boxes, ctx) => {
        for (const b of boxes) {
          if (isDeniedMailbox(b)) {
            ctx.addIssue({ code: z.ZodIssueCode.custom, message: `mailbox "${b}" is hard-denied and cannot be allowed` });
          }
        }
      }),
  }),
  vault: z.strictObject({
    root: str.refine((r) => isAbsolute(r), "vault.root must be an absolute path"),
    allowedDestinations: z
      .array(destination, { error: (iss) => (iss.input === undefined ? DEST_HINT : undefined) })
      .min(1, DEST_HINT),
  }),
  maxAttachmentBytes: z.number().int().positive().default(DEFAULT_MAX_BYTES),
  allowOfficeDocuments: z.boolean().default(false),
});

/** One line for `doctor` saying whether Office documents can be saved. */
export function officeStatus(cfg: Config): string {
  return cfg.allowOfficeDocuments
    ? "Office documents (.docx, .xlsx, .pptx): enabled (allowOfficeDocuments: true; best-effort checks, see SECURITY.md)"
    : "Office documents (.docx, .xlsx, .pptx): disabled (set allowOfficeDocuments: true to enable; see SECURITY.md)";
}

export function parseConfig(raw: unknown): Config {
  const result = schema.safeParse(raw);
  if (!result.success) {
    const msg = result.error.issues
      .map((i) => `${i.path.join(".") || "config"}: ${i.message}`)
      .join("; ");
    throw new ConfigError(`Invalid config: ${msg}`);
  }
  return result.data;
}

const CERT_NAME = basename(CERT_PATH);

/**
 * Trust checks for the config directory, config file and pinned certificate (the certificate only
 * if present). Each must be a real directory/file (not a symlink), owned by `uid`, and not group-
 * or world-writable: otherwise another local user or process could change which mailboxes and
 * folders are allowed, or which certificate is trusted. Missing paths are not reported here.
 */
export async function trustProblems(
  configPath: string = CONFIG_PATH,
  uid: number | undefined = process.getuid?.(),
): Promise<string[]> {
  const dir = dirname(configPath);
  const targets: [string, "directory" | "file"][] = [
    [dir, "directory"],
    [configPath, "file"],
    [join(dir, CERT_NAME), "file"],
  ];
  const problems: string[] = [];
  for (const [p, kind] of targets) {
    let st;
    try {
      st = await lstat(p);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") continue;
      problems.push(`${p} cannot be checked (${(e as NodeJS.ErrnoException).code ?? "error"})`);
      continue;
    }
    if (st.isSymbolicLink()) {
      problems.push(`${p} is a symlink; replace it with a real ${kind}`);
      continue;
    }
    if (kind === "directory" ? !st.isDirectory() : !st.isFile()) {
      problems.push(`${p} is not a regular ${kind}`);
      continue;
    }
    if (uid !== undefined && st.uid !== uid) {
      problems.push(`${p} is not owned by the current user (uid ${uid}); fix with: chown $(id -un) ${p}`);
    }
    if ((st.mode & 0o022) !== 0) {
      problems.push(`${p} is group- or world-writable; fix with: chmod ${kind === "directory" ? "700" : "600"} ${p}`);
    }
  }
  return problems;
}

export async function loadConfig(path: string = CONFIG_PATH): Promise<Config> {
  const problems = await trustProblems(path);
  if (problems.length > 0) throw new ConfigError(`Refusing to load config: ${problems.join("; ")}`);
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") {
      throw new ConfigError(`Config not found at ${path}. See README > Setup.`);
    }
    throw new ConfigError(`Cannot read config at ${path}: ${(e as Error).message}`);
  }
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    throw new ConfigError(`Config at ${path} is not valid JSON.`);
  }
  return parseConfig(json);
}
