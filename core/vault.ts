import * as fs from "node:fs/promises";
import * as path from "node:path";
import type { Config } from "./config.js";
import { contentMatches } from "./content.js";
import { GuardError, stripInvisible } from "./guards.js";

export const SAVEABLE_EXTENSIONS: readonly string[] = [
  ".pdf", ".png", ".jpg", ".jpeg", ".heic", ".gif",
  ".docx", ".xlsx", ".pptx",
  ".txt", ".csv", ".md",
];

/** Office formats: saveable only when the config sets allowOfficeDocuments: true. */
export const OFFICE_EXTENSIONS: readonly string[] = [".docx", ".xlsx", ".pptx"];
export const OFFICE_DISABLED_MESSAGE =
  "Office documents are disabled; set allowOfficeDocuments: true to enable (see SECURITY.md)";

export const MARKDOWN_DISABLED_MESSAGE =
  "Markdown files are disabled; set allowMarkdown: true to enable (see SECURITY.md)";

const MAX_NAME = 120;
const DENIED_SEGMENTS = new Set(["templates", ".obsidian", ".claude"]);
// eslint-disable-next-line no-control-regex
const BAD_CHARS = new RegExp("[\\u0000-\\u001f\\u007f-\\u009f\\u2028\\u2029\\u202a-\\u202e\\u2066-\\u2069<>:\"|?*]", "g");

/** Reduce an untrusted attachment name to a safe single path component. */
export function sanitizeFilename(name: string | undefined, fallbackExt: string): string {
  // Invisible characters first (so "CLAUDE\u200b.md" is "CLAUDE.md"), then NFKC to fold
  // look-alikes, then strip again in case folding produced one.
  let n = stripInvisible(stripInvisible(name ?? "").normalize("NFKC"));
  n = n.split(/[\\/]/).pop() ?? "";
  n = n.replace(BAD_CHARS, "").replace(/\.{2,}/g, ".").trim();
  n = n.replace(/^[\s.]+/, "");
  if (n === "") n = "attachment";
  let ext = path.extname(n);
  if (ext === "" || ext === n) {
    // Trim trailing dots with a loop: an unanchored /\.+$/ is quadratic on long dot runs.
    let end = n.length;
    while (end > 0 && n.charCodeAt(end - 1) === 0x2e) end--;
    n = n.slice(0, end) || "attachment";
    n += fallbackExt;
    ext = path.extname(n);
  }
  if (n.length > MAX_NAME) {
    const stem = n.slice(0, n.length - ext.length);
    n = stem.slice(0, MAX_NAME - ext.length) + ext;
  }
  return n;
}

const notAllowed = (rel: string) =>
  new GuardError("DEST_NOT_ALLOWED", `Destination not allowed: ${rel}`);

/** Resolve a vault-relative destination to a real directory inside an allowed subtree. */
export async function resolveDestination(cfg: Config, destinationDir: string): Promise<string> {
  const rel = destinationDir;
  if (typeof rel !== "string" || rel.trim() === "" || rel.includes("\0")) throw notAllowed(String(rel));
  if (path.isAbsolute(rel) || /^[\\/]/.test(rel) || /^[A-Za-z]:/.test(rel)) throw notAllowed(rel);
  const segs = rel.split(/[\\/]/).filter((s) => s !== "");
  if (segs.length === 0) throw notAllowed(rel);
  for (const s of segs) {
    if (s === "." || s.startsWith(".") || DENIED_SEGMENTS.has(s.toLowerCase())) throw notAllowed(rel);
  }

  let realRoot: string;
  try {
    realRoot = await fs.realpath(cfg.vault.root);
  } catch {
    throw new GuardError("DEST_MISSING", "Vault root not found");
  }

  let target: string;
  try {
    target = await fs.realpath(path.join(realRoot, ...segs));
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT" || (e as NodeJS.ErrnoException).code === "ENOTDIR") {
      // A missing folder is only "missing" if its first segment is an allowed subtree.
      const first = segs[0]!.toLowerCase();
      const ok = cfg.vault.allowedDestinations.some((a) => a.split("/")[0]!.toLowerCase() === first);
      if (!ok) throw notAllowed(rel);
      throw new GuardError("DEST_MISSING", `Destination folder does not exist: ${rel}`);
    }
    throw notAllowed(rel);
  }

  let allowed = false;
  for (const a of cfg.vault.allowedDestinations) {
    let realAllowed: string;
    try {
      realAllowed = await fs.realpath(path.join(realRoot, a));
    } catch {
      continue;
    }
    if (target === realAllowed || target.startsWith(realAllowed + path.sep)) {
      allowed = true;
      break;
    }
  }
  if (!allowed) throw notAllowed(rel);

  for (const s of path.relative(realRoot, target).split(path.sep)) {
    if (s.startsWith(".") || DENIED_SEGMENTS.has(s.toLowerCase())) throw notAllowed(rel);
  }

  const st = await fs.stat(target);
  if (!st.isDirectory()) throw notAllowed(rel);
  return target;
}

/**
 * Names that coding assistants load as standing instructions; never saved from mail. Dot-names
 * are already refused as hidden files, but are listed so the intent is explicit, and a sanitized
 * name is also checked with a leading dot restored.
 */
export const RESERVED_NAMES: ReadonlySet<string> = new Set([
  "claude.md",
  "claude.local.md",
  "agents.md",
  "agents.override.md",
  "agent.md",
  "gemini.md",
  "copilot-instructions.md",
  "conventions.md",
  ".cursorrules",
  ".windsurfrules",
]);

function isReserved(name: string): boolean {
  const n = name.normalize("NFKC").toLowerCase();
  return RESERVED_NAMES.has(n) || RESERVED_NAMES.has("." + n);
}

/** Write `data` into an allowed vault folder, never overwriting. Returns vault-relative path. */
export async function saveFile(
  cfg: Config,
  destinationDir: string,
  filename: string,
  data: Buffer,
): Promise<string> {
  const name = sanitizeFilename(filename, "");
  if (name.startsWith(".")) {
    throw new GuardError("TYPE_NOT_ALLOWED", `Hidden file names are not allowed: ${name}`);
  }
  if (isReserved(name)) {
    throw new GuardError("NAME_NOT_ALLOWED", `File name is reserved (loaded as instructions by tools): ${name}`);
  }
  const ext = path.extname(name).toLowerCase();
  if (!SAVEABLE_EXTENSIONS.includes(ext)) {
    throw new GuardError("TYPE_NOT_ALLOWED", `File type not allowed: ${name}`);
  }
  if (OFFICE_EXTENSIONS.includes(ext) && !cfg.allowOfficeDocuments) {
    throw new GuardError("TYPE_NOT_ALLOWED", OFFICE_DISABLED_MESSAGE);
  }
  if (ext === ".md" && !cfg.allowMarkdown) {
    throw new GuardError("TYPE_NOT_ALLOWED", MARKDOWN_DISABLED_MESSAGE);
  }
  if (data.length > cfg.maxAttachmentBytes) {
    throw new GuardError("TOO_LARGE", `File too large: ${name} (${data.length} bytes, max ${cfg.maxAttachmentBytes})`);
  }
  if (!contentMatches(ext, data)) {
    throw new GuardError("TYPE_NOT_ALLOWED", `Content does not match its ${ext} extension (or is a macro-enabled document): ${name}`);
  }

  const dir = await resolveDestination(cfg, destinationDir);
  const full = path.join(dir, name);
  // macOS iCloud Drive keeps a not-yet-downloaded file as a hidden `.<name>.icloud` stub.
  const stub = path.join(dir, `.${name}.icloud`);
  const exists = new GuardError("EXISTS", `File already exists: ${name} in ${destinationDir}`);
  try {
    await fs.lstat(stub);
    throw exists;
  } catch (e) {
    if (e === exists) throw e;
    if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
  }
  try {
    await fs.writeFile(full, data, { flag: "wx" });
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "EEXIST") throw exists;
    throw e;
  }
  const realRoot = await fs.realpath(cfg.vault.root);
  return path.relative(realRoot, full).split(path.sep).join("/");
}
