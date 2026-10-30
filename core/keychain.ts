import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { ConfigError } from "./config.js";

/** Runs a program directly (no shell) and resolves with its output. Injectable for tests. */
export type ExecFileFn = (
  file: string,
  args: readonly string[],
  options: { encoding: "utf8"; timeout: number; maxBuffer: number },
) => Promise<{ stdout: string; stderr: string }>;

const execFileP = promisify(execFile);
const defaultRun: ExecFileFn = (file, args, options) => execFileP(file, [...args], options);

const SECURITY = "/usr/bin/security";
const SERVICE = "proton-mcp";
/** `security` exits 44 when the item is not in the keychain. */
const ITEM_NOT_FOUND = 44;

function addHint(username: string): string {
  return (
    `Bridge password not found in the macOS Keychain (service "${SERVICE}", account "${username}"). ` +
    `Add it with: security add-generic-password -s ${SERVICE} -a "${username}" -w ` +
    `(you will be prompted for the Bridge password shown in Proton Mail Bridge).`
  );
}

/**
 * Reads the Bridge password from the login keychain via `/usr/bin/security`.
 * This is the only child process in the project: fixed program path, fixed args, never a shell.
 */
export async function bridgePassword(username: string, run: ExecFileFn = defaultRun): Promise<string> {
  let stdout: string;
  try {
    ({ stdout } = await run(SECURITY, ["find-generic-password", "-s", SERVICE, "-a", username, "-w"], {
      encoding: "utf8",
      timeout: 10000,
      maxBuffer: 64 * 1024,
    }));
  } catch (e) {
    const code = (e as { code?: unknown }).code;
    if (code === ITEM_NOT_FOUND) throw new ConfigError(addHint(username));
    throw new ConfigError(`Could not read the Bridge password from the macOS Keychain (security exit ${String(code ?? "unknown")}). ${addHint(username)}`);
  }
  const password = String(stdout).replace(/\r?\n$/, "");
  if (password.length === 0) throw new ConfigError(addHint(username));
  return password;
}
