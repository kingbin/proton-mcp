import { test } from "node:test";
import assert from "node:assert/strict";
import { bridgePassword, type ExecFileFn } from "../core/keychain.js";
import { ConfigError } from "../core/config.js";

test("bridgePassword calls security with fixed args, no shell, and trims the newline", async () => {
  const calls: { file: string; args: readonly string[]; options: object }[] = [];
  const fakeRun: ExecFileFn = async (file, args, options) => {
    calls.push({ file, args, options });
    return { stdout: "secret\n", stderr: "" };
  };
  const pw = await bridgePassword("user@example.com", fakeRun);
  assert.equal(pw, "secret");
  assert.equal(calls.length, 1);
  assert.deepEqual(
    [calls[0]!.file, calls[0]!.args],
    ["/usr/bin/security", ["find-generic-password", "-s", "proton-mcp", "-a", "user@example.com", "-w"]],
  );
  assert.equal(Object.hasOwn(calls[0]!.options, "shell"), false);
});

test("bridgePassword maps a missing keychain item (exit 44) to a ConfigError with setup instructions", async () => {
  const fakeRun: ExecFileFn = async () => {
    throw Object.assign(new Error("Command failed: security ... could not be found"), { code: 44 });
  };
  await assert.rejects(bridgePassword("user@example.com", fakeRun), (e: unknown) => {
    assert.ok(e instanceof ConfigError);
    assert.match(e.message, /security add-generic-password -s proton-mcp/);
    return true;
  });
});

test("bridgePassword rejects an empty password", async () => {
  const fakeRun: ExecFileFn = async () => ({ stdout: "\n", stderr: "" });
  await assert.rejects(bridgePassword("user@example.com", fakeRun), ConfigError);
});
