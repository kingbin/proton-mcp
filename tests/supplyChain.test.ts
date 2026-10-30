import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("../../", import.meta.url));
const json = async (name: string) => JSON.parse(await readFile(ROOT + name, "utf8"));

test("no locked package runs an install script", async () => {
  const lock = await json("package-lock.json");
  const withScripts = Object.entries(lock.packages as Record<string, { hasInstallScript?: boolean }>)
    .filter(([, p]) => p.hasInstallScript)
    .map(([name]) => name);
  assert.deepEqual(withScripts, []);
});

test("every direct dependency is pinned to an exact version", async () => {
  const pkg = await json("package.json");
  const exact = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
  for (const field of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
    for (const [name, range] of Object.entries((pkg[field] ?? {}) as Record<string, string>)) {
      assert.match(range, exact, `${field}.${name} is "${range}", not an exact version`);
    }
  }
});

test("published files exclude source maps, tests and docs", async () => {
  const pkg = await json("package.json");
  const files = pkg.files as string[];
  for (const f of files) {
    assert.ok(!f.includes("tests") && !f.includes("docs") && !f.endsWith(".map"), f);
    assert.ok(!/^build\/(core|Mail)\/?$/.test(f), `${f} would publish source maps`);
  }
});

test(".npmrc saves exact versions and audits at moderate", async () => {
  const rc = await readFile(ROOT + ".npmrc", "utf8");
  assert.match(rc, /^save-exact=true$/m);
  assert.match(rc, /^audit-level=moderate$/m);
});

test("engines require Node 22+, and CI installs without running scripts", async () => {
  const pkg = await json("package.json");
  assert.equal(pkg.engines.node, ">=22.0.0");
  const ci = await readFile(ROOT + ".github/workflows/ci.yml", "utf8");
  assert.match(ci, /run: npm ci --ignore-scripts\n\s+- run: npm run build\n/);
  assert.doesNotMatch(ci, /run: npm ci\s*\n/);
  for (const m of ci.matchAll(/uses: (\S+)/g)) assert.match(m[1]!, /@[0-9a-f]{40}$/, m[1]);
});
