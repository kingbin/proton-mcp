import { inflateRawSync } from "node:zlib";

/**
 * Content checks for saveable attachments. The extension alone is attacker-chosen, so every
 * saved file must also look like the type its extension claims. No parsing beyond what is
 * needed to recognise the type; all reads are bounds-checked.
 */

const startsWith = (data: Buffer, bytes: readonly number[], at = 0): boolean =>
  data.length >= at + bytes.length && bytes.every((b, i) => data[at + i] === b);

const ascii = (data: Buffer, start: number, end: number): string =>
  data.length >= end ? data.subarray(start, end).toString("latin1") : "";

const HEIC_BRANDS = new Set(["heic", "heix", "mif1", "msf1"]);

const EOCD_SIG = 0x06054b50;
const CDH_SIG = 0x02014b50;
const LFH_SIG = 0x04034b50;
const DD_SIG = 0x08074b50;
const EOCD_MIN = 22;
const MAX_COMMENT = 0xffff;
const MAX_ENTRIES = 10000;

/** Largest uncompressed size of one inspected OOXML part ([Content_Types].xml or a .rels). */
export const MAX_INSPECTED_BYTES = 1024 * 1024;
/** Most OOXML parts inspected per file; more is refused rather than partly checked. */
export const MAX_INSPECTED_ENTRIES = 200;
/** Most inflated bytes across all inspected parts of one file; more is refused. */
export const MAX_TOTAL_INFLATED = 16 * 1024 * 1024;

export interface ZipEntry {
  name: string;
  method: number;
  compressedSize: number;
  size: number;
  localOffset: number;
}

/**
 * Entries of a zip, or undefined unless the archive is fully consistent:
 * - the end record ends exactly at the end of the buffer, on a single disk, not zip64;
 * - the central directory sits directly before the end record;
 * - local headers, walked from offset 0, run back-to-back up to the central directory and match
 *   the central entries 1:1 (same order of offsets, name, method, flags and sizes);
 * - no two entries share a name (compared case-insensitively, as OPC part names are);
 * - nothing is encrypted.
 * This removes parser differentials: what is checked here is exactly what any reader sees.
 * Bounded: at most MAX_ENTRIES entries, and every offset is checked against the buffer length.
 */
export function zipEntries(data: Buffer): ZipEntry[] | undefined {
  if (data.length < EOCD_MIN) return undefined;
  const lowest = Math.max(0, data.length - EOCD_MIN - MAX_COMMENT);
  let eocd = -1;
  for (let i = data.length - EOCD_MIN; i >= lowest; i--) {
    if (data.readUInt32LE(i) === EOCD_SIG) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) return undefined;
  if (eocd + EOCD_MIN + data.readUInt16LE(eocd + 20) !== data.length) return undefined;
  if (data.readUInt16LE(eocd + 4) !== 0 || data.readUInt16LE(eocd + 6) !== 0) return undefined; // multi-disk
  const count = data.readUInt16LE(eocd + 10);
  const size = data.readUInt32LE(eocd + 12);
  const offset = data.readUInt32LE(eocd + 16);
  if (count === 0xffff || size === 0xffffffff || offset === 0xffffffff) return undefined; // zip64
  if (data.readUInt16LE(eocd + 8) !== count) return undefined;
  if (count > MAX_ENTRIES || offset + size !== eocd) return undefined;

  interface Central extends ZipEntry {
    flags: number;
    rawName: Buffer;
  }
  const entries: Central[] = [];
  let p = offset;
  for (let n = 0; n < count; n++) {
    if (p + 46 > eocd || data.readUInt32LE(p) !== CDH_SIG) return undefined;
    const nameLen = data.readUInt16LE(p + 28);
    const extraLen = data.readUInt16LE(p + 30);
    const commentLen = data.readUInt16LE(p + 32);
    const nameEnd = p + 46 + nameLen;
    if (nameEnd + extraLen + commentLen > eocd) return undefined;
    const rawName = data.subarray(p + 46, nameEnd);
    entries.push({
      name: rawName.toString("utf8"),
      rawName,
      flags: data.readUInt16LE(p + 8),
      method: data.readUInt16LE(p + 10),
      compressedSize: data.readUInt32LE(p + 20),
      size: data.readUInt32LE(p + 24),
      localOffset: data.readUInt32LE(p + 42),
    });
    p = nameEnd + extraLen + commentLen;
  }
  if (p !== eocd) return undefined;

  const seen = new Set<string>();
  for (const e of entries) {
    const key = e.name.toLowerCase();
    if (seen.has(key)) return undefined;
    seen.add(key);
  }

  // Walk the local headers in file order; each must be where the next central entry says.
  let pos = 0;
  for (const e of [...entries].sort((x, y) => x.localOffset - y.localOffset)) {
    if (e.localOffset !== pos || pos + 30 > offset || data.readUInt32LE(pos) !== LFH_SIG) return undefined;
    const flags = data.readUInt16LE(pos + 6);
    if ((flags & 0x1) !== 0 || flags !== e.flags || data.readUInt16LE(pos + 8) !== e.method) return undefined;
    const nameLen = data.readUInt16LE(pos + 26);
    const extraLen = data.readUInt16LE(pos + 28);
    if (pos + 30 + nameLen + extraLen > offset) return undefined;
    if (!data.subarray(pos + 30, pos + 30 + nameLen).equals(e.rawName)) return undefined;
    const hasDescriptor = (flags & 0x8) !== 0;
    if (!hasDescriptor && (data.readUInt32LE(pos + 18) !== e.compressedSize || data.readUInt32LE(pos + 22) !== e.size)) {
      return undefined;
    }
    pos += 30 + nameLen + extraLen + e.compressedSize;
    if (hasDescriptor) {
      if (pos + 12 > offset) return undefined;
      const signed = data.readUInt32LE(pos) === DD_SIG;
      const d = signed ? pos + 4 : pos;
      if (d + 12 > offset || data.readUInt32LE(d + 4) !== e.compressedSize || data.readUInt32LE(d + 8) !== e.size) {
        return undefined;
      }
      pos = d + 12;
    }
    if (pos > offset) return undefined;
  }
  if (pos !== offset) return undefined;
  return entries.map(({ name, method, compressedSize, size, localOffset }) => ({ name, method, compressedSize, size, localOffset }));
}

/** Central-directory entry names, or undefined if the directory cannot be read. */
export function zipEntryNames(data: Buffer): string[] | undefined {
  return zipEntries(data)?.map((e) => e.name);
}

/** Uncompressed bytes of one entry (stored or deflated), bounded by MAX_INSPECTED_BYTES. */
function readEntry(data: Buffer, e: ZipEntry): Buffer | undefined {
  if (e.size > MAX_INSPECTED_BYTES) return undefined;
  const lh = e.localOffset;
  if (lh + 30 > data.length || data.readUInt32LE(lh) !== LFH_SIG) return undefined;
  const start = lh + 30 + data.readUInt16LE(lh + 26) + data.readUInt16LE(lh + 28);
  const end = start + e.compressedSize;
  if (end > data.length) return undefined;
  const body = data.subarray(start, end);
  let out: Buffer;
  if (e.method === 0) {
    out = body;
  } else if (e.method === 8) {
    try {
      out = inflateRawSync(body, { maxOutputLength: MAX_INSPECTED_BYTES });
    } catch {
      return undefined; // corrupt, or larger than the bound
    }
  } else {
    return undefined;
  }
  // The declared size must be the real size, so the total-inflate pre-check can trust it.
  return out.length === e.size ? out : undefined;
}

/** True if `text` has a control character other than tab, LF and CR, or NEL, LS or PS. */
function hasForbiddenControl(text: string): boolean {
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c < 0x20 ? c !== 0x09 && c !== 0x0a && c !== 0x0d : (c >= 0x7f && c <= 0x9f) || c === 0x2028 || c === 0x2029) {
      return true;
    }
  }
  return false;
}

/**
 * The part as UTF-8 XML text (entities NOT decoded, so markup structure is intact), or undefined
 * if it is not plainly UTF-8: a UTF-16/32 byte-order mark, a NUL byte, invalid UTF-8, an XML
 * declaration naming any other encoding, or a DOCTYPE/ENTITY declaration.
 */
function xmlText(bytes: Buffer): string | undefined {
  if (startsWith(bytes, [0xfe, 0xff]) || startsWith(bytes, [0xff, 0xfe]) || startsWith(bytes, [0, 0, 0xfe, 0xff])) {
    return undefined;
  }
  if (bytes.includes(0)) return undefined;
  const body = startsWith(bytes, [0xef, 0xbb, 0xbf]) ? bytes.subarray(3) : bytes;
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(body);
  } catch {
    return undefined;
  }
  const decl = /^\s*<\?xml\b([^?]*)\?>/.exec(text);
  if (decl) {
    const enc = /\bencoding\s*=\s*["']([^"']*)["']/i.exec(decl[1]!);
    if (enc && enc[1]!.trim().toLowerCase() !== "utf-8") return undefined;
    // XML 1.1 changes which characters count as line ends and names; only 1.0 is accepted.
    const version = /\bversion\s*=\s*["']([^"']*)["']/.exec(decl[1]!);
    if (version && version[1] !== "1.0") return undefined;
  }
  if (hasForbiddenControl(text)) return undefined;
  if (/<!(DOCTYPE|ENTITY)/i.test(text)) return undefined;
  return text;
}

/** Decode character references and the predefined entities. For values and keyword scans only. */
function decodeXml(text: string): string {
  // One pass over the original text: a decoded `&` is never decoded again, so `&#x26;#73;` stays
  // the literal text `&#73;`.
  return text.replace(/&(?:#x([0-9a-fA-F]+)|#([0-9]+)|(lt|gt|quot|apos|amp));/g, (_m, hex?: string, dec?: string, named?: string) => {
    if (hex !== undefined) return codePoint(parseInt(hex, 16));
    if (dec !== undefined) return codePoint(parseInt(dec, 10));
    return ({ lt: "<", gt: ">", quot: '"', apos: "'", amp: "&" } as const)[named as "lt"];
  });
}

function codePoint(n: number): string {
  return Number.isInteger(n) && n >= 0 && n <= 0x10ffff ? String.fromCodePoint(n) : "\uFFFD";
}

const CONTENT_TYPES_NAME = "[content_types].xml";
/** Parts that hold or point at executable or remote content. */
const ACTIVE_PART = /(^|\/)(vbaProject|oleObject\d*|activeX\d*)\.bin$/i;
const ACTIVE_DIR = /(^|\/)(activeX|embeddings)\//i;
/** Binary blobs and whole documents nested inside the archive. */
const NESTED = /\.(bin|docm|xlsm|pptm|docx|xlsx|pptx)$/i;
const BAD_CONTENT_TYPE = /macroEnabled|vbaProject|macrosheet|dialogsheet/i;
/** XLM macro and dialog sheets, refused by location as well as by content type. */
const MACRO_SHEET_DIR = /(^|\/)(macrosheets|dialogsheets)\//i;
const BAD_RELATIONSHIP = /vbaProject|attachedTemplate|oleObject|activeX|externalLink/i;
const EXTERNAL_TARGET = /TargetMode\s*=\s*["']\s*External\s*["']/i;
/** Backstop over the raw archive bytes, case-insensitive. */
const RAW_KEYWORDS = ["vbaproject", "attachedtemplate", "oleobject", "activex"];

/**
 * Relationship types of plain document parts. A Type must be one of these names under one of the
 * known OOXML namespaces; anything else (package, aFChunk, subDocument, frame, control, fonts,
 * printer settings, media, hyperlinks, VML, unknown types) is refused.
 */
const SAFE_REL_NAMES = [
  "officeDocument", "styles", "stylesWithEffects", "settings", "webSettings", "fontTable", "theme",
  "themeOverride", "numbering", "image", "header", "footer", "footnotes", "endnotes", "comments",
  "commentsExtended", "commentsIds", "commentsExtensible", "people", "glossaryDocument", "customXml",
  "customXmlProps", "core-properties", "extended-properties", "custom-properties", "thumbnail",
  "worksheet", "sharedStrings", "calcChain", "table", "drawing", "chart", "chartUserShapes",
  "chartStyle", "chartColorStyle", "diagramData", "diagramLayout", "diagramQuickStyle",
  "diagramColors", "diagramDrawing", "slide", "slideLayout", "slideMaster", "notesSlide",
  "notesMaster", "handoutMaster", "presProps", "viewProps", "tableStyles", "commentAuthors", "tags",
  "extendedProperties", "customProperties",
];
/** Known OOXML relationship namespaces. Matched case-sensitively, exactly as the standard spells them. */
const REL_NAMESPACE =
  /^(?:http:\/\/schemas\.openxmlformats\.org\/officeDocument\/2006\/relationships\/(?:metadata\/)?|http:\/\/schemas\.openxmlformats\.org\/package\/2006\/relationships\/metadata\/|http:\/\/purl\.oclc\.org\/ooxml\/officeDocument\/relationships\/(?:metadata\/)?|http:\/\/schemas\.microsoft\.com\/office\/\d{4}(?:\/\d{2})?\/relationships\/)([A-Za-z-]+)$/;

/** Case-sensitive: the Type must be a known namespace followed by an allowlisted name, verbatim. */
function isSafeRelType(type: string): boolean {
  const m = REL_NAMESPACE.exec(type);
  return m !== null && SAFE_REL_NAMES.includes(m[1]!);
}

const OD = "application/vnd.openxmlformats-officedocument.";
/** Content types of plain document parts. Anything else declared in [Content_Types].xml is refused. */
const SAFE_CONTENT_TYPES = new Set(
  [
    "application/vnd.openxmlformats-package.relationships+xml",
    "application/vnd.openxmlformats-package.core-properties+xml",
    "application/xml",
    "text/xml",
    "image/png", "image/jpeg", "image/gif", "image/tiff", "image/bmp", "image/x-emf", "image/x-wmf",
    "application/vnd.ms-word.styleswitheffects+xml",
    "application/vnd.ms-office.chartstyle+xml",
    "application/vnd.ms-office.chartcolorstyle+xml",
    "application/vnd.ms-office.drawingml.diagramdrawing+xml",
    ...[
      "extended-properties", "custom-properties", "customXmlProperties", "theme", "themeOverride", "drawing",
      "drawingml.chart", "drawingml.chartshapes", "drawingml.diagramData", "drawingml.diagramLayout",
      "drawingml.diagramStyle", "drawingml.diagramColors",
    ].map((t) => `${OD}${t}+xml`),
    ...[
      "document.main", "document.glossary", "styles", "settings", "webSettings", "fontTable", "numbering",
      "footnotes", "endnotes", "comments", "header", "footer", "commentsExtended", "commentsIds",
      "commentsExtensible", "people",
    ].map((t) => `${OD}wordprocessingml.${t}+xml`),
    ...["sheet.main", "worksheet", "styles", "sharedStrings", "calcChain", "table", "comments"].map(
      (t) => `${OD}spreadsheetml.${t}+xml`,
    ),
    ...[
      "presentation.main", "slide", "slideLayout", "slideMaster", "notesSlide", "notesMaster", "handoutMaster",
      "presProps", "viewProps", "tableStyles", "commentAuthors", "comments", "tags",
    ].map((t) => `${OD}presentationml.${t}+xml`),
  ].map((t) => t.toLowerCase()),
);

/** Every ContentType attribute value is allowlisted. */
function contentTypesAreSafe(text: string): boolean {
  // Quoted values use negated classes (no lazy `.*?` plus backreference), so each match is linear.
  for (const m of text.matchAll(/\bContentType\s*=\s*(?:"([^"]*)"|'([^']*)')/gi)) {
    if (!SAFE_CONTENT_TYPES.has((m[1] ?? m[2] ?? "").trim().toLowerCase())) return false;
  }
  return true;
}

/** An XML NCName (a name without ':'), approximated with Unicode letter, mark and number classes. */
const NCNAME = /^[\p{L}_][\p{L}\p{M}\p{N}_.\u00B7-]*$/u;

/** True for XML whitespace and the characters that end an element name. */
function endsName(code: number): boolean {
  return code === 0x20 || code === 0x09 || code === 0x0a || code === 0x0d || code === 0x2f || code === 0x3e || code === 0x3c;
}

/** `Relationship` or `prefix:Relationship` with an NCName prefix; exactly one ':' at most. */
function isRelationshipElementName(name: string): boolean {
  const parts = name.split(":");
  if (parts.length === 1) return name === "Relationship";
  return parts.length === 2 && NCNAME.test(parts[0]!) && parts[1] === "Relationship";
}

/** One attribute: whitespace, name, `=`, then a double- or single-quoted value without `<`. */
const ATTR = /\s+([^\s=<>/"']+)\s*=\s*(?:"([^"<]*)"|'([^'<]*)')/y;
const TAG_END = /\s*\/?>/y;

/**
 * Parse the attributes of the tag starting at `from` (just after the element name), one at a time
 * from the start of each attribute. Returns name -> raw value, or undefined if the attribute text
 * does not parse cleanly or an attribute repeats.
 */
function parseAttributes(text: string, from: number): Map<string, string> | undefined {
  const attrs = new Map<string, string>();
  let pos = from;
  for (;;) {
    TAG_END.lastIndex = pos;
    if (TAG_END.exec(text)) return attrs;
    ATTR.lastIndex = pos;
    const m = ATTR.exec(text);
    if (!m) return undefined;
    const name = m[1]!;
    if (attrs.has(name)) return undefined;
    attrs.set(name, m[2] ?? m[3] ?? "");
    pos = ATTR.lastIndex;
  }
}

/**
 * Every Relationship element has exactly one unprefixed `Type` attribute whose decoded value is
 * allowlisted (case-sensitive), no prefixed `*:Type` attribute, and no TargetMode other than
 * Internal. `text` must be the undecoded XML, so entities in values cannot change the markup.
 *
 * One linear tokenizer drives both counts: for every `<` not followed by `/`, `!` or `?`, the
 * element name runs to whitespace, `/`, `>` or `<`. If its local name (after the last ':') is
 * `relationship` in any case, it is counted loosely, and it must also be exactly `Relationship`
 * with at most one NCName prefix, and its attributes must validate. The loose and validated counts
 * must match. Each character is visited a bounded number of times, so the scan is linear.
 */
function relationshipsAreSafe(text: string): boolean {
  let loose = 0;
  let validated = 0;
  let i = text.indexOf("<");
  while (i !== -1) {
    const next = text.charCodeAt(i + 1);
    if (next === 0x2f || next === 0x21 || next === 0x3f) {
      i = text.indexOf("<", i + 1);
      continue;
    }
    let j = i + 1;
    while (j < text.length && !endsName(text.charCodeAt(j))) j++;
    const name = text.slice(i + 1, j);
    if (name.slice(name.lastIndexOf(":") + 1).toLowerCase() === "relationship") {
      loose++;
      if (!isRelationshipElementName(name)) return false;
      const attrs = parseAttributes(text, j);
      if (!attrs) return false;
      for (const attr of attrs.keys()) {
        if (attr.includes(":") && attr.slice(attr.lastIndexOf(":") + 1) === "Type") return false;
      }
      const type = attrs.get("Type");
      if (type === undefined || !isSafeRelType(decodeXml(type))) return false;
      const mode = attrs.get("TargetMode");
      if (mode !== undefined && decodeXml(mode) !== "Internal") return false;
      validated++;
    }
    i = text.indexOf("<", Math.max(j, i + 1));
  }
  return loose === validated;
}

// ---------------------------------------------------------------------------------------------
// Every XML part: Word field codes, Excel formulas, PowerPoint actions
// ---------------------------------------------------------------------------------------------

/**
 * Word field types allowed in a field instruction. The type is the leading run of ASCII letters
 * of the instruction (after leading whitespace); a leading `=` is a formula field and is allowed.
 * Every other field type is refused (DDE, DDEAUTO, INCLUDETEXT, INCLUDEPICTURE, INCLUDE, LINK,
 * IMPORT, QUOTE, DATABASE, PRINT, DOCPROPERTY, DOCVARIABLE, SET, ASK, FILLIN, MERGEFIELD, IF,
 * MACROBUTTON, GOTOBUTTON, AUTOTEXT, ...). Nested fields are refused separately.
 */
const ALLOWED_FIELDS = new Set([
  "PAGE", "NUMPAGES", "SECTIONPAGES", "SECTION", "DATE", "TIME", "CREATEDATE", "SAVEDATE", "PRINTDATE",
  "EDITTIME", "AUTHOR", "TITLE", "SUBJECT", "KEYWORDS", "COMMENTS", "FILENAME", "FILESIZE", "NUMWORDS",
  "NUMCHARS", "TOC", "TOA", "TC", "XE", "INDEX", "SEQ", "PAGEREF", "NOTEREF", "STYLEREF", "REF", "BOOKMARK",
  "HYPERLINK", "FORMTEXT", "FORMCHECKBOX", "FORMDROPDOWN", "LISTNUM", "AUTONUM", "AUTONUMLGL", "AUTONUMOUT",
  "SYMBOL", "EQ", "ADVANCE",
]);
/** Backstop: words refused anywhere in an instruction, whatever its leading type. */
const FIELD_BACKSTOP =
  /\b(?:DDE|DDEAUTO|INCLUDETEXT|INCLUDEPICTURE|INCLUDE|LINK|IMPORT|QUOTE|DATABASE|PRINT|MERGEFIELD|MACROBUTTON|AUTOTEXT)\b/i;
/** The only elements allowed while a field instruction is open (plus descendants of w:rPr / w:fldChar). */
const INSTRUCTION_REGION = new Set([
  "w:r", "w:rPr", "w:instrText", "w:fldChar", "w:proofErr", "w:bookmarkStart", "w:bookmarkEnd",
]);
/** Elements refused anywhere: auto-update of fields, mail merge, form-field macros. */
const REFUSED_ELEMENTS = new Set(["updatefields", "mailmerge", "entrymacro", "exitmacro"]);
const WML_URIS = new Set([
  "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
  "http://purl.oclc.org/ooxml/wordprocessingml/main",
]);
const MC_URI = "http://schemas.openxmlformats.org/markup-compatibility/2006";
/** Markup compatibility (mc:AlternateContent, mc:Ignorable) lets a part show Office other content. */
const MC_USE = /AlternateContent|:Ignorable\s*=|markup-compatibility/;
/** Excel functions refused in any formula (outside string literals and quoted names). */
const BAD_FUNCTION = /\b(?:CALL|REGISTER(?:\.ID)?|EXEC|WEBSERVICE|FILTERXML|RTD|IMAGE)\s*\(/i;
/** Characters refused inside a quoted sheet name. */
const BAD_NAME_CHARS = /[()[\]+&"|]/;
/** Slide actions that start programs, OLE verbs or macros. */
const BAD_PPACTION = ["ppaction://program", "ppaction://ole", "ppaction://macro"];
/** Elements whose text is an Excel formula. */
const FORMULA_ELEMENTS = new Set([
  "f", "definedname", "formula", "formula1", "formula2", "calculatedcolumnformula", "totalsrowformula",
]);
/** Elements whose text is (part of) a Word field instruction. */
const INSTR_ELEMENTS = new Set(["instrtext", "delinstrtext"]);
/** Known Word and PowerPoint content types: the only parts exempt from the formula rules. */
const WORD_OR_SLIDES_CONTENT_TYPE = /wordprocessingml|presentationml|ms-word\.|ms-powerpoint/i;
/** Extensions that may sit in the package without a declared content type. */
const IMAGE_EXTENSION = /\.(png|jpe?g|gif|tiff?|bmp|emf|wmf)$/i;
const HTTP_URL = /^https?:\/\//i;

/** Index of the `>` that ends the tag whose attributes start at `from` (quote-aware), or -1. */
function tagEnd(text: string, from: number): number {
  let quote = 0;
  for (let p = from; p < text.length; p++) {
    const c = text.charCodeAt(p);
    if (quote !== 0) {
      if (c === quote) quote = 0;
    } else if (c === 0x22 || c === 0x27) {
      quote = c;
    } else if (c === 0x3e) {
      return p;
    } else if (c === 0x3c) {
      return -1;
    }
  }
  return -1;
}

/** Local name (after the last ':'), lower-cased. */
function localName(name: string): string {
  return name.slice(name.lastIndexOf(":") + 1).toLowerCase();
}

/**
 * Content types declared in [Content_Types].xml: Override by part name and Default by extension
 * (both keys lower-cased; part names with a leading '/').
 */
interface ContentTypeMap {
  overrides: Map<string, string>;
  defaults: Map<string, string>;
}

/**
 * Parse [Content_Types].xml. Undefined (refuse) if a tag does not parse, an Override or Default is
 * missing its attributes, a PartName lacks the leading '/', a PartName contains '%', or a PartName
 * or extension is declared twice (compared case-insensitively).
 */
function contentTypeMap(xml: string): ContentTypeMap | undefined {
  const map: ContentTypeMap = { overrides: new Map(), defaults: new Map() };
  let i = xml.indexOf("<");
  while (i !== -1) {
    const next = xml.charCodeAt(i + 1);
    if (next === 0x2f || next === 0x21 || next === 0x3f) {
      i = xml.indexOf("<", i + 1);
      continue;
    }
    let j = i + 1;
    while (j < xml.length && !endsName(xml.charCodeAt(j))) j++;
    const local = localName(xml.slice(i + 1, j));
    if (local === "override" || local === "default") {
      const attrs = parseAttributes(xml, j);
      if (!attrs) return undefined;
      const ct = attrs.get("ContentType");
      const rawKey = attrs.get(local === "override" ? "PartName" : "Extension");
      if (ct === undefined || rawKey === undefined) return undefined;
      const key = decodeXml(rawKey);
      if (local === "override" && (!key.startsWith("/") || key.includes("%"))) return undefined;
      const target = local === "override" ? map.overrides : map.defaults;
      if (target.has(key.toLowerCase())) return undefined;
      target.set(key.toLowerCase(), decodeXml(ct).trim());
    }
    i = xml.indexOf("<", Math.max(j, i + 1));
  }
  return map;
}

/** The content type Office would give `partName`: its Override, else the Default for its extension. */
function contentTypeOf(map: ContentTypeMap, partName: string): string | undefined {
  const override = map.overrides.get(`/${partName}`.toLowerCase());
  if (override !== undefined) return override;
  const base = partName.slice(partName.lastIndexOf("/") + 1);
  const dot = base.lastIndexOf(".");
  return dot === -1 ? undefined : map.defaults.get(base.slice(dot + 1).toLowerCase());
}

/**
 * Remove XML comments that sit outside the root element (after the declaration and before the
 * root, or after the root), as third-party generators write. They are replaced by spaces of the
 * same length. Comments inside the root are left alone (and refused later).
 */
function stripOuterComments(xml: string): string {
  const space = (c: number) => c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d;
  let p = 0;
  if (/^\s*<\?xml\b/.test(xml)) {
    const decl = xml.indexOf("?>");
    if (decl === -1) return xml;
    p = decl + 2;
  }
  const prologStart = p;
  for (;;) {
    while (p < xml.length && space(xml.charCodeAt(p))) p++;
    if (!xml.startsWith("<!--", p)) break;
    const close = xml.indexOf("-->", p + 4);
    if (close === -1) return xml;
    p = close + 3;
  }
  const rootStart = p;
  // Trailing comments: a comment cannot contain "--", so the last "<!--" before a trailing "-->"
  // starts that comment. Each backward search covers only that comment, so this is linear.
  let end = xml.length;
  for (;;) {
    while (end > rootStart && space(xml.charCodeAt(end - 1))) end--;
    if (end - rootStart < 7 || !xml.endsWith("-->", end)) break;
    const open = xml.lastIndexOf("<!--", end - 3);
    if (open < rootStart) break;
    end = open;
  }
  // Rebuild once: blank the leading and trailing regions, keep everything in between.
  return xml.slice(0, prologStart) + " ".repeat(rootStart - prologStart) + xml.slice(rootStart, end) + " ".repeat(xml.length - end);
}

/** True unless WordprocessingML is bound to a prefix other than `w`, `w` is bound elsewhere, or mc is declared. */
function namespacesAreSafe(xml: string): boolean {
  for (const m of xml.matchAll(/\bxmlns(?::([^\s=/>"']+))?\s*=\s*(?:"([^"]*)"|'([^']*)')/g)) {
    const prefix = m[1] ?? "";
    const uri = decodeXml(m[2] ?? m[3] ?? "").trim();
    if (WML_URIS.has(uri) && prefix !== "w") return false;
    if (prefix === "w" && !WML_URIS.has(uri)) return false;
    if (uri === MC_URI) return false;
  }
  return true;
}

interface FieldToken {
  text: string;
  quoted: boolean;
}

/**
 * Split a field instruction into tokens: double-quoted strings (quotes removed; an unclosed quote
 * takes the rest) or runs of non-space characters.
 */
function fieldTokens(line: string): FieldToken[] {
  const tokens: FieldToken[] = [];
  let p = 0;
  while (p < line.length) {
    while (p < line.length && /\s/.test(line[p]!)) p++;
    if (p >= line.length) break;
    if (line[p] === '"') {
      const close = line.indexOf('"', p + 1);
      const end = close === -1 ? line.length : close;
      tokens.push({ text: line.slice(p + 1, end), quoted: true });
      p = end + 1;
    } else {
      const start = p;
      while (p < line.length && !/\s/.test(line[p]!) && line[p] !== '"') p++;
      tokens.push({ text: line.slice(start, p), quoted: false });
    }
  }
  return tokens;
}

/** Looks like a URI or a path: `scheme:...`, `\\host...` or `//host...`. */
function looksLikeUri(text: string): boolean {
  return /^[A-Za-z][A-Za-z0-9+.-]*:/.test(text) || text.startsWith("\\\\") || text.startsWith("//");
}

const safeLink = (text: string) => HTTP_URL.test(text) || text.startsWith("#");

/**
 * HYPERLINK arguments: every argument that looks like a URI or path (including switch arguments)
 * must be http(s) or an in-document `#` reference. The target (first argument that is not a switch
 * or a switch argument) must be http(s) or `#`; with no target, only an in-document `\l` bookmark
 * link is allowed. Switches \l, \o and \t take an argument.
 */
function hyperlinkFieldIsSafe(args: FieldToken[]): boolean {
  let target: string | undefined;
  let bookmark = false;
  for (let k = 0; k < args.length; k++) {
    const a = args[k]!;
    const isSwitch = !a.quoted && a.text.startsWith("\\");
    if (!isSwitch && looksLikeUri(a.text) && !safeLink(a.text)) return false;
    if (isSwitch) {
      const sw = a.text.toLowerCase();
      if (sw === "\\l") bookmark = true;
      if (sw === "\\l" || sw === "\\o" || sw === "\\t") {
        const arg = args[k + 1];
        if (arg && looksLikeUri(arg.text) && !safeLink(arg.text)) return false;
        k++;
      }
      continue;
    }
    if (target === undefined) target = a.text;
  }
  if (target !== undefined) return safeLink(target);
  return bookmark;
}

/**
 * One complete field instruction (entities decoded). Refused if it contains a FIELD_BACKSTOP word
 * anywhere. Its type is the leading run of ASCII letters after leading whitespace, and must be in
 * ALLOWED_FIELDS; a leading `=` (formula field) is allowed. HYPERLINK must pass
 * hyperlinkFieldIsSafe.
 */
function fieldInstructionIsSafe(instruction: string): boolean {
  if (FIELD_BACKSTOP.test(instruction)) return false;
  const t = instruction.replace(/^\s+/, "");
  if (t.startsWith("=")) return true;
  const m = /^[A-Za-z]+/.exec(t);
  if (!m) return false;
  const type = m[0].toUpperCase();
  if (!ALLOWED_FIELDS.has(type)) return false;
  if (type === "HYPERLINK") return hyperlinkFieldIsSafe(fieldTokens(t.slice(m[0].length)));
  return true;
}

/**
 * An Excel formula (entities already decoded).
 * - String literals ("..." with "" escapes) are set aside; an unterminated literal is refused.
 * - A `'` starts a quoted name only in name position, i.e. when its closing quote ('' escapes) is
 *   followed by `!`. Such a name is refused if it contains ( ) [ ] + & " or |, and is set aside
 *   otherwise. A `'` with no closing quote is refused. Any other `'` is ordinary formula text, so
 *   what follows it stays visible to the checks below.
 * - Outside literals and names, a `|` (DDE) or any BAD_FUNCTION call is refused. HYPERLINK( must
 *   take a string-literal target that is http(s) or an in-workbook `#` reference.
 */
function formulaIsSafe(formula: string): boolean {
  const literals: string[] = [];
  let code = "";
  let p = 0;
  while (p < formula.length) {
    const c = formula[p]!;
    if (c === "'") {
      let q = p + 1;
      let name = "";
      let closed = false;
      while (q < formula.length) {
        if (formula[q] === "'") {
          if (formula[q + 1] === "'") {
            name += "'";
            q += 2;
            continue;
          }
          closed = true;
          break;
        }
        name += formula[q];
        q++;
      }
      if (!closed) return false;
      if (formula[q + 1] === "!") {
        if (BAD_NAME_CHARS.test(name)) return false;
        code += "'q'";
        p = q + 1;
      } else {
        code += c;
        p++;
      }
      continue;
    }
    if (c !== '"') {
      code += c;
      p++;
      continue;
    }
    let body = "";
    p++;
    for (;;) {
      if (p >= formula.length) return false; // unterminated string literal
      if (formula[p] === '"') {
        if (formula[p + 1] === '"') {
          body += '"';
          p += 2;
          continue;
        }
        p++;
        break;
      }
      body += formula[p];
      p++;
    }
    code += `"${literals.length}"`;
    literals.push(body);
  }
  if (code.includes("|") || BAD_FUNCTION.test(code)) return false;
  const literalAt = /\s*"(\d+)"/y;
  for (const m of code.matchAll(/\bHYPERLINK\s*\(/gi)) {
    literalAt.lastIndex = m.index! + m[0].length;
    const lit = literalAt.exec(code);
    if (!lit) return false; // computed target: cannot be checked
    if (!safeLink(literals[Number(lit[1])]!)) return false;
  }
  return true;
}

/**
 * One inflated XML part (other than [Content_Types].xml and .rels), with comments outside the root
 * already stripped. `xml` is undecoded, `decoded` has entities decoded, and `formulas` says whether
 * Excel formula rules apply. Refused if:
 * - it has a comment, CDATA section or DOCTYPE (`<!`) inside the root, or a processing instruction
 *   other than the leading XML declaration;
 * - it uses markup compatibility (mc:AlternateContent, mc:Ignorable, or declares the mc
 *   namespace), binds WordprocessingML to a prefix other than `w`, or binds `w` to anything else;
 * - it has w:updateFields, w:mailMerge, w:entryMacro or w:exitMacro;
 * - any decoded text contains a ppaction://program, ppaction://ole or ppaction://macro action;
 * - Word fields: while an instruction is open, any element other than w:r, w:rPr (and its
 *   descendants), w:instrText, w:fldChar (and its descendants), w:proofErr, w:bookmarkStart or
 *   w:bookmarkEnd appears (so w:t, w:delInstrText and wrappers are refused); an instruction fails
 *   fieldInstructionIsSafe; a field begins, or a fldSimple appears, inside an open instruction;
 *   field characters are out of order or unknown; instruction text appears outside an
 *   instruction; or an instruction element holds anything but text;
 * - with formula rules, any formula element fails formulaIsSafe or holds anything but text.
 * One left-to-right pass over the tags, so time is linear in the part size.
 */
function xmlPartIsSafe(xml: string, decoded: string, formulas: boolean): boolean {
  if (xml.includes("<!")) return false;
  const declEnd = /^\s*<\?xml\b/.test(xml) ? xml.indexOf("?>") : -1;
  if (xml.indexOf("<?", declEnd === -1 ? 0 : declEnd + 2) !== -1) return false;
  if (MC_USE.test(xml) || !namespacesAreSafe(xml)) return false;

  const lower = decoded.toLowerCase();
  if (BAD_PPACTION.some((a) => lower.includes(a))) return false;

  /** Open complex fields; `inInstruction` until their fldChar separate. */
  const fields: { inInstruction: boolean; instruction: string }[] = [];
  const top = () => fields[fields.length - 1];
  /** Depth inside a w:rPr or w:fldChar element, whose descendants are allowed in an instruction. */
  let allowDepth = 0;
  let i = xml.indexOf("<");
  while (i !== -1) {
    if (xml.charCodeAt(i + 1) === 0x2f) {
      if (allowDepth > 0) allowDepth--;
      i = xml.indexOf("<", i + 1);
      continue;
    }
    let j = i + 1;
    while (j < xml.length && !endsName(xml.charCodeAt(j))) j++;
    const qname = xml.slice(i + 1, j);
    const local = localName(qname);
    const end = tagEnd(xml, j);
    if (end === -1) return false;
    const selfClosing = xml.charCodeAt(end - 1) === 0x2f;

    if (REFUSED_ELEMENTS.has(local)) return false;
    if (allowDepth > 0) {
      if (!selfClosing) allowDepth++;
      i = xml.indexOf("<", end + 1);
      continue;
    }
    if (top()?.inInstruction && !INSTRUCTION_REGION.has(qname)) return false;

    if (local === "fldchar") {
      const attrs = parseAttributes(xml, j);
      if (!attrs) return false;
      let kind: string | undefined;
      for (const [attr, value] of attrs) if (localName(attr) === "fldchartype") kind = decodeXml(value);
      if (kind === "begin") {
        if (top()?.inInstruction) return false; // nested field in an instruction
        fields.push({ inInstruction: true, instruction: "" });
      } else if (kind === "separate") {
        const f = top();
        if (!f || !f.inInstruction || !fieldInstructionIsSafe(f.instruction)) return false;
        f.inInstruction = false;
      } else if (kind === "end") {
        const f = fields.pop();
        if (!f || (f.inInstruction && !fieldInstructionIsSafe(f.instruction))) return false;
      } else {
        return false;
      }
    } else if (local === "fldsimple") {
      if (top()?.inInstruction) return false; // fldSimple inside a field instruction
      const attrs = parseAttributes(xml, j);
      if (!attrs) return false;
      let found = false;
      for (const [attr, value] of attrs) {
        if (localName(attr) !== "instr") continue;
        found = true;
        if (!fieldInstructionIsSafe(decodeXml(value))) return false;
      }
      if (!found) return false;
    }

    if (!selfClosing && (qname === "w:rPr" || local === "fldchar")) {
      allowDepth = 1;
      i = xml.indexOf("<", end + 1);
      continue;
    }

    const isInstr = INSTR_ELEMENTS.has(local);
    const isFormula = formulas && FORMULA_ELEMENTS.has(local);
    if (isInstr && !top()?.inInstruction) return false; // instruction text outside an instruction
    if ((isInstr || isFormula) && !selfClosing) {
      // Text only, then this element's own end tag.
      const next = xml.indexOf("<", end + 1);
      if (next === -1 || xml.charCodeAt(next + 1) !== 0x2f) return false;
      let k = next + 2;
      while (k < xml.length && !endsName(xml.charCodeAt(k))) k++;
      if (localName(xml.slice(next + 2, k)) !== local) return false;
      const content = decodeXml(xml.slice(end + 1, next));
      if (isInstr) top()!.instruction += content;
      else if (!formulaIsSafe(content)) return false;
      i = xml.indexOf("<", next + 1);
      continue;
    }
    i = xml.indexOf("<", end + 1);
  }
  return fields.length === 0; // every field closed
}

/**
 * OOXML (.docx/.xlsx/.pptx) that is a plain document. Refused unless all of these hold:
 * - the zip is structurally consistent (see zipEntries) and has a [Content_Types].xml entry; no
 *   entry name contains '%';
 * - no entry is a VBA, OLE or ActiveX binary, sits under activeX/, embeddings/, macrosheets/ or
 *   dialogsheets/, or is a nested .bin, .docm, .xlsm, .pptm, .docx, .xlsx or .pptx;
 * - [Content_Types].xml parses cleanly (see contentTypeMap), every declared content type is
 *   allowlisted, and none mentions macroEnabled, vbaProject, macrosheet or dialogsheet;
 * - every part other than [Content_Types].xml and .rels has a declared content type, or is XML by
 *   name (.xml), an image by extension, or an empty directory entry;
 * - every .rels part and every part that is XML by name or by content type is inflated (each at
 *   most 1 MB, at most 200 parts, 16 MB in total) and is plain UTF-8 XML 1.0;
 * - every relationship type is allowlisted, none mentions vbaProject, attachedTemplate, oleObject,
 *   activeX or externalLink, and none is external;
 * - every other XML part passes xmlPartIsSafe (after comments outside its root are stripped), with
 *   formula rules unless its content type is a known Word or PowerPoint type; parts under xl/ get
 *   formula rules whatever their content type;
 * - as a backstop, the raw archive bytes contain none of RAW_KEYWORDS (case-insensitive).
 */
function isPlainOoxml(data: Buffer): boolean {
  if (!startsWith(data, [0x50, 0x4b, 0x03, 0x04])) return false;
  const entries = zipEntries(data);
  if (!entries || entries.length === 0) return false;
  const typesEntry = entries.find((e) => e.name.toLowerCase() === CONTENT_TYPES_NAME);
  if (!typesEntry) return false;
  if (entries.some((e) => e.name.includes("%"))) return false;
  if (entries.some((e) => ACTIVE_PART.test(e.name) || ACTIVE_DIR.test(e.name) || NESTED.test(e.name) || MACRO_SHEET_DIR.test(e.name))) {
    return false;
  }

  // [Content_Types].xml first: it decides which other parts are XML and which get formula rules.
  const typesBytes = readEntry(data, typesEntry);
  if (!typesBytes) return false;
  const typesXml = xmlText(typesBytes);
  if (typesXml === undefined) return false;
  const typesText = decodeXml(typesXml);
  if (BAD_CONTENT_TYPE.test(typesText) || !contentTypesAreSafe(typesText)) return false;
  if (MC_USE.test(typesXml)) return false;
  const types = contentTypeMap(typesXml);
  if (!types) return false;

  const isRels = (e: ZipEntry) => /\.rels$/i.test(e.name);
  const isXml = (e: ZipEntry) => /\.xml$/i.test(e.name) || /xml$/i.test(contentTypeOf(types, e.name) ?? "");
  for (const e of entries) {
    if (e === typesEntry || isRels(e) || isXml(e)) continue;
    if (e.name.endsWith("/") && e.size === 0) continue; // directory entry
    if (contentTypeOf(types, e.name) === undefined && !IMAGE_EXTENSION.test(e.name)) return false;
  }
  const inspected = entries.filter((e) => e !== typesEntry && (isRels(e) || isXml(e)));
  if (inspected.length + 1 > MAX_INSPECTED_ENTRIES) return false;
  // Declared sizes are verified against the real inflated size in readEntry, so refuse up front
  // when they add up past the cap, and keep a running total as well.
  if (inspected.reduce((sum, e) => sum + e.size, typesEntry.size) > MAX_TOTAL_INFLATED) return false;
  let inflated = typesBytes.length;
  for (const e of inspected) {
    const bytes = readEntry(data, e);
    if (!bytes) return false;
    inflated += bytes.length;
    if (inflated > MAX_TOTAL_INFLATED) return false;
    const xml = xmlText(bytes);
    if (xml === undefined) return false;
    const text = decodeXml(xml);
    if (isRels(e)) {
      if (MC_USE.test(xml)) return false;
      if (BAD_RELATIONSHIP.test(text) || EXTERNAL_TARGET.test(text) || !relationshipsAreSafe(xml)) return false;
    } else {
      const ct = contentTypeOf(types, e.name);
      const formulas = /^xl\//i.test(e.name) || ct === undefined || !WORD_OR_SLIDES_CONTENT_TYPE.test(ct);
      if (!xmlPartIsSafe(stripOuterComments(xml), text, formulas)) return false;
    }
  }

  const raw = data.toString("latin1").toLowerCase();
  return !RAW_KEYWORDS.some((k) => raw.includes(k));
}

/** Text types: valid UTF-8 with no NUL bytes. */
function isUtf8Text(data: Buffer): boolean {
  if (data.includes(0)) return false;
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(data);
    return true;
  } catch {
    return false;
  }
}

/**
 * True when a buffer also carries a zip archive: a local file header signature (PK 03 04) and an
 * end-of-central-directory signature (PK 05 06). Used to refuse PDF/zip polyglots.
 */
function isZipPolyglot(d: Buffer): boolean {
  return d.includes(Buffer.from([0x50, 0x4b, 0x03, 0x04])) && d.includes(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
}

const NAMED_ENTITIES: Readonly<Record<string, string>> = {
  colon: ":", tab: "\t", newline: "\n", amp: "&", lt: "<", gt: ">", quot: '"', apos: "'",
  lpar: "(", rpar: ")", sol: "/", num: "#", grave: "`", dollar: "$", equals: "=", percnt: "%",
  excl: "!", quest: "?", lsqb: "[", rsqb: "]", lbrack: "[", rbrack: "]", nbsp: " ",
};

/** Decode numeric and a few named HTML entities, repeatedly (capped), in linear time. */
function decodeEntities(text: string): string {
  let cur = text;
  for (let round = 0; round < 4; round++) {
    const next = cur.replace(/&(?:#[xX]([0-9a-fA-F]{1,8})|#([0-9]{1,9})|([A-Za-z]{2,10}));?/g, (m, hex?: string, dec?: string, name?: string) => {
      if (name !== undefined) return NAMED_ENTITIES[name.toLowerCase()] ?? m;
      const cp = hex !== undefined ? parseInt(hex, 16) : parseInt(dec as string, 10);
      return cp > 0 && cp <= 0x10ffff && !(cp >= 0xd800 && cp <= 0xdfff) ? String.fromCodePoint(cp) : m;
    });
    if (next === cur) break;
    cur = next;
  }
  return cur;
}

// Code fences (also inside quotes or lists), inline code spans, HTML tags and comments, Templater,
// Dataview inline JS.
const MD_ACTIVE = /`|~~~|<[A-Za-z/!?]|<%|\$=/;
const DEST_PREFIXES: readonly string[] = ["http://", "https://", "mailto:", "#"];

function isSpaceLike(c: number): boolean {
  return (
    c <= 0x20 || (c >= 0x7f && c <= 0xa0) || c === 0x1680 || (c >= 0x2000 && c <= 0x200f) ||
    c === 0x2028 || c === 0x2029 || c === 0x202f || c === 0x205f || c === 0x3000 || c === 0xfeff
  );
}

/** True when the link destination starting at `from` (after any whitespace and one "<") is allowed. */
function destinationAllowed(text: string, from: number): boolean {
  let j = from;
  while (j < text.length && isSpaceLike(text.charCodeAt(j))) j++;
  if (text.charCodeAt(j) === 0x3c) j++;
  const head = text.slice(j, j + 8).toLowerCase();
  return DEST_PREFIXES.some((p) => head.startsWith(p));
}

/** Fail closed: every "](" and every "]:" must be followed by an http(s), mailto or "#" destination. */
function linkDestinationsAllowed(text: string): boolean {
  for (const opener of ["](", "]:"]) {
    for (let i = text.indexOf(opener); i !== -1; i = text.indexOf(opener, i + 1)) {
      if (!destinationAllowed(text, i + 2)) return false;
    }
  }
  return true;
}

/**
 * Strict Markdown (only reached when allowMarkdown is true): no code fences, code spans, HTML,
 * Templater tags or `$=`, and every link destination starts with http://, https://, mailto: or #.
 * Entities are decoded first. Linear time.
 */
function isSafeMarkdown(data: Buffer): boolean {
  if (!isUtf8Text(data)) return false;
  const text = decodeEntities(data.toString("utf8"));
  return !MD_ACTIVE.test(text) && linkDestinationsAllowed(text);
}

const CSV_NUMBER = /^-(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$/;
const CSV_NUMBER_MAX = 64;

/**
 * CSV: valid UTF-8 text in which no field, after leading spaces and an opening quote, starts with
 * a spreadsheet formula trigger: = + @ TAB CR. A field starting with "-" must be, as a whole, a
 * plain number (CSV_NUMBER); a bare "-" is refused. A single linear pass; handles quoted fields,
 * "" escapes, commas and line breaks in quotes, CRLF and LF.
 */
function isSafeCsv(data: Buffer): boolean {
  if (!isUtf8Text(data)) return false;
  const s = data.toString("utf8");
  const n = s.length;
  // 0 = at field start (value not begun), 1 = unquoted, 2 = quoted, 3 = after closing quote
  let state = 0;
  let began = false; // quoted value has its first significant character
  let buf: string | undefined; // value of a "-" field so far (bounded)
  const add = (ch: string): boolean => {
    if (buf === undefined) return true;
    buf += ch;
    return buf.length <= CSV_NUMBER_MAX;
  };
  const finish = (): boolean => {
    const b = buf;
    buf = undefined;
    return b === undefined || CSV_NUMBER.test(b);
  };
  const first = (c: number): boolean => {
    if (c === 0x3d || c === 0x2b || c === 0x40 || c === 0x09 || c === 0x0d) return false;
    if (c === 0x2d) buf = "-";
    return true;
  };
  for (let i = 0; i < n; i++) {
    const c = s.charCodeAt(i);
    if (state === 2) {
      if (c === 0x22) {
        if (s.charCodeAt(i + 1) === 0x22) {
          i++; // escaped quote is a value character
          if (!began) {
            began = true;
            first(c);
          } else if (!add('"')) return false;
        } else {
          state = 3;
          if (!finish()) return false;
        }
        continue;
      }
      if (!began) {
        if (c === 0x20) continue; // leading spaces inside the quotes are skipped
        began = true;
        if (!first(c)) return false;
      } else if (!add(s[i]!)) return false;
      continue;
    }
    // Record and field separators outside quotes.
    if (c === 0x2c || c === 0x0a || (c === 0x0d && (state !== 0 || s.charCodeAt(i + 1) === 0x0a))) {
      if (!finish()) return false;
      state = 0;
      began = false;
      continue;
    }
    if (state === 3) continue;
    if (state === 1) {
      if (!add(s[i]!)) return false;
      continue;
    }
    // state 0
    if (c === 0x20) continue;
    if (c === 0x22) {
      state = 2;
      began = false;
      continue;
    }
    state = 1;
    if (!first(c)) return false;
  }
  return finish();
}

const CHECKS: ReadonlyMap<string, (data: Buffer) => boolean> = new Map(Object.entries({
  ".pdf": (d) => ascii(d, 0, 5) === "%PDF-" && !isZipPolyglot(d),
  ".png": (d) => startsWith(d, [0x89, 0x50, 0x4e, 0x47]),
  ".jpg": (d) => startsWith(d, [0xff, 0xd8, 0xff]),
  ".jpeg": (d) => startsWith(d, [0xff, 0xd8, 0xff]),
  ".gif": (d) => ascii(d, 0, 6) === "GIF87a" || ascii(d, 0, 6) === "GIF89a",
  ".heic": (d) => ascii(d, 4, 8) === "ftyp" && HEIC_BRANDS.has(ascii(d, 8, 12)),
  ".docx": isPlainOoxml,
  ".xlsx": isPlainOoxml,
  ".pptx": isPlainOoxml,
  ".txt": isUtf8Text,
  ".csv": isSafeCsv,
  ".md": isSafeMarkdown,
}));

/** Extensions that have a content check. Every saveable extension must be in here. */
export const CHECKED_EXTENSIONS: readonly string[] = [...CHECKS.keys()];

/** True when `data` looks like the type `ext` (lowercase, with dot) claims. Unknown ext: false. */
export function contentMatches(ext: string, data: Buffer): boolean {
  const check = CHECKS.get(ext);
  return check !== undefined && check(data);
}
