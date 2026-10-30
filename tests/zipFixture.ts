import { deflateRawSync } from "node:zlib";

export type ZipEntry =
  | string
  | {
      name: string;
      data: string | Buffer;
      deflate?: boolean;
      /** Set general-purpose bit 3 and write a data descriptor (sizes 0 in the local header). */
      descriptor?: boolean;
      /** Name written in the central directory instead of `name`. */
      centralName?: string;
      /** Write the local entry but leave it out of the central directory. */
      hidden?: boolean;
    };

/**
 * Minimal zip writer for tests: local headers, central directory, end record. Entries are stored,
 * or raw-deflated when `deflate` is set. CRCs are not computed (the code under test ignores them).
 */
export function zip(entries: ZipEntry[]): Buffer {
  const locals: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;
  for (const e of entries) {
    const spec = typeof e === "string" ? { name: e, data: "x" as string | Buffer, deflate: false, descriptor: false, centralName: undefined, hidden: false } : e;
    const name = Buffer.from(spec.name, "utf8");
    const raw = Buffer.isBuffer(spec.data) ? spec.data : Buffer.from(spec.data, "utf8");
    const body = spec.deflate ? deflateRawSync(raw) : raw;
    const method = spec.deflate ? 8 : 0;
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(spec.descriptor ? 8 : 0, 6);
    lh.writeUInt16LE(method, 8);
    lh.writeUInt32LE(spec.descriptor ? 0 : body.length, 18);
    lh.writeUInt32LE(spec.descriptor ? 0 : raw.length, 22);
    lh.writeUInt16LE(name.length, 26);
    const dd = Buffer.alloc(spec.descriptor ? 16 : 0);
    if (spec.descriptor) {
      dd.writeUInt32LE(0x08074b50, 0);
      dd.writeUInt32LE(body.length, 8);
      dd.writeUInt32LE(raw.length, 12);
    }
    const cname = Buffer.from(spec.centralName ?? spec.name, "utf8");
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE(spec.descriptor ? 8 : 0, 8);
    ch.writeUInt16LE(method, 10);
    ch.writeUInt32LE(body.length, 20);
    ch.writeUInt32LE(raw.length, 24);
    ch.writeUInt16LE(cname.length, 28);
    ch.writeUInt32LE(offset, 42);
    locals.push(lh, name, body, dd);
    if (!spec.hidden) central.push(ch, cname);
    offset += lh.length + name.length + body.length + dd.length;
  }
  const cd = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  const listed = central.length / 2;
  end.writeUInt16LE(listed, 8);
  end.writeUInt16LE(listed, 10);
  end.writeUInt32LE(cd.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, end]);
}

export const CONTENT_TYPES =
  '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">' +
  '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>' +
  '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>';

export const rels = (...r: string[]) =>
  '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
  r.join("") +
  "</Relationships>";

export const REL_DOC =
  '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>';

/** A realistic macro-free docx: deflated content types and rels. */
export function goodDocx(extra: ZipEntry[] = []): Buffer {
  return zip([
    { name: "[Content_Types].xml", data: CONTENT_TYPES, deflate: true },
    { name: "_rels/.rels", data: rels(REL_DOC), deflate: true },
    { name: "word/document.xml", data: "<w:document/>", deflate: true },
    { name: "word/_rels/document.xml.rels", data: rels(), deflate: true },
    ...extra,
  ]);
}
