/**
 * Minimal RFC-4180 CSV parser.
 *
 * Hand-written to avoid a runtime dependency. Handles quoted fields,
 * embedded commas/newlines inside quotes, and escaped double quotes (`""`).
 * The first row is treated as the header; each subsequent row is returned as
 * an object keyed by the header columns (mirrors Python's `csv.DictReader`).
 */

/** Parse CSV *text* into an array of rows of string cells. */
export function parseCsvRows(text: string): string[][] {
  const rows: string[][] = [];
  let field = "";
  let row: string[] = [];
  let inQuotes = false;
  let i = 0;
  const n = text.length;

  while (i < n) {
    const ch = text[i];

    if (inQuotes) {
      if (ch === '"') {
        if (i + 1 < n && text[i + 1] === '"') {
          field += '"';
          i += 2;
          continue;
        }
        inQuotes = false;
        i += 1;
        continue;
      }
      field += ch;
      i += 1;
      continue;
    }

    if (ch === '"') {
      inQuotes = true;
      i += 1;
      continue;
    }
    if (ch === ",") {
      row.push(field);
      field = "";
      i += 1;
      continue;
    }
    if (ch === "\r") {
      // Treat CRLF (and bare CR) as a single record separator.
      if (i + 1 < n && text[i + 1] === "\n") i += 1;
      row.push(field);
      rows.push(row);
      field = "";
      row = [];
      i += 1;
      continue;
    }
    if (ch === "\n") {
      row.push(field);
      rows.push(row);
      field = "";
      row = [];
      i += 1;
      continue;
    }
    field += ch;
    i += 1;
  }

  // Flush the final field/row unless the input ended on a record separator
  // (i.e. nothing pending). A trailing newline must not produce an empty row.
  if (field.length > 0 || row.length > 0) {
    row.push(field);
    rows.push(row);
  }

  return rows;
}

/**
 * Parse CSV *text* into an array of record objects keyed by the header row.
 *
 * Mirrors Python's `csv.DictReader`: the first non-empty row is the header.
 * Returns an empty array when there is no data beyond the header.
 */
export function parseCsvDict(text: string): Record<string, string>[] {
  const rows = parseCsvRows(text).filter(
    (r) => !(r.length === 1 && r[0] === ""),
  );
  if (rows.length === 0) return [];

  const header = rows[0];
  const out: Record<string, string>[] = [];
  for (let r = 1; r < rows.length; r++) {
    const cells = rows[r];
    const rec: Record<string, string> = {};
    for (let c = 0; c < header.length; c++) {
      rec[header[c]] = cells[c] ?? "";
    }
    out.push(rec);
  }
  return out;
}
