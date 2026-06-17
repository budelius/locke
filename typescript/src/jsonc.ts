/**
 * JSONC parsing — JSON with comments and trailing commas.
 *
 * Supports line comments, block comments, and trailing commas before `}`/`]`.
 * Comment markers and commas inside string literals are preserved verbatim (a
 * naive regex would corrupt values like `"mongodb://host"` or a string that
 * itself contains comment-like characters).
 *
 * Every JSON config file Locke reads (plaintext inputs and the checked-in
 * encrypted files) is parsed through here, so authors may annotate them with
 * comments. Encrypted payloads are always written as plain JSON; decrypted
 * plaintext is parsed strictly since it is machine-generated, never authored.
 */

/** Parse JSONC text (comments + trailing commas) into a value. */
export function parseJsonc(text: string): unknown {
  return JSON.parse(stripJsonc(text));
}

/**
 * Return `text` with comments and trailing commas removed. The result is
 * valid JSON parseable by `JSON.parse`.
 */
export function stripJsonc(text: string): string {
  return stripTrailingCommas(stripComments(text));
}

function stripComments(text: string): string {
  const n = text.length;
  let out = "";
  let i = 0;
  let inString = false;
  while (i < n) {
    const ch = text[i];
    if (inString) {
      out += ch;
      if (ch === "\\" && i + 1 < n) {
        out += text[i + 1];
        i += 2;
        continue;
      }
      if (ch === '"') inString = false;
      i += 1;
      continue;
    }
    if (ch === '"') {
      inString = true;
      out += ch;
      i += 1;
      continue;
    }
    if (ch === "/" && i + 1 < n && text[i + 1] === "/") {
      i += 2;
      while (i < n && text[i] !== "\n" && text[i] !== "\r") i += 1;
      continue;
    }
    if (ch === "/" && i + 1 < n && text[i + 1] === "*") {
      i += 2;
      while (i + 1 < n && !(text[i] === "*" && text[i + 1] === "/")) i += 1;
      i += 2; // consume the closing */
      continue;
    }
    out += ch;
    i += 1;
  }
  return out;
}

function stripTrailingCommas(text: string): string {
  const n = text.length;
  let out = "";
  let i = 0;
  let inString = false;
  while (i < n) {
    const ch = text[i];
    if (inString) {
      out += ch;
      if (ch === "\\" && i + 1 < n) {
        out += text[i + 1];
        i += 2;
        continue;
      }
      if (ch === '"') inString = false;
      i += 1;
      continue;
    }
    if (ch === '"') {
      inString = true;
      out += ch;
      i += 1;
      continue;
    }
    if (ch === ",") {
      let j = i + 1;
      while (j < n && (text[j] === " " || text[j] === "\t" || text[j] === "\r" || text[j] === "\n")) {
        j += 1;
      }
      if (j < n && (text[j] === "}" || text[j] === "]")) {
        i += 1; // drop the trailing comma
        continue;
      }
    }
    out += ch;
    i += 1;
  }
  return out;
}
