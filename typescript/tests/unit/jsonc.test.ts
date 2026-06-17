import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { parseJsonc, stripJsonc } from "../../src/jsonc.js";

interface Vector {
  name: string;
  description: string;
  input: string;
  expected: unknown;
}

const vectorsPath = fileURLToPath(
  new URL("../../../test-vectors/jsonc.json", import.meta.url),
);
const vectors: Vector[] = JSON.parse(readFileSync(vectorsPath, "utf8")).vectors;

describe("parseJsonc (shared test vectors)", () => {
  for (const vec of vectors) {
    it(vec.name, () => {
      expect(parseJsonc(vec.input)).toEqual(vec.expected);
    });
  }
});

describe("stripJsonc", () => {
  for (const vec of vectors) {
    it(`${vec.name} → valid JSON`, () => {
      expect(JSON.parse(stripJsonc(vec.input))).toEqual(vec.expected);
    });
  }

  it("passes plain JSON through unchanged", () => {
    expect(parseJsonc('{"a": 1}')).toEqual({ a: 1 });
  });
});
