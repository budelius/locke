import { describe, expect, it } from "vitest";

import { asGlabToken } from "../../src/pipeline.js";

describe("asGlabToken", () => {
  it("refuses glab help text and messages", () => {
    const help =
      "\n  Manages authentication for glab against one or more GitLab instances.\n  USAGE\n";
    expect(asGlabToken(help)).toBeNull();
    expect(asGlabToken("! No token found (checked config file).\n")).toBeNull();
    expect(asGlabToken("  \n")).toBeNull();
  });

  it("accepts a single token line", () => {
    expect(asGlabToken("glpat-abc_DEF-123\n")).toBe("glpat-abc_DEF-123");
  });
});
