import { readFileSync, readdirSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

const SERVER_ROOT = join(process.cwd(), "server");
const DDL_PATTERN =
  /\b(?:CREATE\s+(?:TABLE|INDEX|SEQUENCE|EXTENSION)\s+(?:IF\s+NOT\s+EXISTS\s+)?["`]?[\w.]+["`]?(\s*\(|\s+ON\b)|ALTER\s+TABLE\s+["`]?\w+["`]?\s+(?:ADD|ALTER|DROP|RENAME)\b)/i;
// Tenant isolation provisions per-tenant schemas at runtime by design.
const EXEMPT_FILES = new Set(["tenant-isolation.ts"]);

function collectTypeScriptFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const filePath = join(directory, entry.name);
    if (entry.isDirectory()) return collectTypeScriptFiles(filePath);
    return entry.isFile() && entry.name.endsWith(".ts") && !entry.name.endsWith(".test.ts") ? [filePath] : [];
  });
}

describe("runtime schema authority", () => {
  it("keeps schema DDL in migrations, except tenant schema provisioning", () => {
    const violations = collectTypeScriptFiles(SERVER_ROOT)
      .filter((filePath) => !EXEMPT_FILES.has(relative(SERVER_ROOT, filePath)))
      .flatMap((filePath) => {
        const source = readFileSync(filePath, "utf8");
        return DDL_PATTERN.test(source) ? [relative(process.cwd(), filePath)] : [];
      });

    expect(violations).toEqual([]);
  });
});
