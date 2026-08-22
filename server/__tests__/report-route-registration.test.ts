import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("report schedule route registration", () => {
  it("keeps schedule endpoints in the scheduling router only", () => {
    const reportsSource = readFileSync(new URL("../routes/reports.ts", import.meta.url), "utf8");
    const schedulingSource = readFileSync(new URL("../routes/report-scheduling.ts", import.meta.url), "utf8");

    expect(reportsSource).not.toContain('"/api/report-schedules');
    expect((schedulingSource.match(/"\/api\/report-schedules/g) || []).length).toBeGreaterThan(0);
  });
});
