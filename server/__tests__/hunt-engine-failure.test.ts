import { describe, expect, it, vi } from "vitest";

describe("hunt execution failure state", () => {
  it("reports internal execution errors as failed, not completed with zero events", async () => {
    vi.resetModules();
    vi.doMock("../db", () => ({
      db: {
        transaction: vi.fn().mockRejectedValue(new Error("database unavailable")),
      },
    }));

    const { executeHunt } = await import("../hunt-engine");
    const result = await executeHunt("kql", 'alerts | where severity == "critical"', "org-1");

    expect(result.status).toBe("failed");
    expect(result.eventCount).toBe(0);
    expect(result.reason).toContain("database unavailable");
    vi.doUnmock("../db");
  });
});
