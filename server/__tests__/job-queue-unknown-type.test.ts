import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  execute: vi.fn(),
}));

vi.mock("../db", () => ({
  db: { execute: mocks.execute },
  pool: { query: vi.fn() },
}));
vi.mock("../storage", () => ({ storage: {} }));

import { processJob } from "../job-queue";

describe("unknown job types", () => {
  beforeEach(() => {
    mocks.execute.mockReset();
    mocks.execute.mockResolvedValue({ rowCount: 1 });
  });

  it("returns an unknown type through retry handling", async () => {
    await processJob({
      id: "job-1",
      type: "unknown_type",
      attempts: 1,
      maxAttempts: 3,
    });

    expect(mocks.execute).toHaveBeenCalledTimes(1);
    const queryChunks = mocks.execute.mock.calls[0][0].queryChunks;
    const queryText = queryChunks
      .map((chunk: unknown) =>
        typeof chunk === "string" ? chunk : (chunk as { value?: string[] }).value?.join("") || "",
      )
      .join("");
    expect(queryText).toContain("SET status = 'pending'");
    expect(queryChunks).toContain("Unknown job type: unknown_type");
  });

  it("dead-letters an unknown type only on the final attempt", async () => {
    await processJob({
      id: "job-2",
      type: "unknown_type",
      attempts: 3,
      maxAttempts: 3,
    });

    const queryChunks = mocks.execute.mock.calls[0][0].queryChunks;
    const queryText = queryChunks
      .map((chunk: unknown) =>
        typeof chunk === "string" ? chunk : (chunk as { value?: string[] }).value?.join("") || "",
      )
      .join("");
    expect(queryText).toContain("SET status = 'failed'");
    expect(queryChunks).toContain("Unknown job type: unknown_type");
  });
});
