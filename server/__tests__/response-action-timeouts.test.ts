import { beforeEach, describe, expect, it, vi } from "vitest";

const { execute } = vi.hoisted(() => ({ execute: vi.fn() }));

vi.mock("../db", () => ({
  db: { execute },
}));

vi.mock("../logger", () => ({
  logger: {
    child: () => ({
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    }),
  },
}));

vi.mock("../scaling-state", () => ({
  registerShutdownHandler: vi.fn(),
}));

import { expireTimedOutResponseActions } from "../response-action-timeouts";

describe("response action timeout lifecycle", () => {
  beforeEach(() => {
    execute.mockReset();
  });

  it("expires approved and executing actions through a timed_out terminal update", async () => {
    execute.mockResolvedValue({
      rows: [
        {
          id: "approved-action",
          org_id: "org-1",
          status: "timed_out",
          result_error: "Timed out waiting for sensor pickup after 30 seconds",
        },
        {
          id: "executing-action",
          org_id: "org-1",
          status: "timed_out",
          result_error: "Timed out waiting for sensor result after 30 seconds",
        },
      ],
    });

    const result = await expireTimedOutResponseActions("org-1");
    expect(result).toHaveLength(2);
    expect(result[0]).toMatchObject({ id: "approved-action", orgId: "org-1", status: "timed_out" });
    expect(execute).toHaveBeenCalledOnce();
  });
});
