import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  select: vi.fn(),
  insert: vi.fn(),
}));

vi.mock("../db", () => ({
  db: {
    select: mocks.select,
    insert: mocks.insert,
  },
}));

import {
  createVulnScanSchedule,
  createVulnScanTarget,
  getVulnScanSchedules,
  getVulnScanTargets,
} from "../storage/vuln-scanner-config";

describe("vulnerability scanner configuration storage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("reads targets through the organization-scoped query", async () => {
    const targets = [{ id: "target-1", orgId: "org-a" }];
    const where = vi.fn().mockReturnValue({ orderBy: vi.fn().mockResolvedValue(targets) });
    mocks.select.mockReturnValue({ from: vi.fn().mockReturnValue({ where }) });

    await expect(getVulnScanTargets("org-a")).resolves.toEqual(targets);
    expect(where).toHaveBeenCalledTimes(1);
  });

  it("writes targets and schedules with caller-provided organization ids", async () => {
    const target = { id: "target-1", orgId: "org-a" };
    const schedule = { id: "schedule-1", orgId: "org-a" };
    mocks.insert
      .mockReturnValueOnce({ values: vi.fn().mockReturnValue({ returning: vi.fn().mockResolvedValue([target]) }) })
      .mockReturnValueOnce({ values: vi.fn().mockReturnValue({ returning: vi.fn().mockResolvedValue([schedule]) }) });

    await expect(
      createVulnScanTarget({ orgId: "org-a", name: "Target", type: "hostname", value: "host" }),
    ).resolves.toEqual(target);
    await expect(
      createVulnScanSchedule({ orgId: "org-a", name: "Weekly", frequency: "weekly", scanType: "full" }),
    ).resolves.toEqual(schedule);

    expect(mocks.insert.mock.calls[0][0]).toBeDefined();
    expect(mocks.insert.mock.calls[1][0]).toBeDefined();
  });

  it("reads schedules through the organization-scoped query", async () => {
    const schedules = [{ id: "schedule-1", orgId: "org-a" }];
    const where = vi.fn().mockReturnValue({ orderBy: vi.fn().mockResolvedValue(schedules) });
    mocks.select.mockReturnValue({ from: vi.fn().mockReturnValue({ where }) });

    await expect(getVulnScanSchedules("org-a")).resolves.toEqual(schedules);
    expect(where).toHaveBeenCalledTimes(1);
  });
});
