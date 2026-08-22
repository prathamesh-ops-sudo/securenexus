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
  createDetectionRuleVersion,
  createSensorPolicy,
  getDetectionRuleVersions,
  getSensorPolicies,
} from "../storage/sensors";

describe("native sensor workflow storage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("reads sensor policies through the organization predicate", async () => {
    const policies = [{ id: "policy-1", orgId: "org-a" }];
    const where = vi.fn().mockReturnValue({ orderBy: vi.fn().mockResolvedValue(policies) });
    mocks.select.mockReturnValue({ from: vi.fn().mockReturnValue({ where }) });

    await expect(getSensorPolicies("org-a")).resolves.toEqual(policies);
    expect(where).toHaveBeenCalledTimes(1);
  });

  it("writes sensor policies with the caller organization", async () => {
    const policy = { id: "policy-1", orgId: "org-a" };
    const values = vi.fn().mockReturnValue({ returning: vi.fn().mockResolvedValue([policy]) });
    mocks.insert.mockReturnValue({ values });

    await expect(createSensorPolicy({ orgId: "org-a", name: "Endpoint baseline" })).resolves.toEqual(policy);
    expect(values).toHaveBeenCalledWith(expect.objectContaining({ orgId: "org-a" }));
  });

  it("reads rule versions through both rule and organization predicates", async () => {
    const versions = [{ id: "version-1", ruleId: "rule-1", orgId: "org-a", version: 1 }];
    const where = vi.fn().mockReturnValue({ orderBy: vi.fn().mockResolvedValue(versions) });
    mocks.select.mockReturnValue({ from: vi.fn().mockReturnValue({ where }) });

    await expect(getDetectionRuleVersions("rule-1", "org-a")).resolves.toEqual(versions);
    expect(where).toHaveBeenCalledTimes(1);
  });

  it("writes rule versions with the caller organization", async () => {
    const version = { id: "version-1", ruleId: "rule-1", orgId: "org-a", version: 1 };
    const values = vi.fn().mockReturnValue({ returning: vi.fn().mockResolvedValue([version]) });
    mocks.insert.mockReturnValue({ values });

    await expect(
      createDetectionRuleVersion({
        orgId: "org-a",
        ruleId: "rule-1",
        version: 1,
        snapshot: { status: "enabled" },
      }),
    ).resolves.toEqual(version);
    expect(values).toHaveBeenCalledWith(expect.objectContaining({ orgId: "org-a", ruleId: "rule-1" }));
  });
});
