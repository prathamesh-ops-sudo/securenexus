import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  getCspmFindings: vi.fn(),
  getCspmScans: vi.fn(),
  getEndpointAssets: vi.fn(),
  getIncidents: vi.fn(),
  getCompliancePolicy: vi.fn(),
  createPostureScore: vi.fn(),
  dbSelect: vi.fn(),
}));

vi.mock("../storage", () => ({
  storage: {
    getCspmFindings: mocks.getCspmFindings,
    getCspmScans: mocks.getCspmScans,
    getEndpointAssets: mocks.getEndpointAssets,
    getIncidents: mocks.getIncidents,
    getCompliancePolicy: mocks.getCompliancePolicy,
    createPostureScore: mocks.createPostureScore,
  },
}));

vi.mock("../db", () => ({
  db: {
    select: mocks.dbSelect,
  },
}));

describe("evidence-backed posture scoring", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.getCspmFindings.mockResolvedValue([]);
    mocks.getCspmScans.mockResolvedValue([]);
    mocks.getEndpointAssets.mockResolvedValue([]);
    mocks.getIncidents.mockResolvedValue([]);
    mocks.getCompliancePolicy.mockResolvedValue(undefined);
    mocks.createPostureScore.mockImplementation(async (value) => value);
    mocks.dbSelect.mockReturnValue({
      from: () => ({
        where: async () => [],
      }),
    });
  });

  it("returns unavailable without persistence when posture-trust has no evidence", async () => {
    const { generateDomainScores } = await import("../posture-engine-v2");

    const result = await generateDomainScores("fresh-org");

    expect(result.status).toBe("unavailable");
    expect(result.overallScore).toBeNull();
    expect(result.measuredDomains).toEqual([]);
  });

  it("returns unavailable without persisting a favorable original posture score", async () => {
    const { calculatePostureScore } = await import("../posture-engine");

    const result = await calculatePostureScore("fresh-org");

    expect(result.status).toBe("unavailable");
    expect(result.overallScore).toBeNull();
    expect(mocks.createPostureScore).not.toHaveBeenCalled();
  });
});
