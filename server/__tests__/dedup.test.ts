/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock data
const mockAlertBase = {
  id: "alert-1",
  orgId: "org-1",
  source: "crowdstrike",
  sourceEventId: "evt-123",
  category: "malware",
  severity: "high",
  title: "Malware detected",
  description: "Test alert",
  rawData: null,
  normalizedData: null,
  ocsfData: null,
  sourceIp: null,
  destIp: null,
  sourcePort: null,
  destPort: null,
  protocol: null,
  userId: null,
  hostname: null,
  fileHash: null,
  url: null,
  domain: null,
  mitreTactic: null,
  mitreTechnique: null,
  status: "new",
  incidentId: null,
  correlationScore: null,
  correlationReason: null,
  correlationClusterId: null,
  suppressed: false,
  suppressedBy: null,
  suppressionRuleId: null,
  confidenceScore: null,
  confidenceSource: null,
  confidenceNotes: null,
  dedupClusterId: null,
  occurrenceCount: 1,
  analystNotes: null,
  assignedTo: null,
  detectedAt: null,
  ingestedAt: new Date(),
  lastSeenAt: null,
  createdAt: new Date(),
};

let findAlertByDedupResult: any = undefined;
let createAlertResult: any = mockAlertBase;
let updateResult: any = { ...mockAlertBase, occurrenceCount: 2, status: "deduped", lastSeenAt: new Date() };

// Track calls
const updateSetMock = vi.fn().mockReturnThis();
const updateWhereMock = vi.fn().mockReturnThis();
const updateReturningMock = vi.fn().mockImplementation(() => [updateResult]);

vi.mock("../db", () => ({
  db: {
    select: vi.fn().mockReturnThis(),
    from: vi.fn().mockReturnThis(),
    where: vi.fn().mockImplementation(() => {
      if (findAlertByDedupResult) return [findAlertByDedupResult];
      return [];
    }),
    insert: vi.fn().mockReturnThis(),
    values: vi.fn().mockReturnThis(),
    returning: vi.fn().mockImplementation(() => [createAlertResult]),
    update: vi.fn().mockReturnValue({
      set: updateSetMock.mockReturnValue({
        where: updateWhereMock.mockReturnValue({
          returning: updateReturningMock,
        }),
      }),
    }),
  },
}));

vi.mock("../logger", () => ({
  logger: {
    child: () => ({
      debug: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    }),
  },
}));

// Import after mocks
const { upsertAlert, findAlertByDedup } = await import("../storage/alerts");

describe("Temporal Alert Deduplication", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    findAlertByDedupResult = undefined;
    createAlertResult = { ...mockAlertBase };
    updateResult = { ...mockAlertBase, occurrenceCount: 2, status: "deduped", lastSeenAt: new Date() };
  });

  it("returns isDuplicate=true and increments occurrenceCount for same alert within 60min window", async () => {
    // Existing alert ingested 10 minutes ago (within window)
    findAlertByDedupResult = {
      ...mockAlertBase,
      ingestedAt: new Date(Date.now() - 10 * 60 * 1000),
      occurrenceCount: 1,
    };

    const result = await upsertAlert({
      orgId: "org-1",
      source: "crowdstrike",
      sourceEventId: "evt-123",
      severity: "high",
      title: "Malware detected",
    } as any);

    expect(result.isDuplicate).toBe(true);
    expect(result.isNew).toBe(false);
    expect(result.alert.occurrenceCount).toBe(2);
    expect(result.alert.status).toBe("deduped");
  });

  it("creates new record for same key but outside dedup window", async () => {
    // Existing alert ingested 2 hours ago (outside 60min window)
    findAlertByDedupResult = {
      ...mockAlertBase,
      ingestedAt: new Date(Date.now() - 120 * 60 * 1000),
      occurrenceCount: 1,
    };

    const result = await upsertAlert({
      orgId: "org-1",
      source: "crowdstrike",
      sourceEventId: "evt-123",
      severity: "high",
      title: "Malware detected",
    } as any);

    expect(result.isNew).toBe(true);
    expect(result.isDuplicate).toBe(false);
  });

  it("always creates new record when sourceEventId is null", async () => {
    const result = await upsertAlert({
      orgId: "org-1",
      source: "crowdstrike",
      sourceEventId: null,
      severity: "high",
      title: "Malware detected",
    } as any);

    expect(result.isNew).toBe(true);
    expect(result.isDuplicate).toBe(false);
  });

  it("creates new record for different sourceEventId", async () => {
    // findAlertByDedup returns undefined for different sourceEventId
    findAlertByDedupResult = undefined;

    const result = await upsertAlert({
      orgId: "org-1",
      source: "crowdstrike",
      sourceEventId: "evt-999",
      severity: "high",
      title: "Different alert",
    } as any);

    expect(result.isNew).toBe(true);
    expect(result.isDuplicate).toBe(false);
  });

  it("occurrenceCount starts at 1 for new alerts and increments on dedup", async () => {
    // First: new alert
    findAlertByDedupResult = undefined;
    createAlertResult = { ...mockAlertBase, occurrenceCount: 1 };

    const newResult = await upsertAlert({
      orgId: "org-1",
      source: "crowdstrike",
      sourceEventId: "evt-new",
      severity: "high",
      title: "New alert",
    } as any);

    expect(newResult.isNew).toBe(true);
    expect(newResult.alert.occurrenceCount).toBe(1);

    // Second: dedup hit
    findAlertByDedupResult = {
      ...mockAlertBase,
      ingestedAt: new Date(Date.now() - 5 * 60 * 1000),
      occurrenceCount: 3,
    };
    updateResult = { ...mockAlertBase, occurrenceCount: 4, status: "deduped", lastSeenAt: new Date() };

    const dedupResult = await upsertAlert({
      orgId: "org-1",
      source: "crowdstrike",
      sourceEventId: "evt-123",
      severity: "high",
      title: "Malware detected",
    } as any);

    expect(dedupResult.isDuplicate).toBe(true);
    expect(dedupResult.alert.occurrenceCount).toBe(4);
  });

  it("respects custom dedupWindowMinutes parameter", async () => {
    // Alert ingested 20 minutes ago, with a 10-minute window => outside window
    findAlertByDedupResult = {
      ...mockAlertBase,
      ingestedAt: new Date(Date.now() - 20 * 60 * 1000),
      occurrenceCount: 1,
    };

    const result = await upsertAlert(
      {
        orgId: "org-1",
        source: "crowdstrike",
        sourceEventId: "evt-123",
        severity: "high",
        title: "Malware detected",
      } as any,
      10, // 10-minute window
    );

    expect(result.isNew).toBe(true);
    expect(result.isDuplicate).toBe(false);
  });
});
