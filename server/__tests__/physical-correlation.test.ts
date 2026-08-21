/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("../db", () => ({
  db: {
    select: vi.fn().mockReturnThis(),
    from: vi.fn().mockReturnThis(),
    where: vi.fn().mockReturnThis(),
    orderBy: vi.fn().mockReturnThis(),
    limit: vi.fn().mockResolvedValue([]),
    insert: vi.fn().mockReturnThis(),
    values: vi.fn().mockReturnThis(),
    returning: vi.fn().mockResolvedValue([]),
  },
}));

vi.mock("../routes/shared", () => ({
  logger: {
    child: () => ({
      debug: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    }),
  },
}));

vi.mock("../../shared/schema", () => ({
  badgeEvents: { id: "id", orgId: "orgId", occurredAt: "occurredAt" },
  alerts: { id: "id", orgId: "orgId", createdAt: "createdAt" },
  physicalIncidents: { id: "id", orgId: "orgId" },
}));

import { db } from "../db";
import { runCorrelationAnalysis, BUILT_IN_RULES } from "../physical-correlation";

describe("Physical Correlation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe("BUILT_IN_RULES", () => {
    it("defines exactly 6 built-in rules", () => {
      expect(BUILT_IN_RULES).toHaveLength(6);
    });

    it("each rule has required fields", () => {
      for (const rule of BUILT_IN_RULES) {
        expect(rule.name).toBeTruthy();
        expect(rule.description).toBeTruthy();
        expect(rule.physicalCondition).toBeTruthy();
        expect(rule.digitalCondition).toBeTruthy();
        expect(rule.severity).toBeTruthy();
        expect(typeof rule.windowMinutes).toBe("number");
      }
    });

    it("includes critical severity rules", () => {
      const criticalRules = BUILT_IN_RULES.filter((r) => r.severity === "critical");
      expect(criticalRules.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe("runCorrelationAnalysis", () => {
    it("returns correlations when badge events match alerts within time window", async () => {
      const now = new Date();
      const badgeTime = new Date(now.getTime() - 10 * 60 * 1000); // 10 min ago
      // Set badge time to after-hours (22:00)
      badgeTime.setHours(22, 0, 0, 0);

      const mockBadgeEvents = [
        {
          id: "badge-1",
          orgId: "org-1",
          badgeNumber: "B001",
          employeeName: "John Doe",
          location: "Building A",
          doorName: "Main Entrance",
          eventType: "access_granted",
          occurredAt: badgeTime,
        },
      ];

      const mockAlerts = [
        {
          id: "alert-phys-1",
          orgId: "org-1",
          title: "Mass Download Detected",
          severity: "high",
          createdAt: new Date(badgeTime.getTime() + 30 * 60 * 1000), // 30 min after badge
        },
      ];

      // Track select calls: first returns badge events, subsequent return digital alerts
      let selectCallCount = 0;
      (db.select as any).mockImplementation(() => {
        const currentCall = ++selectCallCount;
        const isBadgeQuery = currentCall === 1;
        return {
          from: vi.fn().mockReturnValue({
            where: vi.fn().mockReturnValue({
              orderBy: vi.fn().mockReturnValue({
                limit: vi.fn().mockResolvedValue(isBadgeQuery ? mockBadgeEvents : mockAlerts),
              }),
              // For digital alert queries that don't use orderBy
              limit: vi.fn().mockResolvedValue(isBadgeQuery ? mockBadgeEvents : mockAlerts),
            }),
          }),
        };
      });

      const results = await runCorrelationAnalysis("org-1", 120);

      expect(results.status).toBe("completed");
      expect(results.correlations.length).toBeGreaterThanOrEqual(1);
      expect(results.correlations[0].rule.name).toBe("After-Hours Access + Mass File Download");
      expect(results.correlations[0].badgeEventId).toBe("badge-1");
    });

    it("returns empty array when no badge events exist", async () => {
      (db.select as any).mockReturnValue({
        from: vi.fn().mockReturnValue({
          where: vi.fn().mockReturnValue({
            orderBy: vi.fn().mockReturnValue({
              limit: vi.fn().mockResolvedValue([]),
            }),
          }),
        }),
      });

      const results = await runCorrelationAnalysis("org-1", 60);
      expect(results.status).toBe("completed");
      expect(results.correlations).toHaveLength(0);
    });

    it("returns an explicit failed status when analysis cannot query data", async () => {
      (db.select as any).mockImplementation(() => {
        throw new Error("database unavailable");
      });

      const results = await runCorrelationAnalysis("org-1", 60);

      expect(results).toEqual({
        status: "failed",
        correlations: [],
        eventsAnalyzed: 0,
        reason: "Correlation analysis could not be completed. Try again later.",
      });
    });

    it("detects tailgate events without needing digital alerts", async () => {
      const tailgateEvent = {
        id: "badge-tailgate",
        orgId: "org-1",
        badgeNumber: "B002",
        employeeName: "Jane Smith",
        location: "Building B",
        doorName: "Side Entrance",
        eventType: "tailgate_detected",
        occurredAt: new Date(),
      };

      (db.select as any).mockReturnValue({
        from: vi.fn().mockReturnValue({
          where: vi.fn().mockReturnValue({
            orderBy: vi.fn().mockReturnValue({
              limit: vi.fn().mockResolvedValue([tailgateEvent]),
            }),
          }),
        }),
      });

      const results = await runCorrelationAnalysis("org-1", 60);

      expect(results.status).toBe("completed");
      const tailgateCorrelations = results.correlations.filter((r) => r.rule.name.includes("Tailgate"));
      expect(tailgateCorrelations.length).toBeGreaterThanOrEqual(1);
      expect(tailgateCorrelations[0].badgeEventId).toBe("badge-tailgate");
    });

    it.each([
      ["inside business hours", "2026-08-21T12:00:00.000Z"],
      ["outside business hours", "2026-08-21T22:00:00.000Z"],
    ])("detects impossible travel when same badge used at distant locations (%s)", async (_label, clockTime) => {
      vi.useFakeTimers();
      vi.setSystemTime(new Date(clockTime));
      const now = new Date(clockTime);
      const badgeEvents = [
        {
          id: "badge-travel-1",
          orgId: "org-1",
          badgeNumber: "B003",
          employeeName: "Bob",
          location: "Building A - NYC",
          doorName: "Main",
          eventType: "access_granted",
          occurredAt: now,
        },
        {
          id: "badge-travel-2",
          orgId: "org-1",
          badgeNumber: "B003",
          employeeName: "Bob",
          location: "Building B - LA",
          doorName: "Main",
          eventType: "access_granted",
          occurredAt: new Date(now.getTime() + 5 * 60 * 1000), // 5 min later, different location
        },
      ];

      (db.select as any).mockReturnValue({
        from: vi.fn().mockReturnValue({
          where: vi.fn().mockReturnValue({
            orderBy: vi.fn().mockReturnValue({
              limit: vi.fn().mockResolvedValue(badgeEvents),
            }),
            limit: vi.fn().mockResolvedValue([]),
          }),
        }),
      });

      const results = await runCorrelationAnalysis("org-1", 60);

      expect(results.status).toBe("completed");
      const travelCorrelations = results.correlations.filter((r) => r.rule.name === "Badge Clone Detection");
      expect(travelCorrelations.length).toBeGreaterThanOrEqual(1);
      expect(travelCorrelations[0].details).toContain("B003");
    });
  });
});
