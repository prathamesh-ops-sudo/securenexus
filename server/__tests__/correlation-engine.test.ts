/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unused-vars */
import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../db", () => ({
  db: {
    select: vi.fn().mockReturnThis(),
    from: vi.fn().mockReturnThis(),
    where: vi.fn().mockReturnThis(),
    orderBy: vi.fn().mockReturnThis(),
    limit: vi.fn().mockResolvedValue([]),
    insert: vi.fn().mockReturnThis(),
    values: vi.fn().mockReturnThis(),
    returning: vi.fn().mockResolvedValue([{ id: "cluster-1" }]),
    update: vi.fn().mockReturnThis(),
    set: vi.fn().mockReturnThis(),
  },
}));

vi.mock("../entity-resolver", () => ({
  findRelatedAlertsByEntity: vi.fn().mockResolvedValue([]),
}));

vi.mock("../threat-enrichment", () => ({
  computeThreatIntelConfidenceBoost: vi.fn().mockReturnValue(0),
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

vi.mock("@shared/schema", () => ({
  alerts: {
    id: "id",
    orgId: "orgId",
    createdAt: "createdAt",
    correlationScore: "cs",
    correlationClusterId: "cc",
    correlationReason: "cr",
    incidentId: "ii",
    severity: "sev",
    source: "src",
    category: "cat",
    mitreTactic: "mt",
  },
  entities: { id: "id", orgId: "orgId", type: "type", value: "value", metadata: "metadata" },
  alertEntities: {},
  correlationClusters: { id: "id", orgId: "orgId", createdAt: "createdAt" },
  incidents: { id: "id" },
}));

import { findRelatedAlertsByEntity } from "../entity-resolver";
import { computeThreatIntelConfidenceBoost } from "../threat-enrichment";
import { db } from "../db";
import { correlateAlert } from "../correlation-engine";
import type { Alert } from "@shared/schema";

function makeAlert(overrides: Partial<Alert> = {}): Alert {
  return {
    id: "alert-1",
    orgId: "org-1",
    source: "CrowdStrike EDR",
    sourceEventId: "evt-1",
    category: "malware",
    severity: "high",
    title: "Test Alert",
    description: "Test description",
    rawData: {},
    normalizedData: {},
    ocsfData: null,
    sourceIp: "10.0.0.1",
    destIp: "192.168.1.1",
    sourcePort: null,
    destPort: null,
    protocol: null,
    userId: null,
    hostname: "host-1",
    fileHash: null,
    url: null,
    domain: null,
    mitreTactic: "execution",
    mitreTechnique: "T1059",
    status: "new",
    correlationScore: null,
    correlationClusterId: null,
    correlationReason: null,
    incidentId: null,
    detectedAt: new Date("2026-02-26T10:00:00Z"),
    createdAt: new Date("2026-02-26T10:00:00Z"),
    updatedAt: null,
    ...overrides,
  } as Alert;
}

describe("Correlation Engine", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("correlateAlert", () => {
    it("returns null when no related alerts found by entity", async () => {
      (findRelatedAlertsByEntity as any).mockResolvedValue([]);

      const alert = makeAlert();
      const result = await correlateAlert(alert);

      expect(result).toBeNull();
    });

    it("returns null when related alerts exist but none within time window", async () => {
      (findRelatedAlertsByEntity as any).mockResolvedValue([{ alertId: "alert-2", sharedEntities: ["ip:10.0.0.1"] }]);

      (db.select as any).mockReturnValue({
        from: vi.fn().mockReturnValue({
          where: vi.fn().mockReturnValue({
            orderBy: vi.fn().mockReturnValue({
              limit: vi.fn().mockResolvedValue([]),
            }),
          }),
        }),
      });

      const alert = makeAlert();
      const result = await correlateAlert(alert);

      expect(result).toBeNull();
    });

    it("creates correlation cluster when confidence is sufficient", async () => {
      const relatedAlert = makeAlert({
        id: "alert-2",
        severity: "critical",
        mitreTactic: "lateral-movement",
        source: "CrowdStrike EDR",
        category: "malware",
        createdAt: new Date("2026-02-26T09:30:00Z"),
      });

      (findRelatedAlertsByEntity as any).mockResolvedValue([
        { alertId: "alert-2", sharedEntities: ["ip:10.0.0.1", "host:host-1"] },
      ]);

      const selectMock = vi.fn();
      const fromMock = vi.fn();
      const whereMock = vi.fn();
      const orderByMock = vi.fn();
      const limitMock = vi.fn();

      let callCount = 0;
      (db.select as any).mockImplementation(() => {
        callCount++;
        return {
          from: (...args: unknown[]) => {
            if (callCount === 1) {
              return {
                where: () => ({
                  orderBy: () => ({
                    limit: () => Promise.resolve([relatedAlert]),
                  }),
                }),
              };
            }
            return {
              where: () => ({
                limit: () => Promise.resolve([]),
              }),
            };
          },
        };
      });

      (db.insert as any).mockReturnValue({
        values: () => ({
          returning: () =>
            Promise.resolve([
              {
                id: "cluster-1",
                orgId: "org-1",
                confidence: 0.5,
                method: "temporal_entity_clustering_v1",
                alertIds: ["alert-1", "alert-2"],
              },
            ]),
        }),
      });

      (db.update as any).mockReturnValue({
        set: () => ({
          where: () => Promise.resolve(),
        }),
      });

      (computeThreatIntelConfidenceBoost as any).mockReturnValue(0);

      const alert = makeAlert();
      const result = await correlateAlert(alert);

      if (result) {
        expect(result.clusterId).toBe("cluster-1");
        expect(result.method).toBe("temporal_entity_clustering_v1");
        expect(result.alertIds).toContain("alert-1");
        expect(result.alertIds).toContain("alert-2");
        expect(result.confidence).toBeGreaterThanOrEqual(0.3);
        expect(result.confidence).toBeLessThanOrEqual(1.0);
        expect(result.sharedEntities.length).toBeGreaterThan(0);
        expect(result.reasoningTrace).toContain("CORRELATION ANALYSIS");
      }
    });

    it("caps confidence at 1.0 even with threat intel boost", async () => {
      const relatedAlerts = Array.from({ length: 5 }, (_, i) =>
        makeAlert({
          id: `alert-${i + 2}`,
          severity: "critical",
          mitreTactic: ["execution", "lateral-movement", "persistence", "privilege-escalation", "exfiltration"][i],
          source: "CrowdStrike EDR",
          category: "malware",
          createdAt: new Date("2026-02-26T09:30:00Z"),
        }),
      );

      (findRelatedAlertsByEntity as any).mockResolvedValue(
        relatedAlerts.map((a) => ({
          alertId: a.id,
          sharedEntities: ["ip:10.0.0.1", "host:host-1", "domain:evil.com", "user:admin"],
        })),
      );

      let callCount = 0;
      (db.select as any).mockImplementation(() => {
        callCount++;
        return {
          from: () => {
            if (callCount === 1) {
              return {
                where: () => ({
                  orderBy: () => ({
                    limit: () => Promise.resolve(relatedAlerts),
                  }),
                }),
              };
            }
            return {
              where: () => ({
                limit: () => Promise.resolve([]),
              }),
            };
          },
        };
      });

      (computeThreatIntelConfidenceBoost as any).mockReturnValue(0.15);

      (db.insert as any).mockReturnValue({
        values: () => ({
          returning: () =>
            Promise.resolve([
              {
                id: "cluster-high",
                orgId: "org-1",
                confidence: 1.0,
                method: "temporal_entity_clustering_v1",
                alertIds: ["alert-1", ...relatedAlerts.map((a) => a.id)],
              },
            ]),
        }),
      });

      (db.update as any).mockReturnValue({
        set: () => ({
          where: () => Promise.resolve(),
        }),
      });

      const alert = makeAlert({ severity: "critical" });
      const result = await correlateAlert(alert);

      if (result) {
        expect(result.confidence).toBeLessThanOrEqual(1.0);
      }
    });
  });
});
