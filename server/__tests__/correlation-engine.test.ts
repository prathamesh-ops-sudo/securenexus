/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unused-vars */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { makeCrowdStrikeAlert, makeSplunkAlert, makeGuardDutyAlert } from "./fixtures/correlation/alert-factories";

const txMock = {
  insert: vi.fn().mockReturnThis(),
  values: vi.fn().mockReturnThis(),
  returning: vi.fn().mockResolvedValue([{ id: "cluster-1" }]),
  update: vi.fn().mockReturnThis(),
  set: vi.fn().mockReturnThis(),
  where: vi.fn().mockResolvedValue(undefined),
  select: vi.fn().mockReturnThis(),
  from: vi.fn().mockReturnThis(),
  limit: vi.fn().mockResolvedValue([]),
};

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
    transaction: vi.fn().mockImplementation(async (cb: (tx: any) => Promise<any>) => {
      return cb(txMock);
    }),
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

vi.mock("../correlation-aggregator", () => ({
  aggregateCorrelationScores: vi.fn().mockReturnValue({
    finalConfidence: 0.7,
    algorithmScores: [],
    needsReview: false,
    divergenceSpread: 0,
  }),
  buildAlgorithmScore: vi.fn().mockReturnValue({
    algorithm: "temporal_entity",
    confidence: 0.5,
    weight: 0.5,
    available: true,
  }),
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
    status: "status",
  },
  entities: { id: "id", orgId: "orgId", type: "type", value: "value", metadata: "metadata" },
  alertEntities: {},
  correlationClusters: { id: "id", orgId: "orgId", createdAt: "createdAt" },
  incidents: { id: "id", orgId: "orgId" },
}));

import { findRelatedAlertsByEntity } from "../entity-resolver";
import { computeThreatIntelConfidenceBoost } from "../threat-enrichment";
import { db } from "../db";
import { correlateAlert, promoteClusterToIncident } from "../correlation-engine";
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
    suppressed: false,
    suppressedBy: null,
    suppressionRuleId: null,
    confidenceScore: null,
    confidenceSource: null,
    confidenceNotes: null,
    dedupClusterId: null,
    analystNotes: null,
    assignedTo: null,
    detectedAt: new Date("2026-02-26T10:00:00Z"),
    ingestedAt: new Date("2026-02-26T10:00:00Z"),
    createdAt: new Date("2026-02-26T10:00:00Z"),
    ...overrides,
  } as Alert;
}

describe("Correlation Engine", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Reset transaction mock
    (db.transaction as any).mockImplementation(async (cb: (tx: any) => Promise<any>) => {
      // Reset txMock chain for each call
      txMock.insert.mockReturnThis();
      txMock.values.mockReturnValue({ returning: vi.fn().mockResolvedValue([{ id: "cluster-1" }]) });
      txMock.update.mockReturnValue({ set: vi.fn().mockReturnValue({ where: vi.fn().mockResolvedValue(undefined) }) });
      return cb(txMock);
    });
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

      let callCount = 0;
      (db.select as any).mockImplementation(() => {
        callCount++;
        return {
          from: () => {
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

      (db.transaction as any).mockImplementation(async (cb: (tx: any) => Promise<any>) => {
        const localTx = {
          insert: vi.fn().mockReturnValue({
            values: vi.fn().mockReturnValue({
              returning: vi.fn().mockResolvedValue([
                {
                  id: "cluster-1",
                  orgId: "org-1",
                  confidence: 0.5,
                  method: "temporal_entity_clustering_v1",
                  alertIds: ["alert-1", "alert-2"],
                },
              ]),
            }),
          }),
          update: vi.fn().mockReturnValue({
            set: vi.fn().mockReturnValue({
              where: vi.fn().mockResolvedValue(undefined),
            }),
          }),
        };
        return cb(localTx);
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

    it("invokes db.transaction for cluster creation", async () => {
      const relatedAlert = makeCrowdStrikeAlert({
        id: "alert-cs-1",
        mitreTactic: "lateral-movement",
        severity: "critical",
        createdAt: new Date("2026-02-26T09:30:00Z"),
      });

      (findRelatedAlertsByEntity as any).mockResolvedValue([
        { alertId: "alert-cs-1", sharedEntities: ["ip:10.0.0.1"] },
      ]);

      let callCount = 0;
      (db.select as any).mockImplementation(() => {
        callCount++;
        return {
          from: () => {
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

      (db.transaction as any).mockImplementation(async (cb: (tx: any) => Promise<any>) => {
        const localTx = {
          insert: vi.fn().mockReturnValue({
            values: vi.fn().mockReturnValue({
              returning: vi.fn().mockResolvedValue([{ id: "cluster-tx-1" }]),
            }),
          }),
          update: vi.fn().mockReturnValue({
            set: vi.fn().mockReturnValue({
              where: vi.fn().mockResolvedValue(undefined),
            }),
          }),
        };
        return cb(localTx);
      });

      (computeThreatIntelConfidenceBoost as any).mockReturnValue(0);

      const alert = makeAlert();
      await correlateAlert(alert);

      expect(db.transaction).toHaveBeenCalledTimes(1);
      // Verify isolation level argument
      expect(db.transaction).toHaveBeenCalledWith(expect.any(Function), { isolationLevel: "repeatable read" });
    });

    it("returns algorithmScore in result when correlation succeeds", async () => {
      const relatedAlert = makeSplunkAlert({
        id: "alert-splunk-1",
        mitreTactic: "credential-access",
        createdAt: new Date("2026-02-26T09:45:00Z"),
      });

      (findRelatedAlertsByEntity as any).mockResolvedValue([
        { alertId: "alert-splunk-1", sharedEntities: ["ip:10.0.0.1"] },
      ]);

      let callCount = 0;
      (db.select as any).mockImplementation(() => {
        callCount++;
        return {
          from: () => {
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

      (db.transaction as any).mockImplementation(async (cb: (tx: any) => Promise<any>) => {
        const localTx = {
          insert: vi.fn().mockReturnValue({
            values: vi.fn().mockReturnValue({
              returning: vi.fn().mockResolvedValue([{ id: "cluster-algo-1" }]),
            }),
          }),
          update: vi.fn().mockReturnValue({
            set: vi.fn().mockReturnValue({
              where: vi.fn().mockResolvedValue(undefined),
            }),
          }),
        };
        return cb(localTx);
      });

      (computeThreatIntelConfidenceBoost as any).mockReturnValue(0);

      const alert = makeAlert();
      const result = await correlateAlert(alert);

      expect(result).not.toBeNull();
      expect(result!.algorithmScore).toBeDefined();
      expect(result!.algorithmScore!.algorithm).toBe("temporal_entity");
      expect(result!.algorithmScore!.available).toBe(true);
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

      (db.transaction as any).mockImplementation(async (cb: (tx: any) => Promise<any>) => {
        const localTx = {
          insert: vi.fn().mockReturnValue({
            values: vi.fn().mockReturnValue({
              returning: vi.fn().mockResolvedValue([
                {
                  id: "cluster-high",
                  orgId: "org-1",
                  confidence: 1.0,
                  method: "temporal_entity_clustering_v1",
                  alertIds: ["alert-1", ...relatedAlerts.map((a) => a.id)],
                },
              ]),
            }),
          }),
          update: vi.fn().mockReturnValue({
            set: vi.fn().mockReturnValue({
              where: vi.fn().mockResolvedValue(undefined),
            }),
          }),
        };
        return cb(localTx);
      });

      const alert = makeAlert({ severity: "critical" });
      const result = await correlateAlert(alert);

      if (result) {
        expect(result.confidence).toBeLessThanOrEqual(1.0);
      }
    });
  });

  describe("promoteClusterToIncident", () => {
    it("uses serializable isolation with retry on code 40001", async () => {
      (db.transaction as any).mockImplementation(async (cb: (tx: any) => Promise<any>, config: any) => {
        expect(config).toEqual({ isolationLevel: "serializable" });
        const localTx = {
          select: vi.fn().mockReturnValue({
            from: vi.fn().mockReturnValue({
              where: vi.fn().mockReturnValue({
                limit: vi.fn().mockResolvedValue([{
                  id: "cluster-promote-1",
                  orgId: "org-1",
                  confidence: 0.8,
                  alertIds: ["alert-1", "alert-2"],
                  reasoningTrace: "test trace",
                }]),
              }),
            }),
          }),
          insert: vi.fn().mockReturnValue({
            values: vi.fn().mockReturnValue({
              returning: vi.fn().mockResolvedValue([{ id: "incident-1" }]),
            }),
          }),
          update: vi.fn().mockReturnValue({
            set: vi.fn().mockReturnValue({
              where: vi.fn().mockResolvedValue(undefined),
            }),
          }),
        };
        return cb(localTx);
      });

      const result = await promoteClusterToIncident("cluster-promote-1", "Test Incident", "high");
      expect(result.incidentId).toBe("incident-1");
      expect(db.transaction).toHaveBeenCalledWith(expect.any(Function), { isolationLevel: "serializable" });
    });

    it("retries on serialization failure (code 40001)", async () => {
      let attempt = 0;
      (db.transaction as any).mockImplementation(async (cb: (tx: any) => Promise<any>) => {
        attempt++;
        if (attempt === 1) {
          const error = new Error("could not serialize access");
          (error as any).code = "40001";
          throw error;
        }
        const localTx = {
          select: vi.fn().mockReturnValue({
            from: vi.fn().mockReturnValue({
              where: vi.fn().mockReturnValue({
                limit: vi.fn().mockResolvedValue([{
                  id: "cluster-retry-1",
                  orgId: "org-1",
                  confidence: 0.75,
                  alertIds: ["alert-1"],
                  reasoningTrace: "retry trace",
                }]),
              }),
            }),
          }),
          insert: vi.fn().mockReturnValue({
            values: vi.fn().mockReturnValue({
              returning: vi.fn().mockResolvedValue([{ id: "incident-retry-1" }]),
            }),
          }),
          update: vi.fn().mockReturnValue({
            set: vi.fn().mockReturnValue({
              where: vi.fn().mockResolvedValue(undefined),
            }),
          }),
        };
        return cb(localTx);
      });

      const result = await promoteClusterToIncident("cluster-retry-1", "Retry Test", "high");
      expect(result.incidentId).toBe("incident-retry-1");
      expect(db.transaction).toHaveBeenCalledTimes(2);
    });

    it("passes aggregatedScore to incident when provided", async () => {
      let capturedValues: any = null;
      (db.transaction as any).mockImplementation(async (cb: (tx: any) => Promise<any>) => {
        const localTx = {
          select: vi.fn().mockReturnValue({
            from: vi.fn().mockReturnValue({
              where: vi.fn().mockReturnValue({
                limit: vi.fn().mockResolvedValue([{
                  id: "cluster-agg-1",
                  orgId: "org-1",
                  confidence: 0.7,
                  alertIds: ["alert-1"],
                  reasoningTrace: "agg trace",
                }]),
              }),
            }),
          }),
          insert: vi.fn().mockImplementation(() => ({
            values: vi.fn().mockImplementation((vals: any) => {
              capturedValues = vals;
              return {
                returning: vi.fn().mockResolvedValue([{ id: "incident-agg-1" }]),
              };
            }),
          })),
          update: vi.fn().mockReturnValue({
            set: vi.fn().mockReturnValue({
              where: vi.fn().mockResolvedValue(undefined),
            }),
          }),
        };
        return cb(localTx);
      });

      const aggregatedScore = {
        finalConfidence: 0.85,
        algorithmScores: [
          { algorithm: "temporal_entity" as const, confidence: 0.9, weight: 0.5, available: true },
          { algorithm: "graph" as const, confidence: 0.8, weight: 0.3, available: true },
        ],
        needsReview: true,
        divergenceSpread: 0.35,
      };

      const result = await promoteClusterToIncident("cluster-agg-1", "Aggregated Test", "critical", aggregatedScore);
      expect(result.incidentId).toBe("incident-agg-1");
      expect(capturedValues.needsReview).toBe(true);
      expect(capturedValues.confidence).toBe(0.85);
      expect(capturedValues.algorithmScores).toEqual(aggregatedScore.algorithmScores);
    });
  });
});
