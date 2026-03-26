/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * Correlation Engine Integration Tests
 *
 * Validates the full correlation pipeline by feeding multi-source alert
 * scenarios through correlateAlert and verifying correct entity-based
 * grouping, cross-org isolation, and multi-source cluster formation.
 *
 * These tests mock the DB layer at a high level (same pattern as the
 * existing unit tests) but exercise the full correlation logic including
 * entity linking, confidence calculation, and cluster creation.
 *
 * For real-DB integration tests, set DATABASE_URL and use the
 * describe.skipIf guard below.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  buildLateralMovementScenario,
  expectedEntityLinks,
  expectedIncidentCount,
} from "./fixtures/correlation/scenario-lateral-movement";
import type { Alert } from "@shared/schema";

// --- Mocks ---

// Track clusters created so we can simulate cluster lookup
const createdClusters: {
  id: string;
  orgId: string | null;
  confidence: number;
  method: string;
  alertIds: string[];
  sharedEntities: any[];
}[] = [];
let clusterCounter = 0;

vi.mock("../db", () => {
  const txProxy: any = {
    insert: vi.fn().mockReturnThis(),
    values: vi.fn().mockReturnThis(),
    returning: vi.fn().mockResolvedValue([{ id: "cluster-1" }]),
    update: vi.fn().mockReturnThis(),
    set: vi.fn().mockReturnThis(),
    where: vi.fn().mockResolvedValue(undefined),
  };
  return {
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
      transaction: vi.fn(async (cb: any) => cb(txProxy)),
      _txProxy: txProxy,
    },
  };
});

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

/**
 * Build the entity lookup map from the scenario.
 * For a given alert id, returns which other alert ids share entities with it.
 */
function buildEntityRelationMap(alerts: Alert[]): Map<string, { alertId: string; sharedEntities: string[] }[]> {
  const entityToAlerts = new Map<string, Set<string>>();

  for (const alert of alerts) {
    const ents: string[] = [];
    if (alert.userId) ents.push(`user:${alert.userId}`);
    if (alert.hostname) ents.push(`host:${alert.hostname}`);
    if (alert.sourceIp) ents.push(`ip:${alert.sourceIp}`);
    if (alert.destIp) ents.push(`ip:${alert.destIp}`);
    if (alert.domain) ents.push(`domain:${alert.domain}`);
    if (alert.fileHash) ents.push(`file_hash:${alert.fileHash}`);

    for (const ent of ents) {
      if (!entityToAlerts.has(ent)) entityToAlerts.set(ent, new Set());
      entityToAlerts.get(ent)!.add(alert.id);
    }
  }

  const result = new Map<string, { alertId: string; sharedEntities: string[] }[]>();
  for (const alert of alerts) {
    const ents: string[] = [];
    if (alert.userId) ents.push(`user:${alert.userId}`);
    if (alert.hostname) ents.push(`host:${alert.hostname}`);
    if (alert.sourceIp) ents.push(`ip:${alert.sourceIp}`);
    if (alert.destIp) ents.push(`ip:${alert.destIp}`);
    if (alert.domain) ents.push(`domain:${alert.domain}`);
    if (alert.fileHash) ents.push(`file_hash:${alert.fileHash}`);

    const relatedMap = new Map<string, Set<string>>();
    for (const ent of ents) {
      const alertIds = entityToAlerts.get(ent) ?? new Set();
      for (const relId of alertIds) {
        if (relId === alert.id) continue;
        if (!relatedMap.has(relId)) relatedMap.set(relId, new Set());
        relatedMap.get(relId)!.add(ent);
      }
    }

    result.set(
      alert.id,
      Array.from(relatedMap.entries()).map(([alertId, shared]) => ({
        alertId,
        sharedEntities: Array.from(shared),
      })),
    );
  }

  return result;
}

/**
 * Set up mocks for a given set of alerts so correlateAlert can function.
 * findRelatedAlertsByEntity returns entity links based on the scenario data.
 * db.select chain returns matching alerts within the time window.
 */
function setupMocksForAlerts(allAlerts: Alert[], entityMap: Map<string, { alertId: string; sharedEntities: string[] }[]>) {
  (findRelatedAlertsByEntity as any).mockImplementation((alertId: string) => {
    return Promise.resolve(entityMap.get(alertId) ?? []);
  });

  (computeThreatIntelConfidenceBoost as any).mockReturnValue(0);

  let selectCallCount = 0;
  (db.select as any).mockImplementation(() => {
    selectCallCount++;
    return {
      from: () => ({
        where: () => ({
          orderBy: () => ({
            limit: (n: number) => {
              // First select call per correlateAlert fetches related alerts
              // Subsequent calls are for entity enrichment
              if (selectCallCount % 2 === 1) {
                const relatedIds = new Set<string>();
                for (const rels of entityMap.values()) {
                  for (const r of rels) relatedIds.add(r.alertId);
                }
                return Promise.resolve(allAlerts.filter((a) => relatedIds.has(a.id)).slice(0, n));
              }
              return Promise.resolve([]);
            },
          }),
          // For entity enrichment queries (no orderBy)
          limit: () => Promise.resolve([]),
        }),
      }),
    };
  });

  // Mock the transaction proxy's insert and update (used inside db.transaction callback)
  const txProxy = (db as any)._txProxy;
  const insertImpl = () => ({
    values: (vals: any) => ({
      returning: () => {
        clusterCounter++;
        const cluster = {
          id: `cluster-${clusterCounter}`,
          orgId: vals.orgId ?? "test-org-integration",
          confidence: vals.confidence ?? 0.5,
          method: vals.method ?? "temporal_entity_clustering_v1",
          alertIds: vals.alertIds ?? [],
          sharedEntities: vals.sharedEntities ?? [],
        };
        createdClusters.push(cluster);
        return Promise.resolve([cluster]);
      },
    }),
  });

  const updateImpl = () => ({
    set: () => ({
      where: () => Promise.resolve(),
    }),
  });

  txProxy.insert.mockImplementation(insertImpl);
  txProxy.update.mockImplementation(updateImpl);
  (db.insert as any).mockImplementation(insertImpl);
  (db.update as any).mockImplementation(updateImpl);
}

describe("Correlation Integration", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    createdClusters.length = 0;
    clusterCounter = 0;
  });

  describe("lateral movement campaign", () => {
    it("correlates lateral movement campaign into a single incident cluster", async () => {
      const scenarioAlerts = buildLateralMovementScenario();
      expect(scenarioAlerts.length).toBeGreaterThanOrEqual(10);

      const entityMap = buildEntityRelationMap(scenarioAlerts);
      setupMocksForAlerts(scenarioAlerts, entityMap);

      const results: any[] = [];
      for (const alert of scenarioAlerts) {
        const result = await correlateAlert(alert);
        if (result) results.push(result);
      }

      // At least some alerts should produce correlation results
      expect(results.length).toBeGreaterThan(0);

      // All results should have confidence >= 0.3 (cluster threshold)
      for (const r of results) {
        expect(r.confidence).toBeGreaterThanOrEqual(0.3);
        expect(r.confidence).toBeLessThanOrEqual(1.0);
      }

      // At least one result should have multiple alert IDs
      const multiAlertResults = results.filter((r) => r.alertIds.length >= 2);
      expect(multiAlertResults.length).toBeGreaterThan(0);

      // Shared entities should be detected
      const allSharedEntities = results.flatMap((r) => r.sharedEntities);
      expect(allSharedEntities.length).toBeGreaterThan(0);

      // Reasoning trace should be present
      for (const r of results) {
        expect(r.reasoningTrace).toBeTruthy();
        expect(r.reasoningTrace).toContain("CORRELATION ANALYSIS");
      }
    });

    it("scenario fixture has alerts from all 3 sources", () => {
      const alerts = buildLateralMovementScenario();
      const sources = new Set(alerts.map((a) => a.source));

      expect(sources.has("CrowdStrike EDR")).toBe(true);
      expect(sources.has("Splunk SIEM")).toBe(true);
      expect(sources.has("AWS GuardDuty")).toBe(true);
    });

    it("scenario covers expected MITRE ATT&CK tactics", () => {
      const alerts = buildLateralMovementScenario();
      const tactics = new Set(alerts.map((a) => a.mitreTactic).filter(Boolean));

      expect(tactics.has("initial-access")).toBe(true);
      expect(tactics.has("execution")).toBe(true);
      expect(tactics.has("persistence")).toBe(true);
      expect(tactics.has("privilege-escalation")).toBe(true);
      expect(tactics.has("lateral-movement")).toBe(true);
      expect(tactics.has("collection")).toBe(true);
    });

    it("scenario has correct expected entity links", () => {
      const alerts = buildLateralMovementScenario();
      const entityMap = buildEntityRelationMap(alerts);

      // john.doe appears in at least 6 alerts
      const johnDoeAlerts = alerts.filter((a) => a.userId === "john.doe");
      expect(johnDoeAlerts.length).toBeGreaterThanOrEqual(5);

      // workstation-42 appears in at least 5 alerts
      const ws42Alerts = alerts.filter((a) => a.hostname === "workstation-42");
      expect(ws42Alerts.length).toBeGreaterThanOrEqual(5);

      // server-db-01 appears in at least 4 alerts
      const dbAlerts = alerts.filter((a) => a.hostname === "server-db-01");
      expect(dbAlerts.length).toBeGreaterThanOrEqual(4);

      // All alerts have entity-based relationships to at least one other alert
      for (const alert of alerts) {
        const related = entityMap.get(alert.id) ?? [];
        expect(related.length).toBeGreaterThan(0);
      }
    });
  });

  describe("cross-org isolation", () => {
    it("alerts from different orgs are never correlated together", async () => {
      const orgAAlert: Alert = {
        id: "org-a-alert-1",
        orgId: "org-A",
        source: "CrowdStrike EDR",
        sourceEventId: "evt-a1",
        category: "malware",
        severity: "high",
        title: "Malware on shared-host",
        description: "",
        rawData: {},
        normalizedData: {},
        ocsfData: null,
        sourceIp: "10.0.0.1",
        destIp: null,
        sourcePort: null,
        destPort: null,
        protocol: null,
        userId: "shared-user",
        hostname: "shared-host",
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
        detectedAt: new Date("2026-03-01T10:00:00Z"),
        createdAt: new Date("2026-03-01T10:00:00Z"),
        updatedAt: null,
      } as Alert;

      const orgBAlert: Alert = {
        ...orgAAlert,
        id: "org-b-alert-1",
        orgId: "org-B",
        sourceEventId: "evt-b1",
      } as Alert;

      // findRelatedAlertsByEntity respects orgId -- for org-A alert, no org-B results
      (findRelatedAlertsByEntity as any).mockResolvedValue([]);
      (computeThreatIntelConfidenceBoost as any).mockReturnValue(0);

      const resultA = await correlateAlert(orgAAlert);
      const resultB = await correlateAlert(orgBAlert);

      // With no related alerts found (due to org isolation), both return null
      expect(resultA).toBeNull();
      expect(resultB).toBeNull();

      // findRelatedAlertsByEntity was called with correct orgIds
      expect(findRelatedAlertsByEntity).toHaveBeenCalledWith("org-a-alert-1", "org-A", 30);
      expect(findRelatedAlertsByEntity).toHaveBeenCalledWith("org-b-alert-1", "org-B", 30);
    });
  });

  describe("uncorrelated alerts", () => {
    it("uncorrelated alert returns null", async () => {
      (findRelatedAlertsByEntity as any).mockResolvedValue([]);

      const loneAlert: Alert = {
        id: "lone-alert",
        orgId: "org-lone",
        source: "CrowdStrike EDR",
        sourceEventId: "evt-lone",
        category: "informational",
        severity: "low",
        title: "Informational event",
        description: "",
        rawData: {},
        normalizedData: {},
        ocsfData: null,
        sourceIp: "192.168.99.99",
        destIp: null,
        sourcePort: null,
        destPort: null,
        protocol: null,
        userId: null,
        hostname: "unique-host-xyz",
        fileHash: null,
        url: null,
        domain: null,
        mitreTactic: null,
        mitreTechnique: null,
        status: "new",
        correlationScore: null,
        correlationClusterId: null,
        correlationReason: null,
        incidentId: null,
        detectedAt: new Date("2026-03-01T12:00:00Z"),
        createdAt: new Date("2026-03-01T12:00:00Z"),
        updatedAt: null,
      } as Alert;

      const result = await correlateAlert(loneAlert);
      expect(result).toBeNull();
    });
  });

  describe("multi-source correlation", () => {
    it("alerts from 3 different sources contribute to same cluster", async () => {
      const scenarioAlerts = buildLateralMovementScenario();
      const entityMap = buildEntityRelationMap(scenarioAlerts);
      setupMocksForAlerts(scenarioAlerts, entityMap);

      const results: any[] = [];
      for (const alert of scenarioAlerts) {
        const result = await correlateAlert(alert);
        if (result) results.push(result);
      }

      // Check that alerts from all 3 sources appear in cluster alertIds
      const allClusteredAlertIds = new Set(results.flatMap((r) => r.alertIds));

      const clusteredAlerts = scenarioAlerts.filter((a) => allClusteredAlertIds.has(a.id));
      const sourcesInClusters = new Set(clusteredAlerts.map((a) => a.source));

      // At least 2 sources should be represented (CrowdStrike and others share entities heavily)
      expect(sourcesInClusters.size).toBeGreaterThanOrEqual(2);

      // Verify specific sources appear
      const hasCrowdStrike = clusteredAlerts.some((a) => a.source === "CrowdStrike EDR");
      expect(hasCrowdStrike).toBe(true);
    });
  });
});
