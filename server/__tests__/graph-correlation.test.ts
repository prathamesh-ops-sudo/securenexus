/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, it, expect, vi } from "vitest";

vi.mock("../db", () => ({
  db: {
    select: vi.fn().mockReturnThis(),
    from: vi.fn().mockReturnThis(),
    where: vi.fn().mockReturnThis(),
    orderBy: vi.fn().mockReturnThis(),
    limit: vi.fn().mockResolvedValue([]),
    insert: vi.fn().mockReturnThis(),
    values: vi.fn().mockReturnThis(),
    returning: vi.fn().mockResolvedValue([{ id: "cluster-g-1" }]),
    update: vi.fn().mockReturnThis(),
    set: vi.fn().mockReturnThis(),
    transaction: vi.fn().mockImplementation(async (cb: (tx: any) => Promise<any>) => {
      return cb({});
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

vi.mock("@shared/schema", () => ({
  alerts: { id: "id", orgId: "orgId", createdAt: "createdAt" },
  entities: { id: "id", orgId: "orgId", type: "type", value: "value" },
  alertEntities: { alertId: "alertId", entityId: "entityId" },
  correlationClusters: { id: "id", orgId: "orgId" },
  attackPaths: { id: "id", orgId: "orgId", createdAt: "createdAt" },
  campaigns: { id: "id", orgId: "orgId", fingerprint: "fp", createdAt: "createdAt" },
}));

import {
  computePathConfidence,
  findAttackPaths,
  generateCampaignFingerprint,
  type AlertGraphNode,
  type EntityGraphNode,
  type TypedGraphNode,
  type AlertNodeData,
  type EntityNodeData,
} from "../graph-correlation";

describe("Graph Correlation", () => {
  describe("computePathConfidence", () => {
    it("returns higher confidence for diverse entity types and kill chain progression", () => {
      const alertData: AlertNodeData[] = [
        {
          alertId: "a1",
          title: "Phishing Email",
          severity: "medium",
          source: "Splunk SIEM",
          category: "phishing",
          mitreTactic: "initial-access",
          mitreTechnique: "T1566",
          createdAt: new Date("2026-03-25T08:00:00Z"),
          orgId: "org-1",
        },
        {
          alertId: "a2",
          title: "Malware Execution",
          severity: "high",
          source: "CrowdStrike EDR",
          category: "malware",
          mitreTactic: "execution",
          mitreTechnique: "T1059",
          createdAt: new Date("2026-03-25T09:00:00Z"),
          orgId: "org-1",
        },
        {
          alertId: "a3",
          title: "Lateral Movement",
          severity: "critical",
          source: "AWS GuardDuty",
          category: "lateral_movement",
          mitreTactic: "lateral-movement",
          mitreTechnique: "T1021",
          createdAt: new Date("2026-03-25T10:00:00Z"),
          orgId: "org-1",
        },
      ];

      const entityData: EntityNodeData[] = [
        { entityId: "e1", type: "ip", value: "10.0.0.1", displayName: null, riskScore: 25 },
        { entityId: "e2", type: "host", value: "ws-01", displayName: null, riskScore: 15 },
        { entityId: "e3", type: "user", value: "admin", displayName: null, riskScore: 50 },
        { entityId: "e4", type: "domain", value: "evil.com", displayName: null, riskScore: 80 },
      ];

      const confidence = computePathConfidence(alertData, entityData, 4, 2);

      // With 4 entity types, 3 kill chain tactics in order, 3 sources, high severity spread, 4 hops
      expect(confidence).toBeGreaterThan(0.5);
      expect(confidence).toBeLessThanOrEqual(1.0);
    });

    it("returns lower confidence for single source and no kill chain", () => {
      const alertData: AlertNodeData[] = [
        {
          alertId: "a1",
          title: "Alert 1",
          severity: "low",
          source: "Splunk SIEM",
          category: "info",
          mitreTactic: null,
          mitreTechnique: null,
          createdAt: new Date("2026-03-25T10:00:00Z"),
          orgId: "org-1",
        },
        {
          alertId: "a2",
          title: "Alert 2",
          severity: "low",
          source: "Splunk SIEM",
          category: "info",
          mitreTactic: null,
          mitreTechnique: null,
          createdAt: new Date("2026-03-25T10:01:00Z"),
          orgId: "org-1",
        },
      ];

      const entityData: EntityNodeData[] = [
        { entityId: "e1", type: "ip", value: "10.0.0.1", displayName: null, riskScore: 5 },
      ];

      const confidence = computePathConfidence(alertData, entityData, 1, 0.1);

      expect(confidence).toBeLessThan(0.4);
      expect(confidence).toBeGreaterThanOrEqual(0);
    });

    it("returns zero-or-low for empty inputs", () => {
      const confidence = computePathConfidence([], [], 0, 0);
      expect(confidence).toBeGreaterThanOrEqual(0);
      expect(confidence).toBeLessThan(0.3);
    });
  });

  describe("findAttackPaths", () => {
    it("finds connected components of alerts linked by shared entities", () => {
      const graph = new Map<string, Set<string>>();
      graph.set("a:alert-1", new Set(["e:entity-1"]));
      graph.set("e:entity-1", new Set(["a:alert-1", "a:alert-2"]));
      graph.set("a:alert-2", new Set(["e:entity-1", "e:entity-2"]));
      graph.set("e:entity-2", new Set(["a:alert-2", "a:alert-3"]));
      graph.set("a:alert-3", new Set(["e:entity-2"]));

      const nodeMetadata = new Map<string, TypedGraphNode>();
      nodeMetadata.set("a:alert-1", {
        id: "a:alert-1",
        type: "alert",
        data: {
          alertId: "alert-1",
          title: "Alert 1",
          severity: "high",
          source: "CrowdStrike EDR",
          category: "malware",
          mitreTactic: "execution",
          mitreTechnique: "T1059",
          createdAt: new Date("2026-03-25T08:00:00Z"),
          orgId: "org-1",
        },
      });
      nodeMetadata.set("a:alert-2", {
        id: "a:alert-2",
        type: "alert",
        data: {
          alertId: "alert-2",
          title: "Alert 2",
          severity: "critical",
          source: "Splunk SIEM",
          category: "intrusion",
          mitreTactic: "lateral-movement",
          mitreTechnique: "T1021",
          createdAt: new Date("2026-03-25T09:00:00Z"),
          orgId: "org-1",
        },
      });
      nodeMetadata.set("a:alert-3", {
        id: "a:alert-3",
        type: "alert",
        data: {
          alertId: "alert-3",
          title: "Alert 3",
          severity: "medium",
          source: "AWS GuardDuty",
          category: "credential_access",
          mitreTactic: "credential-access",
          mitreTechnique: "T1110",
          createdAt: new Date("2026-03-25T10:00:00Z"),
          orgId: "org-1",
        },
      });
      nodeMetadata.set("e:entity-1", {
        id: "e:entity-1",
        type: "entity",
        data: {
          entityId: "entity-1",
          type: "ip",
          value: "10.0.0.1",
          displayName: null,
          riskScore: 30,
        },
      });
      nodeMetadata.set("e:entity-2", {
        id: "e:entity-2",
        type: "entity",
        data: {
          entityId: "entity-2",
          type: "host",
          value: "workstation-1",
          displayName: null,
          riskScore: 20,
        },
      });

      const paths = findAttackPaths(graph, nodeMetadata);

      expect(paths.length).toBeGreaterThanOrEqual(1);
      const path = paths[0];
      expect(path.alertIds).toContain("alert-1");
      expect(path.alertIds).toContain("alert-2");
      expect(path.alertIds).toContain("alert-3");
      expect(path.entityIds).toContain("entity-1");
      expect(path.entityIds).toContain("entity-2");
      expect(path.confidence).toBeGreaterThan(0);
    });

    it("skips components with fewer than 2 alerts", () => {
      const graph = new Map<string, Set<string>>();
      graph.set("a:alert-solo", new Set(["e:entity-solo"]));
      graph.set("e:entity-solo", new Set(["a:alert-solo"]));

      const nodeMetadata = new Map<string, TypedGraphNode>();
      nodeMetadata.set("a:alert-solo", {
        id: "a:alert-solo",
        type: "alert",
        data: {
          alertId: "alert-solo",
          title: "Lone Alert",
          severity: "low",
          source: "Splunk SIEM",
          category: "info",
          mitreTactic: null,
          mitreTechnique: null,
          createdAt: new Date("2026-03-25T10:00:00Z"),
          orgId: "org-1",
        },
      });
      nodeMetadata.set("e:entity-solo", {
        id: "e:entity-solo",
        type: "entity",
        data: {
          entityId: "entity-solo",
          type: "ip",
          value: "10.0.0.99",
          displayName: null,
          riskScore: 5,
        },
      });

      const paths = findAttackPaths(graph, nodeMetadata);
      expect(paths).toHaveLength(0);
    });
  });

  describe("generateCampaignFingerprint", () => {
    it("produces consistent fingerprint for same input", () => {
      const attackPath = {
        alertIds: ["a1", "a2"],
        entityIds: ["e1", "e2"],
        nodes: [
          { id: "a:a1", type: "alert" as const, data: { alertId: "a1", title: "X", severity: "high", source: "CrowdStrike EDR", category: "malware", mitreTactic: "execution", mitreTechnique: "T1059", createdAt: new Date(), orgId: "org-1" } },
          { id: "e:e1", type: "entity" as const, data: { entityId: "e1", type: "ip", value: "10.0.0.1", displayName: null, riskScore: 10 } },
          { id: "e:e2", type: "entity" as const, data: { entityId: "e2", type: "host", value: "ws-1", displayName: null, riskScore: 5 } },
        ] as TypedGraphNode[],
        edges: [],
        tacticsSequence: ["execution", "lateral-movement"],
        techniquesUsed: ["T1059", "T1021"],
        hopCount: 2,
        confidence: 0.75,
        timeSpanHours: 3,
        firstAlertAt: new Date("2026-03-25T08:00:00Z"),
        lastAlertAt: new Date("2026-03-25T11:00:00Z"),
      };

      const alertDataList: AlertNodeData[] = [
        { alertId: "a1", title: "X", severity: "high", source: "CrowdStrike EDR", category: "malware", mitreTactic: "execution", mitreTechnique: "T1059", createdAt: new Date(), orgId: "org-1" },
        { alertId: "a2", title: "Y", severity: "medium", source: "Splunk SIEM", category: "intrusion", mitreTactic: "lateral-movement", mitreTechnique: "T1021", createdAt: new Date(), orgId: "org-1" },
      ];

      const fp1 = generateCampaignFingerprint(attackPath, alertDataList);
      const fp2 = generateCampaignFingerprint(attackPath, alertDataList);

      expect(fp1.fingerprint).toBe(fp2.fingerprint);
      expect(fp1.fingerprint).toHaveLength(64); // SHA-256 hex
      expect(fp1.tacticsSequence).toEqual(["execution", "lateral-movement"]);
      expect(fp1.entitySignature).toEqual(["host", "ip"]);
      expect(fp1.sourceSignature).toEqual(["CrowdStrike EDR", "Splunk SIEM"]);
    });

    it("produces different fingerprints for different inputs", () => {
      const basePath = {
        alertIds: ["a1"],
        entityIds: ["e1"],
        nodes: [
          { id: "e:e1", type: "entity" as const, data: { entityId: "e1", type: "ip", value: "10.0.0.1", displayName: null, riskScore: 10 } },
        ] as TypedGraphNode[],
        edges: [],
        tacticsSequence: ["execution"],
        techniquesUsed: ["T1059"],
        hopCount: 1,
        confidence: 0.5,
        timeSpanHours: 1,
        firstAlertAt: new Date(),
        lastAlertAt: new Date(),
      };

      const alertData1: AlertNodeData[] = [
        { alertId: "a1", title: "X", severity: "high", source: "CrowdStrike EDR", category: "malware", mitreTactic: "execution", mitreTechnique: "T1059", createdAt: new Date(), orgId: "org-1" },
      ];
      const alertData2: AlertNodeData[] = [
        { alertId: "a1", title: "X", severity: "high", source: "Splunk SIEM", category: "intrusion", mitreTactic: "execution", mitreTechnique: "T1059", createdAt: new Date(), orgId: "org-1" },
      ];

      const fp1 = generateCampaignFingerprint(basePath, alertData1);
      const fp2 = generateCampaignFingerprint(basePath, alertData2);

      expect(fp1.fingerprint).not.toBe(fp2.fingerprint);
    });
  });
});
