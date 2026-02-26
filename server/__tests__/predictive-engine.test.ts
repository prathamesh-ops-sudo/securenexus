/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unused-vars */
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { Alert } from "@shared/schema";
import { runPredictiveAnalysis } from "../predictive-engine";

function makeAlert(overrides: Partial<Alert> = {}): Alert {
  return {
    id: `alert-${Math.random().toString(36).slice(2, 8)}`,
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
    mitreTactic: null,
    mitreTechnique: null,
    status: "new",
    correlationScore: null,
    correlationClusterId: null,
    correlationReason: null,
    incidentId: null,
    detectedAt: new Date(),
    createdAt: new Date(),
    updatedAt: null,
    ...overrides,
  } as Alert;
}

function makeStorage(alerts: Alert[] = []) {
  const anomalies: any[] = [];
  const assets: any[] = [];
  const forecasts: any[] = [];
  const recommendations: any[] = [];

  return {
    getAlerts: vi.fn().mockResolvedValue(alerts),
    clearPredictiveAnomalies: vi.fn().mockResolvedValue(undefined),
    clearAttackSurfaceAssets: vi.fn().mockResolvedValue(undefined),
    clearRiskForecasts: vi.fn().mockResolvedValue(undefined),
    clearHardeningRecommendations: vi.fn().mockResolvedValue(undefined),
    createPredictiveAnomaly: vi.fn().mockImplementation((a) => {
      anomalies.push(a);
      return Promise.resolve(a);
    }),
    upsertAttackSurfaceAsset: vi.fn().mockImplementation((a) => {
      assets.push(a);
      return Promise.resolve(a);
    }),
    createRiskForecast: vi.fn().mockImplementation((f) => {
      forecasts.push(f);
      return Promise.resolve(f);
    }),
    createHardeningRecommendation: vi.fn().mockImplementation((r) => {
      recommendations.push(r);
      return Promise.resolve(r);
    }),
    getPredictiveAnomalies: vi.fn().mockImplementation(() => Promise.resolve(anomalies)),
    getRiskForecasts: vi.fn().mockImplementation(() => Promise.resolve(forecasts)),
    _anomalies: anomalies,
    _assets: assets,
    _forecasts: forecasts,
    _recommendations: recommendations,
  };
}

describe("Predictive Engine", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("runPredictiveAnalysis", () => {
    it("returns zero counts when there are no alerts", async () => {
      const storage = makeStorage([]);
      const result = await runPredictiveAnalysis("org-1", storage as any);

      expect(result.anomalies).toBe(0);
      expect(result.assets).toBe(0);
      expect(result.forecasts).toBe(0);
      expect(result.recommendations).toBe(0);
      expect(storage.clearPredictiveAnomalies).toHaveBeenCalledWith("org-1");
      expect(storage.clearAttackSurfaceAssets).toHaveBeenCalledWith("org-1");
      expect(storage.clearRiskForecasts).toHaveBeenCalledWith("org-1");
      expect(storage.clearHardeningRecommendations).toHaveBeenCalledWith("org-1");
    });

    it("clears previous data before running analysis", async () => {
      const storage = makeStorage([]);
      await runPredictiveAnalysis("org-1", storage as any);

      expect(storage.clearPredictiveAnomalies).toHaveBeenCalledBefore(storage.getAlerts);
      expect(storage.clearAttackSurfaceAssets).toHaveBeenCalledBefore(storage.getAlerts);
    });

    it("detects volume spike anomalies when recent count exceeds baseline", async () => {
      const now = new Date();
      const recentAlerts = Array.from({ length: 20 }, (_, i) =>
        makeAlert({
          category: "malware",
          severity: "high",
          createdAt: new Date(now.getTime() - i * 60 * 60 * 1000),
        }),
      );

      const priorAlerts = Array.from({ length: 6 }, (_, i) =>
        makeAlert({
          category: "malware",
          severity: "medium",
          createdAt: new Date(now.getTime() - (2 + i) * 24 * 60 * 60 * 1000),
        }),
      );

      const storage = makeStorage([...recentAlerts, ...priorAlerts]);
      const result = await runPredictiveAnalysis("org-1", storage as any);

      expect(result.anomalies).toBeGreaterThanOrEqual(1);
      expect(storage.createPredictiveAnomaly).toHaveBeenCalled();

      const calls = storage.createPredictiveAnomaly.mock.calls;
      const volumeSpikes = calls.filter((c: any) => c[0].kind === "volume_spike");
      expect(volumeSpikes.length).toBeGreaterThanOrEqual(1);
    });

    it("detects new attack vector anomalies", async () => {
      const now = new Date();
      const recentAlerts = Array.from({ length: 5 }, (_, i) =>
        makeAlert({
          category: "lateral_movement",
          severity: "critical",
          createdAt: new Date(now.getTime() - i * 60 * 60 * 1000),
        }),
      );

      const priorAlerts = Array.from({ length: 10 }, (_, i) =>
        makeAlert({
          category: "malware",
          severity: "medium",
          createdAt: new Date(now.getTime() - (2 + i) * 24 * 60 * 60 * 1000),
        }),
      );

      const storage = makeStorage([...recentAlerts, ...priorAlerts]);
      const result = await runPredictiveAnalysis("org-1", storage as any);

      const newVectorCalls = storage.createPredictiveAnomaly.mock.calls.filter((c: any) => c[0].kind === "new_vector");
      expect(newVectorCalls.length).toBeGreaterThanOrEqual(1);
    });

    it("maps attack surface entities from alerts", async () => {
      const alerts = [
        makeAlert({ sourceIp: "10.0.0.1", hostname: "server-1", severity: "critical" }),
        makeAlert({ sourceIp: "10.0.0.1", hostname: "server-1", severity: "high" }),
        makeAlert({ sourceIp: "10.0.0.2", hostname: "server-2", severity: "medium" }),
        makeAlert({ domain: "evil.com", severity: "high" }),
      ];

      const storage = makeStorage(alerts);
      const result = await runPredictiveAnalysis("org-1", storage as any);

      expect(result.assets).toBeGreaterThanOrEqual(3);
      expect(storage.upsertAttackSurfaceAsset).toHaveBeenCalled();
    });

    it("generates ransomware forecast when lateral movement + persistence detected", async () => {
      const now = new Date();
      const alerts = [
        makeAlert({
          mitreTactic: "lateral_movement",
          category: "lateral_movement",
          severity: "critical",
          createdAt: new Date(now.getTime() - 2 * 60 * 60 * 1000),
        }),
        makeAlert({
          mitreTactic: "persistence",
          category: "persistence",
          severity: "high",
          createdAt: new Date(now.getTime() - 4 * 60 * 60 * 1000),
        }),
        makeAlert({
          mitreTactic: "privilege_escalation",
          category: "privilege_escalation",
          severity: "critical",
          createdAt: new Date(now.getTime() - 6 * 60 * 60 * 1000),
        }),
      ];

      const storage = makeStorage(alerts);
      const result = await runPredictiveAnalysis("org-1", storage as any);

      expect(result.forecasts).toBeGreaterThanOrEqual(1);
      const ransomwareForecast = storage._forecasts.find((f: any) => f.forecastType === "ransomware");
      expect(ransomwareForecast).toBeDefined();
      expect(ransomwareForecast.probability).toBeGreaterThanOrEqual(0.3);
      expect(ransomwareForecast.probability).toBeLessThanOrEqual(0.95);
    });

    it("generates data exfiltration forecast when recon + C2 detected", async () => {
      const alerts = [
        makeAlert({ mitreTactic: "reconnaissance", category: "reconnaissance" }),
        makeAlert({ mitreTactic: "command_and_control", category: "command_and_control" }),
        makeAlert({ mitreTactic: "collection", category: "other" }),
      ];

      const storage = makeStorage(alerts);
      const result = await runPredictiveAnalysis("org-1", storage as any);

      const exfilForecast = storage._forecasts.find((f: any) => f.forecastType === "data_exfiltration");
      expect(exfilForecast).toBeDefined();
      expect(exfilForecast.probability).toBeGreaterThan(0.25);
    });

    it("generates phishing campaign forecast when credential access + phishing alerts", async () => {
      const alerts = [
        makeAlert({ mitreTactic: "credential_access", category: "credential_access" }),
        ...Array.from({ length: 6 }, () => makeAlert({ category: "phishing", source: "Proofpoint Email" })),
      ];

      const storage = makeStorage(alerts);
      const result = await runPredictiveAnalysis("org-1", storage as any);

      const phishingForecast = storage._forecasts.find((f: any) => f.forecastType === "phishing_campaign");
      expect(phishingForecast).toBeDefined();
      expect(phishingForecast.probability).toBeGreaterThan(0.3);
    });

    it("generates APT campaign forecast when lateral movement + C2", async () => {
      const alerts = [
        makeAlert({ mitreTactic: "lateral_movement", category: "lateral_movement" }),
        makeAlert({ mitreTactic: "command_and_control", category: "command_and_control" }),
        makeAlert({ mitreTactic: "reconnaissance", category: "reconnaissance" }),
      ];

      const storage = makeStorage(alerts);
      const result = await runPredictiveAnalysis("org-1", storage as any);

      const aptForecast = storage._forecasts.find((f: any) => f.forecastType === "apt_campaign");
      expect(aptForecast).toBeDefined();
    });

    it("generates recommendations for volume spike anomalies", async () => {
      const now = new Date();
      const alerts = Array.from({ length: 25 }, (_, i) =>
        makeAlert({
          category: "malware",
          severity: "critical",
          createdAt: new Date(now.getTime() - i * 30 * 60 * 1000),
        }),
      );

      const priorAlerts = Array.from({ length: 3 }, (_, i) =>
        makeAlert({
          category: "malware",
          severity: "low",
          createdAt: new Date(now.getTime() - (3 + i) * 24 * 60 * 60 * 1000),
        }),
      );

      const storage = makeStorage([...alerts, ...priorAlerts]);
      const result = await runPredictiveAnalysis("org-1", storage as any);

      expect(result.recommendations).toBeGreaterThanOrEqual(1);
    });

    it("generates MITRE coverage gap recommendations", async () => {
      const alerts = [makeAlert({ mitreTactic: "execution" }), makeAlert({ mitreTactic: "persistence" })];

      const storage = makeStorage(alerts);
      const result = await runPredictiveAnalysis("org-1", storage as any);

      const coverageRec = storage._recommendations.find((r: any) => r.title && r.title.includes("MITRE"));
      expect(coverageRec).toBeDefined();
    });

    it("generates suspicious IP recommendation when repeated high/critical alerts from same IP", async () => {
      const alerts = Array.from({ length: 5 }, () =>
        makeAlert({
          sourceIp: "203.0.113.99",
          severity: "critical",
        }),
      );

      const storage = makeStorage(alerts);
      const result = await runPredictiveAnalysis("org-1", storage as any);

      const ipRec = storage._recommendations.find((r: any) => r.title && r.title.includes("suspicious source IP"));
      expect(ipRec).toBeDefined();
    });
  });
});
