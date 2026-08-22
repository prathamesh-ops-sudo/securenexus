import { storage } from "./storage";

export async function calculateEndpointRisk(assetId: string): Promise<number> {
  const telemetry = await storage.getEndpointTelemetry(assetId);
  let risk = 0;

  for (const record of telemetry) {
    const value = record.metricValue as Record<string, unknown>;
    switch (record.metricType) {
      case "av_status":
        if (value.definitions === "outdated") risk += 20;
        break;
      case "patch_level": {
        const criticalPending = typeof value.critical_pending === "number" ? value.critical_pending : 0;
        risk += criticalPending * 15;
        break;
      }
      case "suspicious_processes":
        if (Array.isArray(value.processes)) risk += value.processes.length * 10;
        break;
      case "cpu":
        if (typeof value.usage === "number" && value.usage > 80) risk += 5;
        break;
      case "network_connections": {
        const suspicious = typeof value.suspicious === "number" ? value.suspicious : 0;
        risk += suspicious * 10;
        break;
      }
    }
  }

  risk = Math.max(0, Math.min(100, risk));
  await storage.updateEndpointAsset(assetId, { riskScore: risk });
  return risk;
}
