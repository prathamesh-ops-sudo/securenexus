import { IStorage } from "./storage";
import type { Alert, InsertPredictiveAnomaly, InsertAttackSurfaceAsset, InsertRiskForecast, InsertHardeningRecommendation } from "@shared/schema";

export async function runPredictiveAnalysis(orgId: string, storage: IStorage): Promise<{
  anomalies: number;
  assets: number;
  forecasts: number;
  recommendations: number;
}> {
  await storage.clearPredictiveAnomalies(orgId);
  await storage.clearAttackSurfaceAssets(orgId);
  await storage.clearRiskForecasts(orgId);
  await storage.clearHardeningRecommendations(orgId);

  const allAlerts = await storage.getAlerts(orgId);

  const anomalyCount = await detectAnomalies(orgId, allAlerts, storage);
  const assetCount = await mapAttackSurface(orgId, allAlerts, storage);
  const forecastCount = await generateForecasts(orgId, allAlerts, storage);
  const anomalies = await storage.getPredictiveAnomalies(orgId);
  const forecasts = await storage.getRiskForecasts(orgId);
  const recCount = await generateRecommendations(orgId, allAlerts, anomalies, forecasts, storage);

  return { anomalies: anomalyCount, assets: assetCount, forecasts: forecastCount, recommendations: recCount };
}

async function detectAnomalies(orgId: string, allAlerts: Alert[], storage: IStorage): Promise<number> {
  const now = new Date();
  const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

  const recentAlerts = allAlerts.filter(a => a.createdAt && new Date(a.createdAt) >= oneDayAgo);
  const weekAlerts = allAlerts.filter(a => a.createdAt && new Date(a.createdAt) >= sevenDaysAgo);
  const priorAlerts = weekAlerts.filter(a => a.createdAt && new Date(a.createdAt) < oneDayAgo);

  let count = 0;

  const categoryCount24h = groupCount(recentAlerts, a => a.category || "other");
  const categoryCountWeek = groupCount(priorAlerts, a => a.category || "other");
  const daysInPrior = Math.max(1, (oneDayAgo.getTime() - sevenDaysAgo.getTime()) / (24 * 60 * 60 * 1000));

  for (const [category, current] of Object.entries(categoryCount24h)) {
    const weekTotal = categoryCountWeek[category] || 0;
    const dailyAvg = weekTotal / daysInPrior;
    const dailyCounts = getDailyCounts(priorAlerts.filter(a => (a.category || "other") === category), sevenDaysAgo, oneDayAgo);
    const stddev = computeStddev(dailyCounts);
    const zScore = stddev > 0 ? (current - dailyAvg) / stddev : (current > dailyAvg ? 3 : 0);

    if (current > dailyAvg + 2.5 * stddev && current > 2) {
      const topSignals = recentAlerts
        .filter(a => (a.category || "other") === category)
        .slice(0, 5)
        .map(a => ({ id: a.id, title: a.title }));

      const anomaly: InsertPredictiveAnomaly = {
        orgId,
        kind: "volume_spike",
        metric: `category:${category}`,
        baseline: Math.round(dailyAvg * 100) / 100,
        current,
        zScore: Math.round(zScore * 100) / 100,
        severity: zScore > 4 ? "critical" : zScore > 3 ? "high" : "medium",
        windowStart: oneDayAgo,
        windowEnd: now,
        topSignals,
        description: `Alert volume for ${category} spiked to ${current} (baseline: ${dailyAvg.toFixed(1)}/day, z-score: ${zScore.toFixed(2)})`,
      };
      await storage.createPredictiveAnomaly(anomaly);
      count++;
    }
  }

  for (const [category, _current] of Object.entries(categoryCount24h)) {
    if (!categoryCountWeek[category]) {
      const topSignals = recentAlerts
        .filter(a => (a.category || "other") === category)
        .slice(0, 5)
        .map(a => ({ id: a.id, title: a.title }));

      const anomaly: InsertPredictiveAnomaly = {
        orgId,
        kind: "new_vector",
        metric: `category:${category}`,
        baseline: 0,
        current: categoryCount24h[category],
        zScore: 5,
        severity: "high",
        windowStart: oneDayAgo,
        windowEnd: now,
        topSignals,
        description: `New attack category "${category}" detected with ${categoryCount24h[category]} alerts, not seen in prior 7 days`,
      };
      await storage.createPredictiveAnomaly(anomaly);
      count++;
    }
  }

  const offHourRecent = recentAlerts.filter(a => {
    if (!a.createdAt) return false;
    const hour = new Date(a.createdAt).getUTCHours();
    return hour >= 0 && hour < 6;
  });
  const offHourPrior = priorAlerts.filter(a => {
    if (!a.createdAt) return false;
    const hour = new Date(a.createdAt).getUTCHours();
    return hour >= 0 && hour < 6;
  });

  const recentOffRatio = recentAlerts.length > 0 ? offHourRecent.length / recentAlerts.length : 0;
  const priorOffRatio = priorAlerts.length > 0 ? offHourPrior.length / priorAlerts.length : 0.25;

  if (recentOffRatio > priorOffRatio * 2 && offHourRecent.length > 3) {
    const anomaly: InsertPredictiveAnomaly = {
      orgId,
      kind: "timing_anomaly",
      metric: "off_hours_ratio",
      baseline: Math.round(priorOffRatio * 100) / 100,
      current: Math.round(recentOffRatio * 100) / 100,
      zScore: Math.round(((recentOffRatio - priorOffRatio) / Math.max(priorOffRatio, 0.01)) * 100) / 100,
      severity: recentOffRatio > 0.5 ? "high" : "medium",
      windowStart: oneDayAgo,
      windowEnd: now,
      topSignals: offHourRecent.slice(0, 5).map(a => ({ id: a.id, title: a.title })),
      description: `Off-hours alert ratio increased to ${(recentOffRatio * 100).toFixed(1)}% (baseline: ${(priorOffRatio * 100).toFixed(1)}%)`,
    };
    await storage.createPredictiveAnomaly(anomaly);
    count++;
  }

  const severityCount24h = groupCount(recentAlerts, a => a.severity);
  const severityCountWeek = groupCount(priorAlerts, a => a.severity);
  const criticalRecent = severityCount24h["critical"] || 0;
  const criticalPrior = (severityCountWeek["critical"] || 0) / daysInPrior;

  if (criticalRecent > criticalPrior * 2 && criticalRecent > 2) {
    const zScore = criticalPrior > 0 ? (criticalRecent - criticalPrior) / Math.max(criticalPrior, 1) : criticalRecent;
    const anomaly: InsertPredictiveAnomaly = {
      orgId,
      kind: "severity_escalation",
      metric: "critical_alerts",
      baseline: Math.round(criticalPrior * 100) / 100,
      current: criticalRecent,
      zScore: Math.round(zScore * 100) / 100,
      severity: "critical",
      windowStart: oneDayAgo,
      windowEnd: now,
      topSignals: recentAlerts.filter(a => a.severity === "critical").slice(0, 5).map(a => ({ id: a.id, title: a.title })),
      description: `Critical alert count spiked to ${criticalRecent} (baseline: ${criticalPrior.toFixed(1)}/day)`,
    };
    await storage.createPredictiveAnomaly(anomaly);
    count++;
  }

  return count;
}

async function mapAttackSurface(orgId: string, allAlerts: Alert[], storage: IStorage): Promise<number> {
  const entityMap = new Map<string, {
    entityType: string;
    entityValue: string;
    severities: string[];
    sources: Set<string>;
    firstSeen: Date;
    lastSeen: Date;
    alertCount: number;
  }>();

  for (const alert of allAlerts) {
    const extractedEntities: { type: string; value: string }[] = [];

    if (alert.sourceIp) extractedEntities.push({ type: "ip", value: alert.sourceIp });
    if (alert.destIp) extractedEntities.push({ type: "ip", value: alert.destIp });
    if (alert.hostname) extractedEntities.push({ type: "host", value: alert.hostname });
    if (alert.domain) extractedEntities.push({ type: "domain", value: alert.domain });
    if (alert.fileHash) extractedEntities.push({ type: "file_hash", value: alert.fileHash });
    if (alert.url) extractedEntities.push({ type: "url", value: alert.url });
    if (alert.userId) extractedEntities.push({ type: "user", value: alert.userId });

    const alertDate = alert.createdAt ? new Date(alert.createdAt) : new Date();

    for (const entity of extractedEntities) {
      const key = `${entity.type}:${entity.value}`;
      const existing = entityMap.get(key);
      if (existing) {
        existing.severities.push(alert.severity);
        existing.sources.add(alert.source);
        existing.alertCount++;
        if (alertDate < existing.firstSeen) existing.firstSeen = alertDate;
        if (alertDate > existing.lastSeen) existing.lastSeen = alertDate;
      } else {
        entityMap.set(key, {
          entityType: entity.type,
          entityValue: entity.value,
          severities: [alert.severity],
          sources: new Set([alert.source]),
          firstSeen: alertDate,
          lastSeen: alertDate,
          alertCount: 1,
        });
      }
    }
  }

  let count = 0;
  const now = new Date();

  for (const [_key, data] of entityMap) {
    const criticalCount = data.severities.filter(s => s === "critical").length;
    const highCount = data.severities.filter(s => s === "high").length;
    const mediumCount = data.severities.filter(s => s === "medium").length;
    const lowCount = data.severities.filter(s => s === "low").length;

    const rawScore = criticalCount * 4 + highCount * 3 + mediumCount * 2 + lowCount * 1;
    const daysSinceLastSeen = Math.max(1, (now.getTime() - data.lastSeen.getTime()) / (24 * 60 * 60 * 1000));
    const recencyFactor = Math.max(0.1, 1 / Math.sqrt(daysSinceLastSeen));
    const riskScore = Math.round(rawScore * recencyFactor * 100) / 100;

    const asset: InsertAttackSurfaceAsset = {
      orgId,
      entityType: data.entityType,
      entityValue: data.entityValue,
      firstSeenAt: data.firstSeen,
      lastSeenAt: data.lastSeen,
      riskScore,
      alertCount: data.alertCount,
      criticalCount,
      exposures: { critical: criticalCount, high: highCount, medium: mediumCount, low: lowCount },
      relatedSources: Array.from(data.sources),
    };
    await storage.upsertAttackSurfaceAsset(asset);
    count++;
  }

  return count;
}

async function generateForecasts(orgId: string, allAlerts: Alert[], storage: IStorage): Promise<number> {
  let count = 0;
  const now = new Date();
  const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  const threeDaysAgo = new Date(now.getTime() - 3 * 24 * 60 * 60 * 1000);

  const recentAlerts = allAlerts.filter(a => a.createdAt && new Date(a.createdAt) >= oneDayAgo);
  const priorAlerts = allAlerts.filter(a => a.createdAt && new Date(a.createdAt) >= threeDaysAgo && new Date(a.createdAt!) < oneDayAgo);

  const alertVelocity = priorAlerts.length > 0 ? recentAlerts.length / (priorAlerts.length / 2) : recentAlerts.length > 0 ? 2 : 0;

  const tactics = new Set(allAlerts.filter(a => a.mitreTactic).map(a => a.mitreTactic!.toLowerCase()));
  const categories = new Set(allAlerts.map(a => a.category || "other"));

  const hasLateralMovement = tactics.has("lateral_movement") || tactics.has("lateral movement") || categories.has("lateral_movement");
  const hasPrivilegeEscalation = tactics.has("privilege_escalation") || tactics.has("privilege escalation") || categories.has("privilege_escalation");
  const hasPersistence = tactics.has("persistence");
  const hasReconnaissance = tactics.has("reconnaissance") || categories.has("reconnaissance");
  const hasCollection = tactics.has("collection");
  const hasC2 = tactics.has("command_and_control") || tactics.has("command and control") || categories.has("command_and_control");
  const hasCredentialAccess = tactics.has("credential_access") || tactics.has("credential access") || categories.has("credential_access");
  const hasExfiltration = tactics.has("exfiltration") || categories.has("data_exfiltration");

  const baseWindow = alertVelocity > 2 ? 24 : alertVelocity > 1 ? 48 : 72;

  if (hasLateralMovement || hasPrivilegeEscalation || hasPersistence) {
    const factors = [hasLateralMovement && "lateral_movement", hasPrivilegeEscalation && "privilege_escalation", hasPersistence && "persistence"].filter(Boolean);
    const probability = Math.min(0.95, 0.3 + factors.length * 0.2 + (alertVelocity > 1.5 ? 0.1 : 0));
    const forecast: InsertRiskForecast = {
      orgId,
      forecastType: "ransomware",
      probability: Math.round(probability * 100) / 100,
      predictedWindowHours: baseWindow,
      confidence: Math.round(Math.min(0.9, 0.4 + factors.length * 0.15) * 100) / 100,
      drivers: factors,
      description: `Ransomware risk based on ${factors.join(", ")} tactics detected. Alert velocity: ${alertVelocity.toFixed(1)}x`,
      status: "active",
    };
    await storage.createRiskForecast(forecast);
    count++;
  }

  if (hasReconnaissance || hasCollection || hasC2 || hasExfiltration) {
    const factors = [hasReconnaissance && "reconnaissance", hasCollection && "collection", hasC2 && "command_and_control", hasExfiltration && "data_exfiltration"].filter(Boolean);
    const probability = Math.min(0.95, 0.25 + factors.length * 0.18);
    const forecast: InsertRiskForecast = {
      orgId,
      forecastType: "data_exfiltration",
      probability: Math.round(probability * 100) / 100,
      predictedWindowHours: baseWindow,
      confidence: Math.round(Math.min(0.85, 0.35 + factors.length * 0.12) * 100) / 100,
      drivers: factors,
      description: `Data exfiltration risk based on ${factors.join(", ")} indicators`,
      status: "active",
    };
    await storage.createRiskForecast(forecast);
    count++;
  }

  const phishingAlerts = allAlerts.filter(a => a.category === "phishing" || (a.source && a.source.toLowerCase().includes("email")));
  if (hasCredentialAccess || phishingAlerts.length > 5) {
    const factors = [hasCredentialAccess && "credential_access", phishingAlerts.length > 5 && `${phishingAlerts.length}_phishing_alerts`].filter(Boolean);
    const probability = Math.min(0.9, 0.3 + (hasCredentialAccess ? 0.25 : 0) + Math.min(0.3, phishingAlerts.length * 0.03));
    const forecast: InsertRiskForecast = {
      orgId,
      forecastType: "phishing_campaign",
      probability: Math.round(probability * 100) / 100,
      predictedWindowHours: baseWindow * 2,
      confidence: Math.round(Math.min(0.8, 0.4 + (phishingAlerts.length > 10 ? 0.2 : 0.1)) * 100) / 100,
      drivers: factors,
      description: `Phishing campaign risk based on ${factors.join(", ")}`,
      status: "active",
    };
    await storage.createRiskForecast(forecast);
    count++;
  }

  if (hasLateralMovement && hasC2) {
    const factors = ["lateral_movement", "command_and_control", hasReconnaissance && "reconnaissance", hasPrivilegeEscalation && "privilege_escalation"].filter(Boolean);
    const probability = Math.min(0.9, 0.35 + factors.length * 0.12);
    const forecast: InsertRiskForecast = {
      orgId,
      forecastType: "apt_campaign",
      probability: Math.round(probability * 100) / 100,
      predictedWindowHours: baseWindow * 3,
      confidence: Math.round(Math.min(0.75, 0.3 + factors.length * 0.1) * 100) / 100,
      drivers: factors,
      description: `APT campaign risk: multi-stage attack with ${factors.join(", ")}`,
      status: "active",
    };
    await storage.createRiskForecast(forecast);
    count++;
  }

  if (hasLateralMovement && hasPrivilegeEscalation) {
    const forecast: InsertRiskForecast = {
      orgId,
      forecastType: "lateral_movement",
      probability: Math.round(Math.min(0.85, 0.5 + (alertVelocity > 1.5 ? 0.15 : 0)) * 100) / 100,
      predictedWindowHours: baseWindow,
      confidence: 0.6,
      drivers: ["lateral_movement", "privilege_escalation"],
      description: "Active lateral movement with privilege escalation detected",
      status: "active",
    };
    await storage.createRiskForecast(forecast);
    count++;
  }

  return count;
}

async function generateRecommendations(
  orgId: string,
  allAlerts: Alert[],
  anomalies: { kind: string; metric: string; severity: string; description: string | null }[],
  forecasts: { forecastType: string; probability: number; description: string | null }[],
  storage: IStorage
): Promise<number> {
  let count = 0;

  for (const anomaly of anomalies) {
    if (anomaly.kind === "volume_spike") {
      const category = anomaly.metric.replace("category:", "");
      const rec: InsertHardeningRecommendation = {
        orgId,
        title: `Investigate alert volume increase in ${category}`,
        rationale: anomaly.description || `Significant volume spike detected for ${category} alerts`,
        priority: anomaly.severity === "critical" ? "critical" : "high",
        category: "investigation",
        relatedEntities: [{ metric: anomaly.metric }],
        status: "open",
      };
      await storage.createHardeningRecommendation(rec);
      count++;
    }
    if (anomaly.kind === "new_vector") {
      const category = anomaly.metric.replace("category:", "");
      const rec: InsertHardeningRecommendation = {
        orgId,
        title: `Analyze new attack vector: ${category}`,
        rationale: `Previously unseen attack category detected. Immediate investigation recommended.`,
        priority: "high",
        category: "investigation",
        relatedEntities: [{ metric: anomaly.metric }],
        status: "open",
      };
      await storage.createHardeningRecommendation(rec);
      count++;
    }
    if (anomaly.kind === "timing_anomaly") {
      const rec: InsertHardeningRecommendation = {
        orgId,
        title: "Investigate unusual off-hours activity",
        rationale: anomaly.description || "Elevated alert activity during off-hours (00:00-06:00 UTC) suggests automated attacks or compromised systems.",
        priority: "high",
        category: "monitoring",
        status: "open",
      };
      await storage.createHardeningRecommendation(rec);
      count++;
    }
    if (anomaly.kind === "severity_escalation") {
      const rec: InsertHardeningRecommendation = {
        orgId,
        title: "Address critical alert surge",
        rationale: anomaly.description || "Significant increase in critical severity alerts detected",
        priority: "critical",
        category: "incident_response",
        status: "open",
      };
      await storage.createHardeningRecommendation(rec);
      count++;
    }
  }

  for (const forecast of forecasts) {
    if (forecast.forecastType === "ransomware" && forecast.probability > 0.5) {
      const rec: InsertHardeningRecommendation = {
        orgId,
        title: "Enable endpoint isolation readiness",
        rationale: `Ransomware probability at ${(forecast.probability * 100).toFixed(0)}%. Prepare endpoint isolation and backup verification.`,
        priority: "critical",
        category: "endpoint_security",
        relatedForecasts: [{ type: forecast.forecastType, probability: forecast.probability }],
        status: "open",
      };
      await storage.createHardeningRecommendation(rec);
      count++;
    }
    if (forecast.forecastType === "data_exfiltration" && forecast.probability > 0.4) {
      const rec: InsertHardeningRecommendation = {
        orgId,
        title: "Enhance DLP controls and monitor outbound traffic",
        rationale: `Data exfiltration probability at ${(forecast.probability * 100).toFixed(0)}%. Review DLP policies and monitor large data transfers.`,
        priority: "high",
        category: "data_protection",
        relatedForecasts: [{ type: forecast.forecastType, probability: forecast.probability }],
        status: "open",
      };
      await storage.createHardeningRecommendation(rec);
      count++;
    }
    if (forecast.forecastType === "phishing_campaign" && forecast.probability > 0.4) {
      const rec: InsertHardeningRecommendation = {
        orgId,
        title: "Strengthen email security and user awareness",
        rationale: `Phishing campaign probability at ${(forecast.probability * 100).toFixed(0)}%. Tighten email filtering and issue security advisory.`,
        priority: "high",
        category: "email_security",
        relatedForecasts: [{ type: forecast.forecastType, probability: forecast.probability }],
        status: "open",
      };
      await storage.createHardeningRecommendation(rec);
      count++;
    }
    if (forecast.forecastType === "apt_campaign" && forecast.probability > 0.3) {
      const rec: InsertHardeningRecommendation = {
        orgId,
        title: "Initiate incident containment procedures",
        rationale: `APT campaign indicators detected with ${(forecast.probability * 100).toFixed(0)}% probability. Activate incident response team.`,
        priority: "critical",
        category: "incident_response",
        relatedForecasts: [{ type: forecast.forecastType, probability: forecast.probability }],
        status: "open",
      };
      await storage.createHardeningRecommendation(rec);
      count++;
    }
  }

  const tactics = new Set(allAlerts.filter(a => a.mitreTactic).map(a => a.mitreTactic!.toLowerCase()));
  const allTactics = ["initial_access", "execution", "persistence", "privilege_escalation", "defense_evasion",
    "credential_access", "discovery", "lateral_movement", "collection", "command_and_control", "exfiltration", "impact"];
  const missingTactics = allTactics.filter(t => !tactics.has(t) && !tactics.has(t.replace(/_/g, " ")));

  if (missingTactics.length > 0 && missingTactics.length < allTactics.length) {
    const rec: InsertHardeningRecommendation = {
      orgId,
      title: "Review MITRE ATT&CK coverage gaps",
      rationale: `Detection coverage missing for: ${missingTactics.slice(0, 5).join(", ")}. Consider adding detection rules for these tactics.`,
      priority: "medium",
      category: "detection_engineering",
      relatedEntities: missingTactics.map(t => ({ tactic: t })),
      status: "open",
    };
    await storage.createHardeningRecommendation(rec);
    count++;
  }

  const highRiskIps = allAlerts
    .filter(a => a.sourceIp && (a.severity === "critical" || a.severity === "high"))
    .reduce((acc, a) => {
      const ip = a.sourceIp!;
      acc.set(ip, (acc.get(ip) || 0) + 1);
      return acc;
    }, new Map<string, number>());

  const suspiciousIps = Array.from(highRiskIps.entries()).filter(([_, cnt]) => cnt >= 3);
  if (suspiciousIps.length > 0) {
    const rec: InsertHardeningRecommendation = {
      orgId,
      title: "Block or investigate suspicious source IPs",
      rationale: `${suspiciousIps.length} source IP(s) linked to multiple high/critical alerts: ${suspiciousIps.slice(0, 5).map(([ip, cnt]) => `${ip} (${cnt} alerts)`).join(", ")}`,
      priority: "high",
      category: "network_security",
      relatedEntities: suspiciousIps.slice(0, 10).map(([ip, cnt]) => ({ ip, alertCount: cnt })),
      status: "open",
    };
    await storage.createHardeningRecommendation(rec);
    count++;
  }

  return count;
}

function groupCount<T>(items: T[], keyFn: (item: T) => string): Record<string, number> {
  const result: Record<string, number> = {};
  for (const item of items) {
    const key = keyFn(item);
    result[key] = (result[key] || 0) + 1;
  }
  return result;
}

function getDailyCounts(alerts: Alert[], start: Date, end: Date): number[] {
  const days = Math.ceil((end.getTime() - start.getTime()) / (24 * 60 * 60 * 1000));
  const counts = new Array(days).fill(0);
  for (const alert of alerts) {
    if (!alert.createdAt) continue;
    const dayIndex = Math.floor((new Date(alert.createdAt).getTime() - start.getTime()) / (24 * 60 * 60 * 1000));
    if (dayIndex >= 0 && dayIndex < days) {
      counts[dayIndex]++;
    }
  }
  return counts;
}

function computeStddev(values: number[]): number {
  if (values.length < 2) return 0;
  const mean = values.reduce((s, v) => s + v, 0) / values.length;
  const variance = values.reduce((s, v) => s + (v - mean) ** 2, 0) / values.length;
  return Math.sqrt(variance);
}
