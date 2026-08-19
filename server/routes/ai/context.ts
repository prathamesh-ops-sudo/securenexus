import type { Express, Request, Response } from "express";
import { getOrgId, logger, storage } from "../shared";
import { isAuthenticated } from "../../auth";
import { resolveOrgContext, requireOrgId, requireMinRole } from "../../rbac";
import { db } from "../../db";
import { alerts, incidents, entities, iocEntries, endpointTelemetry } from "@shared/schema";
import { count, eq } from "drizzle-orm";

const log = logger.child("routes-ai-context");

export function registerAiContextRoutes(app: Express): void {
  // Context Window Optimization
  app.post(
    "/api/ai/context-optimization",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { query, maxTokens = 4096, sources = [] } = req.body;

        if (!query || typeof query !== "string") {
          return res.status(400).json({ message: "query string is required" });
        }

        const availableSources = [
          "alerts",
          "incidents",
          "entities",
          "threat_intel",
          "osint",
          "ueba",
          "endpoint_telemetry",
          "network_flows",
          "cloud_configs",
        ];
        const selectedSources =
          sources.length > 0 ? sources.filter((s: string) => availableSources.includes(s)) : availableSources;

        const tokenBudget = Math.min(Math.max(maxTokens, 1024), 32768);
        const perSourceBudget = Math.floor(tokenBudget / selectedSources.length);

        // Query real document counts per source from database
        const [alertCount, incidentCount, entityCount, iocCount, telemetryCount] = await Promise.all([
          db
            .select({ value: count() })
            .from(alerts)
            .where(eq(alerts.orgId, orgId))
            .then((r) => r[0]?.value ?? 0),
          db
            .select({ value: count() })
            .from(incidents)
            .where(eq(incidents.orgId, orgId))
            .then((r) => r[0]?.value ?? 0),
          db
            .select({ value: count() })
            .from(entities)
            .where(eq(entities.orgId, orgId))
            .then((r) => r[0]?.value ?? 0),
          db
            .select({ value: count() })
            .from(iocEntries)
            .where(eq(iocEntries.orgId, orgId))
            .then((r) => r[0]?.value ?? 0),
          db
            .select({ value: count() })
            .from(endpointTelemetry)
            .where(eq(endpointTelemetry.orgId, orgId))
            .then((r) => r[0]?.value ?? 0),
        ]);

        const sourceCountMap: Record<string, number> = {
          alerts: alertCount,
          incidents: incidentCount,
          entities: entityCount,
          threat_intel: iocCount,
          endpoint_telemetry: telemetryCount,
          osint: 0,
          ueba: 0,
          network_flows: 0,
          cloud_configs: 0,
        };

        const contextPlan: {
          source: string;
          tokenBudget: number;
          relevanceScore: number;
          documentCount: number;
          strategy: string;
        }[] = selectedSources.map((source: string) => {
          const relevanceKeywords: Record<string, string[]> = {
            alerts: ["alert", "detection", "rule", "trigger", "fire"],
            incidents: ["incident", "breach", "attack", "compromise"],
            entities: ["entity", "user", "host", "ip", "domain"],
            threat_intel: ["threat", "ioc", "indicator", "malware", "apt"],
            osint: ["osint", "open source", "feed", "public"],
            ueba: ["behavior", "anomaly", "baseline", "insider"],
            endpoint_telemetry: ["endpoint", "process", "file", "registry"],
            network_flows: ["network", "traffic", "flow", "connection"],
            cloud_configs: ["cloud", "config", "policy", "iam", "s3"],
          };

          const keywords = relevanceKeywords[source] || [];
          const queryLower = query.toLowerCase();
          const matchCount = keywords.filter((kw) => queryLower.includes(kw)).length;
          const relevanceScore = Math.min(1.0, 0.3 + matchCount * 0.2);

          return {
            source,
            tokenBudget: Math.round(perSourceBudget * relevanceScore),
            relevanceScore: Math.round(relevanceScore * 100) / 100,
            documentCount: sourceCountMap[source] ?? 0,
            strategy: relevanceScore >= 0.7 ? "full_content" : relevanceScore >= 0.5 ? "summary" : "metadata_only",
          };
        });

        contextPlan.sort((a, b) => b.relevanceScore - a.relevanceScore);
        const totalAllocated = contextPlan.reduce((s, c) => s + c.tokenBudget, 0);
        const utilizationRate = Math.round((totalAllocated / tokenBudget) * 100) / 100;

        res.json({
          query,
          maxTokens: tokenBudget,
          totalAllocated,
          utilizationRate,
          sourceCount: contextPlan.length,
          contextPlan,
          optimizationNotes: [
            "High-relevance sources receive full document content",
            "Medium-relevance sources receive summarized content",
            "Low-relevance sources provide metadata only for reference",
            `Token budget: ${tokenBudget} tokens across ${contextPlan.length} sources`,
          ],
        });
      } catch (error: any) {
        logger.child("ai").error("Context optimization error", { error: String(error) });
        res.status(500).json({ message: "Failed to optimize context window" });
      }
    },
  );

  // Hallucination Detection
  app.post(
    "/api/ai/hallucination-check",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { aiOutput, incidentId } = req.body;

        if (!aiOutput || typeof aiOutput !== "string") {
          return res.status(400).json({ message: "aiOutput string is required" });
        }

        let groundTruthAlerts: any[] = [];
        let incidentData: any = null;
        if (incidentId) {
          incidentData = await storage.getIncident(incidentId);
          if (incidentData && incidentData.orgId === orgId) {
            groundTruthAlerts = await storage.getAlertsByIncident(incidentId);
          }
        }

        const ipPattern = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
        const claimedIps = Array.from(new Set(aiOutput.match(ipPattern) || []));
        const knownIps = new Set(groundTruthAlerts.flatMap((a) => [a.sourceIp, a.destIp].filter(Boolean)));

        const severityPattern = /\b(critical|high|medium|low|informational)\b/gi;
        const claimedSeverities = Array.from(
          new Set((aiOutput.match(severityPattern) || []).map((s: string) => s.toLowerCase())),
        );
        const knownSeverities = new Set(groundTruthAlerts.map((a) => a.severity?.toLowerCase()).filter(Boolean));

        const findings: { claim: string; verified: boolean; source: string; explanation: string }[] = [];

        for (const ip of claimedIps) {
          const isKnown = knownIps.has(ip);
          findings.push({
            claim: `IP address ${ip} referenced in analysis`,
            verified: isKnown,
            source: isKnown ? "correlated_alerts" : "unverified",
            explanation: isKnown
              ? `IP ${ip} appears in ${groundTruthAlerts.filter((a) => a.sourceIp === ip || a.destIp === ip).length} alert(s)`
              : `IP ${ip} not found in any correlated alert data — possible hallucination`,
          });
        }

        const mitrePattern = /T\d{4}(?:\.\d{3})?/g;
        const claimedTechniques = Array.from(new Set(aiOutput.match(mitrePattern) || []));
        const knownTechniques = new Set(groundTruthAlerts.map((a) => a.mitreTechnique).filter(Boolean));

        for (const tech of claimedTechniques) {
          const isKnown = knownTechniques.has(tech);
          findings.push({
            claim: `MITRE technique ${tech} referenced`,
            verified: isKnown,
            source: isKnown ? "alert_mitre_mapping" : "ai_inference",
            explanation: isKnown
              ? `${tech} mapped from correlated alerts`
              : `${tech} inferred by AI — not directly observed in alert data`,
          });
        }

        const verifiedCount = findings.filter((f) => f.verified).length;
        const totalClaims = findings.length;
        const verificationRate = totalClaims > 0 ? Math.round((verifiedCount / totalClaims) * 100) / 100 : 1.0;
        const riskLevel = verificationRate >= 0.8 ? "low" : verificationRate >= 0.5 ? "medium" : "high";

        res.json({
          verificationRate,
          riskLevel,
          totalClaims,
          verifiedClaims: verifiedCount,
          unverifiedClaims: totalClaims - verifiedCount,
          findings,
          groundTruthSummary: {
            alertCount: groundTruthAlerts.length,
            knownIps: Array.from(knownIps),
            knownTechniques: Array.from(knownTechniques),
            knownSeverities: Array.from(knownSeverities),
          },
          recommendation:
            riskLevel === "high"
              ? "High hallucination risk — review AI output carefully against source data"
              : riskLevel === "medium"
                ? "Some claims unverified — analyst review recommended"
                : "AI output well-grounded in source data",
        });
      } catch (error: any) {
        logger.child("ai").error("Hallucination check error", { error: String(error) });
        res.status(500).json({ message: "Failed to perform hallucination check" });
      }
    },
  );
}
