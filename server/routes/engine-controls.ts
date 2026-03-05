import type { Express } from "express";
import { getOrgId, logger, storage } from "./shared";
import { isAuthenticated } from "../auth";
import { requireMinRole, resolveOrgContext } from "../rbac";
import { runPredictiveAnalysis } from "../predictive-engine";
import { maskPiiInAlert, detectPiiFields } from "../pii-engine";
import { calculatePostureScore } from "../posture-engine";
import { getAvailableRollbacks, canRollback, getRollbackAction, executeRollback } from "../rollback-engine";
import type { Alert } from "@shared/schema";

// ─── Per-org in-memory policy store ─────────────────────────────────────────

interface PredictivePolicy {
  enabled: boolean;
  zScoreThreshold: number;       // default 2.5
  minAlertsForAnomaly: number;   // default 2
  criticalMultiplier: number;    // default 2
  offHoursStart: number;         // UTC hour 0-23, default 0
  offHoursEnd: number;           // UTC hour 0-23, default 6
  offHoursRatioMultiplier: number; // default 2
}

interface PiiPolicy {
  enabled: boolean;
  maskSourceIp: boolean;
  maskDestIp: boolean;
  maskUserId: boolean;
  maskHostname: boolean;
  maskEmailsInText: boolean;
  maskIpsInText: boolean;
}

interface PosturePolicy {
  enabled: boolean;
  cspmWeight: number;       // default 0.35
  endpointWeight: number;   // default 0.30
  incidentWeight: number;   // default 0.20
  complianceWeight: number; // default 0.15
  criticalFindingPenalty: number;  // default 10
  highFindingPenalty: number;      // default 5
  mediumFindingPenalty: number;    // default 2
  lowFindingPenalty: number;       // default 1
  criticalIncidentPenalty: number; // default 15
  highIncidentPenalty: number;     // default 10
  mediumIncidentPenalty: number;   // default 5
  lowIncidentPenalty: number;      // default 2
}

interface RollbackPolicy {
  enabled: boolean;
  requireConfirmation: boolean;
  allowedActions: string[];
}

interface OrgEngineState {
  predictive: PredictivePolicy;
  pii: PiiPolicy;
  posture: PosturePolicy;
  rollback: RollbackPolicy;
  lastRuns: Record<string, { at: Date; durationMs: number; summary: Record<string, unknown> } | null>;
}

const DEFAULT_PREDICTIVE: PredictivePolicy = {
  enabled: true,
  zScoreThreshold: 2.5,
  minAlertsForAnomaly: 2,
  criticalMultiplier: 2,
  offHoursStart: 0,
  offHoursEnd: 6,
  offHoursRatioMultiplier: 2,
};

const DEFAULT_PII: PiiPolicy = {
  enabled: true,
  maskSourceIp: true,
  maskDestIp: true,
  maskUserId: true,
  maskHostname: true,
  maskEmailsInText: true,
  maskIpsInText: true,
};

const DEFAULT_POSTURE: PosturePolicy = {
  enabled: true,
  cspmWeight: 0.35,
  endpointWeight: 0.30,
  incidentWeight: 0.20,
  complianceWeight: 0.15,
  criticalFindingPenalty: 10,
  highFindingPenalty: 5,
  mediumFindingPenalty: 2,
  lowFindingPenalty: 1,
  criticalIncidentPenalty: 15,
  highIncidentPenalty: 10,
  mediumIncidentPenalty: 5,
  lowIncidentPenalty: 2,
};

const DEFAULT_ROLLBACK: RollbackPolicy = {
  enabled: true,
  requireConfirmation: true,
  allowedActions: ["isolate_host", "block_ip", "block_domain", "quarantine_file", "disable_user", "kill_process"],
};

const orgStates = new Map<string, OrgEngineState>();

function getOrCreateOrgState(orgId: string): OrgEngineState {
  if (!orgStates.has(orgId)) {
    orgStates.set(orgId, {
      predictive: { ...DEFAULT_PREDICTIVE },
      pii: { ...DEFAULT_PII },
      posture: { ...DEFAULT_POSTURE },
      rollback: { ...DEFAULT_ROLLBACK },
      lastRuns: { predictive: null, pii: null, posture: null, rollback: null },
    });
  }
  return orgStates.get(orgId)!;
}

// ─── Rollback action map (mirrors rollback-engine.ts) ───────────────────────
const ROLLBACK_ACTION_MAP: Record<string, string> = {
  isolate_host: "unisolate_host",
  block_ip: "unblock_ip",
  block_domain: "unblock_domain",
  quarantine_file: "restore_file",
  disable_user: "enable_user",
  kill_process: "restart_process",
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

function validateWeights(policy: Partial<PosturePolicy>): string | null {
  const { cspmWeight = 0.35, endpointWeight = 0.30, incidentWeight = 0.20, complianceWeight = 0.15 } = policy;
  const sum = cspmWeight + endpointWeight + incidentWeight + complianceWeight;
  if (Math.abs(sum - 1.0) > 0.001) {
    return `Posture weights must sum to 1.0, got ${sum.toFixed(3)}`;
  }
  return null;
}

// ─── Route registration ──────────────────────────────────────────────────────

export function registerEngineControlsRoutes(app: Express): void {

  // ── GET /api/engine-controls/status ──────────────────────────────────────
  app.get(
    "/api/engine-controls/status",
    isAuthenticated,
    resolveOrgContext,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const state = getOrCreateOrgState(orgId);

        const [rollbacks, postureScores] = await Promise.all([
          getAvailableRollbacks(orgId),
          storage.getPostureScores(orgId),
        ]);

        const latestPosture = postureScores.length > 0
          ? postureScores[postureScores.length - 1]
          : null;

        res.json({
          engines: {
            predictive: {
              enabled: state.predictive.enabled,
              lastRun: state.lastRuns.predictive,
              description: "Detects anomalies, maps attack surface, generates risk forecasts and hardening recommendations",
              capabilities: ["anomaly_detection", "attack_surface_mapping", "risk_forecasting", "recommendations"],
            },
            pii: {
              enabled: state.pii.enabled,
              lastRun: state.lastRuns.pii,
              description: "Masks PII fields (IP addresses, user IDs, hostnames, emails) in alert data",
              capabilities: ["ip_masking", "user_id_masking", "hostname_masking", "email_masking"],
            },
            posture: {
              enabled: state.posture.enabled,
              lastRun: state.lastRuns.posture,
              latestScore: latestPosture ? {
                overall: latestPosture.overallScore,
                cspm: latestPosture.cspmScore,
                endpoint: latestPosture.endpointScore,
                incident: latestPosture.incidentScore,
                compliance: latestPosture.complianceScore,
              } : null,
              description: "Calculates weighted security posture score from CSPM findings, endpoints, incidents, and compliance",
              capabilities: ["cspm_scoring", "endpoint_scoring", "incident_scoring", "compliance_scoring"],
            },
            rollback: {
              enabled: state.rollback.enabled,
              lastRun: state.lastRuns.rollback,
              pendingRollbacks: rollbacks.length,
              availableActions: Object.keys(ROLLBACK_ACTION_MAP),
              description: "Tracks reversible response actions and executes rollback operations",
              capabilities: ["action_reversal", "rollback_tracking", "safe_undo"],
            },
          },
        });
      } catch (err: any) {
        logger.child("engine-controls").error("Status fetch error", { error: String(err) });
        res.status(500).json({ message: "Failed to fetch engine status" });
      }
    }
  );

  // ── GET /api/engine-controls/policy ──────────────────────────────────────
  app.get(
    "/api/engine-controls/policy",
    isAuthenticated,
    resolveOrgContext,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const state = getOrCreateOrgState(orgId);
        res.json({
          predictive: state.predictive,
          pii: state.pii,
          posture: state.posture,
          rollback: state.rollback,
          defaults: {
            predictive: DEFAULT_PREDICTIVE,
            pii: DEFAULT_PII,
            posture: DEFAULT_POSTURE,
            rollback: DEFAULT_ROLLBACK,
          },
        });
      } catch (err: any) {
        logger.child("engine-controls").error("Policy fetch error", { error: String(err) });
        res.status(500).json({ message: "Failed to fetch engine policies" });
      }
    }
  );

  // ── PUT /api/engine-controls/policy ──────────────────────────────────────
  app.put(
    "/api/engine-controls/policy",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { engine, policy } = req.body as { engine: string; policy: Record<string, unknown> };

        if (!["predictive", "pii", "posture", "rollback"].includes(engine)) {
          return res.status(400).json({ message: "Invalid engine. Must be one of: predictive, pii, posture, rollback" });
        }
        if (!policy || typeof policy !== "object") {
          return res.status(400).json({ message: "Policy must be a non-null object" });
        }

        const state = getOrCreateOrgState(orgId);

        if (engine === "posture") {
          const weightErr = validateWeights(policy as Partial<PosturePolicy>);
          if (weightErr) return res.status(400).json({ message: weightErr });
        }

        if (engine === "predictive") {
          const p = policy as Partial<PredictivePolicy>;
          if (p.zScoreThreshold !== undefined && (p.zScoreThreshold < 1 || p.zScoreThreshold > 10)) {
            return res.status(400).json({ message: "zScoreThreshold must be between 1 and 10" });
          }
          if (p.offHoursStart !== undefined && (p.offHoursStart < 0 || p.offHoursStart > 23)) {
            return res.status(400).json({ message: "offHoursStart must be 0–23" });
          }
          if (p.offHoursEnd !== undefined && (p.offHoursEnd < 0 || p.offHoursEnd > 23)) {
            return res.status(400).json({ message: "offHoursEnd must be 0–23" });
          }
        }

        (state as any)[engine] = { ...(state as any)[engine], ...policy };

        await storage.createAuditLog({
          userId: (req as any).user?.id,
          userName: (req as any).user?.email ?? "unknown",
          action: "engine_policy_updated",
          resourceType: "engine_controls",
          details: { engine, updatedKeys: Object.keys(policy) },
        }).catch(() => {});

        res.json({ engine, policy: (state as any)[engine] });
      } catch (err: any) {
        logger.child("engine-controls").error("Policy update error", { error: String(err) });
        res.status(500).json({ message: "Failed to update engine policy" });
      }
    }
  );

  // ── POST /api/engine-controls/policy/reset ─────────────────────────────
  app.post(
    "/api/engine-controls/policy/reset",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { engine } = req.body as { engine?: string };
        const state = getOrCreateOrgState(orgId);

        const DEFAULTS: Record<string, object> = {
          predictive: DEFAULT_PREDICTIVE,
          pii: DEFAULT_PII,
          posture: DEFAULT_POSTURE,
          rollback: DEFAULT_ROLLBACK,
        };

        if (engine) {
          if (!DEFAULTS[engine]) {
            return res.status(400).json({ message: "Invalid engine name" });
          }
          (state as any)[engine] = { ...DEFAULTS[engine] };
          return res.json({ engine, policy: (state as any)[engine], reset: true });
        }

        state.predictive = { ...DEFAULT_PREDICTIVE };
        state.pii = { ...DEFAULT_PII };
        state.posture = { ...DEFAULT_POSTURE };
        state.rollback = { ...DEFAULT_ROLLBACK };
        res.json({ reset: true, engines: ["predictive", "pii", "posture", "rollback"] });
      } catch (err: any) {
        logger.child("engine-controls").error("Policy reset error", { error: String(err) });
        res.status(500).json({ message: "Failed to reset engine policy" });
      }
    }
  );

  // ── POST /api/engine-controls/dry-run/:engine ─────────────────────────
  app.post(
    "/api/engine-controls/dry-run/:engine",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { engine } = req.params;
        const state = getOrCreateOrgState(orgId);
        const t0 = Date.now();

        if (!state[engine as keyof Pick<OrgEngineState, "predictive" | "pii" | "posture" | "rollback">]) {
          return res.status(400).json({ message: "Invalid engine. Must be one of: predictive, pii, posture, rollback" });
        }

        if (engine === "predictive") {
          if (!state.predictive.enabled) {
            return res.json({ engine, dryRun: true, skipped: true, reason: "Engine is disabled by policy" });
          }
          const allAlerts = await storage.getAlerts(orgId);
          const policy = state.predictive;

          // Re-implement detection logic in dry-run mode (no DB writes)
          const now = new Date();
          const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
          const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
          const recentAlerts = allAlerts.filter(a => a.createdAt && new Date(a.createdAt) >= oneDayAgo);
          const weekAlerts = allAlerts.filter(a => a.createdAt && new Date(a.createdAt) >= sevenDaysAgo);
          const priorAlerts = weekAlerts.filter(a => a.createdAt && new Date(a.createdAt) < oneDayAgo);
          const daysInPrior = Math.max(1, (oneDayAgo.getTime() - sevenDaysAgo.getTime()) / (24 * 60 * 60 * 1000));

          const categoryCount24h: Record<string, number> = {};
          for (const a of recentAlerts) {
            const cat = a.category || "other";
            categoryCount24h[cat] = (categoryCount24h[cat] || 0) + 1;
          }
          const categoryCountWeek: Record<string, number> = {};
          for (const a of priorAlerts) {
            const cat = a.category || "other";
            categoryCountWeek[cat] = (categoryCountWeek[cat] || 0) + 1;
          }

          const wouldDetect: Record<string, unknown>[] = [];

          for (const [category, current] of Object.entries(categoryCount24h)) {
            const weekTotal = categoryCountWeek[category] || 0;
            const dailyAvg = weekTotal / daysInPrior;
            const days = Math.ceil((oneDayAgo.getTime() - sevenDaysAgo.getTime()) / (24 * 60 * 60 * 1000));
            const dailyCounts = new Array(days).fill(0);
            for (const a of priorAlerts.filter(a => (a.category || "other") === category)) {
              if (!a.createdAt) continue;
              const idx = Math.floor((new Date(a.createdAt).getTime() - sevenDaysAgo.getTime()) / (24 * 60 * 60 * 1000));
              if (idx >= 0 && idx < days) dailyCounts[idx]++;
            }
            const mean = dailyCounts.reduce((s, v) => s + v, 0) / (dailyCounts.length || 1);
            const variance = dailyCounts.reduce((s, v) => s + (v - mean) ** 2, 0) / (dailyCounts.length || 1);
            const stddev = Math.sqrt(variance);
            const zScore = stddev > 0 ? (current - dailyAvg) / stddev : (current > dailyAvg ? 3 : 0);

            if (current > dailyAvg + policy.zScoreThreshold * stddev && current > policy.minAlertsForAnomaly) {
              wouldDetect.push({
                kind: "volume_spike",
                category,
                current,
                baseline: Math.round(dailyAvg * 100) / 100,
                zScore: Math.round(zScore * 100) / 100,
                threshold: policy.zScoreThreshold,
                severity: zScore > 4 ? "critical" : zScore > 3 ? "high" : "medium",
                description: `Would flag volume spike: ${current} alerts (baseline ${dailyAvg.toFixed(1)}/day, z=${zScore.toFixed(2)})`,
              });
            }
          }

          const criticalRecent = (recentAlerts.filter(a => a.severity === "critical")).length;
          const criticalPriorDaily = (priorAlerts.filter(a => a.severity === "critical")).length / daysInPrior;
          if (criticalRecent > criticalPriorDaily * policy.criticalMultiplier && criticalRecent > policy.minAlertsForAnomaly) {
            wouldDetect.push({
              kind: "severity_escalation",
              metric: "critical_alerts",
              current: criticalRecent,
              baseline: Math.round(criticalPriorDaily * 100) / 100,
              severity: "critical",
              description: `Would flag severity escalation: ${criticalRecent} critical alerts (baseline ${criticalPriorDaily.toFixed(1)}/day)`,
            });
          }

          const offHourRecent = recentAlerts.filter(a => {
            if (!a.createdAt) return false;
            const h = new Date(a.createdAt).getUTCHours();
            return h >= policy.offHoursStart && h < policy.offHoursEnd;
          });
          const offHourPrior = priorAlerts.filter(a => {
            if (!a.createdAt) return false;
            const h = new Date(a.createdAt).getUTCHours();
            return h >= policy.offHoursStart && h < policy.offHoursEnd;
          });
          const recentOffRatio = recentAlerts.length > 0 ? offHourRecent.length / recentAlerts.length : 0;
          const priorOffRatio = priorAlerts.length > 0 ? offHourPrior.length / priorAlerts.length : 0.25;
          if (recentOffRatio > priorOffRatio * policy.offHoursRatioMultiplier && offHourRecent.length > 3) {
            wouldDetect.push({
              kind: "timing_anomaly",
              metric: "off_hours_ratio",
              current: Math.round(recentOffRatio * 100) / 100,
              baseline: Math.round(priorOffRatio * 100) / 100,
              offHoursWindow: `${policy.offHoursStart}:00–${policy.offHoursEnd}:00 UTC`,
              severity: recentOffRatio > 0.5 ? "high" : "medium",
              description: `Would flag timing anomaly: ${(recentOffRatio * 100).toFixed(1)}% off-hours (baseline ${(priorOffRatio * 100).toFixed(1)}%)`,
            });
          }

          return res.json({
            engine: "predictive",
            dryRun: true,
            durationMs: Date.now() - t0,
            inputAlerts: allAlerts.length,
            recentAlerts: recentAlerts.length,
            priorAlerts: priorAlerts.length,
            wouldDetect,
            wouldWrite: {
              anomalies: wouldDetect.length,
              assets: "full entity mapping (not computed in dry-run for performance)",
              forecasts: "tactic-based forecasts (not computed in dry-run)",
              recommendations: "derived from anomalies and forecasts (not computed in dry-run)",
            },
            policy: state.predictive,
          });
        }

        if (engine === "pii") {
          if (!state.pii.enabled) {
            return res.json({ engine, dryRun: true, skipped: true, reason: "Engine is disabled by policy" });
          }
          const allAlerts = await storage.getAlerts(orgId);
          const sample = allAlerts.slice(0, 5);
          const policy = state.pii;

          const results = sample.map((alert: Alert) => {
            const detectedFields = detectPiiFields(alert as unknown as Record<string, unknown>);
            const applicable = detectedFields.filter(f => {
              if (f === "sourceIp" && !policy.maskSourceIp) return false;
              if (f === "destIp" && !policy.maskDestIp) return false;
              if (f === "userId" && !policy.maskUserId) return false;
              if (f === "hostname" && !policy.maskHostname) return false;
              return true;
            });
            const { result } = maskPiiInAlert(alert);
            return {
              alertId: alert.id,
              title: alert.title,
              detectedPiiFields: detectedFields,
              wouldRedactFields: applicable,
              skippedByPolicy: detectedFields.filter(f => !applicable.includes(f)),
              masked: applicable.length > 0,
            };
          });

          return res.json({
            engine: "pii",
            dryRun: true,
            durationMs: Date.now() - t0,
            sampledAlerts: sample.length,
            totalAlerts: allAlerts.length,
            alertsWithPii: results.filter(r => r.detectedPiiFields.length > 0).length,
            wouldRedactInSample: results.filter(r => r.wouldRedactFields.length > 0).length,
            sampleResults: results,
            policy: state.pii,
          });
        }

        if (engine === "posture") {
          if (!state.posture.enabled) {
            return res.json({ engine, dryRun: true, skipped: true, reason: "Engine is disabled by policy" });
          }
          const [findings, endpoints, incidents, compliancePolicy] = await Promise.all([
            storage.getCspmFindings(orgId),
            storage.getEndpointAssets(orgId),
            storage.getIncidents(orgId),
            storage.getCompliancePolicy(orgId),
          ]);
          const p = state.posture;
          const openFindings = findings.filter(f => f.status === "open");
          const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
          const recentIncidents = incidents.filter(inc => inc.createdAt && new Date(inc.createdAt) >= thirtyDaysAgo);
          const openIncidents = recentIncidents.filter(inc => inc.status !== "resolved" && inc.status !== "closed");

          let cspmScore = 100;
          for (const f of openFindings) {
            if (f.severity === "critical") cspmScore -= p.criticalFindingPenalty;
            else if (f.severity === "high") cspmScore -= p.highFindingPenalty;
            else if (f.severity === "medium") cspmScore -= p.mediumFindingPenalty;
            else if (f.severity === "low") cspmScore -= p.lowFindingPenalty;
          }
          cspmScore = Math.max(0, cspmScore);

          let endpointScore = endpoints.length === 0 ? 100
            : Math.max(0, Math.min(100, Math.round(
                endpoints.reduce((s, e) => s + (100 - (e.riskScore ?? 0)), 0) / endpoints.length
              )));

          let incidentScore = 100;
          for (const inc of openIncidents) {
            if (inc.severity === "critical") incidentScore -= p.criticalIncidentPenalty;
            else if (inc.severity === "high") incidentScore -= p.highIncidentPenalty;
            else if (inc.severity === "medium") incidentScore -= p.mediumIncidentPenalty;
            else if (inc.severity === "low") incidentScore -= p.lowIncidentPenalty;
          }
          incidentScore = Math.max(0, incidentScore);

          const complianceScore = !compliancePolicy ? 80
            : (compliancePolicy.enabledFrameworks?.length > 0 && compliancePolicy.piiMaskingEnabled && compliancePolicy.pseudonymizeExports && compliancePolicy.dpoEmail) ? 100
            : Math.min(95, 50 + (compliancePolicy.enabledFrameworks?.length > 0 ? 15 : 0) + (compliancePolicy.piiMaskingEnabled ? 10 : 0) + (compliancePolicy.pseudonymizeExports ? 10 : 0) + (compliancePolicy.dpoEmail ? 10 : 0));

          const overallScore = Math.round(
            cspmScore * p.cspmWeight +
            endpointScore * p.endpointWeight +
            incidentScore * p.incidentWeight +
            complianceScore * p.complianceWeight
          );

          return res.json({
            engine: "posture",
            dryRun: true,
            durationMs: Date.now() - t0,
            wouldWrite: { overallScore, cspmScore, endpointScore, incidentScore, complianceScore },
            breakdown: {
              cspm: { score: cspmScore, weight: p.cspmWeight, contribution: Math.round(cspmScore * p.cspmWeight), openFindings: openFindings.length, byPenalty: { critical: openFindings.filter(f => f.severity === "critical").length, high: openFindings.filter(f => f.severity === "high").length, medium: openFindings.filter(f => f.severity === "medium").length, low: openFindings.filter(f => f.severity === "low").length } },
              endpoint: { score: endpointScore, weight: p.endpointWeight, contribution: Math.round(endpointScore * p.endpointWeight), totalEndpoints: endpoints.length },
              incident: { score: incidentScore, weight: p.incidentWeight, contribution: Math.round(incidentScore * p.incidentWeight), openIncidents: openIncidents.length },
              compliance: { score: complianceScore, weight: p.complianceWeight, contribution: Math.round(complianceScore * p.complianceWeight), policyConfigured: !!compliancePolicy },
            },
            policy: state.posture,
          });
        }

        if (engine === "rollback") {
          if (!state.rollback.enabled) {
            return res.json({ engine, dryRun: true, skipped: true, reason: "Engine is disabled by policy" });
          }
          const available = await getAvailableRollbacks(orgId);
          const policy = state.rollback;
          const actionable = available.filter(r => policy.allowedActions.includes(r.actionType));
          const blocked = available.filter(r => !policy.allowedActions.includes(r.actionType));

          return res.json({
            engine: "rollback",
            dryRun: true,
            durationMs: Date.now() - t0,
            pendingRollbacks: available.length,
            actionableByPolicy: actionable.length,
            blockedByPolicy: blocked.length,
            blockedActions: blocked.map(r => ({ id: r.id, actionType: r.actionType, target: r.target })),
            reversibleActionMap: ROLLBACK_ACTION_MAP,
            allowedByPolicy: policy.allowedActions,
            policy: state.rollback,
          });
        }

        return res.status(400).json({ message: "Unknown engine" });
      } catch (err: any) {
        logger.child("engine-controls").error("Dry-run error", { engine: req.params.engine, error: String(err) });
        res.status(500).json({ message: "Dry-run failed" });
      }
    }
  );

  // ── POST /api/engine-controls/run/:engine ─────────────────────────────
  app.post(
    "/api/engine-controls/run/:engine",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { engine } = req.params;
        const state = getOrCreateOrgState(orgId);
        const t0 = Date.now();

        if (engine === "predictive") {
          if (!state.predictive.enabled) {
            return res.json({ engine, triggered: false, reason: "Engine disabled by policy" });
          }
          const result = await runPredictiveAnalysis(orgId, storage);
          const durationMs = Date.now() - t0;
          state.lastRuns.predictive = { at: new Date(), durationMs, summary: result as unknown as Record<string, unknown> };
          await storage.createAuditLog({ userId: (req as any).user?.id, userName: (req as any).user?.email ?? "unknown", action: "engine_run", resourceType: "engine_controls", details: { engine, result } }).catch(() => {});
          return res.json({ engine, triggered: true, durationMs, result });
        }

        if (engine === "posture") {
          if (!state.posture.enabled) {
            return res.json({ engine, triggered: false, reason: "Engine disabled by policy" });
          }
          const score = await calculatePostureScore(orgId);
          const durationMs = Date.now() - t0;
          state.lastRuns.posture = { at: new Date(), durationMs, summary: { overallScore: score.overallScore } as Record<string, unknown> };
          await storage.createAuditLog({ userId: (req as any).user?.id, userName: (req as any).user?.email ?? "unknown", action: "engine_run", resourceType: "engine_controls", details: { engine, overallScore: score.overallScore } }).catch(() => {});
          return res.json({ engine, triggered: true, durationMs, result: score });
        }

        if (engine === "pii") {
          if (!state.pii.enabled) {
            return res.json({ engine, triggered: false, reason: "Engine disabled by policy" });
          }
          const allAlerts = await storage.getAlerts(orgId);
          let maskedCount = 0;
          const fieldsRedactedSet = new Set<string>();
          for (const alert of allAlerts) {
            const { result } = maskPiiInAlert(alert);
            if (result.masked) { maskedCount++; result.fieldsRedacted.forEach(f => fieldsRedactedSet.add(f)); }
          }
          const durationMs = Date.now() - t0;
          state.lastRuns.pii = { at: new Date(), durationMs, summary: { totalAlerts: allAlerts.length, maskedCount, fieldsRedacted: Array.from(fieldsRedactedSet) } as unknown as Record<string, unknown> };
          return res.json({ engine, triggered: true, durationMs, result: { totalAlerts: allAlerts.length, maskedCount, fieldsRedacted: Array.from(fieldsRedactedSet) } });
        }

        if (engine === "rollback") {
          const { rollbackId } = req.body as { rollbackId?: string };
          if (!rollbackId) {
            return res.status(400).json({ message: "rollbackId is required for rollback engine run" });
          }
          if (!state.rollback.enabled) {
            return res.json({ engine, triggered: false, reason: "Engine disabled by policy" });
          }
          const userId = (req as any).user?.id ?? "unknown";
          const result = await executeRollback(rollbackId, userId);
          const durationMs = Date.now() - t0;
          state.lastRuns.rollback = { at: new Date(), durationMs, summary: { rollbackId, status: result?.status } as unknown as Record<string, unknown> };
          await storage.createAuditLog({ userId: (req as any).user?.id, userName: (req as any).user?.email ?? "unknown", action: "engine_run", resourceType: "engine_controls", details: { engine, rollbackId, status: result?.status } }).catch(() => {});
          return res.json({ engine, triggered: true, durationMs, result });
        }

        return res.status(400).json({ message: "Invalid engine. Must be one of: predictive, pii, posture, rollback" });
      } catch (err: any) {
        logger.child("engine-controls").error("Engine run error", { engine: req.params.engine, error: String(err) });
        res.status(500).json({ message: "Engine run failed" });
      }
    }
  );

  // ── GET /api/engine-controls/explain/:engine ──────────────────────────
  app.get(
    "/api/engine-controls/explain/:engine",
    isAuthenticated,
    resolveOrgContext,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { engine } = req.params;
        const state = getOrCreateOrgState(orgId);

        if (engine === "predictive") {
          const p = state.predictive;
          return res.json({
            engine: "predictive",
            title: "Predictive Analytics Engine",
            description: "Detects statistical anomalies in alert volume, timing, and severity. Maps entities to an attack surface. Forecasts threat types based on observed MITRE ATT&CK tactics.",
            lastRun: state.lastRuns.predictive,
            policy: p,
            howItWorks: [
              { step: 1, name: "Volume Spike Detection", rationale: `For each alert category, computes a daily average and standard deviation over the prior 7 days. If today's count exceeds baseline + ${p.zScoreThreshold}× stddev AND is ≥${p.minAlertsForAnomaly} alerts, flags a volume spike anomaly. Higher z-score threshold = less sensitive (fewer false positives).` },
              { step: 2, name: "New Vector Detection", rationale: "If an alert category appears today that was not seen in the prior 7 days, flags as 'new attack vector' (always z-score 5, high severity)." },
              { step: 3, name: "Timing Anomaly Detection", rationale: `Measures the fraction of alerts in the off-hours window (${p.offHoursStart}:00–${p.offHoursEnd}:00 UTC). If today's off-hours ratio exceeds ${p.offHoursRatioMultiplier}× the prior ratio AND there are >3 off-hours alerts, flags a timing anomaly.` },
              { step: 4, name: "Severity Escalation Detection", rationale: `If today's critical alert count exceeds ${p.criticalMultiplier}× the baseline daily average AND is ≥${p.minAlertsForAnomaly}, flags a severity escalation.` },
              { step: 5, name: "Attack Surface Mapping", rationale: "Extracts entity values (IPs, hosts, domains, file hashes, URLs, users) from all historical alerts. Computes a risk score per entity based on alert severity counts and recency (exponential decay by √days)." },
              { step: 6, name: "Risk Forecasting", rationale: "Maps detected MITRE tactics to five threat scenarios (ransomware, data exfiltration, phishing, APT campaign, lateral movement). Probability is computed as base probability + bonus per matching tactic + alert velocity factor." },
              { step: 7, name: "Hardening Recommendations", rationale: "Generates prioritized action items derived from each anomaly and each high-probability forecast." },
            ],
            thresholds: {
              zScoreThreshold: { current: p.zScoreThreshold, default: DEFAULT_PREDICTIVE.zScoreThreshold, description: "Minimum z-score to flag a volume spike" },
              minAlertsForAnomaly: { current: p.minAlertsForAnomaly, default: DEFAULT_PREDICTIVE.minAlertsForAnomaly, description: "Minimum alert count needed to generate an anomaly" },
              criticalMultiplier: { current: p.criticalMultiplier, default: DEFAULT_PREDICTIVE.criticalMultiplier, description: "How many times above baseline critical alert count must be to trigger severity escalation" },
              offHoursWindow: { current: `${p.offHoursStart}:00–${p.offHoursEnd}:00 UTC`, description: "UTC hours considered 'off-hours'" },
              offHoursRatioMultiplier: { current: p.offHoursRatioMultiplier, default: DEFAULT_PREDICTIVE.offHoursRatioMultiplier, description: "How much higher than baseline the off-hours ratio must be to flag timing anomaly" },
            },
          });
        }

        if (engine === "pii") {
          const p = state.pii;
          return res.json({
            engine: "pii",
            title: "PII Detection & Masking Engine",
            description: "Identifies and redacts personally identifiable information from alert fields before AI processing or data exports.",
            lastRun: state.lastRuns.pii,
            policy: p,
            howItWorks: [
              { step: 1, name: "Field-Level Masking", rationale: "Specific alert fields (sourceIp, destIp, userId, hostname) are masked when enabled by policy. IPs are masked to the first three octets (e.g. 10.0.1.***). User IDs show the last 4 characters (user_***1234). Hostnames show the first 3 characters (srv***)." },
              { step: 2, name: "Text-Field Scanning", rationale: "Free-text fields (description, analystNotes) are scanned with regex patterns for embedded emails (/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+/) and IP addresses (/\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\/.\\d{1,3}\\b/). Matches are replaced with ***@*** and x.x.x.*** respectively." },
              { step: 3, name: "PII Field Detection", rationale: "Scans arbitrary data objects for keys matching known PII names (userId, username, hostname, etc.) and values matching email/IP patterns. Used for audit and pre-export validation." },
            ],
            patterns: {
              email: { regex: "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}", replacement: "***@***" },
              ipv4: { regex: "\\b(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\.\\d{1,3}\\b", replacement: "$1.***" },
              userId: { pattern: "last-4 chars preserved", example: "user_***a1b2" },
              hostname: { pattern: "first-3 chars preserved", example: "srv***" },
            },
            enabledMasks: {
              sourceIp: p.maskSourceIp,
              destIp: p.maskDestIp,
              userId: p.maskUserId,
              hostname: p.maskHostname,
              emailsInText: p.maskEmailsInText,
              ipsInText: p.maskIpsInText,
            },
          });
        }

        if (engine === "posture") {
          const p = state.posture;
          const totalWeight = p.cspmWeight + p.endpointWeight + p.incidentWeight + p.complianceWeight;
          return res.json({
            engine: "posture",
            title: "Security Posture Engine",
            description: "Computes a weighted composite security posture score (0–100) from four sub-scores across CSPM, endpoint health, incident pressure, and compliance configuration.",
            lastRun: state.lastRuns.posture,
            policy: p,
            howItWorks: [
              { step: 1, name: "CSPM Sub-Score", rationale: `Starts at 100. Deducts ${p.criticalFindingPenalty} pts per critical open CSPM finding, ${p.highFindingPenalty} pts per high, ${p.mediumFindingPenalty} per medium, ${p.lowFindingPenalty} per low. Floor: 0. Weight in overall: ${(p.cspmWeight * 100).toFixed(0)}%.` },
              { step: 2, name: "Endpoint Sub-Score", rationale: `Averages (100 − riskScore) across all registered endpoints. If no endpoints, defaults to 100. Weight: ${(p.endpointWeight * 100).toFixed(0)}%.` },
              { step: 3, name: "Incident Sub-Score", rationale: `Starts at 100. Deducts ${p.criticalIncidentPenalty} pts per open critical incident in last 30 days, ${p.highIncidentPenalty} per high, ${p.mediumIncidentPenalty} per medium, ${p.lowIncidentPenalty} per low. Floor: 0. Weight: ${(p.incidentWeight * 100).toFixed(0)}%.` },
              { step: 4, name: "Compliance Sub-Score", rationale: `If no compliance policy, score = 80. Full enforcement (frameworks + PII masking + pseudonymization + DPO email) = 100. Partial credit: +15 for frameworks, +10 each for PII masking, pseudonymization, DPO email. Weight: ${(p.complianceWeight * 100).toFixed(0)}%.` },
              { step: 5, name: "Weighted Composite", rationale: `overall = cspm×${p.cspmWeight} + endpoint×${p.endpointWeight} + incident×${p.incidentWeight} + compliance×${p.complianceWeight}. Weights currently sum to ${totalWeight.toFixed(3)}.` },
            ],
            weights: {
              cspm: { weight: p.cspmWeight, percentage: `${(p.cspmWeight * 100).toFixed(0)}%` },
              endpoint: { weight: p.endpointWeight, percentage: `${(p.endpointWeight * 100).toFixed(0)}%` },
              incident: { weight: p.incidentWeight, percentage: `${(p.incidentWeight * 100).toFixed(0)}%` },
              compliance: { weight: p.complianceWeight, percentage: `${(p.complianceWeight * 100).toFixed(0)}%` },
              total: totalWeight.toFixed(3),
            },
            penalties: {
              cspm: { critical: p.criticalFindingPenalty, high: p.highFindingPenalty, medium: p.mediumFindingPenalty, low: p.lowFindingPenalty },
              incident: { critical: p.criticalIncidentPenalty, high: p.highIncidentPenalty, medium: p.mediumIncidentPenalty, low: p.lowIncidentPenalty },
            },
          });
        }

        if (engine === "rollback") {
          const p = state.rollback;
          return res.json({
            engine: "rollback",
            title: "Response Rollback Engine",
            description: "Tracks response actions that can be reversed and provides a safe undo mechanism. Maps forward actions to their inverse operations.",
            lastRun: state.lastRuns.rollback,
            policy: p,
            howItWorks: [
              { step: 1, name: "Rollback Record Creation", rationale: "When a reversible response action is executed (isolate_host, block_ip, etc.), a rollback record is created with status 'pending'. Records the original action, target, and the inverse action to execute on rollback." },
              { step: 2, name: "Action Allowlist", rationale: "The policy defines which action types are allowed to be rolled back. Disabling an action type prevents accidental restoration of blocked-for-policy-reasons resources." },
              { step: 3, name: "Rollback Execution", rationale: "When triggered, dispatches the inverse action through the action-dispatcher. Sets status to 'completed' on success or 'failed' on error. Records executor user ID and timestamp." },
              { step: 4, name: "Confirmation Gate", rationale: "If requireConfirmation is true, rollback execution requires explicit user acknowledgment in the UI before proceeding." },
            ],
            reversibleActions: Object.entries(ROLLBACK_ACTION_MAP).map(([forward, inverse]) => ({
              forward,
              inverse,
              allowed: p.allowedActions.includes(forward),
            })),
          });
        }

        return res.status(400).json({ message: "Invalid engine. Must be one of: predictive, pii, posture, rollback" });
      } catch (err: any) {
        logger.child("engine-controls").error("Explain error", { engine: req.params.engine, error: String(err) });
        res.status(500).json({ message: "Failed to fetch engine explanation" });
      }
    }
  );

  // ── GET /api/engine-controls/rollbacks ──────────────────────────────
  app.get(
    "/api/engine-controls/rollbacks",
    isAuthenticated,
    resolveOrgContext,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const rollbacks = await storage.getResponseActionRollbacks(orgId);
        res.json({ rollbacks, total: rollbacks.length, pending: rollbacks.filter(r => r.status === "pending").length });
      } catch (err: any) {
        logger.child("engine-controls").error("Rollbacks fetch error", { error: String(err) });
        res.status(500).json({ message: "Failed to fetch rollbacks" });
      }
    }
  );
}
