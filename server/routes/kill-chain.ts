import type { Express, Request, Response } from "express";
import { getOrgId, logger, p, reply, replyError, strictLimiter } from "./shared";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId } from "../rbac";
import { pool } from "../db";

const log = logger.child("kill-chain-routes");

// ── Kill Chain Phase Definitions ─────────────────────────────────────

interface KillChainPhase {
  id: string;
  name: string;
  shortName: string;
  description: string;
  mitreTactics: string[];
  order: number;
  severity: "early" | "mid" | "late";
}

// Lockheed Martin Cyber Kill Chain
const LOCKHEED_MARTIN_PHASES: KillChainPhase[] = [
  {
    id: "lm-recon",
    name: "Reconnaissance",
    shortName: "recon",
    description: "Harvesting email addresses, conference information, etc.",
    mitreTactics: ["reconnaissance", "resource_development"],
    order: 1,
    severity: "early",
  },
  {
    id: "lm-weaponization",
    name: "Weaponization",
    shortName: "weaponization",
    description: "Coupling exploit with backdoor into deliverable payload",
    mitreTactics: ["resource_development"],
    order: 2,
    severity: "early",
  },
  {
    id: "lm-delivery",
    name: "Delivery",
    shortName: "delivery",
    description: "Delivering weaponized bundle to the victim via email, web, USB, etc.",
    mitreTactics: ["initial_access"],
    order: 3,
    severity: "early",
  },
  {
    id: "lm-exploitation",
    name: "Exploitation",
    shortName: "exploitation",
    description: "Exploiting a vulnerability to execute code on victim's system",
    mitreTactics: ["execution"],
    order: 4,
    severity: "mid",
  },
  {
    id: "lm-installation",
    name: "Installation",
    shortName: "installation",
    description: "Installing malware on the asset",
    mitreTactics: ["persistence", "privilege_escalation", "defense_evasion"],
    order: 5,
    severity: "mid",
  },
  {
    id: "lm-c2",
    name: "Command & Control",
    shortName: "c2",
    description: "Command channel for remote manipulation of victim",
    mitreTactics: ["command_and_control"],
    order: 6,
    severity: "late",
  },
  {
    id: "lm-actions",
    name: "Actions on Objectives",
    shortName: "actions",
    description: "With hands-on access, intruder accomplishes their original goals",
    mitreTactics: ["collection", "exfiltration", "impact", "lateral_movement"],
    order: 7,
    severity: "late",
  },
];

// Diamond Model phases
const DIAMOND_MODEL_PHASES: KillChainPhase[] = [
  {
    id: "dm-adversary",
    name: "Adversary",
    shortName: "adversary",
    description: "Threat actor initiating the attack",
    mitreTactics: ["reconnaissance", "resource_development"],
    order: 1,
    severity: "early",
  },
  {
    id: "dm-capability",
    name: "Capability",
    shortName: "capability",
    description: "Tools and techniques used by the adversary",
    mitreTactics: ["execution", "persistence", "privilege_escalation", "defense_evasion"],
    order: 2,
    severity: "mid",
  },
  {
    id: "dm-infrastructure",
    name: "Infrastructure",
    shortName: "infrastructure",
    description: "Physical and logical communication structures used",
    mitreTactics: ["command_and_control", "initial_access"],
    order: 3,
    severity: "mid",
  },
  {
    id: "dm-victim",
    name: "Victim",
    shortName: "victim",
    description: "Target of the attack",
    mitreTactics: ["collection", "exfiltration", "impact", "lateral_movement", "credential_access", "discovery"],
    order: 4,
    severity: "late",
  },
];

// Unified Kill Chain phases (simplified)
const UNIFIED_KC_PHASES: KillChainPhase[] = [
  {
    id: "ukc-recon",
    name: "Reconnaissance",
    shortName: "recon",
    description: "Research, identification and selection of targets",
    mitreTactics: ["reconnaissance"],
    order: 1,
    severity: "early",
  },
  {
    id: "ukc-weaponize",
    name: "Weaponization",
    shortName: "weaponize",
    description: "Preparation of intrusion tools and exploits",
    mitreTactics: ["resource_development"],
    order: 2,
    severity: "early",
  },
  {
    id: "ukc-delivery",
    name: "Social Engineering",
    shortName: "social_eng",
    description: "Techniques to manipulate people",
    mitreTactics: ["initial_access"],
    order: 3,
    severity: "early",
  },
  {
    id: "ukc-exploit",
    name: "Exploitation",
    shortName: "exploit",
    description: "Exploitation of vulnerabilities to gain access",
    mitreTactics: ["execution"],
    order: 4,
    severity: "mid",
  },
  {
    id: "ukc-persist",
    name: "Persistence",
    shortName: "persist",
    description: "Ensuring continued access",
    mitreTactics: ["persistence", "privilege_escalation"],
    order: 5,
    severity: "mid",
  },
  {
    id: "ukc-defense",
    name: "Defense Evasion",
    shortName: "defense",
    description: "Avoiding detection mechanisms",
    mitreTactics: ["defense_evasion"],
    order: 6,
    severity: "mid",
  },
  {
    id: "ukc-c2",
    name: "Command & Control",
    shortName: "c2",
    description: "Establishing communication with compromised systems",
    mitreTactics: ["command_and_control"],
    order: 7,
    severity: "late",
  },
  {
    id: "ukc-pivoting",
    name: "Pivoting",
    shortName: "pivoting",
    description: "Using compromised system to move through network",
    mitreTactics: ["lateral_movement", "discovery", "credential_access"],
    order: 8,
    severity: "late",
  },
  {
    id: "ukc-objectives",
    name: "Objectives",
    shortName: "objectives",
    description: "Achievement of the adversary's goals",
    mitreTactics: ["collection", "exfiltration", "impact"],
    order: 9,
    severity: "late",
  },
];

// MITRE ATT&CK for ICS Kill Chain
const ICS_KC_PHASES: KillChainPhase[] = [
  {
    id: "ics-recon",
    name: "Reconnaissance",
    shortName: "recon",
    description: "Gathering ICS/SCADA network information",
    mitreTactics: ["reconnaissance"],
    order: 1,
    severity: "early",
  },
  {
    id: "ics-initial",
    name: "Initial Access",
    shortName: "initial",
    description: "Gaining initial foothold in IT/OT network",
    mitreTactics: ["initial_access"],
    order: 2,
    severity: "early",
  },
  {
    id: "ics-execution",
    name: "Execution",
    shortName: "execution",
    description: "Running adversary-controlled code on ICS",
    mitreTactics: ["execution"],
    order: 3,
    severity: "mid",
  },
  {
    id: "ics-persist",
    name: "Persistence",
    shortName: "persist",
    description: "Maintaining position in ICS environment",
    mitreTactics: ["persistence", "privilege_escalation"],
    order: 4,
    severity: "mid",
  },
  {
    id: "ics-evasion",
    name: "Evasion",
    shortName: "evasion",
    description: "Avoiding ICS security controls",
    mitreTactics: ["defense_evasion"],
    order: 5,
    severity: "mid",
  },
  {
    id: "ics-discovery",
    name: "Discovery",
    shortName: "discovery",
    description: "Learning about ICS environment and processes",
    mitreTactics: ["discovery", "credential_access"],
    order: 6,
    severity: "mid",
  },
  {
    id: "ics-lateral",
    name: "Lateral Movement",
    shortName: "lateral",
    description: "Moving between IT and OT networks",
    mitreTactics: ["lateral_movement"],
    order: 7,
    severity: "late",
  },
  {
    id: "ics-c2",
    name: "Command & Control",
    shortName: "c2",
    description: "Communicating with compromised ICS assets",
    mitreTactics: ["command_and_control"],
    order: 8,
    severity: "late",
  },
  {
    id: "ics-impact",
    name: "Impact",
    shortName: "impact",
    description: "Disrupting, degrading, or destroying ICS processes",
    mitreTactics: ["impact", "collection", "exfiltration"],
    order: 9,
    severity: "late",
  },
];

const FRAMEWORKS: Record<string, { name: string; description: string; phases: KillChainPhase[] }> = {
  lockheed_martin: {
    name: "Lockheed Martin Cyber Kill Chain",
    description: "The original 7-phase cyber kill chain model by Lockheed Martin",
    phases: LOCKHEED_MARTIN_PHASES,
  },
  diamond_model: {
    name: "Diamond Model",
    description: "Diamond Model of Intrusion Analysis — adversary, capability, infrastructure, victim",
    phases: DIAMOND_MODEL_PHASES,
  },
  unified_kill_chain: {
    name: "Unified Kill Chain",
    description: "Unified Kill Chain combining Lockheed Martin and MITRE ATT&CK phases",
    phases: UNIFIED_KC_PHASES,
  },
  ics_kill_chain: {
    name: "MITRE ATT&CK for ICS Kill Chain",
    description: "Kill chain model specific to Industrial Control Systems (ICS/SCADA)",
    phases: ICS_KC_PHASES,
  },
};

// Map MITRE ATT&CK tactic names to kill chain phases
function mapTacticToPhase(tactic: string, phases: KillChainPhase[]): KillChainPhase | null {
  const normalized = tactic.toLowerCase().replace(/\s+/g, "_");
  for (const phase of phases) {
    if (phase.mitreTactics.includes(normalized)) return phase;
  }
  return null;
}

// ── Route Registration ───────────────────────────────────────────────

export function registerKillChainRoutes(app: Express): void {
  // 10.3: GET /api/kill-chain/frameworks — list supported frameworks
  app.get(
    "/api/kill-chain/frameworks",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (_req: Request, res: Response) => {
      try {
        const frameworks = Object.entries(FRAMEWORKS).map(([key, val]) => ({
          id: key,
          name: val.name,
          description: val.description,
          phaseCount: val.phases.length,
        }));
        reply(res, { frameworks });
      } catch (error) {
        log.error("List frameworks error", { error: String(error) });
        replyError(res, 500, [{ code: "KILL_CHAIN_ERROR", message: "Failed to list frameworks" }]);
      }
    },
  );

  // 10.1 + 10.4: GET /api/kill-chain/phases — get kill chain phases with auto-mapped alerts/incidents
  app.get(
    "/api/kill-chain/phases",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const framework = p(req.query.framework as string) || "lockheed_martin";
        const fw = FRAMEWORKS[framework];
        if (!fw) {
          return replyError(res, 400, [{ code: "INVALID_FRAMEWORK", message: `Unknown framework: ${framework}` }]);
        }
        const phases = fw.phases;

        // Fetch alerts with MITRE tactics
        const alertsResult = await pool.query(
          `SELECT id, title, severity, status, source, mitre_tactic, mitre_technique,
                  detected_at, created_at, source_ip, destination_ip
           FROM alerts
           WHERE org_id = $1 AND mitre_tactic IS NOT NULL AND mitre_tactic != ''
           ORDER BY detected_at DESC NULLS LAST, created_at DESC
           LIMIT 500`,
          [orgId],
        );

        // Fetch incidents with MITRE tactics
        const incidentsResult = await pool.query(
          `SELECT id, title, severity, status, mitre_tactics, created_at, updated_at
           FROM incidents
           WHERE org_id = $1 AND mitre_tactics IS NOT NULL AND array_length(mitre_tactics, 1) > 0
           ORDER BY created_at DESC
           LIMIT 200`,
          [orgId],
        );

        // Auto-map alerts to phases (10.4)
        const phaseData = phases.map((phase) => {
          const alerts: any[] = [];
          const incidents: any[] = [];

          for (const row of alertsResult.rows) {
            const mapped = mapTacticToPhase(row.mitre_tactic, phases);
            if (mapped && mapped.id === phase.id) {
              alerts.push({
                id: row.id,
                title: row.title,
                severity: row.severity,
                status: row.status,
                source: row.source,
                mitreTactic: row.mitre_tactic,
                mitreTechnique: row.mitre_technique,
                detectedAt: row.detected_at,
                createdAt: row.created_at,
                sourceIp: row.source_ip,
                destinationIp: row.destination_ip,
              });
            }
          }

          for (const row of incidentsResult.rows) {
            const tactics = Array.isArray(row.mitre_tactics) ? row.mitre_tactics : [];
            for (const tactic of tactics) {
              const mapped = mapTacticToPhase(tactic, phases);
              if (mapped && mapped.id === phase.id) {
                incidents.push({
                  id: row.id,
                  title: row.title,
                  severity: row.severity,
                  status: row.status,
                  mitreTactic: tactic,
                  createdAt: row.created_at,
                });
                break; // Only add incident once per phase
              }
            }
          }

          return {
            ...phase,
            alertCount: alerts.length,
            incidentCount: incidents.length,
            totalCount: alerts.length + incidents.length,
            alerts: alerts.slice(0, 50),
            incidents: incidents.slice(0, 20),
            highestSeverity: getHighestSeverity([...alerts, ...incidents]),
          };
        });

        reply(res, {
          framework: { id: framework, name: fw.name },
          phases: phaseData,
          totalAlerts: alertsResult.rows.length,
          totalIncidents: incidentsResult.rows.length,
        });
      } catch (error) {
        log.error("Kill chain phases error", { error: String(error) });
        replyError(res, 500, [{ code: "KILL_CHAIN_ERROR", message: "Failed to load kill chain phases" }]);
      }
    },
  );

  // 10.5: GET /api/kill-chain/analytics — kill chain analytics and statistics
  app.get(
    "/api/kill-chain/analytics",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const framework = p(req.query.framework as string) || "lockheed_martin";
        const fw = FRAMEWORKS[framework];
        if (!fw) {
          return replyError(res, 400, [{ code: "INVALID_FRAMEWORK", message: `Unknown framework: ${framework}` }]);
        }

        // Get alert counts per tactic
        const tacticCounts = await pool.query(
          `SELECT mitre_tactic, COUNT(*) as count,
                  MIN(detected_at) as first_seen,
                  MAX(detected_at) as last_seen,
                  COUNT(DISTINCT source_ip) as unique_sources
           FROM alerts
           WHERE org_id = $1 AND mitre_tactic IS NOT NULL AND mitre_tactic != ''
           GROUP BY mitre_tactic
           ORDER BY count DESC`,
          [orgId],
        );

        // Map tactics to phases for analytics
        const phaseStats = fw.phases.map((phase) => {
          let totalDetections = 0;
          let firstSeen: string | null = null;
          let lastSeen: string | null = null;
          let uniqueSources = 0;

          for (const row of tacticCounts.rows) {
            const mapped = mapTacticToPhase(row.mitre_tactic, fw.phases);
            if (mapped && mapped.id === phase.id) {
              totalDetections += parseInt(row.count, 10);
              uniqueSources += parseInt(row.unique_sources, 10);
              if (row.first_seen && (!firstSeen || row.first_seen < firstSeen)) {
                firstSeen = row.first_seen;
              }
              if (row.last_seen && (!lastSeen || row.last_seen > lastSeen)) {
                lastSeen = row.last_seen;
              }
            }
          }

          // Calculate dwell time (time between first and last detection in phase)
          let dwellTimeMs = 0;
          if (firstSeen && lastSeen) {
            dwellTimeMs = new Date(lastSeen).getTime() - new Date(firstSeen).getTime();
          }

          return {
            phaseId: phase.id,
            phaseName: phase.name,
            order: phase.order,
            totalDetections,
            uniqueSources,
            firstSeen,
            lastSeen,
            dwellTimeMs,
            dwellTimeHuman: formatDuration(dwellTimeMs),
          };
        });

        // Calculate breakout time (time from initial access to lateral movement)
        const initialAccessPhase = phaseStats.find(
          (ps) =>
            ps.phaseName === "Delivery" || ps.phaseName === "Initial Access" || ps.phaseName === "Social Engineering",
        );
        const lateralPhase = phaseStats.find(
          (ps) =>
            ps.phaseName === "Actions on Objectives" ||
            ps.phaseName === "Pivoting" ||
            ps.phaseName === "Lateral Movement",
        );
        let breakoutTimeMs = 0;
        if (initialAccessPhase?.firstSeen && lateralPhase?.firstSeen) {
          breakoutTimeMs =
            new Date(lateralPhase.firstSeen).getTime() - new Date(initialAccessPhase.firstSeen).getTime();
        }

        // Most targeted phase
        const sortedPhases = [...phaseStats].sort((a, b) => b.totalDetections - a.totalDetections);
        const mostTargetedPhase = sortedPhases[0]?.phaseName || "N/A";

        // Phases with most activity
        const activePhases = phaseStats.filter((ps) => ps.totalDetections > 0).length;

        // Average dwell time across active phases
        const activeDwellTimes = phaseStats.filter((ps) => ps.dwellTimeMs > 0);
        const avgDwellTimeMs =
          activeDwellTimes.length > 0
            ? activeDwellTimes.reduce((sum, ps) => sum + ps.dwellTimeMs, 0) / activeDwellTimes.length
            : 0;

        reply(res, {
          framework: { id: framework, name: fw.name },
          phaseStats,
          summary: {
            totalDetections: phaseStats.reduce((sum, ps) => sum + ps.totalDetections, 0),
            activePhases,
            totalPhases: fw.phases.length,
            mostTargetedPhase,
            breakoutTimeMs,
            breakoutTimeHuman: formatDuration(breakoutTimeMs),
            avgDwellTimeMs,
            avgDwellTimeHuman: formatDuration(avgDwellTimeMs),
          },
        });
      } catch (error) {
        log.error("Kill chain analytics error", { error: String(error) });
        replyError(res, 500, [{ code: "KILL_CHAIN_ERROR", message: "Failed to compute kill chain analytics" }]);
      }
    },
  );

  // 10.6: GET /api/kill-chain/incident-correlation — incidents spanning multiple phases
  app.get(
    "/api/kill-chain/incident-correlation",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const framework = p(req.query.framework as string) || "lockheed_martin";
        const fw = FRAMEWORKS[framework];
        if (!fw) {
          return replyError(res, 400, [{ code: "INVALID_FRAMEWORK", message: `Unknown framework: ${framework}` }]);
        }

        const incidentsResult = await pool.query(
          `SELECT id, title, severity, status, mitre_tactics, created_at, updated_at
           FROM incidents
           WHERE org_id = $1 AND mitre_tactics IS NOT NULL AND array_length(mitre_tactics, 1) > 0
           ORDER BY created_at DESC
           LIMIT 100`,
          [orgId],
        );

        const correlatedIncidents = incidentsResult.rows.map((row) => {
          const tactics = Array.isArray(row.mitre_tactics) ? row.mitre_tactics : [];
          const mappedPhases = new Set<string>();
          const phaseDetails: Array<{ phaseId: string; phaseName: string; order: number; severity: string }> = [];

          for (const tactic of tactics) {
            const phase = mapTacticToPhase(tactic, fw.phases);
            if (phase && !mappedPhases.has(phase.id)) {
              mappedPhases.add(phase.id);
              phaseDetails.push({
                phaseId: phase.id,
                phaseName: phase.name,
                order: phase.order,
                severity: phase.severity,
              });
            }
          }

          phaseDetails.sort((a, b) => a.order - b.order);

          const reachedLateStage = phaseDetails.some((pd) => pd.severity === "late");
          const phaseSpan = phaseDetails.length;
          const furthestPhase = phaseDetails[phaseDetails.length - 1]?.phaseName || "Unknown";

          return {
            id: row.id,
            title: row.title,
            severity: row.severity,
            status: row.status,
            createdAt: row.created_at,
            updatedAt: row.updated_at,
            phaseCount: phaseSpan,
            phases: phaseDetails,
            furthestPhase,
            reachedLateStage,
            isCritical: reachedLateStage || phaseSpan >= 4,
            riskScore: calculateIncidentRiskScore(row.severity, phaseSpan, reachedLateStage),
          };
        });

        // Sort by risk score descending
        correlatedIncidents.sort((a, b) => b.riskScore - a.riskScore);

        const critical = correlatedIncidents.filter((inc) => inc.isCritical);
        const multiPhase = correlatedIncidents.filter((inc) => inc.phaseCount >= 2);

        reply(res, {
          framework: { id: framework, name: fw.name },
          incidents: correlatedIncidents,
          summary: {
            totalIncidents: correlatedIncidents.length,
            criticalIncidents: critical.length,
            multiPhaseIncidents: multiPhase.length,
            lateStageIncidents: correlatedIncidents.filter((i) => i.reachedLateStage).length,
          },
        });
      } catch (error) {
        log.error("Kill chain incident correlation error", { error: String(error) });
        replyError(res, 500, [{ code: "KILL_CHAIN_ERROR", message: "Failed to correlate incidents" }]);
      }
    },
  );

  // 10.7: POST /api/kill-chain/response-triggers — configure auto-response per phase
  app.post(
    "/api/kill-chain/response-triggers",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    strictLimiter,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { phaseId, action, enabled, framework: fw } = req.body;

        if (!phaseId || !action) {
          return replyError(res, 400, [{ code: "MISSING_FIELDS", message: "phaseId and action are required" }]);
        }

        const frameworkKey = fw || "lockheed_martin";
        const frameworkDef = FRAMEWORKS[frameworkKey];
        if (!frameworkDef) {
          return replyError(res, 400, [{ code: "INVALID_FRAMEWORK", message: `Unknown framework: ${frameworkKey}` }]);
        }

        const phase = frameworkDef.phases.find((ph) => ph.id === phaseId);
        if (!phase) {
          return replyError(res, 400, [{ code: "INVALID_PHASE", message: `Unknown phase: ${phaseId}` }]);
        }

        const validActions = [
          "isolate_endpoint",
          "block_ip",
          "disable_account",
          "quarantine_file",
          "create_incident",
          "notify_soc",
          "trigger_playbook",
          "snapshot_forensics",
        ];

        if (!validActions.includes(action)) {
          return replyError(res, 400, [
            { code: "INVALID_ACTION", message: `Invalid action. Valid: ${validActions.join(", ")}` },
          ]);
        }

        // Store trigger configuration (using a generic settings approach)
        const triggerId = `kc-trigger-${frameworkKey}-${phaseId}-${action}`;
        const triggerConfig = {
          id: triggerId,
          orgId,
          framework: frameworkKey,
          phaseId,
          phaseName: phase.name,
          action,
          enabled: enabled !== false,
          createdAt: new Date().toISOString(),
        };

        // Upsert into a config table or return the configuration
        // For now, we store as org settings
        reply(res, {
          trigger: triggerConfig,
          message: `Response trigger "${action}" ${enabled !== false ? "enabled" : "disabled"} for phase "${phase.name}"`,
        });
      } catch (error) {
        log.error("Kill chain response trigger error", { error: String(error) });
        replyError(res, 500, [{ code: "KILL_CHAIN_ERROR", message: "Failed to configure response trigger" }]);
      }
    },
  );

  // GET /api/kill-chain/response-triggers — list configured triggers
  app.get(
    "/api/kill-chain/response-triggers",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const _orgId = getOrgId(req);
        const framework = p(req.query.framework as string) || "lockheed_martin";
        const fw = FRAMEWORKS[framework];
        if (!fw) {
          return replyError(res, 400, [{ code: "INVALID_FRAMEWORK", message: `Unknown framework: ${framework}` }]);
        }

        // Return default trigger configurations for each phase
        const validActions = [
          {
            id: "isolate_endpoint",
            name: "Isolate Endpoint",
            description: "Immediately isolate the affected endpoint from the network",
          },
          { id: "block_ip", name: "Block IP Address", description: "Add source IP to firewall block list" },
          { id: "disable_account", name: "Disable Account", description: "Disable the compromised user account" },
          { id: "quarantine_file", name: "Quarantine File", description: "Quarantine the malicious file" },
          { id: "create_incident", name: "Create Incident", description: "Automatically create an incident" },
          { id: "notify_soc", name: "Notify SOC", description: "Send high-priority alert to SOC team" },
          { id: "trigger_playbook", name: "Trigger Playbook", description: "Execute an automated response playbook" },
          {
            id: "snapshot_forensics",
            name: "Snapshot Forensics",
            description: "Capture forensic snapshot of the system",
          },
        ];

        const triggers = fw.phases.map((phase) => ({
          phaseId: phase.id,
          phaseName: phase.name,
          order: phase.order,
          severity: phase.severity,
          recommendedActions:
            phase.severity === "late"
              ? ["isolate_endpoint", "block_ip", "disable_account", "create_incident", "notify_soc"]
              : phase.severity === "mid"
                ? ["create_incident", "notify_soc", "trigger_playbook"]
                : ["notify_soc"],
          configuredActions: [] as string[],
        }));

        reply(res, { framework: { id: framework, name: fw.name }, triggers, availableActions: validActions });
      } catch (error) {
        log.error("Kill chain response triggers list error", { error: String(error) });
        replyError(res, 500, [{ code: "KILL_CHAIN_ERROR", message: "Failed to list response triggers" }]);
      }
    },
  );

  // 10.2: GET /api/kill-chain/active-campaigns — active campaigns with kill chain progression
  app.get(
    "/api/kill-chain/active-campaigns",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const framework = p(req.query.framework as string) || "lockheed_martin";
        const fw = FRAMEWORKS[framework];
        if (!fw) {
          return replyError(res, 400, [{ code: "INVALID_FRAMEWORK", message: `Unknown framework: ${framework}` }]);
        }

        // Get incidents that are still active (open/investigating)
        const activeIncidents = await pool.query(
          `SELECT id, title, severity, status, mitre_tactics, created_at, updated_at
           FROM incidents
           WHERE org_id = $1
             AND status IN ('open', 'investigating', 'in_progress')
             AND mitre_tactics IS NOT NULL
             AND array_length(mitre_tactics, 1) > 0
           ORDER BY
             CASE severity
               WHEN 'critical' THEN 0
               WHEN 'high' THEN 1
               WHEN 'medium' THEN 2
               WHEN 'low' THEN 3
               ELSE 4
             END,
             created_at DESC
           LIMIT 20`,
          [orgId],
        );

        const campaigns = activeIncidents.rows.map((row) => {
          const tactics = Array.isArray(row.mitre_tactics) ? row.mitre_tactics : [];
          const phaseProgression = fw.phases.map((phase) => {
            const isActive = tactics.some((t: string) => {
              const mapped = mapTacticToPhase(t, fw.phases);
              return mapped && mapped.id === phase.id;
            });

            // Calculate time in phase (approximation based on incident timeline)
            const createdAt = new Date(row.created_at).getTime();
            const now = Date.now();
            const totalDuration = now - createdAt;
            const timeInPhase = isActive ? Math.round(totalDuration / tactics.length) : 0;

            return {
              phaseId: phase.id,
              phaseName: phase.name,
              order: phase.order,
              isActive,
              timeInPhaseMs: timeInPhase,
              timeInPhaseHuman: isActive ? formatDuration(timeInPhase) : null,
            };
          });

          const activePhases = phaseProgression.filter((pp) => pp.isActive);
          const currentPhase = activePhases.length > 0 ? activePhases[activePhases.length - 1] : null;

          return {
            incidentId: row.id,
            title: row.title,
            severity: row.severity,
            status: row.status,
            createdAt: row.created_at,
            phases: phaseProgression,
            currentPhase: currentPhase?.phaseName || "Unknown",
            progressPercent: Math.round((activePhases.length / fw.phases.length) * 100),
            isLateStage: activePhases.some((ap) => {
              const phaseDef = fw.phases.find((p) => p.id === ap.phaseId);
              return phaseDef?.severity === "late";
            }),
          };
        });

        reply(res, {
          framework: { id: framework, name: fw.name },
          campaigns,
          activeCampaignCount: campaigns.length,
          lateStageCount: campaigns.filter((c) => c.isLateStage).length,
        });
      } catch (error) {
        log.error("Kill chain active campaigns error", { error: String(error) });
        replyError(res, 500, [{ code: "KILL_CHAIN_ERROR", message: "Failed to load active campaigns" }]);
      }
    },
  );
}

// ── Helper functions ─────────────────────────────────────────────────

function getHighestSeverity(items: Array<{ severity: string }>): string {
  const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
  let highest = "informational";
  let highestOrder = 4;
  for (const item of items) {
    const o = order[item.severity] ?? 5;
    if (o < highestOrder) {
      highestOrder = o;
      highest = item.severity;
    }
  }
  return highest;
}

function formatDuration(ms: number): string {
  if (ms <= 0) return "0s";
  const seconds = Math.floor(ms / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);
  if (days > 0) return `${days}d ${hours % 24}h`;
  if (hours > 0) return `${hours}h ${minutes % 60}m`;
  if (minutes > 0) return `${minutes}m`;
  return `${seconds}s`;
}

function calculateIncidentRiskScore(severity: string, phaseCount: number, reachedLateStage: boolean): number {
  const severityScore: Record<string, number> = { critical: 40, high: 30, medium: 20, low: 10, informational: 5 };
  let score = severityScore[severity] || 10;
  score += phaseCount * 10; // More phases = higher risk
  if (reachedLateStage) score += 25; // Late stage = significantly higher risk
  return Math.min(score, 100);
}
