import { storage } from "./storage";
import type { InvestigationRun, Incident, Alert } from "@shared/schema";

const INVESTIGATION_STEPS = [
  { type: "gather_alerts", title: "Gathering Related Alerts", order: 1 },
  { type: "enrich_entities", title: "Enriching Entities & IOCs", order: 2 },
  { type: "correlate_evidence", title: "Correlating Evidence", order: 3 },
  { type: "mitre_mapping", title: "MITRE ATT&CK Mapping", order: 4 },
  { type: "ai_analysis", title: "AI Deep Analysis", order: 5 },
  { type: "recommendation", title: "Generating Recommendations", order: 6 },
];

export async function runInvestigation(runId: string): Promise<void> {
  try {
    await storage.updateInvestigationRun(runId, { status: "running" });
    const run = await storage.getInvestigationRun(runId);
    if (!run || !run.incidentId) throw new Error("Invalid run");

    const startTime = Date.now();

    for (const stepDef of INVESTIGATION_STEPS) {
      await storage.createInvestigationStep({
        runId,
        stepType: stepDef.type,
        stepOrder: stepDef.order,
        title: stepDef.title,
        status: "pending",
      });
    }

    const steps = await storage.getInvestigationSteps(runId);
    const orgId = run.orgId ?? undefined;

    const step1 = steps.find(s => s.stepType === "gather_alerts");
    if (step1) {
      await storage.updateInvestigationStep(step1.id, { status: "running" });
      const allAlerts = await storage.getAlerts(orgId);
      const incidentAlerts = allAlerts.filter(a => a.incidentId === run.incidentId);
      const s1Start = Date.now();
      await storage.updateInvestigationStep(step1.id, {
        status: "completed",
        result: { alertCount: incidentAlerts.length, severities: countBy(incidentAlerts, "severity"), sources: countBy(incidentAlerts, "source") },
        duration: Date.now() - s1Start,
      });
    }

    const step2 = steps.find(s => s.stepType === "enrich_entities");
    if (step2) {
      await storage.updateInvestigationStep(step2.id, { status: "running" });
      const allAlerts = await storage.getAlerts(orgId);
      const incidentAlerts = allAlerts.filter(a => a.incidentId === run.incidentId);
      const s2Start = Date.now();
      const entitySet = new Set<string>();
      const entityDetails: any[] = [];
      for (const alert of incidentAlerts) {
        const raw = alert.rawData as any;
        if (raw?.sourceIp) { entitySet.add(raw.sourceIp); entityDetails.push({ type: "ip", value: raw.sourceIp }); }
        if (raw?.destIp) { entitySet.add(raw.destIp); entityDetails.push({ type: "ip", value: raw.destIp }); }
        if (raw?.hostname) { entitySet.add(raw.hostname); entityDetails.push({ type: "host", value: raw.hostname }); }
        if (raw?.username) { entitySet.add(raw.username); entityDetails.push({ type: "user", value: raw.username }); }
        if (raw?.domain) { entitySet.add(raw.domain); entityDetails.push({ type: "domain", value: raw.domain }); }
      }
      const uniqueEntities = entityDetails.filter((e, i, arr) => arr.findIndex(x => x.type === e.type && x.value === e.value) === i);
      await storage.updateInvestigationStep(step2.id, {
        status: "completed",
        result: { entityCount: uniqueEntities.length, entities: uniqueEntities.slice(0, 50) },
        artifacts: { iocs: uniqueEntities.filter(e => ["ip", "domain", "file_hash"].includes(e.type)) },
        duration: Date.now() - s2Start,
      });
    }

    const step3 = steps.find(s => s.stepType === "correlate_evidence");
    if (step3) {
      await storage.updateInvestigationStep(step3.id, { status: "running" });
      const allAlerts = await storage.getAlerts(orgId);
      const incidentAlerts = allAlerts.filter(a => a.incidentId === run.incidentId);
      const s3Start = Date.now();
      const timeline = incidentAlerts.sort((a, b) => new Date(a.detectedAt || a.createdAt || 0).getTime() - new Date(b.detectedAt || b.createdAt || 0).getTime());
      const timeSpan = timeline.length >= 2 ? (new Date(timeline[timeline.length - 1].detectedAt || timeline[timeline.length - 1].createdAt || 0).getTime() - new Date(timeline[0].detectedAt || timeline[0].createdAt || 0).getTime()) / 3600000 : 0;
      const attackPattern = {
        timeSpanHours: Math.round(timeSpan * 10) / 10,
        alertProgression: timeline.map(a => ({ severity: a.severity, category: a.category, source: a.source })),
        isMultiStage: new Set(incidentAlerts.map(a => a.category).filter(Boolean)).size > 1,
        sourceDiversity: new Set(incidentAlerts.map(a => a.source)).size,
      };
      await storage.updateInvestigationStep(step3.id, {
        status: "completed",
        result: { correlationPattern: attackPattern, evidenceStrength: attackPattern.isMultiStage ? "strong" : "moderate" },
        duration: Date.now() - s3Start,
      });
    }

    const step4 = steps.find(s => s.stepType === "mitre_mapping");
    if (step4) {
      await storage.updateInvestigationStep(step4.id, { status: "running" });
      const allAlerts = await storage.getAlerts(orgId);
      const incidentAlerts = allAlerts.filter(a => a.incidentId === run.incidentId);
      const s4Start = Date.now();
      const tactics = new Set<string>();
      const techniques = new Set<string>();
      for (const alert of incidentAlerts) {
        if (alert.mitreTactic) tactics.add(alert.mitreTactic);
        if (alert.mitreTechnique) techniques.add(alert.mitreTechnique);
      }
      const killChainStage = mapTacticsToKillChain(Array.from(tactics));
      await storage.updateInvestigationStep(step4.id, {
        status: "completed",
        result: { tactics: Array.from(tactics), techniques: Array.from(techniques), killChainStages: killChainStage, coverage: `${tactics.size}/14 tactics` },
        duration: Date.now() - s4Start,
      });
    }

    const step5 = steps.find(s => s.stepType === "ai_analysis");
    if (step5) {
      await storage.updateInvestigationStep(step5.id, { status: "running" });
      const allAlerts = await storage.getAlerts(orgId);
      const incidentAlerts = allAlerts.filter(a => a.incidentId === run.incidentId);
      const s5Start = Date.now();
      let aiSummary: string;
      try {
        const { generateIncidentNarrative } = await import("./ai");
        const incident = await storage.getIncident(run.incidentId!);
        if (incident) {
          const narrativeResult = await generateIncidentNarrative(incident, incidentAlerts);
          aiSummary = typeof narrativeResult === "string" ? narrativeResult : narrativeResult.narrative || narrativeResult.summary || JSON.stringify(narrativeResult);
        } else {
          aiSummary = generateFallbackAnalysis(incidentAlerts);
        }
      } catch {
        aiSummary = generateFallbackAnalysis(incidentAlerts);
      }
      await storage.updateInvestigationStep(step5.id, {
        status: "completed",
        result: { analysis: aiSummary, model: "mistral-large-2" },
        duration: Date.now() - s5Start,
      });
    }

    const step6 = steps.find(s => s.stepType === "recommendation");
    if (step6) {
      await storage.updateInvestigationStep(step6.id, { status: "running" });
      const allAlerts = await storage.getAlerts(orgId);
      const incidentAlerts = allAlerts.filter(a => a.incidentId === run.incidentId);
      const s6Start = Date.now();
      const recommendations = generateRecommendations(incidentAlerts);
      await storage.updateInvestigationStep(step6.id, {
        status: "completed",
        result: { recommendations },
        duration: Date.now() - s6Start,
      });
    }

    const completedSteps = await storage.getInvestigationSteps(runId);
    const allAlerts = await storage.getAlerts(orgId);
    const incidentAlerts = allAlerts.filter(a => a.incidentId === run.incidentId);
    const aiStep = completedSteps.find(s => s.stepType === "ai_analysis");
    const recStep = completedSteps.find(s => s.stepType === "recommendation");

    const findings = {
      alertsAnalyzed: incidentAlerts.length,
      stepsCompleted: completedSteps.filter(s => s.status === "completed").length,
      totalSteps: completedSteps.length,
    };

    const confidenceScore = calculateConfidence(incidentAlerts, completedSteps);

    await storage.updateInvestigationRun(runId, {
      status: "completed",
      summary: (aiStep?.result as any)?.analysis || "Investigation completed",
      findings,
      recommendedActions: (recStep?.result as any)?.recommendations || [],
      evidenceCount: incidentAlerts.length,
      confidenceScore,
      duration: Date.now() - startTime,
      completedAt: new Date(),
    });
  } catch (error: any) {
    await storage.updateInvestigationRun(runId, {
      status: "failed",
      error: error.message || "Unknown error",
      completedAt: new Date(),
    });
  }
}

function countBy(arr: any[], key: string): Record<string, number> {
  return arr.reduce((acc, item) => {
    const val = item[key] || "unknown";
    acc[val] = (acc[val] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);
}

function mapTacticsToKillChain(tactics: string[]): string[] {
  const mapping: Record<string, string> = {
    reconnaissance: "Reconnaissance",
    resource_development: "Weaponization",
    initial_access: "Delivery",
    execution: "Exploitation",
    persistence: "Installation",
    command_and_control: "C2",
    exfiltration: "Actions on Objectives",
    impact: "Actions on Objectives",
    lateral_movement: "Exploitation",
    privilege_escalation: "Exploitation",
    defense_evasion: "Installation",
    credential_access: "Exploitation",
    discovery: "Reconnaissance",
    collection: "Actions on Objectives",
  };
  const stages = new Set<string>();
  for (const t of tactics) {
    const normalized = t.toLowerCase().replace(/\s+/g, "_");
    if (mapping[normalized]) stages.add(mapping[normalized]);
  }
  return Array.from(stages);
}

function generateFallbackAnalysis(alerts: Alert[]): string {
  const sevCounts = countBy(alerts, "severity");
  const categories = Array.from(new Set(alerts.map(a => a.category).filter(Boolean)));
  const sources = Array.from(new Set(alerts.map(a => a.source)));
  return `Investigation analyzed ${alerts.length} alerts across ${sources.length} source(s). ` +
    `Severity breakdown: ${Object.entries(sevCounts).map(([k,v]) => `${v} ${k}`).join(", ")}. ` +
    `Attack categories observed: ${categories.join(", ") || "N/A"}. ` +
    `Further manual analysis recommended for comprehensive threat assessment.`;
}

function generateRecommendations(alerts: Alert[]): any[] {
  const recs: any[] = [];
  const categories = alerts.map(a => a.category).filter(Boolean);
  const hasCritical = alerts.some(a => a.severity === "critical");

  if (categories.includes("malware")) {
    recs.push({ action: "isolate_host", priority: "critical", reason: "Malware detected - isolate affected hosts immediately" });
    recs.push({ action: "quarantine_file", priority: "high", reason: "Quarantine malicious files identified in alerts" });
  }
  if (categories.includes("data_exfiltration")) {
    recs.push({ action: "block_ip", priority: "critical", reason: "Block exfiltration destination IPs" });
    recs.push({ action: "block_domain", priority: "high", reason: "Block suspicious domains used for data staging" });
  }
  if (categories.includes("credential_access") || categories.includes("privilege_escalation")) {
    recs.push({ action: "disable_user", priority: "critical", reason: "Disable compromised user accounts" });
  }
  if (categories.includes("lateral_movement")) {
    recs.push({ action: "isolate_host", priority: "high", reason: "Isolate hosts showing lateral movement to contain spread" });
  }
  if (hasCritical) {
    recs.push({ action: "escalate", priority: "critical", reason: "Critical severity - escalate to senior SOC analyst and incident commander" });
  }
  if (recs.length === 0) {
    recs.push({ action: "escalate", priority: "medium", reason: "Continue monitoring - escalate if additional indicators emerge" });
  }
  return recs;
}

function calculateConfidence(alerts: Alert[], steps: any[]): number {
  let score = 0.5;
  if (alerts.length >= 5) score += 0.15;
  else if (alerts.length >= 3) score += 0.1;
  else if (alerts.length >= 1) score += 0.05;
  const sources = new Set(alerts.map(a => a.source));
  if (sources.size >= 3) score += 0.15;
  else if (sources.size >= 2) score += 0.1;
  if (alerts.some(a => a.severity === "critical")) score += 0.1;
  const completedSteps = steps.filter((s: any) => s.status === "completed");
  score += (completedSteps.length / Math.max(steps.length, 1)) * 0.1;
  return Math.min(score, 0.99);
}
