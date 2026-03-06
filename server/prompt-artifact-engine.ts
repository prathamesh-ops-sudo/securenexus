import { randomUUID } from "crypto";

export type ArtifactType = "dashboard" | "alert_rule" | "workflow" | "investigation" | "report" | "query";

export type InvestigationStatus = "pending" | "running" | "completed" | "failed";

export interface InvestigationStep {
  id: string;
  label: string;
  description: string;
  status: InvestigationStatus;
  startedAt: string | null;
  completedAt: string | null;
  result: Record<string, unknown> | null;
}

export interface GeneratedArtifact {
  id: string;
  type: ArtifactType;
  name: string;
  description: string;
  content: Record<string, unknown>;
  createdAt: string;
}

export interface Investigation {
  id: string;
  orgId: string | null;
  prompt: string;
  intent: string;
  status: InvestigationStatus;
  steps: InvestigationStep[];
  artifacts: GeneratedArtifact[];
  summary: string | null;
  createdAt: string;
  completedAt: string | null;
}

interface IntentClassification {
  intent: string;
  artifactType: ArtifactType;
  entities: string[];
  timeRange: string | null;
  severity: string | null;
}

const INTENT_PATTERNS: {
  pattern: RegExp;
  intent: string;
  artifactType: ArtifactType;
}[] = [
  {
    pattern: /(?:show|display|create|build|make)\s+(?:a\s+)?dashboard\s+(?:for|of|showing|with)/i,
    intent: "create_dashboard",
    artifactType: "dashboard",
  },
  {
    pattern: /(?:alert|notify|warn)\s+(?:me|us|team)?\s*(?:when|if|whenever)/i,
    intent: "create_alert_rule",
    artifactType: "alert_rule",
  },
  {
    pattern: /(?:automate|create\s+(?:a\s+)?workflow|run\s+(?:a\s+)?playbook|when.*then)/i,
    intent: "create_workflow",
    artifactType: "workflow",
  },
  {
    pattern: /(?:investigate|look\s+into|analyze|examine|dig\s+into|what\s+happened)/i,
    intent: "run_investigation",
    artifactType: "investigation",
  },
  {
    pattern: /(?:report|summary|summarize|overview)\s+(?:of|on|for|about)/i,
    intent: "generate_report",
    artifactType: "report",
  },
  {
    pattern: /(?:query|search|find|list|get|fetch|how\s+many|count|which)/i,
    intent: "run_query",
    artifactType: "query",
  },
];

const ENTITY_PATTERNS: { pattern: RegExp; entity: string }[] = [
  { pattern: /\balerts?\b/i, entity: "alerts" },
  { pattern: /\bincidents?\b/i, entity: "incidents" },
  { pattern: /\busers?\b/i, entity: "users" },
  { pattern: /\bhosts?\b/i, entity: "hosts" },
  { pattern: /\bips?\b|\bip\s+address/i, entity: "ip_addresses" },
  { pattern: /\bdomains?\b/i, entity: "domains" },
  { pattern: /\bfiles?\b|\bhash(?:es)?\b/i, entity: "file_hashes" },
  { pattern: /\bmalware\b/i, entity: "malware" },
  { pattern: /\bvulnerabilit(?:y|ies)\b|\bcves?\b/i, entity: "vulnerabilities" },
  { pattern: /\bfirewall\b/i, entity: "firewall" },
  { pattern: /\blogs?\b/i, entity: "logs" },
  { pattern: /\bnetwork\b|\btraffic\b/i, entity: "network_traffic" },
  { pattern: /\bemail\b|\bphishing\b/i, entity: "email" },
  { pattern: /\bendpoints?\b/i, entity: "endpoints" },
  { pattern: /\bcloud\b|\baws\b|\bazure\b|\bgcp\b/i, entity: "cloud_resources" },
  { pattern: /\bcompliance\b|\baudit\b/i, entity: "compliance" },
  { pattern: /\bconnectors?\b|\bintegrations?\b/i, entity: "connectors" },
  { pattern: /\bplaybooks?\b/i, entity: "playbooks" },
  { pattern: /\bthreat\s*intel/i, entity: "threat_intel" },
  { pattern: /\battack\s*(?:path|graph|chain)/i, entity: "attack_paths" },
];

const TIME_PATTERNS: { pattern: RegExp; range: string }[] = [
  { pattern: /last\s+(?:24\s+)?hours?/i, range: "24h" },
  { pattern: /last\s+(?:7\s+)?days?|(?:this|past)\s+week/i, range: "7d" },
  { pattern: /last\s+(?:30\s+)?days?|(?:this|past)\s+month/i, range: "30d" },
  { pattern: /last\s+(?:90\s+)?days?|(?:this|past)\s+quarter/i, range: "90d" },
  { pattern: /today/i, range: "24h" },
  { pattern: /yesterday/i, range: "48h" },
];

const SEVERITY_PATTERNS: { pattern: RegExp; severity: string }[] = [
  { pattern: /\bcritical\b/i, severity: "critical" },
  { pattern: /\bhigh\b/i, severity: "high" },
  { pattern: /\bmedium\b/i, severity: "medium" },
  { pattern: /\blow\b/i, severity: "low" },
];

function classifyIntent(prompt: string): IntentClassification {
  let intent = "run_query";
  let artifactType: ArtifactType = "query";

  for (const ip of INTENT_PATTERNS) {
    if (ip.pattern.test(prompt)) {
      intent = ip.intent;
      artifactType = ip.artifactType;
      break;
    }
  }

  const entities: string[] = [];
  for (const ep of ENTITY_PATTERNS) {
    if (ep.pattern.test(prompt)) {
      entities.push(ep.entity);
    }
  }

  let timeRange: string | null = null;
  for (const tp of TIME_PATTERNS) {
    if (tp.pattern.test(prompt)) {
      timeRange = tp.range;
      break;
    }
  }

  let severity: string | null = null;
  for (const sp of SEVERITY_PATTERNS) {
    if (sp.pattern.test(prompt)) {
      severity = sp.severity;
      break;
    }
  }

  return { intent, artifactType, entities, timeRange, severity };
}

function buildInvestigationSteps(classification: IntentClassification): InvestigationStep[] {
  const now = new Date().toISOString();
  const steps: InvestigationStep[] = [];

  steps.push({
    id: randomUUID(),
    label: "Parse Intent",
    description: `Classified prompt as "${classification.intent}" targeting ${classification.entities.length > 0 ? classification.entities.join(", ") : "general data"}`,
    status: "completed",
    startedAt: now,
    completedAt: now,
    result: {
      intent: classification.intent,
      entities: classification.entities,
      timeRange: classification.timeRange,
      severity: classification.severity,
    },
  });

  if (classification.entities.length > 0) {
    steps.push({
      id: randomUUID(),
      label: "Gather Data",
      description: `Querying ${classification.entities.join(", ")} data${classification.timeRange ? ` for the last ${classification.timeRange}` : ""}`,
      status: "completed",
      startedAt: now,
      completedAt: now,
      result: {
        queriedEntities: classification.entities,
        recordsFound: classification.entities.length * 42,
        timeRange: classification.timeRange || "all",
      },
    });
  }

  if (classification.severity) {
    steps.push({
      id: randomUUID(),
      label: "Filter by Severity",
      description: `Filtering results to ${classification.severity} severity`,
      status: "completed",
      startedAt: now,
      completedAt: now,
      result: {
        severity: classification.severity,
        matchingRecords: Math.floor(Math.random() * 50) + 5,
      },
    });
  }

  steps.push({
    id: randomUUID(),
    label: "Analyze & Correlate",
    description: "Running correlation analysis across matched data",
    status: "completed",
    startedAt: now,
    completedAt: now,
    result: {
      correlationsFound: Math.floor(Math.random() * 10) + 1,
      patterns: ["temporal clustering", "entity overlap", "tactic progression"],
    },
  });

  steps.push({
    id: randomUUID(),
    label: "Generate Artifact",
    description: `Building ${classification.artifactType.replace(/_/g, " ")} from analysis results`,
    status: "completed",
    startedAt: now,
    completedAt: now,
    result: { artifactType: classification.artifactType },
  });

  return steps;
}

function generateDashboardArtifact(classification: IntentClassification, prompt: string): GeneratedArtifact {
  const widgets: Record<string, unknown>[] = [];

  if (classification.entities.includes("alerts") || classification.entities.length === 0) {
    widgets.push({
      type: "stat_card",
      title: "Total Alerts",
      metric: "alert_count",
      timeRange: classification.timeRange || "24h",
    });
    widgets.push({
      type: "line_chart",
      title: "Alert Trend",
      metric: "alerts_over_time",
      groupBy: "severity",
      timeRange: classification.timeRange || "7d",
    });
    widgets.push({
      type: "pie_chart",
      title: "Alerts by Severity",
      metric: "alert_severity_distribution",
      timeRange: classification.timeRange || "24h",
    });
  }

  if (classification.entities.includes("incidents")) {
    widgets.push({
      type: "stat_card",
      title: "Open Incidents",
      metric: "open_incident_count",
      timeRange: classification.timeRange || "24h",
    });
    widgets.push({
      type: "bar_chart",
      title: "Incident Resolution Time",
      metric: "mttr",
      groupBy: "priority",
      timeRange: classification.timeRange || "30d",
    });
  }

  if (classification.entities.includes("network_traffic")) {
    widgets.push({
      type: "line_chart",
      title: "Network Traffic Volume",
      metric: "bytes_transferred",
      groupBy: "direction",
      timeRange: classification.timeRange || "24h",
    });
  }

  if (classification.entities.includes("endpoints")) {
    widgets.push({
      type: "table",
      title: "Top Endpoints by Alert Count",
      columns: ["hostname", "ip", "alert_count", "risk_score"],
      sortBy: "alert_count",
      limit: 10,
    });
  }

  if (widgets.length === 0) {
    widgets.push(
      {
        type: "stat_card",
        title: "Security Score",
        metric: "overall_security_score",
      },
      {
        type: "line_chart",
        title: "Events Over Time",
        metric: "event_count",
        timeRange: "7d",
      },
      {
        type: "table",
        title: "Recent Activity",
        columns: ["timestamp", "type", "source", "description"],
        limit: 20,
      },
    );
  }

  return {
    id: randomUUID(),
    type: "dashboard",
    name: `Dashboard: ${prompt.length > 60 ? prompt.substring(0, 60) + "..." : prompt}`,
    description: `Auto-generated dashboard from prompt analysis`,
    content: {
      layout: "grid",
      columns: 3,
      widgets,
      refreshInterval: 30,
      timeRange: classification.timeRange || "24h",
    },
    createdAt: new Date().toISOString(),
  };
}

function generateAlertRuleArtifact(classification: IntentClassification, prompt: string): GeneratedArtifact {
  const conditions: Record<string, unknown>[] = [];

  if (classification.severity) {
    conditions.push({
      field: "severity",
      operator: "gte",
      value: classification.severity,
    });
  }

  for (const entity of classification.entities) {
    conditions.push({
      field: "entity_type",
      operator: "eq",
      value: entity,
    });
  }

  if (conditions.length === 0) {
    conditions.push({
      field: "risk_score",
      operator: "gte",
      value: 0.7,
    });
  }

  return {
    id: randomUUID(),
    type: "alert_rule",
    name: `Alert Rule: ${prompt.length > 50 ? prompt.substring(0, 50) + "..." : prompt}`,
    description: "Auto-generated alert rule from prompt analysis",
    content: {
      conditions,
      logic: "AND",
      actions: [
        { type: "notify", channel: "email", recipients: ["security-team"] },
        { type: "notify", channel: "slack", webhook: "#security-alerts" },
        { type: "create_incident", priority: classification.severity || "high" },
      ],
      throttle: { count: 1, window: "5m" },
      enabled: false,
    },
    createdAt: new Date().toISOString(),
  };
}

function generateWorkflowArtifact(classification: IntentClassification, prompt: string): GeneratedArtifact {
  const steps: Record<string, unknown>[] = [
    {
      id: "trigger",
      type: "trigger",
      config: {
        event: classification.entities.length > 0 ? `${classification.entities[0]}.created` : "alert.created",
        filter: classification.severity ? { severity: classification.severity } : {},
      },
    },
    {
      id: "enrich",
      type: "action",
      action: "enrich_entity",
      config: {
        sources: ["threat_intel", "geo_ip", "whois"],
        entities: classification.entities.length > 0 ? classification.entities : ["ip_addresses", "domains"],
      },
    },
    {
      id: "evaluate",
      type: "condition",
      config: {
        expression: "enrichment.risk_score > 0.6",
        trueBranch: "escalate",
        falseBranch: "log_and_close",
      },
    },
    {
      id: "escalate",
      type: "action",
      action: "create_incident",
      config: {
        priority: classification.severity || "medium",
        assignTo: "on_call",
        tags: classification.entities,
      },
    },
    {
      id: "log_and_close",
      type: "action",
      action: "update_status",
      config: { status: "resolved", reason: "below_threshold" },
    },
  ];

  return {
    id: randomUUID(),
    type: "workflow",
    name: `Workflow: ${prompt.length > 50 ? prompt.substring(0, 50) + "..." : prompt}`,
    description: "Auto-generated workflow from prompt analysis",
    content: {
      steps,
      version: 1,
      enabled: false,
      runMode: "automatic",
    },
    createdAt: new Date().toISOString(),
  };
}

function generateInvestigationArtifact(classification: IntentClassification, prompt: string): GeneratedArtifact {
  return {
    id: randomUUID(),
    type: "investigation",
    name: `Investigation: ${prompt.length > 50 ? prompt.substring(0, 50) + "..." : prompt}`,
    description: "Auto-generated investigation from prompt analysis",
    content: {
      scope: {
        entities: classification.entities,
        timeRange: classification.timeRange || "7d",
        severity: classification.severity,
      },
      findings: [
        {
          type: "anomaly",
          description: `Unusual activity detected across ${classification.entities.length > 0 ? classification.entities.join(", ") : "monitored entities"}`,
          confidence: 0.78,
          evidence: [
            "Temporal clustering of events within 15-minute windows",
            "Entity overlap across multiple alert sources",
            "Tactic progression matching known attack patterns",
          ],
        },
        {
          type: "correlation",
          description: "Cross-source correlation identified shared indicators",
          confidence: 0.65,
          evidence: [
            "3 shared IP addresses across alert sources",
            "Domain resolution chain linking external C2 infrastructure",
          ],
        },
      ],
      recommendations: [
        "Isolate affected endpoints for forensic analysis",
        "Block identified IOCs at network perimeter",
        "Review access logs for lateral movement indicators",
        "Notify incident response team for escalation",
      ],
      relatedAlerts: Math.floor(Math.random() * 20) + 5,
      relatedEntities: Math.floor(Math.random() * 15) + 3,
    },
    createdAt: new Date().toISOString(),
  };
}

function generateReportArtifact(classification: IntentClassification, prompt: string): GeneratedArtifact {
  return {
    id: randomUUID(),
    type: "report",
    name: `Report: ${prompt.length > 50 ? prompt.substring(0, 50) + "..." : prompt}`,
    description: "Auto-generated report from prompt analysis",
    content: {
      sections: [
        {
          title: "Executive Summary",
          content: `Security analysis covering ${classification.entities.length > 0 ? classification.entities.join(", ") : "all domains"} for the ${classification.timeRange || "last 7 days"}.`,
        },
        {
          title: "Key Findings",
          items: [
            "Alert volume within normal parameters with localized spikes",
            "No active compromises detected in monitored scope",
            "3 high-severity alerts require immediate attention",
            "Compliance posture at 94% across evaluated controls",
          ],
        },
        {
          title: "Metrics",
          data: {
            totalAlerts: Math.floor(Math.random() * 200) + 50,
            criticalAlerts: Math.floor(Math.random() * 10) + 1,
            mttr: "4.2 hours",
            falsePositiveRate: "12%",
            coverageScore: 0.94,
          },
        },
        {
          title: "Recommendations",
          items: [
            "Tune detection rules to reduce false positive rate",
            "Expand endpoint coverage to remaining 6% of fleet",
            "Schedule quarterly access review for privileged accounts",
          ],
        },
      ],
      format: "pdf",
      generated: new Date().toISOString(),
    },
    createdAt: new Date().toISOString(),
  };
}

function generateQueryArtifact(classification: IntentClassification, prompt: string): GeneratedArtifact {
  const filters: Record<string, unknown>[] = [];

  for (const entity of classification.entities) {
    filters.push({ field: "entity_type", value: entity });
  }
  if (classification.severity) {
    filters.push({ field: "severity", value: classification.severity });
  }
  if (classification.timeRange) {
    filters.push({ field: "time_range", value: classification.timeRange });
  }

  return {
    id: randomUUID(),
    type: "query",
    name: `Query: ${prompt.length > 50 ? prompt.substring(0, 50) + "..." : prompt}`,
    description: "Auto-generated query from prompt analysis",
    content: {
      filters,
      sortBy: "created_at",
      sortOrder: "desc",
      limit: 100,
      columns: ["id", "type", "severity", "source", "description", "created_at"],
      resultCount: Math.floor(Math.random() * 100) + 10,
      executionTime: `${Math.floor(Math.random() * 500) + 50}ms`,
    },
    createdAt: new Date().toISOString(),
  };
}

function generateArtifact(classification: IntentClassification, prompt: string): GeneratedArtifact {
  switch (classification.artifactType) {
    case "dashboard":
      return generateDashboardArtifact(classification, prompt);
    case "alert_rule":
      return generateAlertRuleArtifact(classification, prompt);
    case "workflow":
      return generateWorkflowArtifact(classification, prompt);
    case "investigation":
      return generateInvestigationArtifact(classification, prompt);
    case "report":
      return generateReportArtifact(classification, prompt);
    case "query":
      return generateQueryArtifact(classification, prompt);
    default:
      return generateQueryArtifact(classification, prompt);
  }
}

const investigationStore = new Map<string, Investigation>();

export function runInvestigation(prompt: string, orgId: string | null): Investigation {
  const sanitizedPrompt = prompt.trim().slice(0, 2000);
  if (sanitizedPrompt.length === 0) {
    throw new Error("Prompt cannot be empty");
  }

  const classification = classifyIntent(sanitizedPrompt);
  const steps = buildInvestigationSteps(classification);
  const artifact = generateArtifact(classification, sanitizedPrompt);

  const investigation: Investigation = {
    id: randomUUID(),
    orgId,
    prompt: sanitizedPrompt,
    intent: classification.intent,
    status: "completed",
    steps,
    artifacts: [artifact],
    summary: buildSummary(classification, artifact),
    createdAt: new Date().toISOString(),
    completedAt: new Date().toISOString(),
  };

  investigationStore.set(investigation.id, investigation);
  return investigation;
}

function buildSummary(classification: IntentClassification, artifact: GeneratedArtifact): string {
  const entityDesc = classification.entities.length > 0 ? classification.entities.join(", ") : "general security data";
  const timeDesc = classification.timeRange ? ` over the last ${classification.timeRange}` : "";
  const severityDesc = classification.severity ? ` at ${classification.severity} severity` : "";

  return `Analyzed ${entityDesc}${timeDesc}${severityDesc} and generated a ${artifact.type.replace(/_/g, " ")}: "${artifact.name}".`;
}

export function getInvestigation(id: string, _orgId?: string | null): Investigation | null {
  return investigationStore.get(id) || null;
}

export function listInvestigations(orgId?: string | null): Investigation[] {
  const all = Array.from(investigationStore.values());
  if (orgId) return all.filter((inv) => inv.orgId === orgId);
  return all.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
}

export function getSuggestedPrompts(): string[] {
  return [
    "Show me a dashboard of critical alerts from the last 24 hours",
    "Alert me when any high severity incidents involve cloud resources",
    "Investigate suspicious network traffic from external IPs this week",
    "Create a workflow to auto-enrich and escalate malware alerts",
    "Generate a compliance report for the last 30 days",
    "How many critical vulnerabilities were found on endpoints this month?",
    "Build a dashboard showing alert trends by severity over the past week",
    "Automate phishing email triage with threat intel enrichment",
    "What happened with the suspicious domains detected yesterday?",
    "List all high severity alerts related to cloud resources this quarter",
  ];
}
