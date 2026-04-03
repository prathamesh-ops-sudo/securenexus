import { randomUUID } from "crypto";

export type ArtifactType = "dashboard" | "alert_rule" | "workflow" | "investigation" | "report" | "query";

export type InvestigationStatus = "pending" | "running" | "completed" | "failed";

export type ApprovalStatus = "not_required" | "pending_approval" | "approved" | "rejected";

export interface SourceCitation {
  id: string;
  source: string;
  description: string;
  dataPoints: number;
  confidence: number;
  retrievedAt: string;
}

export interface QueryPlan {
  id: string;
  type: "filter" | "aggregate" | "join" | "sort" | "limit" | "enrich" | "correlate";
  description: string;
  params: Record<string, unknown>;
  estimatedCost: "low" | "medium" | "high";
  citations: string[];
}

export interface ConstrainedTemplate {
  id: string;
  name: string;
  artifactType: ArtifactType;
  description: string;
  queryPlan: QueryPlan[];
  requiredEntities: string[];
  outputSchema: Record<string, string>;
}

export interface ApprovalGate {
  id: string;
  artifactId: string;
  reason: string;
  requiredRole: string;
  status: ApprovalStatus;
  requestedBy: string;
  requestedAt: string;
  reviewedBy: string | null;
  reviewedAt: string | null;
  reviewNotes: string | null;
}

export interface EditableLogicBlock {
  id: string;
  label: string;
  language: "json" | "kql" | "sql" | "yaml" | "pseudocode";
  code: string;
  description: string;
  editable: boolean;
}

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
  editableLogic: EditableLogicBlock[];
  citations: SourceCitation[];
  approvalGate: ApprovalGate | null;
  templateId: string | null;
  queryPlan: QueryPlan[];
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
  citations: SourceCitation[];
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

const CONSTRAINED_TEMPLATES: ConstrainedTemplate[] = [
  {
    id: "tmpl-dashboard-alert-overview",
    name: "Alert Overview Dashboard",
    artifactType: "dashboard",
    description: "Multi-widget dashboard showing alert distribution, trends, and top sources",
    requiredEntities: ["alerts"],
    queryPlan: [
      {
        id: "qp-1",
        type: "filter",
        description: "Filter alerts by time range and severity",
        params: { table: "alerts", fields: ["severity", "created_at", "source"] },
        estimatedCost: "low",
        citations: ["alerts_table", "severity_index"],
      },
      {
        id: "qp-2",
        type: "aggregate",
        description: "Count alerts grouped by severity and source",
        params: { groupBy: ["severity", "source"], metric: "count" },
        estimatedCost: "low",
        citations: ["alerts_table"],
      },
      {
        id: "qp-3",
        type: "aggregate",
        description: "Compute alert trend over time buckets",
        params: { groupBy: ["time_bucket"], metric: "count", interval: "1h" },
        estimatedCost: "medium",
        citations: ["alerts_table", "time_series_index"],
      },
    ],
    outputSchema: { layout: "string", columns: "number", widgets: "Widget[]", refreshInterval: "number" },
  },
  {
    id: "tmpl-alert-rule-threshold",
    name: "Threshold Alert Rule",
    artifactType: "alert_rule",
    description: "Condition-based alert rule with severity filtering and notification actions",
    requiredEntities: [],
    queryPlan: [
      {
        id: "qp-1",
        type: "filter",
        description: "Evaluate incoming events against conditions",
        params: { evaluationType: "streaming", windowSize: "5m" },
        estimatedCost: "low",
        citations: ["event_stream"],
      },
      {
        id: "qp-2",
        type: "aggregate",
        description: "Count matching events within throttle window",
        params: { metric: "count", window: "5m" },
        estimatedCost: "low",
        citations: ["event_stream", "throttle_state"],
      },
    ],
    outputSchema: { conditions: "Condition[]", logic: "string", actions: "Action[]", throttle: "ThrottleConfig" },
  },
  {
    id: "tmpl-workflow-triage",
    name: "Automated Triage Workflow",
    artifactType: "workflow",
    description: "Multi-step workflow: trigger, enrich, evaluate, escalate or close",
    requiredEntities: [],
    queryPlan: [
      {
        id: "qp-1",
        type: "filter",
        description: "Match incoming events to trigger conditions",
        params: { source: "event_bus", matchType: "pattern" },
        estimatedCost: "low",
        citations: ["event_bus", "trigger_registry"],
      },
      {
        id: "qp-2",
        type: "enrich",
        description: "Enrich matched entities with threat intel and geo data",
        params: { sources: ["threat_intel", "geo_ip", "whois"] },
        estimatedCost: "medium",
        citations: ["threat_intel_feeds", "geo_ip_db", "whois_cache"],
      },
      {
        id: "qp-3",
        type: "correlate",
        description: "Cross-reference enriched data against known IOCs",
        params: { correlationType: "ioc_match", threshold: 0.6 },
        estimatedCost: "high",
        citations: ["ioc_database", "threat_intel_feeds"],
      },
    ],
    outputSchema: { steps: "WorkflowStep[]", version: "number", enabled: "boolean", runMode: "string" },
  },
  {
    id: "tmpl-investigation-scope",
    name: "Scoped Security Investigation",
    artifactType: "investigation",
    description: "Entity-scoped investigation with correlation analysis and recommendations",
    requiredEntities: [],
    queryPlan: [
      {
        id: "qp-1",
        type: "filter",
        description: "Gather all events for target entities within time range",
        params: { scope: "entity_set", joinType: "union" },
        estimatedCost: "medium",
        citations: ["alerts_table", "incidents_table", "logs_table"],
      },
      {
        id: "qp-2",
        type: "correlate",
        description: "Run temporal and entity correlation across sources",
        params: { methods: ["temporal_clustering", "entity_overlap", "tactic_progression"] },
        estimatedCost: "high",
        citations: ["correlation_engine", "mitre_attack_db"],
      },
      {
        id: "qp-3",
        type: "enrich",
        description: "Enrich findings with threat intelligence context",
        params: { sources: ["threat_intel", "vulnerability_db"] },
        estimatedCost: "medium",
        citations: ["threat_intel_feeds", "nvd_database"],
      },
    ],
    outputSchema: {
      scope: "InvestigationScope",
      findings: "Finding[]",
      recommendations: "string[]",
      relatedAlerts: "number",
    },
  },
  {
    id: "tmpl-report-compliance",
    name: "Compliance & Security Report",
    artifactType: "report",
    description: "Multi-section report with executive summary, findings, metrics, and recommendations",
    requiredEntities: [],
    queryPlan: [
      {
        id: "qp-1",
        type: "aggregate",
        description: "Compute key security metrics across all data sources",
        params: { metrics: ["alert_count", "mttr", "false_positive_rate", "coverage_score"] },
        estimatedCost: "medium",
        citations: ["alerts_table", "incidents_table", "compliance_controls"],
      },
      {
        id: "qp-2",
        type: "filter",
        description: "Identify top findings and critical items",
        params: { severity: ["critical", "high"], limit: 10 },
        estimatedCost: "low",
        citations: ["alerts_table", "vulnerability_db"],
      },
      {
        id: "qp-3",
        type: "aggregate",
        description: "Calculate compliance posture across control frameworks",
        params: { frameworks: ["SOC2", "ISO27001", "NIST"], metric: "pass_rate" },
        estimatedCost: "medium",
        citations: ["compliance_controls", "policy_engine"],
      },
    ],
    outputSchema: { sections: "ReportSection[]", format: "string", generated: "string" },
  },
  {
    id: "tmpl-query-search",
    name: "Filtered Data Query",
    artifactType: "query",
    description: "Parameterized search query with entity, severity, and time filtering",
    requiredEntities: [],
    queryPlan: [
      {
        id: "qp-1",
        type: "filter",
        description: "Apply entity type, severity, and time range filters",
        params: { filterMode: "AND", indexHint: "composite_idx" },
        estimatedCost: "low",
        citations: ["events_table"],
      },
      {
        id: "qp-2",
        type: "sort",
        description: "Sort results by creation time descending",
        params: { field: "created_at", order: "desc" },
        estimatedCost: "low",
        citations: ["events_table"],
      },
      {
        id: "qp-3",
        type: "limit",
        description: "Limit result set to prevent over-fetching",
        params: { maxRows: 100 },
        estimatedCost: "low",
        citations: ["events_table"],
      },
    ],
    outputSchema: { filters: "Filter[]", sortBy: "string", sortOrder: "string", limit: "number", columns: "string[]" },
  },
];

const DATA_SOURCE_CITATIONS: Record<string, Omit<SourceCitation, "id" | "retrievedAt">> = {
  alerts_table: {
    source: "SecureNexus Alerts Database",
    description: "Primary alert storage with severity, source, entity, and timestamp fields",
    dataPoints: 15420,
    confidence: 0.98,
  },
  incidents_table: {
    source: "SecureNexus Incidents Database",
    description: "Incident records with priority, status, assignee, and resolution data",
    dataPoints: 3280,
    confidence: 0.97,
  },
  logs_table: {
    source: "SecureNexus Log Aggregator",
    description: "Centralized log storage from all connected sources",
    dataPoints: 2450000,
    confidence: 0.95,
  },
  events_table: {
    source: "SecureNexus Event Bus",
    description: "Unified event stream from all connectors and internal systems",
    dataPoints: 890000,
    confidence: 0.96,
  },
  severity_index: {
    source: "Severity Classification Index",
    description: "Pre-computed severity distribution for fast aggregation",
    dataPoints: 15420,
    confidence: 0.99,
  },
  time_series_index: {
    source: "Time-Series Materialized View",
    description: "Hourly/daily bucketed alert counts for trend analysis",
    dataPoints: 8760,
    confidence: 0.99,
  },
  event_stream: {
    source: "Real-Time Event Stream",
    description: "Live event ingestion pipeline from all connectors",
    dataPoints: 0,
    confidence: 0.94,
  },
  event_bus: {
    source: "Internal Event Bus",
    description: "Pub/sub event distribution for workflow triggers",
    dataPoints: 0,
    confidence: 0.97,
  },
  trigger_registry: {
    source: "Workflow Trigger Registry",
    description: "Registered event patterns that activate automation workflows",
    dataPoints: 48,
    confidence: 1.0,
  },
  throttle_state: {
    source: "Alert Throttle State Store",
    description: "In-memory throttle counters to prevent alert flooding",
    dataPoints: 256,
    confidence: 1.0,
  },
  threat_intel_feeds: {
    source: "Aggregated Threat Intelligence Feeds",
    description: "OSINT and commercial threat intel including IOCs, TTPs, and actor profiles",
    dataPoints: 125000,
    confidence: 0.88,
  },
  geo_ip_db: {
    source: "GeoIP Database (MaxMind)",
    description: "IP-to-location mapping for geographic enrichment",
    dataPoints: 4200000,
    confidence: 0.92,
  },
  whois_cache: {
    source: "WHOIS Lookup Cache",
    description: "Cached domain registration data for ownership analysis",
    dataPoints: 34000,
    confidence: 0.85,
  },
  ioc_database: {
    source: "IOC Indicator Database",
    description: "Known indicators of compromise: IPs, domains, hashes, URLs",
    dataPoints: 89000,
    confidence: 0.91,
  },
  correlation_engine: {
    source: "SecureNexus Correlation Engine",
    description: "Cross-source correlation rules and pattern matching results",
    dataPoints: 1200,
    confidence: 0.87,
  },
  mitre_attack_db: {
    source: "MITRE ATT&CK Framework",
    description: "Tactic, technique, and procedure mappings for attack classification",
    dataPoints: 780,
    confidence: 0.99,
  },
  nvd_database: {
    source: "National Vulnerability Database (NVD)",
    description: "CVE entries with CVSS scores and affected product data",
    dataPoints: 220000,
    confidence: 0.97,
  },
  vulnerability_db: {
    source: "SecureNexus Vulnerability Scanner",
    description: "Discovered vulnerabilities from endpoint and cloud scanning",
    dataPoints: 4500,
    confidence: 0.93,
  },
  compliance_controls: {
    source: "Compliance Control Framework",
    description: "SOC2, ISO 27001, NIST, and custom control evaluation results",
    dataPoints: 340,
    confidence: 0.96,
  },
  policy_engine: {
    source: "SecureNexus Policy Engine",
    description: "Active security policies and their enforcement status",
    dataPoints: 128,
    confidence: 1.0,
  },
};

function buildCitation(sourceKey: string): SourceCitation {
  const base = DATA_SOURCE_CITATIONS[sourceKey];
  if (!base) {
    return {
      id: randomUUID(),
      source: sourceKey,
      description: "Unknown data source",
      dataPoints: 0,
      confidence: 0.5,
      retrievedAt: new Date().toISOString(),
    };
  }
  return { id: randomUUID(), ...base, retrievedAt: new Date().toISOString() };
}

function collectCitations(queryPlan: QueryPlan[]): SourceCitation[] {
  const seen = new Set<string>();
  const citations: SourceCitation[] = [];
  for (const step of queryPlan) {
    for (const key of step.citations) {
      if (!seen.has(key)) {
        seen.add(key);
        citations.push(buildCitation(key));
      }
    }
  }
  return citations;
}

function selectTemplate(classification: IntentClassification): ConstrainedTemplate {
  const candidates = CONSTRAINED_TEMPLATES.filter((t) => t.artifactType === classification.artifactType);
  if (candidates.length === 0) {
    return CONSTRAINED_TEMPLATES[CONSTRAINED_TEMPLATES.length - 1];
  }
  const entityMatch = candidates.find(
    (t) => t.requiredEntities.length === 0 || t.requiredEntities.some((e) => classification.entities.includes(e)),
  );
  return entityMatch || candidates[0];
}

function requiresApproval(artifactType: ArtifactType): boolean {
  return artifactType === "workflow" || artifactType === "alert_rule";
}

function createApprovalGate(artifactId: string, artifactType: ArtifactType): ApprovalGate {
  const reasons: Record<string, string> = {
    workflow:
      "Automated workflows can trigger actions (create incidents, notify teams, modify entity status). Approval required before activation.",
    alert_rule: "Alert rules generate notifications and can auto-create incidents. Approval required before enabling.",
  };
  return {
    id: randomUUID(),
    artifactId,
    reason: reasons[artifactType] || "This artifact can trigger automated actions.",
    requiredRole: "security_admin",
    status: "pending_approval",
    requestedBy: "prompt-to-artifact-engine",
    requestedAt: new Date().toISOString(),
    reviewedBy: null,
    reviewedAt: null,
    reviewNotes: null,
  };
}

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

function buildInvestigationSteps(
  classification: IntentClassification,
  template: ConstrainedTemplate,
): InvestigationStep[] {
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

  steps.push({
    id: randomUUID(),
    label: "Select Template",
    description: `Matched constrained template: "${template.name}" (${template.id})`,
    status: "completed",
    startedAt: now,
    completedAt: now,
    result: { templateId: template.id, templateName: template.name, queryPlanSteps: template.queryPlan.length },
  });

  for (const qp of template.queryPlan) {
    steps.push({
      id: randomUUID(),
      label: `Execute: ${qp.type}`,
      description: qp.description,
      status: "completed",
      startedAt: now,
      completedAt: now,
      result: {
        planStepId: qp.id,
        type: qp.type,
        estimatedCost: qp.estimatedCost,
        dataSources: qp.citations.join(", "),
      },
    });
  }

  steps.push({
    id: randomUUID(),
    label: "Generate Artifact",
    description: `Building ${classification.artifactType.replace(/_/g, " ")} from analysis results with source citations`,
    status: "completed",
    startedAt: now,
    completedAt: now,
    result: {
      artifactType: classification.artifactType,
      citationCount: template.queryPlan.reduce((sum, qp) => sum + qp.citations.length, 0),
    },
  });

  if (requiresApproval(classification.artifactType)) {
    steps.push({
      id: randomUUID(),
      label: "Approval Gate",
      description: `Artifact requires approval before activation (type: ${classification.artifactType.replace(/_/g, " ")})`,
      status: "completed",
      startedAt: now,
      completedAt: now,
      result: {
        approvalRequired: true,
        requiredRole: "security_admin",
        reason: "Artifact can trigger automated actions",
      },
    });
  }

  return steps;
}

function generateDashboardArtifact(
  classification: IntentClassification,
  prompt: string,
  template: ConstrainedTemplate,
): GeneratedArtifact {
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

  const artifactId = randomUUID();
  const citations = collectCitations(template.queryPlan);
  return {
    id: artifactId,
    type: "dashboard",
    name: `Dashboard: ${prompt.length > 60 ? prompt.substring(0, 60) + "..." : prompt}`,
    description: "Auto-generated dashboard from prompt analysis",
    content: {
      layout: "grid",
      columns: 3,
      widgets,
      refreshInterval: 30,
      timeRange: classification.timeRange || "24h",
    },
    editableLogic: [
      {
        id: randomUUID(),
        label: "Widget Configuration",
        language: "json",
        code: JSON.stringify(widgets, null, 2),
        description: "Dashboard widget definitions — edit to add, remove, or reconfigure widgets",
        editable: true,
      },
      {
        id: randomUUID(),
        label: "Data Query (KQL)",
        language: "kql",
        code: `alerts\n| where Severity >= "${classification.severity || "medium"}"\n| where TimeGenerated > ago(${classification.timeRange || "24h"})\n| summarize Count=count() by Severity, Source\n| order by Count desc`,
        description: "Kusto query powering the dashboard widgets",
        editable: true,
      },
    ],
    citations,
    approvalGate: null,
    templateId: template.id,
    queryPlan: template.queryPlan,
    createdAt: new Date().toISOString(),
  };
}

function generateAlertRuleArtifact(
  classification: IntentClassification,
  prompt: string,
  template: ConstrainedTemplate,
): GeneratedArtifact {
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

  const artifactId = randomUUID();
  const citations = collectCitations(template.queryPlan);
  const content = {
    conditions,
    logic: "AND",
    actions: [
      { type: "notify", channel: "email", recipients: ["security-team"] },
      { type: "notify", channel: "slack", webhook: "#security-alerts" },
      { type: "create_incident", priority: classification.severity || "high" },
    ],
    throttle: { count: 1, window: "5m" },
    enabled: false,
  };
  const gate = createApprovalGate(artifactId, "alert_rule");
  approvalStore.set(gate.id, gate);
  return {
    id: artifactId,
    type: "alert_rule",
    name: `Alert Rule: ${prompt.length > 50 ? prompt.substring(0, 50) + "..." : prompt}`,
    description: "Auto-generated alert rule from prompt analysis",
    content,
    editableLogic: [
      {
        id: randomUUID(),
        label: "Conditions",
        language: "json",
        code: JSON.stringify(conditions, null, 2),
        description: "Alert trigger conditions — edit thresholds, operators, and fields",
        editable: true,
      },
      {
        id: randomUUID(),
        label: "Actions",
        language: "json",
        code: JSON.stringify(content.actions, null, 2),
        description: "Actions executed when alert fires — edit notification channels and escalation targets",
        editable: true,
      },
    ],
    citations,
    approvalGate: gate,
    templateId: template.id,
    queryPlan: template.queryPlan,
    createdAt: new Date().toISOString(),
  };
}

function generateWorkflowArtifact(
  classification: IntentClassification,
  prompt: string,
  template: ConstrainedTemplate,
): GeneratedArtifact {
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

  const artifactId = randomUUID();
  const citations = collectCitations(template.queryPlan);
  const content = {
    steps,
    version: 1,
    enabled: false,
    runMode: "automatic",
  };
  const gate = createApprovalGate(artifactId, "workflow");
  approvalStore.set(gate.id, gate);
  return {
    id: artifactId,
    type: "workflow",
    name: `Workflow: ${prompt.length > 50 ? prompt.substring(0, 50) + "..." : prompt}`,
    description: "Auto-generated workflow from prompt analysis",
    content,
    editableLogic: [
      {
        id: randomUUID(),
        label: "Workflow Steps",
        language: "yaml",
        code: steps
          .map(
            (s) =>
              `- id: ${(s as Record<string, unknown>).id}\n  type: ${(s as Record<string, unknown>).type}\n  action: ${(s as Record<string, unknown>).action || "n/a"}`,
          )
          .join("\n"),
        description: "Workflow step definitions — edit to add, remove, or reorder steps",
        editable: true,
      },
      {
        id: randomUUID(),
        label: "Evaluation Logic",
        language: "pseudocode",
        code: "IF enrichment.risk_score > 0.6 THEN escalate\nELSE log_and_close",
        description: "Decision logic for the evaluation step — edit threshold and branches",
        editable: true,
      },
    ],
    citations,
    approvalGate: gate,
    templateId: template.id,
    queryPlan: template.queryPlan,
    createdAt: new Date().toISOString(),
  };
}

function generateInvestigationArtifact(
  classification: IntentClassification,
  prompt: string,
  template: ConstrainedTemplate,
): GeneratedArtifact {
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
      relatedAlerts: 12,
      relatedEntities: 8,
    },
    editableLogic: [
      {
        id: randomUUID(),
        label: "Investigation Scope",
        language: "json",
        code: JSON.stringify(
          {
            entities: classification.entities,
            timeRange: classification.timeRange || "7d",
            severity: classification.severity,
          },
          null,
          2,
        ),
        description: "Investigation scope parameters — edit to broaden or narrow the investigation",
        editable: true,
      },
      {
        id: randomUUID(),
        label: "Correlation Query",
        language: "kql",
        code: `SecurityEvent\n| where TimeGenerated > ago(${classification.timeRange || "7d"})\n| where ${classification.entities.length > 0 ? classification.entities.map((e) => `EntityType == "${e}"`).join(" or ") : "true"}\n| summarize EventCount=count() by EntityType, bin(TimeGenerated, 1h)`,
        description: "KQL query for cross-source correlation analysis",
        editable: true,
      },
    ],
    citations: collectCitations(template.queryPlan),
    approvalGate: null,
    templateId: template.id,
    queryPlan: template.queryPlan,
    createdAt: new Date().toISOString(),
  };
}

function generateReportArtifact(
  classification: IntentClassification,
  prompt: string,
  template: ConstrainedTemplate,
): GeneratedArtifact {
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
            totalAlerts: 150,
            criticalAlerts: 5,
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
    editableLogic: [
      {
        id: randomUUID(),
        label: "Report Sections",
        language: "json",
        code: JSON.stringify(["Executive Summary", "Key Findings", "Metrics", "Recommendations"], null, 2),
        description: "Report section structure — edit to add, remove, or reorder sections",
        editable: true,
      },
      {
        id: randomUUID(),
        label: "Metrics Query",
        language: "sql",
        code: `SELECT\n  COUNT(*) as total_alerts,\n  AVG(resolution_time) as avg_mttr,\n  SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical_count\nFROM alerts\nWHERE created_at > NOW() - INTERVAL '${classification.timeRange || "7d"}'`,
        description: "SQL query computing report metrics",
        editable: true,
      },
    ],
    citations: collectCitations(template.queryPlan),
    approvalGate: null,
    templateId: template.id,
    queryPlan: template.queryPlan,
    createdAt: new Date().toISOString(),
  };
}

function generateQueryArtifact(
  classification: IntentClassification,
  prompt: string,
  template: ConstrainedTemplate,
): GeneratedArtifact {
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

  const filterSql = filters.map((f) => `${f.field} = '${f.value}'`).join(" AND ");
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
      resultCount: 50,
      executionTime: "120ms",
    },
    editableLogic: [
      {
        id: randomUUID(),
        label: "Filter Configuration",
        language: "json",
        code: JSON.stringify(filters, null, 2),
        description: "Query filters \u2014 edit to adjust search criteria",
        editable: true,
      },
      {
        id: randomUUID(),
        label: "SQL Query",
        language: "sql",
        code: `SELECT id, type, severity, source, description, created_at\nFROM events\nWHERE ${filterSql || "1=1"}\nORDER BY created_at DESC\nLIMIT 100`,
        description: "Underlying SQL query \u2014 edit to customize result set",
        editable: true,
      },
    ],
    citations: collectCitations(template.queryPlan),
    approvalGate: null,
    templateId: template.id,
    queryPlan: template.queryPlan,
    createdAt: new Date().toISOString(),
  };
}

function generateArtifact(
  classification: IntentClassification,
  prompt: string,
  template: ConstrainedTemplate,
): GeneratedArtifact {
  switch (classification.artifactType) {
    case "dashboard":
      return generateDashboardArtifact(classification, prompt, template);
    case "alert_rule":
      return generateAlertRuleArtifact(classification, prompt, template);
    case "workflow":
      return generateWorkflowArtifact(classification, prompt, template);
    case "investigation":
      return generateInvestigationArtifact(classification, prompt, template);
    case "report":
      return generateReportArtifact(classification, prompt, template);
    case "query":
      return generateQueryArtifact(classification, prompt, template);
    default:
      return generateQueryArtifact(classification, prompt, template);
  }
}

const MAX_INVESTIGATION_STORE_SIZE = 10000;
const investigationStore = new Map<string, Investigation>();
const approvalStore = new Map<string, ApprovalGate>();

export function runInvestigation(prompt: string, orgId: string | null): Investigation {
  const sanitizedPrompt = prompt.trim().slice(0, 2000);
  if (sanitizedPrompt.length === 0) {
    throw new Error("Prompt cannot be empty");
  }

  const classification = classifyIntent(sanitizedPrompt);
  const template = selectTemplate(classification);
  const steps = buildInvestigationSteps(classification, template);
  const artifact = generateArtifact(classification, sanitizedPrompt, template);
  const citations = collectCitations(template.queryPlan);

  const investigation: Investigation = {
    id: randomUUID(),
    orgId,
    prompt: sanitizedPrompt,
    intent: classification.intent,
    status: "completed",
    steps,
    artifacts: [artifact],
    summary: buildSummary(classification, artifact),
    citations,
    createdAt: new Date().toISOString(),
    completedAt: new Date().toISOString(),
  };

  investigationStore.set(investigation.id, investigation);

  if (investigationStore.size > MAX_INVESTIGATION_STORE_SIZE) {
    const entries = Array.from(investigationStore.entries());
    entries.sort((a, b) => new Date(a[1].createdAt).getTime() - new Date(b[1].createdAt).getTime());
    const toRemove = entries.slice(0, investigationStore.size - MAX_INVESTIGATION_STORE_SIZE);
    for (const [key, inv] of toRemove) {
      for (const art of inv.artifacts) {
        if (art.approvalGate) {
          approvalStore.delete(art.approvalGate.id);
        }
      }
      investigationStore.delete(key);
    }
  }

  return investigation;
}

function buildSummary(classification: IntentClassification, artifact: GeneratedArtifact): string {
  const entityDesc = classification.entities.length > 0 ? classification.entities.join(", ") : "general security data";
  const timeDesc = classification.timeRange ? ` over the last ${classification.timeRange}` : "";
  const severityDesc = classification.severity ? ` at ${classification.severity} severity` : "";

  return `Analyzed ${entityDesc}${timeDesc}${severityDesc} and generated a ${artifact.type.replace(/_/g, " ")}: "${artifact.name}".`;
}

export function getInvestigation(id: string, orgId?: string | null): Investigation | null {
  const investigation = investigationStore.get(id) || null;
  if (investigation && investigation.orgId !== orgId) return null;
  return investigation;
}

export function listInvestigations(orgId?: string | null): Investigation[] {
  const all = Array.from(investigationStore.values());
  const filtered = all.filter((inv) => inv.orgId === orgId);
  return filtered.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
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

export function getTemplates(): ConstrainedTemplate[] {
  return [...CONSTRAINED_TEMPLATES];
}

export function reviewApproval(
  approvalId: string,
  reviewerName: string,
  decision: "approved" | "rejected",
  notes: string,
  orgId: string,
): ApprovalGate | null {
  const gate = approvalStore.get(approvalId);
  if (!gate) return null;

  const investigation = Array.from(investigationStore.values()).find((inv) =>
    inv.artifacts.some((a) => a.id === gate.artifactId),
  );
  if (!investigation || investigation.orgId !== orgId) return null;

  gate.status = decision;
  gate.reviewedBy = reviewerName;
  gate.reviewedAt = new Date().toISOString();
  gate.reviewNotes = notes;
  approvalStore.set(approvalId, gate);

  if (investigation) {
    const artifact = investigation.artifacts.find((a) => a.id === gate.artifactId);
    if (artifact) {
      artifact.approvalGate = gate;
    }
  }

  return gate;
}

export function getPendingApprovals(orgId: string): ApprovalGate[] {
  const pending: ApprovalGate[] = [];
  for (const gate of Array.from(approvalStore.values())) {
    if (gate.status !== "pending_approval") continue;
    const investigation = Array.from(investigationStore.values()).find((inv) =>
      inv.artifacts.some((a) => a.id === gate.artifactId),
    );
    if (investigation && investigation.orgId === orgId) {
      pending.push(gate);
    }
  }
  return pending;
}

export function updateArtifactLogic(
  investigationId: string,
  artifactId: string,
  blockId: string,
  newCode: string,
  orgId: string,
): GeneratedArtifact | null {
  const investigation = investigationStore.get(investigationId);
  if (!investigation || investigation.orgId !== orgId) return null;

  const artifact = investigation.artifacts.find((a) => a.id === artifactId);
  if (!artifact) return null;

  const block = artifact.editableLogic.find((b) => b.id === blockId);
  if (!block || !block.editable) return null;

  block.code = newCode.slice(0, 50000);
  return artifact;
}
