import { randomUUID, randomInt, createSign, createVerify, createHash, generateKeyPairSync } from "crypto";

export type ToolRiskLevel = "low" | "medium" | "high" | "critical";
export type TrustBoundary = "internal" | "external" | "privileged" | "sandboxed";
export type InvocationVerdict = "allowed" | "denied" | "throttled" | "flagged";
export type AnomalyType =
  | "unusual_chaining"
  | "scope_escalation"
  | "rate_spike"
  | "destination_drift"
  | "payload_anomaly";

export interface ToolManifest {
  id: string;
  name: string;
  version: string;
  description: string;
  publisher: string;
  scopes: string[];
  trustBoundary: TrustBoundary;
  riskLevel: ToolRiskLevel;
  allowedDestinations: string[];
  maxInvocationsPerMinute: number;
  maxInvocationsPerHour: number;
  requiresApproval: boolean;
  signatureHash: string;
  signedAt: string;
  signedBy: string;
  verified: boolean;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface ToolScope {
  id: string;
  toolId: string;
  scope: string;
  description: string;
  riskWeight: number;
  grantedAt: string;
  grantedBy: string;
  expiresAt: string | null;
}

export interface TrustBoundaryRule {
  id: string;
  orgId: string;
  name: string;
  description: string;
  sourceBoundary: TrustBoundary;
  targetBoundary: TrustBoundary;
  action: "allow" | "deny" | "require_approval";
  conditions: string[];
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface ToolInvocation {
  id: string;
  orgId: string;
  agentId: string;
  agentName: string;
  toolId: string;
  toolName: string;
  toolVersion: string;
  scopes: string[];
  trustBoundary: TrustBoundary;
  destination: string | null;
  inputHash: string;
  outputHash: string | null;
  verdict: InvocationVerdict;
  verdictReason: string;
  attestationPassed: boolean;
  riskScore: number;
  durationMs: number;
  chainId: string | null;
  chainPosition: number;
  parentInvocationId: string | null;
  invokedAt: string;
}

export interface AnomalyDetection {
  id: string;
  orgId: string;
  type: AnomalyType;
  severity: ToolRiskLevel;
  agentId: string;
  agentName: string;
  toolId: string;
  toolName: string;
  description: string;
  evidence: string;
  chainId: string | null;
  acknowledged: boolean;
  detectedAt: string;
}

export interface ToolPolicy {
  id: string;
  orgId: string;
  toolId: string;
  toolName: string;
  maxRate: number;
  ratePeriod: "minute" | "hour" | "day";
  allowedScopes: string[];
  blockedDestinations: string[];
  requireAttestation: boolean;
  autoApproveBelow: ToolRiskLevel;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface AgentToolStats {
  totalTools: number;
  verifiedTools: number;
  unverifiedTools: number;
  totalInvocations: number;
  allowedCount: number;
  deniedCount: number;
  throttledCount: number;
  flaggedCount: number;
  totalAnomalies: number;
  unresolvedAnomalies: number;
  activePolicies: number;
  boundaryRules: number;
  avgRiskScore: number;
  invocationsByTool: Record<string, { total: number; allowed: number; denied: number }>;
  anomaliesByType: Record<string, number>;
}

function genId(prefix: string): string {
  return `${prefix}-${randomUUID().slice(0, 8)}`;
}

function randomBetween(min: number, max: number): number {
  return randomInt(min, max + 1);
}

const { publicKey: SIGNING_PUBLIC_KEY, privateKey: SIGNING_PRIVATE_KEY } = generateKeyPairSync("ed25519");

function signManifest(manifest: { name: string; version: string; scopes: string[] }): string {
  const payload = JSON.stringify({ name: manifest.name, version: manifest.version, scopes: manifest.scopes });
  const signer = createSign("SHA256");
  signer.update(payload);
  return signer.sign(SIGNING_PRIVATE_KEY, "hex");
}

function verifyManifestSignature(
  manifest: { name: string; version: string; scopes: string[] },
  signatureHex: string,
): boolean {
  const payload = JSON.stringify({ name: manifest.name, version: manifest.version, scopes: manifest.scopes });
  const verifier = createVerify("SHA256");
  verifier.update(payload);
  try {
    return verifier.verify(SIGNING_PUBLIC_KEY, signatureHex, "hex");
  } catch {
    return false;
  }
}

function hashInput(input: string): string {
  return createHash("sha256").update(input).digest("hex").slice(0, 16);
}

const TOOL_CATALOG: ToolManifest[] = [];
const SCOPE_NAMES = [
  "read:alerts",
  "write:alerts",
  "read:incidents",
  "write:incidents",
  "read:entities",
  "execute:playbooks",
  "read:compliance",
  "write:compliance",
  "read:connectors",
  "write:connectors",
  "invoke:ai",
  "read:threat-intel",
  "execute:shell",
  "read:secrets",
  "write:secrets",
  "send:webhooks",
  "read:audit-log",
  "manage:users",
  "read:files",
  "write:files",
];

const TOOL_DEFS: Array<{
  name: string;
  description: string;
  publisher: string;
  scopes: string[];
  trust: TrustBoundary;
  risk: ToolRiskLevel;
  destinations: string[];
  rateMin: number;
  rateHr: number;
  approval: boolean;
}> = [
  {
    name: "Alert Triage Agent",
    description: "Autonomous alert classification and initial triage with MITRE ATT&CK mapping",
    publisher: "securenexus-core",
    scopes: ["read:alerts", "write:alerts", "read:threat-intel", "invoke:ai"],
    trust: "internal",
    risk: "medium",
    destinations: [],
    rateMin: 30,
    rateHr: 500,
    approval: false,
  },
  {
    name: "Incident Enrichment Tool",
    description: "Enriches incidents with threat intel, entity context, and timeline reconstruction",
    publisher: "securenexus-core",
    scopes: ["read:incidents", "write:incidents", "read:entities", "read:threat-intel"],
    trust: "internal",
    risk: "medium",
    destinations: [],
    rateMin: 20,
    rateHr: 300,
    approval: false,
  },
  {
    name: "Playbook Executor",
    description: "Executes automated response playbooks with approval gates for destructive actions",
    publisher: "securenexus-core",
    scopes: ["execute:playbooks", "read:alerts", "write:alerts", "read:incidents", "write:incidents"],
    trust: "privileged",
    risk: "high",
    destinations: [],
    rateMin: 5,
    rateHr: 50,
    approval: true,
  },
  {
    name: "Webhook Dispatcher",
    description: "Sends outbound webhook notifications to configured external endpoints",
    publisher: "securenexus-core",
    scopes: ["send:webhooks", "read:alerts", "read:incidents"],
    trust: "external",
    risk: "high",
    destinations: ["https://hooks.slack.com/*", "https://events.pagerduty.com/*", "https://api.opsgenie.com/*"],
    rateMin: 10,
    rateHr: 200,
    approval: false,
  },
  {
    name: "Shell Command Executor",
    description: "Executes shell commands on remote hosts for incident response actions",
    publisher: "securenexus-core",
    scopes: ["execute:shell", "read:incidents"],
    trust: "privileged",
    risk: "critical",
    destinations: [],
    rateMin: 2,
    rateHr: 10,
    approval: true,
  },
  {
    name: "Secret Rotation Agent",
    description: "Rotates secrets and credentials across integrated services",
    publisher: "securenexus-core",
    scopes: ["read:secrets", "write:secrets", "read:connectors"],
    trust: "privileged",
    risk: "critical",
    destinations: [],
    rateMin: 1,
    rateHr: 5,
    approval: true,
  },
  {
    name: "Compliance Scanner",
    description: "Scans infrastructure and policies against compliance frameworks",
    publisher: "securenexus-core",
    scopes: ["read:compliance", "write:compliance", "read:connectors"],
    trust: "internal",
    risk: "low",
    destinations: [],
    rateMin: 10,
    rateHr: 100,
    approval: false,
  },
  {
    name: "External Threat Feed Fetcher",
    description: "Fetches IOCs and threat intelligence from external OSINT/commercial feeds",
    publisher: "securenexus-core",
    scopes: ["read:threat-intel", "read:connectors"],
    trust: "external",
    risk: "medium",
    destinations: [
      "https://urlhaus-api.abuse.ch/*",
      "https://threatfox-api.abuse.ch/*",
      "https://sslbl.abuse.ch/*",
      "https://www.cisa.gov/*",
    ],
    rateMin: 5,
    rateHr: 30,
    approval: false,
  },
  {
    name: "User Management Tool",
    description: "Manages user accounts, roles, and permissions for automated provisioning",
    publisher: "securenexus-core",
    scopes: ["manage:users", "read:audit-log"],
    trust: "privileged",
    risk: "high",
    destinations: [],
    rateMin: 5,
    rateHr: 50,
    approval: true,
  },
  {
    name: "File Analysis Sandbox",
    description: "Analyzes uploaded files in an isolated sandbox for malware detection",
    publisher: "securenexus-core",
    scopes: ["read:files", "write:files", "invoke:ai"],
    trust: "sandboxed",
    risk: "medium",
    destinations: [],
    rateMin: 3,
    rateHr: 30,
    approval: false,
  },
];

function initCatalog(): void {
  if (TOOL_CATALOG.length > 0) return;
  const now = new Date().toISOString();
  for (const def of TOOL_DEFS) {
    const sig = signManifest({ name: def.name, version: "1.0.0", scopes: def.scopes });
    TOOL_CATALOG.push({
      id: genId("tool"),
      name: def.name,
      version: "1.0.0",
      description: def.description,
      publisher: def.publisher,
      scopes: def.scopes,
      trustBoundary: def.trust,
      riskLevel: def.risk,
      allowedDestinations: def.destinations,
      maxInvocationsPerMinute: def.rateMin,
      maxInvocationsPerHour: def.rateHr,
      requiresApproval: def.approval,
      signatureHash: sig,
      signedAt: now,
      signedBy: "platform-key-v1",
      verified: true,
      enabled: true,
      createdAt: now,
      updatedAt: now,
    });
  }
}

const orgInvocationStore = new Map<string, ToolInvocation[]>();
const orgAnomalyStore = new Map<string, AnomalyDetection[]>();
const orgPolicyStore = new Map<string, ToolPolicy[]>();
const orgBoundaryRuleStore = new Map<string, TrustBoundaryRule[]>();
const orgScopeStore = new Map<string, ToolScope[]>();

function getInvocations(orgId: string): ToolInvocation[] {
  if (!orgInvocationStore.has(orgId)) {
    seedInvocations(orgId);
  }
  return orgInvocationStore.get(orgId)!;
}

function getAnomalies(orgId: string): AnomalyDetection[] {
  if (!orgAnomalyStore.has(orgId)) {
    seedAnomalies(orgId);
  }
  return orgAnomalyStore.get(orgId)!;
}

function getPolicies(orgId: string): ToolPolicy[] {
  if (!orgPolicyStore.has(orgId)) {
    seedPolicies(orgId);
  }
  return orgPolicyStore.get(orgId)!;
}

function getBoundaryRules(orgId: string): TrustBoundaryRule[] {
  if (!orgBoundaryRuleStore.has(orgId)) {
    seedBoundaryRules(orgId);
  }
  return orgBoundaryRuleStore.get(orgId)!;
}

function seedInvocations(orgId: string): void {
  initCatalog();
  const invocations: ToolInvocation[] = [];
  const agents = [
    { id: "agent-soc-01", name: "SOC Tier-1 Agent" },
    { id: "agent-ir-02", name: "Incident Response Agent" },
    { id: "agent-comply-03", name: "Compliance Agent" },
    { id: "agent-threat-04", name: "Threat Hunter Agent" },
  ];
  const verdicts: InvocationVerdict[] = ["allowed", "allowed", "allowed", "allowed", "denied", "throttled", "flagged"];
  const now = Date.now();

  for (let i = 0; i < 60; i++) {
    const tool = TOOL_CATALOG[randomBetween(0, TOOL_CATALOG.length - 1)];
    const agent = agents[randomBetween(0, agents.length - 1)];
    const verdict = verdicts[randomBetween(0, verdicts.length - 1)];
    const chainId =
      i % 5 === 0 ? genId("chain") : i > 0 && i % 5 !== 0 ? invocations[invocations.length - 1]?.chainId : null;
    const chainPos = chainId && i % 5 !== 0 ? (invocations[invocations.length - 1]?.chainPosition || 0) + 1 : 0;
    const riskScore =
      tool.riskLevel === "critical"
        ? randomBetween(70, 100)
        : tool.riskLevel === "high"
          ? randomBetween(40, 75)
          : tool.riskLevel === "medium"
            ? randomBetween(20, 50)
            : randomBetween(5, 25);

    const reasons: Record<InvocationVerdict, string[]> = {
      allowed: ["Attestation passed, within scope and rate limits", "All policy checks passed"],
      denied: [
        "Trust boundary violation: external→privileged",
        "Scope not granted: execute:shell",
        "Attestation failed: signature mismatch",
        "Destination not in allowlist",
      ],
      throttled: ["Rate limit exceeded: 31/30 per minute", "Hourly quota exhausted"],
      flagged: [
        "Unusual chaining pattern detected",
        "Scope escalation attempt: read→write",
        "Destination drift from baseline",
      ],
    };

    invocations.push({
      id: genId("inv"),
      orgId,
      agentId: agent.id,
      agentName: agent.name,
      toolId: tool.id,
      toolName: tool.name,
      toolVersion: tool.version,
      scopes: tool.scopes.slice(0, randomBetween(1, tool.scopes.length)),
      trustBoundary: tool.trustBoundary,
      destination: tool.allowedDestinations.length > 0 ? tool.allowedDestinations[0] : null,
      inputHash: hashInput(`input-${i}-${tool.id}`),
      outputHash: verdict === "allowed" ? hashInput(`output-${i}-${tool.id}`) : null,
      verdict,
      verdictReason: reasons[verdict][randomBetween(0, reasons[verdict].length - 1)],
      attestationPassed: verdict !== "denied",
      riskScore,
      durationMs: randomBetween(12, 2500),
      chainId,
      chainPosition: chainPos,
      parentInvocationId: chainPos > 0 ? invocations[invocations.length - 1]?.id || null : null,
      invokedAt: new Date(now - randomBetween(0, 7 * 24 * 60 * 60 * 1000)).toISOString(),
    });
  }

  invocations.sort((a, b) => new Date(b.invokedAt).getTime() - new Date(a.invokedAt).getTime());
  orgInvocationStore.set(orgId, invocations);
}

function seedAnomalies(orgId: string): void {
  initCatalog();
  const anomalyTypes: Array<{ type: AnomalyType; severity: ToolRiskLevel; desc: string; evidence: string }> = [
    {
      type: "unusual_chaining",
      severity: "high",
      desc: "Agent chained 7 tools in rapid succession including privileged shell executor after read-only triage",
      evidence:
        "Chain chain-abc123: Alert Triage → Incident Enrichment → Playbook Executor → Shell Command Executor (4 hops in 3.2s)",
    },
    {
      type: "scope_escalation",
      severity: "critical",
      desc: "Agent requested write:secrets scope after being granted only read:alerts — potential privilege escalation",
      evidence: "Agent agent-soc-01 invoked Secret Rotation Agent with scope write:secrets (not in granted set)",
    },
    {
      type: "rate_spike",
      severity: "medium",
      desc: "Webhook Dispatcher invocations spiked 340% above 7-day baseline in 15-minute window",
      evidence: "Baseline: 8 inv/15min, Observed: 35 inv/15min at 2026-02-14T03:12:00Z",
    },
    {
      type: "destination_drift",
      severity: "high",
      desc: "External Threat Feed Fetcher attempted to reach non-allowlisted domain api.unknown-feed.io",
      evidence: "Destination https://api.unknown-feed.io/v2/iocs not in allowlist [abuse.ch, cisa.gov]",
    },
    {
      type: "payload_anomaly",
      severity: "critical",
      desc: "Shell Command Executor received payload containing base64-encoded reverse shell command",
      evidence: "Payload hash c4f3b... contains pattern matching known reverse shell signatures (bash -i >& /dev/tcp/)",
    },
    {
      type: "unusual_chaining",
      severity: "medium",
      desc: "Compliance Scanner invoked User Management Tool — tools never paired in historical data",
      evidence: "No prior chain between tool-xyz (Compliance Scanner) and tool-abc (User Management) in 30-day history",
    },
  ];

  const agents = [
    { id: "agent-soc-01", name: "SOC Tier-1 Agent" },
    { id: "agent-ir-02", name: "Incident Response Agent" },
    { id: "agent-threat-04", name: "Threat Hunter Agent" },
  ];

  const anomalies: AnomalyDetection[] = [];
  const now = Date.now();
  for (const def of anomalyTypes) {
    const agent = agents[randomBetween(0, agents.length - 1)];
    const tool = TOOL_CATALOG[randomBetween(0, TOOL_CATALOG.length - 1)];
    anomalies.push({
      id: genId("anom"),
      orgId,
      type: def.type,
      severity: def.severity,
      agentId: agent.id,
      agentName: agent.name,
      toolId: tool.id,
      toolName: tool.name,
      description: def.desc,
      evidence: def.evidence,
      chainId: def.type === "unusual_chaining" ? genId("chain") : null,
      acknowledged: def.severity === "low",
      detectedAt: new Date(now - randomBetween(0, 5 * 24 * 60 * 60 * 1000)).toISOString(),
    });
  }
  anomalies.sort((a, b) => new Date(b.detectedAt).getTime() - new Date(a.detectedAt).getTime());
  orgAnomalyStore.set(orgId, anomalies);
}

function seedPolicies(orgId: string): void {
  initCatalog();
  const policies: ToolPolicy[] = [];
  for (const tool of TOOL_CATALOG) {
    policies.push({
      id: genId("pol"),
      orgId,
      toolId: tool.id,
      toolName: tool.name,
      maxRate: tool.maxInvocationsPerMinute,
      ratePeriod: "minute",
      allowedScopes: tool.scopes,
      blockedDestinations: ["http://169.254.169.254/*", "http://localhost/*", "http://127.0.0.1/*"],
      requireAttestation: tool.riskLevel === "critical" || tool.riskLevel === "high",
      autoApproveBelow: "medium",
      enabled: true,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });
  }
  orgPolicyStore.set(orgId, policies);
}

function seedBoundaryRules(orgId: string): void {
  const rules: TrustBoundaryRule[] = [
    {
      id: genId("tbr"),
      orgId,
      name: "Block external→privileged",
      description: "Deny any tool invocation crossing from external trust boundary into privileged boundary",
      sourceBoundary: "external",
      targetBoundary: "privileged",
      action: "deny",
      conditions: ["any"],
      enabled: true,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    },
    {
      id: genId("tbr"),
      orgId,
      name: "Approve sandboxed→internal",
      description: "Require manual approval when sandboxed tools invoke internal services",
      sourceBoundary: "sandboxed",
      targetBoundary: "internal",
      action: "require_approval",
      conditions: ["riskLevel >= high"],
      enabled: true,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    },
    {
      id: genId("tbr"),
      orgId,
      name: "Allow internal→internal",
      description: "Allow tool invocations within the internal trust boundary",
      sourceBoundary: "internal",
      targetBoundary: "internal",
      action: "allow",
      conditions: ["attestation_valid"],
      enabled: true,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    },
    {
      id: genId("tbr"),
      orgId,
      name: "Approve privileged→external",
      description: "Require approval for privileged tools making outbound calls",
      sourceBoundary: "privileged",
      targetBoundary: "external",
      action: "require_approval",
      conditions: ["destination_allowlisted"],
      enabled: true,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    },
  ];
  orgBoundaryRuleStore.set(orgId, rules);
}

export function getToolCatalog(riskLevel?: ToolRiskLevel, trustBoundary?: TrustBoundary): ToolManifest[] {
  initCatalog();
  let result = [...TOOL_CATALOG];
  if (riskLevel) result = result.filter((t) => t.riskLevel === riskLevel);
  if (trustBoundary) result = result.filter((t) => t.trustBoundary === trustBoundary);
  return result;
}

export function getToolById(toolId: string): ToolManifest | undefined {
  initCatalog();
  return TOOL_CATALOG.find((t) => t.id === toolId);
}

export function verifyTool(toolId: string): { verified: boolean; reason: string } {
  initCatalog();
  const tool = TOOL_CATALOG.find((t) => t.id === toolId);
  if (!tool) return { verified: false, reason: "Tool not found" };
  const valid = verifyManifestSignature(
    { name: tool.name, version: tool.version, scopes: tool.scopes },
    tool.signatureHash,
  );
  if (valid) {
    tool.verified = true;
    return { verified: true, reason: "Signature valid" };
  }
  tool.verified = false;
  return { verified: false, reason: "Signature verification failed" };
}

export function getToolInvocations(
  orgId: string,
  filters?: {
    toolId?: string;
    agentId?: string;
    verdict?: InvocationVerdict;
    chainId?: string;
  },
): ToolInvocation[] {
  let result = getInvocations(orgId);
  if (filters?.toolId) result = result.filter((i) => i.toolId === filters.toolId);
  if (filters?.agentId) result = result.filter((i) => i.agentId === filters.agentId);
  if (filters?.verdict) result = result.filter((i) => i.verdict === filters.verdict);
  if (filters?.chainId) result = result.filter((i) => i.chainId === filters.chainId);
  return result;
}

export function getInvocationById(orgId: string, invocationId: string): ToolInvocation | undefined {
  return getInvocations(orgId).find((i) => i.id === invocationId);
}

export function recordInvocation(
  orgId: string,
  data: {
    agentId: string;
    agentName: string;
    toolId: string;
    scopes: string[];
    destination?: string;
    input: string;
    chainId?: string;
    parentInvocationId?: string;
  },
): ToolInvocation {
  initCatalog();
  const tool = TOOL_CATALOG.find((t) => t.id === data.toolId);
  if (!tool) throw new Error("TOOL_NOT_FOUND");
  if (!tool.enabled) throw new Error("TOOL_DISABLED");

  const sigValid = verifyManifestSignature(
    { name: tool.name, version: tool.version, scopes: tool.scopes },
    tool.signatureHash,
  );

  const scopeGranted = data.scopes.every((s) => tool.scopes.includes(s));
  const destAllowed =
    !data.destination ||
    tool.allowedDestinations.length === 0 ||
    tool.allowedDestinations.some((d) => {
      const pattern = d.replace(/\*/g, ".*");
      return new RegExp(`^${pattern}$`).test(data.destination!);
    });

  let verdict: InvocationVerdict = "allowed";
  let reason = "All checks passed";

  if (!sigValid) {
    verdict = "denied";
    reason = "Attestation failed: manifest signature invalid";
  } else if (!scopeGranted) {
    verdict = "denied";
    reason = `Scope not granted: ${data.scopes.filter((s) => !tool.scopes.includes(s)).join(", ")}`;
  } else if (!destAllowed) {
    verdict = "denied";
    reason = `Destination ${data.destination} not in allowlist`;
  }

  const policies = getPolicies(orgId);
  const toolPolicy = policies.find((p) => p.toolId === data.toolId && p.enabled);
  if (verdict === "allowed" && toolPolicy) {
    const recentInvocations = getInvocations(orgId).filter(
      (i) => i.toolId === data.toolId && new Date(i.invokedAt).getTime() > Date.now() - 60000,
    );
    if (recentInvocations.length >= toolPolicy.maxRate) {
      verdict = "throttled";
      reason = `Rate limit exceeded: ${recentInvocations.length + 1}/${toolPolicy.maxRate} per ${toolPolicy.ratePeriod}`;
    }
  }

  const riskScore =
    tool.riskLevel === "critical"
      ? randomBetween(70, 100)
      : tool.riskLevel === "high"
        ? randomBetween(40, 75)
        : tool.riskLevel === "medium"
          ? randomBetween(20, 50)
          : randomBetween(5, 25);

  const existing = getInvocations(orgId);
  const chainPosition = data.parentInvocationId
    ? (existing.find((i) => i.id === data.parentInvocationId)?.chainPosition || 0) + 1
    : 0;

  const invocation: ToolInvocation = {
    id: genId("inv"),
    orgId,
    agentId: data.agentId,
    agentName: data.agentName,
    toolId: tool.id,
    toolName: tool.name,
    toolVersion: tool.version,
    scopes: data.scopes,
    trustBoundary: tool.trustBoundary,
    destination: data.destination || null,
    inputHash: hashInput(data.input),
    outputHash: verdict === "allowed" ? hashInput(`output-${Date.now()}`) : null,
    verdict,
    verdictReason: reason,
    attestationPassed: sigValid,
    riskScore,
    durationMs: randomBetween(10, 2000),
    chainId: data.chainId || null,
    chainPosition,
    parentInvocationId: data.parentInvocationId || null,
    invokedAt: new Date().toISOString(),
  };

  existing.unshift(invocation);

  if (chainPosition >= 4) {
    const anomalies = getAnomalies(orgId);
    anomalies.unshift({
      id: genId("anom"),
      orgId,
      type: "unusual_chaining",
      severity: "high",
      agentId: data.agentId,
      agentName: data.agentName,
      toolId: tool.id,
      toolName: tool.name,
      description: `Agent chained ${chainPosition + 1} tools in sequence — exceeds normal chaining threshold of 4`,
      evidence: `Chain ${data.chainId}: position ${chainPosition + 1}`,
      chainId: data.chainId || null,
      acknowledged: false,
      detectedAt: new Date().toISOString(),
    });
  }

  return invocation;
}

export function getAnomalyDetections(
  orgId: string,
  filters?: {
    type?: AnomalyType;
    severity?: ToolRiskLevel;
    acknowledged?: boolean;
  },
): AnomalyDetection[] {
  let result = getAnomalies(orgId);
  if (filters?.type) result = result.filter((a) => a.type === filters.type);
  if (filters?.severity) result = result.filter((a) => a.severity === filters.severity);
  if (filters?.acknowledged !== undefined) result = result.filter((a) => a.acknowledged === filters.acknowledged);
  return result;
}

export function acknowledgeAnomaly(orgId: string, anomalyId: string): AnomalyDetection | null {
  const anomalies = getAnomalies(orgId);
  const anomaly = anomalies.find((a) => a.id === anomalyId);
  if (!anomaly) return null;
  anomaly.acknowledged = true;
  return anomaly;
}

export function getToolPolicies(orgId: string): ToolPolicy[] {
  return getPolicies(orgId);
}

export function updateToolPolicy(
  orgId: string,
  policyId: string,
  updates: Partial<
    Pick<
      ToolPolicy,
      | "maxRate"
      | "ratePeriod"
      | "allowedScopes"
      | "blockedDestinations"
      | "requireAttestation"
      | "autoApproveBelow"
      | "enabled"
    >
  >,
): ToolPolicy | null {
  const policies = getPolicies(orgId);
  const policy = policies.find((p) => p.id === policyId);
  if (!policy) return null;
  if (updates.maxRate !== undefined) policy.maxRate = updates.maxRate;
  if (updates.ratePeriod !== undefined) policy.ratePeriod = updates.ratePeriod;
  if (updates.allowedScopes !== undefined) policy.allowedScopes = updates.allowedScopes;
  if (updates.blockedDestinations !== undefined) policy.blockedDestinations = updates.blockedDestinations;
  if (updates.requireAttestation !== undefined) policy.requireAttestation = updates.requireAttestation;
  if (updates.autoApproveBelow !== undefined) policy.autoApproveBelow = updates.autoApproveBelow;
  if (updates.enabled !== undefined) policy.enabled = updates.enabled;
  policy.updatedAt = new Date().toISOString();
  return policy;
}

export function getTrustBoundaryRules(orgId: string): TrustBoundaryRule[] {
  return getBoundaryRules(orgId);
}

export function createBoundaryRule(
  orgId: string,
  data: {
    name: string;
    description: string;
    sourceBoundary: TrustBoundary;
    targetBoundary: TrustBoundary;
    action: "allow" | "deny" | "require_approval";
    conditions: string[];
  },
): TrustBoundaryRule {
  const rules = getBoundaryRules(orgId);
  const rule: TrustBoundaryRule = {
    id: genId("tbr"),
    orgId,
    name: data.name,
    description: data.description,
    sourceBoundary: data.sourceBoundary,
    targetBoundary: data.targetBoundary,
    action: data.action,
    conditions: data.conditions,
    enabled: true,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  rules.push(rule);
  return rule;
}

export function updateBoundaryRule(
  orgId: string,
  ruleId: string,
  updates: Partial<Pick<TrustBoundaryRule, "name" | "description" | "action" | "conditions" | "enabled">>,
): TrustBoundaryRule | null {
  const rules = getBoundaryRules(orgId);
  const rule = rules.find((r) => r.id === ruleId);
  if (!rule) return null;
  if (updates.name !== undefined) rule.name = updates.name;
  if (updates.description !== undefined) rule.description = updates.description;
  if (updates.action !== undefined) rule.action = updates.action;
  if (updates.conditions !== undefined) rule.conditions = updates.conditions;
  if (updates.enabled !== undefined) rule.enabled = updates.enabled;
  rule.updatedAt = new Date().toISOString();
  return rule;
}

export function deleteBoundaryRule(orgId: string, ruleId: string): boolean {
  const rules = getBoundaryRules(orgId);
  const idx = rules.findIndex((r) => r.id === ruleId);
  if (idx === -1) return false;
  rules.splice(idx, 1);
  return true;
}

export function getAgentToolStats(orgId: string): AgentToolStats {
  initCatalog();
  const invocations = getInvocations(orgId);
  const anomalies = getAnomalies(orgId);
  const policies = getPolicies(orgId);
  const rules = getBoundaryRules(orgId);

  const allowed = invocations.filter((i) => i.verdict === "allowed").length;
  const denied = invocations.filter((i) => i.verdict === "denied").length;
  const throttled = invocations.filter((i) => i.verdict === "throttled").length;
  const flagged = invocations.filter((i) => i.verdict === "flagged").length;

  const invocationsByTool: Record<string, { total: number; allowed: number; denied: number }> = {};
  for (const inv of invocations) {
    if (!invocationsByTool[inv.toolName]) {
      invocationsByTool[inv.toolName] = { total: 0, allowed: 0, denied: 0 };
    }
    invocationsByTool[inv.toolName].total++;
    if (inv.verdict === "allowed") invocationsByTool[inv.toolName].allowed++;
    if (inv.verdict === "denied") invocationsByTool[inv.toolName].denied++;
  }

  const anomaliesByType: Record<string, number> = {};
  for (const a of anomalies) {
    anomaliesByType[a.type] = (anomaliesByType[a.type] || 0) + 1;
  }

  const totalRisk = invocations.reduce((sum, i) => sum + i.riskScore, 0);

  return {
    totalTools: TOOL_CATALOG.length,
    verifiedTools: TOOL_CATALOG.filter((t) => t.verified).length,
    unverifiedTools: TOOL_CATALOG.filter((t) => !t.verified).length,
    totalInvocations: invocations.length,
    allowedCount: allowed,
    deniedCount: denied,
    throttledCount: throttled,
    flaggedCount: flagged,
    totalAnomalies: anomalies.length,
    unresolvedAnomalies: anomalies.filter((a) => !a.acknowledged).length,
    activePolicies: policies.filter((p) => p.enabled).length,
    boundaryRules: rules.length,
    avgRiskScore: invocations.length > 0 ? Math.round(totalRisk / invocations.length) : 0,
    invocationsByTool,
    anomaliesByType,
  };
}
