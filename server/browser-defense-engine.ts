import { randomUUID, createHash } from "crypto";

export type ThreatCategory =
  | "dom_injection"
  | "prompt_injection"
  | "egress_violation"
  | "path_deviation"
  | "session_hijack"
  | "token_reuse"
  | "xss_attempt"
  | "clickjacking";

export type ActionSeverity = "info" | "low" | "medium" | "high" | "critical";
export type PolicyVerdict = "allow" | "block" | "challenge" | "log_only";
export type SessionState = "active" | "isolated" | "terminated" | "expired";

export interface BrowserSession {
  id: string;
  orgId: string;
  agentId: string;
  agentName: string;
  contextId: string;
  originUrl: string;
  state: SessionState;
  isolationLevel: "none" | "tab" | "process" | "container";
  tokensIssued: number;
  tokensBound: number;
  lastActivityAt: string;
  createdAt: string;
  expiresAt: string;
  metadata: Record<string, string>;
}

export interface DomEvent {
  id: string;
  orgId: string;
  sessionId: string;
  agentId: string;
  eventType: string;
  targetSelector: string;
  actionClassification: ThreatCategory | "benign";
  severity: ActionSeverity;
  verdict: PolicyVerdict;
  details: string;
  rawPayloadHash: string;
  stepUpRequired: boolean;
  stepUpCompleted: boolean;
  timestamp: string;
}

export interface EgressRule {
  id: string;
  orgId: string;
  name: string;
  description: string;
  direction: "outbound" | "inbound";
  domainPattern: string;
  portRange: string;
  protocol: "https" | "http" | "wss" | "ws" | "any";
  action: PolicyVerdict;
  enabled: boolean;
  hitCount: number;
  lastHitAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface TrustedPath {
  id: string;
  orgId: string;
  name: string;
  description: string;
  steps: TrustedPathStep[];
  enforceOrder: boolean;
  maxDurationMs: number;
  failAction: PolicyVerdict;
  enabled: boolean;
  executionCount: number;
  deviationCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface TrustedPathStep {
  order: number;
  actionType: string;
  targetPattern: string;
  requiredContext: string[];
  allowSkip: boolean;
}

export interface InjectionPattern {
  id: string;
  orgId: string;
  name: string;
  category: ThreatCategory;
  pattern: string;
  severity: ActionSeverity;
  action: PolicyVerdict;
  description: string;
  falsePositiveRate: number;
  detectionCount: number;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface BrowserDefenseStats {
  totalSessions: number;
  activeSessions: number;
  isolatedSessions: number;
  terminatedSessions: number;
  totalDomEvents: number;
  blockedEvents: number;
  challengedEvents: number;
  allowedEvents: number;
  totalEgressRules: number;
  activeEgressRules: number;
  egressViolations: number;
  totalTrustedPaths: number;
  activeTrustedPaths: number;
  pathDeviations: number;
  totalInjectionPatterns: number;
  activeInjectionPatterns: number;
  injectionDetections: number;
  threatsByCategory: Record<string, number>;
  eventsBySeverity: Record<string, number>;
}

function genId(prefix: string): string {
  return `${prefix}-${randomUUID().slice(0, 8)}`;
}

let _browserSeed = 0;
function randomBetween(min: number, max: number): number {
  _browserSeed++;
  const h = (_browserSeed * 2654435761) >>> 0;
  return min + (h % (max - min + 1));
}

function hashPayload(payload: string): string {
  return createHash("sha256").update(payload).digest("hex").slice(0, 16);
}

const orgSessionStore = new Map<string, BrowserSession[]>();
const orgDomEventStore = new Map<string, DomEvent[]>();
const orgEgressRuleStore = new Map<string, EgressRule[]>();
const orgTrustedPathStore = new Map<string, TrustedPath[]>();
const orgInjectionPatternStore = new Map<string, InjectionPattern[]>();

const AGENT_NAMES = [
  { id: "browser-agent-01", name: "SOC Browser Agent" },
  { id: "browser-agent-02", name: "Compliance Scanner Bot" },
  { id: "browser-agent-03", name: "Threat Hunter Browser" },
  { id: "browser-agent-04", name: "Automated Tester Agent" },
  { id: "browser-agent-05", name: "Data Collector Bot" },
];

const INJECTION_CATALOG: Array<{
  name: string;
  category: ThreatCategory;
  pattern: string;
  severity: ActionSeverity;
  action: PolicyVerdict;
  description: string;
  falsePositiveRate: number;
}> = [
  {
    name: "Script Tag Injection",
    category: "dom_injection",
    pattern: "<script[^>]*>[\\s\\S]*?</script>",
    severity: "critical",
    action: "block",
    description: "Detects inline script tag injection into DOM elements targeted by browser automation",
    falsePositiveRate: 0.02,
  },
  {
    name: "Event Handler Injection",
    category: "dom_injection",
    pattern: "on(click|load|error|mouseover|focus)\\s*=",
    severity: "high",
    action: "block",
    description: "Detects injection of JavaScript event handlers into DOM attributes",
    falsePositiveRate: 0.05,
  },
  {
    name: "iframe Sandbox Escape",
    category: "dom_injection",
    pattern: "<iframe[^>]*(sandbox\\s*=\\s*['\"][^'\"]*allow-scripts|srcdoc)",
    severity: "critical",
    action: "block",
    description: "Detects attempts to inject iframes that bypass sandbox restrictions",
    falsePositiveRate: 0.01,
  },
  {
    name: "Prompt Override Injection",
    category: "prompt_injection",
    pattern: "(ignore previous|disregard all|system prompt|you are now|forget your instructions)",
    severity: "critical",
    action: "block",
    description: "Detects prompt injection attempts that try to override agent instructions via DOM content",
    falsePositiveRate: 0.08,
  },
  {
    name: "Hidden Prompt via CSS",
    category: "prompt_injection",
    pattern: "(display:\\s*none|visibility:\\s*hidden|font-size:\\s*0|opacity:\\s*0).*\\[data-agent",
    severity: "high",
    action: "challenge",
    description: "Detects visually hidden content designed to be read only by browser automation agents",
    falsePositiveRate: 0.12,
  },
  {
    name: "Data URI XSS",
    category: "xss_attempt",
    pattern: "data:(text/html|application/xhtml)[;,]",
    severity: "high",
    action: "block",
    description: "Detects data URI schemes used to inject executable HTML/JavaScript content",
    falsePositiveRate: 0.03,
  },
  {
    name: "SVG Script Injection",
    category: "xss_attempt",
    pattern: "<svg[^>]*>[\\s\\S]*<(script|foreignObject|use[^>]*href)",
    severity: "high",
    action: "block",
    description: "Detects script injection via SVG elements that can execute in browser context",
    falsePositiveRate: 0.04,
  },
  {
    name: "Clickjacking Frame Ancestor",
    category: "clickjacking",
    pattern: "X-Frame-Options:\\s*(ALLOWALL|$)|frame-ancestors\\s+\\*",
    severity: "medium",
    action: "challenge",
    description: "Detects pages with weak or missing clickjacking protections that could trap agents",
    falsePositiveRate: 0.15,
  },
  {
    name: "Cross-Context Token Extraction",
    category: "token_reuse",
    pattern: "(localStorage|sessionStorage|document\\.cookie)\\.(get|set)Item.*token",
    severity: "critical",
    action: "block",
    description: "Detects attempts to extract or transplant session tokens across browser contexts",
    falsePositiveRate: 0.06,
  },
  {
    name: "Session Cookie Exfiltration",
    category: "session_hijack",
    pattern: "document\\.cookie.*fetch\\(|new Image\\(\\)\\.src.*document\\.cookie",
    severity: "critical",
    action: "block",
    description: "Detects cookie exfiltration patterns targeting agent session credentials",
    falsePositiveRate: 0.02,
  },
  {
    name: "WebSocket Tunnel Escape",
    category: "egress_violation",
    pattern: "new WebSocket\\(['\"]wss?://(?!localhost|127\\.0\\.0\\.1)",
    severity: "high",
    action: "block",
    description: "Detects WebSocket connections to non-local hosts that bypass HTTP egress rules",
    falsePositiveRate: 0.07,
  },
  {
    name: "Mutation Observer Tampering",
    category: "dom_injection",
    pattern: "new MutationObserver.*disconnect|MutationObserver.*observe.*subtree:\\s*true",
    severity: "medium",
    action: "log_only",
    description: "Detects MutationObserver usage that could tamper with DOM state seen by agents",
    falsePositiveRate: 0.2,
  },
];

const EGRESS_RULE_CATALOG: Array<{
  name: string;
  description: string;
  direction: "outbound" | "inbound";
  domainPattern: string;
  portRange: string;
  protocol: "https" | "http" | "wss" | "ws" | "any";
  action: PolicyVerdict;
}> = [
  {
    name: "Allow Internal APIs",
    description: "Permit outbound HTTPS to internal SecureNexus API endpoints",
    direction: "outbound",
    domainPattern: "*.securenexus.internal",
    portRange: "443",
    protocol: "https",
    action: "allow",
  },
  {
    name: "Block Known Exfiltration Domains",
    description: "Block outbound to known data exfiltration and C2 domains",
    direction: "outbound",
    domainPattern: "*.ngrok.io,*.burpcollaborator.net,*.requestbin.com",
    portRange: "*",
    protocol: "any",
    action: "block",
  },
  {
    name: "Challenge External OAuth",
    description: "Require step-up verification for OAuth redirects to external IdPs",
    direction: "outbound",
    domainPattern: "*.okta.com,*.auth0.com,accounts.google.com",
    portRange: "443",
    protocol: "https",
    action: "challenge",
  },
  {
    name: "Block Raw HTTP",
    description: "Block all unencrypted HTTP egress from browser agents",
    direction: "outbound",
    domainPattern: "*",
    portRange: "80",
    protocol: "http",
    action: "block",
  },
  {
    name: "Allow CDN Assets",
    description: "Permit fetching static assets from approved CDN providers",
    direction: "outbound",
    domainPattern: "*.cloudfront.net,*.cdn.jsdelivr.net,*.unpkg.com",
    portRange: "443",
    protocol: "https",
    action: "allow",
  },
  {
    name: "Log WebSocket Connections",
    description: "Log all WebSocket upgrade attempts for forensic analysis",
    direction: "outbound",
    domainPattern: "*",
    portRange: "*",
    protocol: "wss",
    action: "log_only",
  },
  {
    name: "Block File Upload to External",
    description: "Block file upload submissions to non-approved external endpoints",
    direction: "outbound",
    domainPattern: "*.s3.amazonaws.com,*.blob.core.windows.net",
    portRange: "443",
    protocol: "https",
    action: "challenge",
  },
  {
    name: "Block Local Network Access",
    description: "Prevent browser agents from accessing internal network resources",
    direction: "outbound",
    domainPattern: "192.168.*,10.*,172.16.*,localhost,127.0.0.1",
    portRange: "*",
    protocol: "any",
    action: "block",
  },
];

const TRUSTED_PATH_CATALOG: Array<{
  name: string;
  description: string;
  steps: TrustedPathStep[];
  enforceOrder: boolean;
  maxDurationMs: number;
  failAction: PolicyVerdict;
}> = [
  {
    name: "Alert Investigation Flow",
    description: "Enforced execution path for browser-based alert investigation by agents",
    steps: [
      {
        order: 1,
        actionType: "navigate",
        targetPattern: "/alerts/*",
        requiredContext: ["authenticated"],
        allowSkip: false,
      },
      {
        order: 2,
        actionType: "read",
        targetPattern: ".alert-detail-panel",
        requiredContext: ["alert-loaded"],
        allowSkip: false,
      },
      {
        order: 3,
        actionType: "click",
        targetPattern: "[data-action='investigate']",
        requiredContext: ["alert-selected"],
        allowSkip: false,
      },
      {
        order: 4,
        actionType: "submit",
        targetPattern: "form.investigation-notes",
        requiredContext: ["investigation-open"],
        allowSkip: true,
      },
    ],
    enforceOrder: true,
    maxDurationMs: 120000,
    failAction: "block",
  },
  {
    name: "Compliance Evidence Collection",
    description: "Trusted path for automated compliance evidence screenshot collection",
    steps: [
      {
        order: 1,
        actionType: "navigate",
        targetPattern: "/compliance/*",
        requiredContext: ["authenticated", "compliance-role"],
        allowSkip: false,
      },
      {
        order: 2,
        actionType: "read",
        targetPattern: ".evidence-panel",
        requiredContext: ["framework-loaded"],
        allowSkip: false,
      },
      {
        order: 3,
        actionType: "screenshot",
        targetPattern: ".evidence-content",
        requiredContext: ["evidence-visible"],
        allowSkip: false,
      },
      {
        order: 4,
        actionType: "upload",
        targetPattern: "/api/evidence/*",
        requiredContext: ["screenshot-captured"],
        allowSkip: false,
      },
    ],
    enforceOrder: true,
    maxDurationMs: 60000,
    failAction: "challenge",
  },
  {
    name: "Password Reset Automation",
    description: "Strict path for automated password reset flows requiring step-up at each stage",
    steps: [
      {
        order: 1,
        actionType: "navigate",
        targetPattern: "/settings/security",
        requiredContext: ["authenticated", "admin-role"],
        allowSkip: false,
      },
      {
        order: 2,
        actionType: "click",
        targetPattern: "[data-action='reset-password']",
        requiredContext: ["user-selected"],
        allowSkip: false,
      },
      {
        order: 3,
        actionType: "verify",
        targetPattern: ".step-up-prompt",
        requiredContext: ["mfa-required"],
        allowSkip: false,
      },
      {
        order: 4,
        actionType: "submit",
        targetPattern: "form.password-reset",
        requiredContext: ["mfa-verified"],
        allowSkip: false,
      },
    ],
    enforceOrder: true,
    maxDurationMs: 30000,
    failAction: "block",
  },
  {
    name: "Threat Intel Lookup",
    description: "Path for automated IOC lookup and enrichment via browser",
    steps: [
      {
        order: 1,
        actionType: "navigate",
        targetPattern: "/threat-intel/*",
        requiredContext: ["authenticated"],
        allowSkip: false,
      },
      {
        order: 2,
        actionType: "input",
        targetPattern: "input.ioc-search",
        requiredContext: ["page-loaded"],
        allowSkip: false,
      },
      {
        order: 3,
        actionType: "read",
        targetPattern: ".ioc-results",
        requiredContext: ["search-complete"],
        allowSkip: false,
      },
    ],
    enforceOrder: true,
    maxDurationMs: 45000,
    failAction: "log_only",
  },
  {
    name: "User Deprovisioning Flow",
    description: "High-security path for automated user account deprovisioning",
    steps: [
      {
        order: 1,
        actionType: "navigate",
        targetPattern: "/admin/users/*",
        requiredContext: ["authenticated", "super-admin"],
        allowSkip: false,
      },
      {
        order: 2,
        actionType: "click",
        targetPattern: "[data-action='deprovision']",
        requiredContext: ["user-selected"],
        allowSkip: false,
      },
      {
        order: 3,
        actionType: "verify",
        targetPattern: ".confirmation-dialog",
        requiredContext: ["action-confirmed"],
        allowSkip: false,
      },
      {
        order: 4,
        actionType: "verify",
        targetPattern: ".step-up-mfa",
        requiredContext: ["mfa-required"],
        allowSkip: false,
      },
      {
        order: 5,
        actionType: "submit",
        targetPattern: "form.deprovision-confirm",
        requiredContext: ["mfa-verified", "manager-approved"],
        allowSkip: false,
      },
    ],
    enforceOrder: true,
    maxDurationMs: 60000,
    failAction: "block",
  },
];

const DOM_EVENT_TYPES = [
  "click",
  "input",
  "submit",
  "navigate",
  "screenshot",
  "scroll",
  "select",
  "hover",
  "keypress",
  "paste",
  "drag",
  "upload",
];

const TARGET_SELECTORS = [
  ".alert-detail-panel",
  "button.submit-form",
  "input#search-query",
  "[data-action='delete']",
  "form.settings",
  ".modal-confirm",
  "a.external-link",
  "iframe.sandbox",
  "div.editor-content",
  "#evidence-upload",
  ".user-actions-menu",
  "textarea.notes",
];

function seedSessions(orgId: string): void {
  const sessions: BrowserSession[] = [];
  const now = Date.now();
  const states: SessionState[] = ["active", "active", "active", "isolated", "terminated", "expired"];
  const isolationLevels: BrowserSession["isolationLevel"][] = ["none", "tab", "process", "container"];

  for (let i = 0; i < 15; i++) {
    const agent = AGENT_NAMES[randomBetween(0, AGENT_NAMES.length - 1)];
    const state = states[randomBetween(0, states.length - 1)];
    const createdAt = new Date(now - randomBetween(0, 4 * 24 * 60 * 60 * 1000));
    const expiresAt = new Date(createdAt.getTime() + randomBetween(1, 8) * 60 * 60 * 1000);

    sessions.push({
      id: genId("bsess"),
      orgId,
      agentId: agent.id,
      agentName: agent.name,
      contextId: genId("ctx"),
      originUrl: `https://app.securenexus.io/${["alerts", "compliance", "threat-intel", "settings", "incidents"][randomBetween(0, 4)]}`,
      state,
      isolationLevel: isolationLevels[randomBetween(0, isolationLevels.length - 1)],
      tokensIssued: randomBetween(1, 5),
      tokensBound: randomBetween(0, 3),
      lastActivityAt: new Date(now - randomBetween(0, 60 * 60 * 1000)).toISOString(),
      createdAt: createdAt.toISOString(),
      expiresAt: expiresAt.toISOString(),
      metadata: {
        userAgent: "SecureNexus-BrowserAgent/1.0",
        viewport: `${randomBetween(1024, 1920)}x${randomBetween(768, 1080)}`,
      },
    });
  }

  sessions.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  orgSessionStore.set(orgId, sessions);
}

function seedDomEvents(orgId: string): void {
  const sessions = getSessions(orgId);
  const events: DomEvent[] = [];
  const now = Date.now();
  const classifications: Array<ThreatCategory | "benign"> = [
    "benign",
    "benign",
    "benign",
    "benign",
    "benign",
    "dom_injection",
    "prompt_injection",
    "egress_violation",
    "path_deviation",
    "session_hijack",
    "token_reuse",
    "xss_attempt",
    "clickjacking",
  ];

  for (let i = 0; i < 80; i++) {
    const session = sessions[randomBetween(0, sessions.length - 1)];
    const classification = classifications[randomBetween(0, classifications.length - 1)];
    const isThreat = classification !== "benign";
    const severity: ActionSeverity = isThreat
      ? (["low", "medium", "high", "critical"] as ActionSeverity[])[randomBetween(0, 3)]
      : "info";
    const verdict: PolicyVerdict = isThreat
      ? severity === "critical"
        ? "block"
        : severity === "high"
          ? "challenge"
          : "log_only"
      : "allow";
    const stepUpRequired = verdict === "challenge";

    events.push({
      id: genId("evt"),
      orgId,
      sessionId: session.id,
      agentId: session.agentId,
      eventType: DOM_EVENT_TYPES[randomBetween(0, DOM_EVENT_TYPES.length - 1)],
      targetSelector: TARGET_SELECTORS[randomBetween(0, TARGET_SELECTORS.length - 1)],
      actionClassification: classification,
      severity,
      verdict,
      details: isThreat
        ? `Detected ${classification.replace(/_/g, " ")} targeting ${TARGET_SELECTORS[randomBetween(0, TARGET_SELECTORS.length - 1)]}`
        : `Standard ${DOM_EVENT_TYPES[randomBetween(0, DOM_EVENT_TYPES.length - 1)]} action on page element`,
      rawPayloadHash: hashPayload(`payload-${i}-${session.id}`),
      stepUpRequired,
      stepUpCompleted: stepUpRequired ? i % 3 !== 0 : false,
      timestamp: new Date(now - randomBetween(0, 7 * 24 * 60 * 60 * 1000)).toISOString(),
    });
  }

  events.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  orgDomEventStore.set(orgId, events);
}

function seedEgressRules(orgId: string): void {
  const rules: EgressRule[] = [];
  const now = new Date().toISOString();

  for (const def of EGRESS_RULE_CATALOG) {
    rules.push({
      id: genId("egress"),
      orgId,
      name: def.name,
      description: def.description,
      direction: def.direction,
      domainPattern: def.domainPattern,
      portRange: def.portRange,
      protocol: def.protocol,
      action: def.action,
      enabled: true,
      hitCount: randomBetween(0, 500),
      lastHitAt:
        rules.length % 3 !== 0 ? new Date(Date.now() - randomBetween(0, 3 * 24 * 60 * 60 * 1000)).toISOString() : null,
      createdAt: now,
      updatedAt: now,
    });
  }

  orgEgressRuleStore.set(orgId, rules);
}

function seedTrustedPaths(orgId: string): void {
  const paths: TrustedPath[] = [];
  const now = new Date().toISOString();

  for (const def of TRUSTED_PATH_CATALOG) {
    paths.push({
      id: genId("tpath"),
      orgId,
      name: def.name,
      description: def.description,
      steps: def.steps,
      enforceOrder: def.enforceOrder,
      maxDurationMs: def.maxDurationMs,
      failAction: def.failAction,
      enabled: true,
      executionCount: randomBetween(10, 500),
      deviationCount: randomBetween(0, 30),
      createdAt: now,
      updatedAt: now,
    });
  }

  orgTrustedPathStore.set(orgId, paths);
}

function seedInjectionPatterns(orgId: string): void {
  const patterns: InjectionPattern[] = [];
  const now = new Date().toISOString();

  for (const def of INJECTION_CATALOG) {
    patterns.push({
      id: genId("inj"),
      orgId,
      name: def.name,
      category: def.category,
      pattern: def.pattern,
      severity: def.severity,
      action: def.action,
      description: def.description,
      falsePositiveRate: def.falsePositiveRate,
      detectionCount: randomBetween(0, 200),
      enabled: true,
      createdAt: now,
      updatedAt: now,
    });
  }

  orgInjectionPatternStore.set(orgId, patterns);
}

function getSessions(orgId: string): BrowserSession[] {
  if (!orgSessionStore.has(orgId)) seedSessions(orgId);
  return orgSessionStore.get(orgId)!;
}

function getDomEvents(orgId: string): DomEvent[] {
  if (!orgDomEventStore.has(orgId)) seedDomEvents(orgId);
  return orgDomEventStore.get(orgId)!;
}

function getEgressRulesInternal(orgId: string): EgressRule[] {
  if (!orgEgressRuleStore.has(orgId)) seedEgressRules(orgId);
  return orgEgressRuleStore.get(orgId)!;
}

function getTrustedPathsInternal(orgId: string): TrustedPath[] {
  if (!orgTrustedPathStore.has(orgId)) seedTrustedPaths(orgId);
  return orgTrustedPathStore.get(orgId)!;
}

function getInjectionPatternsInternal(orgId: string): InjectionPattern[] {
  if (!orgInjectionPatternStore.has(orgId)) seedInjectionPatterns(orgId);
  return orgInjectionPatternStore.get(orgId)!;
}

export function getBrowserDefenseStats(orgId: string): BrowserDefenseStats {
  const sessions = getSessions(orgId);
  const events = getDomEvents(orgId);
  const egressRules = getEgressRulesInternal(orgId);
  const trustedPaths = getTrustedPathsInternal(orgId);
  const injectionPatterns = getInjectionPatternsInternal(orgId);

  const threatsByCategory: Record<string, number> = {};
  const eventsBySeverity: Record<string, number> = {};
  let blockedEvents = 0;
  let challengedEvents = 0;
  let allowedEvents = 0;
  let injectionDetections = 0;

  for (const evt of events) {
    if (evt.actionClassification !== "benign") {
      threatsByCategory[evt.actionClassification] = (threatsByCategory[evt.actionClassification] || 0) + 1;
    }
    eventsBySeverity[evt.severity] = (eventsBySeverity[evt.severity] || 0) + 1;
    if (evt.verdict === "block") blockedEvents++;
    else if (evt.verdict === "challenge") challengedEvents++;
    else allowedEvents++;
  }

  for (const p of injectionPatterns) {
    injectionDetections += p.detectionCount;
  }

  let pathDeviations = 0;
  for (const tp of trustedPaths) {
    pathDeviations += tp.deviationCount;
  }

  let egressViolations = 0;
  for (const r of egressRules) {
    if (r.action === "block") egressViolations += r.hitCount;
  }

  return {
    totalSessions: sessions.length,
    activeSessions: sessions.filter((s) => s.state === "active").length,
    isolatedSessions: sessions.filter((s) => s.state === "isolated").length,
    terminatedSessions: sessions.filter((s) => s.state === "terminated").length,
    totalDomEvents: events.length,
    blockedEvents,
    challengedEvents,
    allowedEvents,
    totalEgressRules: egressRules.length,
    activeEgressRules: egressRules.filter((r) => r.enabled).length,
    egressViolations,
    totalTrustedPaths: trustedPaths.length,
    activeTrustedPaths: trustedPaths.filter((tp) => tp.enabled).length,
    pathDeviations,
    totalInjectionPatterns: injectionPatterns.length,
    activeInjectionPatterns: injectionPatterns.filter((p) => p.enabled).length,
    injectionDetections,
    threatsByCategory,
    eventsBySeverity,
  };
}

export function listSessions(orgId: string, filters?: { state?: SessionState; agentId?: string }): BrowserSession[] {
  let sessions = getSessions(orgId);
  if (filters?.state) sessions = sessions.filter((s) => s.state === filters.state);
  if (filters?.agentId) sessions = sessions.filter((s) => s.agentId === filters.agentId);
  return sessions;
}

export function getSessionById(orgId: string, sessionId: string): BrowserSession | undefined {
  return getSessions(orgId).find((s) => s.id === sessionId);
}

export function isolateSession(orgId: string, sessionId: string): BrowserSession | undefined {
  const sessions = getSessions(orgId);
  const session = sessions.find((s) => s.id === sessionId);
  if (!session) return undefined;
  session.state = "isolated";
  session.isolationLevel = "container";
  session.lastActivityAt = new Date().toISOString();
  return session;
}

export function terminateSession(orgId: string, sessionId: string): BrowserSession | undefined {
  const sessions = getSessions(orgId);
  const session = sessions.find((s) => s.id === sessionId);
  if (!session) return undefined;
  session.state = "terminated";
  session.lastActivityAt = new Date().toISOString();
  return session;
}

export function listDomEvents(
  orgId: string,
  filters?: {
    sessionId?: string;
    classification?: string;
    severity?: ActionSeverity;
    verdict?: PolicyVerdict;
  },
): DomEvent[] {
  let events = getDomEvents(orgId);
  if (filters?.sessionId) events = events.filter((e) => e.sessionId === filters.sessionId);
  if (filters?.classification) events = events.filter((e) => e.actionClassification === filters.classification);
  if (filters?.severity) events = events.filter((e) => e.severity === filters.severity);
  if (filters?.verdict) events = events.filter((e) => e.verdict === filters.verdict);
  return events;
}

export function classifyDomAction(
  orgId: string,
  sessionId: string,
  payload: {
    eventType: string;
    targetSelector: string;
    rawPayload: string;
  },
): DomEvent {
  const sessions = getSessions(orgId);
  const session = sessions.find((s) => s.id === sessionId);
  if (!session) throw new Error("SESSION_NOT_FOUND");

  const patterns = getInjectionPatternsInternal(orgId);
  let classification: ThreatCategory | "benign" = "benign";
  let matchedSeverity: ActionSeverity = "info";
  let matchedVerdict: PolicyVerdict = "allow";

  for (const pat of patterns) {
    if (!pat.enabled) continue;
    try {
      const re = new RegExp(pat.pattern, "i");
      if (re.test(payload.rawPayload) || re.test(payload.targetSelector)) {
        classification = pat.category;
        matchedSeverity = pat.severity;
        matchedVerdict = pat.action;
        pat.detectionCount++;
        break;
      }
    } catch {
      continue;
    }
  }

  const stepUpRequired = matchedVerdict === "challenge";
  const event: DomEvent = {
    id: genId("evt"),
    orgId,
    sessionId,
    agentId: session.agentId,
    eventType: payload.eventType,
    targetSelector: payload.targetSelector,
    actionClassification: classification,
    severity: matchedSeverity,
    verdict: matchedVerdict,
    details:
      classification !== "benign"
        ? `Detected ${classification.replace(/_/g, " ")} in ${payload.eventType} targeting ${payload.targetSelector}`
        : `Benign ${payload.eventType} action on ${payload.targetSelector}`,
    rawPayloadHash: hashPayload(payload.rawPayload),
    stepUpRequired,
    stepUpCompleted: false,
    timestamp: new Date().toISOString(),
  };

  getDomEvents(orgId).unshift(event);
  return event;
}

export function listEgressRules(orgId: string): EgressRule[] {
  return getEgressRulesInternal(orgId);
}

export function createEgressRule(
  orgId: string,
  input: {
    name: string;
    description: string;
    direction: "outbound" | "inbound";
    domainPattern: string;
    portRange: string;
    protocol: "https" | "http" | "wss" | "ws" | "any";
    action: PolicyVerdict;
  },
): EgressRule {
  const now = new Date().toISOString();
  const rule: EgressRule = {
    id: genId("egress"),
    orgId,
    name: input.name,
    description: input.description,
    direction: input.direction,
    domainPattern: input.domainPattern,
    portRange: input.portRange,
    protocol: input.protocol,
    action: input.action,
    enabled: true,
    hitCount: 0,
    lastHitAt: null,
    createdAt: now,
    updatedAt: now,
  };
  getEgressRulesInternal(orgId).push(rule);
  return rule;
}

export function updateEgressRule(
  orgId: string,
  ruleId: string,
  updates: Partial<
    Pick<EgressRule, "name" | "description" | "domainPattern" | "portRange" | "protocol" | "action" | "enabled">
  >,
): EgressRule | undefined {
  const rules = getEgressRulesInternal(orgId);
  const rule = rules.find((r) => r.id === ruleId);
  if (!rule) return undefined;
  if (updates.name !== undefined) rule.name = updates.name;
  if (updates.description !== undefined) rule.description = updates.description;
  if (updates.domainPattern !== undefined) rule.domainPattern = updates.domainPattern;
  if (updates.portRange !== undefined) rule.portRange = updates.portRange;
  if (updates.protocol !== undefined) rule.protocol = updates.protocol;
  if (updates.action !== undefined) rule.action = updates.action;
  if (updates.enabled !== undefined) rule.enabled = updates.enabled;
  rule.updatedAt = new Date().toISOString();
  return rule;
}

export function deleteEgressRule(orgId: string, ruleId: string): boolean {
  const rules = getEgressRulesInternal(orgId);
  const idx = rules.findIndex((r) => r.id === ruleId);
  if (idx === -1) return false;
  rules.splice(idx, 1);
  return true;
}

export function listTrustedPaths(orgId: string): TrustedPath[] {
  return getTrustedPathsInternal(orgId);
}

export function getTrustedPathById(orgId: string, pathId: string): TrustedPath | undefined {
  return getTrustedPathsInternal(orgId).find((p) => p.id === pathId);
}

export function createTrustedPath(
  orgId: string,
  input: {
    name: string;
    description: string;
    steps: TrustedPathStep[];
    enforceOrder: boolean;
    maxDurationMs: number;
    failAction: PolicyVerdict;
  },
): TrustedPath {
  const now = new Date().toISOString();
  const path: TrustedPath = {
    id: genId("tpath"),
    orgId,
    name: input.name,
    description: input.description,
    steps: input.steps,
    enforceOrder: input.enforceOrder,
    maxDurationMs: input.maxDurationMs,
    failAction: input.failAction,
    enabled: true,
    executionCount: 0,
    deviationCount: 0,
    createdAt: now,
    updatedAt: now,
  };
  getTrustedPathsInternal(orgId).push(path);
  return path;
}

export function updateTrustedPath(
  orgId: string,
  pathId: string,
  updates: Partial<
    Pick<TrustedPath, "name" | "description" | "enforceOrder" | "maxDurationMs" | "failAction" | "enabled">
  >,
): TrustedPath | undefined {
  const paths = getTrustedPathsInternal(orgId);
  const path = paths.find((p) => p.id === pathId);
  if (!path) return undefined;
  if (updates.name !== undefined) path.name = updates.name;
  if (updates.description !== undefined) path.description = updates.description;
  if (updates.enforceOrder !== undefined) path.enforceOrder = updates.enforceOrder;
  if (updates.maxDurationMs !== undefined) path.maxDurationMs = updates.maxDurationMs;
  if (updates.failAction !== undefined) path.failAction = updates.failAction;
  if (updates.enabled !== undefined) path.enabled = updates.enabled;
  path.updatedAt = new Date().toISOString();
  return path;
}

export function deleteTrustedPath(orgId: string, pathId: string): boolean {
  const paths = getTrustedPathsInternal(orgId);
  const idx = paths.findIndex((p) => p.id === pathId);
  if (idx === -1) return false;
  paths.splice(idx, 1);
  return true;
}

export function listInjectionPatterns(orgId: string): InjectionPattern[] {
  return getInjectionPatternsInternal(orgId);
}

export function updateInjectionPattern(
  orgId: string,
  patternId: string,
  updates: Partial<Pick<InjectionPattern, "name" | "severity" | "action" | "enabled">>,
): InjectionPattern | undefined {
  const patterns = getInjectionPatternsInternal(orgId);
  const pattern = patterns.find((p) => p.id === patternId);
  if (!pattern) return undefined;
  if (updates.name !== undefined) pattern.name = updates.name;
  if (updates.severity !== undefined) pattern.severity = updates.severity;
  if (updates.action !== undefined) pattern.action = updates.action;
  if (updates.enabled !== undefined) pattern.enabled = updates.enabled;
  pattern.updatedAt = new Date().toISOString();
  return pattern;
}

export function evaluateEgress(
  orgId: string,
  destination: string,
  protocol: string,
): { verdict: PolicyVerdict; matchedRule: EgressRule | null } {
  const rules = getEgressRulesInternal(orgId).filter((r) => r.enabled);

  for (const rule of rules) {
    const domainPatterns = rule.domainPattern.split(",").map((d) => d.trim());
    for (const dp of domainPatterns) {
      const regex = new RegExp("^" + dp.replace(/\./g, "\\.").replace(/\*/g, ".*") + "$", "i");
      if (regex.test(destination) && (rule.protocol === "any" || rule.protocol === protocol)) {
        rule.hitCount++;
        rule.lastHitAt = new Date().toISOString();
        return { verdict: rule.action, matchedRule: rule };
      }
    }
  }

  return { verdict: "allow", matchedRule: null };
}
