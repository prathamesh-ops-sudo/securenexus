import { randomUUID } from "crypto";

export type RemediationType = "pull_request" | "ide_fix" | "config_change" | "policy_update" | "access_review";

export type RemediationPriority = "critical" | "high" | "medium" | "low";

export type RemediationStatus = "suggested" | "in_progress" | "applied" | "dismissed" | "failed";

export interface CodeOwner {
  id: string;
  name: string;
  email: string;
  team: string;
  filesOwned: string[];
  reviewCount: number;
  lastActive: string;
}

export interface RemediationFix {
  id: string;
  type: RemediationType;
  title: string;
  description: string;
  priority: RemediationPriority;
  status: RemediationStatus;
  finding: FindingContext;
  codeChange: CodeChange | null;
  owner: CodeOwner | null;
  estimatedEffort: string;
  mitreTactics: string[];
  cweIds: string[];
  createdAt: string;
  updatedAt: string;
}

export interface FindingContext {
  source: string;
  rule: string;
  severity: string;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  snippet: string;
  message: string;
}

export interface CodeChange {
  filePath: string;
  language: string;
  diff: string;
  beforeSnippet: string;
  afterSnippet: string;
  explanation: string;
}

export interface RemediationStats {
  totalFindings: number;
  suggestedFixes: number;
  appliedFixes: number;
  dismissedFixes: number;
  inProgressFixes: number;
  byPriority: Record<RemediationPriority, number>;
  byType: Record<RemediationType, number>;
  topOwners: { owner: CodeOwner; fixCount: number }[];
  meanTimeToRemediate: string;
  coveragePercent: number;
}

const CODE_OWNERS: CodeOwner[] = [
  {
    id: "owner-1",
    name: "Alice Chen",
    email: "alice.chen@securenexus.io",
    team: "Platform Security",
    filesOwned: ["server/auth.ts", "server/middleware/*.ts", "server/routes/auth.ts"],
    reviewCount: 47,
    lastActive: "2026-03-05T18:30:00Z",
  },
  {
    id: "owner-2",
    name: "Bob Martinez",
    email: "bob.martinez@securenexus.io",
    team: "Backend Engineering",
    filesOwned: ["server/routes/*.ts", "server/storage.ts", "server/db/*.ts"],
    reviewCount: 62,
    lastActive: "2026-03-06T02:15:00Z",
  },
  {
    id: "owner-3",
    name: "Carol Davis",
    email: "carol.davis@securenexus.io",
    team: "Frontend Engineering",
    filesOwned: ["client/src/pages/*.tsx", "client/src/components/*.tsx"],
    reviewCount: 38,
    lastActive: "2026-03-05T22:45:00Z",
  },
  {
    id: "owner-4",
    name: "Dan Wilson",
    email: "dan.wilson@securenexus.io",
    team: "DevOps",
    filesOwned: ["k8s/*.yaml", ".github/workflows/*.yml", "Dockerfile", "docker-compose.yml"],
    reviewCount: 25,
    lastActive: "2026-03-06T01:00:00Z",
  },
  {
    id: "owner-5",
    name: "Eve Thompson",
    email: "eve.thompson@securenexus.io",
    team: "Data Engineering",
    filesOwned: ["server/connectors/*.ts", "server/ingestion/*.ts", "shared/schema.ts"],
    reviewCount: 31,
    lastActive: "2026-03-05T20:00:00Z",
  },
];

const REMEDIATION_FIXES: RemediationFix[] = [
  {
    id: "fix-1",
    type: "pull_request",
    title: "Fix SQL injection in alert search endpoint",
    description:
      "The /api/alerts search parameter is concatenated directly into a SQL query without parameterization. Replace string concatenation with parameterized queries.",
    priority: "critical",
    status: "suggested",
    finding: {
      source: "CodeQL",
      rule: "js/sql-injection",
      severity: "critical",
      filePath: "server/routes/alerts.ts",
      lineStart: 142,
      lineEnd: 148,
      snippet: "const query = `SELECT * FROM alerts WHERE title LIKE '%${searchTerm}%'`;",
      message: "User-controlled data flows into a SQL query without sanitization",
    },
    codeChange: {
      filePath: "server/routes/alerts.ts",
      language: "typescript",
      diff: `--- a/server/routes/alerts.ts
+++ b/server/routes/alerts.ts
@@ -142,3 +142,3 @@
-  const query = \`SELECT * FROM alerts WHERE title LIKE '%\${searchTerm}%'\`;
+  const query = db.prepare("SELECT * FROM alerts WHERE title LIKE ?").bind(\`%\${searchTerm}%\`);`,
      beforeSnippet: "const query = `SELECT * FROM alerts WHERE title LIKE '%${searchTerm}%'`;",
      afterSnippet: 'const query = db.prepare("SELECT * FROM alerts WHERE title LIKE ?").bind(`%${searchTerm}%`);',
      explanation:
        "Use parameterized queries to prevent SQL injection. The search term is now bound as a parameter instead of being interpolated into the query string.",
    },
    owner: CODE_OWNERS[1],
    estimatedEffort: "15 min",
    mitreTactics: ["initial-access", "execution"],
    cweIds: ["CWE-89"],
    createdAt: "2026-03-05T10:00:00Z",
    updatedAt: "2026-03-05T10:00:00Z",
  },
  {
    id: "fix-2",
    type: "pull_request",
    title: "Add CSRF token validation to state-changing endpoints",
    description:
      "POST/PUT/DELETE endpoints lack CSRF token validation. Add csrf middleware to all state-changing routes.",
    priority: "high",
    status: "suggested",
    finding: {
      source: "Security Audit",
      rule: "csrf-missing",
      severity: "high",
      filePath: "server/routes/incidents.ts",
      lineStart: 45,
      lineEnd: 52,
      snippet:
        'app.post("/api/incidents", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("analyst"), async (req, res) => {',
      message: "State-changing endpoint does not validate CSRF token",
    },
    codeChange: {
      filePath: "server/routes/incidents.ts",
      language: "typescript",
      diff: `--- a/server/routes/incidents.ts
+++ b/server/routes/incidents.ts
@@ -45,1 +45,1 @@
-  app.post("/api/incidents", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("analyst"), async (req, res) => {
+  app.post("/api/incidents", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("analyst"), csrfProtection, async (req, res) => {`,
      beforeSnippet:
        'app.post("/api/incidents", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("analyst"), async (req, res) => {',
      afterSnippet:
        'app.post("/api/incidents", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("analyst"), csrfProtection, async (req, res) => {',
      explanation:
        "Add csrfProtection middleware before the route handler to validate the CSRF token on all state-changing requests.",
    },
    owner: CODE_OWNERS[0],
    estimatedEffort: "30 min",
    mitreTactics: ["initial-access"],
    cweIds: ["CWE-352"],
    createdAt: "2026-03-05T11:00:00Z",
    updatedAt: "2026-03-05T11:00:00Z",
  },
  {
    id: "fix-3",
    type: "ide_fix",
    title: "Sanitize user input in entity search",
    description: "Entity search query parameter is passed directly to a regex constructor, enabling ReDoS attacks.",
    priority: "high",
    status: "in_progress",
    finding: {
      source: "CodeQL",
      rule: "js/regex-injection",
      severity: "high",
      filePath: "server/routes/entities.ts",
      lineStart: 78,
      lineEnd: 82,
      snippet: "const pattern = new RegExp(searchQuery, 'i');",
      message: "User input flows into RegExp constructor without escaping",
    },
    codeChange: {
      filePath: "server/routes/entities.ts",
      language: "typescript",
      diff: "--- a/server/routes/entities.ts\n+++ b/server/routes/entities.ts\n@@ -78,1 +78,2 @@\n-  const pattern = new RegExp(searchQuery, 'i');\n+  const escaped = searchQuery.replace(/[.*+?^${}()|[\\\\]\\\\\\\\]/g, '\\\\\\\\$&');\n+  const pattern = new RegExp(escaped, 'i');",
      beforeSnippet: "const pattern = new RegExp(searchQuery, 'i');",
      afterSnippet:
        "const escaped = searchQuery.replace(/[.*+?^${}()|[\\\\]\\\\\\\\]/g, '\\\\\\\\$&');\nconst pattern = new RegExp(escaped, 'i');",
      explanation:
        "Escape special regex characters in user input before passing to RegExp constructor to prevent ReDoS attacks.",
    },
    owner: CODE_OWNERS[1],
    estimatedEffort: "10 min",
    mitreTactics: ["execution"],
    cweIds: ["CWE-1333"],
    createdAt: "2026-03-05T12:00:00Z",
    updatedAt: "2026-03-05T14:00:00Z",
  },
  {
    id: "fix-4",
    type: "config_change",
    title: "Enable HTTP Strict Transport Security (HSTS)",
    description: "HSTS header is not set. Add helmet HSTS configuration to enforce HTTPS connections.",
    priority: "medium",
    status: "applied",
    finding: {
      source: "Security Headers Scan",
      rule: "hsts-missing",
      severity: "medium",
      filePath: "server/middleware/security.ts",
      lineStart: 12,
      lineEnd: 15,
      snippet: "app.use(helmet());",
      message: "HSTS header not configured with appropriate max-age",
    },
    codeChange: {
      filePath: "server/middleware/security.ts",
      language: "typescript",
      diff: `--- a/server/middleware/security.ts
+++ b/server/middleware/security.ts
@@ -12,1 +12,5 @@
-  app.use(helmet());
+  app.use(helmet({
+    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
+    contentSecurityPolicy: { directives: { defaultSrc: ["'self'"] } },
+    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
+  }));`,
      beforeSnippet: "app.use(helmet());",
      afterSnippet: `app.use(helmet({
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  contentSecurityPolicy: { directives: { defaultSrc: ["'self'"] } },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
}));`,
      explanation: "Configure helmet with explicit HSTS, CSP, and referrer policy settings for defense-in-depth.",
    },
    owner: CODE_OWNERS[0],
    estimatedEffort: "10 min",
    mitreTactics: ["credential-access"],
    cweIds: ["CWE-319"],
    createdAt: "2026-03-04T09:00:00Z",
    updatedAt: "2026-03-05T16:00:00Z",
  },
  {
    id: "fix-5",
    type: "policy_update",
    title: "Enforce least-privilege IAM roles for Lambda functions",
    description: "Lambda execution role uses AdministratorAccess policy. Scope down to minimum required permissions.",
    priority: "critical",
    status: "suggested",
    finding: {
      source: "AWS Config",
      rule: "iam-role-overprivileged",
      severity: "critical",
      filePath: "k8s/iam-roles.yaml",
      lineStart: 22,
      lineEnd: 28,
      snippet: "PolicyArn: arn:aws:iam::aws:policy/AdministratorAccess",
      message: "IAM role attached to compute resource has AdministratorAccess",
    },
    codeChange: {
      filePath: "k8s/iam-roles.yaml",
      language: "yaml",
      diff: `--- a/k8s/iam-roles.yaml
+++ b/k8s/iam-roles.yaml
@@ -22,1 +22,6 @@
-  PolicyArn: arn:aws:iam::aws:policy/AdministratorAccess
+  PolicyDocument:
+    Statement:
+      - Effect: Allow
+        Action:
+          - logs:CreateLogGroup
+          - logs:CreateLogStream
+          - logs:PutLogEvents
+        Resource: "arn:aws:logs:*:*:*"`,
      beforeSnippet: "PolicyArn: arn:aws:iam::aws:policy/AdministratorAccess",
      afterSnippet: `PolicyDocument:
  Statement:
    - Effect: Allow
      Action:
        - logs:CreateLogGroup
        - logs:CreateLogStream
        - logs:PutLogEvents
      Resource: "arn:aws:logs:*:*:*"`,
      explanation:
        "Replace AdministratorAccess with a custom policy that grants only the minimum permissions needed for the function to operate.",
    },
    owner: CODE_OWNERS[3],
    estimatedEffort: "45 min",
    mitreTactics: ["privilege-escalation", "lateral-movement"],
    cweIds: ["CWE-250"],
    createdAt: "2026-03-05T08:00:00Z",
    updatedAt: "2026-03-05T08:00:00Z",
  },
  {
    id: "fix-6",
    type: "access_review",
    title: "Revoke stale service account tokens",
    description: "3 service account tokens have not been rotated in over 90 days. Rotate or revoke these tokens.",
    priority: "high",
    status: "suggested",
    finding: {
      source: "Access Audit",
      rule: "stale-credentials",
      severity: "high",
      filePath: "k8s/service-accounts.yaml",
      lineStart: 1,
      lineEnd: 15,
      snippet: "kind: ServiceAccount\nmetadata:\n  name: connector-sa",
      message: "Service account token last rotated 94 days ago",
    },
    codeChange: null,
    owner: CODE_OWNERS[3],
    estimatedEffort: "20 min",
    mitreTactics: ["credential-access", "persistence"],
    cweIds: ["CWE-798"],
    createdAt: "2026-03-05T07:00:00Z",
    updatedAt: "2026-03-05T07:00:00Z",
  },
  {
    id: "fix-7",
    type: "pull_request",
    title: "Add rate limiting to authentication endpoints",
    description: "Login and password reset endpoints lack rate limiting, enabling brute-force attacks.",
    priority: "high",
    status: "suggested",
    finding: {
      source: "Penetration Test",
      rule: "brute-force-possible",
      severity: "high",
      filePath: "server/routes/auth.ts",
      lineStart: 30,
      lineEnd: 35,
      snippet: 'app.post("/api/auth/login", async (req, res) => {',
      message: "Authentication endpoint has no rate limiting",
    },
    codeChange: {
      filePath: "server/routes/auth.ts",
      language: "typescript",
      diff: `--- a/server/routes/auth.ts
+++ b/server/routes/auth.ts
@@ -30,1 +30,5 @@
-  app.post("/api/auth/login", async (req, res) => {
+  const authLimiter = rateLimit({
+    windowMs: 5 * 60 * 1000,
+    max: 10,
+    message: { message: "Too many login attempts, please try again later" },
+  });
+  app.post("/api/auth/login", authLimiter, async (req, res) => {`,
      beforeSnippet: 'app.post("/api/auth/login", async (req, res) => {',
      afterSnippet: `const authLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 10,
  message: { message: "Too many login attempts, please try again later" },
});
app.post("/api/auth/login", authLimiter, async (req, res) => {`,
      explanation:
        "Add a dedicated rate limiter for authentication endpoints: 10 attempts per 5-minute window to prevent brute-force attacks.",
    },
    owner: CODE_OWNERS[0],
    estimatedEffort: "15 min",
    mitreTactics: ["credential-access", "initial-access"],
    cweIds: ["CWE-307"],
    createdAt: "2026-03-04T15:00:00Z",
    updatedAt: "2026-03-04T15:00:00Z",
  },
  {
    id: "fix-8",
    type: "ide_fix",
    title: "Escape HTML in user-generated content rendering",
    description: "User-supplied description field is rendered with dangerouslySetInnerHTML without sanitization.",
    priority: "critical",
    status: "suggested",
    finding: {
      source: "CodeQL",
      rule: "js/xss",
      severity: "critical",
      filePath: "client/src/pages/incident-detail.tsx",
      lineStart: 156,
      lineEnd: 158,
      snippet: "<div dangerouslySetInnerHTML={{ __html: incident.description }} />",
      message: "User-controlled HTML rendered without sanitization enables XSS",
    },
    codeChange: {
      filePath: "client/src/pages/incident-detail.tsx",
      language: "tsx",
      diff: `--- a/client/src/pages/incident-detail.tsx
+++ b/client/src/pages/incident-detail.tsx
@@ -156,1 +156,2 @@
-  <div dangerouslySetInnerHTML={{ __html: incident.description }} />
+  import DOMPurify from 'dompurify';
+  <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(incident.description) }} />`,
      beforeSnippet: "<div dangerouslySetInnerHTML={{ __html: incident.description }} />",
      afterSnippet: "<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(incident.description) }} />",
      explanation:
        "Sanitize HTML content using DOMPurify before rendering to prevent stored XSS attacks through user-generated content.",
    },
    owner: CODE_OWNERS[2],
    estimatedEffort: "10 min",
    mitreTactics: ["execution", "collection"],
    cweIds: ["CWE-79"],
    createdAt: "2026-03-05T13:00:00Z",
    updatedAt: "2026-03-05T13:00:00Z",
  },
  {
    id: "fix-9",
    type: "config_change",
    title: "Set secure cookie flags for session cookies",
    description: "Session cookies are missing Secure and SameSite flags, making them vulnerable to interception.",
    priority: "medium",
    status: "applied",
    finding: {
      source: "Security Headers Scan",
      rule: "insecure-cookie",
      severity: "medium",
      filePath: "server/auth.ts",
      lineStart: 88,
      lineEnd: 92,
      snippet: "res.cookie('session', token, { httpOnly: true });",
      message: "Session cookie missing Secure and SameSite attributes",
    },
    codeChange: {
      filePath: "server/auth.ts",
      language: "typescript",
      diff: `--- a/server/auth.ts
+++ b/server/auth.ts
@@ -88,1 +88,5 @@
-  res.cookie('session', token, { httpOnly: true });
+  res.cookie('session', token, {
+    httpOnly: true,
+    secure: process.env.NODE_ENV === 'production',
+    sameSite: 'strict',
+    maxAge: 15 * 60 * 1000,
+  });`,
      beforeSnippet: "res.cookie('session', token, { httpOnly: true });",
      afterSnippet: `res.cookie('session', token, {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  maxAge: 15 * 60 * 1000,
});`,
      explanation:
        "Add Secure (HTTPS-only), SameSite (strict), and maxAge flags to session cookies to prevent interception and CSRF.",
    },
    owner: CODE_OWNERS[0],
    estimatedEffort: "5 min",
    mitreTactics: ["credential-access"],
    cweIds: ["CWE-614"],
    createdAt: "2026-03-04T10:00:00Z",
    updatedAt: "2026-03-05T09:00:00Z",
  },
  {
    id: "fix-10",
    type: "pull_request",
    title: "Validate file upload content type and size",
    description:
      "File upload endpoint accepts any content type and has no size limit, enabling arbitrary file upload attacks.",
    priority: "high",
    status: "dismissed",
    finding: {
      source: "Security Audit",
      rule: "unrestricted-upload",
      severity: "high",
      filePath: "server/routes/files.ts",
      lineStart: 25,
      lineEnd: 30,
      snippet:
        'app.post("/api/files/upload", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("analyst"), upload.single("file"), ...',
      message: "File upload has no content type or size restrictions",
    },
    codeChange: {
      filePath: "server/routes/files.ts",
      language: "typescript",
      diff: `--- a/server/routes/files.ts
+++ b/server/routes/files.ts
@@ -25,1 +25,8 @@
-  app.post("/api/files/upload", isAuthenticated, upload.single("file"), ...
+  const ALLOWED_TYPES = ['application/pdf', 'text/plain', 'image/png', 'image/jpeg'];
+  const MAX_SIZE = 10 * 1024 * 1024; // 10MB
+  const restrictedUpload = multer({
+    limits: { fileSize: MAX_SIZE },
+    fileFilter: (req, file, cb) => {
+      cb(null, ALLOWED_TYPES.includes(file.mimetype));
+    },
+  });
+  app.post("/api/files/upload", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("analyst"), restrictedUpload.single("file"), ...`,
      beforeSnippet:
        'app.post("/api/files/upload", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("analyst"), upload.single("file"), ...',
      afterSnippet: `const ALLOWED_TYPES = ['application/pdf', 'text/plain', 'image/png', 'image/jpeg'];
const MAX_SIZE = 10 * 1024 * 1024;
const restrictedUpload = multer({
  limits: { fileSize: MAX_SIZE },
  fileFilter: (req, file, cb) => { cb(null, ALLOWED_TYPES.includes(file.mimetype)); },
});
app.post("/api/files/upload", isAuthenticated, resolveOrgContext, requireOrgId, requireMinRole("analyst"), restrictedUpload.single("file"), ...`,
      explanation:
        "Restrict file uploads to allowed MIME types and enforce a 10MB size limit to prevent arbitrary file upload attacks.",
    },
    owner: CODE_OWNERS[1],
    estimatedEffort: "20 min",
    mitreTactics: ["execution", "initial-access"],
    cweIds: ["CWE-434"],
    createdAt: "2026-03-04T11:00:00Z",
    updatedAt: "2026-03-05T17:00:00Z",
  },
];

function findOwnerForFile(filePath: string): CodeOwner | null {
  for (const owner of CODE_OWNERS) {
    for (const pattern of owner.filesOwned) {
      if (pattern.includes("*")) {
        const prefix = pattern.split("*")[0];
        if (filePath.startsWith(prefix)) return owner;
      } else if (filePath === pattern) {
        return owner;
      }
    }
  }
  return null;
}

export function getRemediations(_orgId?: string | null): RemediationFix[] {
  return [...REMEDIATION_FIXES].sort((a, b) => {
    const priorityOrder: Record<RemediationPriority, number> = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
    };
    return priorityOrder[a.priority] - priorityOrder[b.priority];
  });
}

export function getRemediationById(id: string, _orgId?: string | null): RemediationFix | null {
  return REMEDIATION_FIXES.find((f) => f.id === id) || null;
}

export function getCodeOwners(_orgId?: string | null): CodeOwner[] {
  return [...CODE_OWNERS];
}

export function getCodeOwnerForFile(filePath: string): CodeOwner | null {
  return findOwnerForFile(filePath);
}

export function getRemediationStats(_orgId?: string | null): RemediationStats {
  const fixes = REMEDIATION_FIXES;

  const byPriority: Record<RemediationPriority, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };
  const byType: Record<RemediationType, number> = {
    pull_request: 0,
    ide_fix: 0,
    config_change: 0,
    policy_update: 0,
    access_review: 0,
  };

  let appliedCount = 0;
  let dismissedCount = 0;
  let inProgressCount = 0;

  for (const fix of fixes) {
    byPriority[fix.priority]++;
    byType[fix.type]++;
    if (fix.status === "applied") appliedCount++;
    if (fix.status === "dismissed") dismissedCount++;
    if (fix.status === "in_progress") inProgressCount++;
  }

  const ownerFixCounts = new Map<string, number>();
  for (const fix of fixes) {
    if (fix.owner) {
      ownerFixCounts.set(fix.owner.id, (ownerFixCounts.get(fix.owner.id) || 0) + 1);
    }
  }

  const topOwners = Array.from(ownerFixCounts.entries())
    .map(([ownerId, fixCount]) => ({
      owner: CODE_OWNERS.find((o) => o.id === ownerId)!,
      fixCount,
    }))
    .filter((entry) => entry.owner)
    .sort((a, b) => b.fixCount - a.fixCount)
    .slice(0, 5);

  return {
    totalFindings: fixes.length,
    suggestedFixes: fixes.filter((f) => f.status === "suggested").length,
    appliedFixes: appliedCount,
    dismissedFixes: dismissedCount,
    inProgressFixes: inProgressCount,
    byPriority,
    byType,
    topOwners,
    meanTimeToRemediate: "4.2 hours",
    coveragePercent: Math.round(((appliedCount + inProgressCount) / fixes.length) * 100),
  };
}
