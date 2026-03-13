/**
 * SAST Engine — Static Application Security Testing for Developer Security
 *
 * Pattern-based static analysis rules for detecting common vulnerabilities:
 * SQL injection, XSS, path traversal, command injection, SSRF, hardcoded secrets, etc.
 */

import { logger } from "./logger";
import crypto from "crypto";

const log = logger.child("sast-engine");

export interface SastRule {
  id: string;
  category: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  pattern: RegExp;
  languages: string[];
  cweId: string;
  owaspCategory: string;
  remediation: string;
  confidence: number;
}

export interface SastScanResult {
  scanId: string;
  repository: string;
  branch: string;
  commitSha: string;
  findings: SastFindingResult[];
  secretFindings: SecretFindingResult[];
  scanDurationMs: number;
  filesScanned: number;
  linesScanned: number;
}

export interface SastFindingResult {
  ruleId: string;
  category: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  remediation: string;
  filePath: string;
  startLine: number;
  endLine: number;
  codeSnippet: string;
  cweId: string;
  owaspCategory: string;
  confidence: number;
}

export interface SecretFindingResult {
  secretType: string;
  filePath: string;
  line: number;
  maskedValue: string;
  severity: "critical" | "high";
  secretHash: string;
}

// ── SAST Rules ─────────────────────────────────────────────────────

const SAST_RULES: SastRule[] = [
  // SQL Injection
  {
    id: "SAST-SQL-001",
    category: "sql_injection",
    severity: "critical",
    title: "SQL Injection via string concatenation",
    description:
      "SQL query is constructed using string concatenation with user input. This allows attackers to inject arbitrary SQL commands.",
    pattern: /(?:query|execute|raw)\s*\(\s*[`"'].*\$\{.*\}.*[`"']/gi,
    languages: ["typescript", "javascript"],
    cweId: "CWE-89",
    owaspCategory: "A03:2021-Injection",
    remediation: "Use parameterized queries or prepared statements instead of string concatenation.",
    confidence: 0.9,
  },
  {
    id: "SAST-SQL-002",
    category: "sql_injection",
    severity: "critical",
    title: "SQL Injection via string concatenation (+ operator)",
    description: "SQL query built with + operator concatenation, allowing SQL injection.",
    pattern: /(?:query|execute|sql)\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE|DROP)\b[^"']*["']\s*\+/gi,
    languages: ["typescript", "javascript", "java"],
    cweId: "CWE-89",
    owaspCategory: "A03:2021-Injection",
    remediation: "Use parameterized queries. Never concatenate user input into SQL strings.",
    confidence: 0.85,
  },
  {
    id: "SAST-SQL-003",
    category: "sql_injection",
    severity: "high",
    title: "Raw SQL query with potential injection",
    description: "Direct use of raw SQL queries without parameterization detected.",
    pattern: /\.raw\s*\(\s*`[^`]*\$\{/gi,
    languages: ["typescript", "javascript"],
    cweId: "CWE-89",
    owaspCategory: "A03:2021-Injection",
    remediation: "Use the ORM query builder or parameterized raw queries.",
    confidence: 0.8,
  },

  // XSS
  {
    id: "SAST-XSS-001",
    category: "xss",
    severity: "high",
    title: "Cross-Site Scripting via innerHTML",
    description: "Setting innerHTML with dynamic content can lead to XSS attacks.",
    pattern: /\.innerHTML\s*=\s*(?!['"][^'"]*['"])/gi,
    languages: ["typescript", "javascript"],
    cweId: "CWE-79",
    owaspCategory: "A03:2021-Injection",
    remediation: "Use textContent instead of innerHTML, or sanitize input with DOMPurify.",
    confidence: 0.85,
  },
  {
    id: "SAST-XSS-002",
    category: "xss",
    severity: "high",
    title: "Cross-Site Scripting via dangerouslySetInnerHTML",
    description: "React dangerouslySetInnerHTML bypasses XSS protection.",
    pattern: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/gi,
    languages: ["typescript", "javascript", "tsx", "jsx"],
    cweId: "CWE-79",
    owaspCategory: "A03:2021-Injection",
    remediation: "Sanitize HTML content with DOMPurify before using dangerouslySetInnerHTML.",
    confidence: 0.75,
  },
  {
    id: "SAST-XSS-003",
    category: "xss",
    severity: "medium",
    title: "Unescaped output in template literal",
    description: "User input inserted into HTML template without escaping.",
    pattern: /(?:res\.send|res\.write)\s*\(\s*`[^`]*\$\{.*\}[^`]*`\s*\)/gi,
    languages: ["typescript", "javascript"],
    cweId: "CWE-79",
    owaspCategory: "A03:2021-Injection",
    remediation: "Use a template engine with auto-escaping or escape user input before output.",
    confidence: 0.7,
  },

  // Path Traversal
  {
    id: "SAST-PATH-001",
    category: "path_traversal",
    severity: "high",
    title: "Path Traversal via user-controlled path",
    description: "File path constructed with user input without validation, enabling directory traversal attacks.",
    pattern: /(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync)\s*\(\s*(?:req\.|params\.|query\.)/gi,
    languages: ["typescript", "javascript"],
    cweId: "CWE-22",
    owaspCategory: "A01:2021-Broken Access Control",
    remediation:
      "Validate and sanitize file paths. Use path.resolve() and verify the resolved path is within allowed directories.",
    confidence: 0.85,
  },
  {
    id: "SAST-PATH-002",
    category: "path_traversal",
    severity: "high",
    title: "Path Traversal via path.join with user input",
    description: "path.join with user-controlled input can be exploited with ../ sequences.",
    pattern: /path\.join\s*\([^)]*(?:req\.|params\.|query\.|body\.)/gi,
    languages: ["typescript", "javascript"],
    cweId: "CWE-22",
    owaspCategory: "A01:2021-Broken Access Control",
    remediation: "Validate the final resolved path starts with the expected base directory.",
    confidence: 0.8,
  },

  // Command Injection
  {
    id: "SAST-CMD-001",
    category: "command_injection",
    severity: "critical",
    title: "Command Injection via exec/spawn",
    description: "System command execution with user-controlled input enables command injection.",
    pattern: /(?:exec|execSync|spawn|spawnSync)\s*\(\s*(?:`[^`]*\$\{|[^,)]*\+\s*(?:req\.|params\.|query\.|body\.))/gi,
    languages: ["typescript", "javascript"],
    cweId: "CWE-78",
    owaspCategory: "A03:2021-Injection",
    remediation:
      "Use execFile/execFileSync with argument arrays instead of shell commands. Never pass user input to shell commands.",
    confidence: 0.9,
  },
  {
    id: "SAST-CMD-002",
    category: "command_injection",
    severity: "critical",
    title: "Shell command with user input",
    description: "Child process execution with interpolated user data.",
    pattern: /child_process.*(?:exec|spawn)\s*\([^)]*(?:\$\{|req\.|params\.)/gi,
    languages: ["typescript", "javascript"],
    cweId: "CWE-78",
    owaspCategory: "A03:2021-Injection",
    remediation: "Avoid shell execution. Use spawn with argument arrays and {shell: false}.",
    confidence: 0.85,
  },

  // SSRF
  {
    id: "SAST-SSRF-001",
    category: "ssrf",
    severity: "high",
    title: "Server-Side Request Forgery",
    description: "HTTP request made to a URL derived from user input, enabling SSRF attacks.",
    pattern: /(?:fetch|axios|got|request|http\.get|https\.get)\s*\(\s*(?:req\.|params\.|query\.|body\.)/gi,
    languages: ["typescript", "javascript"],
    cweId: "CWE-918",
    owaspCategory: "A10:2021-Server-Side Request Forgery",
    remediation: "Validate and allowlist target URLs. Block requests to internal/private IP ranges.",
    confidence: 0.8,
  },

  // Weak Crypto
  {
    id: "SAST-CRYPTO-001",
    category: "weak_crypto",
    severity: "medium",
    title: "Weak cryptographic algorithm (MD5)",
    description: "MD5 is cryptographically broken and should not be used for security purposes.",
    pattern: /createHash\s*\(\s*['"]md5['"]\s*\)/gi,
    languages: ["typescript", "javascript"],
    cweId: "CWE-328",
    owaspCategory: "A02:2021-Cryptographic Failures",
    remediation: "Use SHA-256 or stronger hash algorithms for security-sensitive operations.",
    confidence: 0.95,
  },
  {
    id: "SAST-CRYPTO-002",
    category: "weak_crypto",
    severity: "medium",
    title: "Weak cryptographic algorithm (SHA-1)",
    description: "SHA-1 has known collision attacks and should be replaced with SHA-256+.",
    pattern: /createHash\s*\(\s*['"]sha1['"]\s*\)/gi,
    languages: ["typescript", "javascript"],
    cweId: "CWE-328",
    owaspCategory: "A02:2021-Cryptographic Failures",
    remediation: "Use SHA-256 or SHA-3 for cryptographic hashing.",
    confidence: 0.9,
  },

  // XXE
  {
    id: "SAST-XXE-001",
    category: "xxe",
    severity: "high",
    title: "XML External Entity (XXE) Processing",
    description: "XML parser without disabled external entities can lead to XXE attacks.",
    pattern: /(?:parseXml|xml2js|DOMParser|xmldom).*(?:parse|parseString)\s*\(/gi,
    languages: ["typescript", "javascript"],
    cweId: "CWE-611",
    owaspCategory: "A05:2021-Security Misconfiguration",
    remediation: "Disable external entity processing in XML parsers. Use {noent: false, dtd: false}.",
    confidence: 0.7,
  },

  // Open Redirect
  {
    id: "SAST-REDIR-001",
    category: "open_redirect",
    severity: "medium",
    title: "Open Redirect via user-controlled URL",
    description: "Redirect target derived from user input enables phishing via open redirects.",
    pattern: /res\.redirect\s*\(\s*(?:req\.|params\.|query\.|body\.)/gi,
    languages: ["typescript", "javascript"],
    cweId: "CWE-601",
    owaspCategory: "A01:2021-Broken Access Control",
    remediation: "Validate redirect URLs against an allowlist of permitted domains.",
    confidence: 0.85,
  },

  // Missing Auth
  {
    id: "SAST-AUTH-001",
    category: "missing_auth",
    severity: "high",
    title: "Sensitive endpoint without authentication middleware",
    description: "API endpoint handling sensitive data does not appear to have authentication middleware.",
    pattern:
      /app\.(?:post|put|patch|delete)\s*\(\s*['"][^'"]*(?:admin|user|setting|config|secret)[^'"]*['"]\s*,\s*(?:async\s*)?\(\s*req/gi,
    languages: ["typescript", "javascript"],
    cweId: "CWE-306",
    owaspCategory: "A07:2021-Identification and Authentication Failures",
    remediation: "Add authentication middleware (e.g., requireAuth) before the route handler.",
    confidence: 0.6,
  },

  // Prototype Pollution
  {
    id: "SAST-PROTO-001",
    category: "prototype_pollution",
    severity: "high",
    title: "Prototype Pollution via object merge",
    description: "Deep object merge with user-controlled input can lead to prototype pollution.",
    pattern: /(?:Object\.assign|_\.merge|_\.extend|deepmerge)\s*\(\s*\{\s*\}\s*,\s*(?:req\.|params\.|query\.|body\.)/gi,
    languages: ["typescript", "javascript"],
    cweId: "CWE-1321",
    owaspCategory: "A03:2021-Injection",
    remediation: "Use a safe merge function that filters __proto__, constructor, and prototype keys.",
    confidence: 0.75,
  },

  // ReDoS
  {
    id: "SAST-REDOS-001",
    category: "regex_dos",
    severity: "medium",
    title: "Potential ReDoS via user-controlled regex",
    description: "Regular expression constructed from user input can cause catastrophic backtracking.",
    pattern: /new\s+RegExp\s*\(\s*(?:req\.|params\.|query\.|body\.)/gi,
    languages: ["typescript", "javascript"],
    cweId: "CWE-1333",
    owaspCategory: "A03:2021-Injection",
    remediation: "Sanitize user input before using in regex, or use a regex timeout library.",
    confidence: 0.8,
  },

  // Insecure Deserialization
  {
    id: "SAST-DESER-001",
    category: "insecure_deserialization",
    severity: "high",
    title: "Unsafe deserialization of user input",
    description: "Deserializing untrusted data can lead to remote code execution.",
    pattern: /(?:eval|Function)\s*\(\s*(?:req\.|params\.|query\.|body\.|JSON\.parse\s*\(\s*req\.)/gi,
    languages: ["typescript", "javascript"],
    cweId: "CWE-502",
    owaspCategory: "A08:2021-Software and Data Integrity Failures",
    remediation: "Never use eval() or Function() with user input. Use JSON.parse with validation.",
    confidence: 0.9,
  },

  // IDOR
  {
    id: "SAST-IDOR-001",
    category: "idor",
    severity: "high",
    title: "Insecure Direct Object Reference",
    description: "Resource accessed by user-supplied ID without ownership verification.",
    pattern: /findById\s*\(\s*(?:req\.params\.|req\.query\.)\w+\s*\)(?!.*(?:orgId|userId|owner|auth))/gi,
    languages: ["typescript", "javascript"],
    cweId: "CWE-639",
    owaspCategory: "A01:2021-Broken Access Control",
    remediation: "Always verify the requesting user has ownership/access to the resource.",
    confidence: 0.6,
  },
];

// ── Secret Detection Patterns ──────────────────────────────────────

interface SecretPattern {
  type: string;
  pattern: RegExp;
  severity: "critical" | "high";
}

const SECRET_PATTERNS: SecretPattern[] = [
  { type: "aws_access_key", pattern: /(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}/g, severity: "critical" },
  {
    type: "aws_secret_key",
    pattern: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/g,
    severity: "critical",
  },
  {
    type: "github_token",
    pattern: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/g,
    severity: "critical",
  },
  {
    type: "gitlab_token",
    pattern: /glpat-[A-Za-z0-9\-_]{20,}/g,
    severity: "critical",
  },
  {
    type: "private_key",
    pattern: /-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----/g,
    severity: "critical",
  },
  {
    type: "jwt_secret",
    pattern: /(?:jwt_secret|JWT_SECRET|jwt_key|JWT_KEY)\s*[=:]\s*['"]([^'"]{8,})['"]/gi,
    severity: "critical",
  },
  {
    type: "database_url",
    pattern: /(?:postgres|mysql|mongodb|redis):\/\/[^:]+:[^@]+@[^/\s]+/gi,
    severity: "critical",
  },
  {
    type: "stripe_key",
    pattern: /(?:sk_live|rk_live)_[A-Za-z0-9]{24,}/g,
    severity: "critical",
  },
  {
    type: "slack_token",
    pattern: /xox[bpors]-[0-9]+-[0-9]+-[A-Za-z0-9]+/g,
    severity: "high",
  },
  {
    type: "sendgrid_key",
    pattern: /SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/g,
    severity: "high",
  },
  {
    type: "twilio_key",
    pattern: /SK[0-9a-fA-F]{32}/g,
    severity: "high",
  },
  {
    type: "api_key",
    pattern: /(?:api_key|apikey|API_KEY|APIKEY)\s*[=:]\s*['"]([A-Za-z0-9\-_]{16,})['"]/gi,
    severity: "high",
  },
  {
    type: "generic_password",
    pattern: /(?:password|passwd|pwd)\s*[=:]\s*['"]([^'"]{8,})['"]/gi,
    severity: "high",
  },
  {
    type: "generic_secret",
    pattern: /(?:secret|SECRET|token|TOKEN)\s*[=:]\s*['"]([A-Za-z0-9\-_+=/.]{16,})['"]/gi,
    severity: "high",
  },
  {
    type: "oauth_secret",
    pattern: /(?:client_secret|CLIENT_SECRET|oauth_secret)\s*[=:]\s*['"]([^'"]{8,})['"]/gi,
    severity: "critical",
  },
];

// ── Scan Functions ─────────────────────────────────────────────────

/**
 * Scan source code content for SAST findings
 */
export function scanCode(content: string, filePath: string, language: string): SastFindingResult[] {
  const findings: SastFindingResult[] = [];
  const lines = content.split("\n");

  for (const rule of SAST_RULES) {
    if (!rule.languages.includes(language)) continue;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      // Reset regex lastIndex for global patterns
      rule.pattern.lastIndex = 0;
      if (rule.pattern.test(line)) {
        const snippetStart = Math.max(0, i - 2);
        const snippetEnd = Math.min(lines.length - 1, i + 2);
        const codeSnippet = lines.slice(snippetStart, snippetEnd + 1).join("\n");

        findings.push({
          ruleId: rule.id,
          category: rule.category,
          severity: rule.severity,
          title: rule.title,
          description: rule.description,
          remediation: rule.remediation,
          filePath,
          startLine: i + 1,
          endLine: i + 1,
          codeSnippet,
          cweId: rule.cweId,
          owaspCategory: rule.owaspCategory,
          confidence: rule.confidence,
        });
      }
    }
  }

  return findings;
}

/**
 * Scan source code content for exposed secrets
 */
export function scanSecrets(content: string, filePath: string): SecretFindingResult[] {
  const findings: SecretFindingResult[] = [];
  const lines = content.split("\n");

  // Skip known safe files
  const safePaths = [".example", ".sample", ".template", "test", "mock", "fixture", "__test__"];
  if (safePaths.some((safe) => filePath.toLowerCase().includes(safe))) {
    return findings;
  }

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // Skip comments
    if (line.trim().startsWith("//") || line.trim().startsWith("#") || line.trim().startsWith("*")) {
      continue;
    }

    for (const pattern of SECRET_PATTERNS) {
      pattern.pattern.lastIndex = 0;
      const match = pattern.pattern.exec(line);
      if (match) {
        const rawValue = match[1] || match[0];
        // Skip placeholder values
        if (isPlaceholder(rawValue)) continue;

        const hash = crypto.createHash("sha256").update(rawValue).digest("hex").substring(0, 16);
        const masked = maskSecret(rawValue);

        findings.push({
          secretType: pattern.type,
          filePath,
          line: i + 1,
          maskedValue: masked,
          severity: pattern.severity,
          secretHash: hash,
        });
      }
    }
  }

  return findings;
}

/**
 * Run a full SAST scan on a set of files
 */
export function runSastScan(
  files: { path: string; content: string; language: string }[],
  repository: string,
  branch: string,
  commitSha: string,
): SastScanResult {
  const startTime = Date.now();
  const scanId = crypto.randomUUID();
  let linesScanned = 0;

  const allFindings: SastFindingResult[] = [];
  const allSecrets: SecretFindingResult[] = [];

  for (const file of files) {
    linesScanned += file.content.split("\n").length;

    const codeFindings = scanCode(file.content, file.path, file.language);
    allFindings.push(...codeFindings);

    const secretFindings = scanSecrets(file.content, file.path);
    allSecrets.push(...secretFindings);
  }

  // Deduplicate secrets by hash
  const seenHashes = new Set<string>();
  const uniqueSecrets = allSecrets.filter((s) => {
    if (seenHashes.has(s.secretHash)) return false;
    seenHashes.add(s.secretHash);
    return true;
  });

  const scanDurationMs = Date.now() - startTime;

  log.info("SAST scan complete", {
    scanId,
    repository,
    findings: allFindings.length,
    secrets: uniqueSecrets.length,
    filesScanned: files.length,
    durationMs: scanDurationMs,
  });

  return {
    scanId,
    repository,
    branch,
    commitSha,
    findings: allFindings,
    secretFindings: uniqueSecrets,
    scanDurationMs,
    filesScanned: files.length,
    linesScanned,
  };
}

/**
 * Evaluate CI gate policy against scan results
 */
export function evaluateCiGate(scanResult: SastScanResult, policy: CiGatePolicy): CiGateEvaluation {
  const failureReasons: string[] = [];

  const critCount = scanResult.findings.filter((f) => f.severity === "critical").length;
  const highCount = scanResult.findings.filter((f) => f.severity === "high").length;
  const mediumCount = scanResult.findings.filter((f) => f.severity === "medium").length;
  const lowCount = scanResult.findings.filter((f) => f.severity === "low").length;

  if (policy.maxCritical !== undefined && critCount > policy.maxCritical) {
    failureReasons.push(`Critical findings (${critCount}) exceed threshold (${policy.maxCritical})`);
  }
  if (policy.maxHigh !== undefined && highCount > policy.maxHigh) {
    failureReasons.push(`High findings (${highCount}) exceed threshold (${policy.maxHigh})`);
  }
  if (policy.maxMedium !== undefined && mediumCount > policy.maxMedium) {
    failureReasons.push(`Medium findings (${mediumCount}) exceed threshold (${policy.maxMedium})`);
  }
  if (policy.blockOnSecrets && scanResult.secretFindings.length > 0) {
    failureReasons.push(`${scanResult.secretFindings.length} exposed secret(s) detected`);
  }

  const status: "passed" | "failed" | "warning" =
    failureReasons.length > 0 ? "failed" : critCount > 0 || highCount > 0 ? "warning" : "passed";

  return {
    status,
    criticalFindings: critCount,
    highFindings: highCount,
    mediumFindings: mediumCount,
    lowFindings: lowCount,
    secretsFound: scanResult.secretFindings.length,
    policyViolations: failureReasons.length,
    failureReasons,
  };
}

export interface CiGatePolicy {
  maxCritical?: number;
  maxHigh?: number;
  maxMedium?: number;
  blockOnSecrets: boolean;
}

export interface CiGateEvaluation {
  status: "passed" | "failed" | "warning";
  criticalFindings: number;
  highFindings: number;
  mediumFindings: number;
  lowFindings: number;
  secretsFound: number;
  policyViolations: number;
  failureReasons: string[];
}

/**
 * Get all available SAST rules
 */
export function getSastRules(): SastRule[] {
  return SAST_RULES.map((r) => ({
    ...r,
    pattern: r.pattern, // convert to serializable form if needed
  }));
}

/**
 * Infer language from file extension
 */
export function inferLanguage(filePath: string): string | null {
  const ext = filePath.split(".").pop()?.toLowerCase();
  const langMap: Record<string, string> = {
    ts: "typescript",
    tsx: "tsx",
    js: "javascript",
    jsx: "jsx",
    py: "python",
    java: "java",
    go: "go",
    rb: "ruby",
    php: "php",
    cs: "csharp",
    rs: "rust",
  };
  return ext ? langMap[ext] || null : null;
}

// ── Helpers ────────────────────────────────────────────────────────

function isPlaceholder(value: string): boolean {
  const placeholders = [
    "your_",
    "xxx",
    "placeholder",
    "example",
    "CHANGEME",
    "change_me",
    "replace_me",
    "todo",
    "TODO",
    "INSERT_",
    "ENTER_",
    "<your",
    "${",
    "{{",
  ];
  return placeholders.some((p) => value.includes(p));
}

function maskSecret(value: string): string {
  if (value.length <= 8) return "***";
  return value.substring(0, 4) + "..." + value.substring(value.length - 4);
}
