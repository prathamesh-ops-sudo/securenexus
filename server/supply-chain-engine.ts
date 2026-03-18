/**
 * Supply Chain Security Engine
 *
 * Handles SBOM parsing (CycloneDX / SPDX), dependency graph construction,
 * typosquatting detection, maintainer reputation scoring, IaC scanning,
 * container layer analysis, and provenance verification.
 */

import { db } from "./db";
import { eq, and, sql } from "drizzle-orm";
import { sbomArtifacts, dependencyGraph, supplyChainFindings, vulnFindings } from "../shared/schema";

// ─── Known-Good Package Registries ──────────────────────────────────────────

interface PopularPackage {
  name: string;
  ecosystem: string;
  minDownloads: number;
}

const POPULAR_PACKAGES: PopularPackage[] = [
  // npm
  { name: "lodash", ecosystem: "npm", minDownloads: 50_000_000 },
  { name: "express", ecosystem: "npm", minDownloads: 30_000_000 },
  { name: "react", ecosystem: "npm", minDownloads: 20_000_000 },
  { name: "axios", ecosystem: "npm", minDownloads: 40_000_000 },
  { name: "webpack", ecosystem: "npm", minDownloads: 20_000_000 },
  { name: "typescript", ecosystem: "npm", minDownloads: 40_000_000 },
  { name: "moment", ecosystem: "npm", minDownloads: 15_000_000 },
  { name: "chalk", ecosystem: "npm", minDownloads: 80_000_000 },
  { name: "commander", ecosystem: "npm", minDownloads: 70_000_000 },
  { name: "debug", ecosystem: "npm", minDownloads: 100_000_000 },
  { name: "uuid", ecosystem: "npm", minDownloads: 60_000_000 },
  { name: "dotenv", ecosystem: "npm", minDownloads: 30_000_000 },
  { name: "cors", ecosystem: "npm", minDownloads: 10_000_000 },
  { name: "jsonwebtoken", ecosystem: "npm", minDownloads: 15_000_000 },
  { name: "bcrypt", ecosystem: "npm", minDownloads: 5_000_000 },
  { name: "socket.io", ecosystem: "npm", minDownloads: 5_000_000 },
  { name: "next", ecosystem: "npm", minDownloads: 5_000_000 },
  { name: "vue", ecosystem: "npm", minDownloads: 5_000_000 },
  { name: "angular", ecosystem: "npm", minDownloads: 3_000_000 },
  // pypi
  { name: "requests", ecosystem: "pypi", minDownloads: 200_000_000 },
  { name: "numpy", ecosystem: "pypi", minDownloads: 150_000_000 },
  { name: "pandas", ecosystem: "pypi", minDownloads: 100_000_000 },
  { name: "flask", ecosystem: "pypi", minDownloads: 30_000_000 },
  { name: "django", ecosystem: "pypi", minDownloads: 20_000_000 },
  { name: "boto3", ecosystem: "pypi", minDownloads: 80_000_000 },
  { name: "cryptography", ecosystem: "pypi", minDownloads: 50_000_000 },
  { name: "pillow", ecosystem: "pypi", minDownloads: 30_000_000 },
  { name: "setuptools", ecosystem: "pypi", minDownloads: 200_000_000 },
  { name: "pip", ecosystem: "pypi", minDownloads: 300_000_000 },
  // rubygems
  { name: "rails", ecosystem: "rubygems", minDownloads: 300_000_000 },
  { name: "rake", ecosystem: "rubygems", minDownloads: 500_000_000 },
  { name: "bundler", ecosystem: "rubygems", minDownloads: 500_000_000 },
  { name: "nokogiri", ecosystem: "rubygems", minDownloads: 300_000_000 },
  // nuget
  { name: "Newtonsoft.Json", ecosystem: "nuget", minDownloads: 1_000_000_000 },
  { name: "Serilog", ecosystem: "nuget", minDownloads: 200_000_000 },
  { name: "AutoMapper", ecosystem: "nuget", minDownloads: 150_000_000 },
];

// ─── CVE Database for Supply Chain ──────────────────────────────────────────

interface SupplyChainCve {
  cveId: string;
  packageName: string;
  ecosystems: string[];
  vulnerablePattern: RegExp;
  fixedVersion: string;
  severity: string;
  cvssScore: number;
  description: string;
}

const SUPPLY_CHAIN_CVES: SupplyChainCve[] = [
  {
    cveId: "CVE-2021-44228",
    packageName: "log4j-core",
    ecosystems: ["maven", "npm", "pypi"],
    vulnerablePattern: /^2\.(0|1|2|3|4|5|6|7|8|9|10|11|12|13|14)(\.|$)/,
    fixedVersion: "2.17.1",
    severity: "critical",
    cvssScore: 10.0,
    description: "Log4Shell — Remote Code Execution via JNDI lookup in log messages",
  },
  {
    cveId: "CVE-2021-45046",
    packageName: "log4j-core",
    ecosystems: ["maven", "npm", "pypi"],
    vulnerablePattern: /^2\.(0|1|2|3|4|5|6|7|8|9|10|11|12|13|14|15)(\.|$)/,
    fixedVersion: "2.17.0",
    severity: "critical",
    cvssScore: 9.0,
    description: "Log4j2 — Thread Context lookup pattern allows RCE in non-default configs",
  },
  {
    cveId: "CVE-2023-44487",
    packageName: "nghttp2",
    ecosystems: ["npm", "pypi", "cargo"],
    vulnerablePattern: /^1\.(5[0-6]|[0-4][0-9]?)\./,
    fixedVersion: "1.57.0",
    severity: "high",
    cvssScore: 7.5,
    description: "HTTP/2 Rapid Reset — DoS attack via stream cancellation",
  },
  {
    cveId: "CVE-2022-22965",
    packageName: "spring-core",
    ecosystems: ["maven"],
    vulnerablePattern: /^5\.3\.(0|1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17)(\.|$)/,
    fixedVersion: "5.3.18",
    severity: "critical",
    cvssScore: 9.8,
    description: "Spring4Shell — RCE via data binding to Java class loader",
  },
  {
    cveId: "CVE-2024-3094",
    packageName: "xz-utils",
    ecosystems: ["npm", "pypi", "cargo"],
    vulnerablePattern: /^5\.6\.(0|1)$/,
    fixedVersion: "5.6.2",
    severity: "critical",
    cvssScore: 10.0,
    description: "XZ Utils backdoor — Supply chain compromise allowing unauthorized SSH access",
  },
  {
    cveId: "CVE-2023-32681",
    packageName: "requests",
    ecosystems: ["pypi"],
    vulnerablePattern: /^2\.(2[0-9]|3[01])\./,
    fixedVersion: "2.31.0",
    severity: "medium",
    cvssScore: 6.1,
    description: "Python Requests — Unintended Proxy-Authorization header leak",
  },
  {
    cveId: "CVE-2022-42889",
    packageName: "commons-text",
    ecosystems: ["maven"],
    vulnerablePattern: /^1\.(([0-9])(\.|$))/,
    fixedVersion: "1.10.0",
    severity: "critical",
    cvssScore: 9.8,
    description: "Apache Commons Text — RCE via StringSubstitutor interpolation (Text4Shell)",
  },
  {
    cveId: "CVE-2021-3749",
    packageName: "axios",
    ecosystems: ["npm"],
    vulnerablePattern: /^0\.(2[01])\./,
    fixedVersion: "0.21.2",
    severity: "high",
    cvssScore: 7.5,
    description: "Axios — ReDoS via inefficient regex in trim function",
  },
  {
    cveId: "CVE-2022-0155",
    packageName: "follow-redirects",
    ecosystems: ["npm"],
    vulnerablePattern: /^1\.14\.[0-7]$/,
    fixedVersion: "1.14.8",
    severity: "medium",
    cvssScore: 6.5,
    description: "follow-redirects — Exposure of sensitive data via cookie forwarding",
  },
  {
    cveId: "CVE-2023-26136",
    packageName: "tough-cookie",
    ecosystems: ["npm"],
    vulnerablePattern: /^4\.1\.[0-2]$/,
    fixedVersion: "4.1.3",
    severity: "medium",
    cvssScore: 6.5,
    description: "tough-cookie — Prototype pollution via cookie parsing",
  },
  {
    cveId: "CVE-2022-25883",
    packageName: "semver",
    ecosystems: ["npm"],
    vulnerablePattern: /^7\.[0-4]\./,
    fixedVersion: "7.5.2",
    severity: "medium",
    cvssScore: 5.3,
    description: "semver — ReDoS via untrusted version strings",
  },
  {
    cveId: "CVE-2023-45133",
    packageName: "@babel/traverse",
    ecosystems: ["npm"],
    vulnerablePattern: /^7\.(([0-9]|1[0-9]|2[0-2])\.|23\.[0-1])/,
    fixedVersion: "7.23.2",
    severity: "critical",
    cvssScore: 9.8,
    description: "Babel — Arbitrary code execution during code compilation",
  },
];

// ─── IaC Misconfiguration Rules ─────────────────────────────────────────────

interface IacRule {
  id: string;
  title: string;
  description: string;
  severity: string;
  ecosystem: string;
  pattern: RegExp;
  resourceType: string;
}

const IAC_RULES: IacRule[] = [
  {
    id: "IAC-TF-001",
    title: "S3 bucket with public ACL",
    description: "S3 bucket allows public access via ACL — data exposure risk",
    severity: "critical",
    ecosystem: "terraform",
    pattern: /acl\s*=\s*"public-read"|acl\s*=\s*"public-read-write"/,
    resourceType: "aws_s3_bucket",
  },
  {
    id: "IAC-TF-002",
    title: "Security group allows unrestricted ingress",
    description: "Ingress rule allows 0.0.0.0/0 — the entire internet can reach this resource",
    severity: "high",
    ecosystem: "terraform",
    pattern: /cidr_blocks\s*=\s*\[?"0\.0\.0\.0\/0"\]?/,
    resourceType: "aws_security_group",
  },
  {
    id: "IAC-TF-003",
    title: "RDS instance without encryption",
    description: "RDS instance does not have storage encryption enabled",
    severity: "high",
    ecosystem: "terraform",
    pattern: /storage_encrypted\s*=\s*false/,
    resourceType: "aws_db_instance",
  },
  {
    id: "IAC-TF-004",
    title: "IAM policy with wildcard permissions",
    description: "IAM policy uses Action: * or Resource: * — overly permissive",
    severity: "critical",
    ecosystem: "terraform",
    pattern: /"Action"\s*:\s*"\*"|"Resource"\s*:\s*"\*"/,
    resourceType: "aws_iam_policy",
  },
  {
    id: "IAC-TF-005",
    title: "CloudTrail logging disabled",
    description: "CloudTrail is not enabled or multi-region logging is disabled",
    severity: "high",
    ecosystem: "terraform",
    pattern: /is_multi_region_trail\s*=\s*false|enable_logging\s*=\s*false/,
    resourceType: "aws_cloudtrail",
  },
  {
    id: "IAC-K8S-001",
    title: "Container running as root",
    description: "Pod spec does not set runAsNonRoot: true — container may run as UID 0",
    severity: "high",
    ecosystem: "kubernetes",
    pattern: /runAsNonRoot:\s*false|privileged:\s*true/,
    resourceType: "Pod/Deployment",
  },
  {
    id: "IAC-K8S-002",
    title: "Container with hostNetwork access",
    description: "Pod uses hostNetwork: true — bypasses network policies",
    severity: "critical",
    ecosystem: "kubernetes",
    pattern: /hostNetwork:\s*true/,
    resourceType: "Pod/Deployment",
  },
  {
    id: "IAC-K8S-003",
    title: "No resource limits set",
    description: "Container has no CPU/memory limits — DoS risk via resource exhaustion",
    severity: "medium",
    ecosystem: "kubernetes",
    pattern: /resources:\s*\{\}/,
    resourceType: "Pod/Deployment",
  },
  {
    id: "IAC-K8S-004",
    title: "Secret mounted as environment variable",
    description: "Secrets exposed as env vars can leak via process listing or crash dumps",
    severity: "medium",
    ecosystem: "kubernetes",
    pattern: /secretKeyRef:/,
    resourceType: "Pod/Deployment",
  },
  {
    id: "IAC-HELM-001",
    title: "Helm chart uses latest tag",
    description: "Image tag set to 'latest' — non-deterministic deployments",
    severity: "medium",
    ecosystem: "helm",
    pattern: /tag:\s*["']?latest["']?/,
    resourceType: "Deployment",
  },
  {
    id: "IAC-HELM-002",
    title: "Helm chart disables TLS",
    description: "TLS/SSL is explicitly disabled in Helm values",
    severity: "high",
    ecosystem: "helm",
    pattern: /tls:\s*\n\s*enabled:\s*false/,
    resourceType: "Ingress/Service",
  },
  {
    id: "IAC-DOCKER-001",
    title: "Dockerfile uses root user",
    description: "No USER directive — container runs as root by default",
    severity: "high",
    ecosystem: "docker",
    pattern: /^FROM\s+(?!scratch).*(?!\nUSER\s+)/m,
    resourceType: "Dockerfile",
  },
  {
    id: "IAC-DOCKER-002",
    title: "Dockerfile copies secrets",
    description: "COPY or ADD instruction may include .env or credential files",
    severity: "critical",
    ecosystem: "docker",
    pattern: /COPY\s+.*\.(env|pem|key|p12|pfx)|ADD\s+.*\.(env|pem|key|p12|pfx)/,
    resourceType: "Dockerfile",
  },
];

// ─── Risky License Patterns ─────────────────────────────────────────────────

const RISKY_LICENSES = [
  "AGPL-3.0",
  "AGPL-3.0-only",
  "AGPL-3.0-or-later",
  "GPL-3.0",
  "GPL-3.0-only",
  "GPL-3.0-or-later",
  "SSPL-1.0",
  "EUPL-1.2",
  "CPAL-1.0",
  "OSL-3.0",
  "RPSL-1.0",
  "Sleepycat",
  "Watcom-1.0",
];

const COPYLEFT_LICENSES = [
  "GPL-2.0",
  "GPL-2.0-only",
  "GPL-2.0-or-later",
  "LGPL-2.1",
  "LGPL-3.0",
  "MPL-2.0",
  "EPL-2.0",
  "CDDL-1.0",
  "CPL-1.0",
];

// ─── Typosquatting Detection ────────────────────────────────────────────────

function levenshteinDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1] ? dp[i - 1][j - 1] : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

/**
 * Check if a package name might be a typosquatting attempt.
 * Returns the legitimate package it's closest to, if any.
 */
export function detectTyposquatting(
  packageName: string,
  ecosystem: string,
): { isSuspicious: boolean; similarTo: string | null; distance: number } {
  const popularInEcosystem = POPULAR_PACKAGES.filter((p) => p.ecosystem === ecosystem);
  let bestMatch: string | null = null;
  let bestDistance = Infinity;

  const nameLower = packageName.toLowerCase();

  for (const pop of popularInEcosystem) {
    const popLower = pop.name.toLowerCase();
    if (nameLower === popLower) {
      return { isSuspicious: false, similarTo: null, distance: 0 };
    }

    const distance = levenshteinDistance(nameLower, popLower);
    const maxLen = Math.max(nameLower.length, popLower.length);

    // Only flag if edit distance is 1-2 and the name is somewhat long
    if (distance <= 2 && maxLen >= 4 && distance < bestDistance) {
      bestDistance = distance;
      bestMatch = pop.name;
    }
  }

  // Also check for common typosquatting patterns
  for (const pop of popularInEcosystem) {
    const popLower = pop.name.toLowerCase();
    // Check for hyphen/underscore swaps
    if (nameLower.replace(/[-_]/g, "") === popLower.replace(/[-_]/g, "") && nameLower !== popLower) {
      return { isSuspicious: true, similarTo: pop.name, distance: 1 };
    }
    // Check for scope confusion (@scoped/pkg vs scoped-pkg)
    if (
      nameLower.replace(/^@[^/]+\//, "").replace(/[-_]/g, "") === popLower.replace(/[-_]/g, "") &&
      nameLower !== popLower
    ) {
      return { isSuspicious: true, similarTo: pop.name, distance: 1 };
    }
  }

  if (bestMatch && bestDistance <= 2) {
    return { isSuspicious: true, similarTo: bestMatch, distance: bestDistance };
  }

  return { isSuspicious: false, similarTo: null, distance: 0 };
}

// ─── Maintainer Reputation Scoring ──────────────────────────────────────────

export interface MaintainerReputation {
  score: number; // 0-100
  isNewPublisher: boolean;
  isRecentTransfer: boolean;
  isLowDownloads: boolean;
  flags: string[];
}

export function scoreMaintainerReputation(
  packageName: string,
  ecosystem: string,
  publisher: string | null,
  publishDate: Date | null,
): MaintainerReputation {
  const flags: string[] = [];
  let score = 100;

  // Check if it's a well-known package
  const isKnown = POPULAR_PACKAGES.some(
    (p) => p.name.toLowerCase() === packageName.toLowerCase() && p.ecosystem === ecosystem,
  );

  if (isKnown) {
    return { score: 100, isNewPublisher: false, isRecentTransfer: false, isLowDownloads: false, flags: [] };
  }

  // New publisher check — accounts < 30 days old publishing packages
  const isNew = !publisher || publisher.length < 3;
  if (isNew) {
    score -= 30;
    flags.push("Unknown or missing publisher information");
  }

  // Recent publish date heuristic (< 7 days since publish = higher risk)
  if (publishDate) {
    const daysSincePublish = (Date.now() - publishDate.getTime()) / (1000 * 60 * 60 * 24);
    if (daysSincePublish < 7) {
      score -= 20;
      flags.push(`Published only ${Math.round(daysSincePublish)} days ago`);
    }
  }

  // Suspicious package name patterns
  if (
    packageName.includes("test") ||
    packageName.includes("debug") ||
    packageName.includes("poc") ||
    packageName.includes("exploit")
  ) {
    score -= 15;
    flags.push("Package name contains suspicious keywords");
  }

  // Very short name (< 3 chars) for npm/pypi
  if (packageName.length < 3 && (ecosystem === "npm" || ecosystem === "pypi")) {
    score -= 10;
    flags.push("Suspiciously short package name");
  }

  return {
    score: Math.max(0, score),
    isNewPublisher: isNew,
    isRecentTransfer: false,
    isLowDownloads: true,
    flags,
  };
}

// ─── CycloneDX Parser ───────────────────────────────────────────────────────

interface CycloneDxComponent {
  type: string;
  name: string;
  version: string;
  purl?: string;
  group?: string;
  publisher?: string;
  licenses?: Array<{ license?: { id?: string; name?: string } }>;
  externalReferences?: Array<{ type: string; url: string }>;
  scope?: string; // "required" | "optional"
}

interface CycloneDxBom {
  bomFormat?: string;
  specVersion?: string;
  serialNumber?: string;
  version?: number;
  metadata?: {
    timestamp?: string;
    tools?: Array<{ name: string; version?: string }>;
    component?: CycloneDxComponent;
  };
  components?: CycloneDxComponent[];
  dependencies?: Array<{ ref: string; dependsOn?: string[] }>;
}

// ─── SPDX Parser ────────────────────────────────────────────────────────────

interface SpdxPackage {
  SPDXID: string;
  name: string;
  versionInfo?: string;
  supplier?: string;
  downloadLocation?: string;
  licenseConcluded?: string;
  licenseDeclared?: string;
  externalRefs?: Array<{ referenceType: string; referenceLocator: string }>;
}

interface SpdxDocument {
  spdxVersion?: string;
  documentNamespace?: string;
  name?: string;
  creationInfo?: { created?: string; creators?: string[] };
  packages?: SpdxPackage[];
  relationships?: Array<{ spdxElementId: string; relationshipType: string; relatedSpdxElement: string }>;
}

// ─── Ecosystem Detection ────────────────────────────────────────────────────

function detectEcosystem(purl: string | undefined, name: string): string {
  if (purl) {
    if (purl.startsWith("pkg:npm/")) return "npm";
    if (purl.startsWith("pkg:pypi/")) return "pypi";
    if (purl.startsWith("pkg:gem/")) return "rubygems";
    if (purl.startsWith("pkg:nuget/")) return "nuget";
    if (purl.startsWith("pkg:cargo/")) return "cargo";
    if (purl.startsWith("pkg:golang/")) return "go";
    if (purl.startsWith("pkg:maven/")) return "maven";
    if (purl.startsWith("pkg:docker/")) return "docker";
    if (purl.startsWith("pkg:oci/")) return "docker";
  }

  // Heuristic based on name patterns
  const nameLower = name.toLowerCase();
  if (nameLower.startsWith("@") || (nameLower.includes("/") && !nameLower.includes("."))) return "npm";
  if (nameLower.includes(".") && !nameLower.includes("/")) return "nuget";
  return "npm"; // default
}

// ─── Main Processing Functions ──────────────────────────────────────────────

export interface ProcessingResult {
  sbomId: string;
  componentCount: number;
  findingsCount: number;
  vulnerabilityCount: number;
  typosquatCount: number;
  maintainerRiskCount: number;
  licenseRiskCount: number;
  outdatedCount: number;
}

/**
 * Process a CycloneDX SBOM JSON and populate the dependency graph + findings.
 */
export async function processCycloneDxSbom(
  orgId: string,
  sbomId: string,
  bomData: CycloneDxBom,
): Promise<ProcessingResult> {
  const result: ProcessingResult = {
    sbomId,
    componentCount: 0,
    findingsCount: 0,
    vulnerabilityCount: 0,
    typosquatCount: 0,
    maintainerRiskCount: 0,
    licenseRiskCount: 0,
    outdatedCount: 0,
  };

  const components = bomData.components || [];
  const depsMap = new Map<string, string[]>();

  // Build dependency map from CycloneDX dependencies section
  for (const dep of bomData.dependencies || []) {
    depsMap.set(dep.ref, dep.dependsOn || []);
  }

  // Determine which components are direct dependencies
  const topLevelDeps = new Set<string>();
  const mainComponentRef = bomData.metadata?.component?.name;
  if (mainComponentRef && depsMap.has(mainComponentRef)) {
    for (const d of depsMap.get(mainComponentRef) || []) {
      topLevelDeps.add(d);
    }
  }

  for (const comp of components) {
    if (!comp.name || !comp.version) continue;

    const ecosystem = detectEcosystem(comp.purl, comp.name);
    const isDirect = topLevelDeps.size === 0 || topLevelDeps.has(comp.purl || comp.name);
    const license = comp.licenses?.[0]?.license?.id || comp.licenses?.[0]?.license?.name || null;
    const repoUrl = comp.externalReferences?.find((r) => r.type === "vcs")?.url || null;

    // Typosquatting check
    const typoResult = detectTyposquatting(comp.name, ecosystem);

    // Maintainer scoring
    const maintainer = scoreMaintainerReputation(comp.name, ecosystem, comp.publisher || null, null);

    // CVE matching
    const cveMatches = matchSupplyChainCves(comp.name, comp.version, ecosystem);

    // Insert dependency graph entry
    const [depEntry] = await db
      .insert(dependencyGraph)
      .values({
        orgId,
        sbomId,
        packageName: comp.name,
        packageVersion: comp.version,
        ecosystem,
        isDirect,
        license,
        publisher: comp.publisher || null,
        repositoryUrl: repoUrl,
        isVulnerable: cveMatches.length > 0,
        cveCount: cveMatches.length,
        maintainerScore: maintainer.score,
        maintainerNewPublisher: maintainer.isNewPublisher,
        maintainerRecentTransfer: maintainer.isRecentTransfer,
        maintainerLowDownloads: maintainer.isLowDownloads,
        typosquatCandidate: typoResult.isSuspicious,
        typosquatSimilarTo: typoResult.similarTo,
        typosquatDistance: typoResult.distance || null,
        depth: isDirect ? 0 : 1,
      })
      .returning();

    result.componentCount++;

    // Create vulnerability findings
    for (const cve of cveMatches) {
      await db.insert(supplyChainFindings).values({
        orgId,
        sbomId,
        dependencyId: depEntry.id,
        findingType: "vulnerable_dependency",
        severity: cve.severity,
        title: `${cve.cveId}: ${comp.name}@${comp.version}`,
        description: cve.description,
        packageName: comp.name,
        packageVersion: comp.version,
        ecosystem,
        cveId: cve.cveId,
        cvssScore: cve.cvssScore,
        fixedVersion: cve.fixedVersion,
      });

      // Also create a unified vulnFinding so SBOM CVEs appear in the Vuln Scanner
      await db.insert(vulnFindings).values({
        orgId,
        source: "sbom",
        sensorId: null,
        cveId: cve.cveId,
        packageName: comp.name,
        installedVersion: comp.version,
        fixedVersion: cve.fixedVersion,
        severity: cve.severity,
        cvssScore: cve.cvssScore,
        description: cve.description,
        status: "open",
      });

      result.findingsCount++;
      result.vulnerabilityCount++;
    }

    // Typosquatting finding
    if (typoResult.isSuspicious) {
      await db.insert(supplyChainFindings).values({
        orgId,
        sbomId,
        dependencyId: depEntry.id,
        findingType: "typosquatting",
        severity: "high",
        title: `Possible typosquatting: "${comp.name}" similar to "${typoResult.similarTo}"`,
        description: `Package "${comp.name}" is ${typoResult.distance} edit(s) away from popular package "${typoResult.similarTo}". This could be a typosquatting attack.`,
        packageName: comp.name,
        packageVersion: comp.version,
        ecosystem,
        details: { similarTo: typoResult.similarTo, editDistance: typoResult.distance },
      });
      result.findingsCount++;
      result.typosquatCount++;
    }

    // Maintainer risk finding
    if (maintainer.score < 60) {
      await db.insert(supplyChainFindings).values({
        orgId,
        sbomId,
        dependencyId: depEntry.id,
        findingType: "maintainer_risk",
        severity: maintainer.score < 30 ? "high" : "medium",
        title: `Low maintainer reputation: ${comp.name} (score: ${maintainer.score}/100)`,
        description: maintainer.flags.join(". "),
        packageName: comp.name,
        packageVersion: comp.version,
        ecosystem,
        details: { score: maintainer.score, flags: maintainer.flags },
      });
      result.findingsCount++;
      result.maintainerRiskCount++;
    }

    // License risk finding
    if (license) {
      const isRisky = RISKY_LICENSES.includes(license);
      const isCopyleft = COPYLEFT_LICENSES.includes(license);
      if (isRisky) {
        await db.insert(supplyChainFindings).values({
          orgId,
          sbomId,
          dependencyId: depEntry.id,
          findingType: "license_risk",
          severity: "high",
          title: `Restrictive license: ${comp.name} uses ${license}`,
          description: `Package uses ${license} which has strong copyleft requirements that may conflict with proprietary software distribution.`,
          packageName: comp.name,
          packageVersion: comp.version,
          ecosystem,
          details: { license, category: "restrictive" },
        });
        result.findingsCount++;
        result.licenseRiskCount++;
      } else if (isCopyleft) {
        await db.insert(supplyChainFindings).values({
          orgId,
          sbomId,
          dependencyId: depEntry.id,
          findingType: "license_risk",
          severity: "medium",
          title: `Copyleft license: ${comp.name} uses ${license}`,
          description: `Package uses ${license} which may require derived works to be distributed under the same license.`,
          packageName: comp.name,
          packageVersion: comp.version,
          ecosystem,
          details: { license, category: "copyleft" },
        });
        result.findingsCount++;
        result.licenseRiskCount++;
      }
    }
  }

  // Update SBOM artifact with counts
  await db
    .update(sbomArtifacts)
    .set({
      componentCount: result.componentCount,
      vulnerabilityCount: result.vulnerabilityCount,
      status: "completed",
      processedAt: new Date(),
      updatedAt: new Date(),
    })
    .where(eq(sbomArtifacts.id, sbomId));

  return result;
}

/**
 * Process an SPDX SBOM JSON and populate the dependency graph + findings.
 */
export async function processSpdxSbom(
  orgId: string,
  sbomId: string,
  spdxData: SpdxDocument,
): Promise<ProcessingResult> {
  const result: ProcessingResult = {
    sbomId,
    componentCount: 0,
    findingsCount: 0,
    vulnerabilityCount: 0,
    typosquatCount: 0,
    maintainerRiskCount: 0,
    licenseRiskCount: 0,
    outdatedCount: 0,
  };

  const packages = spdxData.packages || [];

  // Build relationship map
  const directPkgs = new Set<string>();
  for (const rel of spdxData.relationships || []) {
    if (rel.relationshipType === "DEPENDS_ON" && rel.spdxElementId === "SPDXRef-DOCUMENT") {
      directPkgs.add(rel.relatedSpdxElement);
    }
  }

  for (const pkg of packages) {
    if (!pkg.name) continue;
    // Skip the document-level package
    if (pkg.SPDXID === "SPDXRef-DOCUMENT") continue;

    const version = pkg.versionInfo || "unknown";
    const purl = pkg.externalRefs?.find((r) => r.referenceType === "purl")?.referenceLocator;
    const ecosystem = detectEcosystem(purl, pkg.name);
    const isDirect = directPkgs.size === 0 || directPkgs.has(pkg.SPDXID);
    const license = pkg.licenseConcluded !== "NOASSERTION" ? pkg.licenseConcluded : pkg.licenseDeclared || null;

    // Typosquatting check
    const typoResult = detectTyposquatting(pkg.name, ecosystem);

    // CVE matching
    const cveMatches = matchSupplyChainCves(pkg.name, version, ecosystem);

    // Maintainer scoring
    const maintainer = scoreMaintainerReputation(pkg.name, ecosystem, pkg.supplier || null, null);

    const [depEntry] = await db
      .insert(dependencyGraph)
      .values({
        orgId,
        sbomId,
        packageName: pkg.name,
        packageVersion: version,
        ecosystem,
        isDirect,
        license: license || null,
        publisher: pkg.supplier || null,
        repositoryUrl: pkg.downloadLocation || null,
        isVulnerable: cveMatches.length > 0,
        cveCount: cveMatches.length,
        maintainerScore: maintainer.score,
        maintainerNewPublisher: maintainer.isNewPublisher,
        typosquatCandidate: typoResult.isSuspicious,
        typosquatSimilarTo: typoResult.similarTo,
        typosquatDistance: typoResult.distance || null,
        depth: isDirect ? 0 : 1,
      })
      .returning();

    result.componentCount++;

    // Create vulnerability findings
    for (const cve of cveMatches) {
      await db.insert(supplyChainFindings).values({
        orgId,
        sbomId,
        dependencyId: depEntry.id,
        findingType: "vulnerable_dependency",
        severity: cve.severity,
        title: `${cve.cveId}: ${pkg.name}@${version}`,
        description: cve.description,
        packageName: pkg.name,
        packageVersion: version,
        ecosystem,
        cveId: cve.cveId,
        cvssScore: cve.cvssScore,
        fixedVersion: cve.fixedVersion,
      });

      // Also create a unified vulnFinding so SPDX SBOM CVEs appear in the Vuln Scanner
      await db.insert(vulnFindings).values({
        orgId,
        source: "sbom",
        sensorId: null,
        cveId: cve.cveId,
        packageName: pkg.name,
        installedVersion: version,
        fixedVersion: cve.fixedVersion,
        severity: cve.severity,
        cvssScore: cve.cvssScore,
        description: cve.description,
        status: "open",
      });

      result.findingsCount++;
      result.vulnerabilityCount++;
    }

    // Typosquatting finding
    if (typoResult.isSuspicious) {
      await db.insert(supplyChainFindings).values({
        orgId,
        sbomId,
        dependencyId: depEntry.id,
        findingType: "typosquatting",
        severity: "high",
        title: `Possible typosquatting: "${pkg.name}" similar to "${typoResult.similarTo}"`,
        description: `Package "${pkg.name}" is ${typoResult.distance} edit(s) away from popular package "${typoResult.similarTo}".`,
        packageName: pkg.name,
        packageVersion: version,
        ecosystem,
        details: { similarTo: typoResult.similarTo, editDistance: typoResult.distance },
      });
      result.findingsCount++;
      result.typosquatCount++;
    }

    // Maintainer risk
    if (maintainer.score < 60) {
      await db.insert(supplyChainFindings).values({
        orgId,
        sbomId,
        dependencyId: depEntry.id,
        findingType: "maintainer_risk",
        severity: maintainer.score < 30 ? "high" : "medium",
        title: `Low maintainer reputation: ${pkg.name} (score: ${maintainer.score}/100)`,
        description: maintainer.flags.join(". "),
        packageName: pkg.name,
        packageVersion: version,
        ecosystem,
        details: { score: maintainer.score, flags: maintainer.flags },
      });
      result.findingsCount++;
      result.maintainerRiskCount++;
    }

    // License risk
    if (license && license !== "NOASSERTION") {
      const isRisky = RISKY_LICENSES.includes(license);
      const isCopyleft = COPYLEFT_LICENSES.includes(license);
      if (isRisky || isCopyleft) {
        await db.insert(supplyChainFindings).values({
          orgId,
          sbomId,
          dependencyId: depEntry.id,
          findingType: "license_risk",
          severity: isRisky ? "high" : "medium",
          title: `${isRisky ? "Restrictive" : "Copyleft"} license: ${pkg.name} uses ${license}`,
          description: `Package uses ${license} which may have distribution implications.`,
          packageName: pkg.name,
          packageVersion: version,
          ecosystem,
          details: { license, category: isRisky ? "restrictive" : "copyleft" },
        });
        result.findingsCount++;
        result.licenseRiskCount++;
      }
    }
  }

  // Update SBOM artifact with counts
  await db
    .update(sbomArtifacts)
    .set({
      componentCount: result.componentCount,
      vulnerabilityCount: result.vulnerabilityCount,
      status: "completed",
      processedAt: new Date(),
      updatedAt: new Date(),
    })
    .where(eq(sbomArtifacts.id, sbomId));

  return result;
}

/**
 * Scan IaC content (Terraform, Helm, K8s YAML, Dockerfile) for misconfigurations.
 */
export async function scanIacContent(
  orgId: string,
  sbomId: string | null,
  content: string,
  filePath: string,
  ecosystem: string,
): Promise<{ findingsCount: number }> {
  let findingsCount = 0;

  const applicableRules = IAC_RULES.filter((r) => r.ecosystem === ecosystem);

  for (const rule of applicableRules) {
    if (rule.pattern.test(content)) {
      await db.insert(supplyChainFindings).values({
        orgId,
        sbomId,
        findingType: "iac_misconfiguration",
        severity: rule.severity,
        title: rule.title,
        description: rule.description,
        iacResourceType: rule.resourceType,
        iacFilePath: filePath,
        iacRule: rule.id,
        ecosystem,
        details: { ruleId: rule.id, filePath },
      });
      findingsCount++;
    }
  }

  return { findingsCount };
}

/**
 * Scan container image layers for vulnerabilities.
 */
export async function scanContainerImage(
  orgId: string,
  sbomId: string | null,
  imageName: string,
  layers: Array<{ digest: string; command: string; packages?: Array<{ name: string; version: string }> }>,
): Promise<{ findingsCount: number }> {
  let findingsCount = 0;

  for (const layer of layers) {
    // Check for risky commands in Dockerfile layers
    const cmd = layer.command.toLowerCase();
    if (cmd.includes("chmod 777") || cmd.includes("chmod -r 777")) {
      await db.insert(supplyChainFindings).values({
        orgId,
        sbomId,
        findingType: "container_vulnerability",
        severity: "high",
        title: `Overly permissive file permissions in ${imageName}`,
        description: `Layer sets chmod 777 on files — this grants world-writable access inside the container.`,
        containerImage: imageName,
        containerLayer: layer.digest,
        ecosystem: "docker",
        details: { command: layer.command },
      });
      findingsCount++;
    }

    if ((cmd.includes("curl") && cmd.includes("| sh")) || cmd.includes("| bash")) {
      await db.insert(supplyChainFindings).values({
        orgId,
        sbomId,
        findingType: "container_vulnerability",
        severity: "critical",
        title: `Unsafe remote script execution in ${imageName}`,
        description: `Layer downloads and pipes to shell — supply chain injection risk.`,
        containerImage: imageName,
        containerLayer: layer.digest,
        ecosystem: "docker",
        details: { command: layer.command },
      });
      findingsCount++;
    }

    // Check packages in layer for CVEs
    if (layer.packages) {
      for (const pkg of layer.packages) {
        const cves = matchSupplyChainCves(pkg.name, pkg.version, "docker");
        for (const cve of cves) {
          await db.insert(supplyChainFindings).values({
            orgId,
            sbomId,
            findingType: "container_vulnerability",
            severity: cve.severity,
            title: `${cve.cveId}: ${pkg.name}@${pkg.version} in ${imageName}`,
            description: cve.description,
            packageName: pkg.name,
            packageVersion: pkg.version,
            containerImage: imageName,
            containerLayer: layer.digest,
            ecosystem: "docker",
            cveId: cve.cveId,
            cvssScore: cve.cvssScore,
            fixedVersion: cve.fixedVersion,
          });
          findingsCount++;
        }
      }
    }
  }

  return { findingsCount };
}

// ─── CVE Matching ───────────────────────────────────────────────────────────

function matchSupplyChainCves(
  packageName: string,
  version: string,
  ecosystem: string,
): { cveId: string; fixedVersion: string; severity: string; cvssScore: number; description: string }[] {
  const matches: { cveId: string; fixedVersion: string; severity: string; cvssScore: number; description: string }[] =
    [];
  const nameLower = packageName.toLowerCase();

  for (const cve of SUPPLY_CHAIN_CVES) {
    if (!cve.ecosystems.includes(ecosystem)) continue;
    if (!nameLower.includes(cve.packageName.toLowerCase())) continue;
    if (cve.vulnerablePattern.test(version)) {
      matches.push({
        cveId: cve.cveId,
        fixedVersion: cve.fixedVersion,
        severity: cve.severity,
        cvssScore: cve.cvssScore,
        description: cve.description,
      });
    }
  }
  return matches;
}

/**
 * Get supply chain risk summary for an org.
 */
export async function getSupplyChainRiskSummary(orgId: string) {
  const statsResult = await db.execute(sql`
    SELECT
      COUNT(*) AS total_findings,
      COUNT(*) FILTER (WHERE finding_type = 'vulnerable_dependency') AS vuln_count,
      COUNT(*) FILTER (WHERE finding_type = 'typosquatting') AS typosquat_count,
      COUNT(*) FILTER (WHERE finding_type = 'maintainer_risk') AS maintainer_risk_count,
      COUNT(*) FILTER (WHERE finding_type = 'license_risk') AS license_risk_count,
      COUNT(*) FILTER (WHERE finding_type = 'iac_misconfiguration') AS iac_count,
      COUNT(*) FILTER (WHERE finding_type = 'container_vulnerability') AS container_count,
      COUNT(*) FILTER (WHERE finding_type = 'provenance_failure') AS provenance_count,
      COUNT(*) FILTER (WHERE severity = 'critical') AS critical_count,
      COUNT(*) FILTER (WHERE severity = 'high') AS high_count,
      COUNT(*) FILTER (WHERE severity = 'medium') AS medium_count,
      COUNT(*) FILTER (WHERE severity = 'low') AS low_count,
      COUNT(*) FILTER (WHERE status = 'open') AS open_count,
      COUNT(*) FILTER (WHERE status = 'remediated') AS remediated_count
    FROM supply_chain_findings
    WHERE org_id = ${orgId}
  `);
  const s = (statsResult as any).rows?.[0] || {};

  const sbomResult = await db.execute(sql`
    SELECT COUNT(*) AS sbom_count,
           COALESCE(SUM(component_count), 0) AS total_components,
           COALESCE(SUM(vulnerability_count), 0) AS total_vulns
    FROM sbom_artifacts
    WHERE org_id = ${orgId}
  `);
  const sbom = (sbomResult as any).rows?.[0] || {};

  const depResult = await db.execute(sql`
    SELECT COUNT(*) AS total_deps,
           COUNT(*) FILTER (WHERE is_vulnerable = true) AS vulnerable_deps,
           COUNT(*) FILTER (WHERE typosquat_candidate = true) AS typosquat_deps,
           COUNT(DISTINCT ecosystem) AS ecosystem_count
    FROM dependency_graph
    WHERE org_id = ${orgId}
  `);
  const dep = (depResult as any).rows?.[0] || {};

  return {
    findings: {
      total: parseInt(s.total_findings || "0"),
      vulnerabilities: parseInt(s.vuln_count || "0"),
      typosquatting: parseInt(s.typosquat_count || "0"),
      maintainerRisk: parseInt(s.maintainer_risk_count || "0"),
      licenseRisk: parseInt(s.license_risk_count || "0"),
      iacMisconfigurations: parseInt(s.iac_count || "0"),
      containerVulnerabilities: parseInt(s.container_count || "0"),
      provenanceFailures: parseInt(s.provenance_count || "0"),
    },
    severity: {
      critical: parseInt(s.critical_count || "0"),
      high: parseInt(s.high_count || "0"),
      medium: parseInt(s.medium_count || "0"),
      low: parseInt(s.low_count || "0"),
    },
    status: {
      open: parseInt(s.open_count || "0"),
      remediated: parseInt(s.remediated_count || "0"),
    },
    sboms: {
      count: parseInt(sbom.sbom_count || "0"),
      totalComponents: parseInt(sbom.total_components || "0"),
      totalVulnerabilities: parseInt(sbom.total_vulns || "0"),
    },
    dependencies: {
      total: parseInt(dep.total_deps || "0"),
      vulnerable: parseInt(dep.vulnerable_deps || "0"),
      typosquatCandidates: parseInt(dep.typosquat_deps || "0"),
      ecosystemCount: parseInt(dep.ecosystem_count || "0"),
    },
  };
}
