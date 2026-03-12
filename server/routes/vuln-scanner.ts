/**
 * Native Vulnerability Scanner API
 *
 * Enables companies to scan for CVEs in installed software without requiring
 * Qualys, Tenable, or any external vulnerability management subscription.
 * A lightweight sensor agent reports installed packages; this backend performs
 * CVE matching and surfaces findings with severity, status, and remediation data.
 *
 * Routes:
 *   POST  /api/native/vuln/packages          — Agent reports installed packages (bulk, token auth)
 *   GET   /api/native/vuln/findings          — List vuln findings for org (user session auth)
 *   PATCH /api/native/vuln/findings/:id      — Update finding status (user session auth)
 *   GET   /api/native/vuln/stats             — Per-org summary stats (user session auth)
 *   GET   /api/native/vuln/inventory         — List all packages with vuln counts (user session auth)
 */

import type { Express } from "express";
import { eq, desc, and, sql, count, inArray } from "drizzle-orm";
import { z } from "zod";
import { isAuthenticated } from "../auth";
import { requireOrgId, requireMinRole, resolveOrgContext } from "../rbac";
import { db } from "../db";
import { logger, getOrgId, sendEnvelope } from "./shared";
import {
  packageInventory,
  vulnFindings,
  nativeSensors,
} from "../../shared/schema";

const log = logger.child("vuln-scanner");

// ============================================================================
// CVE data types
// ============================================================================

interface CveMatch {
  cveId: string;
  severity: "critical" | "high" | "medium" | "low" | "informational";
  cvssScore: number;
  title: string;
  description: string;
  fixedInVersion: string | null;
  publishedAt: Date;
  references: string[];
}

// ============================================================================
// CVE matching stub
//
// Matches known vulnerable package/version combos to realistic CVE records.
// For any package not matching a known vulnerability, returns an empty array.
// ============================================================================

function fetchCvesForPackage(name: string, version: string, _ecosystem: string): CveMatch[] {
  const n = name.toLowerCase();
  const v = version.toLowerCase();

  // log4j 2.14.x / 2.15.x → Log4Shell (CVE-2021-44228)
  if (n === "log4j" || n === "log4j-core" || n === "log4j2") {
    if (v.startsWith("2.14") || v.startsWith("2.15")) {
      return [
        {
          cveId: "CVE-2021-44228",
          severity: "critical",
          cvssScore: 10.0,
          title: "Log4Shell: Remote Code Execution in Apache Log4j2",
          description:
            "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.",
          fixedInVersion: "2.17.1",
          publishedAt: new Date("2021-12-10T00:00:00Z"),
          references: [
            "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
            "https://logging.apache.org/log4j/2.x/security.html",
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "https://github.com/advisories/GHSA-jfh8-c2jp-5v9q",
          ],
        },
      ];
    }
  }

  // openssl 1.0.x → Heartbleed (CVE-2014-0160)
  if (n === "openssl") {
    if (v.startsWith("1.0")) {
      return [
        {
          cveId: "CVE-2014-0160",
          severity: "high",
          cvssScore: 7.5,
          title: "Heartbleed: OpenSSL TLS Heartbeat Extension Buffer Over-read",
          description:
            "The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.",
          fixedInVersion: "1.0.1g",
          publishedAt: new Date("2014-04-07T00:00:00Z"),
          references: [
            "https://nvd.nist.gov/vuln/detail/CVE-2014-0160",
            "https://heartbleed.com/",
            "https://www.openssl.org/news/secadv/20140407.txt",
            "https://github.com/advisories/GHSA-x48q-7gq8-3qxh",
          ],
        },
      ];
    }
  }

  // spring-core / spring-framework 5.3.17 or 5.3.18 → Spring4Shell (CVE-2022-22965)
  if (n === "spring-core" || n === "spring-framework") {
    if (v === "5.3.17" || v === "5.3.18") {
      return [
        {
          cveId: "CVE-2022-22965",
          severity: "critical",
          cvssScore: 9.8,
          title: "Spring4Shell: Remote Code Execution in Spring Framework",
          description:
            "A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit.",
          fixedInVersion: "5.3.19",
          publishedAt: new Date("2022-03-31T00:00:00Z"),
          references: [
            "https://nvd.nist.gov/vuln/detail/CVE-2022-22965",
            "https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement",
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "https://github.com/advisories/GHSA-36p3-wjmg-h94x",
          ],
        },
      ];
    }
  }

  // apache-struts / struts2 2.3.x → CVE-2017-5638
  if (n === "struts" || n === "struts2" || n === "apache-struts" || n === "apache-struts2") {
    if (v.startsWith("2.3")) {
      return [
        {
          cveId: "CVE-2017-5638",
          severity: "critical",
          cvssScore: 10.0,
          title: "Apache Struts2 Remote Code Execution via Content-Type Header",
          description:
            "The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string. This vulnerability was used in the Equifax data breach.",
          fixedInVersion: "2.3.32",
          publishedAt: new Date("2017-03-10T00:00:00Z"),
          references: [
            "https://nvd.nist.gov/vuln/detail/CVE-2017-5638",
            "https://cwiki.apache.org/confluence/display/WW/S2-045",
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "https://github.com/advisories/GHSA-g8g6-99mq-3p74",
          ],
        },
      ];
    }
  }

  // jackson-databind 2.9.x → CVE-2019-14379
  if (n === "jackson-databind") {
    if (v.startsWith("2.9")) {
      return [
        {
          cveId: "CVE-2019-14379",
          severity: "critical",
          cvssScore: 9.8,
          title: "Jackson-databind Polymorphic Deserialization Remote Code Execution",
          description:
            "SubTypeValidator.java in FasterXML jackson-databind before 2.9.9.2 mishandles default typing when ehcache is used (because of net.sf.ehcache.transaction.manager.DefaultTransactionManagerLookup), leading to code execution. An attacker can exploit this vulnerability by submitting a specially crafted JSON payload to an application that uses Jackson for deserialization.",
          fixedInVersion: "2.9.9.2",
          publishedAt: new Date("2019-07-29T00:00:00Z"),
          references: [
            "https://nvd.nist.gov/vuln/detail/CVE-2019-14379",
            "https://github.com/FasterXML/jackson-databind/issues/2387",
            "https://github.com/advisories/GHSA-6fpp-rgj9-8rwc",
            "https://medium.com/@cowtowncoder/on-jackson-cves-dont-panic-here-is-what-you-need-to-know-54cd0d6e8062",
          ],
        },
      ];
    }
  }

  // libssl / libcrypto 1.0.1.x → Heartbleed (CVE-2014-0160)
  if (n === "libssl" || n === "libcrypto") {
    if (v.startsWith("1.0.1")) {
      return [
        {
          cveId: "CVE-2014-0160",
          severity: "high",
          cvssScore: 7.5,
          title: "Heartbleed: OpenSSL TLS Heartbeat Extension Buffer Over-read",
          description:
            "The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.",
          fixedInVersion: "1.0.1g",
          publishedAt: new Date("2014-04-07T00:00:00Z"),
          references: [
            "https://nvd.nist.gov/vuln/detail/CVE-2014-0160",
            "https://heartbleed.com/",
            "https://www.openssl.org/news/secadv/20140407.txt",
            "https://github.com/advisories/GHSA-x48q-7gq8-3qxh",
          ],
        },
      ];
    }
  }

  return [];
}

// ============================================================================
// Validation schemas
// ============================================================================

const packageItemSchema = z.object({
  name: z.string().min(1).max(512),
  version: z.string().min(1).max(128),
  ecosystem: z.string().min(1).max(64),
});

const reportPackagesSchema = z.object({
  token: z.string().min(1),
  sensorId: z.string().min(1),
  packages: z.array(packageItemSchema).max(5000),
});

const updateFindingSchema = z.object({
  status: z.enum(["open", "acknowledged", "remediated", "false_positive"]),
  notes: z.string().max(4096).optional(),
});

// ============================================================================
// Helpers
// ============================================================================

async function findSensorByToken(token: string) {
  const rows = await db
    .select()
    .from(nativeSensors)
    .where(eq(nativeSensors.registrationToken, token))
    .limit(1);
  return rows[0] ?? null;
}

// ============================================================================
// Main route registration
// ============================================================================

export function registerVulnScannerRoutes(app: Express): void {
  // --------------------------------------------------------------------------
  // POST /api/native/vuln/packages
  // Agent bulk-reports installed packages. Auth via sensor token in body.
  // After upserting inventory, performs CVE matching and upserts findings.
  // --------------------------------------------------------------------------
  app.post("/api/native/vuln/packages", async (req, res) => {
    const startTime = Date.now();
    try {
      const body = reportPackagesSchema.parse(req.body);

      const sensor = await findSensorByToken(body.token);
      if (!sensor) {
        return res.status(401).json({ error: "Invalid sensor token" });
      }
      if (!sensor.isActive) {
        return res.status(403).json({ error: "Sensor is decommissioned" });
      }
      if (sensor.id !== body.sensorId) {
        return res.status(403).json({ error: "Sensor ID does not match token" });
      }

      const orgId = sensor.orgId;
      const now = new Date();

      let packagesUpserted = 0;
      let findingsUpserted = 0;
      let newFindings = 0;

      for (const pkg of body.packages) {
        // Upsert package into inventory
        const [inventoryRow] = await db
          .insert(packageInventory)
          .values({
            orgId,
            sensorId: sensor.id,
            hostname: sensor.hostname,
            name: pkg.name,
            version: pkg.version,
            ecosystem: pkg.ecosystem,
            lastScannedAt: now,
          })
          .onConflictDoUpdate({
            target: [
              packageInventory.sensorId,
              packageInventory.name,
              packageInventory.version,
              packageInventory.ecosystem,
            ],
            set: {
              lastScannedAt: now,
              updatedAt: now,
            },
          })
          .returning();

        packagesUpserted++;

        // CVE matching
        const cves = fetchCvesForPackage(pkg.name, pkg.version, pkg.ecosystem);

        if (cves.length === 0) {
          continue;
        }

        let pkgVulnCount = 0;
        let pkgCriticalCount = 0;

        for (const cve of cves) {
          // Upsert vuln finding
          const [finding] = await db
            .insert(vulnFindings)
            .values({
              orgId,
              sensorId: sensor.id,
              packageId: inventoryRow.id,
              cveId: cve.cveId,
              severity: cve.severity,
              cvssScore: cve.cvssScore,
              title: cve.title,
              description: cve.description,
              publishedAt: cve.publishedAt,
              fixedInVersion: cve.fixedInVersion ?? null,
              references: cve.references,
              status: "open",
            })
            .onConflictDoUpdate({
              target: [
                vulnFindings.sensorId,
                vulnFindings.packageId,
                vulnFindings.cveId,
              ],
              set: {
                severity: cve.severity,
                cvssScore: cve.cvssScore,
                title: cve.title,
                description: cve.description,
                publishedAt: cve.publishedAt,
                fixedInVersion: cve.fixedInVersion ?? null,
                references: cve.references,
                updatedAt: now,
              },
            })
            .returning();

          // Track if this was newly inserted (createdAt == updatedAt within a second)
          const wasNew = Math.abs(finding.createdAt!.getTime() - finding.updatedAt!.getTime()) < 1000;
          if (wasNew) {
            newFindings++;
          }
          findingsUpserted++;
          pkgVulnCount++;
          if (cve.severity === "critical") pkgCriticalCount++;
        }

        // Update package vuln counts
        await db
          .update(packageInventory)
          .set({
            vulnCount: pkgVulnCount,
            criticalVulnCount: pkgCriticalCount,
            updatedAt: now,
          })
          .where(eq(packageInventory.id, inventoryRow.id));
      }

      const processingMs = Date.now() - startTime;
      log.info("Package inventory and CVE scan complete", {
        sensorId: sensor.id,
        orgId,
        packagesUpserted,
        findingsUpserted,
        newFindings,
        processingMs,
      });

      return res.status(200).json({
        ok: true,
        packagesProcessed: packagesUpserted,
        findingsUpserted,
        newFindings,
        processingMs,
      });
    } catch (err: any) {
      log.error("Package ingestion failed", { error: String(err) });
      if (err.name === "ZodError") {
        return res.status(400).json({ error: "Invalid request body", details: err.errors });
      }
      return res.status(500).json({ error: "Package ingestion failed" });
    }
  });

  // --------------------------------------------------------------------------
  // GET /api/native/vuln/findings
  // List vuln findings for org with optional filters.
  // Query params: ?severity=critical&status=open&sensorId=xxx
  // --------------------------------------------------------------------------
  app.get(
    "/api/native/vuln/findings",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { severity, status, sensorId } = req.query as Record<string, string | undefined>;

        const conditions = [eq(vulnFindings.orgId, orgId)];

        if (severity) {
          conditions.push(eq(vulnFindings.severity, severity));
        }
        if (status) {
          conditions.push(eq(vulnFindings.status, status));
        }
        if (sensorId) {
          conditions.push(eq(vulnFindings.sensorId, sensorId));
        }

        const rows = await db
          .select({
            id: vulnFindings.id,
            orgId: vulnFindings.orgId,
            sensorId: vulnFindings.sensorId,
            packageId: vulnFindings.packageId,
            cveId: vulnFindings.cveId,
            severity: vulnFindings.severity,
            cvssScore: vulnFindings.cvssScore,
            title: vulnFindings.title,
            description: vulnFindings.description,
            publishedAt: vulnFindings.publishedAt,
            fixedInVersion: vulnFindings.fixedInVersion,
            references: vulnFindings.references,
            status: vulnFindings.status,
            acknowledgedBy: vulnFindings.acknowledgedBy,
            acknowledgedAt: vulnFindings.acknowledgedAt,
            remediatedAt: vulnFindings.remediatedAt,
            notes: vulnFindings.notes,
            createdAt: vulnFindings.createdAt,
            updatedAt: vulnFindings.updatedAt,
            packageName: packageInventory.name,
            packageVersion: packageInventory.version,
            packageEcosystem: packageInventory.ecosystem,
            hostname: packageInventory.hostname,
          })
          .from(vulnFindings)
          .innerJoin(packageInventory, eq(vulnFindings.packageId, packageInventory.id))
          .where(and(...conditions))
          .orderBy(
            sql`CASE ${vulnFindings.severity}
              WHEN 'critical' THEN 1
              WHEN 'high' THEN 2
              WHEN 'medium' THEN 3
              WHEN 'low' THEN 4
              ELSE 5 END`,
            desc(vulnFindings.cvssScore),
            desc(vulnFindings.createdAt),
          );

        return sendEnvelope(res, rows, {
          meta: {
            total: rows.length,
            filtered: {
              severity: severity ?? null,
              status: status ?? null,
              sensorId: sensorId ?? null,
            },
          },
        });
      } catch (err: any) {
        log.error("Failed to list vuln findings", { error: String(err) });
        return res.status(500).json({ error: "Failed to list vulnerability findings" });
      }
    },
  );

  // --------------------------------------------------------------------------
  // PATCH /api/native/vuln/findings/:id
  // Update finding status: acknowledge, remediate, mark false positive.
  // --------------------------------------------------------------------------
  app.patch(
    "/api/native/vuln/findings/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const findingId = req.params.id;
        const userId = (req as any).user?.id ?? null;
        const body = updateFindingSchema.parse(req.body);

        // Verify finding belongs to this org
        const [existing] = await db
          .select()
          .from(vulnFindings)
          .where(and(eq(vulnFindings.id, findingId), eq(vulnFindings.orgId, orgId)))
          .limit(1);

        if (!existing) {
          return res.status(404).json({ error: "Finding not found" });
        }

        const now = new Date();
        const updateData: Partial<typeof vulnFindings.$inferInsert> & { updatedAt: Date } = {
          status: body.status,
          updatedAt: now,
        };

        if (body.notes !== undefined) {
          updateData.notes = body.notes;
        }

        if (body.status === "acknowledged") {
          updateData.acknowledgedBy = userId;
          updateData.acknowledgedAt = now;
        } else if (body.status === "remediated") {
          updateData.remediatedAt = now;
        }

        const [updated] = await db
          .update(vulnFindings)
          .set(updateData)
          .where(and(eq(vulnFindings.id, findingId), eq(vulnFindings.orgId, orgId)))
          .returning();

        log.info("Vuln finding status updated", {
          findingId,
          orgId,
          previousStatus: existing.status,
          newStatus: body.status,
          updatedBy: userId,
        });

        return sendEnvelope(res, updated);
      } catch (err: any) {
        if (err.name === "ZodError") {
          return res.status(400).json({ error: "Invalid request body", details: err.errors });
        }
        log.error("Failed to update vuln finding", { error: String(err) });
        return res.status(500).json({ error: "Failed to update finding" });
      }
    },
  );

  // --------------------------------------------------------------------------
  // GET /api/native/vuln/stats
  // Per-org summary: total findings by severity, affected hosts count,
  // most vulnerable packages top-5.
  // --------------------------------------------------------------------------
  app.get(
    "/api/native/vuln/stats",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        // Findings breakdown by severity
        const [severityStats] = await db
          .select({
            total: count(),
            critical: sql<number>`COUNT(*) FILTER (WHERE ${vulnFindings.severity} = 'critical')`,
            high: sql<number>`COUNT(*) FILTER (WHERE ${vulnFindings.severity} = 'high')`,
            medium: sql<number>`COUNT(*) FILTER (WHERE ${vulnFindings.severity} = 'medium')`,
            low: sql<number>`COUNT(*) FILTER (WHERE ${vulnFindings.severity} = 'low')`,
            open: sql<number>`COUNT(*) FILTER (WHERE ${vulnFindings.status} = 'open')`,
            acknowledged: sql<number>`COUNT(*) FILTER (WHERE ${vulnFindings.status} = 'acknowledged')`,
            remediated: sql<number>`COUNT(*) FILTER (WHERE ${vulnFindings.status} = 'remediated')`,
            falsePositive: sql<number>`COUNT(*) FILTER (WHERE ${vulnFindings.status} = 'false_positive')`,
          })
          .from(vulnFindings)
          .where(eq(vulnFindings.orgId, orgId));

        // Distinct affected hosts
        const [hostStats] = await db
          .select({
            affectedHosts: sql<number>`COUNT(DISTINCT ${packageInventory.hostname})`,
          })
          .from(vulnFindings)
          .innerJoin(packageInventory, eq(vulnFindings.packageId, packageInventory.id))
          .where(
            and(
              eq(vulnFindings.orgId, orgId),
              eq(vulnFindings.status, "open"),
            ),
          );

        // Top 5 most vulnerable packages by open finding count
        const topPackages = await db
          .select({
            packageName: packageInventory.name,
            packageVersion: packageInventory.version,
            ecosystem: packageInventory.ecosystem,
            openFindings: sql<number>`COUNT(*) FILTER (WHERE ${vulnFindings.status} = 'open')`,
            criticalFindings: sql<number>`COUNT(*) FILTER (WHERE ${vulnFindings.severity} = 'critical' AND ${vulnFindings.status} = 'open')`,
            maxCvss: sql<number>`MAX(${vulnFindings.cvssScore})`,
          })
          .from(vulnFindings)
          .innerJoin(packageInventory, eq(vulnFindings.packageId, packageInventory.id))
          .where(eq(vulnFindings.orgId, orgId))
          .groupBy(packageInventory.id, packageInventory.name, packageInventory.version, packageInventory.ecosystem)
          .orderBy(
            desc(sql`COUNT(*) FILTER (WHERE ${vulnFindings.severity} = 'critical' AND ${vulnFindings.status} = 'open')`),
            desc(sql`COUNT(*) FILTER (WHERE ${vulnFindings.status} = 'open')`),
            desc(sql`MAX(${vulnFindings.cvssScore})`),
          )
          .limit(5);

        // Total packages scanned
        const [inventoryStats] = await db
          .select({ totalPackages: count() })
          .from(packageInventory)
          .where(eq(packageInventory.orgId, orgId));

        return sendEnvelope(res, {
          findings: {
            total: Number(severityStats?.total ?? 0),
            bySeverity: {
              critical: Number(severityStats?.critical ?? 0),
              high: Number(severityStats?.high ?? 0),
              medium: Number(severityStats?.medium ?? 0),
              low: Number(severityStats?.low ?? 0),
            },
            byStatus: {
              open: Number(severityStats?.open ?? 0),
              acknowledged: Number(severityStats?.acknowledged ?? 0),
              remediated: Number(severityStats?.remediated ?? 0),
              falsePositive: Number(severityStats?.falsePositive ?? 0),
            },
          },
          affectedHosts: Number(hostStats?.affectedHosts ?? 0),
          totalPackagesScanned: Number(inventoryStats?.totalPackages ?? 0),
          topVulnerablePackages: topPackages.map((p) => ({
            name: p.packageName,
            version: p.packageVersion,
            ecosystem: p.ecosystem,
            openFindings: Number(p.openFindings),
            criticalFindings: Number(p.criticalFindings),
            maxCvssScore: p.maxCvss ? Number(p.maxCvss) : null,
          })),
        });
      } catch (err: any) {
        log.error("Failed to get vuln stats", { error: String(err) });
        return res.status(500).json({ error: "Failed to retrieve vulnerability statistics" });
      }
    },
  );

  // --------------------------------------------------------------------------
  // GET /api/native/vuln/inventory
  // List all packages per org with their vuln counts and worst severity.
  // --------------------------------------------------------------------------
  app.get(
    "/api/native/vuln/inventory",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        const rows = await db
          .select({
            id: packageInventory.id,
            sensorId: packageInventory.sensorId,
            hostname: packageInventory.hostname,
            name: packageInventory.name,
            version: packageInventory.version,
            ecosystem: packageInventory.ecosystem,
            installedAt: packageInventory.installedAt,
            lastScannedAt: packageInventory.lastScannedAt,
            vulnCount: packageInventory.vulnCount,
            criticalVulnCount: packageInventory.criticalVulnCount,
            createdAt: packageInventory.createdAt,
            updatedAt: packageInventory.updatedAt,
            openFindings: sql<number>`COUNT(${vulnFindings.id}) FILTER (WHERE ${vulnFindings.status} = 'open')`,
            worstSeverity: sql<string | null>`
              CASE
                WHEN COUNT(${vulnFindings.id}) FILTER (WHERE ${vulnFindings.severity} = 'critical' AND ${vulnFindings.status} = 'open') > 0 THEN 'critical'
                WHEN COUNT(${vulnFindings.id}) FILTER (WHERE ${vulnFindings.severity} = 'high' AND ${vulnFindings.status} = 'open') > 0 THEN 'high'
                WHEN COUNT(${vulnFindings.id}) FILTER (WHERE ${vulnFindings.severity} = 'medium' AND ${vulnFindings.status} = 'open') > 0 THEN 'medium'
                WHEN COUNT(${vulnFindings.id}) FILTER (WHERE ${vulnFindings.severity} = 'low' AND ${vulnFindings.status} = 'open') > 0 THEN 'low'
                ELSE NULL
              END
            `,
          })
          .from(packageInventory)
          .leftJoin(vulnFindings, eq(vulnFindings.packageId, packageInventory.id))
          .where(eq(packageInventory.orgId, orgId))
          .groupBy(packageInventory.id)
          .orderBy(
            desc(sql`COUNT(${vulnFindings.id}) FILTER (WHERE ${vulnFindings.severity} = 'critical' AND ${vulnFindings.status} = 'open')`),
            desc(sql`COUNT(${vulnFindings.id}) FILTER (WHERE ${vulnFindings.status} = 'open')`),
            packageInventory.name,
          );

        return sendEnvelope(res, rows, {
          meta: { total: rows.length },
        });
      } catch (err: any) {
        log.error("Failed to list package inventory", { error: String(err) });
        return res.status(500).json({ error: "Failed to retrieve package inventory" });
      }
    },
  );
}
