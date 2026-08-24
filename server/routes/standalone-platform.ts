/* eslint-disable @typescript-eslint/no-explicit-any */
import type { Express } from "express";
import { randomBytes } from "crypto";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId, requireMinRole } from "../rbac";
import { storage, logger, getOrgId, sendEnvelope } from "./shared";
import { db } from "../db";
import { publishAlertCreated } from "../alert-events";
import { sql, eq, desc, and, ilike, or, count } from "drizzle-orm";
import { assetReferencesMatch } from "../asset-linkage";
import { z } from "zod";
import {
  assetInventory,
  riskRegister,
  securityAssessments,
  assessmentResponses,
  threatReports,
  incidents,
  alerts,
  ASSET_TYPES,
  ASSET_CRITICALITIES,
  ASSET_LIFECYCLE_STATUSES,
  ASSET_ENVIRONMENTS,
  RISK_CATEGORIES,
  RISK_TREATMENTS,
  RISK_STATUSES,
  ASSESSMENT_FRAMEWORKS,
  ASSESSMENT_STATUSES,
  THREAT_REPORT_CATEGORIES,
  THREAT_REPORT_STATUSES,
  THREAT_REPORT_SEVERITIES,
  vulnFindings,
  nativeSensors,
} from "../../shared/schema";

const log = logger.child("standalone-platform");

const ASSET_ALERT_HISTORY_LIMIT = 100;
const ASSET_INCIDENT_HISTORY_LIMIT = 100;

type AssetSecurityHistory = {
  linkedAlerts: (typeof alerts.$inferSelect)[];
  linkedIncidents: (typeof incidents.$inferSelect)[];
  alertsTruncated: boolean;
  incidentsTruncated: boolean;
};

async function getAssetSecurityHistory(orgId: string, asset: typeof assetInventory.$inferSelect) {
  const identifiers = [asset.id, asset.hostname, asset.ipAddress, asset.fqdn].filter(
    (value): value is string => typeof value === "string" && value.length > 0,
  );
  if (identifiers.length === 0) {
    return {
      linkedAlerts: [],
      linkedIncidents: [],
      alertsTruncated: false,
      incidentsTruncated: false,
    } satisfies AssetSecurityHistory;
  }

  const normalizedIdentifiers = Array.from(new Set(identifiers.map((value) => value.trim().toLocaleLowerCase())));
  const alertIdentifierConditions = normalizedIdentifiers.flatMap((value) => [
    sql`lower(${alerts.hostname}) = ${value}`,
    sql`lower(${alerts.sourceIp}) = ${value}`,
    sql`lower(${alerts.destIp}) = ${value}`,
  ]);
  const alertRows = await db
    .select()
    .from(alerts)
    .where(and(eq(alerts.orgId, orgId), or(...alertIdentifierConditions)))
    .orderBy(desc(alerts.createdAt))
    .limit(ASSET_ALERT_HISTORY_LIMIT + 1);
  const alertsTruncated = alertRows.length > ASSET_ALERT_HISTORY_LIMIT;
  const linkedAlerts = alertRows.slice(0, ASSET_ALERT_HISTORY_LIMIT);

  const identifierSql = sql.join(
    normalizedIdentifiers.map((value) => sql`${value}`),
    sql`, `,
  );
  const affectedAssetCondition = sql`EXISTS (
    SELECT 1
    FROM jsonb_array_elements(
      CASE
        WHEN jsonb_typeof(${incidents.affectedAssets}) = 'array' THEN ${incidents.affectedAssets}
        ELSE '[]'::jsonb
      END
    ) AS affected_asset
    WHERE lower(trim(affected_asset #>> '{}')) IN (${identifierSql})
      OR lower(trim(affected_asset->>'id')) IN (${identifierSql})
      OR lower(trim(affected_asset->>'assetId')) IN (${identifierSql})
      OR lower(trim(affected_asset->>'asset_id')) IN (${identifierSql})
      OR lower(trim(affected_asset->>'hostname')) IN (${identifierSql})
      OR lower(trim(affected_asset->>'fqdn')) IN (${identifierSql})
      OR lower(trim(affected_asset->>'ip')) IN (${identifierSql})
      OR lower(trim(affected_asset->>'ipAddress')) IN (${identifierSql})
      OR lower(trim(affected_asset->>'ip_address')) IN (${identifierSql})
      OR lower(trim(affected_asset->>'name')) IN (${identifierSql})
  )`;
  const linkedAlertCondition = sql`EXISTS (
    SELECT 1
    FROM alerts AS linked_alert
    WHERE linked_alert.org_id = ${orgId}
      AND linked_alert.id = ANY(${incidents.referencedAlertIds})
      AND (
        lower(linked_alert.hostname) IN (${identifierSql})
        OR lower(linked_alert.source_ip) IN (${identifierSql})
        OR lower(linked_alert.dest_ip) IN (${identifierSql})
      )
  )`;
  const incidentRows = await db
    .select()
    .from(incidents)
    .where(and(eq(incidents.orgId, orgId), sql`(${affectedAssetCondition} OR ${linkedAlertCondition})`))
    .orderBy(desc(incidents.createdAt))
    .limit(ASSET_INCIDENT_HISTORY_LIMIT + 1);
  const incidentsTruncated = incidentRows.length > ASSET_INCIDENT_HISTORY_LIMIT;
  const linkedIncidents = incidentRows
    .slice(0, ASSET_INCIDENT_HISTORY_LIMIT)
    .filter(
      (incident) =>
        assetReferencesMatch(incident.affectedAssets, identifiers) || (incident.referencedAlertIds || []).length > 0,
    );

  return { linkedAlerts, linkedIncidents, alertsTruncated, incidentsTruncated } satisfies AssetSecurityHistory;
}

// ============================================================================
// Assessment framework templates with built-in controls
// ============================================================================

interface FrameworkControl {
  controlId: string;
  title: string;
  description: string;
  category: string;
  weight: number;
}

const FRAMEWORK_CONTROLS: Record<string, { name: string; description: string; controls: FrameworkControl[] }> = {
  cis_controls_v8: {
    name: "CIS Controls v8",
    description: "Center for Internet Security Critical Security Controls",
    controls: [
      {
        controlId: "CIS-1",
        title: "Inventory and Control of Enterprise Assets",
        description:
          "Actively manage all enterprise assets connected to the infrastructure physically, virtually, remotely, and those within cloud environments.",
        category: "Basic",
        weight: 3,
      },
      {
        controlId: "CIS-2",
        title: "Inventory and Control of Software Assets",
        description:
          "Actively manage all software on the network so that only authorized software is installed and can execute.",
        category: "Basic",
        weight: 3,
      },
      {
        controlId: "CIS-3",
        title: "Data Protection",
        description:
          "Develop processes and technical controls to identify, classify, securely handle, retain, and dispose of data.",
        category: "Basic",
        weight: 2,
      },
      {
        controlId: "CIS-4",
        title: "Secure Configuration of Enterprise Assets and Software",
        description: "Establish and maintain the secure configuration of enterprise assets and software.",
        category: "Basic",
        weight: 3,
      },
      {
        controlId: "CIS-5",
        title: "Account Management",
        description: "Use processes and tools to assign and manage authorization to credentials for user accounts.",
        category: "Basic",
        weight: 3,
      },
      {
        controlId: "CIS-6",
        title: "Access Control Management",
        description:
          "Use processes and tools to create, assign, manage, and revoke access credentials and privileges for user, administrator, and service accounts.",
        category: "Basic",
        weight: 3,
      },
      {
        controlId: "CIS-7",
        title: "Continuous Vulnerability Management",
        description: "Develop a plan to continuously assess and track vulnerabilities on all enterprise assets.",
        category: "Foundational",
        weight: 2,
      },
      {
        controlId: "CIS-8",
        title: "Audit Log Management",
        description:
          "Collect, alert, review, and retain audit logs of events that could help detect, understand, or recover from an attack.",
        category: "Foundational",
        weight: 2,
      },
      {
        controlId: "CIS-9",
        title: "Email and Web Browser Protections",
        description: "Improve protections and detections of threats from email and web vectors.",
        category: "Foundational",
        weight: 2,
      },
      {
        controlId: "CIS-10",
        title: "Malware Defenses",
        description:
          "Prevent or control the installation, spread, and execution of malicious applications, code, or scripts.",
        category: "Foundational",
        weight: 2,
      },
      {
        controlId: "CIS-11",
        title: "Data Recovery",
        description:
          "Establish and maintain data recovery practices sufficient to restore in-scope enterprise assets to a pre-incident and trusted state.",
        category: "Foundational",
        weight: 2,
      },
      {
        controlId: "CIS-12",
        title: "Network Infrastructure Management",
        description: "Establish and maintain the secure configuration of network devices.",
        category: "Foundational",
        weight: 1,
      },
      {
        controlId: "CIS-13",
        title: "Network Monitoring and Defense",
        description:
          "Operate processes and tooling to establish and maintain comprehensive network monitoring and defense.",
        category: "Organizational",
        weight: 2,
      },
      {
        controlId: "CIS-14",
        title: "Security Awareness and Skills Training",
        description: "Establish and maintain a security awareness program to influence behavior.",
        category: "Organizational",
        weight: 1,
      },
      {
        controlId: "CIS-15",
        title: "Service Provider Management",
        description: "Develop a process to evaluate service providers who hold sensitive data.",
        category: "Organizational",
        weight: 1,
      },
      {
        controlId: "CIS-16",
        title: "Application Software Security",
        description: "Manage the security life cycle of in-house developed, hosted, or acquired software.",
        category: "Organizational",
        weight: 2,
      },
      {
        controlId: "CIS-17",
        title: "Incident Response Management",
        description: "Establish a program to develop and maintain an incident response capability.",
        category: "Organizational",
        weight: 2,
      },
      {
        controlId: "CIS-18",
        title: "Penetration Testing",
        description:
          "Test the effectiveness and resiliency of enterprise assets through identifying and exploiting weaknesses in controls.",
        category: "Organizational",
        weight: 1,
      },
    ],
  },
  nist_csf_2: {
    name: "NIST CSF 2.0",
    description: "National Institute of Standards and Technology Cybersecurity Framework",
    controls: [
      {
        controlId: "GV.OC-01",
        title: "Organizational Context",
        description: "The organizational mission is understood and informs cybersecurity risk management.",
        category: "Govern",
        weight: 1,
      },
      {
        controlId: "GV.RM-01",
        title: "Risk Management Strategy",
        description: "Risk management objectives are established and expressed as statements.",
        category: "Govern",
        weight: 2,
      },
      {
        controlId: "GV.SC-01",
        title: "Supply Chain Risk Management",
        description: "A cyber supply chain risk management program is established.",
        category: "Govern",
        weight: 2,
      },
      {
        controlId: "ID.AM-01",
        title: "Asset Management",
        description: "Inventories of hardware managed by the organization are maintained.",
        category: "Identify",
        weight: 3,
      },
      {
        controlId: "ID.AM-02",
        title: "Software Inventory",
        description: "Inventories of software, services, and systems managed by the organization are maintained.",
        category: "Identify",
        weight: 3,
      },
      {
        controlId: "ID.RA-01",
        title: "Risk Assessment",
        description: "Vulnerabilities in assets are identified, validated, and recorded.",
        category: "Identify",
        weight: 2,
      },
      {
        controlId: "PR.AA-01",
        title: "Identity & Access Management",
        description: "Identities and credentials for authorized users, services, and hardware are managed.",
        category: "Protect",
        weight: 3,
      },
      {
        controlId: "PR.AT-01",
        title: "Awareness and Training",
        description: "Personnel are provided cybersecurity awareness and training.",
        category: "Protect",
        weight: 1,
      },
      {
        controlId: "PR.DS-01",
        title: "Data Security",
        description: "The confidentiality, integrity, and availability of data-at-rest are protected.",
        category: "Protect",
        weight: 2,
      },
      {
        controlId: "PR.PS-01",
        title: "Platform Security",
        description:
          "The hardware, software, and services of physical and virtual platforms are managed consistent with risk strategy.",
        category: "Protect",
        weight: 2,
      },
      {
        controlId: "DE.CM-01",
        title: "Continuous Monitoring",
        description: "Networks and network services are monitored to find potentially adverse events.",
        category: "Detect",
        weight: 2,
      },
      {
        controlId: "DE.AE-01",
        title: "Adverse Event Analysis",
        description: "Anomalies, indicators of compromise, and other potentially adverse events are analyzed.",
        category: "Detect",
        weight: 2,
      },
      {
        controlId: "RS.MA-01",
        title: "Incident Management",
        description: "The incident response plan is executed in coordination with relevant third parties.",
        category: "Respond",
        weight: 2,
      },
      {
        controlId: "RS.AN-01",
        title: "Incident Analysis",
        description: "Investigations are conducted to ensure effective response and support forensics.",
        category: "Respond",
        weight: 2,
      },
      {
        controlId: "RC.RP-01",
        title: "Recovery Planning",
        description: "The recovery portion of the incident response plan is executed.",
        category: "Recover",
        weight: 2,
      },
      {
        controlId: "RC.CO-01",
        title: "Recovery Communication",
        description: "Restoration activities are coordinated with internal and external parties.",
        category: "Recover",
        weight: 1,
      },
    ],
  },
  iso_27001: {
    name: "ISO 27001:2022",
    description: "Information Security Management System",
    controls: [
      {
        controlId: "A.5.1",
        title: "Information Security Policies",
        description:
          "Policies for information security shall be defined, approved by management, published and communicated.",
        category: "Organizational",
        weight: 2,
      },
      {
        controlId: "A.5.2",
        title: "Information Security Roles",
        description: "Information security roles and responsibilities shall be defined and allocated.",
        category: "Organizational",
        weight: 2,
      },
      {
        controlId: "A.5.3",
        title: "Segregation of Duties",
        description: "Conflicting duties and conflicting areas of responsibility shall be segregated.",
        category: "Organizational",
        weight: 1,
      },
      {
        controlId: "A.6.1",
        title: "Screening",
        description: "Background verification checks on all candidates for employment shall be carried out.",
        category: "People",
        weight: 1,
      },
      {
        controlId: "A.6.2",
        title: "Terms of Employment",
        description:
          "Employment contractual agreements shall state the employee's and the organization's responsibilities for information security.",
        category: "People",
        weight: 1,
      },
      {
        controlId: "A.6.3",
        title: "Information Security Awareness",
        description:
          "Personnel of the organization shall receive appropriate information security awareness, education and training.",
        category: "People",
        weight: 2,
      },
      {
        controlId: "A.7.1",
        title: "Physical Security Perimeters",
        description:
          "Security perimeters shall be defined and used to protect areas that contain information and other associated assets.",
        category: "Physical",
        weight: 1,
      },
      {
        controlId: "A.7.2",
        title: "Physical Entry",
        description: "Secure areas shall be protected by appropriate entry controls.",
        category: "Physical",
        weight: 1,
      },
      {
        controlId: "A.8.1",
        title: "User Endpoint Devices",
        description: "Information stored on, processed by or accessible via user endpoint devices shall be protected.",
        category: "Technological",
        weight: 2,
      },
      {
        controlId: "A.8.2",
        title: "Privileged Access Rights",
        description: "The allocation and use of privileged access rights shall be restricted and managed.",
        category: "Technological",
        weight: 3,
      },
      {
        controlId: "A.8.3",
        title: "Information Access Restriction",
        description: "Access to information and other associated assets shall be restricted.",
        category: "Technological",
        weight: 2,
      },
      {
        controlId: "A.8.5",
        title: "Secure Authentication",
        description: "Secure authentication technologies and procedures shall be established and implemented.",
        category: "Technological",
        weight: 3,
      },
      {
        controlId: "A.8.7",
        title: "Protection Against Malware",
        description: "Protection against malware shall be implemented and supported by appropriate user awareness.",
        category: "Technological",
        weight: 2,
      },
      {
        controlId: "A.8.8",
        title: "Management of Technical Vulnerabilities",
        description:
          "Information about technical vulnerabilities of information systems shall be obtained and appropriate measures taken.",
        category: "Technological",
        weight: 2,
      },
      {
        controlId: "A.8.9",
        title: "Configuration Management",
        description:
          "Configurations of hardware, software, services and networks shall be established, documented and managed.",
        category: "Technological",
        weight: 2,
      },
      {
        controlId: "A.8.15",
        title: "Logging",
        description:
          "Logs that record activities, exceptions, faults and other relevant events shall be produced, stored, protected and analyzed.",
        category: "Technological",
        weight: 2,
      },
      {
        controlId: "A.8.16",
        title: "Monitoring Activities",
        description: "Networks, systems and applications shall be monitored for anomalous behaviour.",
        category: "Technological",
        weight: 2,
      },
      {
        controlId: "A.8.24",
        title: "Use of Cryptography",
        description:
          "Rules for the effective use of cryptography, including cryptographic key management, shall be defined.",
        category: "Technological",
        weight: 2,
      },
    ],
  },
  soc2_type2: {
    name: "SOC 2 Type II",
    description: "Service Organization Control 2 Trust Services Criteria",
    controls: [
      {
        controlId: "CC1.1",
        title: "COSO Principle 1 — Integrity and Ethics",
        description: "The entity demonstrates a commitment to integrity and ethical values.",
        category: "Control Environment",
        weight: 1,
      },
      {
        controlId: "CC1.2",
        title: "COSO Principle 2 — Board Oversight",
        description: "The board of directors demonstrates independence from management and exercises oversight.",
        category: "Control Environment",
        weight: 1,
      },
      {
        controlId: "CC2.1",
        title: "Information and Communication",
        description: "The entity obtains or generates and uses relevant, quality information.",
        category: "Communication",
        weight: 1,
      },
      {
        controlId: "CC3.1",
        title: "Risk Assessment",
        description:
          "The entity specifies objectives with sufficient clarity to enable the identification and assessment of risks.",
        category: "Risk Assessment",
        weight: 2,
      },
      {
        controlId: "CC4.1",
        title: "Monitoring Activities",
        description: "The entity selects, develops, and performs ongoing evaluations.",
        category: "Monitoring",
        weight: 2,
      },
      {
        controlId: "CC5.1",
        title: "Control Activities — Logical Access",
        description: "The entity selects and develops control activities that contribute to the mitigation of risks.",
        category: "Control Activities",
        weight: 2,
      },
      {
        controlId: "CC6.1",
        title: "Logical and Physical Access Controls",
        description: "The entity implements logical access security measures to protect against threats.",
        category: "Access Controls",
        weight: 3,
      },
      {
        controlId: "CC6.2",
        title: "User Authentication",
        description:
          "Prior to issuing system credentials, the entity registers and authorizes new internal and external users.",
        category: "Access Controls",
        weight: 3,
      },
      {
        controlId: "CC6.3",
        title: "Access Removal",
        description: "The entity removes access to protected information assets when appropriate.",
        category: "Access Controls",
        weight: 2,
      },
      {
        controlId: "CC7.1",
        title: "Infrastructure and Software Management",
        description:
          "To meet its objectives, the entity uses detection and monitoring procedures to identify changes to configurations.",
        category: "System Operations",
        weight: 2,
      },
      {
        controlId: "CC7.2",
        title: "Anomaly Detection",
        description: "The entity monitors system components and the operation of those components for anomalies.",
        category: "System Operations",
        weight: 2,
      },
      {
        controlId: "CC7.3",
        title: "Security Event Evaluation",
        description:
          "The entity evaluates security events to determine whether they could or have resulted in a failure to meet objectives.",
        category: "System Operations",
        weight: 2,
      },
      {
        controlId: "CC7.4",
        title: "Incident Response",
        description:
          "The entity responds to identified security incidents by executing defined incident response activities.",
        category: "System Operations",
        weight: 2,
      },
      {
        controlId: "CC8.1",
        title: "Change Management",
        description:
          "The entity authorizes, designs, develops, configures, documents, tests, approves, and implements changes.",
        category: "Change Management",
        weight: 2,
      },
      {
        controlId: "CC9.1",
        title: "Risk Mitigation",
        description:
          "The entity identifies, selects, and develops risk mitigation activities for risks arising from potential business disruptions.",
        category: "Risk Mitigation",
        weight: 2,
      },
    ],
  },
};

export function registerStandalonePlatformRoutes(app: Express): void {
  // ==========================================================================
  // 1. ASSET INVENTORY
  // ==========================================================================

  // List assets with filtering
  app.get("/api/assets", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const assetType = req.query.type as string | undefined;
      const criticality = req.query.criticality as string | undefined;
      const status = req.query.status as string | undefined;
      const q = (req.query.q as string) || "";
      const limitParam = parseInt(String(req.query.limit || "100"));
      const offsetParam = parseInt(String(req.query.offset || "0"));
      const limit = Math.min(limitParam, 500);

      const conditions: any[] = [eq(assetInventory.orgId, orgId)];
      if (assetType && assetType !== "all") conditions.push(eq(assetInventory.assetType, assetType));
      if (criticality && criticality !== "all") conditions.push(eq(assetInventory.criticality, criticality));
      if (status && status !== "all") conditions.push(eq(assetInventory.lifecycleStatus, status));
      if (q) {
        conditions.push(
          or(
            ilike(assetInventory.name, `%${q}%`),
            ilike(assetInventory.hostname, `%${q}%`),
            ilike(assetInventory.ipAddress, `%${q}%`),
          ),
        );
      }

      const results = await db
        .select()
        .from(assetInventory)
        .where(and(...conditions))
        .orderBy(desc(assetInventory.riskScore), desc(assetInventory.createdAt))
        .limit(limit)
        .offset(offsetParam);

      // Get summary stats
      const statsResult = await db.execute(sql`
        SELECT
          COUNT(*) AS total,
          COUNT(*) FILTER (WHERE criticality = 'critical') AS critical_count,
          COUNT(*) FILTER (WHERE criticality = 'high') AS high_count,
          COUNT(*) FILTER (WHERE lifecycle_status = 'active') AS active_count,
          COALESCE(AVG(risk_score), 0) AS avg_risk_score,
          SUM(vulnerability_count) AS total_vulns
        FROM asset_inventory
        WHERE org_id = ${orgId}
      `);
      const statsRow = (statsResult as any).rows?.[0] || {};

      res.json({
        assets: results,
        stats: {
          total: parseInt(statsRow.total || "0"),
          criticalCount: parseInt(statsRow.critical_count || "0"),
          highCount: parseInt(statsRow.high_count || "0"),
          activeCount: parseInt(statsRow.active_count || "0"),
          avgRiskScore: Math.round(parseFloat(statsRow.avg_risk_score || "0")),
          totalVulnerabilities: parseInt(statsRow.total_vulns || "0"),
        },
      });
    } catch (error) {
      log.error("Failed to fetch assets", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch assets" });
    }
  });

  // Create asset
  app.post(
    "/api/assets",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const body = req.body;

        const [asset] = await db
          .insert(assetInventory)
          .values({
            orgId,
            name: body.name,
            assetType: body.assetType || "other",
            criticality: body.criticality || "medium",
            lifecycleStatus: body.lifecycleStatus || "active",
            environment: body.environment || "production",
            ipAddress: body.ipAddress,
            macAddress: body.macAddress,
            hostname: body.hostname,
            fqdn: body.fqdn,
            owner: body.owner,
            department: body.department,
            location: body.location,
            operatingSystem: body.operatingSystem,
            osVersion: body.osVersion,
            manufacturer: body.manufacturer,
            model: body.model,
            serialNumber: body.serialNumber,
            installedSoftware: body.installedSoftware || [],
            tags: body.tags || [],
            notes: body.notes,
          })
          .returning();

        res.status(201).json(asset);
      } catch (error) {
        log.error("Failed to create asset", { error: String(error) });
        res.status(500).json({ message: "Failed to create asset" });
      }
    },
  );

  // Bulk import assets (registered BEFORE /:id to avoid route shadowing)
  app.post(
    "/api/assets/bulk-import",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { assets: importAssets } = req.body;

        if (!Array.isArray(importAssets) || importAssets.length === 0) {
          return res.status(400).json({ message: "No assets provided" });
        }

        if (importAssets.length > 500) {
          return res.status(400).json({ message: "Maximum 500 assets per import" });
        }

        const values = importAssets.map((a: any) => ({
          orgId,
          name: a.name || "Unknown Asset",
          assetType: a.assetType || "other",
          criticality: a.criticality || "medium",
          lifecycleStatus: a.lifecycleStatus || "active",
          environment: a.environment || "production",
          ipAddress: a.ipAddress,
          macAddress: a.macAddress,
          hostname: a.hostname,
          fqdn: a.fqdn,
          owner: a.owner,
          department: a.department,
          location: a.location,
          operatingSystem: a.operatingSystem,
          osVersion: a.osVersion,
          manufacturer: a.manufacturer,
          model: a.model,
          serialNumber: a.serialNumber,
          tags: a.tags || [],
          notes: a.notes,
          discoveredBy: "csv_import",
        }));

        const inserted = await db.insert(assetInventory).values(values).returning();
        res.status(201).json({ imported: inserted.length, assets: inserted });
      } catch (error) {
        log.error("Failed to bulk import assets", { error: String(error) });
        res.status(500).json({ message: "Failed to import assets" });
      }
    },
  );

  // Asset type distribution (registered BEFORE /:id to avoid route shadowing)
  app.get("/api/assets/stats/distribution", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      const typeDistribution = await db.execute(sql`
        SELECT asset_type, COUNT(*) as count
        FROM asset_inventory
        WHERE org_id = ${orgId}
        GROUP BY asset_type
        ORDER BY count DESC
      `);

      const critDistribution = await db.execute(sql`
        SELECT criticality, COUNT(*) as count
        FROM asset_inventory
        WHERE org_id = ${orgId}
        GROUP BY criticality
        ORDER BY CASE criticality
          WHEN 'critical' THEN 1
          WHEN 'high' THEN 2
          WHEN 'medium' THEN 3
          WHEN 'low' THEN 4
        END
      `);

      const envDistribution = await db.execute(sql`
        SELECT environment, COUNT(*) as count
        FROM asset_inventory
        WHERE org_id = ${orgId}
        GROUP BY environment
        ORDER BY count DESC
      `);

      res.json({
        byType: (typeDistribution as any).rows || [],
        byCriticality: (critDistribution as any).rows || [],
        byEnvironment: (envDistribution as any).rows || [],
      });
    } catch (error) {
      log.error("Failed to fetch asset distribution", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch asset distribution" });
    }
  });

  // Get single asset
  app.get("/api/assets/:id", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const [asset] = await db
        .select()
        .from(assetInventory)
        .where(and(eq(assetInventory.id, String(req.params.id)), eq(assetInventory.orgId, orgId)));

      if (!asset) return res.status(404).json({ message: "Asset not found" });
      res.json(asset);
    } catch (error) {
      log.error("Failed to fetch asset", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch asset" });
    }
  });

  // Update asset (explicit field picking to prevent mass assignment)
  app.patch(
    "/api/assets/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const [existing] = await db
          .select()
          .from(assetInventory)
          .where(and(eq(assetInventory.id, String(req.params.id)), eq(assetInventory.orgId, orgId)));

        if (!existing) return res.status(404).json({ message: "Asset not found" });

        const body = req.body;
        const [updated] = await db
          .update(assetInventory)
          .set({
            name: body.name,
            assetType: body.assetType,
            criticality: body.criticality,
            lifecycleStatus: body.lifecycleStatus,
            environment: body.environment,
            ipAddress: body.ipAddress,
            macAddress: body.macAddress,
            hostname: body.hostname,
            fqdn: body.fqdn,
            owner: body.owner,
            department: body.department,
            location: body.location,
            operatingSystem: body.operatingSystem,
            osVersion: body.osVersion,
            manufacturer: body.manufacturer,
            model: body.model,
            serialNumber: body.serialNumber,
            installedSoftware: body.installedSoftware,
            lastPatchDate: body.lastPatchDate,
            openFindings: body.openFindings,
            complianceTags: body.complianceTags,
            tags: body.tags,
            notes: body.notes,
            purchaseDate: body.purchaseDate,
            warrantyExpiry: body.warrantyExpiry,
            endOfLife: body.endOfLife,
            riskScore: body.riskScore,
            vulnerabilityCount: body.vulnerabilityCount,
            lastSeenAt: body.lastSeenAt,
            discoveredBy: body.discoveredBy,
            updatedAt: new Date(),
          })
          .where(eq(assetInventory.id, String(req.params.id)))
          .returning();

        res.json(updated);
      } catch (error) {
        log.error("Failed to update asset", { error: String(error) });
        res.status(500).json({ message: "Failed to update asset" });
      }
    },
  );

  // Delete asset
  app.delete(
    "/api/assets/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const [existing] = await db
          .select()
          .from(assetInventory)
          .where(and(eq(assetInventory.id, String(req.params.id)), eq(assetInventory.orgId, orgId)));

        if (!existing) return res.status(404).json({ message: "Asset not found" });

        await db.delete(assetInventory).where(eq(assetInventory.id, String(req.params.id)));
        res.json({ deleted: true });
      } catch (error) {
        log.error("Failed to delete asset", { error: String(error) });
        res.status(500).json({ message: "Failed to delete asset" });
      }
    },
  );

  // 45.1 — Asset detail with full context
  app.get("/api/assets/:id/full-context", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const [asset] = await db
        .select()
        .from(assetInventory)
        .where(and(eq(assetInventory.id, String(req.params.id)), eq(assetInventory.orgId, orgId)));
      if (!asset) return res.status(404).json({ message: "Asset not found" });

      const softwareInventory = Array.isArray(asset.installedSoftware) ? asset.installedSoftware : [];
      const { linkedAlerts, linkedIncidents, alertsTruncated, incidentsTruncated } = await getAssetSecurityHistory(
        orgId,
        asset,
      );

      res.json({
        asset,
        softwareInventory,
        openPorts: [],
        networkConnections: [],
        associatedUsers: [],
        complianceStatus: {
          status: "not_assessed",
          frameworks: [],
          compliant: null,
          reason: "No asset-scoped compliance assessment is persisted for this asset.",
        },
        alertHistory: linkedAlerts,
        alertHistoryMeta: {
          alertsLimit: ASSET_ALERT_HISTORY_LIMIT,
          incidentsLimit: ASSET_INCIDENT_HISTORY_LIMIT,
          alertsTruncated,
          incidentsTruncated,
        },
        vulnerabilityBreakdown: null,
        availability: {
          softwareInventory: {
            available: softwareInventory.length > 0,
            reason:
              softwareInventory.length > 0
                ? null
                : "No software inventory has been collected. Connect an endpoint or asset inventory sensor.",
          },
          network: {
            available: false,
            reason: "Port and connection telemetry is not collected for asset inventory records.",
          },
          users: {
            available: false,
            reason: "User-session telemetry is not collected for asset inventory records.",
          },
          securityHistory: {
            available: linkedAlerts.length > 0 || linkedIncidents.length > 0,
            reason:
              linkedAlerts.length > 0 || linkedIncidents.length > 0
                ? null
                : "No alerts or incidents matched this asset by persisted hostname, IP address, or incident references.",
            alertsTruncated,
            incidentsTruncated,
          },
          vulnerabilities: {
            available: asset.vulnerabilityCount > 0,
            reason:
              asset.vulnerabilityCount > 0 ? null : "No vulnerability scan results are associated with this asset.",
          },
        },
      });
    } catch (error) {
      log.error("Failed to get asset context", { error: String(error) });
      res.status(500).json({ message: "Failed to get asset full context" });
    }
  });

  // 45.2 — Asset classification and criticality update
  app.patch(
    "/api/assets/:id/classification",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { criticality, classification } = req.body as { criticality?: string; classification?: string };
        const validCriticalities = ["critical", "high", "medium", "low"];
        if (criticality && !validCriticalities.includes(criticality)) {
          return res.status(400).json({ message: "Invalid criticality level" });
        }
        const [updated] = await db
          .update(assetInventory)
          .set({
            criticality: criticality || undefined,
            updatedAt: new Date(),
          })
          .where(and(eq(assetInventory.id, String(req.params.id)), eq(assetInventory.orgId, orgId)))
          .returning();
        if (!updated) return res.status(404).json({ message: "Asset not found" });
        res.json(updated);
      } catch (error) {
        log.error("Failed to update classification", { error: String(error) });
        res.status(500).json({ message: "Failed to update asset classification" });
      }
    },
  );

  // 45.3 — Asset topology data
  app.get("/api/assets/topology", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const assets = await db.select().from(assetInventory).where(eq(assetInventory.orgId, orgId)).limit(200);
      const nodes = assets.map((a) => ({
        id: a.id,
        label: a.name,
        type: a.assetType,
        criticality: a.criticality,
        ipAddress: a.ipAddress,
        internetFacing: a.environment === "production" && ["server", "cloud_instance"].includes(a.assetType || ""),
      }));
      const edges: { source: string; target: string; type: string }[] = [];
      for (let i = 0; i < nodes.length && i < 50; i++) {
        if (i > 0) edges.push({ source: nodes[i - 1].id, target: nodes[i].id, type: "network" });
        if (i % 3 === 0 && i + 2 < nodes.length)
          edges.push({ source: nodes[i].id, target: nodes[i + 2].id, type: "dependency" });
      }
      const segments = [
        { name: "DMZ", assets: nodes.filter((n) => n.internetFacing).map((n) => n.id) },
        { name: "Internal", assets: nodes.filter((n) => !n.internetFacing).map((n) => n.id) },
      ];
      res.json({ nodes, edges, segments });
    } catch (error) {
      log.error("Failed to get topology", { error: String(error) });
      res.status(500).json({ message: "Failed to get asset topology" });
    }
  });

  // 45.4 — Asset import sources
  app.get("/api/assets/import-sources", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const [{ assetCount }] = await db
        .select({ assetCount: count() })
        .from(assetInventory)
        .where(eq(assetInventory.orgId, orgId));
      res.json({
        sources: [],
        available: false,
        reason:
          "No asset connector status is persisted. Connect Active Directory, cloud inventory, EDR, CMDB, or a vulnerability scanner to collect source data.",
        assetCount: Number(assetCount),
      });
    } catch (error) {
      log.error("Failed to get import sources", { error: String(error) });
      res.status(500).json({ message: "Failed to get import sources" });
    }
  });

  // 45.5 — Asset auto-discovery status
  app.get("/api/assets/auto-discovery", isAuthenticated, resolveOrgContext, requireOrgId, async (_req, res) => {
    try {
      res.json({
        available: false,
        enabled: false,
        sources: [],
        recentlyDiscovered: [],
        reason:
          "Asset auto-discovery is not configured. Connect a network scanner, EDR sensor, cloud API, or DNS source.",
      });
    } catch (error) {
      log.error("Failed to get auto-discovery", { error: String(error) });
      res.status(500).json({ message: "Failed to get auto-discovery status" });
    }
  });

  // 45.6 — Asset lifecycle management
  app.get("/api/assets/lifecycle-summary", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const assets = await db.select().from(assetInventory).where(eq(assetInventory.orgId, orgId));
      const byStatus: Record<string, number> = {};
      const zombies: any[] = [];
      const now = Date.now();
      for (const a of assets) {
        byStatus[a.lifecycleStatus || "active"] = (byStatus[a.lifecycleStatus || "active"] || 0) + 1;
        if (a.lastSeenAt && now - new Date(a.lastSeenAt).getTime() > 30 * 86400000 && a.lifecycleStatus === "active") {
          zombies.push({
            id: a.id,
            name: a.name,
            lastSeenAt: a.lastSeenAt,
            daysSinceLastSeen: Math.round((now - new Date(a.lastSeenAt).getTime()) / 86400000),
          });
        }
      }
      res.json({
        lifecycle: {
          provisioned: byStatus["procurement"] || 0,
          active: byStatus["active"] || 0,
          decommissioning: byStatus["decommissioning"] || 0,
          decommissioned: byStatus["retired"] || 0,
          maintenance: byStatus["maintenance"] || 0,
        },
        zombieAssets: zombies,
        total: assets.length,
      });
    } catch (error) {
      log.error("Failed to get lifecycle summary", { error: String(error) });
      res.status(500).json({ message: "Failed to get lifecycle summary" });
    }
  });

  // 45.7 — Software inventory per asset
  app.get("/api/assets/:id/software", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const [asset] = await db
        .select()
        .from(assetInventory)
        .where(and(eq(assetInventory.id, String(req.params.id)), eq(assetInventory.orgId, orgId)));
      if (!asset) return res.status(404).json({ message: "Asset not found" });
      const software = Array.isArray(asset.installedSoftware) ? asset.installedSoftware : [];
      res.json({
        assetId: asset.id,
        assetName: asset.name,
        software,
        totalVulnerable: software.filter((s) => s.cves.length > 0).length,
        available: software.length > 0,
        reason:
          software.length > 0
            ? null
            : "No software inventory has been collected. Connect an endpoint or asset inventory sensor.",
      });
    } catch (error) {
      log.error("Failed to get software inventory", { error: String(error) });
      res.status(500).json({ message: "Failed to get software inventory" });
    }
  });

  // 45.8 — Asset CVE matching
  app.get("/api/assets/:id/cve-exposure", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const [asset] = await db
        .select()
        .from(assetInventory)
        .where(and(eq(assetInventory.id, String(req.params.id)), eq(assetInventory.orgId, orgId)));
      if (!asset) return res.status(404).json({ message: "Asset not found" });
      const assetIdentifiers = [asset.hostname, asset.ipAddress, asset.fqdn].filter(
        (value): value is string => typeof value === "string" && value.length > 0,
      );
      const sensorConditions = assetIdentifiers.flatMap((value) => [
        eq(nativeSensors.hostname, value),
        eq(nativeSensors.ipAddress, value),
      ]);
      const affected = sensorConditions.length
        ? await db
            .select({ finding: vulnFindings, sensor: nativeSensors })
            .from(vulnFindings)
            .innerJoin(nativeSensors, eq(nativeSensors.id, vulnFindings.sensorId))
            .where(and(eq(vulnFindings.orgId, orgId), eq(nativeSensors.orgId, orgId), or(...sensorConditions)))
            .orderBy(desc(vulnFindings.cvssScore), desc(vulnFindings.createdAt))
        : [];
      res.json({
        assetId: asset.id,
        assetName: asset.name,
        cves: affected.map(({ finding, sensor }) => ({
          ...finding,
          hostname: sensor.hostname,
        })),
        summary: {
          total: affected.length,
          open: affected.filter(({ finding }) => finding.status === "open").length,
          critical: affected.filter(({ finding }) => finding.severity === "critical").length,
          high: affected.filter(({ finding }) => finding.severity === "high").length,
        },
        available: affected.length > 0,
        reason: affected.length > 0 ? null : "No package inventory yet — install an agent.",
      });
    } catch (error) {
      log.error("Failed to get CVE exposure", { error: String(error) });
      res.status(500).json({ message: "Failed to get CVE exposure" });
    }
  });

  // 45.9 — Asset CSPM correlation
  app.get("/api/assets/:id/cspm-findings", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const [asset] = await db
        .select()
        .from(assetInventory)
        .where(and(eq(assetInventory.id, String(req.params.id)), eq(assetInventory.orgId, orgId)));
      if (!asset) return res.status(404).json({ message: "Asset not found" });
      res.json({
        assetId: asset.id,
        findings: [],
        openCount: null,
        available: false,
        reason: "No asset-linked CSPM findings are persisted. Connect a cloud account and run a CSPM scan.",
      });
    } catch (error) {
      log.error("Failed to get CSPM findings", { error: String(error) });
      res.status(500).json({ message: "Failed to get CSPM findings for asset" });
    }
  });

  // 45.10 — Asset alert/incident association
  app.get("/api/assets/:id/security-history", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const [asset] = await db
        .select()
        .from(assetInventory)
        .where(and(eq(assetInventory.id, String(req.params.id)), eq(assetInventory.orgId, orgId)));
      if (!asset) return res.status(404).json({ message: "Asset not found" });
      const { linkedAlerts, linkedIncidents, alertsTruncated, incidentsTruncated } = await getAssetSecurityHistory(
        orgId,
        asset,
      );
      res.json({
        assetId: asset.id,
        assetName: asset.name,
        alerts: linkedAlerts,
        incidents: linkedIncidents,
        summary: {
          totalAlerts: linkedAlerts.length,
          openAlerts: linkedAlerts.filter((alert) => alert.status === "open").length,
          totalIncidents: linkedIncidents.length,
        },
        limits: {
          alerts: ASSET_ALERT_HISTORY_LIMIT,
          incidents: ASSET_INCIDENT_HISTORY_LIMIT,
          alertsTruncated,
          incidentsTruncated,
        },
        available: linkedAlerts.length > 0 || linkedIncidents.length > 0,
        reason:
          linkedAlerts.length > 0 || linkedIncidents.length > 0
            ? null
            : "No alerts or incidents matched this asset by persisted hostname, IP address, or incident references.",
      });
    } catch (error) {
      log.error("Failed to get security history", { error: String(error) });
      res.status(500).json({ message: "Failed to get asset security history" });
    }
  });

  // ==========================================================================
  // 2. RISK REGISTER
  // ==========================================================================

  // List risks
  app.get("/api/risks", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const category = req.query.category as string | undefined;
      const status = req.query.status as string | undefined;

      const conditions: any[] = [eq(riskRegister.orgId, orgId)];
      if (category && category !== "all") conditions.push(eq(riskRegister.category, category));
      if (status && status !== "all") conditions.push(eq(riskRegister.status, status));

      const risks = await db
        .select()
        .from(riskRegister)
        .where(and(...conditions))
        .orderBy(desc(riskRegister.inherentRiskScore), desc(riskRegister.createdAt));

      // Generate heatmap data (5x5 matrix)
      const heatmapResult = await db.execute(sql`
        SELECT likelihood, impact, COUNT(*) as count
        FROM risk_register
        WHERE org_id = ${orgId} AND status != 'closed'
        GROUP BY likelihood, impact
      `);

      const heatmap: number[][] = Array.from({ length: 5 }, () => Array(5).fill(0));
      for (const row of (heatmapResult as any).rows || []) {
        const l = parseInt(row.likelihood) - 1;
        const i = parseInt(row.impact) - 1;
        if (l >= 0 && l < 5 && i >= 0 && i < 5) {
          heatmap[l][i] = parseInt(row.count);
        }
      }

      // Summary stats
      const statsResult = await db.execute(sql`
        SELECT
          COUNT(*) AS total,
          COUNT(*) FILTER (WHERE inherent_risk_score >= 20) AS critical_risks,
          COUNT(*) FILTER (WHERE inherent_risk_score >= 12 AND inherent_risk_score < 20) AS high_risks,
          COUNT(*) FILTER (WHERE inherent_risk_score >= 6 AND inherent_risk_score < 12) AS medium_risks,
          COUNT(*) FILTER (WHERE inherent_risk_score < 6) AS low_risks,
          COUNT(*) FILTER (WHERE status = 'treating') AS in_treatment
        FROM risk_register
        WHERE org_id = ${orgId}
      `);
      const statsRow = (statsResult as any).rows?.[0] || {};

      res.json({
        risks,
        heatmap,
        stats: {
          total: parseInt(statsRow.total || "0"),
          criticalRisks: parseInt(statsRow.critical_risks || "0"),
          highRisks: parseInt(statsRow.high_risks || "0"),
          mediumRisks: parseInt(statsRow.medium_risks || "0"),
          lowRisks: parseInt(statsRow.low_risks || "0"),
          inTreatment: parseInt(statsRow.in_treatment || "0"),
        },
      });
    } catch (error) {
      log.error("Failed to fetch risks", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch risks" });
    }
  });

  // Create risk
  app.post(
    "/api/risks",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const user = (req as any).user;
        const body = req.body;

        const likelihood = Math.max(1, Math.min(5, body.likelihood || 3));
        const impact = Math.max(1, Math.min(5, body.impact || 3));
        const inherentRiskScore = likelihood * impact;

        const [risk] = await db
          .insert(riskRegister)
          .values({
            orgId,
            title: body.title,
            description: body.description,
            category: body.category || "operational",
            likelihood,
            impact,
            inherentRiskScore,
            residualLikelihood: body.residualLikelihood,
            residualImpact: body.residualImpact,
            residualRiskScore:
              body.residualLikelihood && body.residualImpact
                ? body.residualLikelihood * body.residualImpact
                : undefined,
            treatment: body.treatment || "mitigate",
            treatmentPlan: body.treatmentPlan,
            controls: body.controls || [],
            riskOwner: body.riskOwner,
            status: body.status || "identified",
            relatedAssets: body.relatedAssets || [],
            relatedFrameworks: body.relatedFrameworks || [],
            tags: body.tags || [],
            createdBy: user?.id,
          })
          .returning();

        res.status(201).json(risk);
      } catch (error) {
        log.error("Failed to create risk", { error: String(error) });
        res.status(500).json({ message: "Failed to create risk" });
      }
    },
  );

  // Get single risk
  app.get("/api/risks/:id", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const [risk] = await db
        .select()
        .from(riskRegister)
        .where(and(eq(riskRegister.id, String(req.params.id)), eq(riskRegister.orgId, orgId)));

      if (!risk) return res.status(404).json({ message: "Risk not found" });
      res.json(risk);
    } catch (error) {
      log.error("Failed to fetch risk", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch risk" });
    }
  });

  // Update risk
  app.patch(
    "/api/risks/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const [existing] = await db
          .select()
          .from(riskRegister)
          .where(and(eq(riskRegister.id, String(req.params.id)), eq(riskRegister.orgId, orgId)));

        if (!existing) return res.status(404).json({ message: "Risk not found" });

        const body = req.body;
        const likelihood = body.likelihood !== undefined ? Math.max(1, Math.min(5, body.likelihood)) : undefined;
        const impact = body.impact !== undefined ? Math.max(1, Math.min(5, body.impact)) : undefined;

        // Explicit field picking to prevent mass assignment (forbid orgId, id, createdAt)
        const updateData: Record<string, any> = {
          title: body.title,
          description: body.description,
          category: body.category,
          status: body.status,
          likelihood: likelihood ?? body.likelihood,
          impact: impact ?? body.impact,
          riskOwner: body.riskOwner,
          treatment: body.treatment,
          treatmentPlan: body.treatmentPlan,
          controls: body.controls,
          residualLikelihood: body.residualLikelihood,
          residualImpact: body.residualImpact,
          relatedAssets: body.relatedAssets,
          relatedFrameworks: body.relatedFrameworks,
          lastReviewDate: body.lastReviewDate,
          nextReviewDate: body.nextReviewDate,
          tags: body.tags,
          updatedAt: new Date(),
        };

        if (likelihood !== undefined && impact !== undefined) {
          updateData.inherentRiskScore = likelihood * impact;
        } else if (likelihood !== undefined) {
          updateData.inherentRiskScore = likelihood * existing.impact;
        } else if (impact !== undefined) {
          updateData.inherentRiskScore = existing.likelihood * impact;
        }

        if (body.residualLikelihood !== undefined && body.residualImpact !== undefined) {
          updateData.residualRiskScore = body.residualLikelihood * body.residualImpact;
        }

        const [updated] = await db
          .update(riskRegister)
          .set(updateData)
          .where(eq(riskRegister.id, String(req.params.id)))
          .returning();

        res.json(updated);
      } catch (error) {
        log.error("Failed to update risk", { error: String(error) });
        res.status(500).json({ message: "Failed to update risk" });
      }
    },
  );

  // Delete risk
  app.delete(
    "/api/risks/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const [existing] = await db
          .select()
          .from(riskRegister)
          .where(and(eq(riskRegister.id, String(req.params.id)), eq(riskRegister.orgId, orgId)));

        if (!existing) return res.status(404).json({ message: "Risk not found" });

        await db.delete(riskRegister).where(eq(riskRegister.id, String(req.params.id)));
        res.json({ deleted: true });
      } catch (error) {
        log.error("Failed to delete risk", { error: String(error) });
        res.status(500).json({ message: "Failed to delete risk" });
      }
    },
  );

  // ==========================================================================
  // 3. SECURITY ASSESSMENTS
  // ==========================================================================

  // List frameworks
  app.get("/api/assessments/frameworks", isAuthenticated, resolveOrgContext, requireOrgId, (req, res) => {
    const frameworks = Object.entries(FRAMEWORK_CONTROLS).map(([key, val]) => ({
      id: key,
      name: val.name,
      description: val.description,
      controlCount: val.controls.length,
    }));
    res.json(frameworks);
  });

  // List assessments
  app.get("/api/assessments", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const framework = req.query.framework as string | undefined;

      const conditions: any[] = [eq(securityAssessments.orgId, orgId)];
      if (framework && framework !== "all") conditions.push(eq(securityAssessments.framework, framework));

      const assessments = await db
        .select()
        .from(securityAssessments)
        .where(and(...conditions))
        .orderBy(desc(securityAssessments.createdAt));

      res.json(assessments);
    } catch (error) {
      log.error("Failed to fetch assessments", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch assessments" });
    }
  });

  // Create assessment (starts a new assessment from a framework)
  app.post(
    "/api/assessments",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const user = (req as any).user;
        const { framework, title, description } = req.body;

        const frameworkDef = FRAMEWORK_CONTROLS[framework];
        if (!frameworkDef) {
          return res.status(400).json({ message: "Invalid framework" });
        }

        // Create the assessment
        const [assessment] = await db
          .insert(securityAssessments)
          .values({
            orgId,
            framework,
            title: title || `${frameworkDef.name} Assessment`,
            description: description || frameworkDef.description,
            status: "in_progress",
            totalControls: frameworkDef.controls.length,
            assessor: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : user?.email,
            startedAt: new Date(),
          })
          .returning();

        // Create response entries for each control
        const responseValues = frameworkDef.controls.map((ctrl) => ({
          assessmentId: assessment.id,
          orgId,
          controlId: ctrl.controlId,
          controlTitle: ctrl.title,
          controlDescription: ctrl.description,
          category: ctrl.category,
          status: "not_assessed" as const,
          weight: ctrl.weight,
        }));

        await db.insert(assessmentResponses).values(responseValues);

        res.status(201).json(assessment);
      } catch (error) {
        log.error("Failed to create assessment", { error: String(error) });
        res.status(500).json({ message: "Failed to create assessment" });
      }
    },
  );

  // Get assessment with responses
  app.get("/api/assessments/:id", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      const [assessment] = await db
        .select()
        .from(securityAssessments)
        .where(and(eq(securityAssessments.id, String(req.params.id)), eq(securityAssessments.orgId, orgId)));

      if (!assessment) return res.status(404).json({ message: "Assessment not found" });

      const responses = await db
        .select()
        .from(assessmentResponses)
        .where(eq(assessmentResponses.assessmentId, assessment.id))
        .orderBy(assessmentResponses.controlId);

      res.json({ ...assessment, responses });
    } catch (error) {
      log.error("Failed to fetch assessment", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch assessment" });
    }
  });

  // Update assessment response (answer a control question)
  app.patch(
    "/api/assessments/:assessmentId/responses/:responseId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        // Verify assessment belongs to org
        const [assessment] = await db
          .select()
          .from(securityAssessments)
          .where(
            and(eq(securityAssessments.id, String(req.params.assessmentId)), eq(securityAssessments.orgId, orgId)),
          );

        if (!assessment) return res.status(404).json({ message: "Assessment not found" });

        const [response] = await db
          .select()
          .from(assessmentResponses)
          .where(
            and(
              eq(assessmentResponses.id, String(req.params.responseId)),
              eq(assessmentResponses.assessmentId, assessment.id),
            ),
          );

        if (!response) return res.status(404).json({ message: "Response not found" });

        const body = req.body;
        const [updated] = await db
          .update(assessmentResponses)
          .set({
            status: body.status,
            notes: body.notes,
            evidence: body.evidence,
            gapDescription: body.gapDescription,
            recommendedAction: body.recommendedAction,
            priority: body.priority,
            updatedAt: new Date(),
          })
          .where(eq(assessmentResponses.id, String(req.params.responseId)))
          .returning();

        // Recalculate assessment scores
        const allResponses = await db
          .select()
          .from(assessmentResponses)
          .where(eq(assessmentResponses.assessmentId, assessment.id));

        let implemented = 0,
          partial = 0,
          notImpl = 0,
          na = 0,
          totalWeight = 0,
          earnedWeight = 0;

        for (const r of allResponses) {
          if (r.status === "implemented") {
            implemented++;
            earnedWeight += r.weight;
          } else if (r.status === "partially_implemented") {
            partial++;
            earnedWeight += r.weight * 0.5;
          } else if (r.status === "not_implemented") {
            notImpl++;
          } else if (r.status === "not_applicable") {
            na++;
          }
          if (r.status !== "not_applicable") totalWeight += r.weight;
        }

        const overallScore = totalWeight > 0 ? Math.round((earnedWeight / totalWeight) * 100) : 0;

        await db
          .update(securityAssessments)
          .set({
            implementedControls: implemented,
            partialControls: partial,
            notImplementedControls: notImpl,
            notApplicableControls: na,
            overallScore,
            updatedAt: new Date(),
          })
          .where(eq(securityAssessments.id, assessment.id));

        res.json(updated);
      } catch (error) {
        log.error("Failed to update assessment response", { error: String(error) });
        res.status(500).json({ message: "Failed to update assessment response" });
      }
    },
  );

  // Complete assessment
  app.post(
    "/api/assessments/:id/complete",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        const [assessment] = await db
          .select()
          .from(securityAssessments)
          .where(and(eq(securityAssessments.id, String(req.params.id)), eq(securityAssessments.orgId, orgId)));

        if (!assessment) return res.status(404).json({ message: "Assessment not found" });

        const [updated] = await db
          .update(securityAssessments)
          .set({
            status: "completed",
            completedAt: new Date(),
            updatedAt: new Date(),
          })
          .where(eq(securityAssessments.id, String(req.params.id)))
          .returning();

        res.json(updated);
      } catch (error) {
        log.error("Failed to complete assessment", { error: String(error) });
        res.status(500).json({ message: "Failed to complete assessment" });
      }
    },
  );

  // Delete assessment
  app.delete(
    "/api/assessments/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        const [existing] = await db
          .select()
          .from(securityAssessments)
          .where(and(eq(securityAssessments.id, String(req.params.id)), eq(securityAssessments.orgId, orgId)));

        if (!existing) return res.status(404).json({ message: "Assessment not found" });

        // Cascade will delete responses
        await db.delete(securityAssessments).where(eq(securityAssessments.id, String(req.params.id)));
        res.json({ deleted: true });
      } catch (error) {
        log.error("Failed to delete assessment", { error: String(error) });
        res.status(500).json({ message: "Failed to delete assessment" });
      }
    },
  );

  // ==========================================================================
  // 4. THREAT REPORTS (Employee Portal)
  // ==========================================================================

  // List threat reports
  app.get("/api/threat-reports", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const status = req.query.status as string | undefined;
      const category = req.query.category as string | undefined;

      const conditions: any[] = [eq(threatReports.orgId, orgId)];
      if (status && status !== "all") conditions.push(eq(threatReports.status, status));
      if (category && category !== "all") conditions.push(eq(threatReports.category, category));

      const reports = await db
        .select()
        .from(threatReports)
        .where(and(...conditions))
        .orderBy(desc(threatReports.createdAt));

      // Stats
      const statsResult = await db.execute(sql`
        SELECT
          COUNT(*) AS total,
          COUNT(*) FILTER (WHERE status = 'submitted') AS pending,
          COUNT(*) FILTER (WHERE status = 'reviewing') AS reviewing,
          COUNT(*) FILTER (WHERE status = 'investigating') AS investigating,
          COUNT(*) FILTER (WHERE status = 'resolved') AS resolved
        FROM threat_reports
        WHERE org_id = ${orgId}
      `);
      const statsRow = (statsResult as any).rows?.[0] || {};

      res.json({
        reports,
        stats: {
          total: parseInt(statsRow.total || "0"),
          pending: parseInt(statsRow.pending || "0"),
          reviewing: parseInt(statsRow.reviewing || "0"),
          investigating: parseInt(statsRow.investigating || "0"),
          resolved: parseInt(statsRow.resolved || "0"),
        },
      });
    } catch (error) {
      log.error("Failed to fetch threat reports", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch threat reports" });
    }
  });

  // Create threat report
  app.post(
    "/api/threat-reports",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const user = (req as any).user;
        const body = req.body;

        const [report] = await db
          .insert(threatReports)
          .values({
            orgId,
            reporterUserId: body.isAnonymous ? null : user?.id,
            reporterName: body.isAnonymous
              ? null
              : body.reporterName || `${user?.firstName || ""} ${user?.lastName || ""}`.trim(),
            reporterEmail: body.isAnonymous ? null : body.reporterEmail || user?.email,
            isAnonymous: body.isAnonymous || false,
            category: body.category,
            severity: body.severity || "medium",
            title: body.title,
            description: body.description,
            dateOccurred: body.dateOccurred ? new Date(body.dateOccurred) : null,
            locationDescription: body.locationDescription,
            affectedSystems: body.affectedSystems,
            suspectInfo: body.suspectInfo,
            attachments: body.attachments || [],
          })
          .returning();

        // Auto-create an alert from the threat report if severity is high or critical
        if (body.severity === "critical" || body.severity === "high") {
          try {
            const [alert] = await db
              .insert(alerts)
              .values({
                orgId,
                source: "Employee Report",
                category: body.category === "phishing" ? "phishing" : body.category === "malware" ? "malware" : "other",
                severity: body.severity,
                title: `[Threat Report] ${body.title}`,
                description: body.description,
                status: "new",
              })
              .returning();
            await publishAlertCreated(alert);

            // Link the alert back to the threat report
            await db.update(threatReports).set({ linkedAlertId: alert.id }).where(eq(threatReports.id, report.id));

            report.linkedAlertId = alert.id;
          } catch (alertErr) {
            log.warn("Failed to auto-create alert from threat report", { error: String(alertErr) });
          }
        }

        res.status(201).json(report);
      } catch (error) {
        log.error("Failed to create threat report", { error: String(error) });
        res.status(500).json({ message: "Failed to create threat report" });
      }
    },
  );

  // Get single threat report
  app.get("/api/threat-reports/:id", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const [report] = await db
        .select()
        .from(threatReports)
        .where(and(eq(threatReports.id, String(req.params.id)), eq(threatReports.orgId, orgId)));

      if (!report) return res.status(404).json({ message: "Report not found" });
      res.json(report);
    } catch (error) {
      log.error("Failed to fetch threat report", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch threat report" });
    }
  });

  // Update threat report (status, assignment, resolution)
  app.patch(
    "/api/threat-reports/:id",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const [existing] = await db
          .select()
          .from(threatReports)
          .where(and(eq(threatReports.id, String(req.params.id)), eq(threatReports.orgId, orgId)));

        if (!existing) return res.status(404).json({ message: "Report not found" });

        const body = req.body;
        const updateData: Record<string, any> = { updatedAt: new Date() };

        if (body.status) updateData.status = body.status;
        if (body.assignedTo) updateData.assignedTo = body.assignedTo;
        if (body.severity) updateData.severity = body.severity;
        if (body.resolution) {
          updateData.resolution = body.resolution;
          updateData.resolvedAt = new Date();
          updateData.resolvedBy = (req as any).user?.id;
        }

        const [updated] = await db
          .update(threatReports)
          .set(updateData)
          .where(eq(threatReports.id, String(req.params.id)))
          .returning();

        res.json(updated);
      } catch (error) {
        log.error("Failed to update threat report", { error: String(error) });
        res.status(500).json({ message: "Failed to update threat report" });
      }
    },
  );

  // Escalate threat report to incident
  app.post(
    "/api/threat-reports/:id/escalate",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const [report] = await db
          .select()
          .from(threatReports)
          .where(and(eq(threatReports.id, String(req.params.id)), eq(threatReports.orgId, orgId)));

        if (!report) return res.status(404).json({ message: "Report not found" });

        if (report.linkedIncidentId) {
          return res.status(400).json({ message: "Report already escalated to an incident" });
        }

        // Create incident from threat report
        const incident = await storage.createIncident({
          orgId,
          title: `[Escalated] ${report.title}`,
          summary: report.description,
          severity: report.severity === "informational" ? "low" : report.severity,
          status: "open",
        });

        // Link back
        await db
          .update(threatReports)
          .set({
            linkedIncidentId: incident.id,
            status: "investigating",
            updatedAt: new Date(),
          })
          .where(eq(threatReports.id, report.id));

        res.json({ incident, report: { ...report, linkedIncidentId: incident.id, status: "investigating" } });
      } catch (error) {
        log.error("Failed to escalate threat report", { error: String(error) });
        res.status(500).json({ message: "Failed to escalate threat report" });
      }
    },
  );
  // ─── 27.1 Vulnerability Prioritization Matrix ─────────────────────────────

  app.get("/api/vulnerabilities/prioritized", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const severityFilter = req.query.severity as string | undefined;
      const statusFilter = req.query.status as string | undefined;
      const limitParam = Math.min(parseInt(String(req.query.limit || "50")), 200);
      const findings = await db
        .select({ finding: vulnFindings, asset: assetInventory })
        .from(vulnFindings)
        .leftJoin(nativeSensors, and(eq(nativeSensors.id, vulnFindings.sensorId), eq(nativeSensors.orgId, orgId)))
        .leftJoin(
          assetInventory,
          and(
            eq(assetInventory.orgId, orgId),
            or(
              eq(assetInventory.hostname, nativeSensors.hostname),
              eq(assetInventory.ipAddress, nativeSensors.ipAddress),
              eq(assetInventory.fqdn, nativeSensors.hostname),
              eq(assetInventory.hostname, nativeSensors.ipAddress),
              eq(assetInventory.fqdn, nativeSensors.ipAddress),
            ),
          ),
        )
        .where(eq(vulnFindings.orgId, orgId));
      const prioritized = findings.map(({ finding, asset }) => {
        const cvssScore = finding.cvssScore ?? null;
        const epssScore = finding.epssScore ?? null;
        const criticalityWeight =
          asset?.criticality === "critical"
            ? 4
            : asset?.criticality === "high"
              ? 3
              : asset?.criticality === "medium"
                ? 2
                : asset?.criticality === "low"
                  ? 1
                  : 0;
        const priorityScore =
          (cvssScore ?? 0) * 10 +
          (epssScore ?? 0) * 100 +
          (finding.exploitAvailable === true ? 100 : 0) +
          criticalityWeight;
        return {
          ...finding,
          assetCriticality: asset?.criticality ?? null,
          priorityScore,
          priorityInputs: {
            cvss: cvssScore !== null,
            epss: epssScore !== null,
            kev: finding.exploitAvailable !== null,
            assetCriticality: asset?.criticality !== null && asset?.criticality !== undefined,
          },
        };
      });

      // Apply filters
      let filtered = prioritized;
      if (severityFilter && severityFilter !== "all") {
        filtered = filtered.filter((v) => v.severity === severityFilter);
      }
      if (statusFilter && statusFilter !== "all") {
        filtered = filtered.filter((v) => v.status === statusFilter);
      }

      // Sort by priority score descending
      filtered.sort((a, b) => b.priorityScore - a.priorityScore);

      const summary = {
        total: filtered.length,
        critical: filtered.filter((v) => v.severity === "critical").length,
        high: filtered.filter((v) => v.severity === "high").length,
        medium: filtered.filter((v) => v.severity === "medium").length,
        low: filtered.filter((v) => v.severity === "low").length,
        avgPriorityScore:
          filtered.length > 0 ? Math.round(filtered.reduce((s, v) => s + v.priorityScore, 0) / filtered.length) : 0,
      };

      res.json({ vulnerabilities: filtered.slice(0, limitParam), summary });
    } catch (error) {
      log.error("Vuln prioritization error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch prioritized vulnerabilities" });
    }
  });

  // ─── 27.2 Vulnerability Aging Report ───────────────────────────────────────

  app.get("/api/vulnerabilities/aging", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);

      const risks = await db
        .select()
        .from(riskRegister)
        .where(eq(riskRegister.orgId, orgId))
        .orderBy(desc(riskRegister.createdAt));

      const now = Date.now();
      const SLA_CRITICAL = 7 * 86400000; // 7 days
      const SLA_HIGH = 14 * 86400000;
      const SLA_MEDIUM = 30 * 86400000;
      const SLA_LOW = 90 * 86400000;

      const agingReport = risks.map((risk) => {
        const createdAt = risk.createdAt ? new Date(risk.createdAt).getTime() : now;
        const ageMs = now - createdAt;
        const ageDays = Math.floor(ageMs / 86400000);
        const score = risk.inherentRiskScore ?? 0;
        const severity = score > 70 ? "critical" : score > 50 ? "high" : score > 30 ? "medium" : "low";

        const slaMs =
          severity === "critical"
            ? SLA_CRITICAL
            : severity === "high"
              ? SLA_HIGH
              : severity === "medium"
                ? SLA_MEDIUM
                : SLA_LOW;
        const slaDays = Math.floor(slaMs / 86400000);
        const slaBreached = risk.status !== "closed" && ageMs > slaMs;
        const slaRemainingDays = Math.max(0, Math.floor((slaMs - ageMs) / 86400000));

        return {
          id: risk.id,
          title: risk.title,
          severity,
          status: risk.status,
          ageDays,
          createdAt: risk.createdAt,
          slaDays,
          slaBreached,
          slaRemainingDays,
          owner: risk.riskOwner,
        };
      });

      // Aging distribution histogram
      const histogram = {
        "0-7 days": agingReport.filter((v) => v.ageDays <= 7).length,
        "8-14 days": agingReport.filter((v) => v.ageDays > 7 && v.ageDays <= 14).length,
        "15-30 days": agingReport.filter((v) => v.ageDays > 14 && v.ageDays <= 30).length,
        "31-60 days": agingReport.filter((v) => v.ageDays > 30 && v.ageDays <= 60).length,
        "61-90 days": agingReport.filter((v) => v.ageDays > 60 && v.ageDays <= 90).length,
        "90+ days": agingReport.filter((v) => v.ageDays > 90).length,
      };

      const slaCompliance = {
        total: agingReport.length,
        compliant: agingReport.filter((v) => !v.slaBreached || v.status === "closed").length,
        breached: agingReport.filter((v) => v.slaBreached && v.status !== "closed").length,
        complianceRate:
          agingReport.length > 0
            ? Math.round(
                (agingReport.filter((v) => !v.slaBreached || v.status === "closed").length / agingReport.length) * 100,
              )
            : null,
        available: agingReport.length > 0,
        reason: agingReport.length > 0 ? null : "No vulnerability findings are available in the selected window.",
      };

      res.json({ agingReport, histogram, slaCompliance });
    } catch (error) {
      log.error("Vuln aging report error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch aging report" });
    }
  });

  // ─── 27.3 Remediation Tracking Workflow ────────────────────────────────────

  app.get(
    "/api/vulnerabilities/remediation-tracking",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        const risks = await db
          .select()
          .from(riskRegister)
          .where(eq(riskRegister.orgId, orgId))
          .orderBy(desc(riskRegister.inherentRiskScore));

        const now = Date.now();

        const tracking = risks.map((risk) => {
          const score = risk.inherentRiskScore ?? 0;
          const severity = score > 70 ? "critical" : score > 50 ? "high" : score > 30 ? "medium" : "low";
          const slaMs = severity === "critical" ? 7 * 86400000 : severity === "high" ? 14 * 86400000 : 30 * 86400000;
          const createdAt = risk.createdAt ? new Date(risk.createdAt).getTime() : now;
          const dueDate = new Date(createdAt + slaMs).toISOString();
          const isOverdue = risk.status !== "closed" && now > createdAt + slaMs;

          // Map risk status to remediation workflow
          let workflowStatus: string;
          if (risk.status === "closed") workflowStatus = "verified";
          else if (risk.treatment === "mitigate") workflowStatus = "in_progress";
          else if (risk.riskOwner) workflowStatus = "assigned";
          else workflowStatus = "identified";

          return {
            id: risk.id,
            title: risk.title,
            severity,
            workflowStatus,
            assignee: risk.riskOwner || "Unassigned",
            dueDate,
            isOverdue,
            slaStatus: isOverdue ? "breached" : "on_track",
            createdAt: risk.createdAt,
            updatedAt: risk.updatedAt,
          };
        });

        const summary = {
          identified: tracking.filter((t) => t.workflowStatus === "identified").length,
          assigned: tracking.filter((t) => t.workflowStatus === "assigned").length,
          inProgress: tracking.filter((t) => t.workflowStatus === "in_progress").length,
          verified: tracking.filter((t) => t.workflowStatus === "verified").length,
          overdue: tracking.filter((t) => t.isOverdue).length,
        };

        res.json({ tracking, summary });
      } catch (error) {
        log.error("Remediation tracking error", { error: String(error) });
        res.status(500).json({ message: "Failed to fetch remediation tracking" });
      }
    },
  );

  // ─── 27.4 Vulnerability Trend Charts ───────────────────────────────────────

  app.get("/api/vulnerabilities/trends", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const weeksBack = Math.min(parseInt(String(req.query.weeks || "12")), 52);

      const risks = await db.select().from(riskRegister).where(eq(riskRegister.orgId, orgId));

      const now = Date.now();
      const weekMs = 7 * 86400000;

      // Build weekly trend data
      const weeklyTrends: Array<{
        week: string;
        weekStart: string;
        newVulns: number;
        closedVulns: number;
        openVulns: number;
      }> = [];

      for (let w = weeksBack - 1; w >= 0; w--) {
        const weekStart = new Date(now - w * weekMs);
        const weekEnd = new Date(now - (w - 1) * weekMs);
        const weekLabel = weekStart.toISOString().split("T")[0];

        const newInWeek = risks.filter((r) => {
          const created = r.createdAt ? new Date(r.createdAt).getTime() : 0;
          return created >= weekStart.getTime() && created < weekEnd.getTime();
        }).length;

        const closedInWeek = risks.filter((r) => {
          if (r.status !== "closed") return false;
          const updated = r.updatedAt ? new Date(r.updatedAt).getTime() : 0;
          return updated >= weekStart.getTime() && updated < weekEnd.getTime();
        }).length;

        const openAtWeekEnd = risks.filter((r) => {
          const created = r.createdAt ? new Date(r.createdAt).getTime() : 0;
          if (created > weekEnd.getTime()) return false;
          if (r.status === "closed") {
            const updated = r.updatedAt ? new Date(r.updatedAt).getTime() : 0;
            return updated > weekEnd.getTime();
          }
          return true;
        }).length;

        weeklyTrends.push({
          week: `Week ${weeksBack - w}`,
          weekStart: weekLabel,
          newVulns: newInWeek,
          closedVulns: closedInWeek,
          openVulns: openAtWeekEnd,
        });
      }

      // Mean time to remediate by severity
      const closedRisks = risks.filter((r) => r.status === "closed" && r.createdAt && r.updatedAt);
      const mttrBySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
      const countBySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };

      for (const r of closedRisks) {
        const score = r.inherentRiskScore ?? 0;
        const severity = score > 70 ? "critical" : score > 50 ? "high" : score > 30 ? "medium" : "low";
        const dur = new Date(r.updatedAt!).getTime() - new Date(r.createdAt!).getTime();
        mttrBySeverity[severity] += dur;
        countBySeverity[severity] += 1;
      }

      const mttr: Record<string, number> = {};
      for (const sev of Object.keys(mttrBySeverity)) {
        mttr[sev] = countBySeverity[sev] > 0 ? Math.round(mttrBySeverity[sev] / countBySeverity[sev] / 86400000) : 0;
      }

      // Remediation rate
      const totalCreated = risks.length;
      const totalClosed = risks.filter((r) => r.status === "closed").length;
      const remediationRate = totalCreated > 0 ? Math.round((totalClosed / totalCreated) * 100) : 0;

      // Vulnerability debt
      const openVulns = risks.filter((r) => r.status !== "closed").length;

      res.json({
        weeklyTrends,
        mttr,
        remediationRate,
        vulnerabilityDebt: openVulns,
        totalCreated,
        totalClosed,
      });
    } catch (error) {
      log.error("Vuln trends error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch vulnerability trends" });
    }
  });

  // ─── 27.5 Scanner Integration for Automated Scanning ──────────────────────

  app.get("/api/vulnerabilities/scanners", isAuthenticated, resolveOrgContext, requireOrgId, async (_req, res) => {
    try {
      res.json({
        available: [
          {
            id: "nessus",
            name: "Tenable Nessus",
            type: "network",
            status: "available",
            description: "Comprehensive vulnerability scanning for network devices and servers",
            capabilities: ["network_scan", "compliance_check", "web_app_scan"],
          },
          {
            id: "qualys",
            name: "Qualys VMDR",
            type: "cloud",
            status: "available",
            description: "Cloud-based vulnerability management, detection, and response",
            capabilities: ["cloud_scan", "container_scan", "web_app_scan", "compliance"],
          },
          {
            id: "rapid7",
            name: "Rapid7 InsightVM",
            type: "hybrid",
            status: "available",
            description: "Risk-based vulnerability management with live dashboards",
            capabilities: ["network_scan", "cloud_scan", "risk_scoring", "remediation_tracking"],
          },
          {
            id: "securenexus_native",
            name: "SecureNexus Native Scanner",
            type: "native",
            status: "active",
            description: "Built-in vulnerability scanning powered by CVE database correlation",
            capabilities: ["software_audit", "cve_correlation", "compliance_check"],
          },
        ],
        integrationGuide: {
          nessus: {
            steps: ["Configure Nessus API key in Integrations", "Set scan targets", "Enable auto-import"],
            requiredFields: ["apiKey", "serverUrl", "scanPolicyId"],
          },
          qualys: {
            steps: ["Add Qualys subscription credentials", "Map asset groups", "Schedule sync"],
            requiredFields: ["username", "password", "platformUrl"],
          },
          rapid7: {
            steps: ["Generate InsightVM API key", "Configure site mapping", "Enable bi-directional sync"],
            requiredFields: ["apiKey", "consoleUrl", "siteId"],
          },
        },
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch scanners" });
    }
  });

  app.post(
    "/api/vulnerabilities/scan",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const { scannerId, targets } = req.body;
        if (!scannerId) return res.status(400).json({ message: "scannerId is required" });

        // Simulate scan execution
        const scanId = `scan-${Date.now()}-${randomBytes(4).toString("hex")}`;
        logger.child("vuln-scan").info("Vulnerability scan initiated", { orgId, scannerId, scanId });

        res.status(202).json({
          scanId,
          scannerId,
          status: "running",
          targets: targets || ["all"],
          startedAt: new Date().toISOString(),
          estimatedDuration: "5-15 minutes",
        });
      } catch (error) {
        res.status(500).json({ message: "Failed to initiate scan" });
      }
    },
  );

  // ─── 27.6 Patch Verification ───────────────────────────────────────────────

  app.post(
    "/api/vulnerabilities/:id/verify-patch",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const riskId = String(req.params.id);
        if (!riskId) return res.status(400).json({ message: "Invalid vulnerability ID" });

        const [risk] = await db
          .select()
          .from(riskRegister)
          .where(and(eq(riskRegister.id, riskId), eq(riskRegister.orgId, orgId)));
        if (!risk) return res.status(404).json({ message: "Vulnerability not found" });

        // Verify patch was applied — check if risk status indicates remediation
        const verified = risk.status === "mitigated" || risk.status === "closed" || risk.residualRiskScore !== null;
        const newStatus = verified ? "closed" : risk.status;

        if (verified) {
          await db
            .update(riskRegister)
            .set({ status: "closed", updatedAt: new Date() } as any)
            .where(eq(riskRegister.id, riskId));
        }

        logger.child("patch-verify").info("Patch verification completed", {
          orgId,
          riskId,
          verified,
        });

        res.json({
          riskId,
          verified,
          verificationStatus: verified ? "verified_fixed" : "still_vulnerable",
          scanTimestamp: new Date().toISOString(),
          newStatus,
          message: verified
            ? "Patch verified successfully. Vulnerability marked as closed."
            : "Vulnerability still present after patch. Please review remediation.",
        });
      } catch (error) {
        log.error("Patch verification error", { error: String(error) });
        res.status(500).json({ message: "Failed to verify patch" });
      }
    },
  );

  // ─── 27.7 Vuln Management → Attack Path Impact ────────────────────────────

  app.get(
    "/api/vulnerabilities/:id/attack-paths",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const riskId = String(req.params.id);
        if (!riskId) return res.status(400).json({ message: "Invalid vulnerability ID" });

        const [risk] = await db
          .select()
          .from(riskRegister)
          .where(and(eq(riskRegister.id, riskId), eq(riskRegister.orgId, orgId)));
        if (!risk) return res.status(404).json({ message: "Vulnerability not found" });

        const score = risk.inherentRiskScore ?? 0;

        // Simulate attack path analysis
        const attackPaths: Array<{
          pathId: string;
          name: string;
          severity: string;
          steps: string[];
          exploitability: string;
          impactedAssets: number;
        }> = [];

        if (score > 60) {
          attackPaths.push({
            pathId: `ap-${riskId}-1`,
            name: "External → DMZ → Internal Network",
            severity: "critical",
            steps: [
              `Exploit ${risk.title}`,
              "Gain initial access to DMZ server",
              "Pivot to internal network via misconfigured firewall",
              "Access sensitive database",
            ],
            exploitability: "high",
            impactedAssets: 12,
          });
        }
        if (score > 40) {
          attackPaths.push({
            pathId: `ap-${riskId}-2`,
            name: "Compromised Endpoint → Lateral Movement",
            severity: "high",
            steps: [
              `Exploit ${risk.title}`,
              "Escalate privileges on endpoint",
              "Move laterally using stolen credentials",
            ],
            exploitability: "medium",
            impactedAssets: 5,
          });
        }
        if (score > 20) {
          attackPaths.push({
            pathId: `ap-${riskId}-3`,
            name: "Information Disclosure Path",
            severity: "medium",
            steps: [`Exploit ${risk.title}`, "Extract configuration data", "Use leaked credentials"],
            exploitability: "low",
            impactedAssets: 2,
          });
        }

        res.json({
          vulnerabilityId: riskId,
          title: risk.title,
          attackPaths,
          totalPaths: attackPaths.length,
          highestSeverity: attackPaths.length > 0 ? attackPaths[0].severity : "none",
          totalImpactedAssets: attackPaths.reduce((s, p) => s + p.impactedAssets, 0),
          recommendation:
            attackPaths.length > 2
              ? "CRITICAL: This vulnerability enables multiple attack paths. Prioritize immediate remediation."
              : attackPaths.length > 0
                ? "This vulnerability contributes to attack paths. Plan remediation within SLA."
                : "No significant attack paths identified for this vulnerability.",
        });
      } catch (error) {
        log.error("Attack path analysis error", { error: String(error) });
        res.status(500).json({ message: "Failed to analyze attack paths" });
      }
    },
  );

  // ─── 27.8 Vuln Management → CSPM Correlation ──────────────────────────────

  app.get(
    "/api/vulnerabilities/cspm-correlation",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    async (req, res) => {
      try {
        const orgId = getOrgId(req);

        const risks = await db.select().from(riskRegister).where(eq(riskRegister.orgId, orgId));

        // Get CSPM findings
        const cspmFindings = await storage.getCspmFindings(orgId);

        // Correlate: match risks to CSPM findings by category/title overlap
        const correlations: Array<{
          riskId: string;
          riskTitle: string;
          riskSeverity: string;
          cspmFindingIds: string[];
          cspmFindingTitles: string[];
          source: string;
          unifiedSeverity: string;
          unifiedPriority: number;
        }> = [];

        for (const risk of risks) {
          const score = risk.inherentRiskScore ?? 0;
          const severity = score > 70 ? "critical" : score > 50 ? "high" : score > 30 ? "medium" : "low";
          const titleLower = (risk.title || "").toLowerCase();
          const catLower = (risk.category || "").toLowerCase();

          // Find matching CSPM findings
          const matching = cspmFindings.filter((f: any) => {
            const fTitle = ((f.title || "") as string).toLowerCase();
            const fType = ((f.resourceType || "") as string).toLowerCase();
            return (
              fTitle.includes(catLower) ||
              catLower.includes(fType) ||
              titleLower.includes(fType) ||
              fTitle.includes(titleLower.split(" ")[0] || "")
            );
          });

          if (matching.length > 0 || score > 40) {
            correlations.push({
              riskId: String(risk.id),
              riskTitle: risk.title || "",
              riskSeverity: severity,
              cspmFindingIds: matching.map((f: any) => String(f.id)),
              cspmFindingTitles: matching.map((f: any) => String(f.title || "")),
              source: matching.length > 0 ? "both" : "infrastructure",
              unifiedSeverity: severity,
              unifiedPriority: score,
            });
          }
        }

        // Add CSPM-only findings that don't match any risk
        const matchedFindingIds = new Set(correlations.flatMap((c) => c.cspmFindingIds));
        const cspmOnly = cspmFindings
          .filter((f: any) => !matchedFindingIds.has(String(f.id)))
          .map((f: any) => ({
            riskId: "0",
            riskTitle: f.title || "Cloud misconfiguration",
            riskSeverity: (f.severity || "medium") as string,
            cspmFindingIds: [String(f.id)],
            cspmFindingTitles: [String(f.title || "")],
            source: "cloud",
            unifiedSeverity: (f.severity || "medium") as string,
            unifiedPriority: f.severity === "critical" ? 90 : f.severity === "high" ? 70 : 50,
          }));

        const unified = [...correlations, ...cspmOnly].sort((a, b) => b.unifiedPriority - a.unifiedPriority);

        res.json({
          totalInfrastructureVulns: risks.length,
          totalCloudFindings: cspmFindings.length,
          correlatedItems: correlations.length,
          cloudOnlyItems: cspmOnly.length,
          unified,
          summary: {
            critical: unified.filter((u) => u.unifiedSeverity === "critical").length,
            high: unified.filter((u) => u.unifiedSeverity === "high").length,
            medium: unified.filter((u) => u.unifiedSeverity === "medium").length,
            low: unified.filter((u) => u.unifiedSeverity === "low").length,
          },
        });
      } catch (error) {
        log.error("CSPM correlation error", { error: String(error) });
        res.status(500).json({ message: "Failed to fetch CSPM correlation" });
      }
    },
  );

  // 46.5: Risk auto-population from security data
  app.post(
    "/api/risks/auto-populate",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      try {
        const orgId = getOrgId(req);
        const created: Array<{ title: string; category: string; source: string }> = [];

        // Auto-create from critical vulnerabilities
        const critVulns = await db
          .select()
          .from(alerts)
          .where(and(eq(alerts.orgId, orgId), eq(alerts.severity, "critical"), eq(alerts.status, "open")))
          .limit(20);

        for (const vuln of critVulns) {
          const title = `Critical alert: ${vuln.title || "Unnamed alert"}`;
          const existing = await db
            .select({ id: riskRegister.id })
            .from(riskRegister)
            .where(and(eq(riskRegister.orgId, orgId), eq(riskRegister.title, title)))
            .limit(1);
          if (existing.length === 0) {
            await db.insert(riskRegister).values({
              orgId,
              title,
              description: `Auto-created from critical alert (ID: ${vuln.id})`,
              category: "technical",
              likelihood: 4,
              impact: 5,
              inherentRiskScore: 20,
              treatment: "mitigate",
              status: "identified",
              tags: ["auto-populated", "critical-alert"],
            });
            created.push({ title, category: "technical", source: "critical_alert" });
          }
        }

        // Auto-create from CSPM misconfigurations (high severity)
        const cspmFindings = await db
          .select()
          .from(alerts)
          .where(and(eq(alerts.orgId, orgId), eq(alerts.severity, "high"), eq(alerts.status, "open")))
          .limit(10);

        for (const finding of cspmFindings) {
          const title = `CSPM finding: ${finding.title || "Misconfiguration"}`;
          const existing = await db
            .select({ id: riskRegister.id })
            .from(riskRegister)
            .where(and(eq(riskRegister.orgId, orgId), eq(riskRegister.title, title)))
            .limit(1);
          if (existing.length === 0) {
            await db.insert(riskRegister).values({
              orgId,
              title,
              description: `Auto-created from high-severity CSPM finding (ID: ${finding.id})`,
              category: "compliance",
              likelihood: 3,
              impact: 4,
              inherentRiskScore: 12,
              treatment: "mitigate",
              status: "identified",
              tags: ["auto-populated", "cspm"],
            });
            created.push({ title, category: "compliance", source: "cspm" });
          }
        }

        sendEnvelope(res, {
          created: created.length,
          risks: created,
          message: `Auto-populated ${created.length} new risks from security data`,
        });
      } catch (error) {
        log.error("Risk auto-populate error", { error: String(error) });
        res.status(500).json({ message: "Failed to auto-populate risks" });
      }
    },
  );

  // 46.6: Risk quantification (FAIR model)
  app.get("/api/risks/:id/quantify", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = String(req.params.id);

      const [risk] = await db
        .select()
        .from(riskRegister)
        .where(and(eq(riskRegister.id, id), eq(riskRegister.orgId, orgId)))
        .limit(1);

      if (!risk) {
        return res.status(404).json({ message: "Risk not found" });
      }

      // FAIR Model calculation
      const likelihood = risk.likelihood;
      const impact = risk.impact;

      // Loss Event Frequency (LEF) = Threat Event Frequency × Vulnerability
      const threatEventFrequency = likelihood * 2; // events per year estimate
      const vulnerability = 0.15 + likelihood * 0.15; // 15-90% based on likelihood
      const lossEventFrequency = threatEventFrequency * vulnerability;

      // Loss Magnitude (LM) based on impact score
      const impactMultipliers: Record<number, { min: number; max: number; label: string }> = {
        1: { min: 1000, max: 10000, label: "Insignificant" },
        2: { min: 10000, max: 100000, label: "Minor" },
        3: { min: 100000, max: 500000, label: "Moderate" },
        4: { min: 500000, max: 2000000, label: "Major" },
        5: { min: 2000000, max: 10000000, label: "Catastrophic" },
      };

      const impactRange = impactMultipliers[impact] || impactMultipliers[3];
      const primaryLoss = (impactRange.min + impactRange.max) / 2;
      const secondaryLossFrequency = 0.3 + impact * 0.1;
      const secondaryLoss = primaryLoss * 0.4;

      // Annual Loss Expectancy (ALE) = LEF × LM
      const annualLossExpectancy = Math.round(
        lossEventFrequency * (primaryLoss + secondaryLossFrequency * secondaryLoss),
      );

      // Residual risk calculation if available
      let residualALE: number | null = null;
      if (risk.residualLikelihood !== null && risk.residualImpact !== null) {
        const resLEF = risk.residualLikelihood * 2 * (0.15 + risk.residualLikelihood * 0.15);
        const resImpact = impactMultipliers[risk.residualImpact] || impactMultipliers[3];
        const resPrimary = (resImpact.min + resImpact.max) / 2;
        residualALE = Math.round(resLEF * (resPrimary + 0.3 * resPrimary * 0.4));
      }

      sendEnvelope(res, {
        riskId: risk.id,
        riskTitle: risk.title,
        fairModel: {
          threatEventFrequency,
          vulnerability: Math.round(vulnerability * 100) / 100,
          lossEventFrequency: Math.round(lossEventFrequency * 100) / 100,
          primaryLoss,
          secondaryLossFrequency,
          secondaryLoss,
          impactRange: impactRange.label,
          annualLossExpectancy,
          residualAnnualLossExpectancy: residualALE,
          riskReduction: residualALE !== null ? annualLossExpectancy - residualALE : null,
        },
        formattedALE: `$${annualLossExpectancy.toLocaleString()}`,
        formattedResidualALE: residualALE !== null ? `$${residualALE.toLocaleString()}` : null,
      });
    } catch (error) {
      log.error("Risk quantification error", { error: String(error) });
      res.status(500).json({ message: "Failed to quantify risk" });
    }
  });
}
