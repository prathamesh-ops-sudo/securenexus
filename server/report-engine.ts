import { storage } from "./storage";
import { logger } from "./logger";

interface ReportData {
  title: string;
  generatedAt: string;
  reportType: string;
  orgId: string | null;
  sections: ReportSection[];
}

interface ReportSection {
  title: string;
  type: "table" | "summary" | "chart_data";
  columns?: string[];
  rows?: any[][];
  data?: Record<string, any>;
}

export async function generateReportData(reportType: string, orgId?: string): Promise<ReportData> {
  const now = new Date().toISOString();
  switch (reportType) {
    case "soc_kpi": return generateSocKpiReport(orgId, now);
    case "incidents": return generateIncidentsReport(orgId, now);
    case "attack_coverage": return generateAttackCoverageReport(orgId, now);
    case "connector_health": return generateConnectorHealthReport(orgId, now);
    case "executive_summary": return generateExecutiveSummaryReport(orgId, now);
    case "compliance": return generateComplianceReport(orgId, now);
    default: throw new Error(`Unknown report type: ${reportType}`);
  }
}

async function generateSocKpiReport(orgId: string | undefined, now: string): Promise<ReportData> {
  const stats = await storage.getDashboardStats(orgId);
  const analytics = await storage.getDashboardAnalytics(orgId);
  return {
    title: "SOC KPI Report",
    generatedAt: now,
    reportType: "soc_kpi",
    orgId: orgId || null,
    sections: [
      {
        title: "Overview Metrics",
        type: "summary",
        data: {
          "Total Alerts": stats.totalAlerts,
          "Open Incidents": stats.openIncidents,
          "Critical Alerts": stats.criticalAlerts,
          "Resolved Incidents": stats.resolvedIncidents,
          "New Alerts Today": stats.newAlertsToday,
          "Escalated Incidents": stats.escalatedIncidents,
          "Mean Time to Resolve (hours)": analytics.mttrHours ?? "N/A",
        }
      },
      {
        title: "Severity Distribution",
        type: "table",
        columns: ["Severity", "Count"],
        rows: analytics.severityDistribution.map(s => [s.name, s.value])
      },
      {
        title: "Source Distribution",
        type: "table",
        columns: ["Source", "Count"],
        rows: analytics.sourceDistribution.map(s => [s.name, s.value])
      },
      {
        title: "Category Distribution",
        type: "table",
        columns: ["Category", "Count"],
        rows: analytics.categoryDistribution.map(s => [s.name, s.value])
      },
      {
        title: "Alert Trend (7-day)",
        type: "table",
        columns: ["Date", "Count"],
        rows: analytics.alertTrend.map(t => [t.date, t.count])
      },
      {
        title: "Top MITRE Tactics",
        type: "table",
        columns: ["Tactic", "Count"],
        rows: analytics.topMitreTactics.map(t => [t.name, t.value])
      }
    ]
  };
}

async function generateIncidentsReport(orgId: string | undefined, now: string): Promise<ReportData> {
  const allIncidents = await storage.getIncidents(orgId);
  return {
    title: "Incident Summary Report",
    generatedAt: now,
    reportType: "incidents",
    orgId: orgId || null,
    sections: [
      {
        title: "Incident Overview",
        type: "summary",
        data: {
          "Total Incidents": allIncidents.length,
          "Open": allIncidents.filter(i => i.status === "open").length,
          "Investigating": allIncidents.filter(i => i.status === "investigating").length,
          "Contained": allIncidents.filter(i => i.status === "contained").length,
          "Resolved": allIncidents.filter(i => i.status === "resolved" || i.status === "closed").length,
          "Escalated": allIncidents.filter(i => i.escalated).length,
          "Critical": allIncidents.filter(i => i.severity === "critical").length,
          "High": allIncidents.filter(i => i.severity === "high").length,
        }
      },
      {
        title: "Incident Details",
        type: "table",
        columns: ["ID", "Title", "Severity", "Status", "Priority", "Assigned To", "Alert Count", "Created At"],
        rows: allIncidents.map(i => [
          i.id,
          i.title,
          i.severity,
          i.status,
          i.priority ?? "",
          i.assignedTo ?? "Unassigned",
          i.alertCount ?? 0,
          i.createdAt ? new Date(i.createdAt).toISOString() : "",
        ])
      }
    ]
  };
}

async function generateAttackCoverageReport(orgId: string | undefined, now: string): Promise<ReportData> {
  const analytics = await storage.getDashboardAnalytics(orgId);
  const allAlerts = await storage.getAlerts(orgId);

  const tacticCounts: Record<string, number> = {};
  const techniqueCounts: Record<string, number> = {};
  for (const alert of allAlerts) {
    if (alert.mitreTactic) {
      tacticCounts[alert.mitreTactic] = (tacticCounts[alert.mitreTactic] || 0) + 1;
    }
    if (alert.mitreTechnique) {
      techniqueCounts[alert.mitreTechnique] = (techniqueCounts[alert.mitreTechnique] || 0) + 1;
    }
  }

  return {
    title: "MITRE ATT&CK Coverage Report",
    generatedAt: now,
    reportType: "attack_coverage",
    orgId: orgId || null,
    sections: [
      {
        title: "Coverage Summary",
        type: "summary",
        data: {
          "Total Alerts with MITRE Mapping": allAlerts.filter(a => a.mitreTactic).length,
          "Unique Tactics Detected": Object.keys(tacticCounts).length,
          "Unique Techniques Detected": Object.keys(techniqueCounts).length,
        }
      },
      {
        title: "Top MITRE Tactics",
        type: "table",
        columns: ["Tactic", "Count"],
        rows: analytics.topMitreTactics.map(t => [t.name, t.value])
      },
      {
        title: "Tactic Distribution",
        type: "table",
        columns: ["Tactic", "Alert Count"],
        rows: Object.entries(tacticCounts).sort((a, b) => b[1] - a[1]).map(([tactic, count]) => [tactic, count])
      },
      {
        title: "Technique Distribution",
        type: "table",
        columns: ["Technique", "Alert Count"],
        rows: Object.entries(techniqueCounts).sort((a, b) => b[1] - a[1]).map(([technique, count]) => [technique, count])
      }
    ]
  };
}

async function generateConnectorHealthReport(orgId: string | undefined, now: string): Promise<ReportData> {
  const analytics = await storage.getDashboardAnalytics(orgId);
  return {
    title: "Connector Health Report",
    generatedAt: now,
    reportType: "connector_health",
    orgId: orgId || null,
    sections: [
      {
        title: "Connector Overview",
        type: "summary",
        data: {
          "Total Connectors": analytics.connectorHealth.length,
          "Active": analytics.connectorHealth.filter(c => c.status === "active").length,
          "Inactive": analytics.connectorHealth.filter(c => c.status === "inactive").length,
          "Error": analytics.connectorHealth.filter(c => c.status === "error").length,
        }
      },
      {
        title: "Connector Details",
        type: "table",
        columns: ["Name", "Type", "Status", "Last Sync", "Alerts Synced", "Last Error"],
        rows: analytics.connectorHealth.map(c => [
          c.name,
          c.type,
          c.status,
          c.lastSyncAt ?? "Never",
          c.lastSyncAlerts,
          c.lastSyncError ?? "",
        ])
      }
    ]
  };
}

async function generateExecutiveSummaryReport(orgId: string | undefined, now: string): Promise<ReportData> {
  const stats = await storage.getDashboardStats(orgId);
  const analytics = await storage.getDashboardAnalytics(orgId);
  const allIncidents = await storage.getIncidents(orgId);
  const topIncidents = allIncidents
    .filter(i => i.severity === "critical" || i.severity === "high")
    .slice(0, 5);

  return {
    title: "Executive Security Brief",
    generatedAt: now,
    reportType: "executive_summary",
    orgId: orgId || null,
    sections: [
      {
        title: "Key Performance Indicators",
        type: "summary",
        data: {
          "Total Alerts": stats.totalAlerts,
          "Open Incidents": stats.openIncidents,
          "Critical Alerts": stats.criticalAlerts,
          "Resolved Incidents": stats.resolvedIncidents,
          "MTTR (hours)": analytics.mttrHours ?? "N/A",
          "Escalated Incidents": stats.escalatedIncidents,
          "New Alerts Today": stats.newAlertsToday,
        }
      },
      {
        title: "Risk Posture",
        type: "table",
        columns: ["Severity", "Count"],
        rows: analytics.severityDistribution.map(s => [s.name, s.value])
      },
      {
        title: "Top Critical/High Incidents",
        type: "table",
        columns: ["Title", "Severity", "Status", "Assigned To", "Created"],
        rows: topIncidents.map(i => [
          i.title,
          i.severity,
          i.status,
          i.assignedTo ?? "Unassigned",
          i.createdAt ? new Date(i.createdAt).toISOString() : "",
        ])
      },
      {
        title: "Connector Health Summary",
        type: "table",
        columns: ["Name", "Status", "Last Sync"],
        rows: analytics.connectorHealth.map(c => [c.name, c.status, c.lastSyncAt ?? "Never"])
      },
      {
        title: "Alert Trend (7-day)",
        type: "table",
        columns: ["Date", "Count"],
        rows: analytics.alertTrend.map(t => [t.date, t.count])
      }
    ]
  };
}

async function generateComplianceReport(orgId: string | undefined, now: string): Promise<ReportData> {
  const sections: ReportSection[] = [];

  try {
    if (orgId) {
      const policy = await storage.getCompliancePolicy(orgId);
      if (policy) {
        sections.push({
          title: "Compliance Policy",
          type: "summary",
          data: {
            "Alert Retention (days)": policy.alertRetentionDays ?? 365,
            "Incident Retention (days)": policy.incidentRetentionDays ?? 730,
            "Audit Log Retention (days)": policy.auditLogRetentionDays ?? 2555,
            "PII Masking Enabled": policy.piiMaskingEnabled ? "Yes" : "No",
            "Pseudonymize Exports": policy.pseudonymizeExports ? "Yes" : "No",
            "Enabled Frameworks": (policy.enabledFrameworks || []).join(", "),
            "DPO Email": policy.dpoEmail ?? "Not set",
            "DSAR SLA (days)": policy.dsarSlaDays ?? 30,
          }
        });
      }

      const dsarRequests = await storage.getDsarRequests(orgId);
      sections.push({
        title: "DSAR Requests",
        type: "summary",
        data: {
          "Total Requests": dsarRequests.length,
          "Pending": dsarRequests.filter(r => r.status === "pending").length,
          "In Progress": dsarRequests.filter(r => r.status === "in_progress").length,
          "Fulfilled": dsarRequests.filter(r => r.status === "fulfilled").length,
          "Rejected": dsarRequests.filter(r => r.status === "rejected").length,
        }
      });

      if (dsarRequests.length > 0) {
        sections.push({
          title: "DSAR Request Details",
          type: "table",
          columns: ["ID", "Requestor", "Type", "Status", "Due Date"],
          rows: dsarRequests.map(r => [
            r.id,
            r.requestorEmail,
            r.requestType,
            r.status,
            r.dueDate ? new Date(r.dueDate).toISOString() : "N/A",
          ])
        });
      }
    }
  } catch (err) {
    logger.child("report-engine").error("Failed to generate compliance policy section", { error: String(err) });
    sections.push({
      title: "Compliance Policy",
      type: "summary",
      data: { "Status": "Error retrieving compliance data" }
    });
  }

  const auditLogCount = await storage.getAuditLogCount(orgId);
  sections.push({
    title: "Audit Log Statistics",
    type: "summary",
    data: {
      "Total Audit Log Entries": auditLogCount,
    }
  });

  return {
    title: "Compliance Status Report",
    generatedAt: now,
    reportType: "compliance",
    orgId: orgId || null,
    sections,
  };
}

export function formatAsCSV(data: ReportData): string {
  const lines: string[] = [];
  lines.push(`# ${data.title}`);
  lines.push(`# Generated: ${data.generatedAt}`);
  lines.push("");

  for (const section of data.sections) {
    lines.push(`## ${section.title}`);
    if (section.type === "summary" && section.data) {
      lines.push("Metric,Value");
      for (const [k, v] of Object.entries(section.data)) {
        lines.push(`"${k}","${v}"`);
      }
    } else if (section.type === "table" && section.columns && section.rows) {
      lines.push(section.columns.map(c => `"${c}"`).join(","));
      for (const row of section.rows) {
        lines.push(row.map((v: any) => `"${v ?? ""}"`).join(","));
      }
    }
    lines.push("");
  }
  return lines.join("\n");
}

export function formatAsJSON(data: ReportData): string {
  return JSON.stringify(data, null, 2);
}
