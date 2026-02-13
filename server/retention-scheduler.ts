import { db } from "./db";
import { compliancePolicies } from "@shared/schema";
import { sql } from "drizzle-orm";
import { storage } from "./storage";

export function startRetentionScheduler(): void {
  setTimeout(() => {
    runRetentionCleanup().catch((err) => {
      console.error("Retention cleanup error on startup:", err);
    });
  }, 60 * 1000);

  setInterval(() => {
    runRetentionCleanup().catch((err) => {
      console.error("Retention cleanup error:", err);
    });
  }, 24 * 60 * 60 * 1000);

  console.log("[RetentionScheduler] Started - runs every 24 hours");
}

export async function runRetentionCleanup(): Promise<{ orgId: string; alertsDeleted: number; incidentsDeleted: number; auditLogsDeleted: number }[]> {
  const policies = await db.select().from(compliancePolicies);
  const results: { orgId: string; alertsDeleted: number; incidentsDeleted: number; auditLogsDeleted: number }[] = [];

  for (const policy of policies) {
    if (!policy.orgId) continue;

    const orgId = policy.orgId;
    let alertsDeleted = 0;
    let incidentsDeleted = 0;
    let auditLogsDeleted = 0;

    if (policy.alertRetentionDays && policy.alertRetentionDays > 0) {
      const cutoff = new Date();
      cutoff.setDate(cutoff.getDate() - policy.alertRetentionDays);
      const alertResult = await db.execute(sql`DELETE FROM alerts WHERE org_id = ${orgId} AND created_at < ${cutoff}`);
      alertsDeleted = Number(alertResult.rowCount) || 0;
    }

    if (policy.incidentRetentionDays && policy.incidentRetentionDays > 0) {
      const cutoff = new Date();
      cutoff.setDate(cutoff.getDate() - policy.incidentRetentionDays);
      const incidentResult = await db.execute(sql`DELETE FROM incidents WHERE org_id = ${orgId} AND created_at < ${cutoff} AND (status = 'resolved' OR status = 'closed')`);
      incidentsDeleted = Number(incidentResult.rowCount) || 0;
    }

    if (policy.auditLogRetentionDays && policy.auditLogRetentionDays > 0) {
      const cutoff = new Date();
      cutoff.setDate(cutoff.getDate() - policy.auditLogRetentionDays);
      const auditResult = await db.execute(sql`DELETE FROM audit_logs WHERE org_id = ${orgId} AND created_at < ${cutoff}`);
      auditLogsDeleted = Number(auditResult.rowCount) || 0;
    }

    const totalDeleted = alertsDeleted + incidentsDeleted + auditLogsDeleted;

    await storage.upsertCompliancePolicy({
      orgId,
      alertRetentionDays: policy.alertRetentionDays,
      incidentRetentionDays: policy.incidentRetentionDays,
      auditLogRetentionDays: policy.auditLogRetentionDays,
      piiMaskingEnabled: policy.piiMaskingEnabled,
      pseudonymizeExports: policy.pseudonymizeExports,
      enabledFrameworks: policy.enabledFrameworks,
      dataProcessingBasis: policy.dataProcessingBasis,
      dpoEmail: policy.dpoEmail,
      dsarSlaDays: policy.dsarSlaDays,
    });

    await db.execute(sql`UPDATE compliance_policies SET retention_last_run_at = NOW(), retention_last_deleted_count = ${totalDeleted} WHERE org_id = ${orgId}`);

    try {
      await storage.createAuditLog({
        orgId,
        userId: "system",
        userName: "Retention Scheduler",
        action: "retention_cleanup",
        resourceType: "compliance",
        details: { alertsDeleted, incidentsDeleted, auditLogsDeleted, totalDeleted },
      });
    } catch (e) {
      console.error("Failed to create audit log for retention cleanup:", e);
    }

    results.push({ orgId, alertsDeleted, incidentsDeleted, auditLogsDeleted });
  }

  if (results.length > 0) {
    console.log("[RetentionScheduler] Cleanup complete:", JSON.stringify(results));
  }

  return results;
}
