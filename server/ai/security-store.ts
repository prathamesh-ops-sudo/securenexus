import { pool } from "../db";
import { logger } from "../logger";
import type { InjectionSeverity } from "./injection-detector";
import type { PiiMaskingMode, RedactionCount } from "./egress-redaction";

const log = logger.child("ai-security-store");

export type InjectionMode = "off" | "flag_and_gate" | "block";

export interface AiSecuritySettings {
  injectionMode: InjectionMode;
  piiMasking: PiiMaskingMode;
  aiEnabled: boolean;
  updatedBy: string | null;
  updatedAt: string | null;
}

const DEFAULT_SETTINGS: AiSecuritySettings = {
  injectionMode: "flag_and_gate",
  piiMasking: "mask_identifiers",
  aiEnabled: true,
  updatedBy: null,
  updatedAt: null,
};

export async function getAiSecuritySettings(orgId: string): Promise<AiSecuritySettings> {
  try {
    const result = await pool.query(
      `SELECT injection_mode, pii_masking, ai_enabled, updated_by, updated_at
       FROM org_ai_security_settings WHERE org_id = $1`,
      [orgId],
    );
    const row = result.rows[0] as Record<string, unknown> | undefined;
    if (!row) return DEFAULT_SETTINGS;
    return {
      injectionMode: row.injection_mode as InjectionMode,
      piiMasking: row.pii_masking as PiiMaskingMode,
      aiEnabled: row.ai_enabled as boolean,
      updatedBy: (row.updated_by as string) || null,
      updatedAt: row.updated_at ? new Date(row.updated_at as string).toISOString() : null,
    };
  } catch (error) {
    log.warn("AI security settings unavailable; using secure defaults", { orgId, error: String(error) });
    return DEFAULT_SETTINGS;
  }
}

export async function upsertAiSecuritySettings(
  orgId: string,
  settings: Pick<AiSecuritySettings, "injectionMode" | "piiMasking" | "aiEnabled">,
  updatedBy: string,
): Promise<AiSecuritySettings> {
  await pool.query(
    `INSERT INTO org_ai_security_settings (org_id, injection_mode, pii_masking, ai_enabled, updated_by, updated_at)
     VALUES ($1, $2, $3, $4, $5, NOW())
     ON CONFLICT (org_id) DO UPDATE SET
       injection_mode = EXCLUDED.injection_mode,
       pii_masking = EXCLUDED.pii_masking,
       ai_enabled = EXCLUDED.ai_enabled,
       updated_by = EXCLUDED.updated_by,
       updated_at = NOW()`,
    [orgId, settings.injectionMode, settings.piiMasking, settings.aiEnabled, updatedBy],
  );
  return getAiSecuritySettings(orgId);
}

export async function recordAiGuardEvent(params: {
  orgId: string;
  invocationId: string;
  feature: string;
  modelId: string;
  injectionScore: number;
  severity: InjectionSeverity;
  signals: unknown;
  enforcementMode: InjectionMode;
  actionTaken: string;
  redactionCounts: RedactionCount[];
  humanReviewRequired: boolean;
  alertId?: string;
  incidentId?: string;
}): Promise<void> {
  try {
    await pool.query(
      `INSERT INTO ai_guard_events
       (org_id, invocation_id, feature, model_id, injection_score, signals, enforcement_mode,
        action_taken, redaction_counts, human_review_required, alert_id, incident_id)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9::jsonb, $10, $11, $12)`,
      [
        params.orgId,
        params.invocationId,
        params.feature,
        params.modelId,
        params.injectionScore,
        JSON.stringify(params.signals),
        params.enforcementMode,
        params.actionTaken,
        JSON.stringify(params.redactionCounts),
        params.humanReviewRequired,
        params.alertId || null,
        params.incidentId || null,
      ],
    );
  } catch (error) {
    log.warn("Failed to persist AI guard event", {
      orgId: params.orgId,
      invocationId: params.invocationId,
      error: String(error),
    });
  }
}

export async function listAiGuardEvents(params: {
  orgId: string;
  page: number;
  pageSize: number;
  feature?: string;
  alertId?: string;
  incidentId?: string;
  severity?: "suspected" | "likely";
  from?: Date;
  to?: Date;
}): Promise<{ events: Array<Record<string, unknown>>; total: number }> {
  const values: unknown[] = [params.orgId];
  const conditions = ["org_id = $1"];
  const add = (sql: string, value: unknown): void => {
    values.push(value);
    conditions.push(`${sql} = $${values.length}`);
  };
  if (params.feature) add("feature", params.feature);
  if (params.alertId) add("alert_id", params.alertId);
  if (params.incidentId) add("incident_id", params.incidentId);
  if (params.severity) {
    values.push(params.severity === "likely" ? 3 : 1);
    conditions.push(`injection_score ${params.severity === "likely" ? ">=" : "BETWEEN"} $${values.length}`);
    if (params.severity === "suspected") {
      values.push(2);
      conditions[conditions.length - 1] = `injection_score BETWEEN $${values.length - 1} AND $${values.length}`;
    }
  }
  if (params.from) {
    values.push(params.from);
    conditions.push(`created_at >= $${values.length}`);
  }
  if (params.to) {
    values.push(params.to);
    conditions.push(`created_at <= $${values.length}`);
  }
  const where = conditions.join(" AND ");
  const count = await pool.query(`SELECT COUNT(*)::int AS total FROM ai_guard_events WHERE ${where}`, values);
  const offset = (params.page - 1) * params.pageSize;
  const rows = await pool.query(
    `SELECT id, created_at, invocation_id, feature, model_id, injection_score, signals,
            enforcement_mode, action_taken, redaction_counts, human_review_required, alert_id, incident_id
     FROM ai_guard_events WHERE ${where}
     ORDER BY created_at DESC LIMIT $${values.length + 1} OFFSET $${values.length + 2}`,
    [...values, params.pageSize, offset],
  );
  return {
    events: rows.rows as Array<Record<string, unknown>>,
    total: Number((count.rows[0] as { total: number }).total),
  };
}

export { DEFAULT_SETTINGS };
