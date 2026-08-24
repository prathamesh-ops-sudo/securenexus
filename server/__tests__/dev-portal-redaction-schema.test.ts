process.env.DATABASE_URL ||= "postgresql://localhost/securenexus-test";

import { sql } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import { db } from "../db";
import { isSensitiveColumn } from "../routes/dev-portal";

const SUSPICIOUS_COLUMN_PATTERN =
  /secret|token|api[_-]?key|apikey|credential|private[_-]?key|passphrase|password|certificate|cert|(^|_)sid($|_)|session|otp|pin/i;

const REVIEWED_NON_SENSITIVE_COLUMNS = new Set([
  "ai_inference_log.input_tokens",
  "ai_inference_log.output_tokens",
  "ai_prompt_versions.max_tokens",
  "ai_prompts.max_tokens",
  "browser_defense_sessions.created_at",
  "browser_defense_sessions.ended_at",
  "browser_defense_sessions.started_at",
  "canary_tokens.callback_url",
  "canary_tokens.created_at",
  "canary_tokens.expires_at",
  "canary_tokens.last_hit_at",
  "canary_tokens.token_type",
  "ci_gates.secrets_found",
  "connector_health_checks.credential_expires_at",
  "connector_health_checks.credential_status",
  "connector_secret_rotations.secret_field",
  "deception_hits.accessed_credential",
  "deception_hits.canary_token_id",
  "evidence_attachments.control_mapping_id",
  "hunt_collaborations.session_name",
  "identity_risk_profiles.credential_age_days",
  "identity_risk_profiles.last_credential_rotation",
  "ioc_feeds.api_key_ref",
  "jit_access_requests.secret_path",
  "jit_access_requests.secret_provider",
  "jit_break_glass_access.secret_id",
  "jit_break_glass_access.secret_name",
  "jit_external_shares.secret_id",
  "jit_external_shares.secret_name",
  "jit_managed_secrets.secret_type",
  "jit_managed_secrets.name",
  "jit_ownership_transfers.secret_id",
  "jit_ownership_transfers.secret_name",
  "jit_secret_access_requests.secret_id",
  "jit_secret_access_requests.secret_name",
  "log_sources.field_mappings",
  "marketplace_instances.field_mappings",
  "native_sensors.supersession_match_basis",
  "org_ai_budgets.daily_input_tokens",
  "org_ai_budgets.daily_output_tokens",
  "org_plan_limits.ai_tokens_per_month",
  "org_scim_configs.bearer_token_prefix",
  "org_security_policies.max_concurrent_sessions",
  "org_security_policies.password_expiry_days",
  "org_security_policies.password_min_length",
  "org_security_policies.password_require_number",
  "org_security_policies.password_require_special",
  "org_security_policies.password_require_uppercase",
  "org_security_policies.session_timeout_minutes",
  "ot_anomalies.ics_cert_advisory",
  "phishing_campaigns.credentials_submitted",
  "phishing_results.credential_submitted_at",
  "phishing_simulations.submitted_credentials",
  "public_trust_pages.certifications",
  "public_trust_pages.show_certifications",
  "remote_worker_sessions.session_end",
  "remote_worker_sessions.session_start",
  "rule_generation_jobs.input_tokens",
  "rule_generation_jobs.output_tokens",
  "secrets_exposed.secret_type",
  "ticket_sync_jobs.field_mapping",
  "ticket_sync_jobs.status_mapping",
  "vendors.compliance_certifications",
  "users.password_change_required",
  "users.password_changed_at",
]);

const REVIEWED_SENSITIVE_COLUMNS = new Map([
  [
    "collector_instances.api_key_prefix",
    "A short collector-key identifier useful for correlation, but still a fragment of an authentication secret; redaction is safe in the generic database browser.",
  ],
]);

const OPERATIONAL_COLUMNS_MUST_REMAIN_VISIBLE = [
  "org_security_policies.password_min_length",
  "org_security_policies.password_expiry_days",
  "org_security_policies.password_require_number",
  "org_security_policies.password_require_special",
  "org_security_policies.password_require_uppercase",
  "users.password_changed_at",
  "users.password_change_required",
  "canary_tokens.token_type",
  "org_scim_configs.bearer_token_prefix",
  "connector_health_checks.credential_status",
  "connector_health_checks.credential_expires_at",
  "identity_risk_profiles.credential_age_days",
  "identity_risk_profiles.last_credential_rotation",
  "data_assets.is_encrypted",
  "mobile_devices.is_encrypted",
  "phishing_results.credential_submitted_at",
  "phishing_campaigns.credentials_submitted",
  "phishing_simulations.submitted_credentials",
];

describe("dev-portal redaction schema coverage", () => {
  it("redacts reviewed secret-derived metadata", () => {
    for (const [qualifiedColumn] of REVIEWED_SENSITIVE_COLUMNS) {
      const separator = qualifiedColumn.indexOf(".");
      const tableName = qualifiedColumn.slice(0, separator);
      const columnName = qualifiedColumn.slice(separator + 1);
      expect(isSensitiveColumn(tableName, columnName), qualifiedColumn).toBe(true);
    }
  });

  it("keeps reviewed operational metadata visible", () => {
    for (const qualifiedColumn of OPERATIONAL_COLUMNS_MUST_REMAIN_VISIBLE) {
      const separator = qualifiedColumn.indexOf(".");
      const tableName = qualifiedColumn.slice(0, separator);
      const columnName = qualifiedColumn.slice(separator + 1);
      expect(isSensitiveColumn(tableName, columnName), qualifiedColumn).toBe(false);
    }
  });

  it("classifies every suspicious live-schema column or records a reviewed exception", async ({ skip }) => {
    let columns: Array<{ table_name: string; column_name: string }>;
    try {
      const result = await db.execute(sql`
        SELECT table_name, column_name
        FROM information_schema.columns
        WHERE table_schema = 'public'
        ORDER BY table_name, ordinal_position
      `);
      columns = result.rows as Array<{ table_name: string; column_name: string }>;
    } catch (error) {
      skip(`Database unavailable for schema redaction coverage: ${String(error)}`);
      return;
    }

    const unclassified = columns
      .filter(({ column_name }) => SUSPICIOUS_COLUMN_PATTERN.test(column_name))
      .filter(({ table_name, column_name }) => {
        const qualifiedColumn = `${table_name}.${column_name}`;
        return !isSensitiveColumn(table_name, column_name) && !REVIEWED_NON_SENSITIVE_COLUMNS.has(qualifiedColumn);
      })
      .map(({ table_name, column_name }) => `${table_name}.${column_name}`);

    expect(unclassified).toEqual([]);
  });
});
