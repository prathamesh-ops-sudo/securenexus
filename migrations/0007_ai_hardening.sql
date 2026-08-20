CREATE TABLE "org_ai_security_settings" (
  "org_id" varchar PRIMARY KEY REFERENCES "organizations"("id") ON DELETE CASCADE,
  "injection_mode" text NOT NULL DEFAULT 'flag_and_gate',
  "pii_masking" text NOT NULL DEFAULT 'mask_identifiers',
  "ai_enabled" boolean NOT NULL DEFAULT true,
  "updated_by" varchar,
  "updated_at" timestamp DEFAULT now()
);
CREATE INDEX "idx_org_ai_security_settings_org" ON "org_ai_security_settings" USING btree ("org_id");
CREATE TABLE "ai_guard_events" (
  "id" varchar PRIMARY KEY DEFAULT gen_random_uuid()::text,
  "org_id" varchar NOT NULL REFERENCES "organizations"("id") ON DELETE CASCADE,
  "created_at" timestamp DEFAULT now(),
  "invocation_id" varchar NOT NULL,
  "feature" text NOT NULL,
  "model_id" text NOT NULL,
  "injection_score" integer NOT NULL DEFAULT 0,
  "signals" jsonb NOT NULL DEFAULT '[]'::jsonb,
  "enforcement_mode" text NOT NULL,
  "action_taken" text NOT NULL,
  "redaction_counts" jsonb NOT NULL DEFAULT '[]'::jsonb,
  "human_review_required" boolean NOT NULL DEFAULT false,
  "alert_id" varchar,
  "incident_id" varchar
);
CREATE INDEX "idx_ai_guard_events_org_created" ON "ai_guard_events" USING btree ("org_id", "created_at");
CREATE INDEX "idx_ai_guard_events_org_feature" ON "ai_guard_events" USING btree ("org_id", "feature");
CREATE INDEX "idx_ai_guard_events_org_score" ON "ai_guard_events" USING btree ("org_id", "injection_score");
CREATE INDEX "idx_ai_guard_events_alert" ON "ai_guard_events" USING btree ("org_id", "alert_id");
CREATE INDEX "idx_ai_guard_events_incident" ON "ai_guard_events" USING btree ("org_id", "incident_id");
