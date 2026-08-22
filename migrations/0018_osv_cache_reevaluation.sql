ALTER TABLE "vuln_packages"
  ADD COLUMN IF NOT EXISTS "last_evaluated_at" timestamp;

ALTER TABLE "cve_sync_states"
  ADD COLUMN IF NOT EXISTS "reevaluation_status" text NOT NULL DEFAULT 'never',
  ADD COLUMN IF NOT EXISTS "reevaluation_last_run_at" timestamp,
  ADD COLUMN IF NOT EXISTS "reevaluation_last_completed_at" timestamp,
  ADD COLUMN IF NOT EXISTS "reevaluation_last_error" text,
  ADD COLUMN IF NOT EXISTS "reevaluation_groups" integer NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS "reevaluation_failed_groups" integer NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS "reevaluation_scope" text,
  ADD COLUMN IF NOT EXISTS "full_reevaluation_last_at" timestamp;

CREATE TABLE IF NOT EXISTS "osv_vulnerability_cache" (
  "id" varchar PRIMARY KEY DEFAULT gen_random_uuid(),
  "advisory_id" text NOT NULL UNIQUE,
  "modified_at" timestamp,
  "fetched_at" timestamp NOT NULL DEFAULT now(),
  "payload" jsonb NOT NULL
);

CREATE INDEX IF NOT EXISTS "idx_osv_vulnerability_cache_advisory"
  ON "osv_vulnerability_cache" ("advisory_id");
CREATE INDEX IF NOT EXISTS "idx_osv_vulnerability_cache_modified"
  ON "osv_vulnerability_cache" ("modified_at");

CREATE TABLE IF NOT EXISTS "vuln_reevaluation_runs" (
  "id" varchar PRIMARY KEY DEFAULT gen_random_uuid(),
  "source" text NOT NULL DEFAULT 'nvd',
  "org_id" varchar NOT NULL REFERENCES "organizations" ("id"),
  "sensor_id" varchar NOT NULL REFERENCES "native_sensors" ("id") ON DELETE CASCADE,
  "status" text NOT NULL,
  "package_count" integer NOT NULL DEFAULT 0,
  "affected_products" jsonb DEFAULT '[]'::jsonb,
  "error" text,
  "started_at" timestamp NOT NULL DEFAULT now(),
  "completed_at" timestamp
);

CREATE INDEX IF NOT EXISTS "idx_vuln_reevaluation_runs_org"
  ON "vuln_reevaluation_runs" ("org_id");
CREATE INDEX IF NOT EXISTS "idx_vuln_reevaluation_runs_sensor"
  ON "vuln_reevaluation_runs" ("sensor_id");
CREATE INDEX IF NOT EXISTS "idx_vuln_reevaluation_runs_started"
  ON "vuln_reevaluation_runs" ("started_at");
