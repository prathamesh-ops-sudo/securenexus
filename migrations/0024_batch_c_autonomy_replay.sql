ALTER TABLE "org_ai_security_settings"
  ADD COLUMN IF NOT EXISTS "autonomy_mode" text NOT NULL DEFAULT 'observe_only';

UPDATE "org_ai_security_settings"
SET "autonomy_mode" = 'observe_only'
WHERE "autonomy_mode" IS NULL;

ALTER TABLE "ai_analyst_decisions"
  ADD COLUMN IF NOT EXISTS "autonomy_mode" text NOT NULL DEFAULT 'observe_only',
  ADD COLUMN IF NOT EXISTS "replay_run_id" varchar;

CREATE INDEX IF NOT EXISTS "idx_ai_decisions_replay_run"
  ON "ai_analyst_decisions" ("org_id", "replay_run_id");

CREATE TABLE IF NOT EXISTS "ai_replay_runs" (
  "id" varchar PRIMARY KEY DEFAULT gen_random_uuid(),
  "org_id" varchar NOT NULL REFERENCES "organizations"("id") ON DELETE CASCADE,
  "from_at" timestamp NOT NULL,
  "to_at" timestamp NOT NULL,
  "source" text,
  "severity" text,
  "reason" text NOT NULL,
  "status" text NOT NULL DEFAULT 'pending',
  "cursor" integer NOT NULL DEFAULT 0,
  "total_count" integer NOT NULL DEFAULT 0,
  "processed_count" integer NOT NULL DEFAULT 0,
  "succeeded_count" integer NOT NULL DEFAULT 0,
  "failed_count" integer NOT NULL DEFAULT 0,
  "consecutive_failures" integer NOT NULL DEFAULT 0,
  "concurrency" integer NOT NULL DEFAULT 1,
  "job_id" varchar,
  "error" text,
  "created_by" varchar,
  "started_at" timestamp,
  "completed_at" timestamp,
  "created_at" timestamp DEFAULT now(),
  "updated_at" timestamp DEFAULT now()
);

CREATE INDEX IF NOT EXISTS "idx_ai_replay_runs_org"
  ON "ai_replay_runs" ("org_id");
CREATE INDEX IF NOT EXISTS "idx_ai_replay_runs_org_status"
  ON "ai_replay_runs" ("org_id", "status");
