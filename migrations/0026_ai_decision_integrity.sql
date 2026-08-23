ALTER TABLE "ai_analyst_decisions"
  ADD COLUMN IF NOT EXISTS "integrity_digest" text,
  ADD COLUMN IF NOT EXISTS "integrity_previous_digest" text,
  ADD COLUMN IF NOT EXISTS "integrity_sequence" integer,
  ADD COLUMN IF NOT EXISTS "integrity_finalized_at" timestamp;

CREATE UNIQUE INDEX IF NOT EXISTS "idx_ai_decisions_org_integrity_sequence"
  ON "ai_analyst_decisions" ("org_id", "integrity_sequence")
  WHERE "integrity_sequence" IS NOT NULL;
