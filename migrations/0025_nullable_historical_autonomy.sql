ALTER TABLE "ai_analyst_decisions"
  ALTER COLUMN "autonomy_mode" DROP NOT NULL,
  ALTER COLUMN "autonomy_mode" DROP DEFAULT;

UPDATE "ai_analyst_decisions"
SET "autonomy_mode" = NULL
WHERE "created_at" < TIMESTAMPTZ '2026-08-23 13:47:00+00'
  AND "replay_run_id" IS NULL;

ALTER TABLE "ai_replay_runs"
  ADD COLUMN IF NOT EXISTS "report" jsonb;
