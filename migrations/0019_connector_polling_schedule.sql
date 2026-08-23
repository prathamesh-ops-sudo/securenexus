ALTER TABLE "connectors"
  ADD COLUMN IF NOT EXISTS "auto_sync_enabled" boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS "auto_sync_paused_by_auth" boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS "effective_polling_interval_min" integer NOT NULL DEFAULT 5,
  ADD COLUMN IF NOT EXISTS "next_sync_at" timestamp,
  ADD COLUMN IF NOT EXISTS "consecutive_failures" integer NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS "schedule_reason" text NOT NULL DEFAULT 'auto_sync_off',
  ADD COLUMN IF NOT EXISTS "needs_reconnection" boolean NOT NULL DEFAULT false;

WITH "active_connectors" AS (
  SELECT
    "id",
    GREATEST(5, LEAST(1440, COALESCE("polling_interval_min", 5))) AS "interval_min",
    ROW_NUMBER() OVER (PARTITION BY "org_id" ORDER BY "created_at", "id") - 1 AS "position",
    COUNT(*) OVER (PARTITION BY "org_id") AS "connector_count"
  FROM "connectors"
  WHERE "status" = 'active'
)
UPDATE "connectors" AS "c"
SET
  "auto_sync_enabled" = TRUE,
  "auto_sync_paused_by_auth" = FALSE,
  "effective_polling_interval_min" = "a"."interval_min",
  "next_sync_at" = NOW() + (
    "a"."position"::numeric * "a"."interval_min"::numeric / "a"."connector_count"::numeric
  ) * INTERVAL '1 minute',
  "schedule_reason" = 'scheduled'
FROM "active_connectors" AS "a"
WHERE "c"."id" = "a"."id";

UPDATE "connectors"
SET
  "effective_polling_interval_min" = GREATEST(5, LEAST(1440, COALESCE("polling_interval_min", 5))),
  "schedule_reason" = CASE
    WHEN "status" = 'active' THEN 'scheduled'
    ELSE 'connector_inactive'
  END
WHERE "status" <> 'active';

CREATE INDEX IF NOT EXISTS "idx_connectors_due_schedule"
  ON "connectors" ("auto_sync_enabled", "next_sync_at")
  WHERE "auto_sync_enabled" = true AND "needs_reconnection" = false;
