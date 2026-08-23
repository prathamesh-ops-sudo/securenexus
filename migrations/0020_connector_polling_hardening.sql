ALTER TABLE "connectors"
  ADD COLUMN IF NOT EXISTS "auto_sync_paused_by_auth" boolean NOT NULL DEFAULT false;

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
