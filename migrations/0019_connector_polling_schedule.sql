ALTER TABLE "connectors"
  ADD COLUMN IF NOT EXISTS "auto_sync_enabled" boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS "effective_polling_interval_min" integer NOT NULL DEFAULT 5,
  ADD COLUMN IF NOT EXISTS "next_sync_at" timestamp,
  ADD COLUMN IF NOT EXISTS "consecutive_failures" integer NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS "schedule_reason" text NOT NULL DEFAULT 'auto_sync_off',
  ADD COLUMN IF NOT EXISTS "needs_reconnection" boolean NOT NULL DEFAULT false;

UPDATE "connectors"
SET "effective_polling_interval_min" = GREATEST(5, LEAST(1440, COALESCE("polling_interval_min", 5))),
       "schedule_reason" = CASE
         WHEN "status" = 'active' THEN 'auto_sync_off'
         ELSE 'connector_inactive'
       END;

CREATE INDEX IF NOT EXISTS "idx_connectors_due_schedule"
  ON "connectors" ("auto_sync_enabled", "next_sync_at")
  WHERE "auto_sync_enabled" = true AND "needs_reconnection" = false;
