ALTER TABLE "native_sensors"
  ALTER COLUMN "registration_token" DROP NOT NULL;

ALTER TABLE "native_sensors"
  ADD COLUMN IF NOT EXISTS "revoked_at" timestamp,
  ADD COLUMN IF NOT EXISTS "last_telemetry_at" timestamp;

CREATE TABLE IF NOT EXISTS "sensor_enrollment_tokens" (
  "id" varchar PRIMARY KEY DEFAULT gen_random_uuid(),
  "org_id" varchar NOT NULL REFERENCES "organizations"("id"),
  "token_hash" text NOT NULL,
  "label" text NOT NULL,
  "max_uses" integer NOT NULL DEFAULT 1,
  "use_count" integer NOT NULL DEFAULT 0,
  "expires_at" timestamp NOT NULL,
  "revoked_at" timestamp,
  "created_by" varchar NOT NULL,
  "platform_hint" text,
  "created_at" timestamp DEFAULT now(),
  "updated_at" timestamp DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS "idx_sensor_enrollment_tokens_hash"
  ON "sensor_enrollment_tokens" ("token_hash");
CREATE INDEX IF NOT EXISTS "idx_sensor_enrollment_tokens_org"
  ON "sensor_enrollment_tokens" ("org_id");

CREATE TABLE IF NOT EXISTS "sensor_ingest_batches" (
  "id" varchar PRIMARY KEY DEFAULT gen_random_uuid(),
  "org_id" varchar NOT NULL REFERENCES "organizations"("id"),
  "sensor_id" varchar NOT NULL REFERENCES "native_sensors"("id") ON DELETE CASCADE,
  "batch_id" text NOT NULL,
  "status" text NOT NULL DEFAULT 'processing',
  "accepted" integer NOT NULL DEFAULT 0,
  "rejected" integer NOT NULL DEFAULT 0,
  "alerts_created" integer NOT NULL DEFAULT 0,
  "events_matched" integer NOT NULL DEFAULT 0,
  "created_at" timestamp DEFAULT now(),
  "completed_at" timestamp
);

CREATE UNIQUE INDEX IF NOT EXISTS "idx_sensor_ingest_batches_sensor_batch"
  ON "sensor_ingest_batches" ("sensor_id", "batch_id");
CREATE INDEX IF NOT EXISTS "idx_sensor_ingest_batches_org"
  ON "sensor_ingest_batches" ("org_id");

ALTER TABLE "sensor_events"
  ADD COLUMN IF NOT EXISTS "batch_id" text,
  ADD COLUMN IF NOT EXISTS "batch_event_index" integer;

CREATE UNIQUE INDEX IF NOT EXISTS "idx_sensor_events_sensor_batch_index"
  ON "sensor_events" ("sensor_id", "batch_id", "batch_event_index");

ALTER TABLE "collector_instances"
  ADD COLUMN IF NOT EXISTS "api_key" text,
  ADD COLUMN IF NOT EXISTS "api_key_prefix" text,
  ADD COLUMN IF NOT EXISTS "revoked_at" timestamp;
