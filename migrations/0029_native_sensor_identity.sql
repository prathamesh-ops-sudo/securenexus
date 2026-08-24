ALTER TABLE "native_sensors"
  ADD COLUMN IF NOT EXISTS "machine_identity" text;
--> statement-breakpoint
ALTER TABLE "native_sensors"
  ADD COLUMN IF NOT EXISTS "machine_identity_source" text;
--> statement-breakpoint
ALTER TABLE "native_sensors"
  ADD COLUMN IF NOT EXISTS "superseded_at" timestamp;
--> statement-breakpoint
ALTER TABLE "native_sensors"
  ADD COLUMN IF NOT EXISTS "superseded_by_sensor_id" varchar;
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_native_sensors_machine_identity"
  ON "native_sensors" ("org_id", "machine_identity");
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "idx_native_sensors_active_machine_identity"
  ON "native_sensors" ("org_id", "machine_identity")
  WHERE "machine_identity" IS NOT NULL
    AND "revoked_at" IS NULL
    AND "status" <> 'superseded';
