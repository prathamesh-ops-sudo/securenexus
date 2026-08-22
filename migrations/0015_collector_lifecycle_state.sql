ALTER TABLE "collector_instances"
  ADD COLUMN IF NOT EXISTS "lifecycle_state" text NOT NULL DEFAULT 'enrolled-but-never-heartbeated';

CREATE TABLE IF NOT EXISTS "collector_ingest_batches" (
  "id" varchar PRIMARY KEY DEFAULT gen_random_uuid(),
  "org_id" varchar NOT NULL REFERENCES "organizations"("id"),
  "collector_id" varchar NOT NULL REFERENCES "collector_instances"("id") ON DELETE CASCADE,
  "batch_id" text NOT NULL,
  "accepted" integer NOT NULL DEFAULT 0,
  "created_at" timestamp DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS "idx_collector_ingest_batches_collector_batch"
  ON "collector_ingest_batches" ("collector_id", "batch_id");
CREATE INDEX IF NOT EXISTS "idx_collector_ingest_batches_org"
  ON "collector_ingest_batches" ("org_id");
