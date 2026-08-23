ALTER TABLE "ai_analyst_decisions"
  ALTER COLUMN "confidence_score" DROP NOT NULL,
  ADD COLUMN IF NOT EXISTS "retrieval_status" text,
  ADD COLUMN IF NOT EXISTS "model" text,
  ADD COLUMN IF NOT EXISTS "prompt_id" text,
  ADD COLUMN IF NOT EXISTS "prompt_version" integer,
  ADD COLUMN IF NOT EXISTS "total_input_tokens" integer,
  ADD COLUMN IF NOT EXISTS "total_output_tokens" integer,
  ADD COLUMN IF NOT EXISTS "total_cost_usd" double precision,
  ADD COLUMN IF NOT EXISTS "total_latency_ms" integer;

ALTER TABLE "ai_inference_log"
  ADD COLUMN IF NOT EXISTS "decision_id" varchar REFERENCES "ai_analyst_decisions"("id") ON DELETE SET NULL;

CREATE TABLE IF NOT EXISTS "ai_decision_evidence" (
  "id" varchar PRIMARY KEY DEFAULT gen_random_uuid(),
  "org_id" varchar NOT NULL REFERENCES "organizations"("id") ON DELETE CASCADE,
  "decision_id" varchar NOT NULL REFERENCES "ai_analyst_decisions"("id") ON DELETE CASCADE,
  "source_kind" text NOT NULL,
  "source_table" text NOT NULL,
  "source_primary_key" text NOT NULL,
  "evidence_role" text NOT NULL,
  "evidence_weight" real,
  "value_snapshot" jsonb NOT NULL,
  "created_at" timestamp DEFAULT now()
);

CREATE INDEX IF NOT EXISTS "idx_ai_decision_evidence_org_decision"
  ON "ai_decision_evidence" ("org_id", "decision_id");
CREATE INDEX IF NOT EXISTS "idx_ai_decision_evidence_source"
  ON "ai_decision_evidence" ("org_id", "source_table", "source_primary_key");

CREATE TABLE IF NOT EXISTS "ai_decision_redaction_receipts" (
  "id" varchar PRIMARY KEY DEFAULT gen_random_uuid(),
  "org_id" varchar NOT NULL REFERENCES "organizations"("id") ON DELETE CASCADE,
  "decision_id" varchar NOT NULL REFERENCES "ai_analyst_decisions"("id") ON DELETE CASCADE,
  "invocation_id" varchar NOT NULL,
  "redacted_classes" jsonb NOT NULL,
  "redacted" boolean NOT NULL,
  "created_at" timestamp DEFAULT now()
);

CREATE INDEX IF NOT EXISTS "idx_ai_redaction_receipts_org_decision"
  ON "ai_decision_redaction_receipts" ("org_id", "decision_id");
CREATE INDEX IF NOT EXISTS "idx_ai_redaction_receipts_invocation"
  ON "ai_decision_redaction_receipts" ("invocation_id");

CREATE INDEX IF NOT EXISTS "idx_ai_inference_log_decision"
  ON "ai_inference_log" ("org_id", "decision_id");
