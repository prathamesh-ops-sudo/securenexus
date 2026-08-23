ALTER TABLE "ai_analyst_decisions"
  ALTER COLUMN "outcome" DROP NOT NULL,
  ADD COLUMN IF NOT EXISTS "unmeasured_invocation_count" integer NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS "proof_receipt_captured" boolean NOT NULL DEFAULT false;

ALTER TABLE "ai_decision_evidence"
  ALTER COLUMN "source_table" DROP NOT NULL,
  ALTER COLUMN "source_primary_key" DROP NOT NULL;

ALTER TABLE "ai_inference_log"
  ALTER COLUMN "input_tokens" DROP NOT NULL,
  ALTER COLUMN "input_tokens" DROP DEFAULT,
  ALTER COLUMN "output_tokens" DROP NOT NULL,
  ALTER COLUMN "output_tokens" DROP DEFAULT,
  ALTER COLUMN "latency_ms" DROP NOT NULL,
  ALTER COLUMN "latency_ms" DROP DEFAULT,
  ALTER COLUMN "cost_estimate_usd" DROP NOT NULL,
  ALTER COLUMN "cost_estimate_usd" DROP DEFAULT;
