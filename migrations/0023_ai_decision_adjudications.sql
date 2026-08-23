CREATE UNIQUE INDEX IF NOT EXISTS "idx_ai_decisions_org_id_unique"
  ON "ai_analyst_decisions" ("org_id", "id");

CREATE TABLE IF NOT EXISTS "ai_decision_adjudications" (
  "id" varchar PRIMARY KEY DEFAULT gen_random_uuid(),
  "org_id" varchar NOT NULL REFERENCES "organizations"("id") ON DELETE CASCADE,
  "decision_id" varchar NOT NULL,
  "alert_id" varchar REFERENCES "alerts"("id") ON DELETE SET NULL,
  "adjudicated_outcome" text NOT NULL CHECK ("adjudicated_outcome" IN ('malicious', 'benign', 'inconclusive')),
  "source" text NOT NULL CHECK ("source" IN ('analyst_override', 'analyst_feedback', 'manual_review', 'external')),
  "actor_user_id" varchar,
  "rationale" text NOT NULL,
  "adjudicated_at" timestamp NOT NULL DEFAULT now(),
  "is_final" boolean NOT NULL DEFAULT false,
  "created_at" timestamp NOT NULL DEFAULT now(),
  CONSTRAINT "ai_adjudications_decision_fk"
    FOREIGN KEY ("decision_id") REFERENCES "ai_analyst_decisions"("id") ON DELETE CASCADE,
  CONSTRAINT "ai_adjudications_org_decision_fk"
    FOREIGN KEY ("org_id", "decision_id")
    REFERENCES "ai_analyst_decisions"("org_id", "id") ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS "idx_ai_adjudications_org_decision"
  ON "ai_decision_adjudications" ("org_id", "decision_id");
CREATE INDEX IF NOT EXISTS "idx_ai_adjudications_org_time"
  ON "ai_decision_adjudications" ("org_id", "adjudicated_at");
CREATE UNIQUE INDEX IF NOT EXISTS "idx_ai_adjudications_one_final"
  ON "ai_decision_adjudications" ("decision_id")
  WHERE "is_final" = true;
