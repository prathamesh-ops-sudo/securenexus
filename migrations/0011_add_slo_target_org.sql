ALTER TABLE "slo_targets" ADD COLUMN IF NOT EXISTS "org_id" varchar REFERENCES "organizations"("id");--> statement-breakpoint
