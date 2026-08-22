ALTER TABLE "slo_targets" ADD COLUMN "org_id" varchar REFERENCES "organizations"("id");--> statement-breakpoint
