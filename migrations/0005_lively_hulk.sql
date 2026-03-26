ALTER TABLE "incidents" ADD COLUMN "needs_review" boolean DEFAULT false;--> statement-breakpoint
ALTER TABLE "incidents" ADD COLUMN "algorithm_scores" jsonb;