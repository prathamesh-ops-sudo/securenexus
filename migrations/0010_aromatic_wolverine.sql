ALTER TABLE "report_runs" ADD COLUMN "generation_status" text DEFAULT 'pending' NOT NULL;--> statement-breakpoint
ALTER TABLE "report_runs" ADD COLUMN "delivery_status" text DEFAULT 'pending' NOT NULL;--> statement-breakpoint
ALTER TABLE "report_runs" ADD COLUMN "delivery_reason" text;