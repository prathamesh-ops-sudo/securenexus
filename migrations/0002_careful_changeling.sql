CREATE TABLE "breach_monitoring_targets" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" uuid NOT NULL,
	"target_type" text NOT NULL,
	"target_value" text NOT NULL,
	"label" text,
	"is_active" boolean DEFAULT true NOT NULL,
	"last_checked_at" timestamp,
	"exposure_count" integer DEFAULT 0 NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "dark_web_exposures" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" uuid NOT NULL,
	"target_id" uuid,
	"exposure_type" text NOT NULL,
	"severity" text DEFAULT 'medium' NOT NULL,
	"status" text DEFAULT 'new' NOT NULL,
	"title" text NOT NULL,
	"description" text,
	"source_type" text NOT NULL,
	"source_name" text,
	"source_url" text,
	"breach_date" timestamp,
	"discovered_at" timestamp DEFAULT now() NOT NULL,
	"affected_data" jsonb DEFAULT '[]'::jsonb,
	"affected_count" integer,
	"raw_data" jsonb,
	"matched_value" text,
	"confidence_score" integer DEFAULT 70,
	"mitigation_notes" text,
	"assigned_to" uuid,
	"resolved_at" timestamp,
	"resolved_by" uuid,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "dark_web_monitoring_config" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" uuid NOT NULL,
	"is_enabled" boolean DEFAULT true NOT NULL,
	"scan_frequency_hours" integer DEFAULT 24 NOT NULL,
	"auto_create_alerts" boolean DEFAULT true NOT NULL,
	"alert_severity_threshold" text DEFAULT 'medium' NOT NULL,
	"notify_on_new_exposure" boolean DEFAULT true NOT NULL,
	"hibp_api_key" text,
	"dehashed_api_key" text,
	"last_full_scan_at" timestamp,
	"total_exposures_found" integer DEFAULT 0 NOT NULL,
	"total_exposures_resolved" integer DEFAULT 0 NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "dark_web_scan_history" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" uuid NOT NULL,
	"scan_type" text NOT NULL,
	"status" text DEFAULT 'running' NOT NULL,
	"targets_scanned" integer DEFAULT 0 NOT NULL,
	"new_exposures_found" integer DEFAULT 0 NOT NULL,
	"sources_checked" jsonb DEFAULT '[]'::jsonb,
	"error_message" text,
	"started_at" timestamp DEFAULT now() NOT NULL,
	"completed_at" timestamp,
	"duration_ms" integer
);
--> statement-breakpoint
ALTER TABLE "breach_monitoring_targets" ADD CONSTRAINT "breach_monitoring_targets_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dark_web_exposures" ADD CONSTRAINT "dark_web_exposures_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dark_web_exposures" ADD CONSTRAINT "dark_web_exposures_target_id_breach_monitoring_targets_id_fk" FOREIGN KEY ("target_id") REFERENCES "public"."breach_monitoring_targets"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dark_web_monitoring_config" ADD CONSTRAINT "dark_web_monitoring_config_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dark_web_scan_history" ADD CONSTRAINT "dark_web_scan_history_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;