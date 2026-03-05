CREATE TABLE "notification_user_preferences" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" varchar NOT NULL,
	"org_id" varchar,
	"channel_ids" text[] DEFAULT ARRAY[]::text[],
	"event_types" text[] DEFAULT ARRAY['incident_created'],
	"min_severity" text DEFAULT 'info',
	"quiet_hours_start" integer,
	"quiet_hours_end" integer,
	"digest_enabled" boolean DEFAULT false,
	"digest_frequency_hours" integer DEFAULT 24,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "notification_delivery_log" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"channel_id" varchar NOT NULL,
	"channel_name" text NOT NULL,
	"channel_type" text NOT NULL,
	"org_id" varchar,
	"event_type" text NOT NULL,
	"title" text NOT NULL,
	"severity" text NOT NULL,
	"success" boolean NOT NULL,
	"error_message" text,
	"delivered_at" timestamp DEFAULT now(),
	"metadata" jsonb
);
--> statement-breakpoint
CREATE INDEX "idx_notification_user_prefs_user" ON "notification_user_preferences" USING btree ("user_id");
--> statement-breakpoint
CREATE INDEX "idx_notification_user_prefs_org" ON "notification_user_preferences" USING btree ("org_id");
--> statement-breakpoint
CREATE UNIQUE INDEX "idx_notification_user_prefs_user_org" ON "notification_user_preferences" USING btree ("user_id","org_id");
--> statement-breakpoint
CREATE INDEX "idx_notification_delivery_log_channel" ON "notification_delivery_log" USING btree ("channel_id");
--> statement-breakpoint
CREATE INDEX "idx_notification_delivery_log_org_delivered" ON "notification_delivery_log" USING btree ("org_id","delivered_at");
--> statement-breakpoint
CREATE INDEX "idx_notification_delivery_log_delivered" ON "notification_delivery_log" USING btree ("delivered_at");
--> statement-breakpoint
ALTER TABLE "notification_user_preferences" ADD CONSTRAINT "notification_user_preferences_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "notification_delivery_log" ADD CONSTRAINT "notification_delivery_log_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;
