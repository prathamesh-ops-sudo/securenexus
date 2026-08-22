CREATE TABLE IF NOT EXISTS "sensor_policies" (
  "id" varchar PRIMARY KEY DEFAULT gen_random_uuid(),
  "org_id" varchar NOT NULL REFERENCES "organizations"("id"),
  "name" text NOT NULL,
  "platform" text,
  "telemetry_level" text NOT NULL DEFAULT 'standard',
  "heartbeat_interval" integer NOT NULL DEFAULT 60,
  "auto_update" boolean NOT NULL DEFAULT true,
  "created_by" varchar,
  "created_at" timestamp DEFAULT now(),
  "updated_at" timestamp DEFAULT now()
);--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_sensor_policies_org" ON "sensor_policies" ("org_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_sensor_policies_platform" ON "sensor_policies" ("org_id", "platform");--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "detection_rule_versions" (
  "id" varchar PRIMARY KEY DEFAULT gen_random_uuid(),
  "org_id" varchar NOT NULL REFERENCES "organizations"("id"),
  "rule_id" varchar NOT NULL REFERENCES "detection_rules"("id"),
  "version" integer NOT NULL,
  "snapshot" jsonb NOT NULL,
  "created_by" varchar,
  "created_at" timestamp DEFAULT now()
);--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_detection_rule_versions_org" ON "detection_rule_versions" ("org_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_detection_rule_versions_rule" ON "detection_rule_versions" ("org_id", "rule_id");--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "uq_detection_rule_versions_rule_version" ON "detection_rule_versions" ("org_id", "rule_id", "version");--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "playbook_notification_templates" (
  "id" varchar PRIMARY KEY DEFAULT gen_random_uuid(),
  "org_id" varchar NOT NULL REFERENCES "organizations"("id"),
  "playbook_id" varchar NOT NULL REFERENCES "playbooks"("id"),
  "channel" text NOT NULL,
  "subject" text,
  "body" text NOT NULL,
  "recipients" text,
  "webhook_url" text,
  "urgency" text NOT NULL DEFAULT 'high',
  "created_by" varchar,
  "created_by_name" text,
  "created_at" timestamp DEFAULT now(),
  "updated_at" timestamp DEFAULT now()
);--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_playbook_notification_templates_org" ON "playbook_notification_templates" ("org_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_playbook_notification_templates_playbook"
  ON "playbook_notification_templates" ("org_id", "playbook_id");--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "playbook_change_tickets" (
  "id" varchar PRIMARY KEY,
  "org_id" varchar NOT NULL REFERENCES "organizations"("id"),
  "playbook_id" varchar NOT NULL REFERENCES "playbooks"("id"),
  "execution_id" varchar REFERENCES "playbook_executions"("id"),
  "playbook_name" text NOT NULL,
  "change_type" text NOT NULL,
  "summary" text NOT NULL,
  "description" text,
  "impact_assessment" text,
  "rollback_plan" text,
  "requires_approval" boolean NOT NULL DEFAULT true,
  "status" text NOT NULL DEFAULT 'pending_approval',
  "requested_by" text,
  "requested_at" timestamp DEFAULT now(),
  "approved_by" text,
  "approved_at" timestamp,
  "implemented_at" timestamp,
  "closed_at" timestamp,
  "change_log" jsonb NOT NULL DEFAULT '[]'::jsonb,
  "created_at" timestamp DEFAULT now(),
  "updated_at" timestamp DEFAULT now()
);--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_playbook_change_tickets_org" ON "playbook_change_tickets" ("org_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_playbook_change_tickets_playbook"
  ON "playbook_change_tickets" ("org_id", "playbook_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_playbook_change_tickets_status"
  ON "playbook_change_tickets" ("org_id", "status");
