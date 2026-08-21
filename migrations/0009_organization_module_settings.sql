CREATE TABLE "organization_module_settings" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"module_key" text NOT NULL,
	"enabled_by" varchar NOT NULL,
	"enabled_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "organization_module_settings" ADD CONSTRAINT "organization_module_settings_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "idx_org_module_settings_org_module" ON "organization_module_settings" USING btree ("org_id","module_key");--> statement-breakpoint
CREATE INDEX "idx_org_module_settings_org" ON "organization_module_settings" USING btree ("org_id");