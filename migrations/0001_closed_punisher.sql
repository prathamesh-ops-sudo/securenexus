CREATE TABLE "evidence_access_requests" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"evidence_id" varchar NOT NULL,
	"requested_by" varchar,
	"requested_by_name" text,
	"reason" text NOT NULL,
	"access_type" text DEFAULT 'view' NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"decision_note" text,
	"decided_by" varchar,
	"decided_by_name" text,
	"decided_at" timestamp,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "evidence_tags" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"evidence_id" varchar NOT NULL,
	"tag" text NOT NULL,
	"category" text DEFAULT 'other' NOT NULL,
	"created_by" varchar,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "investigation_annotations" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"investigation_id" varchar NOT NULL,
	"text" text NOT NULL,
	"marker_type" text DEFAULT 'note' NOT NULL,
	"color" text DEFAULT '#3b82f6' NOT NULL,
	"created_by" varchar,
	"created_by_name" text,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "playbook_template_ratings" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"template_id" varchar NOT NULL,
	"rating" integer NOT NULL,
	"rated_by" varchar,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
ALTER TABLE "evidence_access_requests" ADD CONSTRAINT "evidence_access_requests_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "evidence_access_requests" ADD CONSTRAINT "evidence_access_requests_evidence_id_evidence_items_id_fk" FOREIGN KEY ("evidence_id") REFERENCES "public"."evidence_items"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "evidence_tags" ADD CONSTRAINT "evidence_tags_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "evidence_tags" ADD CONSTRAINT "evidence_tags_evidence_id_evidence_items_id_fk" FOREIGN KEY ("evidence_id") REFERENCES "public"."evidence_items"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_annotations" ADD CONSTRAINT "investigation_annotations_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_annotations" ADD CONSTRAINT "investigation_annotations_investigation_id_investigation_runs_id_fk" FOREIGN KEY ("investigation_id") REFERENCES "public"."investigation_runs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "playbook_template_ratings" ADD CONSTRAINT "playbook_template_ratings_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_evidence_access_org" ON "evidence_access_requests" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_evidence_access_evidence" ON "evidence_access_requests" USING btree ("evidence_id");--> statement-breakpoint
CREATE INDEX "idx_evidence_access_status" ON "evidence_access_requests" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_evidence_tags_org" ON "evidence_tags" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_evidence_tags_evidence" ON "evidence_tags" USING btree ("evidence_id");--> statement-breakpoint
CREATE UNIQUE INDEX "uq_evidence_tags_evidence_tag" ON "evidence_tags" USING btree ("evidence_id","tag");--> statement-breakpoint
CREATE INDEX "idx_investigation_annotations_org" ON "investigation_annotations" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_investigation_annotations_investigation" ON "investigation_annotations" USING btree ("investigation_id");--> statement-breakpoint
CREATE INDEX "idx_template_ratings_org" ON "playbook_template_ratings" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_template_ratings_template" ON "playbook_template_ratings" USING btree ("template_id");--> statement-breakpoint
CREATE UNIQUE INDEX "uq_template_ratings_org_template" ON "playbook_template_ratings" USING btree ("org_id","template_id");