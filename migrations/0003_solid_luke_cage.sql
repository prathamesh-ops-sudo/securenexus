CREATE EXTENSION IF NOT EXISTS vector;
--> statement-breakpoint
CREATE TABLE "ai_feedback_learning_log" (
	"id" serial PRIMARY KEY NOT NULL,
	"org_id" varchar,
	"feedback_id" varchar NOT NULL,
	"action" varchar NOT NULL,
	"domain" varchar,
	"few_shot_example_id" varchar,
	"source" varchar,
	"category" varchar,
	"details" jsonb,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "ai_few_shot_examples" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid()::text NOT NULL,
	"org_id" varchar,
	"domain" varchar NOT NULL,
	"input" text NOT NULL,
	"incorrect_output" text NOT NULL,
	"correct_output" text NOT NULL,
	"lesson" text NOT NULL,
	"alert_source" varchar,
	"alert_category" varchar,
	"feedback_id" varchar,
	"active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "ai_source_signal_scores" (
	"id" serial PRIMARY KEY NOT NULL,
	"org_id" varchar NOT NULL,
	"source" varchar NOT NULL,
	"category" varchar DEFAULT '' NOT NULL,
	"total_feedback" integer DEFAULT 0 NOT NULL,
	"overridden_count" integer DEFAULT 0 NOT NULL,
	"dismissed_count" integer DEFAULT 0 NOT NULL,
	"fp_rate" double precision DEFAULT 0 NOT NULL,
	"suppressed" boolean DEFAULT false NOT NULL,
	"manual_override" boolean DEFAULT false NOT NULL,
	"last_updated" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "rag_incident_embeddings" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"incident_id" text NOT NULL,
	"title" text NOT NULL,
	"summary" text,
	"severity" text,
	"mitre_tactics" text[],
	"mitre_techniques" text[],
	"iocs" text[],
	"content" text NOT NULL,
	"embedding" vector(1024),
	"created_at" timestamp with time zone DEFAULT now(),
	"updated_at" timestamp with time zone DEFAULT now(),
	CONSTRAINT "rag_incident_embeddings_incident_id_unique" UNIQUE("incident_id")
);
--> statement-breakpoint
CREATE TABLE "rag_knowledge_base" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"category" text NOT NULL,
	"source_type" text NOT NULL,
	"source_id" text,
	"title" text NOT NULL,
	"content" text NOT NULL,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"embedding" vector(1024),
	"created_at" timestamp with time zone DEFAULT now(),
	"updated_at" timestamp with time zone DEFAULT now()
);
--> statement-breakpoint
ALTER TABLE "ai_feedback_learning_log" ADD CONSTRAINT "ai_feedback_learning_log_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ai_few_shot_examples" ADD CONSTRAINT "ai_few_shot_examples_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ai_source_signal_scores" ADD CONSTRAINT "ai_source_signal_scores_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rag_incident_embeddings" ADD CONSTRAINT "rag_incident_embeddings_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rag_knowledge_base" ADD CONSTRAINT "rag_knowledge_base_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_feedback_learning_org" ON "ai_feedback_learning_log" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_few_shot_org_domain" ON "ai_few_shot_examples" USING btree ("org_id","domain");--> statement-breakpoint
CREATE INDEX "idx_few_shot_active" ON "ai_few_shot_examples" USING btree ("active");--> statement-breakpoint
CREATE INDEX "idx_few_shot_feedback" ON "ai_few_shot_examples" USING btree ("feedback_id");--> statement-breakpoint
CREATE INDEX "idx_source_signal_org" ON "ai_source_signal_scores" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_source_signal_suppressed" ON "ai_source_signal_scores" USING btree ("org_id","suppressed");--> statement-breakpoint
CREATE UNIQUE INDEX "uq_ai_source_signal_org_source_category" ON "ai_source_signal_scores" USING btree ("org_id","source","category");--> statement-breakpoint
CREATE INDEX "idx_rag_incident_org" ON "rag_incident_embeddings" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_rag_kb_category" ON "rag_knowledge_base" USING btree ("category");--> statement-breakpoint
CREATE INDEX "idx_rag_kb_org" ON "rag_knowledge_base" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_rag_kb_source" ON "rag_knowledge_base" USING btree ("source_type","source_id");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_rag_kb_source_unique" ON "rag_knowledge_base" USING btree ("source_type","source_id") WHERE source_id IS NOT NULL;