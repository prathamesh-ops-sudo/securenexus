CREATE TABLE IF NOT EXISTS "ai_inference_log" (
	"id" serial PRIMARY KEY NOT NULL,
	"tier" varchar NOT NULL,
	"model" varchar NOT NULL,
	"prompt_id" varchar,
	"prompt_version" integer,
	"input_tokens" integer DEFAULT 0 NOT NULL,
	"output_tokens" integer DEFAULT 0 NOT NULL,
	"latency_ms" integer DEFAULT 0 NOT NULL,
	"cost_estimate_usd" double precision DEFAULT 0 NOT NULL,
	"cached" boolean DEFAULT false NOT NULL,
	"success" boolean DEFAULT true NOT NULL,
	"error_message" text,
	"org_id" varchar,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_ai_inference_log_tier" ON "ai_inference_log" USING btree ("tier");
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_ai_inference_log_created" ON "ai_inference_log" USING btree ("created_at");
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_ai_inference_log_org" ON "ai_inference_log" USING btree ("org_id");
