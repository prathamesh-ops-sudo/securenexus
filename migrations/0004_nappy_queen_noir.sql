ALTER TABLE "api_keys" ADD COLUMN IF NOT EXISTS "deprecated_at" timestamp;--> statement-breakpoint
ALTER TABLE "api_keys" ADD COLUMN IF NOT EXISTS "grace_expires_at" timestamp;--> statement-breakpoint
ALTER TABLE "api_keys" ADD COLUMN IF NOT EXISTS "replaced_by_key_id" varchar;