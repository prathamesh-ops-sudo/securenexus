ALTER TABLE "evidence_items" ADD COLUMN "checksum_sha256" text;--> statement-breakpoint
ALTER TABLE "evidence_items" ADD COLUMN "upload_status" text DEFAULT 'pending' NOT NULL;--> statement-breakpoint
ALTER TABLE "evidence_items" ADD COLUMN "uploaded_at" timestamp;