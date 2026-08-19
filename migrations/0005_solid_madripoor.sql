ALTER TABLE "rag_incident_embeddings" DROP CONSTRAINT "rag_incident_embeddings_incident_id_unique";--> statement-breakpoint
DROP INDEX "idx_rag_kb_source_unique";--> statement-breakpoint
CREATE UNIQUE INDEX "rag_incident_embeddings_org_incident_unique" ON "rag_incident_embeddings" USING btree ("org_id","incident_id");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_rag_kb_source_unique" ON "rag_knowledge_base" USING btree ("org_id","source_type","source_id") WHERE source_id IS NOT NULL;