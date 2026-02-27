CREATE TABLE "ai_deployment_configs" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"backend" text DEFAULT 'bedrock',
	"model_id" text,
	"endpoint_url" text,
	"region" text DEFAULT 'us-east-1',
	"data_residency" text DEFAULT 'us',
	"allow_external_calls" boolean DEFAULT true,
	"config" jsonb DEFAULT '{}'::jsonb,
	"updated_at" timestamp DEFAULT now(),
	CONSTRAINT "ai_deployment_configs_org_id_unique" UNIQUE("org_id")
);
--> statement-breakpoint
CREATE TABLE "ai_feedback" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"user_id" varchar,
	"user_name" text,
	"resource_type" text NOT NULL,
	"resource_id" varchar,
	"rating" integer NOT NULL,
	"comment" text,
	"correction_reason" text,
	"corrected_severity" text,
	"corrected_category" text,
	"ai_output" jsonb,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "alert_daily_stats" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"date" text NOT NULL,
	"total_alerts" integer DEFAULT 0,
	"critical_count" integer DEFAULT 0,
	"high_count" integer DEFAULT 0,
	"medium_count" integer DEFAULT 0,
	"low_count" integer DEFAULT 0,
	"info_count" integer DEFAULT 0,
	"source_counts" jsonb,
	"category_counts" jsonb,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "alert_dedup_clusters" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"canonical_alert_id" varchar,
	"match_reason" text NOT NULL,
	"match_confidence" real DEFAULT 0,
	"alert_count" integer DEFAULT 1,
	"first_seen_at" timestamp DEFAULT now(),
	"last_seen_at" timestamp DEFAULT now(),
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "alert_entities" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"alert_id" varchar NOT NULL,
	"entity_id" varchar NOT NULL,
	"role" text NOT NULL,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "alert_tags" (
	"alert_id" varchar NOT NULL,
	"tag_id" varchar NOT NULL
);
--> statement-breakpoint
CREATE TABLE "alerts" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"source" text NOT NULL,
	"source_event_id" text,
	"category" text DEFAULT 'other',
	"severity" text NOT NULL,
	"title" text NOT NULL,
	"description" text,
	"raw_data" jsonb,
	"normalized_data" jsonb,
	"ocsf_data" jsonb,
	"source_ip" text,
	"dest_ip" text,
	"source_port" integer,
	"dest_port" integer,
	"protocol" text,
	"user_id_field" text,
	"hostname" text,
	"file_hash" text,
	"url" text,
	"domain" text,
	"mitre_tactic" text,
	"mitre_technique" text,
	"status" text DEFAULT 'new' NOT NULL,
	"incident_id" varchar,
	"correlation_score" real,
	"correlation_reason" text,
	"correlation_cluster_id" varchar,
	"suppressed" boolean DEFAULT false,
	"suppressed_by" varchar,
	"suppression_rule_id" varchar,
	"confidence_score" real,
	"confidence_source" text,
	"confidence_notes" text,
	"dedup_cluster_id" varchar,
	"analyst_notes" text,
	"assigned_to" varchar,
	"detected_at" timestamp,
	"ingested_at" timestamp DEFAULT now(),
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "alerts_archive" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"source" text NOT NULL,
	"source_event_id" text,
	"category" text DEFAULT 'other',
	"severity" text NOT NULL,
	"title" text NOT NULL,
	"description" text,
	"raw_data" jsonb,
	"normalized_data" jsonb,
	"ocsf_data" jsonb,
	"source_ip" text,
	"dest_ip" text,
	"source_port" integer,
	"dest_port" integer,
	"protocol" text,
	"user_id_field" text,
	"hostname" text,
	"file_hash" text,
	"url" text,
	"domain" text,
	"mitre_tactic" text,
	"mitre_technique" text,
	"status" text DEFAULT 'new' NOT NULL,
	"incident_id" varchar,
	"correlation_score" real,
	"correlation_reason" text,
	"correlation_cluster_id" varchar,
	"suppressed" boolean DEFAULT false,
	"suppressed_by" varchar,
	"suppression_rule_id" varchar,
	"confidence_score" real,
	"confidence_source" text,
	"confidence_notes" text,
	"dedup_cluster_id" varchar,
	"analyst_notes" text,
	"assigned_to" varchar,
	"detected_at" timestamp,
	"ingested_at" timestamp DEFAULT now(),
	"created_at" timestamp DEFAULT now(),
	"archived_at" timestamp DEFAULT now(),
	"archive_reason" text
);
--> statement-breakpoint
CREATE TABLE "anomaly_subscriptions" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"name" text NOT NULL,
	"metric_prefix" text DEFAULT '',
	"minimum_severity" text DEFAULT 'medium' NOT NULL,
	"min_delta" real DEFAULT 10 NOT NULL,
	"channel" text DEFAULT 'in_app' NOT NULL,
	"target" text,
	"status" text DEFAULT 'active' NOT NULL,
	"created_by" varchar,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "api_keys" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"name" text NOT NULL,
	"key_hash" text NOT NULL,
	"key_prefix" text NOT NULL,
	"scopes" text[] DEFAULT ARRAY['ingest'],
	"is_active" boolean DEFAULT true,
	"webhook_secret" text,
	"last_used_at" timestamp,
	"created_by" varchar,
	"created_at" timestamp DEFAULT now(),
	"revoked_at" timestamp
);
--> statement-breakpoint
CREATE TABLE "approval_decision_records" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"approval_subject_type" text NOT NULL,
	"approval_subject_id" varchar NOT NULL,
	"decision" text NOT NULL,
	"reason" text,
	"approver_user_id" varchar NOT NULL,
	"approver_user_name" text,
	"approver_role" text,
	"ip_address" text,
	"decided_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "attack_paths" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"cluster_id" varchar,
	"campaign_id" varchar,
	"alert_ids" text[],
	"entity_ids" text[],
	"nodes" jsonb NOT NULL,
	"edges" jsonb NOT NULL,
	"tactics_sequence" text[],
	"techniques_used" text[],
	"hop_count" integer DEFAULT 0,
	"confidence" real DEFAULT 0 NOT NULL,
	"time_span_hours" real,
	"first_alert_at" timestamp,
	"last_alert_at" timestamp,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "attack_surface_assets" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"entity_type" text NOT NULL,
	"entity_value" text NOT NULL,
	"first_seen_at" timestamp NOT NULL,
	"last_seen_at" timestamp NOT NULL,
	"risk_score" real DEFAULT 0 NOT NULL,
	"alert_count" integer DEFAULT 0 NOT NULL,
	"critical_count" integer DEFAULT 0 NOT NULL,
	"exposures" jsonb,
	"related_sources" text[],
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "audit_logs" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"user_id" varchar,
	"user_name" text,
	"action" text NOT NULL,
	"resource_type" text,
	"resource_id" varchar,
	"details" jsonb,
	"ip_address" text,
	"entry_hash" text,
	"prev_hash" text,
	"sequence_num" integer,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "audit_verification_runs" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"status" text DEFAULT 'running' NOT NULL,
	"range_start" integer NOT NULL,
	"range_end" integer NOT NULL,
	"records_checked" integer DEFAULT 0 NOT NULL,
	"chain_valid" boolean,
	"first_break_at" integer,
	"tampered_count" integer DEFAULT 0 NOT NULL,
	"tampered_records" jsonb,
	"missing_sequences" integer[],
	"triggered_by" text DEFAULT 'scheduled' NOT NULL,
	"triggered_by_user_id" varchar,
	"triggered_by_user_name" text,
	"verification_duration_ms" integer,
	"verified_at" timestamp,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "auto_response_policies" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"name" text NOT NULL,
	"description" text,
	"trigger_type" text NOT NULL,
	"conditions" jsonb NOT NULL,
	"actions" jsonb NOT NULL,
	"confidence_threshold" real DEFAULT 0.85 NOT NULL,
	"severity_filter" text[],
	"requires_approval" boolean DEFAULT true,
	"max_actions_per_hour" integer DEFAULT 10,
	"cooldown_minutes" integer DEFAULT 30,
	"status" text DEFAULT 'inactive' NOT NULL,
	"execution_count" integer DEFAULT 0,
	"last_triggered_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "blast_radius_previews" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"playbook_id" varchar NOT NULL,
	"execution_context" jsonb,
	"affected_entities" jsonb,
	"affected_entity_count" integer DEFAULT 0 NOT NULL,
	"risk_level" text DEFAULT 'low' NOT NULL,
	"risk_factors" jsonb,
	"estimated_duration_ms" integer,
	"rollback_plan" jsonb,
	"reversible" boolean DEFAULT true,
	"previewed_by" varchar,
	"previewed_by_name" text,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "campaigns" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"name" text NOT NULL,
	"fingerprint" text NOT NULL,
	"tactics_sequence" text[],
	"entity_signature" text[],
	"source_signature" text[],
	"cluster_ids" text[],
	"attack_path_ids" text[],
	"confidence" real DEFAULT 0 NOT NULL,
	"alert_count" integer DEFAULT 0,
	"status" text DEFAULT 'active' NOT NULL,
	"first_seen_at" timestamp,
	"last_seen_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "compliance_control_mappings" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"control_id" varchar NOT NULL,
	"resource_type" text NOT NULL,
	"resource_id" text NOT NULL,
	"status" text DEFAULT 'not_assessed' NOT NULL,
	"evidence_notes" text,
	"last_assessed_at" timestamp,
	"assessed_by" text,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "compliance_controls" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"framework" text NOT NULL,
	"control_id" text NOT NULL,
	"title" text NOT NULL,
	"description" text,
	"category" text,
	"parent_control_id" text,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "compliance_policies" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"alert_retention_days" integer DEFAULT 365,
	"incident_retention_days" integer DEFAULT 730,
	"audit_log_retention_days" integer DEFAULT 2555,
	"pii_masking_enabled" boolean DEFAULT false,
	"pseudonymize_exports" boolean DEFAULT true,
	"enabled_frameworks" text[] DEFAULT ARRAY['gdpr'],
	"data_processing_basis" text DEFAULT 'legitimate_interest',
	"dpo_email" text,
	"dsar_sla_days" integer DEFAULT 30,
	"retention_last_run_at" timestamp,
	"retention_last_deleted_count" integer DEFAULT 0,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "connector_health_checks" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"connector_id" varchar NOT NULL,
	"org_id" varchar,
	"status" text DEFAULT 'healthy' NOT NULL,
	"latency_ms" integer,
	"error_message" text,
	"credential_expires_at" timestamp,
	"credential_status" text DEFAULT 'valid',
	"checked_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "connector_job_runs" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"connector_id" varchar NOT NULL,
	"org_id" varchar,
	"status" text DEFAULT 'running' NOT NULL,
	"attempt" integer DEFAULT 1 NOT NULL,
	"max_attempts" integer DEFAULT 3 NOT NULL,
	"alerts_received" integer DEFAULT 0,
	"alerts_created" integer DEFAULT 0,
	"alerts_deduped" integer DEFAULT 0,
	"alerts_failed" integer DEFAULT 0,
	"latency_ms" integer,
	"error_message" text,
	"error_type" text,
	"http_status" integer,
	"throttled" boolean DEFAULT false,
	"is_dead_letter" boolean DEFAULT false,
	"retry_strategy" text DEFAULT 'exponential',
	"backoff_seconds" integer,
	"next_retry_at" timestamp,
	"checkpoint_data" jsonb,
	"checkpoint_at" timestamp,
	"pagination_cursor" text,
	"fetch_window_start" timestamp,
	"fetch_window_end" timestamp,
	"started_at" timestamp DEFAULT now(),
	"completed_at" timestamp
);
--> statement-breakpoint
CREATE TABLE "connector_secret_rotations" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"connector_id" varchar NOT NULL,
	"org_id" varchar,
	"secret_field" text NOT NULL,
	"last_rotated_at" timestamp,
	"next_rotation_due" timestamp,
	"rotation_interval_days" integer DEFAULT 90,
	"status" text DEFAULT 'current' NOT NULL,
	"rotated_by" varchar,
	"rotated_by_name" text,
	"reminder_sent_at" timestamp,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "connectors" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"name" text NOT NULL,
	"type" text NOT NULL,
	"auth_type" text NOT NULL,
	"config" jsonb NOT NULL,
	"status" text DEFAULT 'inactive' NOT NULL,
	"polling_interval_min" integer DEFAULT 5,
	"last_sync_at" timestamp,
	"last_sync_status" text,
	"last_sync_alerts" integer DEFAULT 0,
	"last_sync_error" text,
	"total_alerts_synced" integer DEFAULT 0,
	"created_by" varchar,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "correlation_clusters" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"incident_id" varchar,
	"confidence" real DEFAULT 0 NOT NULL,
	"method" text NOT NULL,
	"shared_entities" jsonb,
	"reasoning_trace" text,
	"alert_ids" text[],
	"status" text DEFAULT 'pending' NOT NULL,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "cspm_accounts" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"cloud_provider" text NOT NULL,
	"account_id" text NOT NULL,
	"display_name" text NOT NULL,
	"regions" text[] DEFAULT ARRAY[]::text[],
	"status" text DEFAULT 'active',
	"config" jsonb DEFAULT '{}'::jsonb,
	"last_scan_at" timestamp,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "cspm_findings" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"scan_id" varchar NOT NULL,
	"account_id" varchar NOT NULL,
	"rule_id" text NOT NULL,
	"rule_name" text NOT NULL,
	"severity" text NOT NULL,
	"resource_type" text NOT NULL,
	"resource_id" text NOT NULL,
	"resource_region" text,
	"description" text NOT NULL,
	"remediation" text,
	"compliance_frameworks" text[] DEFAULT ARRAY[]::text[],
	"status" text DEFAULT 'open',
	"detected_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "cspm_scans" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"account_id" varchar NOT NULL,
	"status" text DEFAULT 'pending',
	"findings_count" integer DEFAULT 0,
	"summary" jsonb DEFAULT '{}'::jsonb,
	"started_at" timestamp DEFAULT now(),
	"completed_at" timestamp
);
--> statement-breakpoint
CREATE TABLE "dashboard_metrics_cache" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"metric_type" text NOT NULL,
	"payload" jsonb NOT NULL,
	"generated_at" timestamp DEFAULT now(),
	"expires_at" timestamp NOT NULL,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "dr_runbooks" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"title" text NOT NULL,
	"description" text,
	"category" text NOT NULL,
	"steps" jsonb NOT NULL,
	"rto_minutes" integer,
	"rpo_minutes" integer,
	"owner" text,
	"last_tested_at" timestamp,
	"last_test_result" text,
	"test_notes" text,
	"status" text DEFAULT 'active',
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "dsar_requests" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"requestor_email" text NOT NULL,
	"request_type" text DEFAULT 'access' NOT NULL,
	"subject_identifiers" jsonb NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"due_date" timestamp,
	"notes" text,
	"result_summary" jsonb,
	"fulfilled_at" timestamp,
	"fulfilled_by" varchar,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "endpoint_assets" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"hostname" text NOT NULL,
	"os" text NOT NULL,
	"os_version" text,
	"agent_version" text,
	"agent_status" text DEFAULT 'online',
	"ip_address" text,
	"mac_address" text,
	"last_seen_at" timestamp DEFAULT now(),
	"risk_score" integer DEFAULT 0,
	"tags" text[] DEFAULT ARRAY[]::text[],
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "endpoint_telemetry" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"asset_id" varchar NOT NULL,
	"metric_type" text NOT NULL,
	"metric_value" jsonb NOT NULL,
	"collected_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "entities" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"type" text NOT NULL,
	"value" text NOT NULL,
	"display_name" text,
	"metadata" jsonb,
	"first_seen_at" timestamp DEFAULT now(),
	"last_seen_at" timestamp DEFAULT now(),
	"alert_count" integer DEFAULT 0,
	"risk_score" real DEFAULT 0,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "entity_aliases" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"entity_id" varchar NOT NULL,
	"alias_type" text NOT NULL,
	"alias_value" text NOT NULL,
	"source" text,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "evidence_chain_entries" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"incident_id" varchar NOT NULL,
	"sequence_num" integer NOT NULL,
	"entry_type" text NOT NULL,
	"actor_id" varchar,
	"actor_name" text,
	"summary" text NOT NULL,
	"details" jsonb,
	"related_resource_type" text,
	"related_resource_id" varchar,
	"entry_hash" text NOT NULL,
	"previous_hash" text,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "evidence_items" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"incident_id" varchar NOT NULL,
	"type" text NOT NULL,
	"title" text NOT NULL,
	"description" text,
	"storage_key" text,
	"url" text,
	"mime_type" text,
	"file_size" integer,
	"metadata" jsonb,
	"created_by" varchar,
	"created_by_name" text,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "evidence_locker_items" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"title" text NOT NULL,
	"description" text,
	"artifact_type" text NOT NULL,
	"framework" text,
	"control_id" text,
	"storage_key" text,
	"url" text,
	"mime_type" text,
	"file_size" integer,
	"checksum" text,
	"retention_days" integer DEFAULT 365,
	"expires_at" timestamp,
	"status" text DEFAULT 'active',
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"tags" text[] DEFAULT ARRAY[]::text[],
	"uploaded_by" text,
	"uploaded_by_name" text,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "feature_flags" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"key" text NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"enabled" boolean DEFAULT false,
	"rollout_pct" integer DEFAULT 100,
	"target_orgs" text[] DEFAULT ARRAY[]::text[],
	"target_roles" text[] DEFAULT ARRAY[]::text[],
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_by" varchar,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	CONSTRAINT "feature_flags_key_unique" UNIQUE("key")
);
--> statement-breakpoint
CREATE TABLE "forecast_quality_snapshots" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"module" text NOT NULL,
	"precision" real DEFAULT 0 NOT NULL,
	"recall" real DEFAULT 0 NOT NULL,
	"sample_size" integer DEFAULT 0 NOT NULL,
	"measured_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "hardening_recommendations" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"title" text NOT NULL,
	"rationale" text NOT NULL,
	"priority" text DEFAULT 'medium' NOT NULL,
	"category" text,
	"related_entities" jsonb,
	"related_forecasts" jsonb,
	"status" text DEFAULT 'open' NOT NULL,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "idempotency_keys" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"idempotency_key" text NOT NULL,
	"endpoint" text NOT NULL,
	"method" text NOT NULL,
	"response_status" integer,
	"response_body" jsonb,
	"expires_at" timestamp NOT NULL,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "incident_comments" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"incident_id" varchar NOT NULL,
	"user_id" varchar,
	"user_name" text,
	"body" text NOT NULL,
	"is_internal" boolean DEFAULT false,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "incident_response_approvals" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"incident_id" varchar NOT NULL,
	"action_type" text NOT NULL,
	"action_description" text NOT NULL,
	"action_payload" jsonb,
	"status" text DEFAULT 'pending' NOT NULL,
	"requested_by" varchar,
	"requested_by_name" text,
	"required_approver_role" text DEFAULT 'admin' NOT NULL,
	"decided_by" varchar,
	"decided_by_name" text,
	"decision_note" text,
	"expires_at" timestamp,
	"requested_at" timestamp DEFAULT now(),
	"decided_at" timestamp
);
--> statement-breakpoint
CREATE TABLE "incident_sla_policies" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"name" text NOT NULL,
	"severity" text NOT NULL,
	"ack_minutes" integer NOT NULL,
	"contain_minutes" integer NOT NULL,
	"resolve_minutes" integer NOT NULL,
	"enabled" boolean DEFAULT true,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "incident_tags" (
	"incident_id" varchar NOT NULL,
	"tag_id" varchar NOT NULL
);
--> statement-breakpoint
CREATE TABLE "incidents" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"title" text NOT NULL,
	"summary" text,
	"severity" text NOT NULL,
	"status" text DEFAULT 'open' NOT NULL,
	"priority" integer DEFAULT 3,
	"confidence" real,
	"attacker_profile" jsonb,
	"mitre_tactics" text[],
	"mitre_techniques" text[],
	"alert_count" integer DEFAULT 0,
	"ai_narrative" text,
	"ai_summary" text,
	"reasoning_trace" text,
	"mitigation_steps" jsonb,
	"affected_assets" jsonb,
	"iocs" jsonb,
	"referenced_alert_ids" text[],
	"assigned_to" varchar,
	"lead_analyst" varchar,
	"escalated" boolean DEFAULT false,
	"escalated_at" timestamp,
	"contained_at" timestamp,
	"resolved_at" timestamp,
	"ack_due_at" timestamp,
	"contain_due_at" timestamp,
	"resolve_due_at" timestamp,
	"ack_at" timestamp,
	"sla_breached" boolean DEFAULT false,
	"sla_breach_type" text,
	"sla_breach_count" integer DEFAULT 0 NOT NULL,
	"ack_breached_at" timestamp,
	"contain_breached_at" timestamp,
	"resolve_breached_at" timestamp,
	"sla_notified_at" timestamp,
	"sla_paused_at" timestamp,
	"sla_resumed_at" timestamp,
	"sla_total_paused_minutes" integer DEFAULT 0 NOT NULL,
	"mttr_minutes" integer,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "ingestion_logs" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"source" text NOT NULL,
	"status" text DEFAULT 'success' NOT NULL,
	"alerts_received" integer DEFAULT 0,
	"alerts_created" integer DEFAULT 0,
	"alerts_deduped" integer DEFAULT 0,
	"alerts_failed" integer DEFAULT 0,
	"error_message" text,
	"request_id" varchar,
	"ip_address" text,
	"processing_time_ms" integer,
	"received_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "integration_configs" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"type" text NOT NULL,
	"name" text NOT NULL,
	"config" jsonb NOT NULL,
	"status" text DEFAULT 'inactive' NOT NULL,
	"last_tested_at" timestamp,
	"last_test_status" text,
	"created_by" varchar,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "investigation_hypotheses" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"incident_id" varchar NOT NULL,
	"title" text NOT NULL,
	"description" text,
	"status" text DEFAULT 'open' NOT NULL,
	"confidence" real DEFAULT 0,
	"evidence_for" text[],
	"evidence_against" text[],
	"mitre_tactics" text[],
	"created_by" varchar,
	"created_by_name" text,
	"validated_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "investigation_runs" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"incident_id" varchar,
	"triggered_by" text NOT NULL,
	"trigger_source" text DEFAULT 'manual',
	"status" text DEFAULT 'queued' NOT NULL,
	"summary" text,
	"findings" jsonb,
	"recommended_actions" jsonb,
	"evidence_count" integer DEFAULT 0,
	"confidence_score" real,
	"duration" integer,
	"error" text,
	"created_at" timestamp DEFAULT now(),
	"completed_at" timestamp
);
--> statement-breakpoint
CREATE TABLE "investigation_steps" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"run_id" varchar NOT NULL,
	"step_type" text NOT NULL,
	"step_order" integer NOT NULL,
	"title" text NOT NULL,
	"description" text,
	"status" text DEFAULT 'pending' NOT NULL,
	"result" jsonb,
	"artifacts" jsonb,
	"duration" integer,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "investigation_tasks" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"incident_id" varchar NOT NULL,
	"title" text NOT NULL,
	"description" text,
	"status" text DEFAULT 'open' NOT NULL,
	"priority" integer DEFAULT 3,
	"assigned_to" varchar,
	"assigned_to_name" text,
	"due_date" timestamp,
	"completed_at" timestamp,
	"created_by" varchar,
	"created_by_name" text,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "ioc_entries" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"feed_id" varchar,
	"ioc_type" text NOT NULL,
	"ioc_value" text NOT NULL,
	"confidence" integer DEFAULT 50,
	"severity" text DEFAULT 'medium',
	"malware_family" text,
	"campaign_id" text,
	"campaign_name" text,
	"tags" text[] DEFAULT ARRAY[]::text[],
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"source" text,
	"status" text DEFAULT 'active',
	"first_seen" timestamp DEFAULT now(),
	"last_seen" timestamp DEFAULT now(),
	"expires_at" timestamp,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "ioc_feeds" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"name" text NOT NULL,
	"feed_type" text NOT NULL,
	"url" text,
	"api_key_ref" text,
	"schedule" text DEFAULT 'manual',
	"enabled" boolean DEFAULT true,
	"config" jsonb DEFAULT '{}'::jsonb,
	"last_fetch_at" timestamp,
	"last_fetch_status" text,
	"last_fetch_count" integer DEFAULT 0,
	"total_ioc_count" integer DEFAULT 0,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "ioc_match_rules" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"name" text NOT NULL,
	"description" text,
	"ioc_types" text[] DEFAULT ARRAY[]::text[],
	"match_fields" text[] DEFAULT ARRAY[]::text[],
	"min_confidence" integer DEFAULT 0,
	"enabled" boolean DEFAULT true,
	"auto_enrich" boolean DEFAULT true,
	"action" text DEFAULT 'tag',
	"action_config" jsonb DEFAULT '{}'::jsonb,
	"match_count" integer DEFAULT 0,
	"last_match_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "ioc_matches" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"rule_id" varchar,
	"ioc_entry_id" varchar NOT NULL,
	"alert_id" varchar,
	"incident_id" varchar,
	"entity_id" varchar,
	"match_field" text NOT NULL,
	"match_value" text NOT NULL,
	"confidence" integer DEFAULT 50,
	"enrichment_data" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "ioc_watchlist_entries" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"watchlist_id" varchar NOT NULL,
	"ioc_entry_id" varchar NOT NULL,
	"added_by" varchar,
	"added_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "ioc_watchlists" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"name" text NOT NULL,
	"description" text,
	"color" text DEFAULT '#3b82f6',
	"auto_match" boolean DEFAULT true,
	"created_by" varchar,
	"entry_count" integer DEFAULT 0,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "job_queue" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"type" text NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"payload" jsonb,
	"result" jsonb,
	"priority" integer DEFAULT 0,
	"run_at" timestamp DEFAULT now(),
	"started_at" timestamp,
	"completed_at" timestamp,
	"attempts" integer DEFAULT 0,
	"max_attempts" integer DEFAULT 3,
	"last_error" text,
	"fingerprint" varchar(32),
	"fingerprint_expires_at" timestamp,
	"locked_by" varchar(64),
	"locked_until" timestamp,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "legal_holds" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"name" text NOT NULL,
	"description" text,
	"hold_type" text DEFAULT 'full' NOT NULL,
	"table_scope" text[] DEFAULT ARRAY['alerts','incidents','audit_logs'],
	"filter_criteria" jsonb DEFAULT '{}'::jsonb,
	"reason" text,
	"case_reference" text,
	"is_active" boolean DEFAULT true,
	"activated_by" varchar,
	"activated_by_name" text,
	"deactivated_by" varchar,
	"deactivated_at" timestamp,
	"activated_at" timestamp DEFAULT now(),
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "notification_channels" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"name" text NOT NULL,
	"type" text NOT NULL,
	"config" jsonb NOT NULL,
	"is_default" boolean DEFAULT false,
	"events" text[] DEFAULT ARRAY['incident_created'],
	"status" text DEFAULT 'active' NOT NULL,
	"last_notified_at" timestamp,
	"created_by" varchar,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "onboarding_progress" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"step_key" text NOT NULL,
	"step_label" text NOT NULL,
	"step_description" text,
	"category" text DEFAULT 'setup' NOT NULL,
	"sort_order" integer DEFAULT 0 NOT NULL,
	"is_completed" boolean DEFAULT false,
	"completed_at" timestamp,
	"completed_by" varchar,
	"target_url" text,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "org_domain_verifications" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"domain" text NOT NULL,
	"verification_method" text DEFAULT 'dns_txt' NOT NULL,
	"verification_token" text NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"verified_at" timestamp,
	"expires_at" timestamp,
	"last_checked_at" timestamp,
	"created_by" varchar,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "org_invitations" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"email" text NOT NULL,
	"role" text DEFAULT 'analyst' NOT NULL,
	"token" text NOT NULL,
	"invited_by" varchar NOT NULL,
	"expires_at" timestamp NOT NULL,
	"accepted_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	CONSTRAINT "org_invitations_token_unique" UNIQUE("token")
);
--> statement-breakpoint
CREATE TABLE "org_plan_limits" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"plan_tier" text DEFAULT 'free' NOT NULL,
	"events_per_month" integer DEFAULT 10000 NOT NULL,
	"max_connectors" integer DEFAULT 3 NOT NULL,
	"ai_tokens_per_month" integer DEFAULT 5000 NOT NULL,
	"automation_runs_per_month" integer DEFAULT 100 NOT NULL,
	"api_calls_per_month" integer DEFAULT 10000 NOT NULL,
	"storage_gb" integer DEFAULT 5 NOT NULL,
	"soft_threshold_pct" integer DEFAULT 80 NOT NULL,
	"hard_threshold_pct" integer DEFAULT 95 NOT NULL,
	"overage_allowed" boolean DEFAULT false,
	"billing_cycle_start" timestamp DEFAULT now(),
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "org_role_permissions" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"role_id" varchar NOT NULL,
	"scope" text NOT NULL,
	"action" text NOT NULL,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "org_roles" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"is_system" boolean DEFAULT false NOT NULL,
	"base_role" text,
	"created_by" varchar,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "org_scim_configs" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"enabled" boolean DEFAULT false NOT NULL,
	"endpoint_url" text,
	"bearer_token_hash" text,
	"bearer_token_prefix" text,
	"default_role" text DEFAULT 'analyst' NOT NULL,
	"auto_deprovision" boolean DEFAULT true NOT NULL,
	"last_sync_at" timestamp,
	"last_sync_status" text,
	"last_sync_user_count" integer DEFAULT 0,
	"created_by" varchar,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "org_security_policies" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"mfa_required" boolean DEFAULT false NOT NULL,
	"session_timeout_minutes" integer DEFAULT 480 NOT NULL,
	"max_concurrent_sessions" integer DEFAULT 5 NOT NULL,
	"password_min_length" integer DEFAULT 12 NOT NULL,
	"password_require_uppercase" boolean DEFAULT true NOT NULL,
	"password_require_number" boolean DEFAULT true NOT NULL,
	"password_require_special" boolean DEFAULT true NOT NULL,
	"password_expiry_days" integer DEFAULT 90 NOT NULL,
	"ip_allowlist_enabled" boolean DEFAULT false NOT NULL,
	"ip_allowlist_cidrs" text[] DEFAULT ARRAY[]::text[],
	"device_trust_required" boolean DEFAULT false NOT NULL,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "org_sso_configs" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"provider_type" text NOT NULL,
	"enforced" boolean DEFAULT false NOT NULL,
	"metadata_url" text,
	"entity_id" text,
	"sso_url" text,
	"certificate" text,
	"client_id" text,
	"client_secret" text,
	"allowed_domains" text[] DEFAULT ARRAY[]::text[],
	"auto_provision" boolean DEFAULT true NOT NULL,
	"default_role" text DEFAULT 'analyst' NOT NULL,
	"enabled" boolean DEFAULT false NOT NULL,
	"created_by" varchar,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "org_team_memberships" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"team_id" varchar NOT NULL,
	"user_id" varchar NOT NULL,
	"role" text DEFAULT 'member' NOT NULL,
	"added_by" varchar,
	"added_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "org_teams" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"color" text DEFAULT '#6366f1',
	"created_by" varchar,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "organization_memberships" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"user_id" varchar NOT NULL,
	"role" text DEFAULT 'analyst' NOT NULL,
	"custom_role_id" varchar,
	"status" text DEFAULT 'active' NOT NULL,
	"invited_by" varchar,
	"invited_email" text,
	"invited_at" timestamp,
	"joined_at" timestamp,
	"suspended_at" timestamp,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "organizations" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"slug" text NOT NULL,
	"industry" text,
	"contact_email" text,
	"max_users" integer DEFAULT 10,
	"created_at" timestamp DEFAULT now(),
	CONSTRAINT "organizations_slug_unique" UNIQUE("slug")
);
--> statement-breakpoint
CREATE TABLE "outbound_webhook_logs" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"webhook_id" varchar NOT NULL,
	"event" text NOT NULL,
	"payload" jsonb DEFAULT '{}'::jsonb,
	"response_status" integer,
	"response_body" text,
	"attempt" integer DEFAULT 1,
	"success" boolean DEFAULT false,
	"error_message" text,
	"delivered_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "outbound_webhooks" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"name" text NOT NULL,
	"url" text NOT NULL,
	"secret" text,
	"events" text[] NOT NULL,
	"is_active" boolean DEFAULT true,
	"retry_count" integer DEFAULT 3,
	"timeout_ms" integer DEFAULT 10000,
	"headers" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "outbox_events" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"event_type" text NOT NULL,
	"aggregate_type" text NOT NULL,
	"aggregate_id" varchar NOT NULL,
	"payload" jsonb NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"fingerprint" text NOT NULL,
	"dispatched_at" timestamp,
	"attempts" integer DEFAULT 0,
	"max_attempts" integer DEFAULT 5,
	"last_error" text,
	"next_retry_at" timestamp,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "pir_action_items" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"review_id" varchar NOT NULL,
	"org_id" varchar,
	"title" text NOT NULL,
	"description" text,
	"assignee_id" varchar,
	"assignee_name" text,
	"priority" text DEFAULT 'medium' NOT NULL,
	"status" text DEFAULT 'open' NOT NULL,
	"due_date" timestamp,
	"completed_at" timestamp,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "playbook_approvals" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"execution_id" varchar NOT NULL,
	"playbook_id" varchar NOT NULL,
	"node_id" varchar NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"requested_by" text,
	"approver_role" text,
	"approval_message" text,
	"decided_by" text,
	"decision_note" text,
	"requested_at" timestamp DEFAULT now(),
	"decided_at" timestamp
);
--> statement-breakpoint
CREATE TABLE "playbook_executions" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"playbook_id" varchar NOT NULL,
	"triggered_by" text,
	"trigger_event" text,
	"resource_type" text,
	"resource_id" varchar,
	"status" text DEFAULT 'running' NOT NULL,
	"dry_run" boolean DEFAULT false,
	"actions_executed" jsonb,
	"result" jsonb,
	"error_message" text,
	"execution_time_ms" integer,
	"paused_at_node_id" varchar,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "playbook_rollback_plans" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"playbook_id" varchar NOT NULL,
	"execution_id" varchar,
	"rollback_steps" jsonb NOT NULL,
	"status" text DEFAULT 'ready' NOT NULL,
	"auto_rollback_enabled" boolean DEFAULT false,
	"trigger_conditions" jsonb,
	"executed_at" timestamp,
	"executed_by" varchar,
	"executed_by_name" text,
	"result" jsonb,
	"error" text,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "playbook_simulations" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"playbook_id" varchar NOT NULL,
	"execution_id" varchar,
	"status" text DEFAULT 'pending' NOT NULL,
	"simulated_actions" jsonb,
	"impact_analysis" jsonb,
	"predicted_outcome" text,
	"risk_score" real,
	"warnings" jsonb,
	"simulated_by" varchar,
	"simulated_by_name" text,
	"duration_ms" integer,
	"created_at" timestamp DEFAULT now(),
	"completed_at" timestamp
);
--> statement-breakpoint
CREATE TABLE "playbook_versions" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"playbook_id" varchar NOT NULL,
	"org_id" varchar,
	"version" integer NOT NULL,
	"status" text DEFAULT 'draft' NOT NULL,
	"actions" jsonb NOT NULL,
	"conditions" jsonb,
	"change_description" text,
	"approval_required" boolean DEFAULT false,
	"approved_by" varchar,
	"approved_by_name" text,
	"approved_at" timestamp,
	"rollback_to_version" integer,
	"created_by" varchar,
	"created_by_name" text,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "playbooks" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"name" text NOT NULL,
	"description" text,
	"trigger" text NOT NULL,
	"conditions" jsonb,
	"actions" jsonb NOT NULL,
	"status" text DEFAULT 'draft' NOT NULL,
	"last_triggered_at" timestamp,
	"trigger_count" integer DEFAULT 0,
	"created_by" varchar,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "policy_checks" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"cloud_provider" text,
	"resource_type" text,
	"severity" text DEFAULT 'medium' NOT NULL,
	"rule_logic" jsonb NOT NULL,
	"remediation" text,
	"compliance_frameworks" text[] DEFAULT ARRAY[]::text[],
	"control_ids" text[] DEFAULT ARRAY[]::text[],
	"status" text DEFAULT 'active',
	"is_built_in" boolean DEFAULT false,
	"last_run_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "policy_results" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"policy_check_id" varchar NOT NULL,
	"scan_id" varchar,
	"resource_id" text NOT NULL,
	"resource_type" text,
	"resource_region" text,
	"status" text DEFAULT 'fail' NOT NULL,
	"details" jsonb DEFAULT '{}'::jsonb,
	"evaluated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "post_incident_reviews" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"incident_id" varchar NOT NULL,
	"status" text DEFAULT 'draft' NOT NULL,
	"title" text NOT NULL,
	"summary" text,
	"timeline_json" jsonb,
	"root_cause_analysis" text,
	"impact_assessment" text,
	"lessons_learned" jsonb,
	"action_items" jsonb,
	"participants" text[],
	"review_date" timestamp,
	"lead_reviewer" varchar,
	"lead_reviewer_name" text,
	"created_by" varchar,
	"created_by_name" text,
	"published_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "posture_scores" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"overall_score" integer NOT NULL,
	"cspm_score" integer DEFAULT 0,
	"endpoint_score" integer DEFAULT 0,
	"incident_score" integer DEFAULT 0,
	"compliance_score" integer DEFAULT 0,
	"breakdown" jsonb DEFAULT '{}'::jsonb,
	"generated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "predictive_anomalies" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"kind" text NOT NULL,
	"metric" text NOT NULL,
	"baseline" real NOT NULL,
	"current" real NOT NULL,
	"z_score" real NOT NULL,
	"severity" text DEFAULT 'medium' NOT NULL,
	"window_start" timestamp NOT NULL,
	"window_end" timestamp NOT NULL,
	"top_signals" jsonb,
	"description" text,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "report_runs" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"template_id" varchar NOT NULL,
	"schedule_id" varchar,
	"status" text DEFAULT 'queued' NOT NULL,
	"format" text DEFAULT 'pdf' NOT NULL,
	"output_location" text,
	"file_size" integer,
	"error" text,
	"started_at" timestamp,
	"completed_at" timestamp,
	"created_by" varchar,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "report_schedules" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"template_id" varchar NOT NULL,
	"name" text NOT NULL,
	"cadence" text NOT NULL,
	"timezone" text DEFAULT 'UTC',
	"delivery_targets" text,
	"enabled" boolean DEFAULT true,
	"last_run_at" timestamp,
	"next_run_at" timestamp,
	"created_by" varchar,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "report_templates" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"name" text NOT NULL,
	"description" text,
	"report_type" text NOT NULL,
	"format" text DEFAULT 'pdf' NOT NULL,
	"config" text,
	"dashboard_role" text,
	"is_built_in" boolean DEFAULT false,
	"created_by" varchar,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "response_action_approvals" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"action_type" text NOT NULL,
	"target_type" text,
	"target_value" text,
	"incident_id" varchar,
	"request_payload" jsonb,
	"dry_run_result" jsonb,
	"status" text DEFAULT 'pending' NOT NULL,
	"required_approvers" integer DEFAULT 1 NOT NULL,
	"current_approvals" integer DEFAULT 0,
	"approvers" jsonb DEFAULT '[]'::jsonb,
	"requested_by" varchar,
	"requested_by_name" text,
	"decided_by" varchar,
	"decided_by_name" text,
	"decision_note" text,
	"expires_at" timestamp,
	"requested_at" timestamp DEFAULT now(),
	"decided_at" timestamp
);
--> statement-breakpoint
CREATE TABLE "response_action_rollbacks" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"original_action_id" varchar,
	"action_type" text NOT NULL,
	"target" text NOT NULL,
	"rollback_action" jsonb NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"executed_by" text,
	"result" jsonb,
	"error" text,
	"created_at" timestamp DEFAULT now(),
	"executed_at" timestamp
);
--> statement-breakpoint
CREATE TABLE "response_actions" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"action_type" text NOT NULL,
	"connector_id" varchar,
	"incident_id" varchar,
	"alert_id" varchar,
	"target_type" text,
	"target_value" text,
	"status" text DEFAULT 'pending' NOT NULL,
	"request_payload" jsonb,
	"response_payload" jsonb,
	"error_message" text,
	"executed_by" varchar,
	"executed_at" timestamp,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "risk_forecasts" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"forecast_type" text NOT NULL,
	"probability" real NOT NULL,
	"predicted_window_hours" integer NOT NULL,
	"confidence" real DEFAULT 0 NOT NULL,
	"drivers" jsonb,
	"description" text,
	"status" text DEFAULT 'active' NOT NULL,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "runbook_steps" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"template_id" varchar NOT NULL,
	"step_order" integer NOT NULL,
	"title" text NOT NULL,
	"instructions" text,
	"action_type" text,
	"is_required" boolean DEFAULT true,
	"estimated_minutes" integer,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "runbook_templates" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"incident_type" text NOT NULL,
	"title" text NOT NULL,
	"description" text,
	"severity" text DEFAULT 'medium',
	"estimated_duration" text,
	"tags" text[],
	"is_built_in" boolean DEFAULT false,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "saved_views" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"user_id" varchar NOT NULL,
	"team_id" varchar,
	"name" text NOT NULL,
	"resource_type" text NOT NULL,
	"filters" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"columns" text[],
	"sort_field" text,
	"sort_dir" text DEFAULT 'desc',
	"is_default" boolean DEFAULT false NOT NULL,
	"visibility" text DEFAULT 'private' NOT NULL,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "sli_metrics" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"service" text NOT NULL,
	"metric" text NOT NULL,
	"value" real NOT NULL,
	"labels" jsonb,
	"recorded_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "slo_targets" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"service" text NOT NULL,
	"metric" text NOT NULL,
	"endpoint" text DEFAULT '*' NOT NULL,
	"target" real NOT NULL,
	"operator" text DEFAULT 'gte' NOT NULL,
	"window_minutes" integer DEFAULT 60 NOT NULL,
	"alert_on_breach" boolean DEFAULT true,
	"description" text,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "suppression_rules" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"name" text NOT NULL,
	"description" text,
	"scope" text NOT NULL,
	"scope_value" text NOT NULL,
	"matcher" jsonb,
	"reason" text,
	"source" text,
	"severity" text,
	"category" text,
	"enabled" boolean DEFAULT true,
	"expires_at" timestamp,
	"match_count" integer DEFAULT 0,
	"last_match_at" timestamp,
	"created_by" varchar,
	"owned_by" varchar,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "tags" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"color" text DEFAULT '#6366f1',
	"category" text,
	"created_at" timestamp DEFAULT now(),
	CONSTRAINT "tags_name_unique" UNIQUE("name")
);
--> statement-breakpoint
CREATE TABLE "threat_intel_configs" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"provider" text NOT NULL,
	"api_key" text,
	"enabled" boolean DEFAULT true,
	"last_tested_at" timestamp,
	"last_test_status" text,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "ticket_sync_jobs" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"integration_id" varchar NOT NULL,
	"incident_id" varchar,
	"external_ticket_id" text,
	"external_ticket_url" text,
	"direction" text DEFAULT 'bidirectional' NOT NULL,
	"sync_status" text DEFAULT 'pending' NOT NULL,
	"last_synced_at" timestamp,
	"last_sync_error" text,
	"field_mapping" jsonb DEFAULT '{}'::jsonb,
	"status_mapping" jsonb DEFAULT '{}'::jsonb,
	"comments_mirrored" integer DEFAULT 0,
	"status_syncs" integer DEFAULT 0,
	"created_by" varchar,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "usage_meter_snapshots" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"metric_type" text NOT NULL,
	"period_start" timestamp NOT NULL,
	"period_end" timestamp NOT NULL,
	"current_value" integer DEFAULT 0 NOT NULL,
	"limit_value" integer,
	"pct_used" real DEFAULT 0,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"snapshot_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "workspace_templates" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"slug" text NOT NULL,
	"description" text,
	"category" text DEFAULT 'general' NOT NULL,
	"icon" text,
	"is_default" boolean DEFAULT false,
	"config" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"connectors_config" jsonb DEFAULT '[]'::jsonb,
	"playbooks_config" jsonb DEFAULT '[]'::jsonb,
	"notification_config" jsonb DEFAULT '[]'::jsonb,
	"compliance_config" jsonb DEFAULT '{}'::jsonb,
	"dashboard_layout" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now(),
	CONSTRAINT "workspace_templates_slug_unique" UNIQUE("slug")
);
--> statement-breakpoint
CREATE TABLE "sessions" (
	"sid" varchar PRIMARY KEY NOT NULL,
	"sess" jsonb NOT NULL,
	"expire" timestamp NOT NULL
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"email" varchar,
	"password_hash" varchar,
	"first_name" varchar,
	"last_name" varchar,
	"profile_image_url" varchar,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	CONSTRAINT "users_email_unique" UNIQUE("email")
);
--> statement-breakpoint
ALTER TABLE "alert_dedup_clusters" ADD CONSTRAINT "alert_dedup_clusters_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alert_dedup_clusters" ADD CONSTRAINT "alert_dedup_clusters_canonical_alert_id_alerts_id_fk" FOREIGN KEY ("canonical_alert_id") REFERENCES "public"."alerts"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alert_entities" ADD CONSTRAINT "alert_entities_alert_id_alerts_id_fk" FOREIGN KEY ("alert_id") REFERENCES "public"."alerts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alert_entities" ADD CONSTRAINT "alert_entities_entity_id_entities_id_fk" FOREIGN KEY ("entity_id") REFERENCES "public"."entities"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alert_tags" ADD CONSTRAINT "alert_tags_alert_id_alerts_id_fk" FOREIGN KEY ("alert_id") REFERENCES "public"."alerts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alert_tags" ADD CONSTRAINT "alert_tags_tag_id_tags_id_fk" FOREIGN KEY ("tag_id") REFERENCES "public"."tags"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "anomaly_subscriptions" ADD CONSTRAINT "anomaly_subscriptions_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "api_keys" ADD CONSTRAINT "api_keys_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "approval_decision_records" ADD CONSTRAINT "approval_decision_records_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "attack_paths" ADD CONSTRAINT "attack_paths_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "attack_paths" ADD CONSTRAINT "attack_paths_cluster_id_correlation_clusters_id_fk" FOREIGN KEY ("cluster_id") REFERENCES "public"."correlation_clusters"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "attack_surface_assets" ADD CONSTRAINT "attack_surface_assets_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_verification_runs" ADD CONSTRAINT "audit_verification_runs_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auto_response_policies" ADD CONSTRAINT "auto_response_policies_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "blast_radius_previews" ADD CONSTRAINT "blast_radius_previews_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "blast_radius_previews" ADD CONSTRAINT "blast_radius_previews_playbook_id_playbooks_id_fk" FOREIGN KEY ("playbook_id") REFERENCES "public"."playbooks"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "campaigns" ADD CONSTRAINT "campaigns_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "compliance_control_mappings" ADD CONSTRAINT "compliance_control_mappings_control_id_compliance_controls_id_fk" FOREIGN KEY ("control_id") REFERENCES "public"."compliance_controls"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "compliance_policies" ADD CONSTRAINT "compliance_policies_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "connector_health_checks" ADD CONSTRAINT "connector_health_checks_connector_id_connectors_id_fk" FOREIGN KEY ("connector_id") REFERENCES "public"."connectors"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "connector_job_runs" ADD CONSTRAINT "connector_job_runs_connector_id_connectors_id_fk" FOREIGN KEY ("connector_id") REFERENCES "public"."connectors"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "connector_secret_rotations" ADD CONSTRAINT "connector_secret_rotations_connector_id_connectors_id_fk" FOREIGN KEY ("connector_id") REFERENCES "public"."connectors"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "connectors" ADD CONSTRAINT "connectors_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "correlation_clusters" ADD CONSTRAINT "correlation_clusters_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "correlation_clusters" ADD CONSTRAINT "correlation_clusters_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cspm_scans" ADD CONSTRAINT "cspm_scans_account_id_cspm_accounts_id_fk" FOREIGN KEY ("account_id") REFERENCES "public"."cspm_accounts"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dsar_requests" ADD CONSTRAINT "dsar_requests_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "endpoint_telemetry" ADD CONSTRAINT "endpoint_telemetry_asset_id_endpoint_assets_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."endpoint_assets"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "entities" ADD CONSTRAINT "entities_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "entity_aliases" ADD CONSTRAINT "entity_aliases_entity_id_entities_id_fk" FOREIGN KEY ("entity_id") REFERENCES "public"."entities"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "evidence_chain_entries" ADD CONSTRAINT "evidence_chain_entries_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "evidence_chain_entries" ADD CONSTRAINT "evidence_chain_entries_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "evidence_items" ADD CONSTRAINT "evidence_items_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "evidence_items" ADD CONSTRAINT "evidence_items_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "forecast_quality_snapshots" ADD CONSTRAINT "forecast_quality_snapshots_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hardening_recommendations" ADD CONSTRAINT "hardening_recommendations_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incident_comments" ADD CONSTRAINT "incident_comments_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incident_response_approvals" ADD CONSTRAINT "incident_response_approvals_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incident_response_approvals" ADD CONSTRAINT "incident_response_approvals_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incident_sla_policies" ADD CONSTRAINT "incident_sla_policies_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incident_tags" ADD CONSTRAINT "incident_tags_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incident_tags" ADD CONSTRAINT "incident_tags_tag_id_tags_id_fk" FOREIGN KEY ("tag_id") REFERENCES "public"."tags"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incidents" ADD CONSTRAINT "incidents_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ingestion_logs" ADD CONSTRAINT "ingestion_logs_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "integration_configs" ADD CONSTRAINT "integration_configs_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_hypotheses" ADD CONSTRAINT "investigation_hypotheses_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_hypotheses" ADD CONSTRAINT "investigation_hypotheses_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_runs" ADD CONSTRAINT "investigation_runs_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_runs" ADD CONSTRAINT "investigation_runs_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_steps" ADD CONSTRAINT "investigation_steps_run_id_investigation_runs_id_fk" FOREIGN KEY ("run_id") REFERENCES "public"."investigation_runs"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_tasks" ADD CONSTRAINT "investigation_tasks_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_tasks" ADD CONSTRAINT "investigation_tasks_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ioc_entries" ADD CONSTRAINT "ioc_entries_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ioc_entries" ADD CONSTRAINT "ioc_entries_feed_id_ioc_feeds_id_fk" FOREIGN KEY ("feed_id") REFERENCES "public"."ioc_feeds"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ioc_feeds" ADD CONSTRAINT "ioc_feeds_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ioc_match_rules" ADD CONSTRAINT "ioc_match_rules_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ioc_matches" ADD CONSTRAINT "ioc_matches_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ioc_matches" ADD CONSTRAINT "ioc_matches_rule_id_ioc_match_rules_id_fk" FOREIGN KEY ("rule_id") REFERENCES "public"."ioc_match_rules"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ioc_matches" ADD CONSTRAINT "ioc_matches_ioc_entry_id_ioc_entries_id_fk" FOREIGN KEY ("ioc_entry_id") REFERENCES "public"."ioc_entries"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ioc_matches" ADD CONSTRAINT "ioc_matches_alert_id_alerts_id_fk" FOREIGN KEY ("alert_id") REFERENCES "public"."alerts"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ioc_matches" ADD CONSTRAINT "ioc_matches_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ioc_matches" ADD CONSTRAINT "ioc_matches_entity_id_entities_id_fk" FOREIGN KEY ("entity_id") REFERENCES "public"."entities"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ioc_watchlist_entries" ADD CONSTRAINT "ioc_watchlist_entries_watchlist_id_ioc_watchlists_id_fk" FOREIGN KEY ("watchlist_id") REFERENCES "public"."ioc_watchlists"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ioc_watchlist_entries" ADD CONSTRAINT "ioc_watchlist_entries_ioc_entry_id_ioc_entries_id_fk" FOREIGN KEY ("ioc_entry_id") REFERENCES "public"."ioc_entries"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ioc_watchlists" ADD CONSTRAINT "ioc_watchlists_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "notification_channels" ADD CONSTRAINT "notification_channels_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "onboarding_progress" ADD CONSTRAINT "onboarding_progress_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "org_domain_verifications" ADD CONSTRAINT "org_domain_verifications_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "org_invitations" ADD CONSTRAINT "org_invitations_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "org_plan_limits" ADD CONSTRAINT "org_plan_limits_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "org_role_permissions" ADD CONSTRAINT "org_role_permissions_role_id_org_roles_id_fk" FOREIGN KEY ("role_id") REFERENCES "public"."org_roles"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "org_roles" ADD CONSTRAINT "org_roles_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "org_scim_configs" ADD CONSTRAINT "org_scim_configs_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "org_security_policies" ADD CONSTRAINT "org_security_policies_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "org_sso_configs" ADD CONSTRAINT "org_sso_configs_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "org_team_memberships" ADD CONSTRAINT "org_team_memberships_team_id_org_teams_id_fk" FOREIGN KEY ("team_id") REFERENCES "public"."org_teams"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "org_teams" ADD CONSTRAINT "org_teams_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "organization_memberships" ADD CONSTRAINT "organization_memberships_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "organization_memberships" ADD CONSTRAINT "organization_memberships_custom_role_id_org_roles_id_fk" FOREIGN KEY ("custom_role_id") REFERENCES "public"."org_roles"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "outbound_webhook_logs" ADD CONSTRAINT "outbound_webhook_logs_webhook_id_outbound_webhooks_id_fk" FOREIGN KEY ("webhook_id") REFERENCES "public"."outbound_webhooks"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "pir_action_items" ADD CONSTRAINT "pir_action_items_review_id_post_incident_reviews_id_fk" FOREIGN KEY ("review_id") REFERENCES "public"."post_incident_reviews"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "pir_action_items" ADD CONSTRAINT "pir_action_items_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "playbook_approvals" ADD CONSTRAINT "playbook_approvals_execution_id_playbook_executions_id_fk" FOREIGN KEY ("execution_id") REFERENCES "public"."playbook_executions"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "playbook_approvals" ADD CONSTRAINT "playbook_approvals_playbook_id_playbooks_id_fk" FOREIGN KEY ("playbook_id") REFERENCES "public"."playbooks"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "playbook_executions" ADD CONSTRAINT "playbook_executions_playbook_id_playbooks_id_fk" FOREIGN KEY ("playbook_id") REFERENCES "public"."playbooks"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "playbook_rollback_plans" ADD CONSTRAINT "playbook_rollback_plans_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "playbook_rollback_plans" ADD CONSTRAINT "playbook_rollback_plans_playbook_id_playbooks_id_fk" FOREIGN KEY ("playbook_id") REFERENCES "public"."playbooks"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "playbook_rollback_plans" ADD CONSTRAINT "playbook_rollback_plans_execution_id_playbook_executions_id_fk" FOREIGN KEY ("execution_id") REFERENCES "public"."playbook_executions"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "playbook_simulations" ADD CONSTRAINT "playbook_simulations_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "playbook_simulations" ADD CONSTRAINT "playbook_simulations_playbook_id_playbooks_id_fk" FOREIGN KEY ("playbook_id") REFERENCES "public"."playbooks"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "playbook_simulations" ADD CONSTRAINT "playbook_simulations_execution_id_playbook_executions_id_fk" FOREIGN KEY ("execution_id") REFERENCES "public"."playbook_executions"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "playbook_versions" ADD CONSTRAINT "playbook_versions_playbook_id_playbooks_id_fk" FOREIGN KEY ("playbook_id") REFERENCES "public"."playbooks"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "playbook_versions" ADD CONSTRAINT "playbook_versions_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_results" ADD CONSTRAINT "policy_results_policy_check_id_policy_checks_id_fk" FOREIGN KEY ("policy_check_id") REFERENCES "public"."policy_checks"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "post_incident_reviews" ADD CONSTRAINT "post_incident_reviews_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "post_incident_reviews" ADD CONSTRAINT "post_incident_reviews_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "predictive_anomalies" ADD CONSTRAINT "predictive_anomalies_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "report_runs" ADD CONSTRAINT "report_runs_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "report_runs" ADD CONSTRAINT "report_runs_template_id_report_templates_id_fk" FOREIGN KEY ("template_id") REFERENCES "public"."report_templates"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "report_runs" ADD CONSTRAINT "report_runs_schedule_id_report_schedules_id_fk" FOREIGN KEY ("schedule_id") REFERENCES "public"."report_schedules"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "report_schedules" ADD CONSTRAINT "report_schedules_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "report_schedules" ADD CONSTRAINT "report_schedules_template_id_report_templates_id_fk" FOREIGN KEY ("template_id") REFERENCES "public"."report_templates"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "report_templates" ADD CONSTRAINT "report_templates_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "response_action_approvals" ADD CONSTRAINT "response_action_approvals_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "response_action_rollbacks" ADD CONSTRAINT "response_action_rollbacks_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "response_actions" ADD CONSTRAINT "response_actions_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "response_actions" ADD CONSTRAINT "response_actions_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "risk_forecasts" ADD CONSTRAINT "risk_forecasts_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "runbook_steps" ADD CONSTRAINT "runbook_steps_template_id_runbook_templates_id_fk" FOREIGN KEY ("template_id") REFERENCES "public"."runbook_templates"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "runbook_templates" ADD CONSTRAINT "runbook_templates_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "saved_views" ADD CONSTRAINT "saved_views_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "saved_views" ADD CONSTRAINT "saved_views_team_id_org_teams_id_fk" FOREIGN KEY ("team_id") REFERENCES "public"."org_teams"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "suppression_rules" ADD CONSTRAINT "suppression_rules_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "threat_intel_configs" ADD CONSTRAINT "threat_intel_configs_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ticket_sync_jobs" ADD CONSTRAINT "ticket_sync_jobs_integration_id_integration_configs_id_fk" FOREIGN KEY ("integration_id") REFERENCES "public"."integration_configs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ticket_sync_jobs" ADD CONSTRAINT "ticket_sync_jobs_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "usage_meter_snapshots" ADD CONSTRAINT "usage_meter_snapshots_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_ai_feedback_org" ON "ai_feedback" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ai_feedback_resource" ON "ai_feedback" USING btree ("resource_type","resource_id");--> statement-breakpoint
CREATE INDEX "idx_ai_feedback_created" ON "ai_feedback" USING btree ("created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_alert_daily_stats_org_date_unique" ON "alert_daily_stats" USING btree ("org_id","date");--> statement-breakpoint
CREATE INDEX "idx_alert_daily_stats_org_date" ON "alert_daily_stats" USING btree ("org_id","date");--> statement-breakpoint
CREATE INDEX "idx_dedup_clusters_org" ON "alert_dedup_clusters" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_dedup_clusters_canonical" ON "alert_dedup_clusters" USING btree ("canonical_alert_id");--> statement-breakpoint
CREATE INDEX "idx_alert_entities_alert" ON "alert_entities" USING btree ("alert_id");--> statement-breakpoint
CREATE INDEX "idx_alert_entities_entity" ON "alert_entities" USING btree ("entity_id");--> statement-breakpoint
CREATE INDEX "idx_alert_tags_alert" ON "alert_tags" USING btree ("alert_id");--> statement-breakpoint
CREATE INDEX "idx_alert_tags_tag" ON "alert_tags" USING btree ("tag_id");--> statement-breakpoint
CREATE INDEX "idx_alerts_org" ON "alerts" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_alerts_status" ON "alerts" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_alerts_severity" ON "alerts" USING btree ("severity");--> statement-breakpoint
CREATE INDEX "idx_alerts_incident" ON "alerts" USING btree ("incident_id");--> statement-breakpoint
CREATE INDEX "idx_alerts_source" ON "alerts" USING btree ("source");--> statement-breakpoint
CREATE INDEX "idx_alerts_category" ON "alerts" USING btree ("category");--> statement-breakpoint
CREATE INDEX "idx_alerts_org_created" ON "alerts" USING btree ("org_id","created_at");--> statement-breakpoint
CREATE INDEX "idx_alerts_org_status_created" ON "alerts" USING btree ("org_id","status","created_at");--> statement-breakpoint
CREATE INDEX "idx_alerts_org_severity_created" ON "alerts" USING btree ("org_id","severity","created_at");--> statement-breakpoint
CREATE INDEX "idx_alerts_org_source_created" ON "alerts" USING btree ("org_id","source","created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_alerts_dedup" ON "alerts" USING btree ("org_id","source","source_event_id");--> statement-breakpoint
CREATE INDEX "idx_alerts_archive_org_archived" ON "alerts_archive" USING btree ("org_id","archived_at");--> statement-breakpoint
CREATE INDEX "idx_alerts_archive_org_severity" ON "alerts_archive" USING btree ("org_id","severity");--> statement-breakpoint
CREATE INDEX "idx_api_keys_org" ON "api_keys" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_api_keys_hash" ON "api_keys" USING btree ("key_hash");--> statement-breakpoint
CREATE INDEX "idx_approval_decisions_subject" ON "approval_decision_records" USING btree ("approval_subject_type","approval_subject_id");--> statement-breakpoint
CREATE INDEX "idx_approval_decisions_approver" ON "approval_decision_records" USING btree ("approver_user_id");--> statement-breakpoint
CREATE INDEX "idx_approval_decisions_org" ON "approval_decision_records" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_approval_decisions_decided" ON "approval_decision_records" USING btree ("decided_at");--> statement-breakpoint
CREATE INDEX "idx_attack_paths_org" ON "attack_paths" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_attack_paths_cluster" ON "attack_paths" USING btree ("cluster_id");--> statement-breakpoint
CREATE INDEX "idx_attack_paths_campaign" ON "attack_paths" USING btree ("campaign_id");--> statement-breakpoint
CREATE INDEX "idx_audit_logs_org_seq" ON "audit_logs" USING btree ("org_id","sequence_num");--> statement-breakpoint
CREATE INDEX "idx_audit_logs_org_created" ON "audit_logs" USING btree ("org_id","created_at");--> statement-breakpoint
CREATE INDEX "idx_audit_logs_org_action_created" ON "audit_logs" USING btree ("org_id","action","created_at");--> statement-breakpoint
CREATE INDEX "idx_audit_logs_org_user_created" ON "audit_logs" USING btree ("org_id","user_id","created_at");--> statement-breakpoint
CREATE INDEX "idx_audit_logs_org_resource" ON "audit_logs" USING btree ("org_id","resource_type","resource_id");--> statement-breakpoint
CREATE INDEX "idx_audit_verif_org" ON "audit_verification_runs" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_audit_verif_org_created" ON "audit_verification_runs" USING btree ("org_id","created_at");--> statement-breakpoint
CREATE INDEX "idx_audit_verif_chain_valid" ON "audit_verification_runs" USING btree ("org_id","chain_valid");--> statement-breakpoint
CREATE INDEX "idx_audit_verif_status" ON "audit_verification_runs" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_blast_radius_playbook" ON "blast_radius_previews" USING btree ("playbook_id");--> statement-breakpoint
CREATE INDEX "idx_blast_radius_org" ON "blast_radius_previews" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_blast_radius_risk" ON "blast_radius_previews" USING btree ("risk_level");--> statement-breakpoint
CREATE INDEX "idx_campaigns_org" ON "campaigns" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_campaigns_fingerprint" ON "campaigns" USING btree ("fingerprint");--> statement-breakpoint
CREATE INDEX "idx_campaigns_status" ON "campaigns" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_control_mappings_org" ON "compliance_control_mappings" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_control_mappings_control" ON "compliance_control_mappings" USING btree ("control_id");--> statement-breakpoint
CREATE INDEX "idx_control_mappings_resource" ON "compliance_control_mappings" USING btree ("resource_type","resource_id");--> statement-breakpoint
CREATE INDEX "idx_compliance_controls_framework" ON "compliance_controls" USING btree ("framework");--> statement-breakpoint
CREATE INDEX "idx_compliance_controls_control_id" ON "compliance_controls" USING btree ("control_id");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_compliance_policies_org" ON "compliance_policies" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_connector_health_connector" ON "connector_health_checks" USING btree ("connector_id");--> statement-breakpoint
CREATE INDEX "idx_connector_health_checked" ON "connector_health_checks" USING btree ("checked_at");--> statement-breakpoint
CREATE INDEX "idx_connector_job_runs_connector" ON "connector_job_runs" USING btree ("connector_id");--> statement-breakpoint
CREATE INDEX "idx_connector_job_runs_status" ON "connector_job_runs" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_connector_job_runs_dead_letter" ON "connector_job_runs" USING btree ("is_dead_letter");--> statement-breakpoint
CREATE INDEX "idx_connector_job_runs_started" ON "connector_job_runs" USING btree ("started_at");--> statement-breakpoint
CREATE INDEX "idx_connector_job_runs_next_retry" ON "connector_job_runs" USING btree ("next_retry_at");--> statement-breakpoint
CREATE INDEX "idx_connector_job_runs_connector_started" ON "connector_job_runs" USING btree ("connector_id","started_at");--> statement-breakpoint
CREATE INDEX "idx_secret_rotation_connector" ON "connector_secret_rotations" USING btree ("connector_id");--> statement-breakpoint
CREATE INDEX "idx_secret_rotation_due" ON "connector_secret_rotations" USING btree ("next_rotation_due");--> statement-breakpoint
CREATE INDEX "idx_connectors_org" ON "connectors" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_connectors_type" ON "connectors" USING btree ("type");--> statement-breakpoint
CREATE INDEX "idx_connectors_status" ON "connectors" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_connectors_org_status" ON "connectors" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_connectors_org_created" ON "connectors" USING btree ("org_id","created_at");--> statement-breakpoint
CREATE INDEX "idx_correlation_clusters_org" ON "correlation_clusters" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_correlation_clusters_incident" ON "correlation_clusters" USING btree ("incident_id");--> statement-breakpoint
CREATE INDEX "idx_correlation_clusters_status" ON "correlation_clusters" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_dashboard_cache_org_type" ON "dashboard_metrics_cache" USING btree ("org_id","metric_type");--> statement-breakpoint
CREATE INDEX "idx_dashboard_cache_expires" ON "dashboard_metrics_cache" USING btree ("expires_at");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_dashboard_cache_org_type_unique" ON "dashboard_metrics_cache" USING btree ("org_id","metric_type");--> statement-breakpoint
CREATE INDEX "idx_dr_runbooks_org" ON "dr_runbooks" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_dr_runbooks_category" ON "dr_runbooks" USING btree ("category");--> statement-breakpoint
CREATE INDEX "idx_dsar_requests_org" ON "dsar_requests" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_dsar_requests_status" ON "dsar_requests" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_dsar_requests_due" ON "dsar_requests" USING btree ("due_date");--> statement-breakpoint
CREATE INDEX "idx_entities_org" ON "entities" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_entities_type" ON "entities" USING btree ("type");--> statement-breakpoint
CREATE INDEX "idx_entities_value" ON "entities" USING btree ("value");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_entities_org_type_value" ON "entities" USING btree ("org_id","type","value");--> statement-breakpoint
CREATE INDEX "idx_entity_aliases_entity" ON "entity_aliases" USING btree ("entity_id");--> statement-breakpoint
CREATE INDEX "idx_entity_aliases_value" ON "entity_aliases" USING btree ("alias_value");--> statement-breakpoint
CREATE INDEX "idx_evidence_chain_incident" ON "evidence_chain_entries" USING btree ("incident_id");--> statement-breakpoint
CREATE INDEX "idx_evidence_chain_org" ON "evidence_chain_entries" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_evidence_chain_seq" ON "evidence_chain_entries" USING btree ("incident_id","sequence_num");--> statement-breakpoint
CREATE INDEX "idx_evidence_chain_type" ON "evidence_chain_entries" USING btree ("entry_type");--> statement-breakpoint
CREATE INDEX "idx_evidence_items_incident" ON "evidence_items" USING btree ("incident_id");--> statement-breakpoint
CREATE INDEX "idx_evidence_items_org" ON "evidence_items" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_evidence_locker_org" ON "evidence_locker_items" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_evidence_locker_framework" ON "evidence_locker_items" USING btree ("framework");--> statement-breakpoint
CREATE INDEX "idx_evidence_locker_type" ON "evidence_locker_items" USING btree ("artifact_type");--> statement-breakpoint
CREATE INDEX "idx_evidence_locker_status" ON "evidence_locker_items" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_feature_flags_key" ON "feature_flags" USING btree ("key");--> statement-breakpoint
CREATE INDEX "idx_feature_flags_enabled" ON "feature_flags" USING btree ("enabled");--> statement-breakpoint
CREATE INDEX "idx_idempotency_org_key" ON "idempotency_keys" USING btree ("org_id","idempotency_key","endpoint");--> statement-breakpoint
CREATE INDEX "idx_comments_incident" ON "incident_comments" USING btree ("incident_id");--> statement-breakpoint
CREATE INDEX "idx_ir_approvals_incident" ON "incident_response_approvals" USING btree ("incident_id");--> statement-breakpoint
CREATE INDEX "idx_ir_approvals_org" ON "incident_response_approvals" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ir_approvals_status" ON "incident_response_approvals" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_ir_approvals_org_status" ON "incident_response_approvals" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_sla_policies_org" ON "incident_sla_policies" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_sla_policies_severity" ON "incident_sla_policies" USING btree ("severity");--> statement-breakpoint
CREATE INDEX "idx_incident_tags_incident" ON "incident_tags" USING btree ("incident_id");--> statement-breakpoint
CREATE INDEX "idx_incident_tags_tag" ON "incident_tags" USING btree ("tag_id");--> statement-breakpoint
CREATE INDEX "idx_incidents_org" ON "incidents" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_incidents_status" ON "incidents" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_incidents_severity" ON "incidents" USING btree ("severity");--> statement-breakpoint
CREATE INDEX "idx_incidents_org_created" ON "incidents" USING btree ("org_id","created_at");--> statement-breakpoint
CREATE INDEX "idx_incidents_org_status_created" ON "incidents" USING btree ("org_id","status","created_at");--> statement-breakpoint
CREATE INDEX "idx_incidents_org_severity_created" ON "incidents" USING btree ("org_id","severity","created_at");--> statement-breakpoint
CREATE INDEX "idx_incidents_assigned" ON "incidents" USING btree ("assigned_to");--> statement-breakpoint
CREATE INDEX "idx_incidents_sla_breached" ON "incidents" USING btree ("org_id","sla_breached");--> statement-breakpoint
CREATE INDEX "idx_ingestion_logs_org" ON "ingestion_logs" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ingestion_logs_source" ON "ingestion_logs" USING btree ("source");--> statement-breakpoint
CREATE INDEX "idx_ingestion_logs_received" ON "ingestion_logs" USING btree ("received_at");--> statement-breakpoint
CREATE INDEX "idx_ingestion_logs_org_received" ON "ingestion_logs" USING btree ("org_id","received_at");--> statement-breakpoint
CREATE INDEX "idx_ingestion_logs_org_status_received" ON "ingestion_logs" USING btree ("org_id","status","received_at");--> statement-breakpoint
CREATE INDEX "idx_integration_configs_org" ON "integration_configs" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_integration_configs_type" ON "integration_configs" USING btree ("type");--> statement-breakpoint
CREATE INDEX "idx_hypotheses_incident" ON "investigation_hypotheses" USING btree ("incident_id");--> statement-breakpoint
CREATE INDEX "idx_hypotheses_org" ON "investigation_hypotheses" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_hypotheses_status" ON "investigation_hypotheses" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_inv_tasks_incident" ON "investigation_tasks" USING btree ("incident_id");--> statement-breakpoint
CREATE INDEX "idx_inv_tasks_org" ON "investigation_tasks" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_inv_tasks_assigned" ON "investigation_tasks" USING btree ("assigned_to");--> statement-breakpoint
CREATE INDEX "idx_inv_tasks_status" ON "investigation_tasks" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_ioc_entries_org" ON "ioc_entries" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ioc_entries_feed" ON "ioc_entries" USING btree ("feed_id");--> statement-breakpoint
CREATE INDEX "idx_ioc_entries_type" ON "ioc_entries" USING btree ("ioc_type");--> statement-breakpoint
CREATE INDEX "idx_ioc_entries_value" ON "ioc_entries" USING btree ("ioc_value");--> statement-breakpoint
CREATE INDEX "idx_ioc_entries_type_value" ON "ioc_entries" USING btree ("ioc_type","ioc_value");--> statement-breakpoint
CREATE INDEX "idx_ioc_entries_org_created" ON "ioc_entries" USING btree ("org_id","created_at");--> statement-breakpoint
CREATE INDEX "idx_ioc_entries_org_type_created" ON "ioc_entries" USING btree ("org_id","ioc_type","created_at");--> statement-breakpoint
CREATE INDEX "idx_ioc_entries_status" ON "ioc_entries" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_ioc_feeds_org" ON "ioc_feeds" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ioc_match_rules_org" ON "ioc_match_rules" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ioc_matches_org" ON "ioc_matches" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ioc_matches_alert" ON "ioc_matches" USING btree ("alert_id");--> statement-breakpoint
CREATE INDEX "idx_ioc_matches_ioc" ON "ioc_matches" USING btree ("ioc_entry_id");--> statement-breakpoint
CREATE INDEX "idx_ioc_watchlist_entries_wl" ON "ioc_watchlist_entries" USING btree ("watchlist_id");--> statement-breakpoint
CREATE INDEX "idx_ioc_watchlist_entries_ioc" ON "ioc_watchlist_entries" USING btree ("ioc_entry_id");--> statement-breakpoint
CREATE INDEX "idx_ioc_watchlists_org" ON "ioc_watchlists" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_job_queue_status_run" ON "job_queue" USING btree ("status","run_at");--> statement-breakpoint
CREATE INDEX "idx_job_queue_org" ON "job_queue" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_job_queue_type_status" ON "job_queue" USING btree ("type","status");--> statement-breakpoint
CREATE INDEX "idx_job_queue_fingerprint" ON "job_queue" USING btree ("fingerprint");--> statement-breakpoint
CREATE INDEX "idx_job_queue_locked_until" ON "job_queue" USING btree ("locked_until");--> statement-breakpoint
CREATE INDEX "idx_legal_holds_org" ON "legal_holds" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_legal_holds_active" ON "legal_holds" USING btree ("is_active");--> statement-breakpoint
CREATE INDEX "idx_notification_channels_org" ON "notification_channels" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_notification_channels_type" ON "notification_channels" USING btree ("type");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_onboarding_org_step" ON "onboarding_progress" USING btree ("org_id","step_key");--> statement-breakpoint
CREATE INDEX "idx_onboarding_org" ON "onboarding_progress" USING btree ("org_id");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_domain_verifications_org_domain" ON "org_domain_verifications" USING btree ("org_id","domain");--> statement-breakpoint
CREATE INDEX "idx_domain_verifications_org" ON "org_domain_verifications" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_domain_verifications_status" ON "org_domain_verifications" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_invitation_org" ON "org_invitations" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_invitation_email" ON "org_invitations" USING btree ("email");--> statement-breakpoint
CREATE INDEX "idx_invitation_token" ON "org_invitations" USING btree ("token");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_org_plan_unique" ON "org_plan_limits" USING btree ("org_id");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_role_perms_role_scope_action" ON "org_role_permissions" USING btree ("role_id","scope","action");--> statement-breakpoint
CREATE INDEX "idx_role_perms_role" ON "org_role_permissions" USING btree ("role_id");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_org_roles_org_name" ON "org_roles" USING btree ("org_id","name");--> statement-breakpoint
CREATE INDEX "idx_org_roles_org" ON "org_roles" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_org_roles_system" ON "org_roles" USING btree ("is_system");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_scim_configs_org" ON "org_scim_configs" USING btree ("org_id");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_org_security_policies_org" ON "org_security_policies" USING btree ("org_id");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_sso_configs_org" ON "org_sso_configs" USING btree ("org_id");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_team_memberships_team_user" ON "org_team_memberships" USING btree ("team_id","user_id");--> statement-breakpoint
CREATE INDEX "idx_team_memberships_team" ON "org_team_memberships" USING btree ("team_id");--> statement-breakpoint
CREATE INDEX "idx_team_memberships_user" ON "org_team_memberships" USING btree ("user_id");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_org_teams_org_name" ON "org_teams" USING btree ("org_id","name");--> statement-breakpoint
CREATE INDEX "idx_org_teams_org" ON "org_teams" USING btree ("org_id");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_membership_org_user" ON "organization_memberships" USING btree ("org_id","user_id");--> statement-breakpoint
CREATE INDEX "idx_membership_org" ON "organization_memberships" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_membership_user" ON "organization_memberships" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "idx_webhook_logs_webhook" ON "outbound_webhook_logs" USING btree ("webhook_id");--> statement-breakpoint
CREATE INDEX "idx_webhook_logs_event" ON "outbound_webhook_logs" USING btree ("event");--> statement-breakpoint
CREATE INDEX "idx_webhook_logs_delivered" ON "outbound_webhook_logs" USING btree ("delivered_at");--> statement-breakpoint
CREATE INDEX "idx_outbound_webhooks_org" ON "outbound_webhooks" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_outbound_webhooks_active" ON "outbound_webhooks" USING btree ("is_active");--> statement-breakpoint
CREATE INDEX "idx_outbox_status_next_retry" ON "outbox_events" USING btree ("status","next_retry_at");--> statement-breakpoint
CREATE INDEX "idx_outbox_org" ON "outbox_events" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_outbox_aggregate" ON "outbox_events" USING btree ("aggregate_type","aggregate_id");--> statement-breakpoint
CREATE INDEX "idx_outbox_fingerprint" ON "outbox_events" USING btree ("fingerprint");--> statement-breakpoint
CREATE INDEX "idx_outbox_event_type" ON "outbox_events" USING btree ("event_type");--> statement-breakpoint
CREATE INDEX "idx_pir_action_items_review" ON "pir_action_items" USING btree ("review_id");--> statement-breakpoint
CREATE INDEX "idx_pir_action_items_org" ON "pir_action_items" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_pir_action_items_status" ON "pir_action_items" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_playbook_approvals_execution" ON "playbook_approvals" USING btree ("execution_id");--> statement-breakpoint
CREATE INDEX "idx_playbook_approvals_status" ON "playbook_approvals" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_playbook_executions_playbook" ON "playbook_executions" USING btree ("playbook_id");--> statement-breakpoint
CREATE INDEX "idx_playbook_executions_status" ON "playbook_executions" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_playbook_executions_created" ON "playbook_executions" USING btree ("created_at");--> statement-breakpoint
CREATE INDEX "idx_pb_rollback_playbook" ON "playbook_rollback_plans" USING btree ("playbook_id");--> statement-breakpoint
CREATE INDEX "idx_pb_rollback_execution" ON "playbook_rollback_plans" USING btree ("execution_id");--> statement-breakpoint
CREATE INDEX "idx_pb_rollback_org" ON "playbook_rollback_plans" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_pb_rollback_status" ON "playbook_rollback_plans" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_pb_simulations_playbook" ON "playbook_simulations" USING btree ("playbook_id");--> statement-breakpoint
CREATE INDEX "idx_pb_simulations_org" ON "playbook_simulations" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_pb_simulations_status" ON "playbook_simulations" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_pb_versions_playbook" ON "playbook_versions" USING btree ("playbook_id");--> statement-breakpoint
CREATE INDEX "idx_pb_versions_org" ON "playbook_versions" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_pb_versions_status" ON "playbook_versions" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_pb_versions_playbook_version" ON "playbook_versions" USING btree ("playbook_id","version");--> statement-breakpoint
CREATE INDEX "idx_playbooks_org" ON "playbooks" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_playbooks_status" ON "playbooks" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_playbooks_trigger" ON "playbooks" USING btree ("trigger");--> statement-breakpoint
CREATE INDEX "idx_policy_checks_org" ON "policy_checks" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_policy_checks_provider" ON "policy_checks" USING btree ("cloud_provider");--> statement-breakpoint
CREATE INDEX "idx_policy_checks_status" ON "policy_checks" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_policy_results_org" ON "policy_results" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_policy_results_check" ON "policy_results" USING btree ("policy_check_id");--> statement-breakpoint
CREATE INDEX "idx_policy_results_status" ON "policy_results" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_pir_incident" ON "post_incident_reviews" USING btree ("incident_id");--> statement-breakpoint
CREATE INDEX "idx_pir_org" ON "post_incident_reviews" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_pir_status" ON "post_incident_reviews" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_pir_org_created" ON "post_incident_reviews" USING btree ("org_id","created_at");--> statement-breakpoint
CREATE INDEX "idx_resp_approval_org" ON "response_action_approvals" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_resp_approval_status" ON "response_action_approvals" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_resp_approval_incident" ON "response_action_approvals" USING btree ("incident_id");--> statement-breakpoint
CREATE INDEX "idx_response_actions_org" ON "response_actions" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_response_actions_incident" ON "response_actions" USING btree ("incident_id");--> statement-breakpoint
CREATE INDEX "idx_response_actions_status" ON "response_actions" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_response_actions_type" ON "response_actions" USING btree ("action_type");--> statement-breakpoint
CREATE INDEX "idx_response_actions_org_created" ON "response_actions" USING btree ("org_id","created_at");--> statement-breakpoint
CREATE INDEX "idx_response_actions_org_status_created" ON "response_actions" USING btree ("org_id","status","created_at");--> statement-breakpoint
CREATE INDEX "idx_runbook_steps_template" ON "runbook_steps" USING btree ("template_id");--> statement-breakpoint
CREATE INDEX "idx_runbook_templates_type" ON "runbook_templates" USING btree ("incident_type");--> statement-breakpoint
CREATE INDEX "idx_runbook_templates_org" ON "runbook_templates" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_saved_views_org" ON "saved_views" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_saved_views_user" ON "saved_views" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "idx_saved_views_team" ON "saved_views" USING btree ("team_id");--> statement-breakpoint
CREATE INDEX "idx_saved_views_resource" ON "saved_views" USING btree ("org_id","resource_type");--> statement-breakpoint
CREATE INDEX "idx_saved_views_visibility" ON "saved_views" USING btree ("org_id","visibility");--> statement-breakpoint
CREATE INDEX "idx_sli_metrics_service_metric_recorded" ON "sli_metrics" USING btree ("service","metric","recorded_at");--> statement-breakpoint
CREATE INDEX "idx_sli_metrics_recorded" ON "sli_metrics" USING btree ("recorded_at");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_slo_targets_service_metric_endpoint" ON "slo_targets" USING btree ("service","metric","endpoint");--> statement-breakpoint
CREATE INDEX "idx_suppression_rules_org" ON "suppression_rules" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_suppression_rules_enabled" ON "suppression_rules" USING btree ("enabled");--> statement-breakpoint
CREATE INDEX "idx_suppression_rules_expires" ON "suppression_rules" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "idx_suppression_rules_owner" ON "suppression_rules" USING btree ("owned_by");--> statement-breakpoint
CREATE INDEX "idx_threat_intel_configs_org" ON "threat_intel_configs" USING btree ("org_id");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_threat_intel_configs_org_provider" ON "threat_intel_configs" USING btree ("org_id","provider");--> statement-breakpoint
CREATE INDEX "idx_ticket_sync_org" ON "ticket_sync_jobs" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ticket_sync_integration" ON "ticket_sync_jobs" USING btree ("integration_id");--> statement-breakpoint
CREATE INDEX "idx_ticket_sync_incident" ON "ticket_sync_jobs" USING btree ("incident_id");--> statement-breakpoint
CREATE INDEX "idx_usage_meter_org" ON "usage_meter_snapshots" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_usage_meter_type" ON "usage_meter_snapshots" USING btree ("metric_type");--> statement-breakpoint
CREATE INDEX "idx_usage_meter_period" ON "usage_meter_snapshots" USING btree ("period_start","period_end");--> statement-breakpoint
CREATE INDEX "IDX_session_expire" ON "sessions" USING btree ("expire");