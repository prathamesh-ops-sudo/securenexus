CREATE TABLE "access_review_campaigns" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"cadence" text DEFAULT 'quarterly' NOT NULL,
	"status" text DEFAULT 'draft' NOT NULL,
	"reviewer_user_id" varchar,
	"reviewer_name" text,
	"total_entitlements" integer DEFAULT 0 NOT NULL,
	"reviewed_count" integer DEFAULT 0 NOT NULL,
	"approved_count" integer DEFAULT 0 NOT NULL,
	"revoked_count" integer DEFAULT 0 NOT NULL,
	"due_date" timestamp,
	"started_at" timestamp,
	"completed_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "access_review_entitlements" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"campaign_id" varchar NOT NULL,
	"user_id" varchar NOT NULL,
	"user_name" text NOT NULL,
	"user_email" text,
	"entitlement_type" text NOT NULL,
	"entitlement_name" text NOT NULL,
	"entitlement_description" text,
	"granted_at" timestamp,
	"last_used_at" timestamp,
	"risk_level" text DEFAULT 'low',
	"status" text DEFAULT 'pending' NOT NULL,
	"decision" text,
	"decision_by" varchar,
	"decision_at" timestamp,
	"decision_reason" text,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "access_reviews" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"review_type" text DEFAULT 'periodic' NOT NULL,
	"scope" text,
	"status" text DEFAULT 'pending' NOT NULL,
	"reviewer_id" text,
	"reviewer_name" text,
	"total_entitlements" integer DEFAULT 0,
	"reviewed_count" integer DEFAULT 0,
	"approved_count" integer DEFAULT 0,
	"revoked_count" integer DEFAULT 0,
	"due_date" timestamp,
	"completed_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "adversarial_remediations" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"execution_id" text NOT NULL,
	"test_case_name" text NOT NULL,
	"severity" text DEFAULT 'medium' NOT NULL,
	"status" text DEFAULT 'open' NOT NULL,
	"assignee" text,
	"recommendation" text,
	"resolved_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "adversarial_test_executions" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"test_case_id" text NOT NULL,
	"test_case_name" text NOT NULL,
	"domain" text NOT NULL,
	"category" text NOT NULL,
	"phase" text DEFAULT 'pre_production' NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"trigger" text DEFAULT 'manual' NOT NULL,
	"severity" text DEFAULT 'medium',
	"result" jsonb DEFAULT '{}'::jsonb,
	"duration" integer,
	"started_at" timestamp DEFAULT now(),
	"completed_at" timestamp,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "adversarial_test_schedules" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"test_case_ids" text[] DEFAULT ARRAY[]::text[],
	"frequency" text DEFAULT 'weekly' NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"last_run_at" timestamp,
	"next_run_at" timestamp,
	"config" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "agent_response_actions" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"sensor_id" varchar NOT NULL,
	"action_type" text NOT NULL,
	"risk_level" text DEFAULT 'medium' NOT NULL,
	"status" text DEFAULT 'pending_approval' NOT NULL,
	"target_pid" integer,
	"target_process_name" text,
	"target_ip" text,
	"target_file_path" text,
	"target_user_name" text,
	"target_domain" text,
	"target_service_name" text,
	"script_content" text,
	"script_type" text,
	"parameters" jsonb,
	"requested_by" varchar,
	"requested_by_name" text,
	"approved_by" varchar,
	"approved_by_name" text,
	"approved_at" timestamp,
	"rejected_by" varchar,
	"rejected_reason" text,
	"rejected_at" timestamp,
	"dispatched_at" timestamp,
	"completed_at" timestamp,
	"result_output" text,
	"result_error" text,
	"timeout_seconds" integer DEFAULT 300 NOT NULL,
	"expires_at" timestamp,
	"incident_id" varchar,
	"reason" text,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "agent_tool_anomalies" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"tool_id" text NOT NULL,
	"agent_id" text NOT NULL,
	"anomaly_type" text NOT NULL,
	"severity" text DEFAULT 'medium' NOT NULL,
	"description" text,
	"acknowledged" boolean DEFAULT false NOT NULL,
	"acknowledged_by" text,
	"acknowledged_at" timestamp,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"detected_at" timestamp DEFAULT now(),
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "agent_tool_invocations" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"tool_id" text NOT NULL,
	"tool_name" text NOT NULL,
	"agent_id" text NOT NULL,
	"verdict" text DEFAULT 'allowed' NOT NULL,
	"input_hash" text,
	"output_summary" text,
	"duration_ms" integer,
	"risk_score" real DEFAULT 0,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "agent_tool_policies" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"tool_id" text NOT NULL,
	"max_calls_per_minute" integer DEFAULT 60,
	"max_calls_per_hour" integer DEFAULT 1000,
	"require_approval_above_risk" real DEFAULT 0.8,
	"allowed_agent_ids" text[] DEFAULT ARRAY[]::text[],
	"blocked" boolean DEFAULT false NOT NULL,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "agent_trust_boundary_rules" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"source_boundary" text NOT NULL,
	"target_boundary" text NOT NULL,
	"action" text DEFAULT 'deny' NOT NULL,
	"priority" integer DEFAULT 100 NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "ai_analyst_decisions" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"alert_id" varchar,
	"incident_id" varchar,
	"tier" text DEFAULT 'tier1_autonomous' NOT NULL,
	"outcome" text NOT NULL,
	"confidence_score" real NOT NULL,
	"confidence_factors" jsonb,
	"enrichment_data" jsonb,
	"correlation_results" jsonb,
	"hypotheses" jsonb,
	"reasoning" text,
	"executive_summary" text,
	"recommended_actions" jsonb,
	"executed_actions" jsonb,
	"mitre_tactics" text[],
	"mitre_techniques" text[],
	"related_alert_ids" text[],
	"time_to_decision_ms" integer,
	"human_override" boolean DEFAULT false NOT NULL,
	"human_override_by" text,
	"human_override_reason" text,
	"human_override_at" timestamp,
	"status" text DEFAULT 'pending' NOT NULL,
	"reviewed_by" text,
	"reviewed_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
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
CREATE TABLE "ai_generated_rules" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"source_incident_id" varchar,
	"name" text NOT NULL,
	"description" text,
	"rule_content" jsonb NOT NULL,
	"sigma_normalized" text,
	"confidence" real DEFAULT 0.5 NOT NULL,
	"status" text DEFAULT 'draft' NOT NULL,
	"mitre_tactic" text,
	"mitre_technique" text,
	"generated_by" text DEFAULT 'claude-opus' NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"reviewed_at" timestamp,
	"reviewed_by" varchar
);
--> statement-breakpoint
CREATE TABLE "ai_inference_log" (
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
CREATE TABLE "ai_prompt_audit_log" (
	"id" integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY (sequence name "ai_prompt_audit_log_id_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 2147483647 START WITH 1 CACHE 1),
	"prompt_id" varchar NOT NULL,
	"version" integer NOT NULL,
	"action" varchar NOT NULL,
	"metadata" jsonb,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "ai_prompt_versions" (
	"id" integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY (sequence name "ai_prompt_versions_id_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 2147483647 START WITH 1 CACHE 1),
	"prompt_id" varchar NOT NULL,
	"org_id" varchar,
	"version" integer NOT NULL,
	"name" varchar NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"tier" varchar DEFAULT 'general' NOT NULL,
	"system_prompt" text NOT NULL,
	"user_template" text NOT NULL,
	"output_schema" jsonb,
	"max_tokens" integer DEFAULT 2048 NOT NULL,
	"temperature" double precision DEFAULT 0.1 NOT NULL,
	"tags" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "ai_prompts" (
	"id" varchar PRIMARY KEY NOT NULL,
	"org_id" varchar,
	"name" varchar NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"tier" varchar DEFAULT 'general' NOT NULL,
	"system_prompt" text NOT NULL,
	"user_template" text NOT NULL,
	"output_schema" jsonb,
	"max_tokens" integer DEFAULT 2048 NOT NULL,
	"temperature" double precision DEFAULT 0.1 NOT NULL,
	"version" integer DEFAULT 1 NOT NULL,
	"deprecated" boolean DEFAULT false NOT NULL,
	"deprecated_at" timestamp,
	"superseded_by" varchar,
	"tags" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
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
	"occurrence_count" integer DEFAULT 1,
	"analyst_notes" text,
	"assigned_to" varchar,
	"detected_at" timestamp,
	"ingested_at" timestamp DEFAULT now(),
	"last_seen_at" timestamp,
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
	"occurrence_count" integer DEFAULT 1,
	"analyst_notes" text,
	"assigned_to" varchar,
	"detected_at" timestamp,
	"ingested_at" timestamp DEFAULT now(),
	"last_seen_at" timestamp,
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
CREATE TABLE "api_findings" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"api_id" varchar,
	"finding_type" text NOT NULL,
	"severity" text DEFAULT 'medium' NOT NULL,
	"status" text DEFAULT 'open' NOT NULL,
	"title" text NOT NULL,
	"description" text,
	"endpoint" text,
	"method" text,
	"evidence" jsonb,
	"remediation" text,
	"cwe_id" text,
	"owasp_category" text,
	"request_sample" text,
	"response_sample" text,
	"detected_at" timestamp DEFAULT now(),
	"acknowledged_by" varchar,
	"acknowledged_at" timestamp,
	"mitigated_by" varchar,
	"mitigated_at" timestamp,
	"metadata" jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "api_inventory" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"method" text NOT NULL,
	"path" text NOT NULL,
	"host" text NOT NULL,
	"version" text,
	"spec_source" text,
	"is_shadow" boolean DEFAULT false NOT NULL,
	"is_deprecated" boolean DEFAULT false NOT NULL,
	"auth_type" text DEFAULT 'none' NOT NULL,
	"risk_score" integer DEFAULT 0 NOT NULL,
	"request_count_24h" integer DEFAULT 0 NOT NULL,
	"error_rate_24h" real DEFAULT 0 NOT NULL,
	"avg_latency_ms" real DEFAULT 0 NOT NULL,
	"last_seen_at" timestamp,
	"first_seen_at" timestamp DEFAULT now(),
	"openapi_spec" jsonb,
	"tags" jsonb,
	"sensitive_data_types" jsonb,
	"metadata" jsonb,
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
	"revoked_at" timestamp,
	"deprecated_at" timestamp,
	"grace_expires_at" timestamp,
	"replaced_by_key_id" varchar
);
--> statement-breakpoint
CREATE TABLE "api_security_endpoints" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"method" text NOT NULL,
	"path" text NOT NULL,
	"service_name" text,
	"auth_type" text,
	"risk_score" double precision DEFAULT 0,
	"sensitive_data_exposed" boolean DEFAULT false,
	"last_called_at" timestamp,
	"total_calls" integer DEFAULT 0,
	"error_rate" double precision DEFAULT 0,
	"avg_latency_ms" double precision DEFAULT 0,
	"status" text DEFAULT 'active' NOT NULL,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "api_security_threats" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"endpoint_id" text,
	"threat_type" text NOT NULL,
	"severity" text DEFAULT 'medium' NOT NULL,
	"source_ip" text,
	"description" text,
	"blocked" boolean DEFAULT false,
	"details" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "api_traffic_baselines" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"api_id" varchar NOT NULL,
	"window_start" timestamp NOT NULL,
	"window_end" timestamp NOT NULL,
	"request_count" integer DEFAULT 0 NOT NULL,
	"unique_callers" integer DEFAULT 0 NOT NULL,
	"error_count" integer DEFAULT 0 NOT NULL,
	"avg_latency_ms" real DEFAULT 0 NOT NULL,
	"p95_latency_ms" real DEFAULT 0 NOT NULL,
	"p99_latency_ms" real DEFAULT 0 NOT NULL,
	"status_code_distribution" jsonb,
	"top_caller_ips" jsonb,
	"anomaly_score" real DEFAULT 0 NOT NULL,
	"metadata" jsonb,
	"created_at" timestamp DEFAULT now()
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
CREATE TABLE "artifact_approvals" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"artifact_id" text NOT NULL,
	"investigation_id" text NOT NULL,
	"reason" text NOT NULL,
	"required_role" text DEFAULT 'admin' NOT NULL,
	"status" text DEFAULT 'pending_approval' NOT NULL,
	"requested_by" text NOT NULL,
	"requested_at" timestamp DEFAULT now(),
	"reviewed_by" text,
	"reviewed_at" timestamp,
	"review_notes" text
);
--> statement-breakpoint
CREATE TABLE "artifact_deployments" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"artifact_id" text NOT NULL,
	"investigation_id" text NOT NULL,
	"artifact_type" text NOT NULL,
	"target_page" text NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"deployed_at" timestamp DEFAULT now(),
	"rolled_back_at" timestamp,
	"deployed_by" text NOT NULL,
	"snapshot_content" jsonb DEFAULT '{}'::jsonb
);
--> statement-breakpoint
CREATE TABLE "assessment_responses" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"assessment_id" varchar NOT NULL,
	"org_id" varchar NOT NULL,
	"control_id" text NOT NULL,
	"control_title" text NOT NULL,
	"control_description" text,
	"category" text,
	"status" text DEFAULT 'not_assessed' NOT NULL,
	"notes" text,
	"evidence" text,
	"gap_description" text,
	"recommended_action" text,
	"priority" text DEFAULT 'medium',
	"weight" integer DEFAULT 1 NOT NULL,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "asset_inventory" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"asset_type" text NOT NULL,
	"criticality" text DEFAULT 'medium' NOT NULL,
	"lifecycle_status" text DEFAULT 'active' NOT NULL,
	"environment" text DEFAULT 'production',
	"ip_address" text,
	"mac_address" text,
	"hostname" text,
	"fqdn" text,
	"owner" text,
	"department" text,
	"location" text,
	"operating_system" text,
	"os_version" text,
	"manufacturer" text,
	"model" text,
	"serial_number" text,
	"installed_software" jsonb DEFAULT '[]'::jsonb,
	"last_patch_date" timestamp,
	"risk_score" integer DEFAULT 0 NOT NULL,
	"vulnerability_count" integer DEFAULT 0 NOT NULL,
	"open_findings" integer DEFAULT 0 NOT NULL,
	"compliance_tags" text[] DEFAULT ARRAY[]::text[],
	"tags" text[] DEFAULT ARRAY[]::text[],
	"notes" text,
	"purchase_date" timestamp,
	"warranty_expiry" timestamp,
	"end_of_life" timestamp,
	"last_seen_at" timestamp,
	"discovered_by" text,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "attack_graph_edges" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"graph_id" varchar NOT NULL,
	"source_node_id" text NOT NULL,
	"target_node_id" text NOT NULL,
	"relationship" text NOT NULL,
	"technique" text,
	"confidence" real DEFAULT 0,
	"timestamp" text,
	"evidence" text[] DEFAULT ARRAY[]::text[],
	"metadata" jsonb,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "attack_graph_nodes" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"graph_id" varchar NOT NULL,
	"node_id" text NOT NULL,
	"node_type" text NOT NULL,
	"label" text NOT NULL,
	"description" text,
	"mitre_technique" text,
	"mitre_tactic" text,
	"confidence" real DEFAULT 0,
	"severity" text,
	"evidence" text[] DEFAULT ARRAY[]::text[],
	"metadata" jsonb,
	"position_x" real,
	"position_y" real,
	"depth" integer DEFAULT 0,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "attack_graphs" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"incident_id" varchar NOT NULL,
	"investigation_id" varchar,
	"initial_access_description" text,
	"current_position" text,
	"objectives_achieved" text[] DEFAULT ARRAY[]::text[],
	"objectives_in_progress" text[] DEFAULT ARRAY[]::text[],
	"total_nodes" integer DEFAULT 0,
	"total_edges" integer DEFAULT 0,
	"max_depth" integer DEFAULT 0,
	"confidence" real DEFAULT 0,
	"metadata" jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
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
	"user_agent" text,
	"impersonated_by" varchar,
	"request_id" varchar,
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
CREATE TABLE "autonomy_log" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"decision_id" varchar,
	"action" text NOT NULL,
	"tier" text NOT NULL,
	"alert_id" varchar,
	"incident_id" varchar,
	"details" jsonb,
	"confidence_before" real,
	"confidence_after" real,
	"duration_ms" integer,
	"success" boolean DEFAULT true NOT NULL,
	"error" text,
	"triggered_by" text DEFAULT 'ai_analyst' NOT NULL,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "awareness_programs" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"program_type" text DEFAULT 'training' NOT NULL,
	"status" text DEFAULT 'active' NOT NULL,
	"target_audience" jsonb DEFAULT '[]'::jsonb,
	"completion_rate" double precision DEFAULT 0,
	"participant_count" integer DEFAULT 0,
	"pass_rate" double precision DEFAULT 0,
	"start_date" timestamp,
	"end_date" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "backup_verifications" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"backup_name" text NOT NULL,
	"backup_type" text NOT NULL,
	"backup_location" text NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"integrity_check_result" text,
	"restore_test_result" text,
	"backup_size_bytes" integer,
	"backup_created_at" timestamp,
	"retention_days" integer,
	"encryption_status" text,
	"encryption_algorithm" text,
	"last_verified_at" timestamp,
	"next_scheduled_verification" timestamp,
	"verification_duration_seconds" integer,
	"issues" jsonb,
	"covered_systems" jsonb,
	"rpo_hours" integer,
	"rto_hours" integer,
	"verified_by" varchar,
	"metadata" jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "badge_events" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"asset_id" uuid,
	"event_type" text NOT NULL,
	"badge_number" text,
	"employee_name" text,
	"employee_email" text,
	"employee_department" text,
	"location" text NOT NULL,
	"door_name" text,
	"direction" text,
	"is_anomaly" boolean DEFAULT false NOT NULL,
	"anomaly_reason" text,
	"correlated_alert_id" uuid,
	"raw_payload" jsonb DEFAULT '{}'::jsonb,
	"occurred_at" timestamp DEFAULT now() NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL
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
CREATE TABLE "board_kpi_configs" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"kpi_type" text NOT NULL,
	"display_name" text NOT NULL,
	"position" integer DEFAULT 0 NOT NULL,
	"visible" boolean DEFAULT true NOT NULL,
	"target_value" double precision,
	"warning_threshold" double precision,
	"critical_threshold" double precision,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "board_summaries" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"period" text DEFAULT 'monthly' NOT NULL,
	"title" text NOT NULL,
	"executive_synopsis" text,
	"key_findings" jsonb DEFAULT '[]'::jsonb,
	"risk_posture" jsonb DEFAULT '{}'::jsonb,
	"recommendations" jsonb DEFAULT '[]'::jsonb,
	"mttr" jsonb DEFAULT '{}'::jsonb,
	"exploitability" jsonb DEFAULT '{}'::jsonb,
	"remediation_throughput" jsonb DEFAULT '{}'::jsonb,
	"automation_savings" jsonb DEFAULT '{}'::jsonb,
	"generated_by" text,
	"generated_at" timestamp DEFAULT now(),
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "breach_monitoring_targets" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"target_type" text NOT NULL,
	"target_value" text NOT NULL,
	"label" text,
	"is_active" boolean DEFAULT true NOT NULL,
	"last_checked_at" timestamp,
	"exposure_count" integer DEFAULT 0 NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "browser_defense_sessions" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"agent_id" text NOT NULL,
	"url" text NOT NULL,
	"state" text DEFAULT 'active' NOT NULL,
	"threat_level" text DEFAULT 'none',
	"dom_events_count" integer DEFAULT 0,
	"egress_blocked_count" integer DEFAULT 0,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"started_at" timestamp DEFAULT now(),
	"ended_at" timestamp,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "browser_dom_events" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"session_id" varchar NOT NULL,
	"event_type" varchar(30) NOT NULL,
	"target" text NOT NULL,
	"severity" varchar(20) DEFAULT 'info' NOT NULL,
	"verdict" varchar(20) DEFAULT 'allow' NOT NULL,
	"details" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "browser_egress_rules" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"domain" text NOT NULL,
	"protocol" text DEFAULT 'https' NOT NULL,
	"direction" text DEFAULT 'outbound' NOT NULL,
	"verdict" text DEFAULT 'allow' NOT NULL,
	"priority" integer DEFAULT 100 NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "browser_injection_patterns" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"pattern" text NOT NULL,
	"pattern_type" varchar(20) DEFAULT 'regex' NOT NULL,
	"severity" varchar(20) DEFAULT 'high' NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"match_count" integer DEFAULT 0 NOT NULL,
	"last_matched_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "browser_trusted_paths" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"steps" jsonb DEFAULT '[]'::jsonb,
	"enabled" boolean DEFAULT true NOT NULL,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
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
CREATE TABLE "canary_tokens" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"token_type" text NOT NULL,
	"token_value" text NOT NULL,
	"token_hash" text NOT NULL,
	"callback_url" text NOT NULL,
	"callback_secret" text NOT NULL,
	"deployed_to" text,
	"deployment_target" text,
	"deployment_metadata" jsonb,
	"is_active" boolean DEFAULT true NOT NULL,
	"hit_count" integer DEFAULT 0 NOT NULL,
	"last_hit_at" timestamp,
	"created_by" varchar,
	"expires_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "chaos_schedules" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"frequency" text DEFAULT 'weekly' NOT NULL,
	"simulation_ids" text[],
	"mitre_ids" text[],
	"enabled" boolean DEFAULT true NOT NULL,
	"last_run_at" timestamp,
	"next_run_at" timestamp,
	"total_runs" integer DEFAULT 0 NOT NULL,
	"last_score" integer,
	"previous_score" integer,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "chaos_simulations" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"mitre_id" text NOT NULL,
	"mitre_tactic" text NOT NULL,
	"mitre_technique" text NOT NULL,
	"domain" text DEFAULT 'endpoint' NOT NULL,
	"platform" text DEFAULT 'windows' NOT NULL,
	"severity" text DEFAULT 'medium' NOT NULL,
	"payload" text,
	"expected_outcome" text,
	"status" text DEFAULT 'pending' NOT NULL,
	"verdict" text,
	"duration_ms" integer,
	"output" text,
	"trigger" text DEFAULT 'manual' NOT NULL,
	"executed_by" text,
	"executed_at" timestamp,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "ci_gates" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"repository" text NOT NULL,
	"branch" text NOT NULL,
	"commit_sha" text NOT NULL,
	"pull_request_id" text,
	"pipeline_provider" text DEFAULT 'github_actions' NOT NULL,
	"pipeline_run_id" text,
	"status" text DEFAULT 'passed' NOT NULL,
	"critical_findings" integer DEFAULT 0 NOT NULL,
	"high_findings" integer DEFAULT 0 NOT NULL,
	"medium_findings" integer DEFAULT 0 NOT NULL,
	"low_findings" integer DEFAULT 0 NOT NULL,
	"secrets_found" integer DEFAULT 0 NOT NULL,
	"policy_violations" integer DEFAULT 0 NOT NULL,
	"gate_policy" jsonb,
	"failure_reasons" text[],
	"scan_duration_ms" integer,
	"report_url" text,
	"metadata" jsonb,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "code_owners" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"email" text NOT NULL,
	"team" text NOT NULL,
	"files_owned" jsonb DEFAULT '[]'::jsonb,
	"review_count" integer DEFAULT 0,
	"last_active" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "code_review_findings" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"repository" text NOT NULL,
	"pull_request_id" text NOT NULL,
	"commit_sha" text NOT NULL,
	"file_path" text NOT NULL,
	"line" integer NOT NULL,
	"category" text NOT NULL,
	"severity" text DEFAULT 'medium' NOT NULL,
	"title" text NOT NULL,
	"description" text NOT NULL,
	"suggestion" text,
	"comment_posted" boolean DEFAULT false NOT NULL,
	"comment_id" text,
	"accepted" boolean,
	"accepted_by" text,
	"metadata" jsonb,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "cold_storage_inventory" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"data_type" text NOT NULL,
	"tier" text DEFAULT 'cold' NOT NULL,
	"s3_key" text NOT NULL,
	"format" text DEFAULT 'parquet' NOT NULL,
	"record_count" integer DEFAULT 0 NOT NULL,
	"compressed_size_bytes" bigint DEFAULT 0 NOT NULL,
	"oldest_record" timestamp,
	"newest_record" timestamp,
	"checksum_sha256" text,
	"tiering_job_id" uuid,
	"retention_policy_id" uuid,
	"purge_eligible_at" timestamp,
	"is_rehydrated" boolean DEFAULT false NOT NULL,
	"rehydrated_at" timestamp,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "collector_events" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"collector_id" varchar NOT NULL,
	"org_id" varchar NOT NULL,
	"event_type" text NOT NULL,
	"severity" text DEFAULT 'info' NOT NULL,
	"source" text NOT NULL,
	"timestamp" timestamp DEFAULT now(),
	"raw_data" jsonb DEFAULT '{}'::jsonb,
	"parsed_fields" jsonb DEFAULT '{}'::jsonb,
	"tags" text[] DEFAULT ARRAY[]::text[],
	"processed" boolean DEFAULT false NOT NULL,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "collector_instances" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"template_slug" text NOT NULL,
	"name" text NOT NULL,
	"status" text DEFAULT 'pending_install' NOT NULL,
	"platform" text NOT NULL,
	"deployment_method" text NOT NULL,
	"config" jsonb DEFAULT '{}'::jsonb,
	"host_info" jsonb,
	"metrics" jsonb DEFAULT '{"eventsPerSecond":0,"bytesIngested":0,"errorsLast24h":0,"uptimePercent":0,"latencyP50Ms":0,"latencyP99Ms":0,"lastEventCount":0,"totalEventsIngested":0}'::jsonb,
	"version" text DEFAULT '1.0.0',
	"tags" text[] DEFAULT ARRAY[]::text[],
	"last_heartbeat_at" timestamp,
	"last_data_at" timestamp,
	"installed_at" timestamp DEFAULT now(),
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "collector_scans" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"collector_id" varchar NOT NULL,
	"org_id" varchar NOT NULL,
	"scan_type" text NOT NULL,
	"status" text DEFAULT 'running' NOT NULL,
	"targets" text[] DEFAULT ARRAY[]::text[],
	"findings" jsonb DEFAULT '[]'::jsonb,
	"summary" jsonb DEFAULT '{}'::jsonb,
	"started_at" timestamp DEFAULT now(),
	"completed_at" timestamp,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "community_feeds" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"feed_name" text NOT NULL,
	"feed_type" text DEFAULT 'industry' NOT NULL,
	"industry_sector" text,
	"description" text,
	"ioc_count" integer DEFAULT 0 NOT NULL,
	"member_count" integer DEFAULT 0 NOT NULL,
	"last_updated_at" timestamp DEFAULT now(),
	"is_subscribed" boolean DEFAULT false NOT NULL,
	"subscribed_at" timestamp,
	"auto_ingest" boolean DEFAULT false NOT NULL,
	"filter_severity" text DEFAULT 'medium',
	"filter_confidence" integer DEFAULT 50,
	"stats" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "community_hunt_shares" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"hunt_id" uuid,
	"title" text NOT NULL,
	"description" text,
	"query_type" text NOT NULL,
	"query_text" text NOT NULL,
	"category" text,
	"mitre_techniques" jsonb DEFAULT '[]'::jsonb,
	"tags" jsonb DEFAULT '[]'::jsonb,
	"anonymized_stats" jsonb DEFAULT '{}'::jsonb,
	"upvotes" integer DEFAULT 0 NOT NULL,
	"downloads" integer DEFAULT 0 NOT NULL,
	"shared_by" text,
	"shared_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "community_intel_feeds" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"feed_type" text NOT NULL,
	"source" text,
	"description" text,
	"enabled" boolean DEFAULT true,
	"last_sync_at" timestamp,
	"indicator_count" integer DEFAULT 0,
	"reliability" double precision DEFAULT 0,
	"config" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "community_intel_indicators" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"feed_id" text,
	"indicator_type" text NOT NULL,
	"value" text NOT NULL,
	"threat_type" text,
	"confidence" double precision DEFAULT 0,
	"severity" text DEFAULT 'medium',
	"tags" jsonb DEFAULT '[]'::jsonb,
	"first_seen_at" timestamp DEFAULT now(),
	"last_seen_at" timestamp DEFAULT now(),
	"expires_at" timestamp,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "community_threat_campaigns" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"campaign_name" text NOT NULL,
	"threat_actor_name" text,
	"description" text,
	"mitre_attack_ids" jsonb DEFAULT '[]'::jsonb,
	"target_sectors" jsonb DEFAULT '[]'::jsonb,
	"ioc_ids" jsonb DEFAULT '[]'::jsonb,
	"ioc_count" integer DEFAULT 0 NOT NULL,
	"affected_org_count" integer DEFAULT 0 NOT NULL,
	"first_seen_at" timestamp DEFAULT now() NOT NULL,
	"last_seen_at" timestamp DEFAULT now() NOT NULL,
	"status" text DEFAULT 'active' NOT NULL,
	"severity" text DEFAULT 'high' NOT NULL,
	"tlp_level" text DEFAULT 'amber' NOT NULL,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "compliance_control_helpers" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"helper_type" text NOT NULL,
	"source_framework" text,
	"target_framework" text,
	"result" jsonb DEFAULT '{}'::jsonb,
	"status" text DEFAULT 'pending' NOT NULL,
	"created_by" text,
	"created_at" timestamp DEFAULT now(),
	"completed_at" timestamp
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
CREATE TABLE "compliance_gap_assessments" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"framework_id" text NOT NULL,
	"framework_name" text,
	"control_id" text NOT NULL,
	"control_name" text,
	"category" text,
	"status" text DEFAULT 'missing' NOT NULL,
	"evidence" jsonb DEFAULT '[]'::jsonb,
	"remediation_priority" text DEFAULT 'medium',
	"estimated_effort" text,
	"description" text,
	"assessed_by" text,
	"assessed_at" timestamp DEFAULT now(),
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
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
CREATE TABLE "connector_job_runs_archive" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"connector_id" varchar NOT NULL,
	"org_id" varchar,
	"status" text DEFAULT 'running' NOT NULL,
	"attempt" integer DEFAULT 1 NOT NULL,
	"alerts_received" integer DEFAULT 0,
	"alerts_created" integer DEFAULT 0,
	"alerts_deduped" integer DEFAULT 0,
	"alerts_failed" integer DEFAULT 0,
	"latency_ms" integer,
	"error_message" text,
	"started_at" timestamp,
	"completed_at" timestamp,
	"archived_at" timestamp DEFAULT now(),
	"archive_reason" text DEFAULT 'retention'
);
--> statement-breakpoint
CREATE TABLE "connector_provider_state" (
	"provider" varchar PRIMARY KEY NOT NULL,
	"active_count" integer DEFAULT 0 NOT NULL,
	"max_concurrency" integer DEFAULT 3 NOT NULL,
	"backoff_until" timestamp,
	"backoff_factor" integer DEFAULT 1 NOT NULL,
	"updated_at" timestamp DEFAULT now()
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
CREATE TABLE "consent_records" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"data_subject_id" text NOT NULL,
	"data_subject_email" text,
	"purpose" text NOT NULL,
	"granted" boolean DEFAULT false NOT NULL,
	"source" text DEFAULT 'manual' NOT NULL,
	"external_consent_id" text,
	"legal_basis" text,
	"jurisdiction" text,
	"consent_version" text,
	"granted_at" timestamp,
	"withdrawn_at" timestamp,
	"expires_at" timestamp,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "control_effectiveness" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"control_name" text NOT NULL,
	"control_type" text NOT NULL,
	"total_tests" integer DEFAULT 0 NOT NULL,
	"passed_tests" integer DEFAULT 0 NOT NULL,
	"failed_tests" integer DEFAULT 0 NOT NULL,
	"effectiveness_score" integer DEFAULT 0 NOT NULL,
	"last_tested_at" timestamp,
	"mitre_ids" text[],
	"status" text DEFAULT 'untested' NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "copilot_actions" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"triage_id" text,
	"action_class" text DEFAULT 'SUGGEST' NOT NULL,
	"action_type" text NOT NULL,
	"description" text,
	"target" text,
	"parameters" jsonb DEFAULT '{}'::jsonb,
	"status" text DEFAULT 'pending_approval' NOT NULL,
	"approved_by" text,
	"approved_at" timestamp,
	"executed_at" timestamp,
	"result" jsonb,
	"rollback_info" jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "copilot_feedback" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"domain" text NOT NULL,
	"reference_id" text,
	"outcome" text NOT NULL,
	"analyst_id" text,
	"comment" text,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "copilot_hypotheses" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"incident_id" text,
	"hypothesis" text NOT NULL,
	"confidence" text DEFAULT 'medium' NOT NULL,
	"status" text DEFAULT 'active' NOT NULL,
	"supporting_evidence" jsonb DEFAULT '[]'::jsonb,
	"contradicting_evidence" jsonb DEFAULT '[]'::jsonb,
	"suggested_investigations" jsonb DEFAULT '[]'::jsonb,
	"analyst_verdict" text,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "copilot_triages" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"alert_id" text,
	"alert_title" text,
	"severity" text DEFAULT 'medium' NOT NULL,
	"verdict" text DEFAULT 'needs_investigation' NOT NULL,
	"confidence" double precision DEFAULT 0,
	"reasoning" text,
	"suggested_actions" jsonb DEFAULT '[]'::jsonb,
	"context_summary" text,
	"related_alerts" jsonb DEFAULT '[]'::jsonb,
	"analyst_notes" text,
	"status" text DEFAULT 'pending' NOT NULL,
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
CREATE TABLE "cross_border_flow_audit" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"source_region" text NOT NULL,
	"destination_region" text NOT NULL,
	"data_type" text NOT NULL,
	"action" text NOT NULL,
	"rule_id" varchar,
	"blocked" boolean DEFAULT false NOT NULL,
	"user_id" varchar,
	"ip_address" text,
	"user_agent" text,
	"details" jsonb,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "cross_border_flow_rules" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"source_region" text NOT NULL,
	"destination_region" text NOT NULL,
	"action" text DEFAULT 'block' NOT NULL,
	"data_classification" text DEFAULT 'all',
	"requires_approval" boolean DEFAULT true NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"justification" text,
	"approved_by" varchar,
	"approved_at" timestamp,
	"created_by" varchar,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "cross_border_transfer_alerts" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"data_flow_id" uuid,
	"source_jurisdiction" text NOT NULL,
	"destination_jurisdiction" text NOT NULL,
	"data_categories" jsonb DEFAULT '[]'::jsonb,
	"risk_level" text DEFAULT 'medium' NOT NULL,
	"alert_reason" text NOT NULL,
	"legal_mechanism" text,
	"requires_action" boolean DEFAULT true NOT NULL,
	"resolved_at" timestamp,
	"resolved_by" text,
	"resolution_notes" text,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "cross_cutting_drift" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"drift_type" text NOT NULL,
	"source_module" text NOT NULL,
	"resource_id" text,
	"resource_type" text,
	"expected_state" jsonb,
	"actual_state" jsonb,
	"severity" text DEFAULT 'medium',
	"status" text DEFAULT 'detected' NOT NULL,
	"remediation_action" text,
	"detected_at" timestamp DEFAULT now(),
	"remediated_at" timestamp,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "cross_cutting_evidence" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"evidence_type" text NOT NULL,
	"source_module" text NOT NULL,
	"resource_id" text,
	"resource_type" text,
	"title" text NOT NULL,
	"description" text,
	"severity" text DEFAULT 'info',
	"status" text DEFAULT 'open' NOT NULL,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"detected_at" timestamp DEFAULT now(),
	"resolved_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "cross_cutting_kill_switches" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"feature_name" text NOT NULL,
	"engine_name" text NOT NULL,
	"state" varchar(20) DEFAULT 'armed' NOT NULL,
	"confidence_threshold" integer DEFAULT 70 NOT NULL,
	"current_confidence" integer DEFAULT 100 NOT NULL,
	"last_triggered_at" timestamp,
	"triggered_by" text,
	"trigger_reason" text,
	"rollback_instructions" text DEFAULT '' NOT NULL,
	"updated_at" timestamp DEFAULT now(),
	"updated_by" text DEFAULT 'system' NOT NULL
);
--> statement-breakpoint
CREATE TABLE "cross_cutting_overrides" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"override_type" text NOT NULL,
	"target_module" text NOT NULL,
	"target_resource_id" text,
	"target_resource_type" text,
	"reason" text NOT NULL,
	"approved_by" text,
	"expires_at" timestamp,
	"status" text DEFAULT 'active' NOT NULL,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "crypto_inventory" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"asset_name" text NOT NULL,
	"algorithm" text NOT NULL,
	"key_length" integer,
	"source" text NOT NULL,
	"hostname" text,
	"port" integer,
	"service_name" text,
	"file_path" text,
	"expires_at" timestamp,
	"is_quantum_vulnerable" boolean DEFAULT false NOT NULL,
	"quantum_risk_level" text DEFAULT 'medium' NOT NULL,
	"is_hardcoded" boolean DEFAULT false NOT NULL,
	"can_be_upgraded" boolean DEFAULT true NOT NULL,
	"pqc_replacement" text,
	"migration_status" text DEFAULT 'not_started' NOT NULL,
	"migration_priority" integer DEFAULT 50 NOT NULL,
	"migration_notes" text,
	"last_scanned_at" timestamp,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
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
CREATE TABLE "cspm_attack_paths" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"name" text NOT NULL,
	"description" text NOT NULL,
	"severity" text NOT NULL,
	"risk_score" integer DEFAULT 0,
	"nodes" jsonb DEFAULT '[]'::jsonb,
	"edges" jsonb DEFAULT '[]'::jsonb,
	"mitigations" text[] DEFAULT ARRAY[]::text[],
	"is_cross_cloud" boolean DEFAULT false,
	"status" text DEFAULT 'active',
	"detected_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "cspm_drift_baselines" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"account_id" varchar NOT NULL,
	"resource_id" text NOT NULL,
	"resource_type" text NOT NULL,
	"region" text,
	"approved_config" jsonb DEFAULT '{}'::jsonb,
	"snapshot_at" timestamp DEFAULT now(),
	"created_by" text
);
--> statement-breakpoint
CREATE TABLE "cspm_drift_events" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"account_id" varchar NOT NULL,
	"resource_id" text NOT NULL,
	"resource_type" text NOT NULL,
	"region" text,
	"drift_type" text NOT NULL,
	"field" text NOT NULL,
	"baseline_value" jsonb,
	"current_value" jsonb,
	"severity" text NOT NULL,
	"description" text NOT NULL,
	"status" text DEFAULT 'open',
	"detected_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "cspm_dspm_findings" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"account_id" varchar NOT NULL,
	"resource_id" text NOT NULL,
	"resource_type" text NOT NULL,
	"region" text,
	"data_classification" text NOT NULL,
	"sensitivity_level" text NOT NULL,
	"data_categories" text[] DEFAULT ARRAY[]::text[],
	"object_count" integer DEFAULT 0,
	"sample_objects" text[] DEFAULT ARRAY[]::text[],
	"description" text NOT NULL,
	"remediation" text,
	"status" text DEFAULT 'open',
	"detected_at" timestamp DEFAULT now()
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
CREATE TABLE "cspm_remediation_safety_records" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"account_id" text NOT NULL,
	"finding_id" text,
	"playbook_id" text NOT NULL,
	"resource_id" text NOT NULL,
	"mode" text DEFAULT 'dry_run' NOT NULL,
	"dry_run_result" jsonb DEFAULT '{}'::jsonb,
	"approved_by" text,
	"approved_at" timestamp,
	"executed_at" timestamp,
	"rollback_available" boolean DEFAULT true,
	"rollback_executed_at" timestamp,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "cspm_remediations" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"account_id" varchar NOT NULL,
	"finding_id" varchar,
	"playbook_id" text NOT NULL,
	"playbook_name" text NOT NULL,
	"resource_id" text NOT NULL,
	"rule_id" text NOT NULL,
	"status" text NOT NULL,
	"actions_executed" integer DEFAULT 0,
	"actions_total" integer DEFAULT 0,
	"error" text,
	"details" jsonb DEFAULT '{}'::jsonb,
	"requested_by" text,
	"approved_by" text,
	"executed_at" timestamp DEFAULT now()
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
CREATE TABLE "cve_entries" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"cve_id" text NOT NULL,
	"description" text NOT NULL,
	"severity" text DEFAULT 'medium' NOT NULL,
	"cvss_score" double precision DEFAULT 0,
	"published_date" timestamp,
	"modified_date" timestamp,
	"affected_products" jsonb DEFAULT '[]'::jsonb,
	"references" jsonb DEFAULT '[]'::jsonb,
	"cwe_ids" jsonb DEFAULT '[]'::jsonb,
	"exploit_available" boolean DEFAULT false,
	"source" text DEFAULT 'NVD',
	"created_at" timestamp DEFAULT now(),
	CONSTRAINT "cve_entries_cve_id_unique" UNIQUE("cve_id")
);
--> statement-breakpoint
CREATE TABLE "dark_web_exposures" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"target_id" uuid,
	"exposure_type" text NOT NULL,
	"severity" text DEFAULT 'medium' NOT NULL,
	"status" text DEFAULT 'new' NOT NULL,
	"title" text NOT NULL,
	"description" text,
	"source_type" text NOT NULL,
	"source_name" text,
	"source_url" text,
	"breach_date" timestamp,
	"discovered_at" timestamp DEFAULT now() NOT NULL,
	"affected_data" jsonb DEFAULT '[]'::jsonb,
	"affected_count" integer,
	"raw_data" jsonb,
	"matched_value" text,
	"confidence_score" integer DEFAULT 70,
	"mitigation_notes" text,
	"assigned_to" uuid,
	"resolved_at" timestamp,
	"resolved_by" uuid,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "dark_web_monitoring_config" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"is_enabled" boolean DEFAULT true NOT NULL,
	"scan_frequency_hours" integer DEFAULT 24 NOT NULL,
	"auto_create_alerts" boolean DEFAULT true NOT NULL,
	"alert_severity_threshold" text DEFAULT 'medium' NOT NULL,
	"notify_on_new_exposure" boolean DEFAULT true NOT NULL,
	"hibp_api_key" text,
	"dehashed_api_key" text,
	"last_full_scan_at" timestamp,
	"total_exposures_found" integer DEFAULT 0 NOT NULL,
	"total_exposures_resolved" integer DEFAULT 0 NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "dark_web_scan_history" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"scan_type" text NOT NULL,
	"status" text DEFAULT 'running' NOT NULL,
	"targets_scanned" integer DEFAULT 0 NOT NULL,
	"new_exposures_found" integer DEFAULT 0 NOT NULL,
	"sources_checked" jsonb DEFAULT '[]'::jsonb,
	"error_message" text,
	"started_at" timestamp DEFAULT now() NOT NULL,
	"completed_at" timestamp,
	"duration_ms" integer
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
CREATE TABLE "data_assets" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"asset_type" text NOT NULL,
	"connection_string" text,
	"hostname" text,
	"database" text,
	"schema" text,
	"table_name" text,
	"bucket_name" text,
	"file_path" text,
	"classification" text DEFAULT 'internal' NOT NULL,
	"pii_categories" jsonb DEFAULT '[]'::jsonb,
	"record_count" integer,
	"data_subject_count" integer,
	"jurisdiction" text DEFAULT 'OTHER' NOT NULL,
	"retention_days" integer,
	"is_encrypted" boolean DEFAULT false NOT NULL,
	"encryption_method" text,
	"data_owner" text,
	"data_processor" text,
	"legal_basis" text,
	"last_scanned_at" timestamp,
	"scan_findings" jsonb DEFAULT '{}'::jsonb,
	"minimization_recommendations" jsonb DEFAULT '[]'::jsonb,
	"risk_score" integer DEFAULT 0 NOT NULL,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "data_flows" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"source_asset_id" uuid,
	"source_name" text NOT NULL,
	"source_jurisdiction" text DEFAULT 'OTHER' NOT NULL,
	"destination_asset_id" uuid,
	"destination_name" text NOT NULL,
	"destination_jurisdiction" text DEFAULT 'OTHER' NOT NULL,
	"data_categories" jsonb DEFAULT '[]'::jsonb,
	"pii_categories" jsonb DEFAULT '[]'::jsonb,
	"purpose" text,
	"legal_basis" text,
	"processor_name" text,
	"is_cross_border" boolean DEFAULT false NOT NULL,
	"cross_border_mechanism" text,
	"transfer_risk_level" text,
	"status" text DEFAULT 'active' NOT NULL,
	"volume_per_day" integer,
	"frequency" text,
	"encryption_in_transit" boolean DEFAULT false NOT NULL,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "data_lake_queries" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"query_text" text NOT NULL,
	"query_type" text DEFAULT 'federated' NOT NULL,
	"data_types" jsonb DEFAULT '[]'::jsonb,
	"date_range_start" timestamp,
	"date_range_end" timestamp,
	"status" text DEFAULT 'pending' NOT NULL,
	"hot_result_count" integer DEFAULT 0,
	"cold_result_count" integer DEFAULT 0,
	"total_result_count" integer DEFAULT 0,
	"execution_time_ms" integer,
	"result_s3_key" text,
	"error_message" text,
	"executed_by" text,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"completed_at" timestamp
);
--> statement-breakpoint
CREATE TABLE "data_lake_retention_policies" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"name" text NOT NULL,
	"data_type" text NOT NULL,
	"compliance_framework" text DEFAULT 'custom' NOT NULL,
	"hot_retention_days" integer DEFAULT 90 NOT NULL,
	"warm_retention_days" integer DEFAULT 365 NOT NULL,
	"cold_retention_days" integer DEFAULT 2555 NOT NULL,
	"purge_after_days" integer,
	"compression_format" text DEFAULT 'parquet' NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"priority" integer DEFAULT 0 NOT NULL,
	"filter_criteria" jsonb DEFAULT '{}'::jsonb,
	"created_by" text,
	"updated_by" text,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "deception_assets" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"asset_type" text NOT NULL,
	"decoy_type" text,
	"network" text,
	"ip_address" text,
	"status" text DEFAULT 'active' NOT NULL,
	"interactions" integer DEFAULT 0,
	"last_interaction_at" timestamp,
	"config" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "deception_hits" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"canary_token_id" varchar,
	"honeypot_asset_id" varchar,
	"source_ip" text,
	"source_hostname" text,
	"source_user_agent" text,
	"source_geo_country" text,
	"source_geo_city" text,
	"source_asn" text,
	"attributed_user_id" text,
	"attributed_username" text,
	"attributed_service" text,
	"severity" text DEFAULT 'critical' NOT NULL,
	"is_internal" boolean DEFAULT false,
	"is_tor_exit" boolean DEFAULT false,
	"is_known_bad" boolean DEFAULT false,
	"alert_id" varchar,
	"incident_id" varchar,
	"auto_contained" boolean DEFAULT false,
	"containment_action" text,
	"raw_request" jsonb,
	"http_method" text,
	"http_path" text,
	"accessed_credential" text,
	"hit_at" timestamp DEFAULT now(),
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "deception_interactions" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"asset_id" text NOT NULL,
	"source_ip" text,
	"source_hostname" text,
	"interaction_type" text NOT NULL,
	"protocol" text,
	"details" jsonb DEFAULT '{}'::jsonb,
	"severity" text DEFAULT 'medium',
	"attack_stage" text,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "dependency_graph" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"sbom_id" varchar NOT NULL,
	"package_name" text NOT NULL,
	"package_version" text,
	"ecosystem" text NOT NULL,
	"is_direct" boolean DEFAULT true NOT NULL,
	"parent_package_id" varchar,
	"license" text,
	"publisher" text,
	"publisher_email" text,
	"repository_url" text,
	"latest_version" text,
	"is_outdated" boolean DEFAULT false,
	"is_vulnerable" boolean DEFAULT false,
	"cve_count" integer DEFAULT 0 NOT NULL,
	"maintainer_score" real,
	"maintainer_new_publisher" boolean DEFAULT false,
	"maintainer_recent_transfer" boolean DEFAULT false,
	"maintainer_low_downloads" boolean DEFAULT false,
	"provenance_verified" boolean,
	"provenance_signature" text,
	"typosquat_candidate" boolean DEFAULT false,
	"typosquat_similar_to" text,
	"typosquat_distance" integer,
	"depth" integer DEFAULT 0 NOT NULL,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "detection_alerts" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"rule_id" varchar NOT NULL,
	"sensor_id" varchar NOT NULL,
	"event_id" varchar,
	"severity" text NOT NULL,
	"title" text NOT NULL,
	"description" text,
	"mitre_tactic" text,
	"mitre_technique" text,
	"matched_fields" jsonb,
	"raw_event" jsonb,
	"linked_alert_id" varchar,
	"status" text DEFAULT 'new' NOT NULL,
	"acknowledged_by" varchar,
	"acknowledged_at" timestamp,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "detection_gaps" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"mitre_id" text NOT NULL,
	"mitre_tactic" text NOT NULL,
	"mitre_technique" text NOT NULL,
	"coverage_status" text DEFAULT 'no_coverage' NOT NULL,
	"detection_rule_count" integer DEFAULT 0 NOT NULL,
	"last_simulated_at" timestamp,
	"recommendation" text,
	"priority" text DEFAULT 'medium' NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "detection_rules" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"name" text NOT NULL,
	"description" text,
	"severity" text DEFAULT 'medium' NOT NULL,
	"status" text DEFAULT 'enabled' NOT NULL,
	"mitre_tactic" text,
	"mitre_technique" text,
	"mitre_subtechnique" text,
	"event_types" text[] DEFAULT ARRAY[]::text[],
	"condition_tree" jsonb NOT NULL,
	"author" text,
	"tags" text[] DEFAULT ARRAY[]::text[],
	"false_positive_notes" text,
	"references" text[] DEFAULT ARRAY[]::text[],
	"is_builtin" boolean DEFAULT false,
	"match_count" integer DEFAULT 0 NOT NULL,
	"last_match_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "device_posture_checks" (
	"id" varchar(36) PRIMARY KEY NOT NULL,
	"org_id" varchar(36) NOT NULL,
	"device_id" varchar(36) NOT NULL,
	"check_type" text NOT NULL,
	"check_name" text NOT NULL,
	"passed" boolean NOT NULL,
	"details" text,
	"severity" text DEFAULT 'medium' NOT NULL,
	"remediation_hint" text,
	"checked_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "dns_events" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"event_type" text NOT NULL,
	"query_name" text NOT NULL,
	"query_type" text DEFAULT 'A',
	"response_code" text,
	"response_data" text,
	"source_ip" text,
	"source_hostname" text,
	"destination_ip" text,
	"server_ip" text,
	"query_size" integer,
	"response_size" integer,
	"entropy" double precision,
	"is_suspicious" boolean DEFAULT false,
	"finding_id" varchar,
	"raw_data" jsonb,
	"timestamp" timestamp DEFAULT now(),
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "dns_findings" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"finding_type" text NOT NULL,
	"severity" text DEFAULT 'medium' NOT NULL,
	"domain" text NOT NULL,
	"description" text,
	"confidence" double precision,
	"source_ip" text,
	"source_hostname" text,
	"indicators" jsonb,
	"mitre_technique" text,
	"status" text DEFAULT 'open' NOT NULL,
	"analyst_notes" text,
	"resolved_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "dns_security_events" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"query_domain" text NOT NULL,
	"query_type" text,
	"source_ip" text,
	"verdict" text DEFAULT 'allowed' NOT NULL,
	"threat_category" text,
	"blocked" boolean DEFAULT false,
	"policy_id" text,
	"details" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "dns_security_policies" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"action" text DEFAULT 'block' NOT NULL,
	"categories" jsonb DEFAULT '[]'::jsonb,
	"custom_domains" jsonb DEFAULT '[]'::jsonb,
	"enabled" boolean DEFAULT true,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "dr_drill_results" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"runbook_id" varchar,
	"org_id" varchar,
	"dry_run" boolean DEFAULT true,
	"status" text DEFAULT 'pending' NOT NULL,
	"triggered_by" text DEFAULT 'scheduler' NOT NULL,
	"rto_target_minutes" integer,
	"rpo_target_minutes" integer,
	"rto_actual_minutes" real,
	"rpo_actual_minutes" real,
	"rto_met" boolean,
	"rpo_met" boolean,
	"step_results" jsonb,
	"total_duration_ms" integer,
	"error_message" text,
	"notes" text,
	"started_at" timestamp DEFAULT now(),
	"completed_at" timestamp,
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
CREATE TABLE "dsar_fulfillment_tasks" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"dsar_request_id" varchar,
	"target_system" text NOT NULL,
	"target_asset_id" uuid,
	"task_type" text NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"records_affected" integer DEFAULT 0 NOT NULL,
	"error_message" text,
	"execution_log" jsonb DEFAULT '[]'::jsonb,
	"started_at" timestamp,
	"completed_at" timestamp,
	"created_at" timestamp DEFAULT now() NOT NULL
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
CREATE TABLE "ediscovery_exports" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"status" text DEFAULT 'requested' NOT NULL,
	"legal_hold_id" varchar,
	"data_types" jsonb DEFAULT '[]'::jsonb,
	"date_range_start" timestamp,
	"date_range_end" timestamp,
	"filter_criteria" jsonb DEFAULT '{}'::jsonb,
	"export_format" text DEFAULT 'json' NOT NULL,
	"include_metadata" boolean DEFAULT true NOT NULL,
	"include_chain_of_custody" boolean DEFAULT true NOT NULL,
	"total_records" integer DEFAULT 0,
	"export_size_bytes" bigint DEFAULT 0,
	"s3_key" text,
	"checksum_sha256" text,
	"download_count" integer DEFAULT 0,
	"expires_at" timestamp,
	"requested_by" text,
	"requested_by_name" text,
	"approved_by" text,
	"approved_at" timestamp,
	"completed_at" timestamp,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "email_findings" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"email_message_id" varchar,
	"finding_type" text NOT NULL,
	"severity" text DEFAULT 'medium' NOT NULL,
	"confidence" double precision,
	"title" text NOT NULL,
	"description" text,
	"sender_address" text,
	"recipient_address" text,
	"domain" text,
	"indicators" jsonb,
	"mitre_technique" text,
	"status" text DEFAULT 'open' NOT NULL,
	"analyst_notes" text,
	"action_taken" text,
	"resolved_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "email_messages" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"message_id" text,
	"internet_message_id" text,
	"subject" text,
	"sender_address" text NOT NULL,
	"sender_display_name" text,
	"recipient_addresses" jsonb,
	"cc_addresses" jsonb,
	"reply_to" text,
	"return_path" text,
	"received_at" timestamp DEFAULT now(),
	"direction" text DEFAULT 'inbound',
	"has_attachments" boolean DEFAULT false,
	"attachment_count" integer DEFAULT 0,
	"attachment_names" jsonb,
	"url_count" integer DEFAULT 0,
	"extracted_urls" jsonb,
	"spf_result" text,
	"dkim_result" text,
	"dmarc_result" text,
	"authentication_results" text,
	"sender_reputation" double precision,
	"thread_id" text,
	"in_reply_to" text,
	"email_references" jsonb,
	"headers" jsonb,
	"body_preview" text,
	"is_suspicious" boolean DEFAULT false,
	"source" text DEFAULT 'manual',
	"raw_data" jsonb,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "email_policies" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"policy_type" text NOT NULL,
	"action" text DEFAULT 'quarantine' NOT NULL,
	"conditions" jsonb,
	"enabled" boolean DEFAULT true NOT NULL,
	"priority" integer DEFAULT 0 NOT NULL,
	"match_count" integer DEFAULT 0 NOT NULL,
	"last_match_at" timestamp,
	"created_by" varchar,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "email_quarantine_items" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"email_message_id" varchar,
	"reason" text NOT NULL,
	"finding_id" varchar,
	"policy_id" varchar,
	"status" text DEFAULT 'quarantined' NOT NULL,
	"released_by" varchar,
	"released_at" timestamp,
	"expires_at" timestamp,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "email_security_events" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"direction" text DEFAULT 'inbound' NOT NULL,
	"sender" text,
	"recipient" text,
	"subject" text,
	"verdict" text DEFAULT 'clean' NOT NULL,
	"threat_type" text,
	"confidence" double precision DEFAULT 0,
	"quarantined" boolean DEFAULT false,
	"details" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "email_url_rewrites" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"original_url" text NOT NULL,
	"rewritten_url" text,
	"email_message_id" varchar,
	"click_count" integer DEFAULT 0 NOT NULL,
	"last_click_at" timestamp,
	"scan_result" text,
	"is_malicious" boolean DEFAULT false,
	"scan_details" jsonb,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "employee_risk_scores" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"email" text NOT NULL,
	"name" text,
	"department" text,
	"risk_score" real DEFAULT 50 NOT NULL,
	"phishing_click_rate" real DEFAULT 0 NOT NULL,
	"report_rate" real DEFAULT 0 NOT NULL,
	"training_completion_rate" real DEFAULT 0 NOT NULL,
	"campaigns_received" integer DEFAULT 0 NOT NULL,
	"campaigns_clicked" integer DEFAULT 0 NOT NULL,
	"campaigns_reported" integer DEFAULT 0 NOT NULL,
	"trainings_completed" integer DEFAULT 0 NOT NULL,
	"trainings_assigned" integer DEFAULT 0 NOT NULL,
	"last_phishing_test_at" timestamp,
	"last_training_completed_at" timestamp,
	"risk_trend" text DEFAULT 'stable' NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
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
CREATE TABLE "endpoint_groups" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"group_by" text NOT NULL,
	"criteria" jsonb DEFAULT '{}'::jsonb,
	"policies" jsonb DEFAULT '[]'::jsonb,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "endpoint_heartbeats" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"asset_id" text NOT NULL,
	"last_heartbeat" timestamp DEFAULT now(),
	"status" text DEFAULT 'online' NOT NULL,
	"metadata" jsonb DEFAULT '{}'::jsonb
);
--> statement-breakpoint
CREATE TABLE "endpoint_scan_schedules" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"asset_id" text NOT NULL,
	"scan_type" text NOT NULL,
	"cron_expression" text,
	"enabled" boolean DEFAULT true,
	"last_run_at" timestamp,
	"next_run_at" timestamp,
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
CREATE TABLE "endpoint_telemetry_archive" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"asset_id" varchar NOT NULL,
	"metric_type" text NOT NULL,
	"metric_value" jsonb NOT NULL,
	"collected_at" timestamp,
	"archived_at" timestamp DEFAULT now(),
	"archive_reason" text DEFAULT 'retention'
);
--> statement-breakpoint
CREATE TABLE "engine_configs" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"engine_name" text NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"dry_run_mode" boolean DEFAULT false NOT NULL,
	"policy_config" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"last_dry_run_at" timestamp,
	"last_dry_run_result" jsonb,
	"updated_by" varchar,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "engine_dry_runs" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"engine_name" text NOT NULL,
	"input_params" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"simulated_result" jsonb,
	"status" text DEFAULT 'pending' NOT NULL,
	"duration_ms" integer,
	"executed_by" varchar,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "engine_explainability_logs" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"engine_name" text NOT NULL,
	"execution_id" varchar,
	"decision_type" text NOT NULL,
	"decision_outcome" text NOT NULL,
	"drivers" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"confidence" integer,
	"input_snapshot" jsonb,
	"created_at" timestamp DEFAULT now()
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
CREATE TABLE "entity_merge_history" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"target_entity_id" varchar NOT NULL,
	"source_entity_id" varchar NOT NULL,
	"source_entity_snapshot" jsonb NOT NULL,
	"target_entity_snapshot" jsonb NOT NULL,
	"moved_alert_ids" text[],
	"moved_alias_ids" text[],
	"merged_by" varchar,
	"undone" boolean DEFAULT false,
	"undone_at" timestamp,
	"undone_by" varchar,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "evidence_attachments" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"control_mapping_id" varchar,
	"evidence_locker_id" varchar,
	"file_name" text NOT NULL,
	"mime_type" text,
	"file_size" integer,
	"s3_bucket" text,
	"s3_key" text,
	"checksum" text,
	"status" text DEFAULT 'pending_upload' NOT NULL,
	"reviewed_by" text,
	"reviewed_at" timestamp,
	"review_notes" text,
	"expires_at" timestamp,
	"uploaded_by" text,
	"uploaded_by_name" text,
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
CREATE TABLE "executive_metrics" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"category" text DEFAULT 'action' NOT NULL,
	"value" double precision DEFAULT 0 NOT NULL,
	"unit" text DEFAULT 'count' NOT NULL,
	"trend" text DEFAULT 'stable' NOT NULL,
	"change_percent" double precision DEFAULT 0,
	"target" double precision,
	"target_met" boolean DEFAULT false,
	"sparkline" jsonb DEFAULT '[]'::jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
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
CREATE TABLE "finding_lineage_records" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"title" text NOT NULL,
	"description" text,
	"severity" text DEFAULT 'medium' NOT NULL,
	"source" text NOT NULL,
	"status" text DEFAULT 'open' NOT NULL,
	"risk_score" double precision DEFAULT 0,
	"cwe_id" text,
	"cve_id" text,
	"source_location" jsonb DEFAULT '{}'::jsonb,
	"deployed_asset" jsonb DEFAULT '{}'::jsonb,
	"owner" jsonb DEFAULT '{}'::jsonb,
	"evidence" jsonb DEFAULT '[]'::jsonb,
	"remediations" jsonb DEFAULT '[]'::jsonb,
	"lineage" jsonb DEFAULT '[]'::jsonb,
	"first_detected_at" timestamp DEFAULT now(),
	"last_seen_at" timestamp DEFAULT now(),
	"resolved_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
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
CREATE TABLE "graph_snapshots" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"graph_data" jsonb DEFAULT '{}'::jsonb,
	"node_count" integer DEFAULT 0,
	"edge_count" integer DEFAULT 0,
	"created_by" text,
	"created_at" timestamp DEFAULT now()
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
CREATE TABLE "honeypot_assets" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"asset_type" text NOT NULL,
	"fake_username" text,
	"fake_email" text,
	"fake_domain" text,
	"listen_address" text,
	"protocol" text,
	"share_path" text,
	"decoy_files" jsonb,
	"decoy_hostname" text,
	"decoy_ip" text,
	"open_ports" jsonb,
	"configuration" jsonb,
	"is_active" boolean DEFAULT true NOT NULL,
	"hit_count" integer DEFAULT 0 NOT NULL,
	"last_hit_at" timestamp,
	"created_by" varchar,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "hunt_cache" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"query_hash" text NOT NULL,
	"query_type" text NOT NULL,
	"query_text" text NOT NULL,
	"result_json" jsonb DEFAULT '{}'::jsonb,
	"event_count" integer DEFAULT 0 NOT NULL,
	"execution_duration_ms" integer,
	"ttl_seconds" integer DEFAULT 3600 NOT NULL,
	"hit_count" integer DEFAULT 0 NOT NULL,
	"cached_at" timestamp DEFAULT now() NOT NULL,
	"expires_at" timestamp NOT NULL
);
--> statement-breakpoint
CREATE TABLE "hunt_collaborations" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"hunt_id" uuid,
	"session_name" text NOT NULL,
	"participants" jsonb DEFAULT '[]'::jsonb,
	"shared_results" jsonb DEFAULT '[]'::jsonb,
	"chat_messages" jsonb DEFAULT '[]'::jsonb,
	"status" text DEFAULT 'active' NOT NULL,
	"started_at" timestamp DEFAULT now() NOT NULL,
	"ended_at" timestamp
);
--> statement-breakpoint
CREATE TABLE "hunt_library" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"hunt_id" uuid NOT NULL,
	"is_public" boolean DEFAULT false NOT NULL,
	"shared_by" text,
	"category" text,
	"difficulty" text,
	"rating" integer DEFAULT 0,
	"download_count" integer DEFAULT 0,
	"shared_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "hunt_notebooks" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"steps" jsonb DEFAULT '[]'::jsonb,
	"created_by" text,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "hunt_playbooks" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"threat_actor" text,
	"mitre_techniques" jsonb DEFAULT '[]'::jsonb,
	"steps" jsonb DEFAULT '[]'::jsonb,
	"difficulty" text DEFAULT 'intermediate',
	"estimated_time_min" integer,
	"datasources_required" jsonb DEFAULT '[]'::jsonb,
	"created_by" text,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "hunt_results" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"hunt_id" uuid NOT NULL,
	"event_count" integer DEFAULT 0 NOT NULL,
	"events_json" jsonb DEFAULT '[]'::jsonb,
	"summary" text,
	"false_positive_count" integer DEFAULT 0,
	"true_positive_count" integer DEFAULT 0,
	"execution_duration_ms" integer,
	"executed_at" timestamp DEFAULT now() NOT NULL,
	"executed_by" text,
	"linked_incident_id" varchar
);
--> statement-breakpoint
CREATE TABLE "hunt_schedule_drifts" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"schedule_id" uuid,
	"hunt_id" uuid,
	"previous_event_count" integer NOT NULL,
	"current_event_count" integer NOT NULL,
	"drift_percentage" integer NOT NULL,
	"drift_direction" text NOT NULL,
	"is_significant" boolean DEFAULT false NOT NULL,
	"detected_at" timestamp DEFAULT now() NOT NULL,
	"acknowledged" boolean DEFAULT false NOT NULL
);
--> statement-breakpoint
CREATE TABLE "hunt_schedules" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"hunt_id" uuid NOT NULL,
	"cadence" text NOT NULL,
	"day_of_week" integer,
	"hour_utc" integer DEFAULT 8 NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"next_run_at" timestamp,
	"last_run_at" timestamp,
	"created_at" timestamp DEFAULT now() NOT NULL
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
CREATE TABLE "identity_access_graph" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"source_user_id" varchar NOT NULL,
	"source_user_name" text NOT NULL,
	"target_system" text NOT NULL,
	"target_resource" text,
	"access_type" text NOT NULL,
	"permission_level" text NOT NULL,
	"granted_via" text,
	"is_active" boolean DEFAULT true NOT NULL,
	"last_used_at" timestamp,
	"expires_at" timestamp,
	"risk_weight" integer DEFAULT 1,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "identity_entitlements" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"user_id" text NOT NULL,
	"user_name" text,
	"resource_type" text NOT NULL,
	"resource_name" text NOT NULL,
	"access_level" text NOT NULL,
	"risk_level" text DEFAULT 'low',
	"last_used_at" timestamp,
	"granted_at" timestamp DEFAULT now(),
	"expires_at" timestamp,
	"status" text DEFAULT 'active' NOT NULL,
	"review_id" text,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "identity_risk_profiles" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"user_id" varchar NOT NULL,
	"user_name" text NOT NULL,
	"user_email" text,
	"risk_level" text DEFAULT 'low' NOT NULL,
	"risk_score" integer DEFAULT 0 NOT NULL,
	"is_stale" boolean DEFAULT false,
	"last_activity_at" timestamp,
	"days_since_activity" integer,
	"is_service_account" boolean DEFAULT false,
	"last_credential_rotation" timestamp,
	"credential_age_days" integer,
	"blast_radius_score" integer DEFAULT 0,
	"accessible_systems" integer DEFAULT 0,
	"accessible_secrets" integer DEFAULT 0,
	"privileged_roles" jsonb,
	"lateral_movement_paths" integer DEFAULT 0,
	"can_reach_critical" boolean DEFAULT false,
	"pivot_points" jsonb,
	"mfa_enabled" boolean DEFAULT false,
	"has_excessive_permissions" boolean DEFAULT false,
	"unused_permissions" jsonb,
	"anomalous_login_count" integer DEFAULT 0,
	"failed_login_count" integer DEFAULT 0,
	"last_assessed_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
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
	"needs_review" boolean DEFAULT false,
	"algorithm_scores" jsonb,
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
CREATE TABLE "industrial_protocol_events" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"asset_id" varchar,
	"protocol" text NOT NULL,
	"function_code" integer,
	"function_name" text,
	"source_ip" text,
	"dest_ip" text,
	"source_port" integer,
	"dest_port" integer,
	"register_address" integer,
	"register_count" integer,
	"write_value" text,
	"read_value" text,
	"unit_id" integer,
	"is_write" boolean DEFAULT false NOT NULL,
	"is_anomalous" boolean DEFAULT false NOT NULL,
	"anomaly_id" varchar,
	"raw_data" jsonb,
	"captured_at" timestamp DEFAULT now(),
	"created_at" timestamp DEFAULT now()
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
CREATE TABLE "ingestion_logs_archive" (
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
	"received_at" timestamp,
	"archived_at" timestamp DEFAULT now(),
	"archive_reason" text DEFAULT 'retention'
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
CREATE TABLE "investigation_chat_messages" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"incident_id" varchar NOT NULL,
	"thread_id" varchar NOT NULL,
	"role" text NOT NULL,
	"content" text NOT NULL,
	"metadata" jsonb,
	"created_at" timestamp DEFAULT now() NOT NULL
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
CREATE TABLE "invoices" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"subscription_id" varchar,
	"stripe_invoice_id" text,
	"amount_due_cents" integer DEFAULT 0 NOT NULL,
	"amount_paid_cents" integer DEFAULT 0 NOT NULL,
	"currency" text DEFAULT 'usd' NOT NULL,
	"status" text DEFAULT 'draft' NOT NULL,
	"pdf_url" text,
	"hosted_url" text,
	"period_start" timestamp,
	"period_end" timestamp,
	"paid_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	CONSTRAINT "invoices_stripe_invoice_id_unique" UNIQUE("stripe_invoice_id")
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
	"feed_id" varchar,
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
CREATE TABLE "jit_access_requests" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"requester_id" text NOT NULL,
	"requester_email" text,
	"secret_path" text NOT NULL,
	"secret_provider" text NOT NULL,
	"reason" text NOT NULL,
	"duration_minutes" integer DEFAULT 60 NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"approved_by" text,
	"approved_at" timestamp,
	"expires_at" timestamp,
	"revoked_at" timestamp,
	"accessed_at" timestamp,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "jit_audit_log" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"action" text NOT NULL,
	"actor" text NOT NULL,
	"details" text,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "jit_break_glass_access" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"secret_id" varchar NOT NULL,
	"secret_name" text NOT NULL,
	"requester_id" varchar NOT NULL,
	"requester_name" text NOT NULL,
	"justification" text NOT NULL,
	"incident_id" varchar,
	"status" varchar(20) DEFAULT 'active' NOT NULL,
	"ephemeral_token" text NOT NULL,
	"expires_at" timestamp NOT NULL,
	"duration_minutes" integer DEFAULT 60 NOT NULL,
	"reviewed_by" text,
	"reviewed_at" timestamp,
	"review_notes" text,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "jit_external_shares" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"secret_id" varchar NOT NULL,
	"secret_name" text NOT NULL,
	"created_by" text NOT NULL,
	"recipient_email" text NOT NULL,
	"share_token" text NOT NULL,
	"expires_at" timestamp NOT NULL,
	"max_uses" integer DEFAULT 1 NOT NULL,
	"current_uses" integer DEFAULT 0 NOT NULL,
	"status" varchar(20) DEFAULT 'active' NOT NULL,
	"no_plaintext" boolean DEFAULT true NOT NULL,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "jit_managed_secrets" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"secret_type" varchar(30) NOT NULL,
	"classification" varchar(20) DEFAULT 'internal' NOT NULL,
	"owner_id" varchar NOT NULL,
	"owner_name" text NOT NULL,
	"environment" varchar(30) DEFAULT 'production' NOT NULL,
	"service" text DEFAULT '' NOT NULL,
	"last_rotated_at" timestamp DEFAULT now(),
	"rotation_interval_days" integer DEFAULT 90 NOT NULL,
	"needs_rotation" boolean DEFAULT false NOT NULL,
	"no_plaintext_sharing" boolean DEFAULT true NOT NULL,
	"access_count" integer DEFAULT 0 NOT NULL,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "jit_ownership_transfers" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"secret_id" varchar NOT NULL,
	"secret_name" text NOT NULL,
	"from_owner_id" varchar NOT NULL,
	"from_owner_name" text NOT NULL,
	"to_owner_id" varchar NOT NULL,
	"to_owner_name" text NOT NULL,
	"action" varchar(30) NOT NULL,
	"reason" text NOT NULL,
	"is_offboarding" boolean DEFAULT false NOT NULL,
	"initiated_by" text NOT NULL,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "jit_secret_access_requests" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"secret_id" varchar NOT NULL,
	"secret_name" text NOT NULL,
	"requester_id" varchar NOT NULL,
	"requester_name" text NOT NULL,
	"reason" text NOT NULL,
	"duration_minutes" integer DEFAULT 60 NOT NULL,
	"status" varchar(20) DEFAULT 'pending' NOT NULL,
	"approver_role" varchar(20) DEFAULT 'owner' NOT NULL,
	"approved_by" text,
	"approved_at" timestamp,
	"denied_by" text,
	"denied_at" timestamp,
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
CREATE TABLE "log_sources" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"sensor_id" varchar,
	"name" text NOT NULL,
	"description" text,
	"source_type" text NOT NULL,
	"status" text DEFAULT 'configuring' NOT NULL,
	"listen_address" text,
	"listen_port" integer,
	"protocol" text,
	"format" text DEFAULT 'raw',
	"syslog_facility" text,
	"syslog_severity" text,
	"win_event_channels" text[] DEFAULT ARRAY[]::text[],
	"win_event_levels" text[] DEFAULT ARRAY[]::text[],
	"cloudwatch_region" text,
	"cloudwatch_log_group" text,
	"cloudwatch_filter_pattern" text,
	"http_endpoint" text,
	"http_auth_token" text,
	"journald_units" text[] DEFAULT ARRAY[]::text[],
	"journald_priority" text,
	"parser_regex" text,
	"field_mappings" jsonb,
	"tags" text[] DEFAULT ARRAY[]::text[],
	"filter_include" text,
	"filter_exclude" text,
	"events_received" bigint DEFAULT 0 NOT NULL,
	"events_dropped" bigint DEFAULT 0 NOT NULL,
	"bytes_received" bigint DEFAULT 0 NOT NULL,
	"last_event_at" timestamp,
	"last_error" text,
	"last_error_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "marketplace_dead_letters" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"instance_id" varchar NOT NULL,
	"event_type" text NOT NULL,
	"payload" jsonb DEFAULT '{}'::jsonb,
	"error_message" text,
	"retry_count" integer DEFAULT 0,
	"status" text DEFAULT 'pending' NOT NULL,
	"original_received_at" timestamp,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "marketplace_instances" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"connector_slug" text NOT NULL,
	"auth_method" text NOT NULL,
	"sync_direction" text DEFAULT 'inbound' NOT NULL,
	"permission_mode" text DEFAULT 'read_only' NOT NULL,
	"config" jsonb DEFAULT '{}'::jsonb,
	"sync_interval_minutes" integer DEFAULT 15,
	"status" text DEFAULT 'pending' NOT NULL,
	"last_sync_at" timestamp,
	"last_sync_status" text,
	"last_sync_error" text,
	"events_ingested" integer DEFAULT 0,
	"field_mappings" jsonb DEFAULT '[]'::jsonb,
	"health_score" integer DEFAULT 100,
	"installed_by" text,
	"installed_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "marketplace_sync_history" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"instance_id" varchar NOT NULL,
	"sync_type" text DEFAULT 'scheduled' NOT NULL,
	"status" text DEFAULT 'running' NOT NULL,
	"events_ingested" integer DEFAULT 0,
	"error_message" text,
	"duration_ms" integer,
	"started_at" timestamp DEFAULT now(),
	"completed_at" timestamp
);
--> statement-breakpoint
CREATE TABLE "marketplace_webhook_events" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"instance_id" varchar NOT NULL,
	"event_type" text NOT NULL,
	"payload" jsonb DEFAULT '{}'::jsonb,
	"idempotency_key" text,
	"status" text DEFAULT 'received' NOT NULL,
	"processed_at" timestamp,
	"error_message" text,
	"received_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "mobile_devices" (
	"id" varchar(36) PRIMARY KEY NOT NULL,
	"org_id" varchar(36) NOT NULL,
	"user_id" varchar(36),
	"device_name" text NOT NULL,
	"platform" text NOT NULL,
	"os_version" text,
	"model" text,
	"manufacturer" text,
	"serial_number" text,
	"imei" text,
	"mac_address" text,
	"mdm_provider" text,
	"mdm_device_id" text,
	"mdm_enrolled_at" timestamp,
	"last_check_in" timestamp,
	"compliance_status" text DEFAULT 'unknown' NOT NULL,
	"risk_level" text DEFAULT 'low' NOT NULL,
	"risk_score" integer DEFAULT 0 NOT NULL,
	"is_encrypted" boolean DEFAULT false,
	"is_rooted" boolean DEFAULT false,
	"is_jailbroken" boolean DEFAULT false,
	"has_mdm" boolean DEFAULT false,
	"has_screen_lock" boolean DEFAULT false,
	"has_firewall" boolean DEFAULT false,
	"is_vpn_active" boolean DEFAULT false,
	"vpn_provider" text,
	"last_known_ip" text,
	"last_known_location" text,
	"last_known_country" text,
	"installed_apps" jsonb,
	"sideloaded_apps" jsonb,
	"certificates" jsonb,
	"tags" jsonb,
	"metadata" jsonb,
	"status" text DEFAULT 'active' NOT NULL,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "mobile_threats" (
	"id" varchar(36) PRIMARY KEY NOT NULL,
	"org_id" varchar(36) NOT NULL,
	"device_id" varchar(36) NOT NULL,
	"threat_type" text NOT NULL,
	"severity" text DEFAULT 'medium' NOT NULL,
	"title" text NOT NULL,
	"description" text,
	"app_name" text,
	"app_package" text,
	"network_ssid" text,
	"source_ip" text,
	"mitre_tactic" text,
	"mitre_technique" text,
	"status" text DEFAULT 'new' NOT NULL,
	"resolved_by" varchar(36),
	"resolved_at" timestamp,
	"alert_id" varchar(36),
	"metadata" jsonb,
	"detected_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "mssp_access_grants" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"parent_org_id" varchar NOT NULL,
	"child_org_id" varchar NOT NULL,
	"granted_role" text DEFAULT 'viewer' NOT NULL,
	"scope" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"granted_by" varchar NOT NULL,
	"granted_at" timestamp DEFAULT now(),
	"revoked_at" timestamp,
	"revoked_by" varchar,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "mssp_billing_records" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"parent_org_id" varchar NOT NULL,
	"child_org_id" varchar NOT NULL,
	"period_start" timestamp NOT NULL,
	"period_end" timestamp NOT NULL,
	"base_fee" integer DEFAULT 0 NOT NULL,
	"markup_percent" real DEFAULT 0 NOT NULL,
	"alerts_ingested" integer DEFAULT 0 NOT NULL,
	"alerts_cost" integer DEFAULT 0 NOT NULL,
	"ai_analyses" integer DEFAULT 0 NOT NULL,
	"ai_cost" integer DEFAULT 0 NOT NULL,
	"storage_gb" real DEFAULT 0 NOT NULL,
	"storage_cost" integer DEFAULT 0 NOT NULL,
	"user_count" integer DEFAULT 0 NOT NULL,
	"user_cost" integer DEFAULT 0 NOT NULL,
	"subtotal" integer DEFAULT 0 NOT NULL,
	"markup_amount" integer DEFAULT 0 NOT NULL,
	"total_amount" integer DEFAULT 0 NOT NULL,
	"currency" text DEFAULT 'USD' NOT NULL,
	"status" text DEFAULT 'draft' NOT NULL,
	"invoice_url" text,
	"paid_at" timestamp,
	"notes" text,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "mssp_client_onboarding" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"parent_org_id" varchar NOT NULL,
	"child_org_id" varchar NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"steps" jsonb DEFAULT '[{"key":"org_created","label":"Organization Created","done":true},{"key":"admin_invited","label":"Admin User Invited","done":false},{"key":"connectors_configured","label":"Connectors Configured","done":false},{"key":"sla_defined","label":"SLA Defined","done":false},{"key":"branding_applied","label":"Branding Applied","done":false},{"key":"go_live","label":"Go Live","done":false}]'::jsonb NOT NULL,
	"assigned_to" text,
	"target_go_live_date" timestamp,
	"actual_go_live_date" timestamp,
	"notes" text,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "mssp_client_slas" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"parent_org_id" varchar NOT NULL,
	"child_org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"priority" text DEFAULT 'medium' NOT NULL,
	"response_time_minutes" integer DEFAULT 60 NOT NULL,
	"resolution_time_minutes" integer DEFAULT 480 NOT NULL,
	"escalation_contact_email" text,
	"escalation_contact_phone" text,
	"auto_escalate_on_breach" boolean DEFAULT true NOT NULL,
	"business_hours_only" boolean DEFAULT false NOT NULL,
	"business_hours_start" text DEFAULT '09:00',
	"business_hours_end" text DEFAULT '17:00',
	"business_timezone" text DEFAULT 'UTC',
	"is_active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "mssp_sla_breaches" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"sla_id" varchar NOT NULL,
	"parent_org_id" varchar NOT NULL,
	"child_org_id" varchar NOT NULL,
	"incident_id" varchar,
	"alert_id" varchar,
	"breach_type" text DEFAULT 'response' NOT NULL,
	"target_minutes" integer NOT NULL,
	"actual_minutes" integer NOT NULL,
	"status" text DEFAULT 'breached' NOT NULL,
	"resolved_at" timestamp,
	"resolved_by" text,
	"notes" text,
	"notified_at" timestamp,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "mssp_white_label_configs" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"custom_logo_url" text,
	"custom_favicon_url" text,
	"primary_color" text DEFAULT '#0ea5e9',
	"secondary_color" text DEFAULT '#6366f1',
	"accent_color" text DEFAULT '#10b981',
	"custom_domain" text,
	"custom_app_name" text,
	"custom_support_email" text,
	"custom_support_url" text,
	"login_page_html" text,
	"email_header_html" text,
	"email_footer_html" text,
	"report_header_html" text,
	"report_footer_html" text,
	"hide_powered_by" boolean DEFAULT false NOT NULL,
	"custom_css" text,
	"is_active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "native_sensors" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"hostname" text NOT NULL,
	"platform" text NOT NULL,
	"os_version" text,
	"agent_version" text,
	"registration_token" text NOT NULL,
	"api_key" text,
	"status" text DEFAULT 'provisioning' NOT NULL,
	"ip_address" text,
	"mac_address" text,
	"tags" text[] DEFAULT ARRAY[]::text[],
	"last_heartbeat" timestamp,
	"cpu_usage" real,
	"memory_usage" real,
	"disk_usage" real,
	"events_ingested" integer DEFAULT 0 NOT NULL,
	"alerts_generated" integer DEFAULT 0 NOT NULL,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
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
CREATE TABLE "org_ai_budgets" (
	"org_id" varchar PRIMARY KEY NOT NULL,
	"budget_usd" double precision DEFAULT 50 NOT NULL,
	"invocation_cap" integer DEFAULT 5000 NOT NULL,
	"daily_spend_usd" double precision DEFAULT 0 NOT NULL,
	"daily_invocations" integer DEFAULT 0 NOT NULL,
	"daily_input_tokens" integer DEFAULT 0 NOT NULL,
	"daily_output_tokens" integer DEFAULT 0 NOT NULL,
	"last_reset_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
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
	"auto_join" boolean DEFAULT false NOT NULL,
	"default_role" text DEFAULT 'analyst' NOT NULL,
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
	"billing_email" text,
	"phone" text,
	"address" jsonb,
	"company_size" text,
	"logo_url" text,
	"primary_color" text,
	"max_users" integer DEFAULT 10,
	"locale" text DEFAULT 'en-US',
	"timezone" text DEFAULT 'UTC',
	"org_type" text DEFAULT 'standard' NOT NULL,
	"parent_org_id" varchar,
	"data_residency" text DEFAULT 'us-east-1',
	"data_region" text DEFAULT 'US',
	"sovereign_key_config" jsonb,
	"cross_border_flow_controls" jsonb,
	"default_member_role" text DEFAULT 'analyst' NOT NULL,
	"require_approval" boolean DEFAULT false NOT NULL,
	"deleted_at" timestamp,
	"updated_at" timestamp DEFAULT now(),
	"created_at" timestamp DEFAULT now(),
	CONSTRAINT "organizations_slug_unique" UNIQUE("slug")
);
--> statement-breakpoint
CREATE TABLE "ot_anomalies" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"asset_id" varchar,
	"connection_id" varchar,
	"anomaly_type" text NOT NULL,
	"severity" text DEFAULT 'high' NOT NULL,
	"title" text NOT NULL,
	"description" text,
	"protocol" text,
	"function_code" integer,
	"register_address" integer,
	"previous_value" text,
	"new_value" text,
	"source_ip" text,
	"dest_ip" text,
	"source_port" integer,
	"dest_port" integer,
	"ics_cert_advisory" text,
	"mitre_tactic" text,
	"mitre_technique" text,
	"alert_id" varchar,
	"status" text DEFAULT 'new' NOT NULL,
	"resolved_by" varchar,
	"resolved_at" timestamp,
	"raw_packet" jsonb,
	"metadata" jsonb,
	"detected_at" timestamp DEFAULT now(),
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "ot_assets" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"asset_type" text NOT NULL,
	"ip_address" text,
	"mac_address" text,
	"hostname" text,
	"purdue_level" text,
	"zone" text,
	"vendor" text,
	"model" text,
	"firmware_version" text,
	"serial_number" text,
	"hardware_revision" text,
	"protocols" jsonb,
	"facility" text,
	"area" text,
	"line" text,
	"status" text DEFAULT 'online' NOT NULL,
	"last_seen" timestamp,
	"first_seen" timestamp,
	"is_managed" boolean DEFAULT false NOT NULL,
	"is_critical" boolean DEFAULT false NOT NULL,
	"is_safety_system" boolean DEFAULT false NOT NULL,
	"sil_rating" text,
	"cve_count" integer DEFAULT 0 NOT NULL,
	"highest_cvss" real,
	"last_vuln_scan" timestamp,
	"tags" jsonb,
	"metadata" jsonb,
	"discovered_by" text,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "ot_connections" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"source_asset_id" varchar,
	"dest_asset_id" varchar,
	"source_ip" text,
	"dest_ip" text,
	"source_port" integer,
	"dest_port" integer,
	"protocol" text,
	"source_purdue_level" text,
	"dest_purdue_level" text,
	"crosses_boundary" boolean DEFAULT false NOT NULL,
	"is_allowed" boolean DEFAULT true,
	"rule_id" text,
	"packet_count" bigint DEFAULT 0,
	"byte_count" bigint DEFAULT 0,
	"last_activity" timestamp,
	"first_seen" timestamp DEFAULT now(),
	"metadata" jsonb,
	"created_at" timestamp DEFAULT now()
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
CREATE TABLE "pam_sessions" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"requester_id" varchar NOT NULL,
	"requester_name" text NOT NULL,
	"requester_email" text,
	"target_system" text NOT NULL,
	"target_host" text,
	"target_account" text NOT NULL,
	"access_level" text NOT NULL,
	"justification" text NOT NULL,
	"incident_id" varchar,
	"status" text DEFAULT 'requested' NOT NULL,
	"duration_minutes" integer DEFAULT 60 NOT NULL,
	"approved_by" varchar,
	"approved_at" timestamp,
	"denied_by" varchar,
	"denied_reason" text,
	"activated_at" timestamp,
	"expires_at" timestamp,
	"terminated_at" timestamp,
	"terminated_by" varchar,
	"termination_reason" text,
	"session_token" text,
	"recording_enabled" boolean DEFAULT true NOT NULL,
	"recording_size" integer,
	"command_count" integer DEFAULT 0,
	"keystroke_count" integer DEFAULT 0,
	"risk_score" integer,
	"risk_factors" jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "passive_dns_records" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"domain" text NOT NULL,
	"record_type" text NOT NULL,
	"resolved_value" text NOT NULL,
	"first_seen" timestamp DEFAULT now(),
	"last_seen" timestamp DEFAULT now(),
	"query_count" integer DEFAULT 1 NOT NULL,
	"sources" jsonb,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "password_reset_tokens" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" varchar NOT NULL,
	"token" text NOT NULL,
	"expires_at" timestamp NOT NULL,
	"used_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	CONSTRAINT "password_reset_tokens_token_unique" UNIQUE("token")
);
--> statement-breakpoint
CREATE TABLE "peer_benchmarks" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"industry_segment" text NOT NULL,
	"company_size" text NOT NULL,
	"overall_score" integer NOT NULL,
	"identity_score" integer DEFAULT 0,
	"endpoint_score" integer DEFAULT 0,
	"cloud_score" integer DEFAULT 0,
	"network_score" integer DEFAULT 0,
	"application_score" integer DEFAULT 0,
	"data_score" integer DEFAULT 0,
	"percentile_rank" integer DEFAULT 50,
	"peer_count" integer DEFAULT 0,
	"top_strengths" jsonb DEFAULT '[]'::jsonb,
	"top_weaknesses" jsonb DEFAULT '[]'::jsonb,
	"calculated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "phishing_campaigns" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"status" text DEFAULT 'draft' NOT NULL,
	"template_id" uuid,
	"template_category" text,
	"sender_name" text,
	"sender_email" text,
	"subject" text,
	"email_body" text,
	"landing_page_html" text,
	"target_departments" jsonb DEFAULT '[]'::jsonb,
	"target_emails" jsonb DEFAULT '[]'::jsonb,
	"total_recipients" integer DEFAULT 0 NOT NULL,
	"emails_sent" integer DEFAULT 0 NOT NULL,
	"emails_opened" integer DEFAULT 0 NOT NULL,
	"links_clicked" integer DEFAULT 0 NOT NULL,
	"credentials_submitted" integer DEFAULT 0 NOT NULL,
	"reported" integer DEFAULT 0 NOT NULL,
	"scheduled_at" timestamp,
	"started_at" timestamp,
	"completed_at" timestamp,
	"created_by" uuid,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "phishing_results" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"campaign_id" uuid NOT NULL,
	"recipient_email" text NOT NULL,
	"recipient_name" text,
	"department" text,
	"email_sent_at" timestamp,
	"email_opened_at" timestamp,
	"link_clicked_at" timestamp,
	"credential_submitted_at" timestamp,
	"reported_at" timestamp,
	"user_agent" text,
	"ip_address" text,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "phishing_simulations" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"campaign_name" text NOT NULL,
	"template_type" text,
	"status" text DEFAULT 'draft' NOT NULL,
	"sent_count" integer DEFAULT 0,
	"opened_count" integer DEFAULT 0,
	"clicked_count" integer DEFAULT 0,
	"reported_count" integer DEFAULT 0,
	"submitted_credentials" integer DEFAULT 0,
	"launched_at" timestamp,
	"completed_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "phishing_templates" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"category" text NOT NULL,
	"difficulty" text DEFAULT 'medium' NOT NULL,
	"industry" text,
	"subject" text NOT NULL,
	"sender_name" text NOT NULL,
	"sender_email" text NOT NULL,
	"email_body" text NOT NULL,
	"landing_page_html" text,
	"is_built_in" boolean DEFAULT false NOT NULL,
	"usage_count" integer DEFAULT 0 NOT NULL,
	"success_rate" real,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "physical_assets" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"asset_type" text NOT NULL,
	"location" text NOT NULL,
	"building" text,
	"floor" text,
	"zone" text,
	"controller_type" text,
	"controller_id" text,
	"ip_address" text,
	"is_online" boolean DEFAULT true NOT NULL,
	"last_heartbeat" timestamp,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "physical_incidents" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"title" text NOT NULL,
	"description" text,
	"incident_type" text NOT NULL,
	"severity" text DEFAULT 'medium' NOT NULL,
	"status" text DEFAULT 'open' NOT NULL,
	"location" text,
	"badge_event_ids" jsonb DEFAULT '[]'::jsonb,
	"correlated_digital_incident_id" uuid,
	"correlated_alert_ids" jsonb DEFAULT '[]'::jsonb,
	"assigned_to" text,
	"resolved_at" timestamp,
	"resolution_notes" text,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "physical_security_config" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"is_enabled" boolean DEFAULT true NOT NULL,
	"controller_integrations" jsonb DEFAULT '[]'::jsonb,
	"after_hours_start" text DEFAULT '20:00',
	"after_hours_end" text DEFAULT '06:00',
	"tailgate_detection_enabled" boolean DEFAULT true NOT NULL,
	"anomaly_correlation_enabled" boolean DEFAULT true NOT NULL,
	"auto_create_digital_incidents" boolean DEFAULT true NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
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
CREATE TABLE "plans" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"display_name" text NOT NULL,
	"description" text,
	"monthly_price_cents" integer DEFAULT 0 NOT NULL,
	"annual_price_cents" integer DEFAULT 0 NOT NULL,
	"stripe_price_id_monthly" text,
	"stripe_price_id_annual" text,
	"features" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"is_active" boolean DEFAULT true,
	"sort_order" integer DEFAULT 0 NOT NULL,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	CONSTRAINT "plans_name_unique" UNIQUE("name")
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
CREATE TABLE "playbook_template_catalog" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"name" text NOT NULL,
	"description" text NOT NULL,
	"category" text NOT NULL,
	"severity" text DEFAULT 'medium' NOT NULL,
	"steps" jsonb DEFAULT '[]'::jsonb,
	"tags" jsonb DEFAULT '[]'::jsonb,
	"author" text,
	"version" text DEFAULT '1.0.0',
	"is_built_in" boolean DEFAULT false,
	"usage_count" integer DEFAULT 0,
	"rating" real DEFAULT 0,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
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
CREATE TABLE "policy_pack_activations" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"pack_id" text NOT NULL,
	"strictness_override" text,
	"enabled_rule_ids" text[] DEFAULT ARRAY[]::text[],
	"disabled_rule_ids" text[] DEFAULT ARRAY[]::text[],
	"status" text DEFAULT 'active' NOT NULL,
	"activated_by" text,
	"activated_at" timestamp DEFAULT now(),
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
CREATE TABLE "posture_score_history" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"overall_score" integer NOT NULL,
	"identity_score" integer DEFAULT 0,
	"endpoint_score" integer DEFAULT 0,
	"cloud_score" integer DEFAULT 0,
	"network_score" integer DEFAULT 0,
	"application_score" integer DEFAULT 0,
	"data_score" integer DEFAULT 0,
	"percentile_rank" integer DEFAULT 50,
	"change_from_previous" integer DEFAULT 0,
	"period" text NOT NULL,
	"period_type" text DEFAULT 'monthly' NOT NULL,
	"generated_at" timestamp DEFAULT now()
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
CREATE TABLE "posture_sub_scores" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"posture_score_id" varchar,
	"domain" text NOT NULL,
	"score" integer DEFAULT 0 NOT NULL,
	"weight" integer DEFAULT 16 NOT NULL,
	"findings" jsonb DEFAULT '[]'::jsonb,
	"recommendations" jsonb DEFAULT '[]'::jsonb,
	"controls_evaluated" integer DEFAULT 0,
	"controls_passed" integer DEFAULT 0,
	"controls_failed" integer DEFAULT 0,
	"risk_factors" jsonb DEFAULT '[]'::jsonb,
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
CREATE TABLE "privacy_impact_assessments" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"title" text NOT NULL,
	"description" text,
	"project_name" text,
	"assessor_name" text,
	"assessor_email" text,
	"status" text DEFAULT 'draft' NOT NULL,
	"overall_risk" text DEFAULT 'medium' NOT NULL,
	"data_collected" jsonb DEFAULT '[]'::jsonb,
	"data_subject_types" jsonb DEFAULT '[]'::jsonb,
	"processing_purposes" jsonb DEFAULT '[]'::jsonb,
	"legal_basis" text,
	"retention_period" text,
	"third_party_recipients" jsonb DEFAULT '[]'::jsonb,
	"cross_border_transfers" boolean DEFAULT false NOT NULL,
	"cross_border_destinations" jsonb DEFAULT '[]'::jsonb,
	"security_measures" jsonb DEFAULT '[]'::jsonb,
	"privacy_risks" jsonb DEFAULT '[]'::jsonb,
	"mitigation_plan" text,
	"dpo_approval" boolean DEFAULT false NOT NULL,
	"dpo_comments" text,
	"review_date" timestamp,
	"expires_at" timestamp,
	"completed_at" timestamp,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "privacy_scans" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"scan_type" text NOT NULL,
	"target_asset_id" uuid,
	"target_description" text,
	"status" text DEFAULT 'queued' NOT NULL,
	"findings_count" integer DEFAULT 0 NOT NULL,
	"pii_fields_found" integer DEFAULT 0 NOT NULL,
	"phi_fields_found" integer DEFAULT 0 NOT NULL,
	"pci_fields_found" integer DEFAULT 0 NOT NULL,
	"classification_results" jsonb DEFAULT '[]'::jsonb,
	"minimization_findings" jsonb DEFAULT '[]'::jsonb,
	"scan_duration_ms" integer,
	"error_message" text,
	"started_at" timestamp DEFAULT now() NOT NULL,
	"completed_at" timestamp
);
--> statement-breakpoint
CREATE TABLE "prompt_ab_tests" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"prompt_id" varchar NOT NULL,
	"version_a" integer NOT NULL,
	"version_b" integer NOT NULL,
	"status" varchar(20) DEFAULT 'running' NOT NULL,
	"sample_size" integer DEFAULT 100 NOT NULL,
	"results" jsonb DEFAULT '{}'::jsonb,
	"started_at" timestamp DEFAULT now(),
	"completed_at" timestamp,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "prompt_history" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"prompt" text NOT NULL,
	"artifact_type" text NOT NULL,
	"is_favorite" boolean DEFAULT false,
	"shared_with" jsonb DEFAULT '[]'::jsonb,
	"used_at" timestamp DEFAULT now(),
	"result_id" text
);
--> statement-breakpoint
CREATE TABLE "prompt_investigations" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"prompt" text NOT NULL,
	"intent" text DEFAULT '' NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"summary" text,
	"steps" jsonb DEFAULT '[]'::jsonb,
	"artifacts" jsonb DEFAULT '[]'::jsonb,
	"citations" jsonb DEFAULT '[]'::jsonb,
	"created_at" timestamp DEFAULT now(),
	"completed_at" timestamp
);
--> statement-breakpoint
CREATE TABLE "prompt_quality_scores" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"prompt_id" varchar NOT NULL,
	"version" integer DEFAULT 1 NOT NULL,
	"relevance" integer NOT NULL,
	"accuracy" integer NOT NULL,
	"actionability" integer NOT NULL,
	"format_compliance" integer NOT NULL,
	"overall" integer NOT NULL,
	"sample_output" text DEFAULT '',
	"evaluated_at" timestamp DEFAULT now(),
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "public_trust_pages" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"slug" text NOT NULL,
	"status" text DEFAULT 'draft' NOT NULL,
	"company_name" text NOT NULL,
	"company_logo" text,
	"tagline" text,
	"overall_score" integer DEFAULT 0,
	"domain_scores" jsonb DEFAULT '{}'::jsonb,
	"certifications" jsonb DEFAULT '[]'::jsonb,
	"last_audit_date" timestamp,
	"show_sub_scores" boolean DEFAULT true,
	"show_certifications" boolean DEFAULT true,
	"show_last_audit" boolean DEFAULT true,
	"show_percentile" boolean DEFAULT false,
	"custom_sections" jsonb DEFAULT '[]'::jsonb,
	"contact_email" text,
	"brand_color" text DEFAULT '#0ea5e9',
	"visit_count" integer DEFAULT 0,
	"published_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	CONSTRAINT "public_trust_pages_slug_unique" UNIQUE("slug")
);
--> statement-breakpoint
CREATE TABLE "purple_team_exercises" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"attack_scenario" text NOT NULL,
	"mitre_chain" text[],
	"red_team_actions" text,
	"blue_team_expected" text,
	"blue_team_actual" text,
	"status" text DEFAULT 'planned' NOT NULL,
	"overall_verdict" text,
	"detection_time" integer,
	"response_time" integer,
	"containment_time" integer,
	"gaps_identified" text[],
	"improvements" text[],
	"executed_at" timestamp,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "quantum_migration_tasks" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"title" text NOT NULL,
	"description" text,
	"crypto_inventory_id" uuid,
	"current_algorithm" text NOT NULL,
	"target_algorithm" text NOT NULL,
	"priority" text DEFAULT 'medium' NOT NULL,
	"status" text DEFAULT 'not_started' NOT NULL,
	"effort_estimate_days" integer,
	"assigned_to" text,
	"due_date" timestamp,
	"completed_at" timestamp,
	"blockers" text,
	"nist_standard" text,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "quantum_risk_scores" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"overall_score" integer DEFAULT 0 NOT NULL,
	"crypto_agility" integer DEFAULT 0 NOT NULL,
	"algorithm_diversity" integer DEFAULT 0 NOT NULL,
	"pqc_readiness" integer DEFAULT 0 NOT NULL,
	"compliance_score" integer DEFAULT 0 NOT NULL,
	"total_assets" integer DEFAULT 0 NOT NULL,
	"vulnerable_assets" integer DEFAULT 0 NOT NULL,
	"migrated_assets" integer DEFAULT 0 NOT NULL,
	"critical_risk_count" integer DEFAULT 0 NOT NULL,
	"high_risk_count" integer DEFAULT 0 NOT NULL,
	"medium_risk_count" integer DEFAULT 0 NOT NULL,
	"low_risk_count" integer DEFAULT 0 NOT NULL,
	"estimated_migration_months" integer,
	"estimated_migration_cost" integer,
	"nist_compliance_status" jsonb DEFAULT '{}'::jsonb,
	"scored_at" timestamp DEFAULT now() NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "quantum_scan_history" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"scan_type" text NOT NULL,
	"status" text DEFAULT 'running' NOT NULL,
	"assets_discovered" integer DEFAULT 0 NOT NULL,
	"vulnerable_found" integer DEFAULT 0 NOT NULL,
	"scan_duration_ms" integer,
	"scan_targets" jsonb DEFAULT '[]'::jsonb,
	"error_message" text,
	"started_at" timestamp DEFAULT now() NOT NULL,
	"completed_at" timestamp
);
--> statement-breakpoint
CREATE TABLE "questionnaire_responses" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"questionnaire_id" varchar NOT NULL,
	"question_number" integer NOT NULL,
	"question_text" text NOT NULL,
	"category" text,
	"answer_text" text,
	"answer_source" text DEFAULT 'manual' NOT NULL,
	"confidence_percent" integer DEFAULT 0,
	"evidence_refs" jsonb DEFAULT '[]'::jsonb,
	"reviewed_by" text,
	"reviewed_at" timestamp,
	"status" text DEFAULT 'pending' NOT NULL,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "ransomware_canary_files" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"file_name" text NOT NULL,
	"file_path" text NOT NULL,
	"file_type" text NOT NULL,
	"file_hash" text NOT NULL,
	"deployed_to_host" text,
	"deployed_to_sensor_id" varchar,
	"status" text DEFAULT 'active' NOT NULL,
	"last_checked_at" timestamp,
	"last_checked_hash" text,
	"triggered_at" timestamp,
	"trigger_type" text,
	"alert_sent" boolean DEFAULT false NOT NULL,
	"created_by" varchar,
	"metadata" jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "ransomware_groups" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"aliases" jsonb,
	"threat_level" text DEFAULT 'high' NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"first_seen" text,
	"last_active" text,
	"description" text,
	"ttps" jsonb,
	"target_industries" jsonb,
	"target_regions" jsonb,
	"ransomware_variants" jsonb,
	"known_payment_addresses" jsonb,
	"avg_ransom_demand_usd" integer,
	"decryptor_available" boolean DEFAULT false NOT NULL,
	"decryptor_source" text,
	"negotiation_notes" text,
	"ioc_indicators" jsonb,
	"reference_urls" jsonb,
	"metadata" jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "ransomware_indicators" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"indicator_type" text NOT NULL,
	"value" text NOT NULL,
	"threat_family" text,
	"confidence" double precision DEFAULT 0,
	"severity" text DEFAULT 'high' NOT NULL,
	"source" text,
	"status" text DEFAULT 'active' NOT NULL,
	"details" jsonb DEFAULT '{}'::jsonb,
	"first_seen_at" timestamp DEFAULT now(),
	"last_seen_at" timestamp DEFAULT now(),
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "ransomware_kill_switch_events" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"status" text DEFAULT 'initiated' NOT NULL,
	"triggered_by" varchar NOT NULL,
	"triggered_by_name" text,
	"reason" text,
	"total_sensors" integer DEFAULT 0 NOT NULL,
	"isolated_count" integer DEFAULT 0 NOT NULL,
	"failed_count" integer DEFAULT 0 NOT NULL,
	"skipped_count" integer DEFAULT 0 NOT NULL,
	"action_ids" jsonb,
	"failed_sensors" jsonb,
	"rollback_at" timestamp,
	"rollback_by" varchar,
	"completed_at" timestamp,
	"incident_id" varchar,
	"metadata" jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "recovery_runbooks" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"title" text NOT NULL,
	"incident_id" varchar,
	"status" text DEFAULT 'draft' NOT NULL,
	"scenario" text NOT NULL,
	"affected_systems" jsonb,
	"affected_data_types" jsonb,
	"ransomware_variant" text,
	"estimated_downtime_hours" integer,
	"estimated_recovery_cost_usd" integer,
	"steps" jsonb,
	"priority_actions" jsonb,
	"communication_plan" jsonb,
	"legal_requirements" jsonb,
	"generated_by" text DEFAULT 'ai',
	"reviewed_by" varchar,
	"reviewed_at" timestamp,
	"approved_by" varchar,
	"approved_at" timestamp,
	"metadata" jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "remediation_fixes" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"type" text NOT NULL,
	"title" text NOT NULL,
	"description" text NOT NULL,
	"priority" text DEFAULT 'medium' NOT NULL,
	"status" text DEFAULT 'suggested' NOT NULL,
	"finding" jsonb DEFAULT '{}'::jsonb,
	"code_change" jsonb,
	"owner_id" text,
	"estimated_effort" text,
	"mitre_tactics" jsonb DEFAULT '[]'::jsonb,
	"cwe_ids" jsonb DEFAULT '[]'::jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "remote_worker_sessions" (
	"id" varchar(36) PRIMARY KEY NOT NULL,
	"org_id" varchar(36) NOT NULL,
	"user_id" varchar(36) NOT NULL,
	"device_id" varchar(36),
	"session_start" timestamp DEFAULT now(),
	"session_end" timestamp,
	"ip_address" text,
	"country" text,
	"city" text,
	"vpn_connected" boolean DEFAULT false,
	"vpn_provider" text,
	"is_off_hours" boolean DEFAULT false,
	"is_new_location" boolean DEFAULT false,
	"risk_score" integer DEFAULT 0 NOT NULL,
	"risk_factors" jsonb,
	"ztna_decision" text,
	"policy_id" varchar(36),
	"metadata" jsonb
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
CREATE TABLE "report_template_versions" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"template_id" varchar NOT NULL,
	"version" integer NOT NULL,
	"change_description" text NOT NULL,
	"config" text,
	"format" text,
	"status" text DEFAULT 'draft' NOT NULL,
	"approved_by" text,
	"approved_at" timestamp,
	"created_by" text,
	"created_at" timestamp DEFAULT now()
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
CREATE TABLE "risk_register" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"title" text NOT NULL,
	"description" text,
	"category" text NOT NULL,
	"likelihood" integer DEFAULT 3 NOT NULL,
	"impact" integer DEFAULT 3 NOT NULL,
	"inherent_risk_score" integer DEFAULT 9 NOT NULL,
	"residual_likelihood" integer,
	"residual_impact" integer,
	"residual_risk_score" integer,
	"treatment" text DEFAULT 'mitigate' NOT NULL,
	"treatment_plan" text,
	"controls" jsonb DEFAULT '[]'::jsonb,
	"risk_owner" text,
	"status" text DEFAULT 'identified' NOT NULL,
	"last_review_date" timestamp,
	"next_review_date" timestamp,
	"related_assets" text[] DEFAULT ARRAY[]::text[],
	"related_frameworks" text[] DEFAULT ARRAY[]::text[],
	"tags" text[] DEFAULT ARRAY[]::text[],
	"created_by" varchar,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "rule_ab_tests" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"rule_id" varchar NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"shadow_mode_enabled" boolean DEFAULT true NOT NULL,
	"started_at" timestamp,
	"ended_at" timestamp,
	"duration_days" integer DEFAULT 7 NOT NULL,
	"shadow_matches" integer DEFAULT 0 NOT NULL,
	"false_positives" integer DEFAULT 0 NOT NULL,
	"true_positives" integer DEFAULT 0 NOT NULL,
	"match_samples" jsonb DEFAULT '[]'::jsonb,
	"verdict" text,
	"verdict_reason" text,
	"promoted_at" timestamp,
	"created_by" text,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "rule_generation_jobs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"source" text DEFAULT 'manual' NOT NULL,
	"source_id" text,
	"source_context" text,
	"rule_format" text DEFAULT 'sigma' NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"generated_rule_id" varchar,
	"generated_sigma_yaml" text,
	"generated_yara_rule" text,
	"generated_condition_tree" jsonb,
	"generated_name" text,
	"generated_description" text,
	"generated_severity" text,
	"generated_mitre_tactic" text,
	"generated_mitre_technique" text,
	"generated_tags" text[] DEFAULT ARRAY[]::text[],
	"quality_score" integer,
	"estimated_fp_rate" real,
	"quality_breakdown" jsonb,
	"model_id" text,
	"prompt_version" integer,
	"input_tokens" integer,
	"output_tokens" integer,
	"cost_usd" real,
	"latency_ms" integer,
	"error_message" text,
	"requested_by" text,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"completed_at" timestamp
);
--> statement-breakpoint
CREATE TABLE "rule_lifecycle_events" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"rule_id" varchar NOT NULL,
	"action" text NOT NULL,
	"previous_status" text,
	"new_status" text,
	"reason" text,
	"match_count_at_action" integer DEFAULT 0 NOT NULL,
	"performed_by" text,
	"metadata" jsonb,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "rule_marketplace" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"rule_id" varchar NOT NULL,
	"title" text NOT NULL,
	"description" text,
	"category" text DEFAULT 'general' NOT NULL,
	"rule_format" text DEFAULT 'sigma' NOT NULL,
	"sigma_yaml" text,
	"yara_rule" text,
	"condition_tree" jsonb,
	"mitre_tactic" text,
	"mitre_technique" text,
	"severity" text DEFAULT 'medium' NOT NULL,
	"tags" text[] DEFAULT ARRAY[]::text[],
	"status" text DEFAULT 'draft' NOT NULL,
	"version" integer DEFAULT 1 NOT NULL,
	"downloads" integer DEFAULT 0 NOT NULL,
	"rating" real,
	"rating_count" integer DEFAULT 0 NOT NULL,
	"published_by" text,
	"published_at" timestamp,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
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
CREATE TABLE "runtime_guardrail_decisions" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"policy_id" text,
	"policy_name" text,
	"action" text NOT NULL,
	"verdict" text NOT NULL,
	"reason" text,
	"actor_id" text,
	"resource_id" text,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"evaluated_at" timestamp DEFAULT now(),
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "runtime_guardrail_overrides" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"policy_id" text NOT NULL,
	"requested_by" text NOT NULL,
	"reason" text NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"approved_by" text,
	"approved_at" timestamp,
	"expires_at" timestamp,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "runtime_guardrail_policies" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"action" text NOT NULL,
	"scope" text DEFAULT 'global' NOT NULL,
	"mode" text DEFAULT 'enforce' NOT NULL,
	"conditions" jsonb DEFAULT '[]'::jsonb,
	"priority" integer DEFAULT 100 NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "sast_findings" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"repository" text NOT NULL,
	"branch" text DEFAULT 'main' NOT NULL,
	"commit_sha" text,
	"pull_request_id" text,
	"file_path" text NOT NULL,
	"start_line" integer NOT NULL,
	"end_line" integer,
	"code_snippet" text,
	"category" text NOT NULL,
	"severity" text DEFAULT 'medium' NOT NULL,
	"title" text NOT NULL,
	"description" text NOT NULL,
	"remediation" text,
	"cwe_id" text,
	"owasp_category" text,
	"confidence" real DEFAULT 0.8 NOT NULL,
	"status" text DEFAULT 'open' NOT NULL,
	"assignee" text,
	"false_positive" boolean DEFAULT false NOT NULL,
	"false_positive_by" text,
	"false_positive_reason" text,
	"fixed_in_commit" text,
	"fixed_at" timestamp,
	"first_seen_at" timestamp DEFAULT now(),
	"last_seen_at" timestamp DEFAULT now(),
	"scan_id" varchar,
	"rule_id" text,
	"metadata" jsonb,
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
CREATE TABLE "sbom_artifacts" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"version" text,
	"format" text NOT NULL,
	"source" text,
	"component_count" integer DEFAULT 0 NOT NULL,
	"vulnerability_count" integer DEFAULT 0 NOT NULL,
	"license_count" integer DEFAULT 0 NOT NULL,
	"status" text DEFAULT 'processing' NOT NULL,
	"raw_data" jsonb,
	"metadata" jsonb,
	"uploaded_by" varchar,
	"processed_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "scim_provisioning_logs" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"provider" text NOT NULL,
	"operation_type" text NOT NULL,
	"external_user_id" text,
	"external_user_name" text,
	"external_email" text,
	"internal_user_id" varchar,
	"group_name" text,
	"success" boolean DEFAULT true NOT NULL,
	"error_message" text,
	"raw_payload" jsonb,
	"processed_at" timestamp DEFAULT now(),
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "secrets_exposed" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"repository" text NOT NULL,
	"branch" text DEFAULT 'main' NOT NULL,
	"commit_sha" text NOT NULL,
	"commit_author" text,
	"commit_date" timestamp,
	"file_path" text NOT NULL,
	"line" integer NOT NULL,
	"secret_type" text NOT NULL,
	"secret_hash" text NOT NULL,
	"masked_value" text,
	"severity" text DEFAULT 'critical' NOT NULL,
	"status" text DEFAULT 'active' NOT NULL,
	"rotated" boolean DEFAULT false NOT NULL,
	"rotated_at" timestamp,
	"rotated_by" text,
	"false_positive" boolean DEFAULT false NOT NULL,
	"false_positive_by" text,
	"pull_request_id" text,
	"pr_comment_posted" boolean DEFAULT false NOT NULL,
	"scan_id" varchar,
	"metadata" jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "security_assessments" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"framework" text NOT NULL,
	"title" text NOT NULL,
	"description" text,
	"status" text DEFAULT 'draft' NOT NULL,
	"total_controls" integer DEFAULT 0 NOT NULL,
	"implemented_controls" integer DEFAULT 0 NOT NULL,
	"partial_controls" integer DEFAULT 0 NOT NULL,
	"not_implemented_controls" integer DEFAULT 0 NOT NULL,
	"not_applicable_controls" integer DEFAULT 0 NOT NULL,
	"overall_score" integer DEFAULT 0 NOT NULL,
	"assessor" text,
	"reviewed_by" text,
	"started_at" timestamp,
	"completed_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "security_awareness_config" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"is_enabled" boolean DEFAULT true NOT NULL,
	"auto_enroll_on_click" boolean DEFAULT true NOT NULL,
	"default_training_module_id" uuid,
	"phishing_frequency_days" integer DEFAULT 30 NOT NULL,
	"vishing_enabled" boolean DEFAULT false NOT NULL,
	"smishing_enabled" boolean DEFAULT false NOT NULL,
	"risk_score_threshold" integer DEFAULT 75 NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "security_debt_items" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"repository" text NOT NULL,
	"category" text NOT NULL,
	"severity" text DEFAULT 'medium' NOT NULL,
	"title" text NOT NULL,
	"description" text NOT NULL,
	"file_path" text,
	"finding_count" integer DEFAULT 1 NOT NULL,
	"exploitability" text DEFAULT 'medium' NOT NULL,
	"effort_to_fix" text DEFAULT 'medium' NOT NULL,
	"priority" integer DEFAULT 50 NOT NULL,
	"status" text DEFAULT 'open' NOT NULL,
	"assignee" text,
	"due_date" timestamp,
	"related_finding_ids" text[],
	"metadata" jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "security_graph_assets" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"type" text NOT NULL,
	"sub_type" text NOT NULL,
	"environment" text DEFAULT 'production' NOT NULL,
	"risk_score" real DEFAULT 0 NOT NULL,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"tags" text[] DEFAULT ARRAY[]::text[],
	"owner" text,
	"last_scanned_at" timestamp,
	"resolution_key" text NOT NULL,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "security_graph_relationships" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"source_id" varchar NOT NULL,
	"target_id" varchar NOT NULL,
	"relationship" text NOT NULL,
	"weight" real DEFAULT 1 NOT NULL,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"bidirectional" boolean DEFAULT false NOT NULL,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "security_kpi_snapshots" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"kpi_type" text NOT NULL,
	"period" text DEFAULT 'daily' NOT NULL,
	"value" double precision NOT NULL,
	"previous_value" double precision,
	"unit" text,
	"metadata" jsonb,
	"period_start" timestamp NOT NULL,
	"period_end" timestamp NOT NULL,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "security_questionnaires" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"title" text NOT NULL,
	"framework" text NOT NULL,
	"status" text DEFAULT 'draft' NOT NULL,
	"total_questions" integer DEFAULT 0,
	"answered_questions" integer DEFAULT 0,
	"auto_answered_questions" integer DEFAULT 0,
	"manual_questions" integer DEFAULT 0,
	"confidence_score" integer DEFAULT 0,
	"requested_by" text,
	"requested_by_email" text,
	"assigned_to" text,
	"due_date" timestamp,
	"completed_at" timestamp,
	"submitted_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "security_tool_overlaps" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"capability" text NOT NULL,
	"tools" jsonb NOT NULL,
	"annual_cost" double precision,
	"recommendation" text,
	"potential_savings" double precision,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "sensor_events" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"sensor_id" varchar NOT NULL,
	"event_type" text NOT NULL,
	"timestamp" timestamp NOT NULL,
	"process_name" text,
	"process_path" text,
	"process_args" text,
	"parent_process" text,
	"pid" integer,
	"ppid" integer,
	"user_name" text,
	"src_ip" text,
	"dst_ip" text,
	"src_port" integer,
	"dst_port" integer,
	"protocol" text,
	"bytes_in" integer,
	"bytes_out" integer,
	"file_path" text,
	"file_action" text,
	"file_hash" text,
	"file_size" integer,
	"auth_action" text,
	"auth_result" text,
	"auth_method" text,
	"dns_query" text,
	"dns_type" text,
	"dns_response" text,
	"log_source" text,
	"log_level" text,
	"log_message" text,
	"raw_data" jsonb,
	"detection_matched" boolean DEFAULT false,
	"detection_rule_id" varchar,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "shared_iocs" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"contributor_org_id" text NOT NULL,
	"anonymous_contributor_hash" text NOT NULL,
	"ioc_type" text NOT NULL,
	"ioc_value" text NOT NULL,
	"ioc_value_hash" text NOT NULL,
	"severity" text DEFAULT 'medium' NOT NULL,
	"confidence" integer DEFAULT 70 NOT NULL,
	"tlp_level" text DEFAULT 'amber' NOT NULL,
	"tags" jsonb DEFAULT '[]'::jsonb,
	"threat_actor_ref" text,
	"campaign_ref" text,
	"context" text,
	"first_seen_at" timestamp DEFAULT now() NOT NULL,
	"last_seen_at" timestamp DEFAULT now() NOT NULL,
	"sighting_count" integer DEFAULT 1 NOT NULL,
	"reporting_orgs" jsonb DEFAULT '[]'::jsonb,
	"industry_sectors" jsonb DEFAULT '[]'::jsonb,
	"expires_at" timestamp,
	"is_active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "sharing_consents" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"consent_level" text DEFAULT 'none' NOT NULL,
	"industry_sector" text DEFAULT 'other' NOT NULL,
	"company_size" text DEFAULT 'medium' NOT NULL,
	"anonymous_org_hash" text NOT NULL,
	"share_iocs" boolean DEFAULT false NOT NULL,
	"share_detection_patterns" boolean DEFAULT false NOT NULL,
	"share_telemetry" boolean DEFAULT false NOT NULL,
	"receive_global_feed" boolean DEFAULT true NOT NULL,
	"receive_industry_feed" boolean DEFAULT true NOT NULL,
	"auto_contribute" boolean DEFAULT false NOT NULL,
	"contributed_ioc_count" integer DEFAULT 0 NOT NULL,
	"received_ioc_count" integer DEFAULT 0 NOT NULL,
	"last_contributed_at" timestamp,
	"last_received_at" timestamp,
	"consent_granted_at" timestamp,
	"consent_updated_at" timestamp DEFAULT now(),
	"created_at" timestamp DEFAULT now(),
	CONSTRAINT "sharing_consents_org_id_unique" UNIQUE("org_id")
);
--> statement-breakpoint
CREATE TABLE "sinkholed_domains" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"domain" text NOT NULL,
	"reason" text,
	"source" text DEFAULT 'manual',
	"status" text DEFAULT 'active' NOT NULL,
	"hit_count" integer DEFAULT 0 NOT NULL,
	"last_hit_at" timestamp,
	"expires_at" timestamp,
	"added_by" varchar,
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
CREATE TABLE "sli_metrics_daily" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"service" text NOT NULL,
	"metric" text NOT NULL,
	"day" timestamp NOT NULL,
	"min_value" real NOT NULL,
	"max_value" real NOT NULL,
	"avg_value" real NOT NULL,
	"p50_value" real,
	"p95_value" real,
	"p99_value" real,
	"sample_count" integer DEFAULT 0 NOT NULL,
	"labels" jsonb,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "sli_metrics_hourly" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"service" text NOT NULL,
	"metric" text NOT NULL,
	"hour" timestamp NOT NULL,
	"min_value" real NOT NULL,
	"max_value" real NOT NULL,
	"avg_value" real NOT NULL,
	"p50_value" real,
	"p95_value" real,
	"p99_value" real,
	"sample_count" integer DEFAULT 0 NOT NULL,
	"labels" jsonb,
	"created_at" timestamp DEFAULT now()
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
CREATE TABLE "sovereign_keys" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"key_alias" text NOT NULL,
	"key_provider" text DEFAULT 'aws-kms' NOT NULL,
	"key_arn" text,
	"key_fingerprint" text,
	"status" text DEFAULT 'active' NOT NULL,
	"rotation_interval_days" integer DEFAULT 90,
	"last_rotated_at" timestamp,
	"next_rotation_at" timestamp,
	"metadata" jsonb,
	"created_by" varchar,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "subscriptions" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"plan_id" varchar NOT NULL,
	"status" text DEFAULT 'active' NOT NULL,
	"billing_cycle" text DEFAULT 'monthly' NOT NULL,
	"stripe_customer_id" text,
	"stripe_subscription_id" text,
	"trial_end_date" timestamp,
	"current_period_start" timestamp,
	"current_period_end" timestamp,
	"cancelled_at" timestamp,
	"cancel_reason" text,
	"custom_overrides" jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "supply_chain_components" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"version" text,
	"component_type" text NOT NULL,
	"ecosystem" text,
	"license" text,
	"risk_score" double precision DEFAULT 0,
	"vulnerabilities" integer DEFAULT 0,
	"direct_dependency" boolean DEFAULT true,
	"maintainer_score" double precision DEFAULT 0,
	"last_updated_upstream" timestamp,
	"status" text DEFAULT 'monitored' NOT NULL,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "supply_chain_findings" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"sbom_id" varchar,
	"dependency_id" varchar,
	"finding_type" text NOT NULL,
	"severity" text DEFAULT 'medium' NOT NULL,
	"status" text DEFAULT 'open' NOT NULL,
	"title" text NOT NULL,
	"description" text,
	"package_name" text,
	"package_version" text,
	"ecosystem" text,
	"cve_id" text,
	"cvss_score" real,
	"fixed_version" text,
	"iac_resource_type" text,
	"iac_file_path" text,
	"iac_rule" text,
	"container_image" text,
	"container_layer" text,
	"details" jsonb,
	"acknowledged_by" varchar,
	"acknowledged_at" timestamp,
	"remediated_by" varchar,
	"remediated_at" timestamp,
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
CREATE TABLE "table_partitions" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"table_name" text NOT NULL,
	"partition_name" text NOT NULL,
	"range_start" timestamp NOT NULL,
	"range_end" timestamp NOT NULL,
	"row_count_estimate" integer DEFAULT 0,
	"size_bytes" integer DEFAULT 0,
	"status" text DEFAULT 'active' NOT NULL,
	"created_at" timestamp DEFAULT now(),
	"detached_at" timestamp
);
--> statement-breakpoint
CREATE TABLE "tabletop_exercises" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"title" text NOT NULL,
	"description" text,
	"status" text DEFAULT 'draft' NOT NULL,
	"scenario_type" text NOT NULL,
	"difficulty" text DEFAULT 'intermediate' NOT NULL,
	"ransomware_group" text,
	"scenario" jsonb,
	"injects" jsonb,
	"participants" jsonb,
	"findings" jsonb,
	"score" integer,
	"scheduled_at" timestamp,
	"started_at" timestamp,
	"completed_at" timestamp,
	"duration_minutes" integer,
	"facilitated_by" varchar,
	"after_action_report" text,
	"metadata" jsonb,
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
CREATE TABLE "tenant_data_jobs" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"job_type" text NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"format" text,
	"scope" jsonb DEFAULT '{}'::jsonb,
	"progress" integer DEFAULT 0,
	"total_records" integer DEFAULT 0,
	"processed_records" integer DEFAULT 0,
	"download_url" text,
	"error" text,
	"requested_by" text,
	"created_at" timestamp DEFAULT now(),
	"completed_at" timestamp
);
--> statement-breakpoint
CREATE TABLE "threat_hunts" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"query_type" text NOT NULL,
	"query_text" text NOT NULL,
	"compiled_query" text,
	"status" text DEFAULT 'draft' NOT NULL,
	"hypothesis" text,
	"mitre_techniques" jsonb DEFAULT '[]'::jsonb,
	"tags" jsonb DEFAULT '[]'::jsonb,
	"last_run_at" timestamp,
	"last_run_duration_ms" integer,
	"last_run_event_count" integer,
	"created_by" text,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
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
CREATE TABLE "threat_reports" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"reporter_user_id" varchar,
	"reporter_name" text,
	"reporter_email" text,
	"is_anonymous" boolean DEFAULT false NOT NULL,
	"category" text NOT NULL,
	"severity" text DEFAULT 'medium' NOT NULL,
	"title" text NOT NULL,
	"description" text NOT NULL,
	"date_occurred" timestamp,
	"location_description" text,
	"affected_systems" text,
	"suspect_info" text,
	"attachments" jsonb DEFAULT '[]'::jsonb,
	"status" text DEFAULT 'submitted' NOT NULL,
	"assigned_to" varchar,
	"linked_alert_id" varchar,
	"linked_incident_id" varchar,
	"resolution" text,
	"resolved_at" timestamp,
	"resolved_by" varchar,
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
CREATE TABLE "tiering_jobs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" text NOT NULL,
	"data_type" text NOT NULL,
	"source_tier" text NOT NULL,
	"target_tier" text NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"record_count" integer DEFAULT 0,
	"records_processed" integer DEFAULT 0,
	"compressed_size_bytes" bigint DEFAULT 0,
	"s3_key_prefix" text,
	"parquet_manifest" jsonb DEFAULT '{}'::jsonb,
	"error_message" text,
	"retention_policy_id" uuid,
	"started_at" timestamp,
	"completed_at" timestamp,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "tprm_assessments" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"vendor_id" text NOT NULL,
	"assessment_type" text DEFAULT 'security' NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"score" double precision DEFAULT 0,
	"findings" jsonb DEFAULT '[]'::jsonb,
	"questionnaire" jsonb DEFAULT '{}'::jsonb,
	"assessor_id" text,
	"due_date" timestamp,
	"completed_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "tprm_vendors" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"category" text,
	"tier" text DEFAULT 'standard' NOT NULL,
	"risk_rating" text DEFAULT 'medium',
	"overall_score" double precision DEFAULT 0,
	"security_score" double precision DEFAULT 0,
	"compliance_score" double precision DEFAULT 0,
	"data_access" jsonb DEFAULT '[]'::jsonb,
	"integrations" jsonb DEFAULT '[]'::jsonb,
	"contact_name" text,
	"contact_email" text,
	"contract_expiry" timestamp,
	"last_assessed_at" timestamp,
	"status" text DEFAULT 'active' NOT NULL,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "training_assignments" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"module_id" uuid NOT NULL,
	"employee_email" text NOT NULL,
	"employee_name" text,
	"assigned_reason" text,
	"assigned_at" timestamp DEFAULT now() NOT NULL,
	"due_at" timestamp,
	"started_at" timestamp,
	"completed_at" timestamp,
	"score" integer,
	"passed" boolean,
	"attempts" integer DEFAULT 0 NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "training_modules" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"title" text NOT NULL,
	"description" text,
	"module_type" text NOT NULL,
	"category" text NOT NULL,
	"difficulty" text DEFAULT 'beginner' NOT NULL,
	"duration_minutes" integer DEFAULT 15 NOT NULL,
	"content_url" text,
	"passing_score" integer DEFAULT 80,
	"is_built_in" boolean DEFAULT false NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"completion_count" integer DEFAULT 0 NOT NULL,
	"average_score" real,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "trust_center_artifacts" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"category" text NOT NULL,
	"title" text NOT NULL,
	"description" text DEFAULT '',
	"version" text DEFAULT '1.0',
	"file_name" text NOT NULL,
	"file_size" integer DEFAULT 0,
	"mime_type" text DEFAULT 'application/pdf',
	"uploaded_by" text NOT NULL,
	"uploaded_at" timestamp DEFAULT now(),
	"last_reviewed_at" timestamp,
	"next_review_due" timestamp,
	"freshness_sla_days" integer DEFAULT 180,
	"status" text DEFAULT 'current' NOT NULL,
	"access_level" text DEFAULT 'customer_only' NOT NULL,
	"download_count" integer DEFAULT 0,
	"tags" text[] DEFAULT ARRAY[]::text[],
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "trust_center_download_log" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"artifact_id" varchar NOT NULL,
	"user_id" text NOT NULL,
	"user_email" text,
	"ip_address" text,
	"user_agent" text,
	"downloaded_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "ttv_milestones" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"kind" varchar(50) NOT NULL,
	"label" text NOT NULL,
	"achieved_at" timestamp,
	"duration_from_signup_ms" integer,
	"triggered_by_action" text,
	"triggered_by_actor" text,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "ueba_anomalies" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"entity_type" text NOT NULL,
	"entity_id" text NOT NULL,
	"entity_name" text,
	"anomaly_type" text NOT NULL,
	"severity" text DEFAULT 'medium' NOT NULL,
	"risk_score" integer DEFAULT 0 NOT NULL,
	"description" text,
	"details" jsonb,
	"source_ip" text,
	"geo_location" text,
	"process_name" text,
	"alert_created" boolean DEFAULT false,
	"alert_id" varchar,
	"dismissed" boolean DEFAULT false,
	"dismissed_by" varchar,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "ueba_baselines" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"entity_type" text NOT NULL,
	"entity_id" text NOT NULL,
	"entity_name" text,
	"normal_login_hours_start" integer,
	"normal_login_hours_end" integer,
	"known_source_ips" text[] DEFAULT ARRAY[]::text[],
	"process_allow_list" text[] DEFAULT ARRAY[]::text[],
	"avg_daily_event_volume" real DEFAULT 0,
	"avg_daily_data_bytes" real DEFAULT 0,
	"baseline_window_days" integer DEFAULT 30 NOT NULL,
	"last_updated" timestamp DEFAULT now(),
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "ueba_entity_scores" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"entity_type" text NOT NULL,
	"entity_id" text NOT NULL,
	"entity_name" text,
	"risk_score" integer DEFAULT 0 NOT NULL,
	"risk_level" text DEFAULT 'none' NOT NULL,
	"anomaly_count" integer DEFAULT 0 NOT NULL,
	"last_anomaly_at" timestamp,
	"updated_at" timestamp DEFAULT now(),
	"created_at" timestamp DEFAULT now()
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
CREATE TABLE "usage_records" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"metric" text NOT NULL,
	"value" integer DEFAULT 0 NOT NULL,
	"period_start" timestamp NOT NULL,
	"period_end" timestamp NOT NULL,
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "vendor_assessments" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"vendor_id" varchar NOT NULL,
	"questionnaire_type" text DEFAULT 'custom' NOT NULL,
	"title" text NOT NULL,
	"status" text DEFAULT 'draft' NOT NULL,
	"sent_at" timestamp,
	"due_date" timestamp,
	"completed_at" timestamp,
	"respondent_name" text,
	"respondent_email" text,
	"total_questions" integer DEFAULT 0 NOT NULL,
	"answered_questions" integer DEFAULT 0 NOT NULL,
	"score" integer,
	"max_score" integer,
	"risk_rating" text,
	"findings" jsonb,
	"responses" jsonb,
	"attachments" text[],
	"reviewed_by" text,
	"reviewed_at" timestamp,
	"review_notes" text,
	"metadata" jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "vendor_breach_alerts" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"vendor_id" varchar NOT NULL,
	"title" text NOT NULL,
	"description" text NOT NULL,
	"source" text NOT NULL,
	"source_url" text,
	"breach_date" timestamp,
	"impact_assessment" text,
	"affected_data_types" text[],
	"severity" text DEFAULT 'high' NOT NULL,
	"status" text DEFAULT 'new' NOT NULL,
	"acknowledged_by" text,
	"acknowledged_at" timestamp,
	"response_actions" jsonb,
	"metadata" jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "vendor_monitoring" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"vendor_id" varchar NOT NULL,
	"check_type" text NOT NULL,
	"status" text DEFAULT 'ok' NOT NULL,
	"details" text,
	"previous_value" text,
	"current_value" text,
	"severity" text DEFAULT 'info' NOT NULL,
	"acknowledged" boolean DEFAULT false NOT NULL,
	"acknowledged_by" text,
	"acknowledged_at" timestamp,
	"metadata" jsonb,
	"checked_at" timestamp DEFAULT now(),
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "vendor_risks" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"vendor_id" varchar NOT NULL,
	"category" text NOT NULL,
	"title" text NOT NULL,
	"description" text NOT NULL,
	"severity" text DEFAULT 'medium' NOT NULL,
	"status" text DEFAULT 'open' NOT NULL,
	"source" text DEFAULT 'manual' NOT NULL,
	"evidence" text,
	"remediation" text,
	"mitigated_at" timestamp,
	"mitigated_by" text,
	"accepted_at" timestamp,
	"accepted_by" text,
	"acceptance_reason" text,
	"due_date" timestamp,
	"metadata" jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "vendors" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"domain" text,
	"website" text,
	"category" text DEFAULT 'other' NOT NULL,
	"description" text,
	"status" text DEFAULT 'active' NOT NULL,
	"risk_tier" text DEFAULT 'medium' NOT NULL,
	"overall_risk_score" integer,
	"security_score" integer,
	"compliance_certifications" text[],
	"data_access_level" text,
	"data_types" text[],
	"contract_start_date" timestamp,
	"contract_end_date" timestamp,
	"contract_value" integer,
	"primary_contact" text,
	"primary_contact_email" text,
	"security_contact" text,
	"security_contact_email" text,
	"fourth_party_vendors" jsonb,
	"review_cadence" text DEFAULT 'annually' NOT NULL,
	"last_review_date" timestamp,
	"next_review_date" timestamp,
	"onboarded_by" text,
	"notes" text,
	"metadata" jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "visitors" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"email" text,
	"company" text,
	"host_employee_name" text,
	"host_employee_email" text,
	"purpose" text,
	"status" text DEFAULT 'pre_registered' NOT NULL,
	"badge_number" text,
	"scheduled_at" timestamp,
	"checked_in_at" timestamp,
	"checked_out_at" timestamp,
	"areas_authorized" jsonb DEFAULT '[]'::jsonb,
	"correlated_events" jsonb DEFAULT '[]'::jsonb,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "vuln_findings" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"sensor_id" varchar,
	"source" text DEFAULT 'native_sensor' NOT NULL,
	"package_id" varchar,
	"cve_id" text NOT NULL,
	"package_name" text NOT NULL,
	"installed_version" text NOT NULL,
	"fixed_version" text,
	"severity" text DEFAULT 'medium' NOT NULL,
	"cvss_score" real,
	"description" text,
	"references" jsonb,
	"status" text DEFAULT 'open' NOT NULL,
	"acknowledged_by" varchar,
	"acknowledged_at" timestamp,
	"remediated_by" varchar,
	"remediated_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "vuln_packages" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"sensor_id" varchar NOT NULL,
	"package_manager" text NOT NULL,
	"package_name" text NOT NULL,
	"installed_version" text NOT NULL,
	"is_vulnerable" boolean DEFAULT false NOT NULL,
	"cve_count" integer DEFAULT 0 NOT NULL,
	"reported_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "vuln_scans" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"scan_type" text DEFAULT 'full' NOT NULL,
	"targets" jsonb DEFAULT '[]'::jsonb,
	"status" text DEFAULT 'pending' NOT NULL,
	"progress" integer DEFAULT 0,
	"findings_count" integer DEFAULT 0,
	"critical_count" integer DEFAULT 0,
	"high_count" integer DEFAULT 0,
	"medium_count" integer DEFAULT 0,
	"low_count" integer DEFAULT 0,
	"started_at" timestamp,
	"completed_at" timestamp,
	"scheduled_by" text,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "vulnerability_sla_targets" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"severity" text NOT NULL,
	"target_hours" integer NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "war_room_action_items" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"war_room_id" varchar NOT NULL,
	"org_id" varchar NOT NULL,
	"title" text NOT NULL,
	"assignee" text DEFAULT 'unassigned' NOT NULL,
	"assignee_id" varchar,
	"status" text DEFAULT 'pending' NOT NULL,
	"priority" text DEFAULT 'medium' NOT NULL,
	"due_at" timestamp,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"completed_at" timestamp
);
--> statement-breakpoint
CREATE TABLE "war_room_activity_log" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"war_room_id" varchar NOT NULL,
	"org_id" varchar NOT NULL,
	"action" text NOT NULL,
	"actor_id" varchar,
	"actor_name" text NOT NULL,
	"details" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "war_room_handoffs" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"war_room_id" varchar NOT NULL,
	"org_id" varchar NOT NULL,
	"from_user_id" varchar NOT NULL,
	"from_user_name" text NOT NULL,
	"to_user_id" varchar NOT NULL,
	"to_user_name" text NOT NULL,
	"summary" text NOT NULL,
	"open_actions" jsonb DEFAULT '[]'::jsonb,
	"key_findings" jsonb DEFAULT '[]'::jsonb,
	"next_steps" jsonb DEFAULT '[]'::jsonb,
	"status" text DEFAULT 'pending' NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"acknowledged_at" timestamp
);
--> statement-breakpoint
CREATE TABLE "war_room_messages" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"war_room_id" varchar NOT NULL,
	"org_id" varchar NOT NULL,
	"actor" text NOT NULL,
	"actor_id" varchar,
	"type" text DEFAULT 'message' NOT NULL,
	"content" text NOT NULL,
	"content_format" text DEFAULT 'plain' NOT NULL,
	"parent_message_id" varchar,
	"attachments" jsonb DEFAULT '[]'::jsonb,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "war_room_participants" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"war_room_id" varchar NOT NULL,
	"user_id" varchar NOT NULL,
	"display_name" text NOT NULL,
	"role" text DEFAULT 'responder' NOT NULL,
	"joined_at" timestamp DEFAULT now() NOT NULL,
	"left_at" timestamp
);
--> statement-breakpoint
CREATE TABLE "war_room_templates" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"incident_type" text NOT NULL,
	"severity" text DEFAULT 'high' NOT NULL,
	"channels" jsonb DEFAULT '[]'::jsonb,
	"checklist" jsonb DEFAULT '[]'::jsonb,
	"role_assignments" jsonb DEFAULT '[]'::jsonb,
	"is_built_in" boolean DEFAULT false NOT NULL,
	"created_by" varchar,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "war_rooms" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"incident_id" varchar NOT NULL,
	"name" text NOT NULL,
	"status" text DEFAULT 'active' NOT NULL,
	"severity" text DEFAULT 'high' NOT NULL,
	"commander" varchar NOT NULL,
	"commander_name" text DEFAULT 'Commander' NOT NULL,
	"slack_channel_id" text,
	"slack_channel_name" text,
	"teams_channel_id" text,
	"resolution" text,
	"template_id" varchar,
	"archived_at" timestamp,
	"archived_by" varchar,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"closed_at" timestamp,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "wizard_progress" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar,
	"user_id" varchar NOT NULL,
	"current_step" integer DEFAULT 0 NOT NULL,
	"completed_steps" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"skipped_steps" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"completed_at" timestamp,
	"tour_completed_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
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
CREATE TABLE "ztna_policies" (
	"id" varchar(36) PRIMARY KEY NOT NULL,
	"org_id" varchar(36) NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"enabled" boolean DEFAULT true NOT NULL,
	"priority" integer DEFAULT 100 NOT NULL,
	"conditions" jsonb NOT NULL,
	"action" text DEFAULT 'deny' NOT NULL,
	"require_mfa" boolean DEFAULT false,
	"allowed_platforms" jsonb,
	"min_os_version" jsonb,
	"require_encryption" boolean DEFAULT false,
	"require_mdm" boolean DEFAULT false,
	"require_screen_lock" boolean DEFAULT false,
	"block_rooted" boolean DEFAULT true,
	"max_risk_score" integer DEFAULT 70,
	"allowed_countries" jsonb,
	"blocked_countries" jsonb,
	"time_restrictions" jsonb,
	"created_by" varchar(36),
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "failed_login_attempts" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" varchar,
	"email" varchar NOT NULL,
	"ip_address" text NOT NULL,
	"user_agent" text,
	"reason" text NOT NULL,
	"attempted_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "impersonation_sessions" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"super_admin_id" varchar NOT NULL,
	"target_user_id" varchar NOT NULL,
	"session_sid" varchar NOT NULL,
	"expires_at" timestamp NOT NULL,
	"ended_at" timestamp,
	"created_at" timestamp DEFAULT now()
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
	"is_super_admin" boolean DEFAULT false NOT NULL,
	"disabled_at" timestamp,
	"last_login_at" timestamp,
	"password_changed_at" timestamp,
	"locked_until" timestamp,
	"failed_login_count" integer DEFAULT 0 NOT NULL,
	"mfa_enabled" boolean DEFAULT false NOT NULL,
	"mfa_secret" varchar,
	"mfa_verified_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	CONSTRAINT "users_email_unique" UNIQUE("email")
);
--> statement-breakpoint
ALTER TABLE "access_review_campaigns" ADD CONSTRAINT "access_review_campaigns_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "access_review_entitlements" ADD CONSTRAINT "access_review_entitlements_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "access_review_entitlements" ADD CONSTRAINT "access_review_entitlements_campaign_id_access_review_campaigns_id_fk" FOREIGN KEY ("campaign_id") REFERENCES "public"."access_review_campaigns"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_response_actions" ADD CONSTRAINT "agent_response_actions_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_response_actions" ADD CONSTRAINT "agent_response_actions_sensor_id_native_sensors_id_fk" FOREIGN KEY ("sensor_id") REFERENCES "public"."native_sensors"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ai_analyst_decisions" ADD CONSTRAINT "ai_analyst_decisions_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ai_analyst_decisions" ADD CONSTRAINT "ai_analyst_decisions_alert_id_alerts_id_fk" FOREIGN KEY ("alert_id") REFERENCES "public"."alerts"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ai_analyst_decisions" ADD CONSTRAINT "ai_analyst_decisions_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ai_generated_rules" ADD CONSTRAINT "ai_generated_rules_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ai_generated_rules" ADD CONSTRAINT "ai_generated_rules_source_incident_id_incidents_id_fk" FOREIGN KEY ("source_incident_id") REFERENCES "public"."incidents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alert_dedup_clusters" ADD CONSTRAINT "alert_dedup_clusters_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alert_dedup_clusters" ADD CONSTRAINT "alert_dedup_clusters_canonical_alert_id_alerts_id_fk" FOREIGN KEY ("canonical_alert_id") REFERENCES "public"."alerts"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alert_entities" ADD CONSTRAINT "alert_entities_alert_id_alerts_id_fk" FOREIGN KEY ("alert_id") REFERENCES "public"."alerts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alert_entities" ADD CONSTRAINT "alert_entities_entity_id_entities_id_fk" FOREIGN KEY ("entity_id") REFERENCES "public"."entities"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alert_tags" ADD CONSTRAINT "alert_tags_alert_id_alerts_id_fk" FOREIGN KEY ("alert_id") REFERENCES "public"."alerts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alert_tags" ADD CONSTRAINT "alert_tags_tag_id_tags_id_fk" FOREIGN KEY ("tag_id") REFERENCES "public"."tags"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "anomaly_subscriptions" ADD CONSTRAINT "anomaly_subscriptions_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "api_findings" ADD CONSTRAINT "api_findings_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "api_findings" ADD CONSTRAINT "api_findings_api_id_api_inventory_id_fk" FOREIGN KEY ("api_id") REFERENCES "public"."api_inventory"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "api_inventory" ADD CONSTRAINT "api_inventory_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "api_keys" ADD CONSTRAINT "api_keys_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "api_traffic_baselines" ADD CONSTRAINT "api_traffic_baselines_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "api_traffic_baselines" ADD CONSTRAINT "api_traffic_baselines_api_id_api_inventory_id_fk" FOREIGN KEY ("api_id") REFERENCES "public"."api_inventory"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "approval_decision_records" ADD CONSTRAINT "approval_decision_records_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "assessment_responses" ADD CONSTRAINT "assessment_responses_assessment_id_security_assessments_id_fk" FOREIGN KEY ("assessment_id") REFERENCES "public"."security_assessments"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "assessment_responses" ADD CONSTRAINT "assessment_responses_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "asset_inventory" ADD CONSTRAINT "asset_inventory_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "attack_graph_edges" ADD CONSTRAINT "attack_graph_edges_graph_id_attack_graphs_id_fk" FOREIGN KEY ("graph_id") REFERENCES "public"."attack_graphs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "attack_graph_nodes" ADD CONSTRAINT "attack_graph_nodes_graph_id_attack_graphs_id_fk" FOREIGN KEY ("graph_id") REFERENCES "public"."attack_graphs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "attack_graphs" ADD CONSTRAINT "attack_graphs_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "attack_graphs" ADD CONSTRAINT "attack_graphs_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "attack_paths" ADD CONSTRAINT "attack_paths_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "attack_paths" ADD CONSTRAINT "attack_paths_cluster_id_correlation_clusters_id_fk" FOREIGN KEY ("cluster_id") REFERENCES "public"."correlation_clusters"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "attack_surface_assets" ADD CONSTRAINT "attack_surface_assets_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_verification_runs" ADD CONSTRAINT "audit_verification_runs_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auto_response_policies" ADD CONSTRAINT "auto_response_policies_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "autonomy_log" ADD CONSTRAINT "autonomy_log_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "autonomy_log" ADD CONSTRAINT "autonomy_log_decision_id_ai_analyst_decisions_id_fk" FOREIGN KEY ("decision_id") REFERENCES "public"."ai_analyst_decisions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "backup_verifications" ADD CONSTRAINT "backup_verifications_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "badge_events" ADD CONSTRAINT "badge_events_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "badge_events" ADD CONSTRAINT "badge_events_asset_id_physical_assets_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."physical_assets"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "blast_radius_previews" ADD CONSTRAINT "blast_radius_previews_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "blast_radius_previews" ADD CONSTRAINT "blast_radius_previews_playbook_id_playbooks_id_fk" FOREIGN KEY ("playbook_id") REFERENCES "public"."playbooks"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "board_kpi_configs" ADD CONSTRAINT "board_kpi_configs_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "breach_monitoring_targets" ADD CONSTRAINT "breach_monitoring_targets_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "campaigns" ADD CONSTRAINT "campaigns_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "canary_tokens" ADD CONSTRAINT "canary_tokens_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "chaos_schedules" ADD CONSTRAINT "chaos_schedules_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "chaos_simulations" ADD CONSTRAINT "chaos_simulations_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ci_gates" ADD CONSTRAINT "ci_gates_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "code_review_findings" ADD CONSTRAINT "code_review_findings_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "collector_events" ADD CONSTRAINT "collector_events_collector_id_collector_instances_id_fk" FOREIGN KEY ("collector_id") REFERENCES "public"."collector_instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "collector_events" ADD CONSTRAINT "collector_events_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "collector_instances" ADD CONSTRAINT "collector_instances_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "collector_scans" ADD CONSTRAINT "collector_scans_collector_id_collector_instances_id_fk" FOREIGN KEY ("collector_id") REFERENCES "public"."collector_instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "collector_scans" ADD CONSTRAINT "collector_scans_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "community_hunt_shares" ADD CONSTRAINT "community_hunt_shares_hunt_id_threat_hunts_id_fk" FOREIGN KEY ("hunt_id") REFERENCES "public"."threat_hunts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "compliance_control_mappings" ADD CONSTRAINT "compliance_control_mappings_control_id_compliance_controls_id_fk" FOREIGN KEY ("control_id") REFERENCES "public"."compliance_controls"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "compliance_policies" ADD CONSTRAINT "compliance_policies_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "connector_health_checks" ADD CONSTRAINT "connector_health_checks_connector_id_connectors_id_fk" FOREIGN KEY ("connector_id") REFERENCES "public"."connectors"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "connector_job_runs" ADD CONSTRAINT "connector_job_runs_connector_id_connectors_id_fk" FOREIGN KEY ("connector_id") REFERENCES "public"."connectors"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "connector_secret_rotations" ADD CONSTRAINT "connector_secret_rotations_connector_id_connectors_id_fk" FOREIGN KEY ("connector_id") REFERENCES "public"."connectors"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "connectors" ADD CONSTRAINT "connectors_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "consent_records" ADD CONSTRAINT "consent_records_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control_effectiveness" ADD CONSTRAINT "control_effectiveness_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "correlation_clusters" ADD CONSTRAINT "correlation_clusters_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "correlation_clusters" ADD CONSTRAINT "correlation_clusters_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cross_border_transfer_alerts" ADD CONSTRAINT "cross_border_transfer_alerts_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cross_border_transfer_alerts" ADD CONSTRAINT "cross_border_transfer_alerts_data_flow_id_data_flows_id_fk" FOREIGN KEY ("data_flow_id") REFERENCES "public"."data_flows"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "crypto_inventory" ADD CONSTRAINT "crypto_inventory_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cspm_scans" ADD CONSTRAINT "cspm_scans_account_id_cspm_accounts_id_fk" FOREIGN KEY ("account_id") REFERENCES "public"."cspm_accounts"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dark_web_exposures" ADD CONSTRAINT "dark_web_exposures_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dark_web_exposures" ADD CONSTRAINT "dark_web_exposures_target_id_breach_monitoring_targets_id_fk" FOREIGN KEY ("target_id") REFERENCES "public"."breach_monitoring_targets"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dark_web_monitoring_config" ADD CONSTRAINT "dark_web_monitoring_config_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dark_web_scan_history" ADD CONSTRAINT "dark_web_scan_history_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "data_assets" ADD CONSTRAINT "data_assets_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "data_flows" ADD CONSTRAINT "data_flows_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "data_flows" ADD CONSTRAINT "data_flows_source_asset_id_data_assets_id_fk" FOREIGN KEY ("source_asset_id") REFERENCES "public"."data_assets"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "data_flows" ADD CONSTRAINT "data_flows_destination_asset_id_data_assets_id_fk" FOREIGN KEY ("destination_asset_id") REFERENCES "public"."data_assets"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "deception_hits" ADD CONSTRAINT "deception_hits_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "deception_hits" ADD CONSTRAINT "deception_hits_canary_token_id_canary_tokens_id_fk" FOREIGN KEY ("canary_token_id") REFERENCES "public"."canary_tokens"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "deception_hits" ADD CONSTRAINT "deception_hits_honeypot_asset_id_honeypot_assets_id_fk" FOREIGN KEY ("honeypot_asset_id") REFERENCES "public"."honeypot_assets"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "deception_hits" ADD CONSTRAINT "deception_hits_alert_id_alerts_id_fk" FOREIGN KEY ("alert_id") REFERENCES "public"."alerts"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "deception_hits" ADD CONSTRAINT "deception_hits_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dependency_graph" ADD CONSTRAINT "dependency_graph_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dependency_graph" ADD CONSTRAINT "dependency_graph_sbom_id_sbom_artifacts_id_fk" FOREIGN KEY ("sbom_id") REFERENCES "public"."sbom_artifacts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "detection_alerts" ADD CONSTRAINT "detection_alerts_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "detection_alerts" ADD CONSTRAINT "detection_alerts_rule_id_detection_rules_id_fk" FOREIGN KEY ("rule_id") REFERENCES "public"."detection_rules"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "detection_alerts" ADD CONSTRAINT "detection_alerts_sensor_id_native_sensors_id_fk" FOREIGN KEY ("sensor_id") REFERENCES "public"."native_sensors"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "detection_alerts" ADD CONSTRAINT "detection_alerts_event_id_sensor_events_id_fk" FOREIGN KEY ("event_id") REFERENCES "public"."sensor_events"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "detection_gaps" ADD CONSTRAINT "detection_gaps_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "detection_rules" ADD CONSTRAINT "detection_rules_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dns_events" ADD CONSTRAINT "dns_events_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dns_findings" ADD CONSTRAINT "dns_findings_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dr_drill_results" ADD CONSTRAINT "dr_drill_results_runbook_id_dr_runbooks_id_fk" FOREIGN KEY ("runbook_id") REFERENCES "public"."dr_runbooks"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dsar_fulfillment_tasks" ADD CONSTRAINT "dsar_fulfillment_tasks_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dsar_fulfillment_tasks" ADD CONSTRAINT "dsar_fulfillment_tasks_dsar_request_id_dsar_requests_id_fk" FOREIGN KEY ("dsar_request_id") REFERENCES "public"."dsar_requests"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dsar_fulfillment_tasks" ADD CONSTRAINT "dsar_fulfillment_tasks_target_asset_id_data_assets_id_fk" FOREIGN KEY ("target_asset_id") REFERENCES "public"."data_assets"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dsar_requests" ADD CONSTRAINT "dsar_requests_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "email_findings" ADD CONSTRAINT "email_findings_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "email_messages" ADD CONSTRAINT "email_messages_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "email_policies" ADD CONSTRAINT "email_policies_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "email_quarantine_items" ADD CONSTRAINT "email_quarantine_items_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "email_url_rewrites" ADD CONSTRAINT "email_url_rewrites_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "employee_risk_scores" ADD CONSTRAINT "employee_risk_scores_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "endpoint_telemetry" ADD CONSTRAINT "endpoint_telemetry_asset_id_endpoint_assets_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."endpoint_assets"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "engine_configs" ADD CONSTRAINT "engine_configs_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "engine_dry_runs" ADD CONSTRAINT "engine_dry_runs_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "engine_explainability_logs" ADD CONSTRAINT "engine_explainability_logs_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "entities" ADD CONSTRAINT "entities_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "entity_aliases" ADD CONSTRAINT "entity_aliases_entity_id_entities_id_fk" FOREIGN KEY ("entity_id") REFERENCES "public"."entities"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "entity_merge_history" ADD CONSTRAINT "entity_merge_history_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "evidence_attachments" ADD CONSTRAINT "evidence_attachments_control_mapping_id_compliance_control_mappings_id_fk" FOREIGN KEY ("control_mapping_id") REFERENCES "public"."compliance_control_mappings"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "evidence_attachments" ADD CONSTRAINT "evidence_attachments_evidence_locker_id_evidence_locker_items_id_fk" FOREIGN KEY ("evidence_locker_id") REFERENCES "public"."evidence_locker_items"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "evidence_chain_entries" ADD CONSTRAINT "evidence_chain_entries_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "evidence_chain_entries" ADD CONSTRAINT "evidence_chain_entries_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "evidence_items" ADD CONSTRAINT "evidence_items_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "evidence_items" ADD CONSTRAINT "evidence_items_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "forecast_quality_snapshots" ADD CONSTRAINT "forecast_quality_snapshots_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hardening_recommendations" ADD CONSTRAINT "hardening_recommendations_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "honeypot_assets" ADD CONSTRAINT "honeypot_assets_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hunt_collaborations" ADD CONSTRAINT "hunt_collaborations_hunt_id_threat_hunts_id_fk" FOREIGN KEY ("hunt_id") REFERENCES "public"."threat_hunts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hunt_library" ADD CONSTRAINT "hunt_library_hunt_id_threat_hunts_id_fk" FOREIGN KEY ("hunt_id") REFERENCES "public"."threat_hunts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hunt_results" ADD CONSTRAINT "hunt_results_hunt_id_threat_hunts_id_fk" FOREIGN KEY ("hunt_id") REFERENCES "public"."threat_hunts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hunt_results" ADD CONSTRAINT "hunt_results_linked_incident_id_incidents_id_fk" FOREIGN KEY ("linked_incident_id") REFERENCES "public"."incidents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hunt_schedule_drifts" ADD CONSTRAINT "hunt_schedule_drifts_schedule_id_hunt_schedules_id_fk" FOREIGN KEY ("schedule_id") REFERENCES "public"."hunt_schedules"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hunt_schedule_drifts" ADD CONSTRAINT "hunt_schedule_drifts_hunt_id_threat_hunts_id_fk" FOREIGN KEY ("hunt_id") REFERENCES "public"."threat_hunts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hunt_schedules" ADD CONSTRAINT "hunt_schedules_hunt_id_threat_hunts_id_fk" FOREIGN KEY ("hunt_id") REFERENCES "public"."threat_hunts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_access_graph" ADD CONSTRAINT "identity_access_graph_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_risk_profiles" ADD CONSTRAINT "identity_risk_profiles_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incident_comments" ADD CONSTRAINT "incident_comments_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incident_response_approvals" ADD CONSTRAINT "incident_response_approvals_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incident_response_approvals" ADD CONSTRAINT "incident_response_approvals_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incident_sla_policies" ADD CONSTRAINT "incident_sla_policies_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incident_tags" ADD CONSTRAINT "incident_tags_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incident_tags" ADD CONSTRAINT "incident_tags_tag_id_tags_id_fk" FOREIGN KEY ("tag_id") REFERENCES "public"."tags"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incidents" ADD CONSTRAINT "incidents_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "industrial_protocol_events" ADD CONSTRAINT "industrial_protocol_events_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "industrial_protocol_events" ADD CONSTRAINT "industrial_protocol_events_asset_id_ot_assets_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."ot_assets"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "industrial_protocol_events" ADD CONSTRAINT "industrial_protocol_events_anomaly_id_ot_anomalies_id_fk" FOREIGN KEY ("anomaly_id") REFERENCES "public"."ot_anomalies"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ingestion_logs" ADD CONSTRAINT "ingestion_logs_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "integration_configs" ADD CONSTRAINT "integration_configs_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_chat_messages" ADD CONSTRAINT "investigation_chat_messages_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_chat_messages" ADD CONSTRAINT "investigation_chat_messages_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_hypotheses" ADD CONSTRAINT "investigation_hypotheses_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_hypotheses" ADD CONSTRAINT "investigation_hypotheses_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_runs" ADD CONSTRAINT "investigation_runs_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_runs" ADD CONSTRAINT "investigation_runs_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_steps" ADD CONSTRAINT "investigation_steps_run_id_investigation_runs_id_fk" FOREIGN KEY ("run_id") REFERENCES "public"."investigation_runs"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_tasks" ADD CONSTRAINT "investigation_tasks_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_tasks" ADD CONSTRAINT "investigation_tasks_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "invoices" ADD CONSTRAINT "invoices_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "invoices" ADD CONSTRAINT "invoices_subscription_id_subscriptions_id_fk" FOREIGN KEY ("subscription_id") REFERENCES "public"."subscriptions"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ioc_entries" ADD CONSTRAINT "ioc_entries_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ioc_entries" ADD CONSTRAINT "ioc_entries_feed_id_ioc_feeds_id_fk" FOREIGN KEY ("feed_id") REFERENCES "public"."ioc_feeds"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ioc_feeds" ADD CONSTRAINT "ioc_feeds_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ioc_match_rules" ADD CONSTRAINT "ioc_match_rules_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ioc_match_rules" ADD CONSTRAINT "ioc_match_rules_feed_id_ioc_feeds_id_fk" FOREIGN KEY ("feed_id") REFERENCES "public"."ioc_feeds"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ioc_matches" ADD CONSTRAINT "ioc_matches_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ioc_matches" ADD CONSTRAINT "ioc_matches_rule_id_ioc_match_rules_id_fk" FOREIGN KEY ("rule_id") REFERENCES "public"."ioc_match_rules"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ioc_matches" ADD CONSTRAINT "ioc_matches_ioc_entry_id_ioc_entries_id_fk" FOREIGN KEY ("ioc_entry_id") REFERENCES "public"."ioc_entries"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ioc_matches" ADD CONSTRAINT "ioc_matches_alert_id_alerts_id_fk" FOREIGN KEY ("alert_id") REFERENCES "public"."alerts"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ioc_matches" ADD CONSTRAINT "ioc_matches_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ioc_matches" ADD CONSTRAINT "ioc_matches_entity_id_entities_id_fk" FOREIGN KEY ("entity_id") REFERENCES "public"."entities"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ioc_watchlist_entries" ADD CONSTRAINT "ioc_watchlist_entries_watchlist_id_ioc_watchlists_id_fk" FOREIGN KEY ("watchlist_id") REFERENCES "public"."ioc_watchlists"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ioc_watchlist_entries" ADD CONSTRAINT "ioc_watchlist_entries_ioc_entry_id_ioc_entries_id_fk" FOREIGN KEY ("ioc_entry_id") REFERENCES "public"."ioc_entries"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ioc_watchlists" ADD CONSTRAINT "ioc_watchlists_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "log_sources" ADD CONSTRAINT "log_sources_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "log_sources" ADD CONSTRAINT "log_sources_sensor_id_native_sensors_id_fk" FOREIGN KEY ("sensor_id") REFERENCES "public"."native_sensors"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "marketplace_dead_letters" ADD CONSTRAINT "marketplace_dead_letters_instance_id_marketplace_instances_id_fk" FOREIGN KEY ("instance_id") REFERENCES "public"."marketplace_instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "marketplace_sync_history" ADD CONSTRAINT "marketplace_sync_history_instance_id_marketplace_instances_id_fk" FOREIGN KEY ("instance_id") REFERENCES "public"."marketplace_instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "marketplace_webhook_events" ADD CONSTRAINT "marketplace_webhook_events_instance_id_marketplace_instances_id_fk" FOREIGN KEY ("instance_id") REFERENCES "public"."marketplace_instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "mssp_access_grants" ADD CONSTRAINT "mssp_access_grants_parent_org_id_organizations_id_fk" FOREIGN KEY ("parent_org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "mssp_access_grants" ADD CONSTRAINT "mssp_access_grants_child_org_id_organizations_id_fk" FOREIGN KEY ("child_org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "mssp_billing_records" ADD CONSTRAINT "mssp_billing_records_parent_org_id_organizations_id_fk" FOREIGN KEY ("parent_org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "mssp_billing_records" ADD CONSTRAINT "mssp_billing_records_child_org_id_organizations_id_fk" FOREIGN KEY ("child_org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "mssp_client_onboarding" ADD CONSTRAINT "mssp_client_onboarding_parent_org_id_organizations_id_fk" FOREIGN KEY ("parent_org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "mssp_client_onboarding" ADD CONSTRAINT "mssp_client_onboarding_child_org_id_organizations_id_fk" FOREIGN KEY ("child_org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "mssp_client_slas" ADD CONSTRAINT "mssp_client_slas_parent_org_id_organizations_id_fk" FOREIGN KEY ("parent_org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "mssp_client_slas" ADD CONSTRAINT "mssp_client_slas_child_org_id_organizations_id_fk" FOREIGN KEY ("child_org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "mssp_sla_breaches" ADD CONSTRAINT "mssp_sla_breaches_sla_id_mssp_client_slas_id_fk" FOREIGN KEY ("sla_id") REFERENCES "public"."mssp_client_slas"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "mssp_white_label_configs" ADD CONSTRAINT "mssp_white_label_configs_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "native_sensors" ADD CONSTRAINT "native_sensors_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "notification_channels" ADD CONSTRAINT "notification_channels_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "notification_delivery_log" ADD CONSTRAINT "notification_delivery_log_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "notification_user_preferences" ADD CONSTRAINT "notification_user_preferences_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
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
ALTER TABLE "ot_anomalies" ADD CONSTRAINT "ot_anomalies_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ot_anomalies" ADD CONSTRAINT "ot_anomalies_asset_id_ot_assets_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."ot_assets"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ot_anomalies" ADD CONSTRAINT "ot_anomalies_connection_id_ot_connections_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."ot_connections"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ot_anomalies" ADD CONSTRAINT "ot_anomalies_alert_id_alerts_id_fk" FOREIGN KEY ("alert_id") REFERENCES "public"."alerts"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ot_assets" ADD CONSTRAINT "ot_assets_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ot_connections" ADD CONSTRAINT "ot_connections_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ot_connections" ADD CONSTRAINT "ot_connections_source_asset_id_ot_assets_id_fk" FOREIGN KEY ("source_asset_id") REFERENCES "public"."ot_assets"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ot_connections" ADD CONSTRAINT "ot_connections_dest_asset_id_ot_assets_id_fk" FOREIGN KEY ("dest_asset_id") REFERENCES "public"."ot_assets"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "outbound_webhook_logs" ADD CONSTRAINT "outbound_webhook_logs_webhook_id_outbound_webhooks_id_fk" FOREIGN KEY ("webhook_id") REFERENCES "public"."outbound_webhooks"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "pam_sessions" ADD CONSTRAINT "pam_sessions_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "passive_dns_records" ADD CONSTRAINT "passive_dns_records_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "phishing_campaigns" ADD CONSTRAINT "phishing_campaigns_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "phishing_results" ADD CONSTRAINT "phishing_results_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "phishing_results" ADD CONSTRAINT "phishing_results_campaign_id_phishing_campaigns_id_fk" FOREIGN KEY ("campaign_id") REFERENCES "public"."phishing_campaigns"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "phishing_templates" ADD CONSTRAINT "phishing_templates_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "physical_assets" ADD CONSTRAINT "physical_assets_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "physical_incidents" ADD CONSTRAINT "physical_incidents_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "physical_security_config" ADD CONSTRAINT "physical_security_config_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
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
ALTER TABLE "privacy_impact_assessments" ADD CONSTRAINT "privacy_impact_assessments_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "privacy_scans" ADD CONSTRAINT "privacy_scans_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "privacy_scans" ADD CONSTRAINT "privacy_scans_target_asset_id_data_assets_id_fk" FOREIGN KEY ("target_asset_id") REFERENCES "public"."data_assets"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "purple_team_exercises" ADD CONSTRAINT "purple_team_exercises_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "quantum_migration_tasks" ADD CONSTRAINT "quantum_migration_tasks_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "quantum_migration_tasks" ADD CONSTRAINT "quantum_migration_tasks_crypto_inventory_id_crypto_inventory_id_fk" FOREIGN KEY ("crypto_inventory_id") REFERENCES "public"."crypto_inventory"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "quantum_risk_scores" ADD CONSTRAINT "quantum_risk_scores_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "quantum_scan_history" ADD CONSTRAINT "quantum_scan_history_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ransomware_canary_files" ADD CONSTRAINT "ransomware_canary_files_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ransomware_groups" ADD CONSTRAINT "ransomware_groups_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ransomware_kill_switch_events" ADD CONSTRAINT "ransomware_kill_switch_events_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "recovery_runbooks" ADD CONSTRAINT "recovery_runbooks_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "report_runs" ADD CONSTRAINT "report_runs_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "report_runs" ADD CONSTRAINT "report_runs_template_id_report_templates_id_fk" FOREIGN KEY ("template_id") REFERENCES "public"."report_templates"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "report_runs" ADD CONSTRAINT "report_runs_schedule_id_report_schedules_id_fk" FOREIGN KEY ("schedule_id") REFERENCES "public"."report_schedules"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "report_schedules" ADD CONSTRAINT "report_schedules_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "report_schedules" ADD CONSTRAINT "report_schedules_template_id_report_templates_id_fk" FOREIGN KEY ("template_id") REFERENCES "public"."report_templates"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "report_template_versions" ADD CONSTRAINT "report_template_versions_template_id_report_templates_id_fk" FOREIGN KEY ("template_id") REFERENCES "public"."report_templates"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "report_templates" ADD CONSTRAINT "report_templates_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "response_action_approvals" ADD CONSTRAINT "response_action_approvals_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "response_action_rollbacks" ADD CONSTRAINT "response_action_rollbacks_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "response_actions" ADD CONSTRAINT "response_actions_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "response_actions" ADD CONSTRAINT "response_actions_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "risk_forecasts" ADD CONSTRAINT "risk_forecasts_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "risk_register" ADD CONSTRAINT "risk_register_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rule_ab_tests" ADD CONSTRAINT "rule_ab_tests_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rule_generation_jobs" ADD CONSTRAINT "rule_generation_jobs_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rule_lifecycle_events" ADD CONSTRAINT "rule_lifecycle_events_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rule_marketplace" ADD CONSTRAINT "rule_marketplace_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "runbook_steps" ADD CONSTRAINT "runbook_steps_template_id_runbook_templates_id_fk" FOREIGN KEY ("template_id") REFERENCES "public"."runbook_templates"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "runbook_templates" ADD CONSTRAINT "runbook_templates_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sast_findings" ADD CONSTRAINT "sast_findings_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "saved_views" ADD CONSTRAINT "saved_views_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "saved_views" ADD CONSTRAINT "saved_views_team_id_org_teams_id_fk" FOREIGN KEY ("team_id") REFERENCES "public"."org_teams"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sbom_artifacts" ADD CONSTRAINT "sbom_artifacts_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scim_provisioning_logs" ADD CONSTRAINT "scim_provisioning_logs_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "secrets_exposed" ADD CONSTRAINT "secrets_exposed_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "security_assessments" ADD CONSTRAINT "security_assessments_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "security_awareness_config" ADD CONSTRAINT "security_awareness_config_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "security_debt_items" ADD CONSTRAINT "security_debt_items_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "security_graph_relationships" ADD CONSTRAINT "security_graph_relationships_source_id_security_graph_assets_id_fk" FOREIGN KEY ("source_id") REFERENCES "public"."security_graph_assets"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "security_graph_relationships" ADD CONSTRAINT "security_graph_relationships_target_id_security_graph_assets_id_fk" FOREIGN KEY ("target_id") REFERENCES "public"."security_graph_assets"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "security_kpi_snapshots" ADD CONSTRAINT "security_kpi_snapshots_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "security_tool_overlaps" ADD CONSTRAINT "security_tool_overlaps_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sensor_events" ADD CONSTRAINT "sensor_events_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sensor_events" ADD CONSTRAINT "sensor_events_sensor_id_native_sensors_id_fk" FOREIGN KEY ("sensor_id") REFERENCES "public"."native_sensors"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sinkholed_domains" ADD CONSTRAINT "sinkholed_domains_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "subscriptions" ADD CONSTRAINT "subscriptions_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "subscriptions" ADD CONSTRAINT "subscriptions_plan_id_plans_id_fk" FOREIGN KEY ("plan_id") REFERENCES "public"."plans"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "supply_chain_findings" ADD CONSTRAINT "supply_chain_findings_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "supply_chain_findings" ADD CONSTRAINT "supply_chain_findings_sbom_id_sbom_artifacts_id_fk" FOREIGN KEY ("sbom_id") REFERENCES "public"."sbom_artifacts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "supply_chain_findings" ADD CONSTRAINT "supply_chain_findings_dependency_id_dependency_graph_id_fk" FOREIGN KEY ("dependency_id") REFERENCES "public"."dependency_graph"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "suppression_rules" ADD CONSTRAINT "suppression_rules_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tabletop_exercises" ADD CONSTRAINT "tabletop_exercises_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "threat_intel_configs" ADD CONSTRAINT "threat_intel_configs_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "threat_reports" ADD CONSTRAINT "threat_reports_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ticket_sync_jobs" ADD CONSTRAINT "ticket_sync_jobs_integration_id_integration_configs_id_fk" FOREIGN KEY ("integration_id") REFERENCES "public"."integration_configs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ticket_sync_jobs" ADD CONSTRAINT "ticket_sync_jobs_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "training_assignments" ADD CONSTRAINT "training_assignments_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "training_assignments" ADD CONSTRAINT "training_assignments_module_id_training_modules_id_fk" FOREIGN KEY ("module_id") REFERENCES "public"."training_modules"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "training_modules" ADD CONSTRAINT "training_modules_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "trust_center_download_log" ADD CONSTRAINT "trust_center_download_log_artifact_id_trust_center_artifacts_id_fk" FOREIGN KEY ("artifact_id") REFERENCES "public"."trust_center_artifacts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ueba_anomalies" ADD CONSTRAINT "ueba_anomalies_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ueba_baselines" ADD CONSTRAINT "ueba_baselines_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ueba_entity_scores" ADD CONSTRAINT "ueba_entity_scores_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "usage_meter_snapshots" ADD CONSTRAINT "usage_meter_snapshots_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "usage_records" ADD CONSTRAINT "usage_records_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vendor_assessments" ADD CONSTRAINT "vendor_assessments_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vendor_assessments" ADD CONSTRAINT "vendor_assessments_vendor_id_vendors_id_fk" FOREIGN KEY ("vendor_id") REFERENCES "public"."vendors"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vendor_breach_alerts" ADD CONSTRAINT "vendor_breach_alerts_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vendor_breach_alerts" ADD CONSTRAINT "vendor_breach_alerts_vendor_id_vendors_id_fk" FOREIGN KEY ("vendor_id") REFERENCES "public"."vendors"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vendor_monitoring" ADD CONSTRAINT "vendor_monitoring_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vendor_monitoring" ADD CONSTRAINT "vendor_monitoring_vendor_id_vendors_id_fk" FOREIGN KEY ("vendor_id") REFERENCES "public"."vendors"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vendor_risks" ADD CONSTRAINT "vendor_risks_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vendor_risks" ADD CONSTRAINT "vendor_risks_vendor_id_vendors_id_fk" FOREIGN KEY ("vendor_id") REFERENCES "public"."vendors"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vendors" ADD CONSTRAINT "vendors_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "visitors" ADD CONSTRAINT "visitors_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vuln_findings" ADD CONSTRAINT "vuln_findings_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vuln_findings" ADD CONSTRAINT "vuln_findings_sensor_id_native_sensors_id_fk" FOREIGN KEY ("sensor_id") REFERENCES "public"."native_sensors"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vuln_findings" ADD CONSTRAINT "vuln_findings_package_id_vuln_packages_id_fk" FOREIGN KEY ("package_id") REFERENCES "public"."vuln_packages"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vuln_packages" ADD CONSTRAINT "vuln_packages_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vuln_packages" ADD CONSTRAINT "vuln_packages_sensor_id_native_sensors_id_fk" FOREIGN KEY ("sensor_id") REFERENCES "public"."native_sensors"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vulnerability_sla_targets" ADD CONSTRAINT "vulnerability_sla_targets_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "war_room_action_items" ADD CONSTRAINT "war_room_action_items_war_room_id_war_rooms_id_fk" FOREIGN KEY ("war_room_id") REFERENCES "public"."war_rooms"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "war_room_action_items" ADD CONSTRAINT "war_room_action_items_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "war_room_activity_log" ADD CONSTRAINT "war_room_activity_log_war_room_id_war_rooms_id_fk" FOREIGN KEY ("war_room_id") REFERENCES "public"."war_rooms"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "war_room_activity_log" ADD CONSTRAINT "war_room_activity_log_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "war_room_handoffs" ADD CONSTRAINT "war_room_handoffs_war_room_id_war_rooms_id_fk" FOREIGN KEY ("war_room_id") REFERENCES "public"."war_rooms"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "war_room_handoffs" ADD CONSTRAINT "war_room_handoffs_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "war_room_messages" ADD CONSTRAINT "war_room_messages_war_room_id_war_rooms_id_fk" FOREIGN KEY ("war_room_id") REFERENCES "public"."war_rooms"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "war_room_messages" ADD CONSTRAINT "war_room_messages_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "war_room_participants" ADD CONSTRAINT "war_room_participants_war_room_id_war_rooms_id_fk" FOREIGN KEY ("war_room_id") REFERENCES "public"."war_rooms"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "war_room_templates" ADD CONSTRAINT "war_room_templates_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "war_rooms" ADD CONSTRAINT "war_rooms_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "war_rooms" ADD CONSTRAINT "war_rooms_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wizard_progress" ADD CONSTRAINT "wizard_progress_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "failed_login_attempts" ADD CONSTRAINT "failed_login_attempts_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "impersonation_sessions" ADD CONSTRAINT "impersonation_sessions_super_admin_id_users_id_fk" FOREIGN KEY ("super_admin_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "impersonation_sessions" ADD CONSTRAINT "impersonation_sessions_target_user_id_users_id_fk" FOREIGN KEY ("target_user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_arc_org" ON "access_review_campaigns" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_arc_status" ON "access_review_campaigns" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_are_org" ON "access_review_entitlements" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_are_campaign" ON "access_review_entitlements" USING btree ("campaign_id");--> statement-breakpoint
CREATE INDEX "idx_are_user" ON "access_review_entitlements" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "idx_are_status" ON "access_review_entitlements" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_accessrev_org" ON "access_reviews" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_accessrev_status" ON "access_reviews" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_ar_org" ON "adversarial_remediations" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ar_status" ON "adversarial_remediations" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_ate_org" ON "adversarial_test_executions" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ate_status" ON "adversarial_test_executions" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_ate_domain" ON "adversarial_test_executions" USING btree ("org_id","domain");--> statement-breakpoint
CREATE INDEX "idx_ate_testcase" ON "adversarial_test_executions" USING btree ("org_id","test_case_id");--> statement-breakpoint
CREATE INDEX "idx_ats_org" ON "adversarial_test_schedules" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ats_enabled" ON "adversarial_test_schedules" USING btree ("org_id","enabled");--> statement-breakpoint
CREATE INDEX "idx_agent_actions_org" ON "agent_response_actions" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_agent_actions_sensor" ON "agent_response_actions" USING btree ("sensor_id");--> statement-breakpoint
CREATE INDEX "idx_agent_actions_status" ON "agent_response_actions" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_agent_actions_type" ON "agent_response_actions" USING btree ("org_id","action_type");--> statement-breakpoint
CREATE INDEX "idx_agent_actions_created" ON "agent_response_actions" USING btree ("org_id","created_at");--> statement-breakpoint
CREATE INDEX "idx_ata_org" ON "agent_tool_anomalies" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ata_type" ON "agent_tool_anomalies" USING btree ("org_id","anomaly_type");--> statement-breakpoint
CREATE INDEX "idx_ata_ack" ON "agent_tool_anomalies" USING btree ("org_id","acknowledged");--> statement-breakpoint
CREATE INDEX "idx_ati_org" ON "agent_tool_invocations" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ati_tool" ON "agent_tool_invocations" USING btree ("org_id","tool_id");--> statement-breakpoint
CREATE INDEX "idx_ati_agent" ON "agent_tool_invocations" USING btree ("org_id","agent_id");--> statement-breakpoint
CREATE INDEX "idx_ati_verdict" ON "agent_tool_invocations" USING btree ("org_id","verdict");--> statement-breakpoint
CREATE INDEX "idx_atp_org" ON "agent_tool_policies" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_atp_tool" ON "agent_tool_policies" USING btree ("org_id","tool_id");--> statement-breakpoint
CREATE INDEX "idx_atbr_org" ON "agent_trust_boundary_rules" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_atbr_source" ON "agent_trust_boundary_rules" USING btree ("org_id","source_boundary");--> statement-breakpoint
CREATE INDEX "idx_ai_decisions_org" ON "ai_analyst_decisions" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ai_decisions_alert" ON "ai_analyst_decisions" USING btree ("alert_id");--> statement-breakpoint
CREATE INDEX "idx_ai_decisions_incident" ON "ai_analyst_decisions" USING btree ("incident_id");--> statement-breakpoint
CREATE INDEX "idx_ai_decisions_tier" ON "ai_analyst_decisions" USING btree ("org_id","tier");--> statement-breakpoint
CREATE INDEX "idx_ai_decisions_outcome" ON "ai_analyst_decisions" USING btree ("org_id","outcome");--> statement-breakpoint
CREATE INDEX "idx_ai_decisions_status" ON "ai_analyst_decisions" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_ai_decisions_created" ON "ai_analyst_decisions" USING btree ("org_id","created_at");--> statement-breakpoint
CREATE INDEX "idx_ai_feedback_org" ON "ai_feedback" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ai_feedback_resource" ON "ai_feedback" USING btree ("resource_type","resource_id");--> statement-breakpoint
CREATE INDEX "idx_ai_feedback_created" ON "ai_feedback" USING btree ("created_at");--> statement-breakpoint
CREATE INDEX "idx_ai_rules_org" ON "ai_generated_rules" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ai_rules_incident" ON "ai_generated_rules" USING btree ("source_incident_id");--> statement-breakpoint
CREATE INDEX "idx_ai_rules_status" ON "ai_generated_rules" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_ai_inference_log_tier" ON "ai_inference_log" USING btree ("tier");--> statement-breakpoint
CREATE INDEX "idx_ai_inference_log_created" ON "ai_inference_log" USING btree ("created_at");--> statement-breakpoint
CREATE INDEX "idx_ai_inference_log_org" ON "ai_inference_log" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ai_prompt_audit_prompt" ON "ai_prompt_audit_log" USING btree ("prompt_id");--> statement-breakpoint
CREATE INDEX "idx_ai_prompt_audit_action" ON "ai_prompt_audit_log" USING btree ("action");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_ai_prompt_versions_prompt_version" ON "ai_prompt_versions" USING btree ("prompt_id","version");--> statement-breakpoint
CREATE INDEX "idx_ai_prompt_versions_prompt" ON "ai_prompt_versions" USING btree ("prompt_id");--> statement-breakpoint
CREATE INDEX "idx_ai_prompt_versions_org" ON "ai_prompt_versions" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ai_prompts_org" ON "ai_prompts" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ai_prompts_tier" ON "ai_prompts" USING btree ("tier");--> statement-breakpoint
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
CREATE INDEX "idx_api_findings_org" ON "api_findings" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_api_findings_api" ON "api_findings" USING btree ("api_id");--> statement-breakpoint
CREATE INDEX "idx_api_findings_type" ON "api_findings" USING btree ("org_id","finding_type");--> statement-breakpoint
CREATE INDEX "idx_api_findings_severity" ON "api_findings" USING btree ("org_id","severity");--> statement-breakpoint
CREATE INDEX "idx_api_findings_status" ON "api_findings" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_api_inventory_org" ON "api_inventory" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_api_inventory_host" ON "api_inventory" USING btree ("org_id","host");--> statement-breakpoint
CREATE INDEX "idx_api_inventory_shadow" ON "api_inventory" USING btree ("org_id","is_shadow");--> statement-breakpoint
CREATE INDEX "idx_api_inventory_risk" ON "api_inventory" USING btree ("org_id","risk_score");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_api_inventory_unique" ON "api_inventory" USING btree ("org_id","method","path","host");--> statement-breakpoint
CREATE INDEX "idx_api_keys_org" ON "api_keys" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_api_keys_hash" ON "api_keys" USING btree ("key_hash");--> statement-breakpoint
CREATE INDEX "idx_apisec_org" ON "api_security_endpoints" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_apisec_risk" ON "api_security_endpoints" USING btree ("org_id","risk_score");--> statement-breakpoint
CREATE INDEX "idx_apithreat_org" ON "api_security_threats" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_apithreat_severity" ON "api_security_threats" USING btree ("org_id","severity");--> statement-breakpoint
CREATE INDEX "idx_api_baselines_org" ON "api_traffic_baselines" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_api_baselines_api" ON "api_traffic_baselines" USING btree ("api_id");--> statement-breakpoint
CREATE INDEX "idx_api_baselines_window" ON "api_traffic_baselines" USING btree ("api_id","window_start");--> statement-breakpoint
CREATE INDEX "idx_api_baselines_anomaly" ON "api_traffic_baselines" USING btree ("org_id","anomaly_score");--> statement-breakpoint
CREATE INDEX "idx_approval_decisions_subject" ON "approval_decision_records" USING btree ("approval_subject_type","approval_subject_id");--> statement-breakpoint
CREATE INDEX "idx_approval_decisions_approver" ON "approval_decision_records" USING btree ("approver_user_id");--> statement-breakpoint
CREATE INDEX "idx_approval_decisions_org" ON "approval_decision_records" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_approval_decisions_decided" ON "approval_decision_records" USING btree ("decided_at");--> statement-breakpoint
CREATE INDEX "idx_artappr_org" ON "artifact_approvals" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_artappr_status" ON "artifact_approvals" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_artdeploy_org" ON "artifact_deployments" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_artdeploy_status" ON "artifact_deployments" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_assess_resp_assessment" ON "assessment_responses" USING btree ("assessment_id");--> statement-breakpoint
CREATE INDEX "idx_assess_resp_org" ON "assessment_responses" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_assess_resp_status" ON "assessment_responses" USING btree ("assessment_id","status");--> statement-breakpoint
CREATE INDEX "idx_asset_inv_org" ON "asset_inventory" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_asset_inv_type" ON "asset_inventory" USING btree ("org_id","asset_type");--> statement-breakpoint
CREATE INDEX "idx_asset_inv_criticality" ON "asset_inventory" USING btree ("org_id","criticality");--> statement-breakpoint
CREATE INDEX "idx_asset_inv_status" ON "asset_inventory" USING btree ("org_id","lifecycle_status");--> statement-breakpoint
CREATE INDEX "idx_asset_inv_risk" ON "asset_inventory" USING btree ("org_id","risk_score");--> statement-breakpoint
CREATE INDEX "idx_age_graph" ON "attack_graph_edges" USING btree ("graph_id");--> statement-breakpoint
CREATE INDEX "idx_age_source" ON "attack_graph_edges" USING btree ("source_node_id");--> statement-breakpoint
CREATE INDEX "idx_age_target" ON "attack_graph_edges" USING btree ("target_node_id");--> statement-breakpoint
CREATE INDEX "idx_agn_graph" ON "attack_graph_nodes" USING btree ("graph_id");--> statement-breakpoint
CREATE INDEX "idx_agn_type" ON "attack_graph_nodes" USING btree ("node_type");--> statement-breakpoint
CREATE INDEX "idx_agn_mitre" ON "attack_graph_nodes" USING btree ("mitre_technique");--> statement-breakpoint
CREATE INDEX "idx_attack_graphs_org" ON "attack_graphs" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_attack_graphs_incident" ON "attack_graphs" USING btree ("incident_id");--> statement-breakpoint
CREATE INDEX "idx_attack_graphs_created" ON "attack_graphs" USING btree ("created_at");--> statement-breakpoint
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
CREATE INDEX "idx_autonomy_log_org" ON "autonomy_log" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_autonomy_log_decision" ON "autonomy_log" USING btree ("decision_id");--> statement-breakpoint
CREATE INDEX "idx_autonomy_log_action" ON "autonomy_log" USING btree ("org_id","action");--> statement-breakpoint
CREATE INDEX "idx_autonomy_log_tier" ON "autonomy_log" USING btree ("org_id","tier");--> statement-breakpoint
CREATE INDEX "idx_autonomy_log_created" ON "autonomy_log" USING btree ("org_id","created_at");--> statement-breakpoint
CREATE INDEX "idx_awprog_org" ON "awareness_programs" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_awprog_type" ON "awareness_programs" USING btree ("org_id","program_type");--> statement-breakpoint
CREATE INDEX "idx_backup_verify_org" ON "backup_verifications" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_backup_verify_status" ON "backup_verifications" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_backup_verify_type" ON "backup_verifications" USING btree ("org_id","backup_type");--> statement-breakpoint
CREATE INDEX "idx_blast_radius_playbook" ON "blast_radius_previews" USING btree ("playbook_id");--> statement-breakpoint
CREATE INDEX "idx_blast_radius_org" ON "blast_radius_previews" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_blast_radius_risk" ON "blast_radius_previews" USING btree ("risk_level");--> statement-breakpoint
CREATE INDEX "idx_board_kpi_org" ON "board_kpi_configs" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_board_org" ON "board_summaries" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_board_period" ON "board_summaries" USING btree ("org_id","period");--> statement-breakpoint
CREATE INDEX "idx_bds_org" ON "browser_defense_sessions" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_bds_state" ON "browser_defense_sessions" USING btree ("org_id","state");--> statement-breakpoint
CREATE INDEX "idx_bds_agent" ON "browser_defense_sessions" USING btree ("org_id","agent_id");--> statement-breakpoint
CREATE INDEX "idx_bde_org" ON "browser_dom_events" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_bde_session" ON "browser_dom_events" USING btree ("org_id","session_id");--> statement-breakpoint
CREATE INDEX "idx_ber_org" ON "browser_egress_rules" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ber_domain" ON "browser_egress_rules" USING btree ("org_id","domain");--> statement-breakpoint
CREATE INDEX "idx_bip_org" ON "browser_injection_patterns" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_btp_org" ON "browser_trusted_paths" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_campaigns_org" ON "campaigns" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_campaigns_fingerprint" ON "campaigns" USING btree ("fingerprint");--> statement-breakpoint
CREATE INDEX "idx_campaigns_status" ON "campaigns" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_canary_tokens_org" ON "canary_tokens" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_canary_tokens_type" ON "canary_tokens" USING btree ("token_type");--> statement-breakpoint
CREATE INDEX "idx_canary_tokens_hash" ON "canary_tokens" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "idx_canary_tokens_active" ON "canary_tokens" USING btree ("org_id","is_active");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_canary_tokens_callback" ON "canary_tokens" USING btree ("callback_url");--> statement-breakpoint
CREATE INDEX "idx_ci_gates_org" ON "ci_gates" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ci_gates_repo" ON "ci_gates" USING btree ("org_id","repository");--> statement-breakpoint
CREATE INDEX "idx_ci_gates_status" ON "ci_gates" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_ci_gates_commit" ON "ci_gates" USING btree ("org_id","commit_sha");--> statement-breakpoint
CREATE INDEX "idx_ci_gates_pr" ON "ci_gates" USING btree ("org_id","pull_request_id");--> statement-breakpoint
CREATE INDEX "idx_codeown_org" ON "code_owners" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_code_review_org" ON "code_review_findings" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_code_review_repo" ON "code_review_findings" USING btree ("org_id","repository");--> statement-breakpoint
CREATE INDEX "idx_code_review_pr" ON "code_review_findings" USING btree ("org_id","pull_request_id");--> statement-breakpoint
CREATE INDEX "idx_cold_inv_org" ON "cold_storage_inventory" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_cold_inv_org_type" ON "cold_storage_inventory" USING btree ("org_id","data_type");--> statement-breakpoint
CREATE INDEX "idx_cold_inv_tier" ON "cold_storage_inventory" USING btree ("tier");--> statement-breakpoint
CREATE INDEX "idx_cold_inv_purge" ON "cold_storage_inventory" USING btree ("purge_eligible_at");--> statement-breakpoint
CREATE INDEX "idx_collector_events_org" ON "collector_events" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_collector_events_collector" ON "collector_events" USING btree ("collector_id");--> statement-breakpoint
CREATE INDEX "idx_collector_events_type" ON "collector_events" USING btree ("org_id","event_type");--> statement-breakpoint
CREATE INDEX "idx_collector_events_ts" ON "collector_events" USING btree ("org_id","timestamp");--> statement-breakpoint
CREATE INDEX "idx_collector_instances_org" ON "collector_instances" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_collector_instances_status" ON "collector_instances" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_collector_instances_template" ON "collector_instances" USING btree ("org_id","template_slug");--> statement-breakpoint
CREATE INDEX "idx_collector_scans_org" ON "collector_scans" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_collector_scans_collector" ON "collector_scans" USING btree ("collector_id");--> statement-breakpoint
CREATE INDEX "idx_collector_scans_type" ON "collector_scans" USING btree ("org_id","scan_type");--> statement-breakpoint
CREATE INDEX "community_feeds_org_idx" ON "community_feeds" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "community_feeds_type_idx" ON "community_feeds" USING btree ("feed_type");--> statement-breakpoint
CREATE INDEX "community_feeds_sector_idx" ON "community_feeds" USING btree ("industry_sector");--> statement-breakpoint
CREATE INDEX "idx_th_community_org" ON "community_hunt_shares" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_th_community_category" ON "community_hunt_shares" USING btree ("category");--> statement-breakpoint
CREATE INDEX "idx_cif_org" ON "community_intel_feeds" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_cif_type" ON "community_intel_feeds" USING btree ("org_id","feed_type");--> statement-breakpoint
CREATE INDEX "idx_cii_org" ON "community_intel_indicators" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_cii_feed" ON "community_intel_indicators" USING btree ("org_id","feed_id");--> statement-breakpoint
CREATE INDEX "idx_cii_type" ON "community_intel_indicators" USING btree ("org_id","indicator_type");--> statement-breakpoint
CREATE INDEX "community_campaigns_status_idx" ON "community_threat_campaigns" USING btree ("status");--> statement-breakpoint
CREATE INDEX "community_campaigns_actor_idx" ON "community_threat_campaigns" USING btree ("threat_actor_name");--> statement-breakpoint
CREATE INDEX "community_campaigns_first_seen_idx" ON "community_threat_campaigns" USING btree ("first_seen_at");--> statement-breakpoint
CREATE INDEX "idx_compliance_helpers_org" ON "compliance_control_helpers" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_compliance_helpers_type" ON "compliance_control_helpers" USING btree ("helper_type");--> statement-breakpoint
CREATE INDEX "idx_control_mappings_org" ON "compliance_control_mappings" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_control_mappings_control" ON "compliance_control_mappings" USING btree ("control_id");--> statement-breakpoint
CREATE INDEX "idx_control_mappings_resource" ON "compliance_control_mappings" USING btree ("resource_type","resource_id");--> statement-breakpoint
CREATE INDEX "idx_compliance_controls_framework" ON "compliance_controls" USING btree ("framework");--> statement-breakpoint
CREATE INDEX "idx_compliance_controls_control_id" ON "compliance_controls" USING btree ("control_id");--> statement-breakpoint
CREATE INDEX "idx_cga_org" ON "compliance_gap_assessments" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_cga_framework" ON "compliance_gap_assessments" USING btree ("org_id","framework_id");--> statement-breakpoint
CREATE INDEX "idx_cga_status" ON "compliance_gap_assessments" USING btree ("org_id","status");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_compliance_policies_org" ON "compliance_policies" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_connector_health_connector" ON "connector_health_checks" USING btree ("connector_id");--> statement-breakpoint
CREATE INDEX "idx_connector_health_checked" ON "connector_health_checks" USING btree ("checked_at");--> statement-breakpoint
CREATE INDEX "idx_connector_job_runs_connector" ON "connector_job_runs" USING btree ("connector_id");--> statement-breakpoint
CREATE INDEX "idx_connector_job_runs_status" ON "connector_job_runs" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_connector_job_runs_dead_letter" ON "connector_job_runs" USING btree ("is_dead_letter");--> statement-breakpoint
CREATE INDEX "idx_connector_job_runs_started" ON "connector_job_runs" USING btree ("started_at");--> statement-breakpoint
CREATE INDEX "idx_connector_job_runs_next_retry" ON "connector_job_runs" USING btree ("next_retry_at");--> statement-breakpoint
CREATE INDEX "idx_connector_job_runs_connector_started" ON "connector_job_runs" USING btree ("connector_id","started_at");--> statement-breakpoint
CREATE INDEX "idx_connector_runs_archive_org" ON "connector_job_runs_archive" USING btree ("org_id","archived_at");--> statement-breakpoint
CREATE INDEX "idx_connector_runs_archive_connector" ON "connector_job_runs_archive" USING btree ("connector_id","archived_at");--> statement-breakpoint
CREATE INDEX "idx_secret_rotation_connector" ON "connector_secret_rotations" USING btree ("connector_id");--> statement-breakpoint
CREATE INDEX "idx_secret_rotation_due" ON "connector_secret_rotations" USING btree ("next_rotation_due");--> statement-breakpoint
CREATE INDEX "idx_connectors_org" ON "connectors" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_connectors_type" ON "connectors" USING btree ("type");--> statement-breakpoint
CREATE INDEX "idx_connectors_status" ON "connectors" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_connectors_org_status" ON "connectors" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_connectors_org_created" ON "connectors" USING btree ("org_id","created_at");--> statement-breakpoint
CREATE INDEX "idx_consent_org" ON "consent_records" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_consent_subject" ON "consent_records" USING btree ("data_subject_id");--> statement-breakpoint
CREATE INDEX "idx_consent_purpose" ON "consent_records" USING btree ("purpose");--> statement-breakpoint
CREATE INDEX "idx_copact_org" ON "copilot_actions" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_copact_status" ON "copilot_actions" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_copact_triage" ON "copilot_actions" USING btree ("org_id","triage_id");--> statement-breakpoint
CREATE INDEX "idx_copfb_org" ON "copilot_feedback" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_copfb_domain" ON "copilot_feedback" USING btree ("org_id","domain");--> statement-breakpoint
CREATE INDEX "idx_cophyp_org" ON "copilot_hypotheses" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_cophyp_status" ON "copilot_hypotheses" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_triage_org" ON "copilot_triages" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_triage_verdict" ON "copilot_triages" USING btree ("org_id","verdict");--> statement-breakpoint
CREATE INDEX "idx_triage_alert" ON "copilot_triages" USING btree ("org_id","alert_id");--> statement-breakpoint
CREATE INDEX "idx_correlation_clusters_org" ON "correlation_clusters" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_correlation_clusters_incident" ON "correlation_clusters" USING btree ("incident_id");--> statement-breakpoint
CREATE INDEX "idx_correlation_clusters_status" ON "correlation_clusters" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_cbf_audit_org" ON "cross_border_flow_audit" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_cbf_audit_created" ON "cross_border_flow_audit" USING btree ("created_at");--> statement-breakpoint
CREATE INDEX "idx_cbf_rules_org" ON "cross_border_flow_rules" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_cbf_rules_regions" ON "cross_border_flow_rules" USING btree ("source_region","destination_region");--> statement-breakpoint
CREATE INDEX "idx_cbt_alerts_org" ON "cross_border_transfer_alerts" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_cbt_alerts_flow" ON "cross_border_transfer_alerts" USING btree ("data_flow_id");--> statement-breakpoint
CREATE INDEX "idx_cbt_alerts_risk" ON "cross_border_transfer_alerts" USING btree ("risk_level");--> statement-breakpoint
CREATE INDEX "idx_ccd_org" ON "cross_cutting_drift" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ccd_type" ON "cross_cutting_drift" USING btree ("org_id","drift_type");--> statement-breakpoint
CREATE INDEX "idx_ccd_status" ON "cross_cutting_drift" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_cce_org" ON "cross_cutting_evidence" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_cce_type" ON "cross_cutting_evidence" USING btree ("org_id","evidence_type");--> statement-breakpoint
CREATE INDEX "idx_cce_status" ON "cross_cutting_evidence" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_cce_resource" ON "cross_cutting_evidence" USING btree ("org_id","resource_id");--> statement-breakpoint
CREATE INDEX "idx_cc_ks_org" ON "cross_cutting_kill_switches" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_cc_ks_feature" ON "cross_cutting_kill_switches" USING btree ("org_id","feature_name");--> statement-breakpoint
CREATE INDEX "idx_cco_org" ON "cross_cutting_overrides" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_cco_type" ON "cross_cutting_overrides" USING btree ("org_id","override_type");--> statement-breakpoint
CREATE INDEX "idx_cco_status" ON "cross_cutting_overrides" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_cco_target" ON "cross_cutting_overrides" USING btree ("org_id","target_module","target_resource_id");--> statement-breakpoint
CREATE INDEX "idx_cspmrem_org" ON "cspm_remediation_safety_records" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_cspmrem_mode" ON "cspm_remediation_safety_records" USING btree ("org_id","mode");--> statement-breakpoint
CREATE INDEX "idx_cve_entries_cve_id" ON "cve_entries" USING btree ("cve_id");--> statement-breakpoint
CREATE INDEX "idx_cve_entries_severity" ON "cve_entries" USING btree ("severity");--> statement-breakpoint
CREATE INDEX "idx_cve_entries_cvss" ON "cve_entries" USING btree ("cvss_score");--> statement-breakpoint
CREATE INDEX "idx_cve_entries_published" ON "cve_entries" USING btree ("published_date");--> statement-breakpoint
CREATE INDEX "idx_dashboard_cache_org_type" ON "dashboard_metrics_cache" USING btree ("org_id","metric_type");--> statement-breakpoint
CREATE INDEX "idx_dashboard_cache_expires" ON "dashboard_metrics_cache" USING btree ("expires_at");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_dashboard_cache_org_type_unique" ON "dashboard_metrics_cache" USING btree ("org_id","metric_type");--> statement-breakpoint
CREATE INDEX "idx_data_assets_org" ON "data_assets" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_data_assets_type" ON "data_assets" USING btree ("asset_type");--> statement-breakpoint
CREATE INDEX "idx_data_assets_classification" ON "data_assets" USING btree ("classification");--> statement-breakpoint
CREATE INDEX "idx_data_assets_jurisdiction" ON "data_assets" USING btree ("jurisdiction");--> statement-breakpoint
CREATE INDEX "idx_data_flows_org" ON "data_flows" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_data_flows_source" ON "data_flows" USING btree ("source_asset_id");--> statement-breakpoint
CREATE INDEX "idx_data_flows_dest" ON "data_flows" USING btree ("destination_asset_id");--> statement-breakpoint
CREATE INDEX "idx_data_flows_cross_border" ON "data_flows" USING btree ("is_cross_border");--> statement-breakpoint
CREATE INDEX "idx_dl_queries_org" ON "data_lake_queries" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_dl_queries_status" ON "data_lake_queries" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_dl_retention_org" ON "data_lake_retention_policies" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_dl_retention_org_type" ON "data_lake_retention_policies" USING btree ("org_id","data_type");--> statement-breakpoint
CREATE INDEX "idx_dl_retention_framework" ON "data_lake_retention_policies" USING btree ("compliance_framework");--> statement-breakpoint
CREATE INDEX "idx_decep_org" ON "deception_assets" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_decep_type" ON "deception_assets" USING btree ("org_id","asset_type");--> statement-breakpoint
CREATE INDEX "idx_decep_status" ON "deception_assets" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_deception_hits_org" ON "deception_hits" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_deception_hits_token" ON "deception_hits" USING btree ("canary_token_id");--> statement-breakpoint
CREATE INDEX "idx_deception_hits_honeypot" ON "deception_hits" USING btree ("honeypot_asset_id");--> statement-breakpoint
CREATE INDEX "idx_deception_hits_severity" ON "deception_hits" USING btree ("org_id","severity");--> statement-breakpoint
CREATE INDEX "idx_deception_hits_time" ON "deception_hits" USING btree ("org_id","hit_at");--> statement-breakpoint
CREATE INDEX "idx_deception_hits_source_ip" ON "deception_hits" USING btree ("source_ip");--> statement-breakpoint
CREATE INDEX "idx_decepint_org" ON "deception_interactions" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_decepint_asset" ON "deception_interactions" USING btree ("org_id","asset_id");--> statement-breakpoint
CREATE INDEX "idx_dep_graph_org" ON "dependency_graph" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_dep_graph_sbom" ON "dependency_graph" USING btree ("sbom_id");--> statement-breakpoint
CREATE INDEX "idx_dep_graph_pkg" ON "dependency_graph" USING btree ("org_id","package_name");--> statement-breakpoint
CREATE INDEX "idx_dep_graph_ecosystem" ON "dependency_graph" USING btree ("org_id","ecosystem");--> statement-breakpoint
CREATE INDEX "idx_dep_graph_vulnerable" ON "dependency_graph" USING btree ("org_id","is_vulnerable");--> statement-breakpoint
CREATE INDEX "idx_dep_graph_typosquat" ON "dependency_graph" USING btree ("org_id","typosquat_candidate");--> statement-breakpoint
CREATE INDEX "idx_detection_alerts_org" ON "detection_alerts" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_detection_alerts_rule" ON "detection_alerts" USING btree ("rule_id");--> statement-breakpoint
CREATE INDEX "idx_detection_alerts_sensor" ON "detection_alerts" USING btree ("sensor_id");--> statement-breakpoint
CREATE INDEX "idx_detection_alerts_status" ON "detection_alerts" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_detection_alerts_created" ON "detection_alerts" USING btree ("org_id","created_at");--> statement-breakpoint
CREATE INDEX "idx_detection_rules_org" ON "detection_rules" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_detection_rules_status" ON "detection_rules" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_detection_rules_tactic" ON "detection_rules" USING btree ("mitre_tactic");--> statement-breakpoint
CREATE INDEX "idx_detection_rules_severity" ON "detection_rules" USING btree ("severity");--> statement-breakpoint
CREATE INDEX "idx_posture_checks_org" ON "device_posture_checks" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_posture_checks_device" ON "device_posture_checks" USING btree ("device_id");--> statement-breakpoint
CREATE INDEX "idx_dns_events_org" ON "dns_events" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_dns_events_org_type" ON "dns_events" USING btree ("org_id","event_type");--> statement-breakpoint
CREATE INDEX "idx_dns_events_org_query" ON "dns_events" USING btree ("org_id","query_name");--> statement-breakpoint
CREATE INDEX "idx_dns_events_org_timestamp" ON "dns_events" USING btree ("org_id","timestamp");--> statement-breakpoint
CREATE INDEX "idx_dns_events_source_ip" ON "dns_events" USING btree ("org_id","source_ip");--> statement-breakpoint
CREATE INDEX "idx_dns_findings_org" ON "dns_findings" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_dns_findings_org_type" ON "dns_findings" USING btree ("org_id","finding_type");--> statement-breakpoint
CREATE INDEX "idx_dns_findings_org_severity" ON "dns_findings" USING btree ("org_id","severity");--> statement-breakpoint
CREATE INDEX "idx_dns_findings_org_status" ON "dns_findings" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_dns_findings_domain" ON "dns_findings" USING btree ("org_id","domain");--> statement-breakpoint
CREATE INDEX "idx_dnssec_org" ON "dns_security_events" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_dnssec_verdict" ON "dns_security_events" USING btree ("org_id","verdict");--> statement-breakpoint
CREATE INDEX "idx_dnspol_org" ON "dns_security_policies" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_dr_drill_results_runbook" ON "dr_drill_results" USING btree ("runbook_id");--> statement-breakpoint
CREATE INDEX "idx_dr_drill_results_org" ON "dr_drill_results" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_dr_drill_results_status" ON "dr_drill_results" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_dr_drill_results_created" ON "dr_drill_results" USING btree ("created_at");--> statement-breakpoint
CREATE INDEX "idx_dr_runbooks_org" ON "dr_runbooks" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_dr_runbooks_category" ON "dr_runbooks" USING btree ("category");--> statement-breakpoint
CREATE INDEX "idx_dsar_tasks_org" ON "dsar_fulfillment_tasks" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_dsar_tasks_request" ON "dsar_fulfillment_tasks" USING btree ("dsar_request_id");--> statement-breakpoint
CREATE INDEX "idx_dsar_tasks_status" ON "dsar_fulfillment_tasks" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_dsar_requests_org" ON "dsar_requests" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_dsar_requests_status" ON "dsar_requests" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_dsar_requests_due" ON "dsar_requests" USING btree ("due_date");--> statement-breakpoint
CREATE INDEX "idx_ediscovery_org" ON "ediscovery_exports" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ediscovery_status" ON "ediscovery_exports" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_ediscovery_hold" ON "ediscovery_exports" USING btree ("legal_hold_id");--> statement-breakpoint
CREATE INDEX "idx_email_findings_org" ON "email_findings" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_email_findings_org_type" ON "email_findings" USING btree ("org_id","finding_type");--> statement-breakpoint
CREATE INDEX "idx_email_findings_org_severity" ON "email_findings" USING btree ("org_id","severity");--> statement-breakpoint
CREATE INDEX "idx_email_findings_org_status" ON "email_findings" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_email_findings_org_sender" ON "email_findings" USING btree ("org_id","sender_address");--> statement-breakpoint
CREATE INDEX "idx_email_messages_org" ON "email_messages" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_email_messages_org_sender" ON "email_messages" USING btree ("org_id","sender_address");--> statement-breakpoint
CREATE INDEX "idx_email_messages_org_received" ON "email_messages" USING btree ("org_id","received_at");--> statement-breakpoint
CREATE INDEX "idx_email_messages_org_thread" ON "email_messages" USING btree ("org_id","thread_id");--> statement-breakpoint
CREATE INDEX "idx_email_messages_org_suspicious" ON "email_messages" USING btree ("org_id","is_suspicious");--> statement-breakpoint
CREATE INDEX "idx_email_policies_org" ON "email_policies" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_email_policies_org_type" ON "email_policies" USING btree ("org_id","policy_type");--> statement-breakpoint
CREATE INDEX "idx_email_quarantine_org" ON "email_quarantine_items" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_email_quarantine_org_status" ON "email_quarantine_items" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_emailsec_org" ON "email_security_events" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_emailsec_verdict" ON "email_security_events" USING btree ("org_id","verdict");--> statement-breakpoint
CREATE INDEX "idx_email_url_rewrites_org" ON "email_url_rewrites" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_email_url_rewrites_org_url" ON "email_url_rewrites" USING btree ("org_id","original_url");--> statement-breakpoint
CREATE INDEX "idx_epgrp_org" ON "endpoint_groups" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ephb_org" ON "endpoint_heartbeats" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ephb_asset" ON "endpoint_heartbeats" USING btree ("org_id","asset_id");--> statement-breakpoint
CREATE INDEX "idx_epss_org" ON "endpoint_scan_schedules" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_epss_asset" ON "endpoint_scan_schedules" USING btree ("org_id","asset_id");--> statement-breakpoint
CREATE INDEX "idx_telemetry_archive_org_archived" ON "endpoint_telemetry_archive" USING btree ("org_id","archived_at");--> statement-breakpoint
CREATE INDEX "idx_telemetry_archive_asset" ON "endpoint_telemetry_archive" USING btree ("asset_id","archived_at");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_engine_configs_org_engine" ON "engine_configs" USING btree ("org_id","engine_name");--> statement-breakpoint
CREATE INDEX "idx_engine_configs_org" ON "engine_configs" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_engine_dry_runs_org" ON "engine_dry_runs" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_engine_dry_runs_engine" ON "engine_dry_runs" USING btree ("org_id","engine_name");--> statement-breakpoint
CREATE INDEX "idx_engine_explain_org" ON "engine_explainability_logs" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_engine_explain_engine" ON "engine_explainability_logs" USING btree ("org_id","engine_name");--> statement-breakpoint
CREATE INDEX "idx_entities_org" ON "entities" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_entities_type" ON "entities" USING btree ("type");--> statement-breakpoint
CREATE INDEX "idx_entities_value" ON "entities" USING btree ("value");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_entities_org_type_value" ON "entities" USING btree ("org_id","type","value");--> statement-breakpoint
CREATE INDEX "idx_entity_aliases_entity" ON "entity_aliases" USING btree ("entity_id");--> statement-breakpoint
CREATE INDEX "idx_entity_aliases_value" ON "entity_aliases" USING btree ("alias_value");--> statement-breakpoint
CREATE INDEX "idx_entity_merge_history_org" ON "entity_merge_history" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_entity_merge_history_target" ON "entity_merge_history" USING btree ("target_entity_id");--> statement-breakpoint
CREATE INDEX "idx_entity_merge_history_source" ON "entity_merge_history" USING btree ("source_entity_id");--> statement-breakpoint
CREATE INDEX "idx_evidence_attach_org" ON "evidence_attachments" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_evidence_attach_mapping" ON "evidence_attachments" USING btree ("control_mapping_id");--> statement-breakpoint
CREATE INDEX "idx_evidence_attach_locker" ON "evidence_attachments" USING btree ("evidence_locker_id");--> statement-breakpoint
CREATE INDEX "idx_evidence_attach_status" ON "evidence_attachments" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_evidence_chain_incident" ON "evidence_chain_entries" USING btree ("incident_id");--> statement-breakpoint
CREATE INDEX "idx_evidence_chain_org" ON "evidence_chain_entries" USING btree ("org_id");--> statement-breakpoint
CREATE UNIQUE INDEX "uq_evidence_chain_incident_seq" ON "evidence_chain_entries" USING btree ("incident_id","sequence_num");--> statement-breakpoint
CREATE INDEX "idx_evidence_chain_type" ON "evidence_chain_entries" USING btree ("entry_type");--> statement-breakpoint
CREATE INDEX "idx_evidence_items_incident" ON "evidence_items" USING btree ("incident_id");--> statement-breakpoint
CREATE INDEX "idx_evidence_items_org" ON "evidence_items" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_evidence_locker_org" ON "evidence_locker_items" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_evidence_locker_framework" ON "evidence_locker_items" USING btree ("framework");--> statement-breakpoint
CREATE INDEX "idx_evidence_locker_type" ON "evidence_locker_items" USING btree ("artifact_type");--> statement-breakpoint
CREATE INDEX "idx_evidence_locker_status" ON "evidence_locker_items" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_execmetric_org" ON "executive_metrics" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_execmetric_cat" ON "executive_metrics" USING btree ("org_id","category");--> statement-breakpoint
CREATE INDEX "idx_feature_flags_key" ON "feature_flags" USING btree ("key");--> statement-breakpoint
CREATE INDEX "idx_feature_flags_enabled" ON "feature_flags" USING btree ("enabled");--> statement-breakpoint
CREATE INDEX "idx_flr_org" ON "finding_lineage_records" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_flr_severity" ON "finding_lineage_records" USING btree ("org_id","severity");--> statement-breakpoint
CREATE INDEX "idx_flr_status" ON "finding_lineage_records" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_flr_source" ON "finding_lineage_records" USING btree ("org_id","source");--> statement-breakpoint
CREATE INDEX "idx_graphsnap_org" ON "graph_snapshots" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_honeypot_assets_org" ON "honeypot_assets" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_honeypot_assets_type" ON "honeypot_assets" USING btree ("asset_type");--> statement-breakpoint
CREATE INDEX "idx_honeypot_assets_active" ON "honeypot_assets" USING btree ("org_id","is_active");--> statement-breakpoint
CREATE INDEX "idx_th_cache_org" ON "hunt_cache" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_th_cache_hash" ON "hunt_cache" USING btree ("query_hash");--> statement-breakpoint
CREATE INDEX "idx_th_collab_org" ON "hunt_collaborations" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_th_collab_hunt" ON "hunt_collaborations" USING btree ("hunt_id");--> statement-breakpoint
CREATE INDEX "idx_th_library_org" ON "hunt_library" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_th_library_public" ON "hunt_library" USING btree ("is_public");--> statement-breakpoint
CREATE INDEX "idx_th_notebooks_org" ON "hunt_notebooks" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_th_playbooks_org" ON "hunt_playbooks" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_th_results_hunt" ON "hunt_results" USING btree ("hunt_id");--> statement-breakpoint
CREATE INDEX "idx_th_results_org" ON "hunt_results" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_th_drift_org" ON "hunt_schedule_drifts" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_th_drift_schedule" ON "hunt_schedule_drifts" USING btree ("schedule_id");--> statement-breakpoint
CREATE INDEX "idx_th_schedules_org" ON "hunt_schedules" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_th_schedules_hunt" ON "hunt_schedules" USING btree ("hunt_id");--> statement-breakpoint
CREATE INDEX "idx_idempotency_org_key" ON "idempotency_keys" USING btree ("org_id","idempotency_key","endpoint");--> statement-breakpoint
CREATE INDEX "idx_iag_org" ON "identity_access_graph" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_iag_source" ON "identity_access_graph" USING btree ("org_id","source_user_id");--> statement-breakpoint
CREATE INDEX "idx_iag_target" ON "identity_access_graph" USING btree ("org_id","target_system");--> statement-breakpoint
CREATE INDEX "idx_iag_active" ON "identity_access_graph" USING btree ("org_id","is_active");--> statement-breakpoint
CREATE INDEX "idx_ident_org" ON "identity_entitlements" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ident_user" ON "identity_entitlements" USING btree ("org_id","user_id");--> statement-breakpoint
CREATE INDEX "idx_ident_review" ON "identity_entitlements" USING btree ("org_id","review_id");--> statement-breakpoint
CREATE INDEX "idx_irp_org" ON "identity_risk_profiles" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_irp_user" ON "identity_risk_profiles" USING btree ("org_id","user_id");--> statement-breakpoint
CREATE INDEX "idx_irp_risk" ON "identity_risk_profiles" USING btree ("org_id","risk_level");--> statement-breakpoint
CREATE INDEX "idx_irp_stale" ON "identity_risk_profiles" USING btree ("org_id","is_stale");--> statement-breakpoint
CREATE INDEX "idx_irp_blast" ON "identity_risk_profiles" USING btree ("org_id","blast_radius_score");--> statement-breakpoint
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
CREATE INDEX "idx_ipe_org" ON "industrial_protocol_events" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ipe_asset" ON "industrial_protocol_events" USING btree ("asset_id");--> statement-breakpoint
CREATE INDEX "idx_ipe_protocol" ON "industrial_protocol_events" USING btree ("org_id","protocol");--> statement-breakpoint
CREATE INDEX "idx_ipe_write" ON "industrial_protocol_events" USING btree ("org_id","is_write");--> statement-breakpoint
CREATE INDEX "idx_ipe_anomalous" ON "industrial_protocol_events" USING btree ("org_id","is_anomalous");--> statement-breakpoint
CREATE INDEX "idx_ipe_time" ON "industrial_protocol_events" USING btree ("org_id","captured_at");--> statement-breakpoint
CREATE INDEX "idx_ingestion_logs_org" ON "ingestion_logs" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ingestion_logs_source" ON "ingestion_logs" USING btree ("source");--> statement-breakpoint
CREATE INDEX "idx_ingestion_logs_received" ON "ingestion_logs" USING btree ("received_at");--> statement-breakpoint
CREATE INDEX "idx_ingestion_logs_org_received" ON "ingestion_logs" USING btree ("org_id","received_at");--> statement-breakpoint
CREATE INDEX "idx_ingestion_logs_org_status_received" ON "ingestion_logs" USING btree ("org_id","status","received_at");--> statement-breakpoint
CREATE INDEX "idx_ingestion_archive_org_archived" ON "ingestion_logs_archive" USING btree ("org_id","archived_at");--> statement-breakpoint
CREATE INDEX "idx_integration_configs_org" ON "integration_configs" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_integration_configs_type" ON "integration_configs" USING btree ("type");--> statement-breakpoint
CREATE INDEX "idx_chat_messages_thread" ON "investigation_chat_messages" USING btree ("thread_id");--> statement-breakpoint
CREATE INDEX "idx_chat_messages_incident" ON "investigation_chat_messages" USING btree ("incident_id");--> statement-breakpoint
CREATE INDEX "idx_chat_messages_org" ON "investigation_chat_messages" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_hypotheses_incident" ON "investigation_hypotheses" USING btree ("incident_id");--> statement-breakpoint
CREATE INDEX "idx_hypotheses_org" ON "investigation_hypotheses" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_hypotheses_status" ON "investigation_hypotheses" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_inv_tasks_incident" ON "investigation_tasks" USING btree ("incident_id");--> statement-breakpoint
CREATE INDEX "idx_inv_tasks_org" ON "investigation_tasks" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_inv_tasks_assigned" ON "investigation_tasks" USING btree ("assigned_to");--> statement-breakpoint
CREATE INDEX "idx_inv_tasks_status" ON "investigation_tasks" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_invoices_org" ON "invoices" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_invoices_subscription" ON "invoices" USING btree ("subscription_id");--> statement-breakpoint
CREATE INDEX "idx_invoices_stripe" ON "invoices" USING btree ("stripe_invoice_id");--> statement-breakpoint
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
CREATE INDEX "idx_jar_org" ON "jit_access_requests" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_jar_requester" ON "jit_access_requests" USING btree ("org_id","requester_id");--> statement-breakpoint
CREATE INDEX "idx_jar_status" ON "jit_access_requests" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_jar_secret" ON "jit_access_requests" USING btree ("org_id","secret_path");--> statement-breakpoint
CREATE INDEX "idx_jit_al_org" ON "jit_audit_log" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_jit_bg_org" ON "jit_break_glass_access" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_jit_es_org" ON "jit_external_shares" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_jit_es_token" ON "jit_external_shares" USING btree ("share_token");--> statement-breakpoint
CREATE INDEX "idx_jit_ms_org" ON "jit_managed_secrets" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_jit_ms_owner" ON "jit_managed_secrets" USING btree ("org_id","owner_id");--> statement-breakpoint
CREATE INDEX "idx_jit_ot_org" ON "jit_ownership_transfers" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_jit_sar_org" ON "jit_secret_access_requests" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_jit_sar_secret" ON "jit_secret_access_requests" USING btree ("org_id","secret_id");--> statement-breakpoint
CREATE INDEX "idx_job_queue_status_run" ON "job_queue" USING btree ("status","run_at");--> statement-breakpoint
CREATE INDEX "idx_job_queue_org" ON "job_queue" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_job_queue_type_status" ON "job_queue" USING btree ("type","status");--> statement-breakpoint
CREATE INDEX "idx_job_queue_fingerprint" ON "job_queue" USING btree ("fingerprint");--> statement-breakpoint
CREATE INDEX "idx_job_queue_locked_until" ON "job_queue" USING btree ("locked_until");--> statement-breakpoint
CREATE INDEX "idx_legal_holds_org" ON "legal_holds" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_legal_holds_active" ON "legal_holds" USING btree ("is_active");--> statement-breakpoint
CREATE INDEX "idx_log_sources_org" ON "log_sources" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_log_sources_sensor" ON "log_sources" USING btree ("sensor_id");--> statement-breakpoint
CREATE INDEX "idx_log_sources_type" ON "log_sources" USING btree ("org_id","source_type");--> statement-breakpoint
CREATE INDEX "idx_log_sources_status" ON "log_sources" USING btree ("org_id","status");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_log_sources_http_auth_token" ON "log_sources" USING btree ("http_auth_token");--> statement-breakpoint
CREATE INDEX "idx_mdl_org" ON "marketplace_dead_letters" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_mdl_instance" ON "marketplace_dead_letters" USING btree ("instance_id");--> statement-breakpoint
CREATE INDEX "idx_mdl_status" ON "marketplace_dead_letters" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_mi_org" ON "marketplace_instances" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_mi_connector" ON "marketplace_instances" USING btree ("org_id","connector_slug");--> statement-breakpoint
CREATE INDEX "idx_mi_status" ON "marketplace_instances" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_msh_org" ON "marketplace_sync_history" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_msh_instance" ON "marketplace_sync_history" USING btree ("instance_id");--> statement-breakpoint
CREATE INDEX "idx_msh_started" ON "marketplace_sync_history" USING btree ("started_at");--> statement-breakpoint
CREATE INDEX "idx_mwe_org" ON "marketplace_webhook_events" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_mwe_instance" ON "marketplace_webhook_events" USING btree ("instance_id");--> statement-breakpoint
CREATE INDEX "idx_mwe_ikey" ON "marketplace_webhook_events" USING btree ("idempotency_key");--> statement-breakpoint
CREATE INDEX "idx_mobile_devices_org" ON "mobile_devices" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_mobile_devices_user" ON "mobile_devices" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "idx_mobile_devices_compliance" ON "mobile_devices" USING btree ("compliance_status");--> statement-breakpoint
CREATE INDEX "idx_mobile_devices_risk" ON "mobile_devices" USING btree ("risk_level");--> statement-breakpoint
CREATE INDEX "idx_mobile_threats_org" ON "mobile_threats" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_mobile_threats_device" ON "mobile_threats" USING btree ("device_id");--> statement-breakpoint
CREATE INDEX "idx_mobile_threats_status" ON "mobile_threats" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_mssp_grant_parent_child" ON "mssp_access_grants" USING btree ("parent_org_id","child_org_id");--> statement-breakpoint
CREATE INDEX "idx_mssp_grant_parent" ON "mssp_access_grants" USING btree ("parent_org_id");--> statement-breakpoint
CREATE INDEX "idx_mssp_grant_child" ON "mssp_access_grants" USING btree ("child_org_id");--> statement-breakpoint
CREATE INDEX "idx_mssp_billing_parent" ON "mssp_billing_records" USING btree ("parent_org_id");--> statement-breakpoint
CREATE INDEX "idx_mssp_billing_child" ON "mssp_billing_records" USING btree ("child_org_id");--> statement-breakpoint
CREATE INDEX "idx_mssp_billing_period" ON "mssp_billing_records" USING btree ("parent_org_id","period_start");--> statement-breakpoint
CREATE INDEX "idx_mssp_billing_status" ON "mssp_billing_records" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_mssp_onboarding_parent" ON "mssp_client_onboarding" USING btree ("parent_org_id");--> statement-breakpoint
CREATE INDEX "idx_mssp_onboarding_child" ON "mssp_client_onboarding" USING btree ("child_org_id");--> statement-breakpoint
CREATE INDEX "idx_mssp_onboarding_status" ON "mssp_client_onboarding" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_mssp_sla_parent" ON "mssp_client_slas" USING btree ("parent_org_id");--> statement-breakpoint
CREATE INDEX "idx_mssp_sla_child" ON "mssp_client_slas" USING btree ("child_org_id");--> statement-breakpoint
CREATE INDEX "idx_mssp_sla_parent_child" ON "mssp_client_slas" USING btree ("parent_org_id","child_org_id");--> statement-breakpoint
CREATE INDEX "idx_mssp_sla_breach_sla" ON "mssp_sla_breaches" USING btree ("sla_id");--> statement-breakpoint
CREATE INDEX "idx_mssp_sla_breach_parent" ON "mssp_sla_breaches" USING btree ("parent_org_id");--> statement-breakpoint
CREATE INDEX "idx_mssp_sla_breach_child" ON "mssp_sla_breaches" USING btree ("child_org_id");--> statement-breakpoint
CREATE INDEX "idx_mssp_sla_breach_status" ON "mssp_sla_breaches" USING btree ("status");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_mssp_wl_org" ON "mssp_white_label_configs" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_native_sensors_org" ON "native_sensors" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_native_sensors_status" ON "native_sensors" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_native_sensors_hostname" ON "native_sensors" USING btree ("org_id","hostname");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_native_sensors_token" ON "native_sensors" USING btree ("registration_token");--> statement-breakpoint
CREATE INDEX "idx_notification_channels_org" ON "notification_channels" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_notification_channels_type" ON "notification_channels" USING btree ("type");--> statement-breakpoint
CREATE INDEX "idx_notification_delivery_log_channel" ON "notification_delivery_log" USING btree ("channel_id");--> statement-breakpoint
CREATE INDEX "idx_notification_delivery_log_org_delivered" ON "notification_delivery_log" USING btree ("org_id","delivered_at");--> statement-breakpoint
CREATE INDEX "idx_notification_delivery_log_delivered" ON "notification_delivery_log" USING btree ("delivered_at");--> statement-breakpoint
CREATE INDEX "idx_notification_user_prefs_user" ON "notification_user_preferences" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "idx_notification_user_prefs_org" ON "notification_user_preferences" USING btree ("org_id");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_notification_user_prefs_user_org" ON "notification_user_preferences" USING btree ("user_id","org_id");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_onboarding_org_step" ON "onboarding_progress" USING btree ("org_id","step_key");--> statement-breakpoint
CREATE INDEX "idx_onboarding_org" ON "onboarding_progress" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_org_ai_budgets_org_id" ON "org_ai_budgets" USING btree ("org_id");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_domain_verifications_org_domain" ON "org_domain_verifications" USING btree ("org_id","domain");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_domain_verifications_domain" ON "org_domain_verifications" USING btree ("domain");--> statement-breakpoint
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
CREATE INDEX "idx_ot_anomalies_org" ON "ot_anomalies" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ot_anomalies_asset" ON "ot_anomalies" USING btree ("asset_id");--> statement-breakpoint
CREATE INDEX "idx_ot_anomalies_type" ON "ot_anomalies" USING btree ("org_id","anomaly_type");--> statement-breakpoint
CREATE INDEX "idx_ot_anomalies_severity" ON "ot_anomalies" USING btree ("org_id","severity");--> statement-breakpoint
CREATE INDEX "idx_ot_anomalies_status" ON "ot_anomalies" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_ot_anomalies_time" ON "ot_anomalies" USING btree ("org_id","detected_at");--> statement-breakpoint
CREATE INDEX "idx_ot_assets_org" ON "ot_assets" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ot_assets_type" ON "ot_assets" USING btree ("org_id","asset_type");--> statement-breakpoint
CREATE INDEX "idx_ot_assets_purdue" ON "ot_assets" USING btree ("org_id","purdue_level");--> statement-breakpoint
CREATE INDEX "idx_ot_assets_ip" ON "ot_assets" USING btree ("org_id","ip_address");--> statement-breakpoint
CREATE INDEX "idx_ot_assets_vendor" ON "ot_assets" USING btree ("org_id","vendor");--> statement-breakpoint
CREATE INDEX "idx_ot_assets_status" ON "ot_assets" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_ot_assets_critical" ON "ot_assets" USING btree ("org_id","is_critical");--> statement-breakpoint
CREATE INDEX "idx_ot_connections_org" ON "ot_connections" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ot_connections_source" ON "ot_connections" USING btree ("source_asset_id");--> statement-breakpoint
CREATE INDEX "idx_ot_connections_dest" ON "ot_connections" USING btree ("dest_asset_id");--> statement-breakpoint
CREATE INDEX "idx_ot_connections_boundary" ON "ot_connections" USING btree ("org_id","crosses_boundary");--> statement-breakpoint
CREATE INDEX "idx_ot_connections_protocol" ON "ot_connections" USING btree ("org_id","protocol");--> statement-breakpoint
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
CREATE INDEX "idx_pam_org" ON "pam_sessions" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_pam_requester" ON "pam_sessions" USING btree ("org_id","requester_id");--> statement-breakpoint
CREATE INDEX "idx_pam_status" ON "pam_sessions" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_pam_target" ON "pam_sessions" USING btree ("org_id","target_system");--> statement-breakpoint
CREATE INDEX "idx_pam_expires" ON "pam_sessions" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "idx_passive_dns_org" ON "passive_dns_records" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_passive_dns_domain" ON "passive_dns_records" USING btree ("org_id","domain");--> statement-breakpoint
CREATE INDEX "idx_passive_dns_resolved" ON "passive_dns_records" USING btree ("org_id","resolved_value");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_passive_dns_unique" ON "passive_dns_records" USING btree ("org_id","domain","record_type","resolved_value");--> statement-breakpoint
CREATE INDEX "idx_password_reset_user" ON "password_reset_tokens" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "idx_password_reset_token" ON "password_reset_tokens" USING btree ("token");--> statement-breakpoint
CREATE INDEX "peer_benchmarks_org_idx" ON "peer_benchmarks" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "peer_benchmarks_industry_idx" ON "peer_benchmarks" USING btree ("industry_segment","company_size");--> statement-breakpoint
CREATE INDEX "idx_phishsim_org" ON "phishing_simulations" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_phishsim_status" ON "phishing_simulations" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_pir_action_items_review" ON "pir_action_items" USING btree ("review_id");--> statement-breakpoint
CREATE INDEX "idx_pir_action_items_org" ON "pir_action_items" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_pir_action_items_status" ON "pir_action_items" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_plans_active" ON "plans" USING btree ("is_active");--> statement-breakpoint
CREATE INDEX "idx_plans_sort" ON "plans" USING btree ("sort_order");--> statement-breakpoint
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
CREATE INDEX "idx_pbtc_org" ON "playbook_template_catalog" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_pbtc_cat" ON "playbook_template_catalog" USING btree ("category");--> statement-breakpoint
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
CREATE INDEX "idx_ppa_org" ON "policy_pack_activations" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ppa_pack" ON "policy_pack_activations" USING btree ("org_id","pack_id");--> statement-breakpoint
CREATE INDEX "idx_ppa_status" ON "policy_pack_activations" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_policy_results_org" ON "policy_results" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_policy_results_check" ON "policy_results" USING btree ("policy_check_id");--> statement-breakpoint
CREATE INDEX "idx_policy_results_status" ON "policy_results" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_pir_incident" ON "post_incident_reviews" USING btree ("incident_id");--> statement-breakpoint
CREATE INDEX "idx_pir_org" ON "post_incident_reviews" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_pir_status" ON "post_incident_reviews" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_pir_org_created" ON "post_incident_reviews" USING btree ("org_id","created_at");--> statement-breakpoint
CREATE INDEX "posture_score_history_org_idx" ON "posture_score_history" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "posture_score_history_period_idx" ON "posture_score_history" USING btree ("org_id","period_type");--> statement-breakpoint
CREATE INDEX "posture_sub_scores_org_idx" ON "posture_sub_scores" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "posture_sub_scores_domain_idx" ON "posture_sub_scores" USING btree ("org_id","domain");--> statement-breakpoint
CREATE INDEX "idx_pia_org" ON "privacy_impact_assessments" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_pia_status" ON "privacy_impact_assessments" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_pia_risk" ON "privacy_impact_assessments" USING btree ("overall_risk");--> statement-breakpoint
CREATE INDEX "idx_privacy_scans_org" ON "privacy_scans" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_privacy_scans_status" ON "privacy_scans" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_prompt_ab_org" ON "prompt_ab_tests" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_prompt_ab_prompt" ON "prompt_ab_tests" USING btree ("prompt_id");--> statement-breakpoint
CREATE INDEX "idx_prompthist_org" ON "prompt_history" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_prompthist_fav" ON "prompt_history" USING btree ("org_id","is_favorite");--> statement-breakpoint
CREATE INDEX "idx_promptinv_org" ON "prompt_investigations" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_promptinv_status" ON "prompt_investigations" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_prompt_qs_org" ON "prompt_quality_scores" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_prompt_qs_prompt" ON "prompt_quality_scores" USING btree ("prompt_id");--> statement-breakpoint
CREATE INDEX "public_trust_pages_org_idx" ON "public_trust_pages" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "public_trust_pages_slug_idx" ON "public_trust_pages" USING btree ("slug");--> statement-breakpoint
CREATE INDEX "questionnaire_responses_org_idx" ON "questionnaire_responses" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "questionnaire_responses_qid_idx" ON "questionnaire_responses" USING btree ("questionnaire_id");--> statement-breakpoint
CREATE INDEX "idx_canary_files_org" ON "ransomware_canary_files" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_canary_files_status" ON "ransomware_canary_files" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_canary_files_host" ON "ransomware_canary_files" USING btree ("org_id","deployed_to_host");--> statement-breakpoint
CREATE INDEX "idx_ransomware_groups_org" ON "ransomware_groups" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ransomware_groups_threat" ON "ransomware_groups" USING btree ("org_id","threat_level");--> statement-breakpoint
CREATE INDEX "idx_ransomware_groups_active" ON "ransomware_groups" USING btree ("org_id","is_active");--> statement-breakpoint
CREATE INDEX "idx_ransom_org" ON "ransomware_indicators" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ransom_type" ON "ransomware_indicators" USING btree ("org_id","indicator_type");--> statement-breakpoint
CREATE INDEX "idx_ransom_family" ON "ransomware_indicators" USING btree ("org_id","threat_family");--> statement-breakpoint
CREATE INDEX "idx_kill_switch_org" ON "ransomware_kill_switch_events" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_kill_switch_status" ON "ransomware_kill_switch_events" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_kill_switch_created" ON "ransomware_kill_switch_events" USING btree ("org_id","created_at");--> statement-breakpoint
CREATE INDEX "idx_recovery_runbooks_org" ON "recovery_runbooks" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_recovery_runbooks_status" ON "recovery_runbooks" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_recovery_runbooks_incident" ON "recovery_runbooks" USING btree ("incident_id");--> statement-breakpoint
CREATE INDEX "idx_remfix_org" ON "remediation_fixes" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_remfix_status" ON "remediation_fixes" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_remfix_priority" ON "remediation_fixes" USING btree ("org_id","priority");--> statement-breakpoint
CREATE INDEX "idx_remote_sessions_org" ON "remote_worker_sessions" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_remote_sessions_user" ON "remote_worker_sessions" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "idx_remote_sessions_device" ON "remote_worker_sessions" USING btree ("device_id");--> statement-breakpoint
CREATE INDEX "idx_report_tpl_ver_template" ON "report_template_versions" USING btree ("template_id");--> statement-breakpoint
CREATE INDEX "idx_report_tpl_ver_org" ON "report_template_versions" USING btree ("org_id");--> statement-breakpoint
CREATE UNIQUE INDEX "uq_report_tpl_ver_version" ON "report_template_versions" USING btree ("template_id","version");--> statement-breakpoint
CREATE INDEX "idx_resp_approval_org" ON "response_action_approvals" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_resp_approval_status" ON "response_action_approvals" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_resp_approval_incident" ON "response_action_approvals" USING btree ("incident_id");--> statement-breakpoint
CREATE INDEX "idx_response_actions_org" ON "response_actions" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_response_actions_incident" ON "response_actions" USING btree ("incident_id");--> statement-breakpoint
CREATE INDEX "idx_response_actions_status" ON "response_actions" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_response_actions_type" ON "response_actions" USING btree ("action_type");--> statement-breakpoint
CREATE INDEX "idx_response_actions_org_created" ON "response_actions" USING btree ("org_id","created_at");--> statement-breakpoint
CREATE INDEX "idx_response_actions_org_status_created" ON "response_actions" USING btree ("org_id","status","created_at");--> statement-breakpoint
CREATE INDEX "idx_risk_reg_org" ON "risk_register" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_risk_reg_category" ON "risk_register" USING btree ("org_id","category");--> statement-breakpoint
CREATE INDEX "idx_risk_reg_status" ON "risk_register" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_risk_reg_score" ON "risk_register" USING btree ("org_id","inherent_risk_score");--> statement-breakpoint
CREATE INDEX "idx_rule_ab_tests_org" ON "rule_ab_tests" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_rule_ab_tests_rule" ON "rule_ab_tests" USING btree ("rule_id");--> statement-breakpoint
CREATE INDEX "idx_rule_ab_tests_status" ON "rule_ab_tests" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_rule_gen_jobs_org" ON "rule_generation_jobs" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_rule_gen_jobs_status" ON "rule_generation_jobs" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_rule_lifecycle_org" ON "rule_lifecycle_events" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_rule_lifecycle_rule" ON "rule_lifecycle_events" USING btree ("rule_id");--> statement-breakpoint
CREATE INDEX "idx_rule_marketplace_status" ON "rule_marketplace" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_rule_marketplace_category" ON "rule_marketplace" USING btree ("category");--> statement-breakpoint
CREATE INDEX "idx_runbook_steps_template" ON "runbook_steps" USING btree ("template_id");--> statement-breakpoint
CREATE INDEX "idx_runbook_templates_type" ON "runbook_templates" USING btree ("incident_type");--> statement-breakpoint
CREATE INDEX "idx_runbook_templates_org" ON "runbook_templates" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_rgd_org" ON "runtime_guardrail_decisions" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_rgd_verdict" ON "runtime_guardrail_decisions" USING btree ("org_id","verdict");--> statement-breakpoint
CREATE INDEX "idx_rgd_policy" ON "runtime_guardrail_decisions" USING btree ("org_id","policy_id");--> statement-breakpoint
CREATE INDEX "idx_rgo_org" ON "runtime_guardrail_overrides" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_rgo_status" ON "runtime_guardrail_overrides" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_rgo_policy" ON "runtime_guardrail_overrides" USING btree ("org_id","policy_id");--> statement-breakpoint
CREATE INDEX "idx_rgp_org" ON "runtime_guardrail_policies" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_rgp_action" ON "runtime_guardrail_policies" USING btree ("org_id","action");--> statement-breakpoint
CREATE INDEX "idx_rgp_scope" ON "runtime_guardrail_policies" USING btree ("org_id","scope");--> statement-breakpoint
CREATE INDEX "idx_sast_findings_org" ON "sast_findings" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_sast_findings_repo" ON "sast_findings" USING btree ("org_id","repository");--> statement-breakpoint
CREATE INDEX "idx_sast_findings_severity" ON "sast_findings" USING btree ("org_id","severity");--> statement-breakpoint
CREATE INDEX "idx_sast_findings_category" ON "sast_findings" USING btree ("org_id","category");--> statement-breakpoint
CREATE INDEX "idx_sast_findings_status" ON "sast_findings" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_sast_findings_pr" ON "sast_findings" USING btree ("org_id","pull_request_id");--> statement-breakpoint
CREATE INDEX "idx_sast_findings_commit" ON "sast_findings" USING btree ("org_id","commit_sha");--> statement-breakpoint
CREATE INDEX "idx_saved_views_org" ON "saved_views" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_saved_views_user" ON "saved_views" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "idx_saved_views_team" ON "saved_views" USING btree ("team_id");--> statement-breakpoint
CREATE INDEX "idx_saved_views_resource" ON "saved_views" USING btree ("org_id","resource_type");--> statement-breakpoint
CREATE INDEX "idx_saved_views_visibility" ON "saved_views" USING btree ("org_id","visibility");--> statement-breakpoint
CREATE INDEX "idx_sbom_artifacts_org" ON "sbom_artifacts" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_sbom_artifacts_org_created" ON "sbom_artifacts" USING btree ("org_id","created_at");--> statement-breakpoint
CREATE INDEX "idx_sbom_artifacts_status" ON "sbom_artifacts" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_scim_org" ON "scim_provisioning_logs" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_scim_provider" ON "scim_provisioning_logs" USING btree ("org_id","provider");--> statement-breakpoint
CREATE INDEX "idx_scim_operation" ON "scim_provisioning_logs" USING btree ("org_id","operation_type");--> statement-breakpoint
CREATE INDEX "idx_scim_ext_user" ON "scim_provisioning_logs" USING btree ("external_user_id");--> statement-breakpoint
CREATE INDEX "idx_secrets_exposed_org" ON "secrets_exposed" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_secrets_exposed_repo" ON "secrets_exposed" USING btree ("org_id","repository");--> statement-breakpoint
CREATE INDEX "idx_secrets_exposed_type" ON "secrets_exposed" USING btree ("org_id","secret_type");--> statement-breakpoint
CREATE INDEX "idx_secrets_exposed_status" ON "secrets_exposed" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_secrets_exposed_commit" ON "secrets_exposed" USING btree ("org_id","commit_sha");--> statement-breakpoint
CREATE INDEX "idx_sec_assess_org" ON "security_assessments" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_sec_assess_framework" ON "security_assessments" USING btree ("org_id","framework");--> statement-breakpoint
CREATE INDEX "idx_sec_assess_status" ON "security_assessments" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_security_debt_org" ON "security_debt_items" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_security_debt_repo" ON "security_debt_items" USING btree ("org_id","repository");--> statement-breakpoint
CREATE INDEX "idx_security_debt_priority" ON "security_debt_items" USING btree ("org_id","priority");--> statement-breakpoint
CREATE INDEX "idx_security_debt_status" ON "security_debt_items" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_sg_assets_org" ON "security_graph_assets" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_sg_assets_type" ON "security_graph_assets" USING btree ("org_id","type");--> statement-breakpoint
CREATE INDEX "idx_sg_assets_env" ON "security_graph_assets" USING btree ("org_id","environment");--> statement-breakpoint
CREATE INDEX "idx_sg_assets_resolution" ON "security_graph_assets" USING btree ("org_id","resolution_key");--> statement-breakpoint
CREATE INDEX "idx_sg_rels_org" ON "security_graph_relationships" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_sg_rels_source" ON "security_graph_relationships" USING btree ("source_id");--> statement-breakpoint
CREATE INDEX "idx_sg_rels_target" ON "security_graph_relationships" USING btree ("target_id");--> statement-breakpoint
CREATE INDEX "idx_sg_rels_type" ON "security_graph_relationships" USING btree ("org_id","relationship");--> statement-breakpoint
CREATE INDEX "idx_kpi_snapshots_org" ON "security_kpi_snapshots" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_kpi_snapshots_org_type" ON "security_kpi_snapshots" USING btree ("org_id","kpi_type");--> statement-breakpoint
CREATE INDEX "idx_kpi_snapshots_org_period" ON "security_kpi_snapshots" USING btree ("org_id","period_start");--> statement-breakpoint
CREATE INDEX "security_questionnaires_org_idx" ON "security_questionnaires" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "security_questionnaires_status_idx" ON "security_questionnaires" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_tool_overlaps_org" ON "security_tool_overlaps" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_sensor_events_org" ON "sensor_events" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_sensor_events_sensor" ON "sensor_events" USING btree ("sensor_id");--> statement-breakpoint
CREATE INDEX "idx_sensor_events_type" ON "sensor_events" USING btree ("org_id","event_type");--> statement-breakpoint
CREATE INDEX "idx_sensor_events_ts" ON "sensor_events" USING btree ("org_id","timestamp");--> statement-breakpoint
CREATE INDEX "shared_iocs_type_idx" ON "shared_iocs" USING btree ("ioc_type");--> statement-breakpoint
CREATE INDEX "shared_iocs_value_hash_idx" ON "shared_iocs" USING btree ("ioc_value_hash");--> statement-breakpoint
CREATE INDEX "shared_iocs_severity_idx" ON "shared_iocs" USING btree ("severity");--> statement-breakpoint
CREATE INDEX "shared_iocs_active_idx" ON "shared_iocs" USING btree ("is_active");--> statement-breakpoint
CREATE INDEX "shared_iocs_first_seen_idx" ON "shared_iocs" USING btree ("first_seen_at");--> statement-breakpoint
CREATE INDEX "sharing_consents_org_idx" ON "sharing_consents" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "sharing_consents_sector_idx" ON "sharing_consents" USING btree ("industry_sector");--> statement-breakpoint
CREATE INDEX "idx_sinkholed_org" ON "sinkholed_domains" USING btree ("org_id");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_sinkholed_org_domain" ON "sinkholed_domains" USING btree ("org_id","domain");--> statement-breakpoint
CREATE INDEX "idx_sinkholed_org_status" ON "sinkholed_domains" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_sli_metrics_service_metric_recorded" ON "sli_metrics" USING btree ("service","metric","recorded_at");--> statement-breakpoint
CREATE INDEX "idx_sli_metrics_recorded" ON "sli_metrics" USING btree ("recorded_at");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_sli_daily_unique" ON "sli_metrics_daily" USING btree ("service","metric","day");--> statement-breakpoint
CREATE INDEX "idx_sli_daily_day" ON "sli_metrics_daily" USING btree ("day");--> statement-breakpoint
CREATE INDEX "idx_sli_daily_service_day" ON "sli_metrics_daily" USING btree ("service","day");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_sli_hourly_unique" ON "sli_metrics_hourly" USING btree ("service","metric","hour");--> statement-breakpoint
CREATE INDEX "idx_sli_hourly_hour" ON "sli_metrics_hourly" USING btree ("hour");--> statement-breakpoint
CREATE INDEX "idx_sli_hourly_service_hour" ON "sli_metrics_hourly" USING btree ("service","hour");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_slo_targets_service_metric_endpoint" ON "slo_targets" USING btree ("service","metric","endpoint");--> statement-breakpoint
CREATE INDEX "idx_sovereign_keys_org" ON "sovereign_keys" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_sovereign_keys_status" ON "sovereign_keys" USING btree ("status");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_subscriptions_org" ON "subscriptions" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_subscriptions_stripe_customer" ON "subscriptions" USING btree ("stripe_customer_id");--> statement-breakpoint
CREATE INDEX "idx_subscriptions_status" ON "subscriptions" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_scc_org" ON "supply_chain_components" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_scc_type" ON "supply_chain_components" USING btree ("org_id","component_type");--> statement-breakpoint
CREATE INDEX "idx_scc_risk" ON "supply_chain_components" USING btree ("org_id","risk_score");--> statement-breakpoint
CREATE INDEX "idx_sc_findings_org" ON "supply_chain_findings" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_sc_findings_sbom" ON "supply_chain_findings" USING btree ("sbom_id");--> statement-breakpoint
CREATE INDEX "idx_sc_findings_type" ON "supply_chain_findings" USING btree ("org_id","finding_type");--> statement-breakpoint
CREATE INDEX "idx_sc_findings_severity" ON "supply_chain_findings" USING btree ("org_id","severity");--> statement-breakpoint
CREATE INDEX "idx_sc_findings_status" ON "supply_chain_findings" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_sc_findings_cve" ON "supply_chain_findings" USING btree ("cve_id");--> statement-breakpoint
CREATE INDEX "idx_sc_findings_pkg" ON "supply_chain_findings" USING btree ("org_id","package_name");--> statement-breakpoint
CREATE INDEX "idx_suppression_rules_org" ON "suppression_rules" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_suppression_rules_enabled" ON "suppression_rules" USING btree ("enabled");--> statement-breakpoint
CREATE INDEX "idx_suppression_rules_expires" ON "suppression_rules" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "idx_suppression_rules_owner" ON "suppression_rules" USING btree ("owned_by");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_table_partitions_unique" ON "table_partitions" USING btree ("table_name","partition_name");--> statement-breakpoint
CREATE INDEX "idx_table_partitions_table_status" ON "table_partitions" USING btree ("table_name","status");--> statement-breakpoint
CREATE INDEX "idx_tabletop_org" ON "tabletop_exercises" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_tabletop_status" ON "tabletop_exercises" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_tabletop_type" ON "tabletop_exercises" USING btree ("org_id","scenario_type");--> statement-breakpoint
CREATE INDEX "idx_tabletop_scheduled" ON "tabletop_exercises" USING btree ("org_id","scheduled_at");--> statement-breakpoint
CREATE INDEX "idx_tdj_org" ON "tenant_data_jobs" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_tdj_type" ON "tenant_data_jobs" USING btree ("org_id","job_type");--> statement-breakpoint
CREATE INDEX "idx_tdj_status" ON "tenant_data_jobs" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_th_hunts_org" ON "threat_hunts" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_th_hunts_status" ON "threat_hunts" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_threat_intel_configs_org" ON "threat_intel_configs" USING btree ("org_id");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_threat_intel_configs_org_provider" ON "threat_intel_configs" USING btree ("org_id","provider");--> statement-breakpoint
CREATE INDEX "idx_threat_reports_org" ON "threat_reports" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_threat_reports_status" ON "threat_reports" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_threat_reports_category" ON "threat_reports" USING btree ("org_id","category");--> statement-breakpoint
CREATE INDEX "idx_threat_reports_reporter" ON "threat_reports" USING btree ("reporter_user_id");--> statement-breakpoint
CREATE INDEX "idx_ticket_sync_org" ON "ticket_sync_jobs" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ticket_sync_integration" ON "ticket_sync_jobs" USING btree ("integration_id");--> statement-breakpoint
CREATE INDEX "idx_ticket_sync_incident" ON "ticket_sync_jobs" USING btree ("incident_id");--> statement-breakpoint
CREATE INDEX "idx_tiering_jobs_org" ON "tiering_jobs" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_tiering_jobs_status" ON "tiering_jobs" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_tiering_jobs_org_type" ON "tiering_jobs" USING btree ("org_id","data_type");--> statement-breakpoint
CREATE INDEX "idx_tprma_org" ON "tprm_assessments" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_tprma_vendor" ON "tprm_assessments" USING btree ("org_id","vendor_id");--> statement-breakpoint
CREATE INDEX "idx_tprma_status" ON "tprm_assessments" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_tprm_org" ON "tprm_vendors" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_tprm_tier" ON "tprm_vendors" USING btree ("org_id","tier");--> statement-breakpoint
CREATE INDEX "idx_tprm_risk" ON "tprm_vendors" USING btree ("org_id","risk_rating");--> statement-breakpoint
CREATE INDEX "idx_tc_artifacts_org" ON "trust_center_artifacts" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_tc_artifacts_category" ON "trust_center_artifacts" USING btree ("org_id","category");--> statement-breakpoint
CREATE INDEX "idx_tc_artifacts_status" ON "trust_center_artifacts" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_tc_downloads_org" ON "trust_center_download_log" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_tc_downloads_artifact" ON "trust_center_download_log" USING btree ("artifact_id");--> statement-breakpoint
CREATE INDEX "idx_ttv_org" ON "ttv_milestones" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ttv_kind" ON "ttv_milestones" USING btree ("org_id","kind");--> statement-breakpoint
CREATE INDEX "idx_ueba_anomalies_org" ON "ueba_anomalies" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ueba_anomalies_entity" ON "ueba_anomalies" USING btree ("org_id","entity_type","entity_id");--> statement-breakpoint
CREATE INDEX "idx_ueba_anomalies_type" ON "ueba_anomalies" USING btree ("org_id","anomaly_type");--> statement-breakpoint
CREATE INDEX "idx_ueba_anomalies_created" ON "ueba_anomalies" USING btree ("org_id","created_at");--> statement-breakpoint
CREATE INDEX "idx_ueba_baselines_org" ON "ueba_baselines" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ueba_baselines_entity" ON "ueba_baselines" USING btree ("org_id","entity_type","entity_id");--> statement-breakpoint
CREATE INDEX "idx_ueba_scores_org" ON "ueba_entity_scores" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ueba_scores_risk" ON "ueba_entity_scores" USING btree ("org_id","risk_score");--> statement-breakpoint
CREATE INDEX "idx_ueba_scores_entity" ON "ueba_entity_scores" USING btree ("org_id","entity_type","entity_id");--> statement-breakpoint
CREATE INDEX "idx_usage_meter_org" ON "usage_meter_snapshots" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_usage_meter_type" ON "usage_meter_snapshots" USING btree ("metric_type");--> statement-breakpoint
CREATE INDEX "idx_usage_meter_period" ON "usage_meter_snapshots" USING btree ("period_start","period_end");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_usage_records_org_metric_period" ON "usage_records" USING btree ("org_id","metric","period_start");--> statement-breakpoint
CREATE INDEX "idx_usage_records_org" ON "usage_records" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_usage_records_period" ON "usage_records" USING btree ("period_start","period_end");--> statement-breakpoint
CREATE INDEX "idx_vendor_assessments_org" ON "vendor_assessments" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_vendor_assessments_vendor" ON "vendor_assessments" USING btree ("org_id","vendor_id");--> statement-breakpoint
CREATE INDEX "idx_vendor_assessments_status" ON "vendor_assessments" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_vendor_assessments_due" ON "vendor_assessments" USING btree ("org_id","due_date");--> statement-breakpoint
CREATE INDEX "idx_vendor_breach_alerts_org" ON "vendor_breach_alerts" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_vendor_breach_alerts_vendor" ON "vendor_breach_alerts" USING btree ("org_id","vendor_id");--> statement-breakpoint
CREATE INDEX "idx_vendor_breach_alerts_status" ON "vendor_breach_alerts" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_vendor_monitoring_org" ON "vendor_monitoring" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_vendor_monitoring_vendor" ON "vendor_monitoring" USING btree ("org_id","vendor_id");--> statement-breakpoint
CREATE INDEX "idx_vendor_monitoring_type" ON "vendor_monitoring" USING btree ("org_id","check_type");--> statement-breakpoint
CREATE INDEX "idx_vendor_monitoring_status" ON "vendor_monitoring" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_vendor_risks_org" ON "vendor_risks" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_vendor_risks_vendor" ON "vendor_risks" USING btree ("org_id","vendor_id");--> statement-breakpoint
CREATE INDEX "idx_vendor_risks_severity" ON "vendor_risks" USING btree ("org_id","severity");--> statement-breakpoint
CREATE INDEX "idx_vendor_risks_status" ON "vendor_risks" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_vendors_org" ON "vendors" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_vendors_status" ON "vendors" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_vendors_risk_tier" ON "vendors" USING btree ("org_id","risk_tier");--> statement-breakpoint
CREATE INDEX "idx_vendors_category" ON "vendors" USING btree ("org_id","category");--> statement-breakpoint
CREATE INDEX "idx_vendors_domain" ON "vendors" USING btree ("org_id","domain");--> statement-breakpoint
CREATE INDEX "idx_vendors_next_review" ON "vendors" USING btree ("org_id","next_review_date");--> statement-breakpoint
CREATE INDEX "idx_vuln_findings_org" ON "vuln_findings" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_vuln_findings_sensor" ON "vuln_findings" USING btree ("sensor_id");--> statement-breakpoint
CREATE INDEX "idx_vuln_findings_cve" ON "vuln_findings" USING btree ("cve_id");--> statement-breakpoint
CREATE INDEX "idx_vuln_findings_status" ON "vuln_findings" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_vuln_findings_severity" ON "vuln_findings" USING btree ("org_id","severity");--> statement-breakpoint
CREATE INDEX "idx_vuln_packages_org" ON "vuln_packages" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_vuln_packages_sensor" ON "vuln_packages" USING btree ("sensor_id");--> statement-breakpoint
CREATE INDEX "idx_vuln_packages_vuln" ON "vuln_packages" USING btree ("org_id","is_vulnerable");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_vuln_packages_unique" ON "vuln_packages" USING btree ("org_id","sensor_id","package_manager","package_name");--> statement-breakpoint
CREATE INDEX "idx_vscan_org" ON "vuln_scans" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_vscan_status" ON "vuln_scans" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_vuln_sla_org" ON "vulnerability_sla_targets" USING btree ("org_id");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_vuln_sla_org_severity" ON "vulnerability_sla_targets" USING btree ("org_id","severity");--> statement-breakpoint
CREATE INDEX "idx_wr_actions_room" ON "war_room_action_items" USING btree ("war_room_id");--> statement-breakpoint
CREATE INDEX "idx_wr_actions_org" ON "war_room_action_items" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_wr_actions_status" ON "war_room_action_items" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_wr_activity_room" ON "war_room_activity_log" USING btree ("war_room_id");--> statement-breakpoint
CREATE INDEX "idx_wr_activity_org" ON "war_room_activity_log" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_wr_activity_created" ON "war_room_activity_log" USING btree ("created_at");--> statement-breakpoint
CREATE INDEX "idx_wr_handoffs_room" ON "war_room_handoffs" USING btree ("war_room_id");--> statement-breakpoint
CREATE INDEX "idx_wr_handoffs_org" ON "war_room_handoffs" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_wr_messages_room" ON "war_room_messages" USING btree ("war_room_id");--> statement-breakpoint
CREATE INDEX "idx_wr_messages_org" ON "war_room_messages" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_wr_messages_created" ON "war_room_messages" USING btree ("created_at");--> statement-breakpoint
CREATE INDEX "idx_wr_messages_parent" ON "war_room_messages" USING btree ("parent_message_id");--> statement-breakpoint
CREATE INDEX "idx_wr_participants_room" ON "war_room_participants" USING btree ("war_room_id");--> statement-breakpoint
CREATE INDEX "idx_wr_participants_user" ON "war_room_participants" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "idx_wr_templates_org" ON "war_room_templates" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_wr_templates_type" ON "war_room_templates" USING btree ("incident_type");--> statement-breakpoint
CREATE INDEX "idx_war_rooms_org" ON "war_rooms" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_war_rooms_incident" ON "war_rooms" USING btree ("incident_id");--> statement-breakpoint
CREATE INDEX "idx_war_rooms_status" ON "war_rooms" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_wizard_progress_org" ON "wizard_progress" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_wizard_progress_user" ON "wizard_progress" USING btree ("user_id");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_wizard_progress_user_unique" ON "wizard_progress" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "idx_ztna_policies_org" ON "ztna_policies" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_failed_login_email" ON "failed_login_attempts" USING btree ("email");--> statement-breakpoint
CREATE INDEX "idx_failed_login_user" ON "failed_login_attempts" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "idx_failed_login_ip" ON "failed_login_attempts" USING btree ("ip_address");--> statement-breakpoint
CREATE INDEX "idx_failed_login_attempted" ON "failed_login_attempts" USING btree ("attempted_at");--> statement-breakpoint
CREATE INDEX "idx_impersonation_admin" ON "impersonation_sessions" USING btree ("super_admin_id");--> statement-breakpoint
CREATE INDEX "idx_impersonation_target" ON "impersonation_sessions" USING btree ("target_user_id");--> statement-breakpoint
CREATE INDEX "idx_impersonation_session" ON "impersonation_sessions" USING btree ("session_sid");--> statement-breakpoint
CREATE INDEX "IDX_session_expire" ON "sessions" USING btree ("expire");