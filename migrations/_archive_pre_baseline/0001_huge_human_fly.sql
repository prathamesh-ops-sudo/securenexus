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
	"org_id" uuid NOT NULL,
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
	"org_id" uuid NOT NULL,
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
CREATE TABLE "control_effectiveness" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" uuid NOT NULL,
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
	"org_id" uuid NOT NULL,
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
	"executed_by" text
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
	"org_id" uuid NOT NULL,
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
	"org_id" uuid NOT NULL,
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
	"org_id" uuid NOT NULL,
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
	"org_id" uuid NOT NULL,
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
	"org_id" uuid NOT NULL,
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
CREATE TABLE "vuln_findings" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" varchar NOT NULL,
	"sensor_id" varchar NOT NULL,
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
ALTER TABLE "alert_dedup_clusters" DROP CONSTRAINT "alert_dedup_clusters_canonical_alert_id_alerts_id_fk";
--> statement-breakpoint
ALTER TABLE "ioc_matches" DROP CONSTRAINT "ioc_matches_alert_id_alerts_id_fk";
--> statement-breakpoint
DROP INDEX "idx_evidence_chain_seq";--> statement-breakpoint
ALTER TABLE "audit_logs" ADD COLUMN "user_agent" text;--> statement-breakpoint
ALTER TABLE "audit_logs" ADD COLUMN "impersonated_by" varchar;--> statement-breakpoint
ALTER TABLE "audit_logs" ADD COLUMN "request_id" varchar;--> statement-breakpoint
ALTER TABLE "ioc_match_rules" ADD COLUMN "feed_id" varchar;--> statement-breakpoint
ALTER TABLE "org_domain_verifications" ADD COLUMN "auto_join" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "org_domain_verifications" ADD COLUMN "default_role" text DEFAULT 'analyst' NOT NULL;--> statement-breakpoint
ALTER TABLE "organizations" ADD COLUMN "billing_email" text;--> statement-breakpoint
ALTER TABLE "organizations" ADD COLUMN "phone" text;--> statement-breakpoint
ALTER TABLE "organizations" ADD COLUMN "address" jsonb;--> statement-breakpoint
ALTER TABLE "organizations" ADD COLUMN "company_size" text;--> statement-breakpoint
ALTER TABLE "organizations" ADD COLUMN "logo_url" text;--> statement-breakpoint
ALTER TABLE "organizations" ADD COLUMN "primary_color" text;--> statement-breakpoint
ALTER TABLE "organizations" ADD COLUMN "locale" text DEFAULT 'en-US';--> statement-breakpoint
ALTER TABLE "organizations" ADD COLUMN "timezone" text DEFAULT 'UTC';--> statement-breakpoint
ALTER TABLE "organizations" ADD COLUMN "org_type" text DEFAULT 'standard' NOT NULL;--> statement-breakpoint
ALTER TABLE "organizations" ADD COLUMN "parent_org_id" varchar;--> statement-breakpoint
ALTER TABLE "organizations" ADD COLUMN "data_residency" text DEFAULT 'us-east-1';--> statement-breakpoint
ALTER TABLE "organizations" ADD COLUMN "data_region" text DEFAULT 'US';--> statement-breakpoint
ALTER TABLE "organizations" ADD COLUMN "sovereign_key_config" jsonb;--> statement-breakpoint
ALTER TABLE "organizations" ADD COLUMN "cross_border_flow_controls" jsonb;--> statement-breakpoint
ALTER TABLE "organizations" ADD COLUMN "default_member_role" text DEFAULT 'analyst' NOT NULL;--> statement-breakpoint
ALTER TABLE "organizations" ADD COLUMN "require_approval" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "organizations" ADD COLUMN "deleted_at" timestamp;--> statement-breakpoint
ALTER TABLE "organizations" ADD COLUMN "updated_at" timestamp DEFAULT now();--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "is_super_admin" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "disabled_at" timestamp;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "last_login_at" timestamp;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "password_changed_at" timestamp;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "locked_until" timestamp;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "failed_login_count" integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "mfa_enabled" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "mfa_secret" varchar;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "mfa_verified_at" timestamp;--> statement-breakpoint
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
ALTER TABLE "api_findings" ADD CONSTRAINT "api_findings_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "api_findings" ADD CONSTRAINT "api_findings_api_id_api_inventory_id_fk" FOREIGN KEY ("api_id") REFERENCES "public"."api_inventory"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "api_inventory" ADD CONSTRAINT "api_inventory_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "api_traffic_baselines" ADD CONSTRAINT "api_traffic_baselines_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "api_traffic_baselines" ADD CONSTRAINT "api_traffic_baselines_api_id_api_inventory_id_fk" FOREIGN KEY ("api_id") REFERENCES "public"."api_inventory"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "assessment_responses" ADD CONSTRAINT "assessment_responses_assessment_id_security_assessments_id_fk" FOREIGN KEY ("assessment_id") REFERENCES "public"."security_assessments"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "assessment_responses" ADD CONSTRAINT "assessment_responses_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "asset_inventory" ADD CONSTRAINT "asset_inventory_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "attack_graph_edges" ADD CONSTRAINT "attack_graph_edges_graph_id_attack_graphs_id_fk" FOREIGN KEY ("graph_id") REFERENCES "public"."attack_graphs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "attack_graph_nodes" ADD CONSTRAINT "attack_graph_nodes_graph_id_attack_graphs_id_fk" FOREIGN KEY ("graph_id") REFERENCES "public"."attack_graphs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "attack_graphs" ADD CONSTRAINT "attack_graphs_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "attack_graphs" ADD CONSTRAINT "attack_graphs_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "autonomy_log" ADD CONSTRAINT "autonomy_log_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "autonomy_log" ADD CONSTRAINT "autonomy_log_decision_id_ai_analyst_decisions_id_fk" FOREIGN KEY ("decision_id") REFERENCES "public"."ai_analyst_decisions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "backup_verifications" ADD CONSTRAINT "backup_verifications_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "canary_tokens" ADD CONSTRAINT "canary_tokens_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ci_gates" ADD CONSTRAINT "ci_gates_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "code_review_findings" ADD CONSTRAINT "code_review_findings_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
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
ALTER TABLE "detection_rules" ADD CONSTRAINT "detection_rules_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dr_drill_results" ADD CONSTRAINT "dr_drill_results_runbook_id_dr_runbooks_id_fk" FOREIGN KEY ("runbook_id") REFERENCES "public"."dr_runbooks"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "engine_configs" ADD CONSTRAINT "engine_configs_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "engine_dry_runs" ADD CONSTRAINT "engine_dry_runs_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "engine_explainability_logs" ADD CONSTRAINT "engine_explainability_logs_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "evidence_attachments" ADD CONSTRAINT "evidence_attachments_control_mapping_id_compliance_control_mappings_id_fk" FOREIGN KEY ("control_mapping_id") REFERENCES "public"."compliance_control_mappings"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "evidence_attachments" ADD CONSTRAINT "evidence_attachments_evidence_locker_id_evidence_locker_items_id_fk" FOREIGN KEY ("evidence_locker_id") REFERENCES "public"."evidence_locker_items"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "honeypot_assets" ADD CONSTRAINT "honeypot_assets_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hunt_library" ADD CONSTRAINT "hunt_library_hunt_id_threat_hunts_id_fk" FOREIGN KEY ("hunt_id") REFERENCES "public"."threat_hunts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hunt_results" ADD CONSTRAINT "hunt_results_hunt_id_threat_hunts_id_fk" FOREIGN KEY ("hunt_id") REFERENCES "public"."threat_hunts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hunt_schedules" ADD CONSTRAINT "hunt_schedules_hunt_id_threat_hunts_id_fk" FOREIGN KEY ("hunt_id") REFERENCES "public"."threat_hunts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_access_graph" ADD CONSTRAINT "identity_access_graph_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_risk_profiles" ADD CONSTRAINT "identity_risk_profiles_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "industrial_protocol_events" ADD CONSTRAINT "industrial_protocol_events_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "industrial_protocol_events" ADD CONSTRAINT "industrial_protocol_events_asset_id_ot_assets_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."ot_assets"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "industrial_protocol_events" ADD CONSTRAINT "industrial_protocol_events_anomaly_id_ot_anomalies_id_fk" FOREIGN KEY ("anomaly_id") REFERENCES "public"."ot_anomalies"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_chat_messages" ADD CONSTRAINT "investigation_chat_messages_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_chat_messages" ADD CONSTRAINT "investigation_chat_messages_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "invoices" ADD CONSTRAINT "invoices_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "invoices" ADD CONSTRAINT "invoices_subscription_id_subscriptions_id_fk" FOREIGN KEY ("subscription_id") REFERENCES "public"."subscriptions"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "log_sources" ADD CONSTRAINT "log_sources_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "log_sources" ADD CONSTRAINT "log_sources_sensor_id_native_sensors_id_fk" FOREIGN KEY ("sensor_id") REFERENCES "public"."native_sensors"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
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
ALTER TABLE "notification_delivery_log" ADD CONSTRAINT "notification_delivery_log_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "notification_user_preferences" ADD CONSTRAINT "notification_user_preferences_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ot_anomalies" ADD CONSTRAINT "ot_anomalies_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ot_anomalies" ADD CONSTRAINT "ot_anomalies_asset_id_ot_assets_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."ot_assets"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ot_anomalies" ADD CONSTRAINT "ot_anomalies_connection_id_ot_connections_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."ot_connections"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ot_anomalies" ADD CONSTRAINT "ot_anomalies_alert_id_alerts_id_fk" FOREIGN KEY ("alert_id") REFERENCES "public"."alerts"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ot_assets" ADD CONSTRAINT "ot_assets_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ot_connections" ADD CONSTRAINT "ot_connections_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ot_connections" ADD CONSTRAINT "ot_connections_source_asset_id_ot_assets_id_fk" FOREIGN KEY ("source_asset_id") REFERENCES "public"."ot_assets"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ot_connections" ADD CONSTRAINT "ot_connections_dest_asset_id_ot_assets_id_fk" FOREIGN KEY ("dest_asset_id") REFERENCES "public"."ot_assets"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "pam_sessions" ADD CONSTRAINT "pam_sessions_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ransomware_canary_files" ADD CONSTRAINT "ransomware_canary_files_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ransomware_groups" ADD CONSTRAINT "ransomware_groups_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ransomware_kill_switch_events" ADD CONSTRAINT "ransomware_kill_switch_events_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "recovery_runbooks" ADD CONSTRAINT "recovery_runbooks_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "report_template_versions" ADD CONSTRAINT "report_template_versions_template_id_report_templates_id_fk" FOREIGN KEY ("template_id") REFERENCES "public"."report_templates"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "risk_register" ADD CONSTRAINT "risk_register_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sast_findings" ADD CONSTRAINT "sast_findings_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sbom_artifacts" ADD CONSTRAINT "sbom_artifacts_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scim_provisioning_logs" ADD CONSTRAINT "scim_provisioning_logs_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "secrets_exposed" ADD CONSTRAINT "secrets_exposed_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "security_assessments" ADD CONSTRAINT "security_assessments_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "security_debt_items" ADD CONSTRAINT "security_debt_items_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sensor_events" ADD CONSTRAINT "sensor_events_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sensor_events" ADD CONSTRAINT "sensor_events_sensor_id_native_sensors_id_fk" FOREIGN KEY ("sensor_id") REFERENCES "public"."native_sensors"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "subscriptions" ADD CONSTRAINT "subscriptions_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "subscriptions" ADD CONSTRAINT "subscriptions_plan_id_plans_id_fk" FOREIGN KEY ("plan_id") REFERENCES "public"."plans"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "supply_chain_findings" ADD CONSTRAINT "supply_chain_findings_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "supply_chain_findings" ADD CONSTRAINT "supply_chain_findings_sbom_id_sbom_artifacts_id_fk" FOREIGN KEY ("sbom_id") REFERENCES "public"."sbom_artifacts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "supply_chain_findings" ADD CONSTRAINT "supply_chain_findings_dependency_id_dependency_graph_id_fk" FOREIGN KEY ("dependency_id") REFERENCES "public"."dependency_graph"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tabletop_exercises" ADD CONSTRAINT "tabletop_exercises_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "threat_reports" ADD CONSTRAINT "threat_reports_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ueba_anomalies" ADD CONSTRAINT "ueba_anomalies_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ueba_baselines" ADD CONSTRAINT "ueba_baselines_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ueba_entity_scores" ADD CONSTRAINT "ueba_entity_scores_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
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
ALTER TABLE "vuln_findings" ADD CONSTRAINT "vuln_findings_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vuln_findings" ADD CONSTRAINT "vuln_findings_sensor_id_native_sensors_id_fk" FOREIGN KEY ("sensor_id") REFERENCES "public"."native_sensors"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vuln_findings" ADD CONSTRAINT "vuln_findings_package_id_vuln_packages_id_fk" FOREIGN KEY ("package_id") REFERENCES "public"."vuln_packages"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vuln_packages" ADD CONSTRAINT "vuln_packages_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vuln_packages" ADD CONSTRAINT "vuln_packages_sensor_id_native_sensors_id_fk" FOREIGN KEY ("sensor_id") REFERENCES "public"."native_sensors"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "war_room_action_items" ADD CONSTRAINT "war_room_action_items_war_room_id_war_rooms_id_fk" FOREIGN KEY ("war_room_id") REFERENCES "public"."war_rooms"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "war_room_action_items" ADD CONSTRAINT "war_room_action_items_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "war_room_handoffs" ADD CONSTRAINT "war_room_handoffs_war_room_id_war_rooms_id_fk" FOREIGN KEY ("war_room_id") REFERENCES "public"."war_rooms"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "war_room_handoffs" ADD CONSTRAINT "war_room_handoffs_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "war_room_messages" ADD CONSTRAINT "war_room_messages_war_room_id_war_rooms_id_fk" FOREIGN KEY ("war_room_id") REFERENCES "public"."war_rooms"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "war_room_messages" ADD CONSTRAINT "war_room_messages_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "war_room_participants" ADD CONSTRAINT "war_room_participants_war_room_id_war_rooms_id_fk" FOREIGN KEY ("war_room_id") REFERENCES "public"."war_rooms"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
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
CREATE INDEX "idx_agent_actions_org" ON "agent_response_actions" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_agent_actions_sensor" ON "agent_response_actions" USING btree ("sensor_id");--> statement-breakpoint
CREATE INDEX "idx_agent_actions_status" ON "agent_response_actions" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_agent_actions_type" ON "agent_response_actions" USING btree ("org_id","action_type");--> statement-breakpoint
CREATE INDEX "idx_agent_actions_created" ON "agent_response_actions" USING btree ("org_id","created_at");--> statement-breakpoint
CREATE INDEX "idx_ai_decisions_org" ON "ai_analyst_decisions" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ai_decisions_alert" ON "ai_analyst_decisions" USING btree ("alert_id");--> statement-breakpoint
CREATE INDEX "idx_ai_decisions_incident" ON "ai_analyst_decisions" USING btree ("incident_id");--> statement-breakpoint
CREATE INDEX "idx_ai_decisions_tier" ON "ai_analyst_decisions" USING btree ("org_id","tier");--> statement-breakpoint
CREATE INDEX "idx_ai_decisions_outcome" ON "ai_analyst_decisions" USING btree ("org_id","outcome");--> statement-breakpoint
CREATE INDEX "idx_ai_decisions_status" ON "ai_analyst_decisions" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_ai_decisions_created" ON "ai_analyst_decisions" USING btree ("org_id","created_at");--> statement-breakpoint
CREATE INDEX "idx_ai_rules_org" ON "ai_generated_rules" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ai_rules_incident" ON "ai_generated_rules" USING btree ("source_incident_id");--> statement-breakpoint
CREATE INDEX "idx_ai_rules_status" ON "ai_generated_rules" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_ai_prompt_audit_prompt" ON "ai_prompt_audit_log" USING btree ("prompt_id");--> statement-breakpoint
CREATE INDEX "idx_ai_prompt_audit_action" ON "ai_prompt_audit_log" USING btree ("action");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_ai_prompt_versions_prompt_version" ON "ai_prompt_versions" USING btree ("prompt_id","version");--> statement-breakpoint
CREATE INDEX "idx_ai_prompt_versions_prompt" ON "ai_prompt_versions" USING btree ("prompt_id");--> statement-breakpoint
CREATE INDEX "idx_ai_prompt_versions_org" ON "ai_prompt_versions" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ai_prompts_org" ON "ai_prompts" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ai_prompts_tier" ON "ai_prompts" USING btree ("tier");--> statement-breakpoint
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
CREATE INDEX "idx_api_baselines_org" ON "api_traffic_baselines" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_api_baselines_api" ON "api_traffic_baselines" USING btree ("api_id");--> statement-breakpoint
CREATE INDEX "idx_api_baselines_window" ON "api_traffic_baselines" USING btree ("api_id","window_start");--> statement-breakpoint
CREATE INDEX "idx_api_baselines_anomaly" ON "api_traffic_baselines" USING btree ("org_id","anomaly_score");--> statement-breakpoint
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
CREATE INDEX "idx_autonomy_log_org" ON "autonomy_log" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_autonomy_log_decision" ON "autonomy_log" USING btree ("decision_id");--> statement-breakpoint
CREATE INDEX "idx_autonomy_log_action" ON "autonomy_log" USING btree ("org_id","action");--> statement-breakpoint
CREATE INDEX "idx_autonomy_log_tier" ON "autonomy_log" USING btree ("org_id","tier");--> statement-breakpoint
CREATE INDEX "idx_autonomy_log_created" ON "autonomy_log" USING btree ("org_id","created_at");--> statement-breakpoint
CREATE INDEX "idx_backup_verify_org" ON "backup_verifications" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_backup_verify_status" ON "backup_verifications" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_backup_verify_type" ON "backup_verifications" USING btree ("org_id","backup_type");--> statement-breakpoint
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
CREATE INDEX "idx_code_review_org" ON "code_review_findings" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_code_review_repo" ON "code_review_findings" USING btree ("org_id","repository");--> statement-breakpoint
CREATE INDEX "idx_code_review_pr" ON "code_review_findings" USING btree ("org_id","pull_request_id");--> statement-breakpoint
CREATE INDEX "idx_cold_inv_org" ON "cold_storage_inventory" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_cold_inv_org_type" ON "cold_storage_inventory" USING btree ("org_id","data_type");--> statement-breakpoint
CREATE INDEX "idx_cold_inv_tier" ON "cold_storage_inventory" USING btree ("tier");--> statement-breakpoint
CREATE INDEX "idx_cold_inv_purge" ON "cold_storage_inventory" USING btree ("purge_eligible_at");--> statement-breakpoint
CREATE INDEX "community_feeds_org_idx" ON "community_feeds" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "community_feeds_type_idx" ON "community_feeds" USING btree ("feed_type");--> statement-breakpoint
CREATE INDEX "community_feeds_sector_idx" ON "community_feeds" USING btree ("industry_sector");--> statement-breakpoint
CREATE INDEX "community_campaigns_status_idx" ON "community_threat_campaigns" USING btree ("status");--> statement-breakpoint
CREATE INDEX "community_campaigns_actor_idx" ON "community_threat_campaigns" USING btree ("threat_actor_name");--> statement-breakpoint
CREATE INDEX "community_campaigns_first_seen_idx" ON "community_threat_campaigns" USING btree ("first_seen_at");--> statement-breakpoint
CREATE INDEX "idx_compliance_helpers_org" ON "compliance_control_helpers" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_compliance_helpers_type" ON "compliance_control_helpers" USING btree ("helper_type");--> statement-breakpoint
CREATE INDEX "idx_connector_runs_archive_org" ON "connector_job_runs_archive" USING btree ("org_id","archived_at");--> statement-breakpoint
CREATE INDEX "idx_connector_runs_archive_connector" ON "connector_job_runs_archive" USING btree ("connector_id","archived_at");--> statement-breakpoint
CREATE INDEX "idx_cbf_audit_org" ON "cross_border_flow_audit" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_cbf_audit_created" ON "cross_border_flow_audit" USING btree ("created_at");--> statement-breakpoint
CREATE INDEX "idx_cbf_rules_org" ON "cross_border_flow_rules" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_cbf_rules_regions" ON "cross_border_flow_rules" USING btree ("source_region","destination_region");--> statement-breakpoint
CREATE INDEX "idx_cve_entries_cve_id" ON "cve_entries" USING btree ("cve_id");--> statement-breakpoint
CREATE INDEX "idx_cve_entries_severity" ON "cve_entries" USING btree ("severity");--> statement-breakpoint
CREATE INDEX "idx_cve_entries_cvss" ON "cve_entries" USING btree ("cvss_score");--> statement-breakpoint
CREATE INDEX "idx_cve_entries_published" ON "cve_entries" USING btree ("published_date");--> statement-breakpoint
CREATE INDEX "idx_dl_queries_org" ON "data_lake_queries" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_dl_queries_status" ON "data_lake_queries" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_dl_retention_org" ON "data_lake_retention_policies" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_dl_retention_org_type" ON "data_lake_retention_policies" USING btree ("org_id","data_type");--> statement-breakpoint
CREATE INDEX "idx_dl_retention_framework" ON "data_lake_retention_policies" USING btree ("compliance_framework");--> statement-breakpoint
CREATE INDEX "idx_deception_hits_org" ON "deception_hits" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_deception_hits_token" ON "deception_hits" USING btree ("canary_token_id");--> statement-breakpoint
CREATE INDEX "idx_deception_hits_honeypot" ON "deception_hits" USING btree ("honeypot_asset_id");--> statement-breakpoint
CREATE INDEX "idx_deception_hits_severity" ON "deception_hits" USING btree ("org_id","severity");--> statement-breakpoint
CREATE INDEX "idx_deception_hits_time" ON "deception_hits" USING btree ("org_id","hit_at");--> statement-breakpoint
CREATE INDEX "idx_deception_hits_source_ip" ON "deception_hits" USING btree ("source_ip");--> statement-breakpoint
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
CREATE INDEX "idx_dr_drill_results_runbook" ON "dr_drill_results" USING btree ("runbook_id");--> statement-breakpoint
CREATE INDEX "idx_dr_drill_results_org" ON "dr_drill_results" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_dr_drill_results_status" ON "dr_drill_results" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_dr_drill_results_created" ON "dr_drill_results" USING btree ("created_at");--> statement-breakpoint
CREATE INDEX "idx_ediscovery_org" ON "ediscovery_exports" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ediscovery_status" ON "ediscovery_exports" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_ediscovery_hold" ON "ediscovery_exports" USING btree ("legal_hold_id");--> statement-breakpoint
CREATE INDEX "idx_telemetry_archive_org_archived" ON "endpoint_telemetry_archive" USING btree ("org_id","archived_at");--> statement-breakpoint
CREATE INDEX "idx_telemetry_archive_asset" ON "endpoint_telemetry_archive" USING btree ("asset_id","archived_at");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_engine_configs_org_engine" ON "engine_configs" USING btree ("org_id","engine_name");--> statement-breakpoint
CREATE INDEX "idx_engine_configs_org" ON "engine_configs" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_engine_dry_runs_org" ON "engine_dry_runs" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_engine_dry_runs_engine" ON "engine_dry_runs" USING btree ("org_id","engine_name");--> statement-breakpoint
CREATE INDEX "idx_engine_explain_org" ON "engine_explainability_logs" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_engine_explain_engine" ON "engine_explainability_logs" USING btree ("org_id","engine_name");--> statement-breakpoint
CREATE INDEX "idx_evidence_attach_org" ON "evidence_attachments" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_evidence_attach_mapping" ON "evidence_attachments" USING btree ("control_mapping_id");--> statement-breakpoint
CREATE INDEX "idx_evidence_attach_locker" ON "evidence_attachments" USING btree ("evidence_locker_id");--> statement-breakpoint
CREATE INDEX "idx_evidence_attach_status" ON "evidence_attachments" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_honeypot_assets_org" ON "honeypot_assets" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_honeypot_assets_type" ON "honeypot_assets" USING btree ("asset_type");--> statement-breakpoint
CREATE INDEX "idx_honeypot_assets_active" ON "honeypot_assets" USING btree ("org_id","is_active");--> statement-breakpoint
CREATE INDEX "idx_th_library_org" ON "hunt_library" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_th_library_public" ON "hunt_library" USING btree ("is_public");--> statement-breakpoint
CREATE INDEX "idx_th_playbooks_org" ON "hunt_playbooks" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_th_results_hunt" ON "hunt_results" USING btree ("hunt_id");--> statement-breakpoint
CREATE INDEX "idx_th_results_org" ON "hunt_results" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_th_schedules_org" ON "hunt_schedules" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_th_schedules_hunt" ON "hunt_schedules" USING btree ("hunt_id");--> statement-breakpoint
CREATE INDEX "idx_iag_org" ON "identity_access_graph" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_iag_source" ON "identity_access_graph" USING btree ("org_id","source_user_id");--> statement-breakpoint
CREATE INDEX "idx_iag_target" ON "identity_access_graph" USING btree ("org_id","target_system");--> statement-breakpoint
CREATE INDEX "idx_iag_active" ON "identity_access_graph" USING btree ("org_id","is_active");--> statement-breakpoint
CREATE INDEX "idx_irp_org" ON "identity_risk_profiles" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_irp_user" ON "identity_risk_profiles" USING btree ("org_id","user_id");--> statement-breakpoint
CREATE INDEX "idx_irp_risk" ON "identity_risk_profiles" USING btree ("org_id","risk_level");--> statement-breakpoint
CREATE INDEX "idx_irp_stale" ON "identity_risk_profiles" USING btree ("org_id","is_stale");--> statement-breakpoint
CREATE INDEX "idx_irp_blast" ON "identity_risk_profiles" USING btree ("org_id","blast_radius_score");--> statement-breakpoint
CREATE INDEX "idx_ipe_org" ON "industrial_protocol_events" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ipe_asset" ON "industrial_protocol_events" USING btree ("asset_id");--> statement-breakpoint
CREATE INDEX "idx_ipe_protocol" ON "industrial_protocol_events" USING btree ("org_id","protocol");--> statement-breakpoint
CREATE INDEX "idx_ipe_write" ON "industrial_protocol_events" USING btree ("org_id","is_write");--> statement-breakpoint
CREATE INDEX "idx_ipe_anomalous" ON "industrial_protocol_events" USING btree ("org_id","is_anomalous");--> statement-breakpoint
CREATE INDEX "idx_ipe_time" ON "industrial_protocol_events" USING btree ("org_id","captured_at");--> statement-breakpoint
CREATE INDEX "idx_ingestion_archive_org_archived" ON "ingestion_logs_archive" USING btree ("org_id","archived_at");--> statement-breakpoint
CREATE INDEX "idx_chat_messages_thread" ON "investigation_chat_messages" USING btree ("thread_id");--> statement-breakpoint
CREATE INDEX "idx_chat_messages_incident" ON "investigation_chat_messages" USING btree ("incident_id");--> statement-breakpoint
CREATE INDEX "idx_chat_messages_org" ON "investigation_chat_messages" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_invoices_org" ON "invoices" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_invoices_subscription" ON "invoices" USING btree ("subscription_id");--> statement-breakpoint
CREATE INDEX "idx_invoices_stripe" ON "invoices" USING btree ("stripe_invoice_id");--> statement-breakpoint
CREATE INDEX "idx_log_sources_org" ON "log_sources" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_log_sources_sensor" ON "log_sources" USING btree ("sensor_id");--> statement-breakpoint
CREATE INDEX "idx_log_sources_type" ON "log_sources" USING btree ("org_id","source_type");--> statement-breakpoint
CREATE INDEX "idx_log_sources_status" ON "log_sources" USING btree ("org_id","status");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_log_sources_http_auth_token" ON "log_sources" USING btree ("http_auth_token");--> statement-breakpoint
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
CREATE INDEX "idx_notification_delivery_log_channel" ON "notification_delivery_log" USING btree ("channel_id");--> statement-breakpoint
CREATE INDEX "idx_notification_delivery_log_org_delivered" ON "notification_delivery_log" USING btree ("org_id","delivered_at");--> statement-breakpoint
CREATE INDEX "idx_notification_delivery_log_delivered" ON "notification_delivery_log" USING btree ("delivered_at");--> statement-breakpoint
CREATE INDEX "idx_notification_user_prefs_user" ON "notification_user_preferences" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "idx_notification_user_prefs_org" ON "notification_user_preferences" USING btree ("org_id");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_notification_user_prefs_user_org" ON "notification_user_preferences" USING btree ("user_id","org_id");--> statement-breakpoint
CREATE INDEX "idx_org_ai_budgets_org_id" ON "org_ai_budgets" USING btree ("org_id");--> statement-breakpoint
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
CREATE INDEX "idx_pam_org" ON "pam_sessions" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_pam_requester" ON "pam_sessions" USING btree ("org_id","requester_id");--> statement-breakpoint
CREATE INDEX "idx_pam_status" ON "pam_sessions" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_pam_target" ON "pam_sessions" USING btree ("org_id","target_system");--> statement-breakpoint
CREATE INDEX "idx_pam_expires" ON "pam_sessions" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "idx_password_reset_user" ON "password_reset_tokens" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "idx_password_reset_token" ON "password_reset_tokens" USING btree ("token");--> statement-breakpoint
CREATE INDEX "peer_benchmarks_org_idx" ON "peer_benchmarks" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "peer_benchmarks_industry_idx" ON "peer_benchmarks" USING btree ("industry_segment","company_size");--> statement-breakpoint
CREATE INDEX "idx_plans_active" ON "plans" USING btree ("is_active");--> statement-breakpoint
CREATE INDEX "idx_plans_sort" ON "plans" USING btree ("sort_order");--> statement-breakpoint
CREATE INDEX "posture_score_history_org_idx" ON "posture_score_history" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "posture_score_history_period_idx" ON "posture_score_history" USING btree ("org_id","period_type");--> statement-breakpoint
CREATE INDEX "posture_sub_scores_org_idx" ON "posture_sub_scores" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "posture_sub_scores_domain_idx" ON "posture_sub_scores" USING btree ("org_id","domain");--> statement-breakpoint
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
CREATE INDEX "idx_kill_switch_org" ON "ransomware_kill_switch_events" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_kill_switch_status" ON "ransomware_kill_switch_events" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_kill_switch_created" ON "ransomware_kill_switch_events" USING btree ("org_id","created_at");--> statement-breakpoint
CREATE INDEX "idx_recovery_runbooks_org" ON "recovery_runbooks" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_recovery_runbooks_status" ON "recovery_runbooks" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_recovery_runbooks_incident" ON "recovery_runbooks" USING btree ("incident_id");--> statement-breakpoint
CREATE INDEX "idx_remote_sessions_org" ON "remote_worker_sessions" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_remote_sessions_user" ON "remote_worker_sessions" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "idx_remote_sessions_device" ON "remote_worker_sessions" USING btree ("device_id");--> statement-breakpoint
CREATE INDEX "idx_report_tpl_ver_template" ON "report_template_versions" USING btree ("template_id");--> statement-breakpoint
CREATE INDEX "idx_report_tpl_ver_org" ON "report_template_versions" USING btree ("org_id");--> statement-breakpoint
CREATE UNIQUE INDEX "uq_report_tpl_ver_version" ON "report_template_versions" USING btree ("template_id","version");--> statement-breakpoint
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
CREATE INDEX "idx_sast_findings_org" ON "sast_findings" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_sast_findings_repo" ON "sast_findings" USING btree ("org_id","repository");--> statement-breakpoint
CREATE INDEX "idx_sast_findings_severity" ON "sast_findings" USING btree ("org_id","severity");--> statement-breakpoint
CREATE INDEX "idx_sast_findings_category" ON "sast_findings" USING btree ("org_id","category");--> statement-breakpoint
CREATE INDEX "idx_sast_findings_status" ON "sast_findings" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_sast_findings_pr" ON "sast_findings" USING btree ("org_id","pull_request_id");--> statement-breakpoint
CREATE INDEX "idx_sast_findings_commit" ON "sast_findings" USING btree ("org_id","commit_sha");--> statement-breakpoint
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
CREATE INDEX "security_questionnaires_org_idx" ON "security_questionnaires" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "security_questionnaires_status_idx" ON "security_questionnaires" USING btree ("org_id","status");--> statement-breakpoint
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
CREATE UNIQUE INDEX "idx_sli_daily_unique" ON "sli_metrics_daily" USING btree ("service","metric","day");--> statement-breakpoint
CREATE INDEX "idx_sli_daily_day" ON "sli_metrics_daily" USING btree ("day");--> statement-breakpoint
CREATE INDEX "idx_sli_daily_service_day" ON "sli_metrics_daily" USING btree ("service","day");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_sli_hourly_unique" ON "sli_metrics_hourly" USING btree ("service","metric","hour");--> statement-breakpoint
CREATE INDEX "idx_sli_hourly_hour" ON "sli_metrics_hourly" USING btree ("hour");--> statement-breakpoint
CREATE INDEX "idx_sli_hourly_service_hour" ON "sli_metrics_hourly" USING btree ("service","hour");--> statement-breakpoint
CREATE INDEX "idx_sovereign_keys_org" ON "sovereign_keys" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_sovereign_keys_status" ON "sovereign_keys" USING btree ("status");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_subscriptions_org" ON "subscriptions" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_subscriptions_stripe_customer" ON "subscriptions" USING btree ("stripe_customer_id");--> statement-breakpoint
CREATE INDEX "idx_subscriptions_status" ON "subscriptions" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_sc_findings_org" ON "supply_chain_findings" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_sc_findings_sbom" ON "supply_chain_findings" USING btree ("sbom_id");--> statement-breakpoint
CREATE INDEX "idx_sc_findings_type" ON "supply_chain_findings" USING btree ("org_id","finding_type");--> statement-breakpoint
CREATE INDEX "idx_sc_findings_severity" ON "supply_chain_findings" USING btree ("org_id","severity");--> statement-breakpoint
CREATE INDEX "idx_sc_findings_status" ON "supply_chain_findings" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_sc_findings_cve" ON "supply_chain_findings" USING btree ("cve_id");--> statement-breakpoint
CREATE INDEX "idx_sc_findings_pkg" ON "supply_chain_findings" USING btree ("org_id","package_name");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_table_partitions_unique" ON "table_partitions" USING btree ("table_name","partition_name");--> statement-breakpoint
CREATE INDEX "idx_table_partitions_table_status" ON "table_partitions" USING btree ("table_name","status");--> statement-breakpoint
CREATE INDEX "idx_tabletop_org" ON "tabletop_exercises" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_tabletop_status" ON "tabletop_exercises" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_tabletop_type" ON "tabletop_exercises" USING btree ("org_id","scenario_type");--> statement-breakpoint
CREATE INDEX "idx_tabletop_scheduled" ON "tabletop_exercises" USING btree ("org_id","scheduled_at");--> statement-breakpoint
CREATE INDEX "idx_th_hunts_org" ON "threat_hunts" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_th_hunts_status" ON "threat_hunts" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_threat_reports_org" ON "threat_reports" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_threat_reports_status" ON "threat_reports" USING btree ("org_id","status");--> statement-breakpoint
CREATE INDEX "idx_threat_reports_category" ON "threat_reports" USING btree ("org_id","category");--> statement-breakpoint
CREATE INDEX "idx_threat_reports_reporter" ON "threat_reports" USING btree ("reporter_user_id");--> statement-breakpoint
CREATE INDEX "idx_tiering_jobs_org" ON "tiering_jobs" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_tiering_jobs_status" ON "tiering_jobs" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_tiering_jobs_org_type" ON "tiering_jobs" USING btree ("org_id","data_type");--> statement-breakpoint
CREATE INDEX "idx_ueba_anomalies_org" ON "ueba_anomalies" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ueba_anomalies_entity" ON "ueba_anomalies" USING btree ("org_id","entity_type","entity_id");--> statement-breakpoint
CREATE INDEX "idx_ueba_anomalies_type" ON "ueba_anomalies" USING btree ("org_id","anomaly_type");--> statement-breakpoint
CREATE INDEX "idx_ueba_anomalies_created" ON "ueba_anomalies" USING btree ("org_id","created_at");--> statement-breakpoint
CREATE INDEX "idx_ueba_baselines_org" ON "ueba_baselines" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ueba_baselines_entity" ON "ueba_baselines" USING btree ("org_id","entity_type","entity_id");--> statement-breakpoint
CREATE INDEX "idx_ueba_scores_org" ON "ueba_entity_scores" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_ueba_scores_risk" ON "ueba_entity_scores" USING btree ("org_id","risk_score");--> statement-breakpoint
CREATE INDEX "idx_ueba_scores_entity" ON "ueba_entity_scores" USING btree ("org_id","entity_type","entity_id");--> statement-breakpoint
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
CREATE INDEX "idx_wr_actions_room" ON "war_room_action_items" USING btree ("war_room_id");--> statement-breakpoint
CREATE INDEX "idx_wr_actions_org" ON "war_room_action_items" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_wr_actions_status" ON "war_room_action_items" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_wr_handoffs_room" ON "war_room_handoffs" USING btree ("war_room_id");--> statement-breakpoint
CREATE INDEX "idx_wr_handoffs_org" ON "war_room_handoffs" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_wr_messages_room" ON "war_room_messages" USING btree ("war_room_id");--> statement-breakpoint
CREATE INDEX "idx_wr_messages_org" ON "war_room_messages" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_wr_messages_created" ON "war_room_messages" USING btree ("created_at");--> statement-breakpoint
CREATE INDEX "idx_wr_participants_room" ON "war_room_participants" USING btree ("war_room_id");--> statement-breakpoint
CREATE INDEX "idx_wr_participants_user" ON "war_room_participants" USING btree ("user_id");--> statement-breakpoint
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
ALTER TABLE "alert_dedup_clusters" ADD CONSTRAINT "alert_dedup_clusters_canonical_alert_id_alerts_id_fk" FOREIGN KEY ("canonical_alert_id") REFERENCES "public"."alerts"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ioc_match_rules" ADD CONSTRAINT "ioc_match_rules_feed_id_ioc_feeds_id_fk" FOREIGN KEY ("feed_id") REFERENCES "public"."ioc_feeds"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ioc_matches" ADD CONSTRAINT "ioc_matches_alert_id_alerts_id_fk" FOREIGN KEY ("alert_id") REFERENCES "public"."alerts"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "uq_evidence_chain_incident_seq" ON "evidence_chain_entries" USING btree ("incident_id","sequence_num");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_domain_verifications_domain" ON "org_domain_verifications" USING btree ("domain");