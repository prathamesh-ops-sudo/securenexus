# Phase 9: Threat Intelligence Layer Detailed Implementation Report

## 1. Executive Summary
Phase 9 introduces intelligence-driven context by ingesting IOC feeds, normalizing indicators, scoring credibility, and correlating relevant threat signals directly into analyst workflows.

## 2. Objectives
- Build resilient feed ingestion for STIX/TAXII and flat-file sources.
- Normalize IOC data into canonical schema.
- Correlate indicators to alerts/incidents with explainable scoring.
- Provide IOC lifecycle management and suppression controls.

## 3. Current Baseline
- Partial IOC ingestion exists in `server/ioc-ingestion.ts`.
- Correlation and lifecycle control are incomplete.

## 4. Data Model
- `intel_feeds`
- `id`, `orgId`, `name`, `type`, `config`, `authRef`, `isActive`, `lastSyncAt`, `lastStatus`, `lastError`.
- `intel_indicators`
- `id`, `orgId`, `type`, `value`, `firstSeen`, `lastSeen`, `confidence`, `severity`, `reputation`, `threatActor`, `campaign`, `tags`, `sourceFeedId`, `rawJson`.
- `indicator_matches`
- `id`, `orgId`, `indicatorId`, `targetType`, `targetId`, `matchField`, `matchScore`, `matchedAt`, `explanation`.
- `indicator_lifecycle`
- `indicatorId`, `status`, `changedBy`, `changedAt`, `reason`.

## 5. Ingestion Pipeline
- Fetch -> parse -> normalize -> deduplicate -> score -> persist.
- Per-feed checkpointing and retry policy.
- Idempotent ingestion by source hash and indicator key.

## 6. Correlation Logic
- Match types: exact, normalized, fuzzy.
- Weighted fields by IOC type:
- IP and domain exact match high weight.
- URL path/token partial match medium weight.
- Hash exact match critical weight.
- Confidence formula includes source reliability and recency.

## 7. API Endpoints
- `POST /api/intel/feeds`
- `PATCH /api/intel/feeds/:id`
- `POST /api/intel/feeds/:id/sync`
- `GET /api/intel/indicators`
- `GET /api/intel/indicators/:id`
- `POST /api/intel/indicators/:id/suppress`
- `GET /api/intel/matches`

## 8. UI/UX
- Threat Intel console with:
- feed health panel.
- indicator explorer.
- match timeline.
- suppression and allowlist controls.

## 9. Security and Reliability
- Feed credentials stored as secrets.
- Rate limit ingestion and sync endpoints.
- Alerting on feed failures and ingestion drift.

## 10. Testing
- Parser tests with STIX/TAXII fixtures.
- Matching engine tests with precision/recall thresholds.
- Integration tests for full feed sync path.

## 11. Definition of Done
- Feeds sync reliably.
- IOC normalization and scoring implemented.
- Matches visible in alerts/incidents.
- Suppression flow reduces false positives without data loss.
