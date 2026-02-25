# Phase 9: Threat Intelligence Layer Detailed Implementation Report

## Objective
Ingest, normalize, score, and correlate threat intelligence indicators to improve triage and containment speed.

## Current Baseline
- Partial IOC ingestion support exists.

## Critical Gaps
- Feed lifecycle and health management incomplete.
- IOC confidence and suppression workflow missing.
- Correlation scoring is not consistently explainable.

## Required Fixes
- Add STIX/TAXII/CSV feed management.
- Normalize IOC storage and dedup.
- Add confidence scoring using source reliability and recency.
- Add suppression and allowlist controls.

## Data Model
- `intel_feeds`
- `intel_indicators`
- `indicator_matches`
- `indicator_lifecycle`

## API Plan
- `POST /api/intel/feeds`
- `PATCH /api/intel/feeds/:id`
- `POST /api/intel/feeds/:id/sync`
- `GET /api/intel/indicators`
- `POST /api/intel/indicators/:id/suppress`
- `GET /api/intel/matches`

## UI Plan
- Feed health dashboard.
- IOC explorer.
- Match timeline and suppression actions.

## Testing
- Parser tests with fixture feeds.
- Correlation precision/recall tests.
- Feed retry and idempotency tests.

## Definition of Done
- Intel feeds sync reliably and produce actionable matches.
