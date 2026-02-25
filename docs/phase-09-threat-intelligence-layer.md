# Phase 9: Threat Intelligence Layer Detailed Report

## Goal
Add reliable IOC feed ingestion, enrichment, scoring, and correlation to incidents/alerts.

## What Must Be Fixed
- IOC ingestion exists partially but lacks complete lifecycle and correlation quality controls.

## Required Work
- Build feed manager for STIX/TAXII/CSV/JSON.
- Normalize IOC schema and dedupe indicators.
- Score IOC confidence using recency and source reliability.
- Add suppression and allowlist controls.

## Data and API Scope
- Tables: `intel_feeds`, `intel_indicators`, `indicator_matches`, `indicator_lifecycle`.
- APIs: feed CRUD/sync, indicator list/detail, suppression, match query.

## UI Scope
- Threat intel console with feed health, IOC explorer, match timeline.

## Testing
- Parser tests with fixtures.
- Match precision/recall tests.

## Definition of Done
- IOC matches are visible and actionable with low false-positive noise.
