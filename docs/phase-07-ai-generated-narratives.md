# SecureNexus Phase 07: AI-Generated Narratives - Ultimate Execution Reference (Exhaustive)

This document is a comprehensive, operations-grade reference for Phase 07. It defines how AI-generated narratives must be designed, governed, validated, approved, and sustained in production. It is written as a persistent execution backlog for engineering, SOC operations, AI governance, and compliance stakeholders.

For every item below, the structure is:
- Current problem (what exists today / what is missing)
- Why it matters (risk, trust, cost, analyst impact, compliance impact)
- What to do (exact implementation and governance actions)

Scope assumptions for this Phase 07 document:
- Phase 06 lifecycle controls are available and stable.
- Incident objects, evidence, status history, and ownership are authoritative inputs.
- AI model invocations are available through Bedrock and/or equivalent managed interfaces.
- Multi-tenant context and audit logging must be preserved in all narrative workflows.

---

## 0) Phase 07 Charter and Boundaries

### 0.1 Define exact mission of Phase 07
- Current problem: AI narrative features are often treated as "single-click summary text" rather than controlled incident intelligence artifacts.
- Why it matters: Ungoverned narrative generation causes hallucinations, inconsistent analyst trust, and poor audit defensibility.
- What to do:
  - Define Phase 07 as the governed narrative-intelligence phase.
  - Set objective: convert incident data into structured, reviewable, versioned narrative outputs.
  - Tie narrative generation to lifecycle context and evidence provenance.

### 0.2 Clarify in-scope outcomes
- Current problem: Teams blur boundaries between narrative generation, automation, and model retraining.
- Why it matters: Scope drift delays delivery and weakens quality controls.
- What to do:
  - Keep Phase 07 scope to narrative generation, approval, provenance, confidence signaling, and consumption UX.
  - Treat model retraining loops as Phase 12 dependencies.
  - Treat autonomous action execution as Phase 13 dependency.

### 0.3 Define phase completion criteria
- Current problem: Completion is frequently declared when generation endpoint exists, not when governance is complete.
- Why it matters: Feature availability without controls creates operational risk.
- What to do:
  - Require versioned narrative storage.
  - Require review and approval lifecycle.
  - Require model/prompt/input provenance persistence.
  - Require confidence semantics and uncertainty labeling.
  - Require full audit and rollback capability.

---

## 1) Terminology and Controlled Vocabulary

### 1.1 Define primary terms
- Current problem: Teams use terms such as "summary," "narrative," "analysis," and "report" interchangeably.
- Why it matters: Semantic ambiguity causes API misuse and review confusion.
- What to do:
  - Define "Narrative" as structured AI-generated incident interpretation artifact.
  - Define "Executive Summary" as short leadership-oriented output.
  - Define "Technical Narrative" as analyst-focused detailed chronology and evidence interpretation.
  - Define "Version" as immutable generated artifact tied to specific inputs and model settings.

### 1.2 Define governance terms
- Current problem: Approval and publication states are inconsistently interpreted.
- Why it matters: Unauthorized or unverified text can be treated as final truth.
- What to do:
  - Define states: `draft`, `pending_review`, `approved`, `rejected`, `superseded`.
  - Define "canonical narrative" as currently approved version used in primary views/exports.
  - Define "provenance" as model, prompt template, parameters, input hash, and generation timestamp.

### 1.3 Define reliability terms
- Current problem: Confidence, certainty, and accuracy labels are mixed in UI and discussions.
- Why it matters: Analysts may over-trust uncertain outputs.
- What to do:
  - Define confidence score as model-derived certainty indicator, not factual guarantee.
  - Define uncertainty annotation as explicit statement of evidence gaps.
  - Define hallucination risk as unsupported claim not grounded in available incident data.

---

## 2) Upstream/Downstream Dependencies

### 2.1 Upstream dependencies (required before Phase 07)
- Current problem: Narrative generation is attempted without stable incident lifecycle and evidence quality.
- Why it matters: AI outputs degrade when input records are incomplete.
- What to do:
  - Require Phase 06 completeness for lifecycle integrity and evidence metadata.
  - Require incident status history and linked evidence availability.
  - Require tenant-safe access controls on all narrative inputs.

### 2.2 Downstream dependencies (what Phase 07 must provide)
- Current problem: Later phases consume narratives without explicit data contracts.
- Why it matters: Reporting, automation, and feedback loops break when narrative contracts are unstable.
- What to do:
  - Define narrative output schema contract for Phase 10 reporting.
  - Provide version/approval metadata required by Phase 12 feedback loop.
  - Provide confidence and uncertainty metadata used by Phase 13 automation safeguards.

### 2.3 Contract validation approach
- Current problem: Dependency contracts are documented loosely and not machine-validated.
- Why it matters: Silent drift occurs as features evolve.
- What to do:
  - Add schema validation tests for narrative payloads.
  - Add compatibility tests for downstream consumers.
  - Fail CI on contract-breaking changes.

---

## 3) Narrative Product Architecture

### 3.1 Define narrative output layers
- Current problem: A single narrative format is used for all consumers.
- Why it matters: Different roles need different depth and framing.
- What to do:
  - Implement at minimum two output forms: executive and technical.
  - Add optional chronology-first and recommendation-first modes.
  - Make output mode explicit in generation request and stored metadata.

### 3.2 Define required narrative sections
- Current problem: Generated narratives vary in structure and may omit critical content.
- Why it matters: Inconsistent structure increases analyst verification time.
- What to do:
  - Require sections: summary, timeline, scope/impact, evidence-backed findings, ATT&CK mapping, kill chain interpretation, recommended actions, open questions.
  - Enforce schema-level section presence before saving.
  - Mark sections with confidence where uncertainty exists.

### 3.3 Separate facts from inference
- Current problem: Model text can blend factual evidence and inferred conclusions without distinction.
- Why it matters: Decision errors occur when inferred claims are interpreted as verified facts.
- What to do:
  - Introduce explicit labeling: "Observed", "Inferred", "Uncertain".
  - Require citation linkage from narrative claims to incident evidence IDs.
  - Block approval if critical claims lack evidence references.

---

## 4) Generation Workflow and Process Controls

### 4.1 Define generation triggers
- Current problem: Generation is invoked ad-hoc with no lifecycle context checks.
- Why it matters: Premature generation creates low-quality outputs and wasted compute cost.
- What to do:
  - Define trigger points: manual generate, regenerate after major incident updates, scheduled refresh for active critical incidents.
  - Require minimum input readiness (incident must have baseline evidence and classification).
  - Reject generation if incident context is insufficient.

### 4.2 Define generation inputs
- Current problem: Input set varies across calls and can include inconsistent fields.
- Why it matters: Output quality and repeatability become unpredictable.
- What to do:
  - Standardize input bundle: incident summary fields, state history, linked alerts, evidence references, affected assets, existing analyst notes, threat context.
  - Hash input bundle for provenance and reproducibility.
  - Persist input version for every generated narrative.

### 4.3 Define generation execution path
- Current problem: Generation can be synchronous in user request paths, causing latency and timeout risk.
- Why it matters: Poor UX and unreliable job completion under load.
- What to do:
  - Use async job pipeline for generation.
  - Persist job status (`queued`, `running`, `completed`, `failed`, `expired`).
  - Add retry policy with capped attempts and failure classification.

### 4.4 Define generation outputs
- Current problem: Output payloads can be saved even when partially malformed.
- Why it matters: Malformed narratives propagate to UI and reports.
- What to do:
  - Validate generated output against strict schema.
  - Reject or quarantine invalid outputs.
  - Save validated outputs as immutable versioned artifacts.

---

## 5) Prompt Governance and Model Control

### 5.1 Centralize prompt templates
- Current problem: Prompt content can live in scattered inline strings.
- Why it matters: Prompt drift and undocumented behavior changes reduce trust.
- What to do:
  - Create prompt template registry with versioning.
  - Associate templates with output mode and use case.
  - Require change logging for prompt modifications.

### 5.2 Define prompt safety constraints
- Current problem: Prompts can produce overconfident language when evidence is sparse.
- Why it matters: Overconfidence creates operational mistakes.
- What to do:
  - Embed explicit uncertainty instruction in every template.
  - Instruct model to avoid unsupported causal claims.
  - Require evidence-reference style in outputs.

### 5.3 Control model selection and fallback
- Current problem: Model switching may occur without visibility or governance.
- Why it matters: Output behavior can change silently across versions.
- What to do:
  - Persist model identifier and version for every generation.
  - Define approved model list per environment.
  - Define fallback model policy with explicit event logging.

### 5.4 Parameter governance
- Current problem: Generation parameters (temperature, max tokens, etc.) may vary ad-hoc.
- Why it matters: Narrative reproducibility and quality stability degrade.
- What to do:
  - Define parameter profiles per narrative type.
  - Persist parameter profile ID in provenance.
  - Require governance approval for profile changes.

---

## 6) Versioning, Review, and Approval Lifecycle

### 6.1 Make narratives immutable by version
- Current problem: Teams may edit generated text in place, losing historical traceability.
- Why it matters: Audit and comparison are impossible without immutable versions.
- What to do:
  - Store every generation as a new version.
  - Prohibit destructive overwrite of old versions.
  - Mark superseded versions explicitly.

### 6.2 Implement review workflow
- Current problem: Generated output may be consumed directly without human review.
- Why it matters: Hallucinations and misinterpretations can influence incident decisions.
- What to do:
  - Require `pending_review` state before publication.
  - Assign reviewer role ownership.
  - Require reviewer decision (`approve` or `reject`) with rationale.

### 6.3 Define rejection and revision path
- Current problem: Rejected outputs are discarded without learnings.
- Why it matters: Quality improvement loops are weakened.
- What to do:
  - Capture rejection reason categories (factual error, missing context, poor clarity, unsupported inference).
  - Allow targeted regeneration with revision objective.
  - Preserve rejected versions for analysis.

### 6.4 Define canonical narrative selection
- Current problem: Multiple approved narratives may exist with no clear default selection.
- Why it matters: UI and exports may show inconsistent results.
- What to do:
  - Enforce single canonical narrative per incident at any time.
  - Require explicit promote/demote actions with audit entries.
  - Use canonical version for default read paths.

---

## 7) Confidence, Uncertainty, and Explainability

### 7.1 Standardize confidence model
- Current problem: Confidence scores are inconsistent or absent across sections.
- Why it matters: Analysts cannot calibrate trust correctly.
- What to do:
  - Define confidence semantics and scale.
  - Attach confidence at both narrative-level and section-level.
  - Display confidence with contextual explanation.

### 7.2 Explicit uncertainty handling
- Current problem: Missing data is often implied but not explicitly surfaced.
- Why it matters: Decision-makers may assume completeness.
- What to do:
  - Require uncertainty notes for incomplete evidence paths.
  - Add "data gaps" section in narrative schema.
  - Block approval if known critical gaps are not disclosed.

### 7.3 Explainability and evidence linkage
- Current problem: Narrative claims can be difficult to trace back to evidence.
- Why it matters: Review efficiency and trust are reduced.
- What to do:
  - Link major claims to evidence IDs and incident timeline events.
  - Provide reviewer UI to inspect claim-to-evidence mapping.
  - Record unsupported-claim findings as quality defects.

---

## 8) Security, Privacy, and Tenant Controls

### 8.1 Preserve tenant boundaries in generation context
- Current problem: Narrative generation pipelines can accidentally aggregate cross-tenant context if safeguards are weak.
- Why it matters: Cross-tenant leakage is critical severity risk.
- What to do:
  - Enforce org-scoped query constraints in all generation data assembly.
  - Validate tenant IDs at request and storage boundaries.
  - Add security tests for cross-tenant leakage prevention.

### 8.2 Protect sensitive data in narrative outputs
- Current problem: AI output may include sensitive strings copied from source data.
- Why it matters: Narrative text can be shared broadly and exported, increasing exposure risk.
- What to do:
  - Add configurable redaction policies before narrative persistence and export.
  - Redact secrets, credentials, direct identifiers, and policy-defined sensitive fields.
  - Log redaction actions for transparency.

### 8.3 Access control for narrative operations
- Current problem: View, generate, approve, and promote actions may not be separated by privilege.
- Why it matters: Unauthorized publication can occur.
- What to do:
  - Define permission matrix for narrative actions.
  - Require elevated role for approval and canonical promotion.
  - Audit denied access attempts.

---

## 9) API and Data Contracts

### 9.1 Define narrative data model
- Current problem: Narrative metadata may be incomplete for governance needs.
- Why it matters: Missing metadata blocks traceability and quality analytics.
- What to do:
  - Store fields for version, state, summary, full content, structure JSON, confidence, model, prompt template, input hash, creator, reviewer, timestamps.
  - Store generation job linkage.
  - Store rejection reason taxonomy.

### 9.2 Standardize API endpoints and behavior
- Current problem: Endpoint behaviors may diverge by route and state.
- Why it matters: Frontend complexity and integration brittleness increase.
- What to do:
  - Define canonical endpoints for generate/list/get/approve/reject/promote.
  - Enforce consistent response envelope and error codes.
  - Return state-machine-aware validation messages.

### 9.3 Define compatibility and deprecation policy
- Current problem: Narrative schema changes may break consumers.
- Why it matters: Reports and downstream tools fail unpredictably.
- What to do:
  - Version narrative schema.
  - Provide deprecation windows and migration guidance.
  - Validate backward compatibility in CI.

---

## 10) UI/UX Workflow Requirements

### 10.1 Narrative workspace design
- Current problem: Narrative interaction is fragmented across pages.
- Why it matters: Analysts lose context and waste time during review.
- What to do:
  - Provide dedicated narrative panel in incident detail.
  - Show lifecycle state, version list, reviewer status, confidence indicators, and evidence links in one place.
  - Keep timeline and narrative views tightly linked.

### 10.2 Version comparison and diff
- Current problem: Analysts cannot quickly identify changes between versions.
- Why it matters: Review and approval cycle slows down.
- What to do:
  - Add structured diff view by section.
  - Highlight changed claims and confidence changes.
  - Provide reviewer notes per version comparison.

### 10.3 Reviewer action UX
- Current problem: Approval actions can occur without contextual checks.
- Why it matters: Low-quality narratives can be published.
- What to do:
  - Require review checklist completion before approve action.
  - Require reason on rejection.
  - Show unresolved data gap warnings prior to decision.

---

## 11) Operational Metrics and Quality Monitoring

### 11.1 Define quality KPIs
- Current problem: Narrative quality is discussed qualitatively rather than measured.
- Why it matters: Quality drift is hard to detect.
- What to do:
  - Track approval rate, rejection rate, average revision count, unsupported claim count, turnaround time from generation to approval.
  - Segment metrics by model, prompt template, incident category, and severity.

### 11.2 Define reliability KPIs
- Current problem: Generation failures and latency are not consistently operationalized.
- Why it matters: Service degradation impacts analyst workflow.
- What to do:
  - Track job queue latency, generation runtime, timeout rate, retry rate, schema-validation failure rate.
  - Set alert thresholds per environment.

### 11.3 Define governance KPIs
- Current problem: Governance adherence is not quantified.
- Why it matters: Policy violations can remain hidden.
- What to do:
  - Track percent of narratives with complete provenance.
  - Track percent approved without reviewer notes (should be controlled).
  - Track policy violation attempts and denied operations.

---

## 12) Risk Register and Mitigation Actions

### 12.1 Hallucination and unsupported inference risk
- Current problem: Model can generate plausible but unsupported statements.
- Why it matters: Operational decisions may be based on false conclusions.
- What to do:
  - Enforce evidence-link requirement for critical claims.
  - Require reviewer verification before canonical publication.
  - Track hallucination incidents and feed into prompt/model governance.

### 12.2 Data leakage risk in generated text
- Current problem: Sensitive fields can appear in narrative output.
- Why it matters: Exported narratives become leakage vectors.
- What to do:
  - Redact sensitive data before save/export.
  - Add leakage detection checks in approval workflow.
  - Restrict narrative export permissions by role.

### 12.3 Cost amplification risk
- Current problem: Frequent regeneration without controls increases model usage cost.
- Why it matters: Unbounded cost growth harms platform economics.
- What to do:
  - Apply generation rate limits and cooldown controls.
  - Add budget monitoring per tenant and per environment.
  - Cache validated narrative versions for unchanged input sets.

### 12.4 Operational dependency outage risk
- Current problem: Upstream AI service outages can block narrative updates.
- Why it matters: Analyst workflow interruptions reduce trust.
- What to do:
  - Use graceful degradation with clear UI status.
  - Queue retries with capped backoff.
  - Provide manual narrative fallback path.

---

## 13) Edge Cases and Exception Handling

### 13.1 Narrative generated from stale incident state
- Current problem: Incident mutates after generation job starts.
- Why it matters: Saved narrative may not match current reality.
- What to do:
  - Include input hash and incident version check at save time.
  - Mark stale-output versions and prevent canonical promotion until regenerated.

### 13.2 Reviewer approves wrong version
- Current problem: Multiple versions in rapid succession can cause reviewer confusion.
- Why it matters: Incorrect narrative can become canonical.
- What to do:
  - Require explicit version confirmation on approval action.
  - Display generated timestamp and input summary before confirmation.
  - Record reviewer action context in audit log.

### 13.3 Incident reopened after narrative approval
- Current problem: Canonical narrative remains approved even when incident scope changes.
- Why it matters: Consumers read outdated conclusions.
- What to do:
  - Auto-mark canonical narrative as `superseded_pending_refresh` on reopen.
  - Trigger regeneration recommendation.
  - Gate exports to indicate stale narrative status.

### 13.4 Missing or malformed model output
- Current problem: Model can return incomplete structures under edge prompts.
- Why it matters: UI/runtime failures and broken exports.
- What to do:
  - Enforce strict schema validation before persistence.
  - Store failure diagnostics for tuning.
  - Return actionable error to user with retry guidance.

### 13.5 Disputed reviewer decisions
- Current problem: Reviewer and incident owner may disagree on approval outcome.
- Why it matters: Governance disputes delay operational progress.
- What to do:
  - Add escalation path to incident lead or SOC manager.
  - Preserve both reviewer rationale and owner feedback.
  - Require final arbitration record for contested approvals.

---

## 14) Testing and Validation Strategy

### 14.1 Unit tests
- Current problem: Narrative state machine and validation logic may lack complete test coverage.
- Why it matters: Regression risk in approval and promotion behavior is high.
- What to do:
  - Test state transitions and invalid transition rejection.
  - Test schema validation and error contracts.
  - Test confidence/uncertainty labeling logic.

### 14.2 Integration tests
- Current problem: Async generation workflows are hard to validate without integrated tests.
- Why it matters: Job status drift and race conditions can persist unnoticed.
- What to do:
  - Test end-to-end job pipeline from generate request to persisted version.
  - Test reviewer actions and canonical promotion behavior.
  - Test stale input detection path.

### 14.3 Security and isolation tests
- Current problem: Cross-tenant and sensitive-data leakage risks are not always covered.
- Why it matters: Security regression risk is severe.
- What to do:
  - Add tenant-isolation tests for generation input and output access.
  - Add redaction policy tests.
  - Add permission checks for approve/promote/export actions.

### 14.4 Non-functional tests
- Current problem: Load and failure behavior may be under-validated.
- Why it matters: Production reliability and cost predictability degrade under load.
- What to do:
  - Run load tests on generation queue and retrieval endpoints.
  - Simulate upstream model timeouts and retries.
  - Measure p95 generation-to-availability latency.

---

## 15) Implementation Roadmap for Phase 07

### 15.1 First 30 days (foundation)
- Current problem: Core narrative controls may be fragmented.
- Why it matters: Without foundation, advanced governance cannot be layered safely.
- What to do:
  - Implement narrative version model and schema.
  - Implement async generation jobs.
  - Implement provenance capture (model/template/input hash).
  - Implement baseline reviewer workflow.

### 15.2 First 60 days (governance hardening)
- Current problem: Approval and quality controls need deeper guardrails.
- Why it matters: Weak governance leads to trust erosion.
- What to do:
  - Add rejection taxonomy and revision objectives.
  - Add confidence/uncertainty enforcement.
  - Add canonical promotion constraints and stale detection.
  - Add security/redaction controls.

### 15.3 First 90 days (operationalization)
- Current problem: Metrics and sustainment loops are often added late.
- Why it matters: Long-term quality cannot be maintained without measurement.
- What to do:
  - Implement KPI dashboards and alerts.
  - Integrate governance review cadence.
  - Complete downstream contract validation with reporting and feedback systems.

---

## 16) Never-Regress Controls for Phase 07

### 16.1 Critical non-negotiable controls
- Current problem: AI feature acceleration can bypass quality safeguards.
- Why it matters: Unsafe shortcuts create high operational and reputational risk.
- What to do:
  - Never publish canonical narrative without approved reviewer action.
  - Never store narrative without provenance metadata.
  - Never allow cross-tenant context in generation.
  - Never treat confidence as factual certainty.
  - Never export stale canonical narrative without explicit stale marker.

### 16.2 Regression detection and response
- Current problem: Control regressions are often detected by users first.
- Why it matters: Detection delay increases impact.
- What to do:
  - Add automated governance checks in CI.
  - Add runtime alerts for policy bypass attempts.
  - Define rollback path for narrative governance regressions.

---

## Appendix A: Required Artifacts Before Phase 07 Signoff

- Narrative schema and versioning spec
- Generation pipeline design and retry policy
- Prompt registry and parameter profile policy
- Reviewer workflow specification
- Canonical promotion rules
- Provenance field catalog
- Confidence and uncertainty policy
- Redaction and access control policy
- Test evidence package (unit/integration/security/non-functional)
- Operational KPI and alert definition set

## Appendix B: Required KPI Set for Ongoing Governance

- Narrative approval rate
- Narrative rejection rate
- Average revisions per approved narrative
- Unsupported claim detection count
- Average generation-to-approval time
- Generation job failure rate
- Schema validation failure rate
- Stale narrative promotion attempts denied
- Redaction action counts
- Percent of narratives with complete provenance
