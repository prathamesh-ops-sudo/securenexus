# Claude Code Production-Grade Plugin — Knowledge Reference

## Overview

The **claude-code-production-grade-plugin** (v5.4.0, MIT, author: Quan / nagisanzenin) is a Claude Code plugin that transforms Claude into a multi-agent software engineering pipeline. It routes user requests through 14 specialized agents coordinated by an orchestrator, enforced by 8 shared protocols, governed by 11 principles, executing across a 5-phase pipeline with 3 strategic gates.

Repository: `https://github.com/nagisanzenin/claude-code-production-guide-plugin`
Local clone: `/home/ubuntu/repos/claude-code-production-grade-plugin`

---

## Architecture Summary

### 5-Phase Pipeline: DEFINE → BUILD → HARDEN → SHIP → SUSTAIN

| Phase | Purpose | Agents | Gate |
|-------|---------|--------|------|
| **DEFINE** | Requirements + architecture | product-manager, solution-architect | Gate 1 (Requirements) + Gate 2 (Architecture) |
| **BUILD** | Implementation | software-engineer, frontend-engineer, devops (containers) | — |
| **HARDEN** | Quality + security | qa-engineer, security-engineer, code-reviewer | Gate 3 (Production Readiness) |
| **SHIP** | Infrastructure + operations | devops (IaC/CI/CD), sre, data-scientist | — |
| **SUSTAIN** | Documentation + custom skills | technical-writer, skill-maker | — |

### 3 Strategic Gates

1. **Gate 1 — Requirements Validation**: After product-manager completes BRD. Verify all acceptance criteria, user stories, business rules documented.
2. **Gate 2 — Architecture Approval**: After solution-architect completes design. Verify ADRs, API contracts, data models, tech stack justified.
3. **Gate 3 — Production Readiness**: After HARDEN phase. Verify security findings remediated, tests passing, code review issues resolved.

Gates are **self-healing**: rejection loops back to the relevant agent for rework (max 2 cycles). Rework is logged to `.orchestrator/rework-log.md`. Only stops if user explicitly cancels or rework limit reached.

### Two-Wave Parallel Execution

- **Wave A (BUILD + ANALYSIS)**: software-engineer + frontend-engineer + devops containers run in parallel
- **Wave B (EXECUTION against code)**: qa-engineer + security-engineer + code-reviewer run in parallel
- Within each agent, internal sub-phases also parallelize (e.g., QA spawns 5 parallel test-type agents)

### Worktree Isolation

When parallelism is Maximum, each agent runs in an isolated git worktree — zero file race conditions. After each parallel wave, worktree branches merge back to the working branch before the next phase reads their outputs.

---

## 14 Specialized Agents

### 1. production-grade (Orchestrator)
- **Role**: Router and pipeline controller. Does NOT execute domain work — delegates to specialized agents.
- **Key file**: `skills/production-grade/SKILL.md` (1152 lines)
- **Responsibilities**: Route user intent to correct execution mode, bootstrap workspace (`Claude-Production-Grade-Suite/`), manage task dependency graph, enforce gates, re-anchor at phase transitions, aggregate receipts into final summary, cleanup team after completion.
- **Re-Anchoring Protocol**: At every phase transition, re-reads key workspace artifacts FROM DISK (not memory) to prevent context drift. After 30+ minutes, compressed memory of architecture specs becomes lossy.
- **Pipeline Cleanup**: `TeamDelete(team_name="production-grade")` is MANDATORY after final summary or gate rejection.

### 2. polymath (Research & Thinking Partner)
- **Role**: The ONLY skill designed for genuine dialogue. Every other skill executes a pipeline; polymath thinks WITH the user.
- **Purpose**: Close the gap between what user knows and what they need to know to act effectively.
- **6 Modes**: Onboard (new repo orientation), Research (domain/competitive analysis), Ideate (brainstorming), Advise (trade-off analysis), Translate (explain pipeline artifacts), Synthesize (holistic project view)
- **Readiness Spectrum**: Full Exploration ↔ Quick Consultation ↔ Pass-Through. Never feels like a blocker.
- **Gate Companion**: When user selects "Chat about this" at any gate, polymath explains artifacts in plain language, then re-presents original gate options.
- **Web search is primary superpower**: Research discipline requires multiple sources, recency preference, synthesis over link-dumping.
- **Writes ONLY to**: `Claude-Production-Grade-Suite/polymath/`
- **Downstream consumers**: product-manager reads `handoff/context-package.md`, solution-architect reads `context/domain-research.md`

### 3. product-manager
- **Role**: Interview CEO, write BRD/PRD, verify implementation matches requirements.
- **Process**: CEO Interview (depth scales by engagement mode: Express 2-3 Qs, Meticulous 8-12 Qs) → Write BRD → Hand off to engineering → Autonomous verification
- **BRD canonical path**: `Claude-Production-Grade-Suite/product-manager/BRD/brd.md`
- **Pre-loaded context**: Reads polymath `handoff/context-package.md` if exists — reduces interview to cover ONLY gaps
- **Phase 4 verification**: Spawns verification agent to compare acceptance criteria against actual code

### 4. solution-architect
- **Role**: Designs system architecture as a FUNCTION of inputs (scale, team, budget, compliance), not from templates.
- **Fitness Function**: Scale interview → Architecture Pattern derivation. <1K users = monolith, 1K-100K = modular monolith, 100K+ = microservices, solo dev = simplest possible.
- **6 Phases**: Discovery & Scale Assessment → Architecture Design (ADRs, C4 diagrams) → Tech Stack Selection → API Contract Design (OpenAPI 3.1) → Data Model Design (ERD, migrations) → Project Scaffolding
- **Infrastructure sizing by budget**: <$500/mo = serverless-first, $500-5K = managed K8s, >$5K = dedicated infrastructure
- **Compliance impact tables**: GDPR, SOC2, HIPAA, PCI-DSS each change architecture in specific ways
- **Brownfield awareness**: If codebase-context.md exists and mode is brownfield, read existing architecture first, extend not replace

### 5. software-engineer
- **Role**: Implements backend services, APIs, business logic from architecture contracts.
- **Clean architecture**: handlers → services → repositories
- **Parallel execution**: Phase 2a establishes shared foundations (libs/shared/) sequentially, then Phase 2b spawns parallel agents (1 per service)
- **TDD enforced**: Write test first, watch fail, implement, watch pass, refactor
- **Brownfield rules**: READ existing code first, MATCH existing style, NEVER overwrite, EXTEND don't recreate
- **12 common mistakes documented**: business logic in handlers, DB queries in services, catching/swallowing errors, missing tenant isolation, hardcoding config, no idempotency, custom auth from scratch, etc.

### 6. frontend-engineer
- **Role**: Builds React/Next.js web frontends from BRD and API contracts.
- **Pipeline position**: Runs PARALLEL with software-engineer (both consume OpenAPI specs independently)
- **6 Phases**: Analysis → Design System → Components (primitives first, then parallel layout+feature) → Pages (parallel by route group) → Design & Polish → Testing & A11y
- **Functional Completeness (CRITICAL)**: Dead element rule — any interactive element that renders but does nothing when clicked is a Critical bug, not a TODO. Navigation graph verification, interaction trace for top 5 user flows, cross-agent reconciliation.
- **Boundary safety**: Never use `<Link>`/`navigate()` for API routes, external URLs, OAuth endpoints. These need raw `<a href>` or `window.location`.

### 7. qa-engineer
- **Role**: Writes and runs tests — unit, integration, e2e, performance, contract testing. Does NOT modify source code.
- **7 Phases**: Test Planning → Unit Tests → Integration Tests → Contract Tests → E2E Tests → Performance Tests → Test Infrastructure
- **Parallel execution**: After Phase 1 (test plan), Phases 2-6 run in parallel (each test type independent, writes to own directory)
- **Graceful degradation**: If `frontend/` not found, skip all frontend tests, print `[DEGRADED]`, continue backend tests
- **Output to `tests/` at project root**: unit/, integration/, contract/, e2e/, performance/, fixtures/, coverage/
- **Cross-boundary journey testing**: Auth test must verify complete flow: unauthenticated → redirect → login → redirect back → authenticated content

### 8. security-engineer
- **Role**: SOLE authority on OWASP Top 10, STRIDE, PII, encryption. Application-level security only.
- **6 Phases**: Threat Modeling → Code Audit → Auth Review → Data Security → Supply Chain → Remediation
- **Parallel execution**: After Phase 0 (Recon) + Phase 1 (Threat Model), Phases 2-5 run in parallel
- **Scope boundary**: Application security (STRIDE, OWASP, auth flows, PII) vs DevOps security (WAF, IAM, network, container scanning)
- **Severity SLAs**: Critical (24-48h), High (1 week), Medium (1 sprint), Low (1 quarter), Informational (opportunistic)
- **Remediation chain**: Finding receipt → Remediation receipt → Verification receipt for critical/high findings

### 9. code-reviewer
- **Role**: Reviews code for quality — architecture conformance, anti-patterns, performance. READ-ONLY, never modifies code.
- **Review stance: ADVERSARIAL**: "Assume every function has an edge case the author missed."
- **5 Phases** (1-4 parallel, then 5 sequential): Architecture Conformance → Code Quality Analysis → Performance Review → Test Quality Review → Review Report
- **Adversarial depth scales with engagement mode**: Express = Critical only; Standard = Critical + High; Thorough = all severities; Meticulous = hostile, write specific attack scenarios
- **Boundary safety checks**: 7 specific boundary-safety patterns checked (framework nav misuse, duplicated control flow, self-referencing config, unconditional interceptors, identity consistency, dead interactive elements, navigation completeness)
- **Security scope**: Does NOT perform OWASP/security review — defers to security-engineer

### 10. devops
- **Role**: Full DevOps pipeline: Docker, CI/CD, cloud provisioning, monitoring, security infrastructure.
- **6 Phases**: Infrastructure Assessment → IaC (Terraform) → CI/CD Pipelines → Container Orchestration → Monitoring & Observability → Security
- **Parallel groups**: Phases 2-4 parallel (IaC + CI/CD + Containers), then Phases 5-6 parallel (Monitoring + Security)
- **Multi-cloud support**: AWS/GCP/Azure provider mapping tables for compute, database, cache, queue, storage, secrets, DNS, WAF
- **Distinction from SRE**: DevOps provides monitoring infrastructure; SRE defines SLOs. DevOps provides tools; SRE owns incident process. DevOps writes manifests; SRE tunes resources.
- **Does NOT define SLOs or write runbooks** — those are SRE's domain

### 11. sre (Site Reliability Engineering)
- **Role**: SOLE authority on SLO definitions, error budgets, runbooks, capacity planning.
- **5 Phases**: Readiness Review → SLO Definition → Chaos Engineering → Incident Management → Capacity Planning
- **Parallel execution**: After Phase 1 + 2, Phases 3-5 run in parallel
- **SLO guidance**: Don't set 99.99% for everything (zero error budget). Start 99.5%, tighten based on user impact.
- **Runbook quality**: Include exact commands with real metric names and pod labels. Decision trees, not prose. On-call at 3 AM must be able to follow.
- **Error budget policy with enforcement**: Deployment freeze, reliability sprint, executive review when budget exhausts

### 12. data-scientist
- **Role**: Production AI/ML systems specialist — LLM optimization, prompt engineering, A/B testing, cost modeling.
- **6 Phases**: System Audit → LLM Optimization → Experiment Framework → Data Pipeline → ML Infrastructure → Cost Modeling
- **System classification**: LLM-Powered App → Phases 1,2,3,6; ML-Enhanced → 1,3,5,6; Data-Intensive → 1,3,4,6; Hybrid → All
- **Key rules**: Always measure baseline before optimizing, version-control prompts (prompts ARE code), model costs at 2x/5x/10x scale, only cache LLM responses with temperature ≤ 0.5
- **Escalation triggers**: Monthly AI spend >$10K, quality score <7.0/10, guardrail metric regression, PII in training data

### 13. technical-writer
- **Role**: Produces comprehensive documentation. Every statement traces to an artifact — missing info gets `<!-- TODO -->` placeholder.
- **4 Phases**: Content Audit → API Reference → Developer Guides → Docusaurus Scaffold
- **Parallel execution**: After Phase 1, Phases 2-3 run in parallel
- **Quality bar**: Quickstart must get working system in under 10 minutes. Code examples must be tested. Document what IS, not what SHOULD BE.
- **Brownfield**: Match existing doc style, never overwrite existing README/CONTRIBUTING/API docs

### 14. skill-maker
- **Role**: Creates reusable Claude Code skills and plugins — interview, write SKILL.md, package as plugin, create repo, add to marketplace.
- **5 Phases**: Interview → Write SKILL.md → Package as Plugin → Create Repo & Push → Add to Marketplace
- **SKILL.md rules**: Description = triggering conditions only ("Use when..."), max 500 chars, never summarize workflow. Keep under 500 words. One excellent example beats many mediocre ones.
- **Plugin structure**: `.claude-plugin/plugin.json` + `skills/<name>/SKILL.md` + `README.md`

---

## 8 Shared Protocols

Every agent loads all 8 protocols at startup via `!cat` directives. These constrain ALL agents uniformly.

### 1. UX Protocol (`ux-protocol.md`)
- NEVER ask open-ended questions — use AskUserQuestion with predefined options only
- "Chat about this" always last option (escape hatch)
- Recommended option first with `(Recommended)` suffix
- Continuous execution — never ask "should I continue?" just keep going
- Autonomy scales with engagement mode: Express auto-resolve → Meticulous surface every decision

### 2. Input Validation (`input-validation.md`)
- Every skill MUST validate inputs before starting
- 5-step process: Read config → Probe inputs in parallel → Classify missing (Critical/Degraded/Optional) → Print gap summary → Adapt scope
- Critical = STOP (e.g., API contracts, schemas, tech-stack.md)
- Degraded = WARN continue partial (e.g., ADRs, migration files)
- Optional = skip silently (e.g., AsyncAPI, existing scaffold)

### 3. Tool Efficiency (`tool-efficiency.md`)
- Parallel tool calls — issue ALL independent reads simultaneously
- Use structural tools before full reads: smart_outline (~200-500 tokens) → smart_unfold (~200-1000) → full Read (~500-5000)
- Config-aware paths — always check `.production-grade.yaml` for path overrides

### 4. Visual Identity (`visual-identity.md`)
- Design language: sleek, elegant, high-tech, informative. "Mission control, not decoration."
- Icon vocabulary: ◆ (brand), ⬥ (gate), ● (active), ○ (pending), ✓ (complete), ✗ (failed), ⧖ (in progress), ⚠ (warning)
- Container hierarchy: Tier 1 `╔═╗` (pipeline header, gates — max 3-5 uses), Tier 2 `┌─┐` (wave announcements, agent boards), Tier 3 `━━━` (phase headers, dividers)
- Completion summaries MUST include concrete numbers: `✓ [Skill Name]    {concrete metrics}    ⏱ Xm Ys`
- Streaming as animation: structured info that changes state > spinners

### 5. Freshness Protocol (`freshness-protocol.md`)
- Tier 1 (MUST WebSearch): LLM model IDs, API pricing, CVEs, SDK breaking changes
- Tier 2 (WebSearch when writing config): package versions, framework APIs, Docker tags, cloud services
- Tier 3 (WebSearch if uncertain): browser APIs, crypto algorithms, compliance
- Tier 4 (Trust training data): language fundamentals, protocols, SQL, algorithms

### 6. Receipt Protocol (`receipt-protocol.md`)
- Every agent writes a JSON receipt as LAST action before `TaskUpdate(status="completed")`
- Path: `Claude-Production-Grade-Suite/.orchestrator/receipts/{task_id}-{agent_name}.json`
- Schema: task, agent, phase, status, artifacts, metrics, effort (files_read, files_written, tool_calls), verification
- Orchestrator verifies receipts before gate transitions — missing receipt = task didn't complete
- Cost Dashboard: Effort tracking aggregated from all receipts into final summary

### 7. Boundary Safety (`boundary-safety.md`)
- 6 structural patterns causing silent failures at system boundaries:
  1. Abstractions break at boundaries — use platform primitives for cross-domain calls
  2. Delegate to framework control flow — wire UI to destination not auth endpoints
  3. Self-referencing config = infinite loops — overrides must point to something different
  4. Global interceptors must be conditional — never hardcoded returns
  5. Test full user journeys across boundaries
  6. Identity must be consistent across integrated systems

### 8. Conflict Resolution (`conflict-resolution.md`)
- Authority hierarchy: Each skill owns specific artifact types (e.g., product-manager owns BRD, security-engineer owns security findings)
- Deduplication: Keep highest severity, deduplicate by file:line
- Feedback loops: HARDEN findings create remediation tasks back to BUILD agents, max 2 fix-rescan cycles before user escalation
- Boundary clarifications: security-engineer does OWASP (not code-reviewer), sre defines SLOs (not devops)

---

## 10 Execution Modes

| Mode | Description | Typical Scope |
|------|-------------|---------------|
| **Full Build** | Complete DEFINE→BUILD→HARDEN→SHIP→SUSTAIN | New project from scratch |
| **Feature** | Add feature to existing codebase | Single feature addition |
| **Harden** | Security audit + code review + testing | Quality/security pass |
| **Ship** | Infrastructure + CI/CD + monitoring | Deployment readiness |
| **Test** | Testing only | QA phase |
| **Review** | Code review only | Quality gate |
| **Architect** | Architecture design only | Design phase |
| **Document** | Documentation generation | Docs phase |
| **Explore** | Research + thinking (polymath) | Discovery/planning |
| **Optimize** | Performance + cost optimization | Optimization pass |
| **Custom** | User-defined subset | Any combination |

---

## 11 Governing Principles

1. **Superalignment**: AI acts ON BEHALF of user with same goals
2. **Production Grade**: No stubs, no TODOs, all code compiles and runs
3. **On Behalf of User**: Make decisions user would make with full context
4. **Interactive When Absolutely Needed**: Minimize interruptions, maximize autonomy
5. **Efficiency Through Parallelism**: Maximum parallel execution — every independent unit gets its own agent
6. **Dynamic and Adaptive**: Architecture derived from constraints, not templates
7. **Self-Extension**: System creates custom skills for project-specific patterns
8. **Extreme Ownership**: Every agent owns its output quality end-to-end
9. **First-Principles Thinking**: Derive solutions from fundamentals, not cargo-culting
10. **Mathematical Rigor**: Concrete numbers, statistical significance, measurable outcomes
11. **Autonomous Resilience**: Self-debug, validation loops, report after 3 failures

---

## 4 Engagement Modes

| Mode | User Interaction | Question Depth |
|------|-----------------|----------------|
| **Express** | Zero questions, auto-resolve everything | 3 gates only |
| **Standard** | 1-2 critical decisions per skill | Moderate interview |
| **Thorough** | All major decisions surfaced | Deep interviews |
| **Meticulous** | Every decision point surfaced | Full walkthrough |

---

## Configuration

### .production-grade.yaml
Project-level config at root. Defines:
- **project**: name, language, framework, cloud, architecture
- **paths**: Override all default paths (api_contracts, services, frontend, terraform, etc.)
- **preferences**: test_framework, orm, ci_provider, package_manager, linter, formatter, frontend_framework, state_management, styling
- **features**: Toggle frontend, ai_ml, multi_tenancy, documentation_site, payment, real_time, graphql, grpc, event_driven
- **phases**: Enable/disable individual pipeline phases

Template at: `skills/_shared/templates/production-grade.yaml.tmpl`

### Session Guard Hook
`hooks/session-guard.sh` — Fires on SessionStart when `Claude-Production-Grade-Suite/` directory exists in project. Asks user: use production-grade pipeline, work directly, or chat about approach.

---

## Workspace Architecture

```
Claude-Production-Grade-Suite/
├── .protocols/              # Shared protocols (written at bootstrap)
├── .orchestrator/           # Pipeline state, receipts, settings, rework-log
│   ├── receipts/            # JSON receipts from every completed task
│   ├── settings.md          # Engagement mode, parallelism level
│   ├── codebase-context.md  # Brownfield context (if existing project)
│   └── rework-log.md        # Gate rejection rework tracking
├── product-manager/         # BRD, research
├── solution-architect/      # Architecture working notes
├── software-engineer/       # Backend logs/artifacts
├── frontend-engineer/       # Frontend logs/artifacts
├── qa-engineer/             # Test plan, coverage report, findings
├── security-engineer/       # Threat model, code audit, auth review, supply chain, remediation
├── code-reviewer/           # Review report, findings by severity, metrics, auto-fixes
├── devops/                  # Deployment plan, infrastructure assessment
├── sre/                     # Production readiness, SLOs, chaos, capacity, incidents, DR
├── data-scientist/          # AI/ML analysis, LLM optimization, experiments, pipelines
├── technical-writer/        # Writing notes, content inventory
├── polymath/                # Context, research, decisions, handoff
└── skill-maker/             # Custom skills
```

**Deliverables** go to project root (services/, frontend/, infrastructure/, docs/, tests/, api/, schemas/).
**Workspace artifacts** go to `Claude-Production-Grade-Suite/<skill-name>/`.

---

## Key Differentiators

1. **Receipt enforcement**: Every agent produces a JSON proof-of-completion. No receipt = task didn't complete. Gates verify receipts before allowing transitions.
2. **Re-anchoring**: Orchestrator re-reads specs FROM DISK at every phase transition to prevent context drift over long pipeline runs.
3. **Self-healing gates**: Gate rejection doesn't stop the pipeline — it loops back for rework (max 2 cycles).
4. **Worktree isolation**: Parallel agents can't cause file race conditions.
5. **Boundary safety protocol**: 6 structural patterns that prevent silent failures at system boundaries (auth flows, payment callbacks, multi-system integrations).
6. **Engagement mode scaling**: Same pipeline, different autonomy levels — from fully autonomous (Express) to every-decision-reviewed (Meticulous).
7. **Brownfield awareness**: Every agent checks for existing code/infra first, matches existing patterns, extends rather than replaces.
8. **Cost dashboard**: Effort tracking (files_read, files_written, tool_calls) in every receipt, aggregated into final summary with token/cost estimates.
9. **Conflict resolution hierarchy**: Clear ownership boundaries — security-engineer does OWASP (not code-reviewer), sre defines SLOs (not devops).
10. **Session guard**: Hook detects production-grade projects and offers user choice on how to work.
