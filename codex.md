# SecureNexus - AI Security Intelligence Platform

## Overview
SecureNexus is an AI-powered Security Orchestration & Intelligence Platform built as a full SaaS product. It unifies alerts from multiple cybersecurity tools (EDR, SIEM, IDS/IPS, cloud security), correlates them using AI, and produces attacker-centric incident narratives.

## Tech Stack
- **Frontend**: React + TypeScript, Vite, TailwindCSS, shadcn/ui, wouter (routing), TanStack Query
- **Backend**: Express.js, TypeScript
- **Database**: PostgreSQL (Drizzle ORM)
- **Auth**: Replit Auth (OpenID Connect)
- **AI**: AWS Bedrock Converse API (Mistral Large 2 Instruct - specialized cybersecurity engine) + SageMaker endpoint support for custom fine-tuned models
- **GitHub**: Connected via Replit GitHub connector (@octokit/rest)
- **Deployment**: GitHub → AWS App Runner (planned)

## Project Structure
```
client/src/
  App.tsx                    - Main app with auth-gated routing
  components/
    app-sidebar.tsx          - Navigation sidebar
    theme-provider.tsx       - Dark/light mode
    theme-toggle.tsx         - Theme toggle button
    ui/                      - shadcn components
  pages/
    landing.tsx              - Marketing landing page
    dashboard.tsx            - Security dashboard (6 stat cards)
    alerts.tsx               - Alert list/table with category column
    incidents.tsx            - Incident list
    incident-detail.tsx      - Incident view with comments, tags, affected assets
    ingestion.tsx            - Alert ingestion dashboard, API key management, health stats
    connectors.tsx           - Pull-based connector management (CRUD, test, sync)
    audit-log.tsx            - Activity log with user names
    settings.tsx             - User settings
  hooks/
    use-auth.ts              - Auth state hook
  lib/
    queryClient.ts           - TanStack Query setup (joins queryKey with "/" for URL)
    auth-utils.ts            - Auth utility functions

server/
  index.ts                   - Express server entry
  routes.ts                  - API routes (alerts, incidents, comments, tags, audit logs, ingestion, API keys)
  storage.ts                 - Database storage layer
  normalizer.ts              - Alert normalization engine (6 source transformers)
  connector-engine.ts        - Pull-based connector engine (8 sources: CrowdStrike, Splunk, Wiz, Wazuh, Palo Alto, GuardDuty, Defender, SentinelOne)
  ai.ts                      - AWS Bedrock AI integration
  db.ts                      - Database connection
  seed.ts                    - Seed data (3 incidents, 12 alerts, 10 tags, comments)
  github.ts                  - GitHub API client via Replit connector
  replit_integrations/auth/  - Replit Auth integration

scripts/
  push-to-github.ts          - Push codebase to GitHub repo

shared/
  schema.ts                  - Drizzle schemas + types + enums
  models/auth.ts             - Auth-specific schemas
```

## Database Schema (Phase 2)
- **organizations**: id, name, slug, industry, contactEmail, maxUsers
- **alerts**: id, orgId, source, sourceEventId, category, severity, title, description, rawData, normalizedData, sourceIp, destIp, sourcePort, destPort, protocol, userId, hostname, fileHash, url, domain, mitreTactic, mitreTechnique, status, incidentId (FK), correlationScore, correlationReason, analystNotes, assignedTo, detectedAt, ingestedAt, createdAt + uniqueIndex(orgId, source, sourceEventId) for dedup
- **incidents**: id, orgId, title, summary, severity, status, priority, confidence, attackerProfile, mitreTactics[], mitreTechniques[], alertCount, aiNarrative, aiSummary, mitigationSteps, affectedAssets, iocs, assignedTo, leadAnalyst, escalated, escalatedAt, containedAt, resolvedAt, createdAt, updatedAt
- **incident_comments**: id, incidentId (FK), userId, userName, body, isInternal, createdAt
- **tags**: id, name (unique), color, category, createdAt
- **alert_tags**: alertId (FK), tagId (FK)
- **incident_tags**: incidentId (FK), tagId (FK)
- **audit_logs**: id, orgId, userId, userName, action, resourceType, resourceId, details, ipAddress, createdAt
- **api_keys**: id, orgId (FK), name, keyHash (SHA-256), keyPrefix, scopes[], isActive, lastUsedAt, createdBy, createdAt, revokedAt
- **ingestion_logs**: id, orgId (FK), source, status, alertsReceived, alertsCreated, alertsDeduped, alertsFailed, errorMessage, requestId, ipAddress, processingTimeMs, receivedAt
- **connectors**: id, orgId (FK), name, type, authType, config (jsonb), status (active/inactive/error/syncing), pollingIntervalMin, lastSyncAt, lastSyncStatus, lastSyncAlerts, lastSyncError, totalAlertsSynced, createdBy, createdAt, updatedAt
- **users/sessions**: Managed by Replit Auth integration

## Enums
- Alert Severities: critical, high, medium, low, informational
- Alert Statuses: new, triaged, correlated, investigating, resolved, dismissed, false_positive
- Incident Severities: critical, high, medium, low
- Incident Statuses: open, investigating, contained, eradicated, recovered, resolved, closed
- Alert Categories: malware, intrusion, phishing, data_exfiltration, privilege_escalation, lateral_movement, credential_access, reconnaissance, persistence, command_and_control, cloud_misconfiguration, policy_violation, other

## Development Phases (0-16)
- **Phase 0** (Complete): Foundation - Auth, DB, UI shell, dashboard, basic CRUD
- **Phase 1** (Complete): Data Models & Alert Schema refinements, comments, tags, correlation fields
- **Phase 5** (Complete): AI Correlation Engine - AWS Bedrock Claude 3.5 Sonnet v2, alert correlation, incident narratives, AI triage
- **Phase 2** (Complete): Alert Ingestion System - API key auth (SHA-256), normalization engine (6 sources), single/bulk ingestion endpoints, dedup, ingestion dashboard
- **Phase 3** (Complete): Normalization Engine - Built into Phase 2 (CrowdStrike, Splunk, Palo Alto, GuardDuty, Suricata, Defender transformers)
- **Phase 4** (Complete): Enhanced SOC Dashboard - Recharts analytics (severity/source/category donut/bar charts, 7-day trend area chart), MTTR metric, MITRE ATT&CK tactics widget, threat category badges, connector health status, ingestion rate stacked bar, `/api/dashboard/analytics` endpoint
- Phase 6: Incident Management
- Phase 7: AI-Generated Narratives
- Phase 8: MITRE ATT&CK Integration
- Phase 9: Threat Intelligence Layer
- Phase 10: Reporting & Export
- Phase 11: Multi-Tenant & RBAC
- Phase 12: Analyst Feedback Loop
- Phase 13: SOAR-Lite Automation
- Phase 14: Analytics & Metrics
- Phase 15: Advanced Features
- Phase 16: Payment & Billing (Stripe)

## GitHub Repository
- Repo: https://github.com/prathamesh-ops-sudo/ATS-AI-SEC
- Push script: `npx tsx scripts/push-to-github.ts`

## Key Commands
- `npm run dev` - Start development server
- `npm run db:push` - Push schema changes to database
- `npx tsx scripts/push-to-github.ts` - Push to GitHub

## Environment Variables
- DATABASE_URL - PostgreSQL connection
- SESSION_SECRET - Session encryption
- AWS_ACCESS_KEY_ID - AWS credentials
- AWS_SECRET_ACCESS_KEY - AWS credentials
- GITHUB_API_KEY - GitHub API access (legacy, now using connector)

## User Preferences
- Default to dark mode
- Cybersecurity-focused design language
- Professional, enterprise-grade UI
- Human-in-the-loop approach for AI features
