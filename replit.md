# SecureNexus - AI Security Intelligence Platform

## Overview
SecureNexus is an AI-powered Security Orchestration & Intelligence Platform built as a full SaaS product. It unifies alerts from multiple cybersecurity tools (EDR, SIEM, IDS/IPS, cloud security), correlates them using AI, and produces attacker-centric incident narratives.

## Tech Stack
- **Frontend**: React + TypeScript, Vite, TailwindCSS, shadcn/ui, wouter (routing), TanStack Query
- **Backend**: Express.js, TypeScript
- **Database**: PostgreSQL (Drizzle ORM)
- **Auth**: Replit Auth (OpenID Connect)
- **AI**: AWS Bedrock (Claude 3.5 Sonnet for cybersecurity analysis) - planned
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
    dashboard.tsx            - Security dashboard
    alerts.tsx               - Alert list/table
    incidents.tsx            - Incident list
    incident-detail.tsx      - Individual incident view
    audit-log.tsx            - Activity log
    settings.tsx             - User settings
  hooks/
    use-auth.ts              - Auth state hook
  lib/
    queryClient.ts           - TanStack Query setup
    auth-utils.ts            - Auth utility functions

server/
  index.ts                   - Express server entry
  routes.ts                  - API routes
  storage.ts                 - Database storage layer
  db.ts                      - Database connection
  seed.ts                    - Seed data
  replit_integrations/auth/  - Replit Auth integration

shared/
  schema.ts                  - Drizzle schemas + types
  models/auth.ts             - Auth-specific schemas
```

## Development Phases (0-16)
- **Phase 0** (Current): Foundation - Auth, DB, UI shell, dashboard, basic CRUD
- Phase 1: Data Models & Alert Schema refinements
- Phase 2: Alert Ingestion System
- Phase 3: Normalization Engine
- Phase 4: Enhanced SOC Dashboard
- Phase 5: AI Correlation Engine (AWS Bedrock)
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

## Key Commands
- `npm run dev` - Start development server
- `npm run db:push` - Push schema changes to database

## Environment Variables
- DATABASE_URL - PostgreSQL connection
- SESSION_SECRET - Session encryption
- AWS_ACCESS_KEY_ID - AWS credentials
- AWS_SECRET_ACCESS_KEY - AWS credentials
- GITHUB_API_KEY - GitHub API access

## User Preferences
- Default to dark mode
- Cybersecurity-focused design language
- Professional, enterprise-grade UI
