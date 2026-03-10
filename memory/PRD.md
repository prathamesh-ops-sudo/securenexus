# SecureNexus - Product Requirements Document

## Product Overview
SecureNexus is an AI-powered Security Operations Center (SOC) platform designed for enterprise security teams. It provides comprehensive alert management, incident response, AI-driven analysis, compliance management, and automated threat response capabilities.

## Core Requirements
1. Full-stack SaaS application (React frontend + Python/FastAPI backend + MongoDB)
2. Enterprise-grade security (RBAC, work email validation, MFA, audit logging)
3. AI-powered alert triage and incident analysis (Emergent LLM key)
4. 25+ security connector integrations
5. SOAR playbook automation
6. Compliance management (GDPR, HIPAA, SOX, PCI-DSS)
7. Stripe billing with plan tiers

## User Personas
- **SOC Analyst**: Triages alerts, investigates incidents, runs playbooks
- **SOC Manager**: Monitors KPIs, manages team, reviews compliance
- **CISO**: Views executive dashboards, manages policies, reviews posture
- **Platform Admin**: Manages organizations, users, system health

## What's Been Implemented
- [2026-02-xx] Complete TypeScript/Express codebase with 365 API endpoints, 49 pages, 126 DB tables (NON-FUNCTIONAL due to infrastructure mismatch)
- [2026-02-xx] Comprehensive 5-phase ship plan created at `/app/docs/SECURENEXUS_COMPLETE_5_PHASE_SHIP_PLAN.md`

## Current Status
- Both services FATAL - app cannot start
- Infrastructure mismatch: TypeScript/Express/PostgreSQL codebase vs Python/FastAPI/MongoDB deployment
- Zero tests passing
- Ship-readiness score: 15/100

## Key Documents
- `/app/docs/SECURENEXUS_COMPLETE_5_PHASE_SHIP_PLAN.md` - Definitive 5-phase ship plan
- `/app/docs/SECURENEXUS_SHIP_READINESS_AUDIT.md` - Ship-readiness audit
- `/app/shared/schema.ts` - Complete database schema (4,818 lines)
- `/app/server/` - TypeScript backend (55,048 lines) - serves as specification
- `/app/client/` - TypeScript frontend (53,871 lines) - serves as specification

## Tech Stack (Target)
- Frontend: React + Vite + TailwindCSS + shadcn/ui
- Backend: Python FastAPI
- Database: MongoDB
- AI: Emergent LLM key (OpenAI/Claude/Gemini)
- Billing: Stripe

## Prioritized Backlog
### P0 (Must Have for Launch)
- Infrastructure setup (backend + frontend directories)
- Authentication (register, login, logout)
- Dashboard with real data
- Alerts CRUD
- Incidents CRUD
- RBAC enforcement
- AI triage integration

### P1 (Should Have)
- Connector management
- Entity resolution
- Alert correlation
- Threat intelligence
- SOAR playbooks
- Compliance management
- Reporting

### P2 (Nice to Have)
- CSPM integration
- MSSP multi-tenant
- Advanced visualizations (attack graph, kill chain)
- Developer portal
- Platform admin

## Next Tasks
1. Get approval from user to begin Phase 1 implementation
2. Set up /app/backend/ with Python FastAPI + MongoDB
3. Set up /app/frontend/ with React + Vite
4. Implement auth system
5. Build dashboard and core CRUD
