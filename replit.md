# SecureNexus - AI Security Intelligence Platform

## Overview
SecureNexus is an AI-powered Security Orchestration & Intelligence Platform offered as a full SaaS solution. It centralizes cybersecurity alerts from diverse tools, employs AI for correlation, and generates attacker-centric incident narratives. The platform aims to deliver comprehensive security intelligence, automate incident response, and enhance threat detection, with a roadmap to achieve feature parity with leading security platforms and address market needs for unified, intelligent security operations.

## User Preferences
- Default to dark mode
- Cybersecurity-focused design language
- Professional, enterprise-grade UI
- Human-in-the-loop approach for AI features

## System Architecture
The platform features a modern web stack: React + TypeScript frontend using Vite, TailwindCSS, and shadcn/ui, with an Express.js (TypeScript) backend. Data persistence is managed by PostgreSQL via Drizzle ORM, and authentication uses Passport.js (Local, Google OAuth, GitHub OAuth) with PostgreSQL session store.

**Key Architectural Decisions and Features:**

- **AI Integration**: Leverages AWS Bedrock Converse API (Mistral Large 2 Instruct) for cybersecurity analysis, supported by custom SageMaker models. AI assists in alert correlation, triage, and generating evidence-backed incident narratives, enriched with threat intelligence from various sources.
- **Data Model**: Comprehensive schemas for organizations, alerts, incidents, and associated operational data, optimized for security operations.
- **Normalization Engine**: Supports 24 diverse cybersecurity data sources, normalizing alerts into an OCSF-aligned format.
- **Correlation Engine**: Employs both temporal entity clustering and a graph-based approach (BFS traversal over entity-alert bipartite graphs) to detect sophisticated campaigns, including multi-hop attack paths with a 6-factor confidence scoring system.
- **Alert Quality Management**: Implements suppression rules and fuzzy duplicate clustering to reduce noise and enhance alert relevance, with custom tagging and confidence calibration.
- **Incident Workflow Management**: Features SLA tracking with configurable policies, queue views, and post-incident review templates for continuous improvement.
- **Incident Management**: Provides robust capabilities for managing incident status, priority, assignment, escalation, and an auditable activity timeline.
- **Case Management & Investigation Workspace**: Offers a tabbed interface for evidence tracking, investigation hypotheses, task management, and built-in runbook templates.
- **MITRE ATT&CK Integration**: Visualizes the MITRE ATT&CK matrix, mapping techniques from alerts to enhance understanding of attacker methodologies.
- **Entity Resolution & Graph**: Extracts and resolves entities from security findings, building a relationship graph for visualizing attack paths and identity resolution.
- **Reporting & Executive Briefs**: Provides configurable report templates, scheduled delivery, and role-specific dashboards with CSV/JSON export options.
- **SOAR-Lite Automation**: A visual playbook builder with node-based flow canvas supports 25+ action types, including ticketing, notifications, and EDR containment actions, with a graph-based execution engine.
- **Bi-Directional Integrations**: Configurable integrations for ticketing systems, communication platforms, and EDRs, with encrypted credential storage and an audit trail for response actions.
- **Real-time Capabilities**: Utilizes Server-Sent Events (SSE) and webhook ingestion with HMAC signature verification for instant threat detection and live updates.
- **Threat Intelligence Enrichment**: Automated enrichment via AbuseIPDB, VirusTotal, and OTX AlienVault, complemented by free public OSINT feeds.
- **Threat Intel Fusion Layer**: An IOC ingestion engine with multi-format parsers and an IOC matcher for rule-based matching against alerts, with watchlists for curated indicators.
- **Kill Chain Visualization**: Interactive Cyber Kill Chain timeline and Executive Attack Summary integrating the Diamond Model, kill chain progress, and impact assessment.
- **Predictive Attack Modeling & Proactive Defense**: Anomaly detection, attack surface mapping with risk scoring, risk forecasting, and rule-based hardening recommendations.
- **Autonomous Response & Agentic SOC**: Auto-response policies with confidence thresholds, an AI investigation agent, and a rollback engine for automated containment actions.
- **Cloud Security Posture Management (CSPM)**: Wiz-like cloud posture scanning for AWS, Azure, and GCP, generating findings mapped to compliance frameworks (CIS/NIST/PCI-DSS/SOC2). Includes policy-as-code checks with rule-based evaluation against CSPM findings.
- **Compliance Control Mappings**: Mapped controls for NIST CSF, ISO 27001, CIS, and SOC 2 frameworks with seedable built-in controls and resource-level status tracking.
- **Evidence Locker**: Audit-ready artifact management with retention policies, framework/control mapping, checksums, and expiry tracking for compliance evidence.
- **Versioned API & OpenAPI**: Public /api/v1/status and /api/v1/openapi endpoints for API consumers, with typed OpenAPI 3.0 specification.
- **Outbound Webhooks**: Configurable webhooks for incident lifecycle events (created/updated/closed/escalated) with HMAC signing, retry policies, delivery logging, and test functionality.
- **Idempotency Keys**: X-Idempotency-Key header support on ingestion endpoints for at-most-once delivery with 24-hour key expiry.
- **Endpoint Telemetry Dashboards**: Provides CrowdStrike-like endpoint health monitoring, asset inventory, telemetry snapshots, and automated risk scoring.
- **Unified Security Posture Scoring**: Aggregates security posture into a single score (0-100) combining CSPM, endpoint health, incident trends, and compliance status.
- **On-Prem/Sovereign AI Deployment Configuration**: Configurable AI model backend selection (AWS Bedrock, SageMaker, on-prem, Azure OpenAI) with data residency settings.
- **UI/UX**: Emphasizes a professional, cybersecurity-centric design with a global command palette, advanced dashboards, and interactive visualizations.
- **Enterprise Compliance & Data Governance**: Supports DPDP Act/GDPR compliance with configurable data retention policies, PII pseudonymization, immutable audit trails, and DSAR management.
- **Multi-Tenancy & RBAC**: Designed for multi-organization support with role-based access control (Admin, Analyst, Viewer).
- **Scalability**: Engineered for SaaS deployment with planned migration to AWS App Runner.

## External Dependencies
- **Authentication**: Passport.js (Local, Google OAuth, GitHub OAuth)
- **Database**: PostgreSQL
- **Cloud AI Services**: AWS Bedrock Converse API, AWS SageMaker
- **Object Storage**: AWS S3
- **Container Registry**: AWS ECR
- **Deployment**: AWS App Runner
- **Threat Intelligence Feeds**: AbuseIPDB, VirusTotal, OTX AlienVault
- **Ticketing Systems**: Jira, ServiceNow, PagerDuty
- **Communication Platforms**: Email, Slack, Microsoft Teams
- **EDR/Security Tools**: Integration with 24 specific cybersecurity tools (e.g., CrowdStrike, Splunk, Palo Alto, GuardDuty).
