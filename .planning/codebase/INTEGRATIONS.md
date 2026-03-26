# External Integrations

**Analysis Date:** 2026-03-25

## APIs & External Services

**Security Tools (Alert Ingestion):**
- Supported connectors in `server/connectors/`:
  - CarbonBlack EDR
  - CrowdStrike Falcon
  - Microsoft Defender
  - Elastic Security
  - Palo Alto Networks
  - FortiGate
  - Checkpoint
  - Darktrace
  - Okta
  - Proofpoint
  - QRadar
  - Qualys
  - Rapid7
  - SentinelOne
- SDK/Client: Connector-specific HTTP clients (configured per connector)
- Auth: API keys stored in `connectors` table in database

**Cloud Connectors:**
- AWS - `server/cloud-connectors/aws.ts`
  - GuardDuty integration
  - RDS enumeration
  - EC2 security group analysis
  - IAM policy analysis
- Azure - `server/cloud-connectors/azure.ts`
- GCP - `server/cloud-connectors/gcp.ts`

**GitHub:**
- @octokit/rest 22.0.0 - GitHub REST API client
- Uses `GITHUB_TOKEN` environment variable
- Location: `server/` routes and integrations

**Stripe (Payment Processing):**
- stripe 20.4.0 - Payment SDK
- Auth: `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`
- Location: `server/stripe-service.ts`
- Webhook endpoint: Processes checkout.session.completed, invoice.paid, invoice.payment_failed, customer.subscription.*, etc.
- Features: Checkout sessions, billing portal, subscription management, plan changes

## Data Storage

**Databases:**
- PostgreSQL 16 (AWS RDS in production)
  - Connection: `DATABASE_URL` environment variable
  - Client: pg 8.16.3
  - ORM: Drizzle ORM 0.39.3
  - Vector support: pgvector 0.2.1 for embeddings

**File Storage:**
- AWS S3
  - Bucket: `S3_BUCKET_NAME` environment variable
  - Pre-signed URLs: `@aws-sdk/s3-request-presigner`
  - Local testing: LocalStack 3 (docker-compose.yml)

**Caching:**
- In-memory session store: memorystore 1.6.7 (development)
- PostgreSQL session store: connect-pg-simple 10.0.0 (production)
- Query cache: `server/query-cache.ts` (in-memory with TTL)

## Authentication & Identity

**Auth Provider:**
- Replit Auth (OpenID Connect) - Primary
- Passport.js 0.7.0 - Authentication middleware
- Custom implementations via `server/auth/`

**OAuth Strategies:**
- Google OAuth 2.0 - passport-google-oauth20
  - Env vars: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_CALLBACK_URL`
- GitHub OAuth 2.0 - passport-github2
  - Env vars: `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GITHUB_CALLBACK_URL`
- Local (username/password) - passport-local with scrypt hashing

**Session Management:**
- express-session 1.19.0 - Session middleware
- Storage: PostgreSQL via connect-pg-simple (production) or memorystore (dev)
- Secret: `SESSION_SECRET` environment variable (32+ chars in production)
- Cache: User deserialization cache with 30s TTL, 500 entry limit
- Location: `server/auth/session.ts`

**MFA:**
- TOTP/HOTP via otplib 13.3.0
- QR code generation: qrcode 1.5.4
- UI component: input-otp 1.4.2

## Monitoring & Observability

**Error Tracking:**
- Custom error tracking middleware at `server/error-tracker.ts`
- Logs errors with context (route, method, user ID)

**Logs:**
- Custom logger at `server/logger.ts`
- Child loggers per module for context
- Correlation IDs via correlationMiddleware
- Request logging via requestLogger

**Metrics:**
- Prometheus scraping via `server/prometheus.ts`
  - Endpoint: `GET /metrics`
- Middleware: prometheusMiddleware
- Render metrics: renderMetrics()

**Performance Monitoring:**
- Request lifecycle tracking: `server/request-lifecycle.ts` (inFlightMiddleware)
- Database performance: `server/db-performance.ts` (performanceBudgetMiddleware)
- Connection pool health: `server/db.ts` (startPoolHealthMonitor)
- SLI collection: `server/sli-middleware.ts`
- SLO alerting: `server/slo-alerting.ts`

## CI/CD & Deployment

**Hosting:**
- AWS EKS (Kubernetes 1.31) - Primary
- AWS App Runner - Alternative (apprunner.yaml config present)

**CI Pipeline:**
- GitHub Actions (`.github/` directory)
- Builds Docker image → pushes to AWS ECR
- Stages: staging → uat → production
- Canary releases via Argo Rollouts

**Container:**
- Docker image: `node:20-slim` base
- Built via `npm run build` (script/build.ts)
- Security: Non-root user (uid 1001), read-only dist
- Healthcheck: HTTP GET /api/ops/health with 30s interval

## Environment Configuration

**Required env vars (startup will fail without these):**
- `DATABASE_URL` - PostgreSQL connection string
- `SESSION_SECRET` - Session encryption key (32+ chars in prod)
- `S3_BUCKET_NAME` - AWS S3 bucket name

**AWS Configuration:**
- `AWS_REGION` - AWS region (default: us-east-1)
- `AWS_ACCESS_KEY_ID` - Optional; EKS uses IRSA (IAM Roles for Service Accounts)
- `AWS_SECRET_ACCESS_KEY` - Optional; EKS uses IRSA

**AI/ML Configuration:**
- `AI_BACKEND` - bedrock (default) | sagemaker
- `AI_MODEL_ID` - Bedrock model ID (default: anthropic.claude-sonnet-4-20250514-v1:0)
- `AI_MAX_TOKENS` - Max tokens (default: 4096)
- `AI_TEMPERATURE` - Model temperature (default: 0.1)
- `AI_TOP_P` - Nucleus sampling (default: 0.9)
- `AI_TRIAGE_MODEL_ID` - Triage-specific model (default: anthropic.claude-sonnet-4-20250514-v1:0)
- `AI_TRIAGE_MAX_TOKENS` - Triage max tokens (default: 2048)
- `AI_TRIAGE_TEMPERATURE` - Triage temperature (default: 0.05)
- `AI_INVESTIGATION_MODEL_ID` - Deep investigation model (default: anthropic.claude-opus-4-20250514-v1:0)
- `AI_INVESTIGATION_MAX_TOKENS` - Investigation tokens (default: 8192)
- `SAGEMAKER_ENDPOINT` - Required when AI_BACKEND=sagemaker
- `SAGEMAKER_TRIAGE_ENDPOINT` - Required when AI_BACKEND=sagemaker

**OAuth Configuration:**
- `GOOGLE_CLIENT_ID` - Google OAuth client ID (optional)
- `GOOGLE_CLIENT_SECRET` - Google OAuth client secret (optional)
- `GOOGLE_CALLBACK_URL` - Google OAuth callback (default: /api/auth/google/callback)
- `GITHUB_CLIENT_ID` - GitHub OAuth client ID (optional)
- `GITHUB_CLIENT_SECRET` - GitHub OAuth client secret (optional)
- `GITHUB_CALLBACK_URL` - GitHub OAuth callback (default: /api/auth/github/callback)
- `GITHUB_TOKEN` - GitHub API token for integrations (optional)
- `COGNITO_USER_POOL_ID` - AWS Cognito user pool (optional)

**Billing Configuration:**
- `STRIPE_SECRET_KEY` - Stripe API key (optional; billing disabled if not set)
- `STRIPE_WEBHOOK_SECRET` - Stripe webhook signing key (optional)

**Application Configuration:**
- `NODE_ENV` - development | staging | uat | production (default: development)
- `PORT` - Server port (default: 5000)
- `FORCE_HTTPS` - Set to "true" in production for secure cookies
- `APP_BASE_URL` - Absolute application URL for OAuth callbacks (e.g., https://staging.aricatech.xyz)
- `SUPER_ADMIN_EMAIL` - Email auto-promoted to super admin on login (optional)

**Secrets location:**
- `.env` file (not committed; template: `.env.example`)
- AWS Secrets Manager for EKS deployments (via IRSA)
- Environment variables in CI/CD pipeline

## Webhooks & Callbacks

**Incoming Webhooks:**
- `POST /api/webhooks/stripe` - Stripe event webhook (checkout, invoice, subscription events)
- Signature verification: HMAC-SHA256 via Stripe SDK

**Outgoing Webhooks:**
- Playbook action dispatcher can send HTTP POST webhooks to configured endpoints
- Location: `server/action-dispatcher.ts`
- Validation: `validateWebhookUrl()` to prevent SSRF attacks
- Event types: Custom webhook dispatch via alert/incident actions

**SSE (Server-Sent Events):**
- Endpoint: `GET /api/events` - Real-time event stream
- Returns: alert created, incident updated, system events, etc.

## Rate Limiting

**Implementation:**
- express-rate-limit 8.2.1
- Global rate limit middleware configured in `server/index.ts`
- API response includes rate limit headers

## Security Features

**Implemented:**
- Helmet 8.1.0 - Security headers (CSP, X-Frame-Options, X-Content-Type-Options, etc.)
- Input sanitization middleware: `server/security-middleware.ts`
- CORS support in API routes
- Idle session timeout: 30 seconds (production), 10 seconds (development)
- Connection statement timeout: 30s (production), 60s (development)
- Request timeout middleware: `server/request-timeout.ts`
- Tenant isolation: `server/tenant-isolation.ts`

**PII/Sensitive Data:**
- PII masking engine: `server/pii-engine.ts`
- OCSF normalization: `server/ocsf.ts` (Open Cybersecurity Schema Framework)

**Audit & Compliance:**
- Audit logging: `server/` routes
- Chain-hash audit trail: tamper-evident logging
- Outbox pattern: `server/outbox-processor.ts` for reliable event delivery
- Feature flags: `server/feature-flags.ts` for gradual rollout

## API Standards

**Canonical Envelope:**
- All endpoints return `ApiEnvelope<T>` from `server/api-response.ts`
- Structure:
  ```json
  {
    "data": <T>|null,
    "meta": {page?, pageSize?, total?, ...},
    "errors": [{code, message, field?, details?}]|null
  }
  ```
- ERROR_CODES define machine-readable error codes
- Helpers: `reply()`, `replyError()`, `sendEnvelope()`

**Idempotency:**
- X-Idempotency-Key header support on mutations
- Location: `server/` routes

**Deprecation Headers:**
- RFC 8594 Deprecation, Sunset, and Link headers
- Middleware: legacyEndpoint() in routes.ts
- Sunset date: 2026-07-01

**OpenAPI Specification:**
- Generated from routes: `server/openapi.ts`
- Available for API documentation

---

*Integration audit: 2026-03-25*
