# Contributing to SecureNexus

## Prerequisites

- **Node.js** v20+
- **npm** (ships with Node)
- **Docker** and **Docker Compose** (for local PostgreSQL and LocalStack)

## Quick Start (single command)

```bash
npm run dev:setup
```

This runs `scripts/dev-setup.sh` which:

1. Checks prerequisites (Node 20+, npm, Docker)
2. Creates `.env` from `.env.example` (if missing)
3. Starts PostgreSQL 16 and LocalStack (S3 mock) via Docker Compose
4. Installs npm dependencies
5. Pushes the Drizzle schema to the local database
6. Prints connection details

After setup, start the dev server:

```bash
npm run dev
```

The app is available at **http://localhost:5000**.

## Manual Setup

If you prefer step-by-step:

```bash
# 1. Copy env template
cp .env.example .env

# 2. Start services (PostgreSQL + LocalStack)
npm run dev:services

# 3. Install dependencies
npm ci

# 4. Push database schema
npx drizzle-kit push

# 5. Start dev server (seeds DB on first run)
npm run dev
```

## Dev Check Scripts

| Command               | What it does                                     |
|-----------------------|--------------------------------------------------|
| `npm run typecheck`   | TypeScript compiler — zero-emission type check   |
| `npm test`            | Run unit tests via Vitest                        |
| `npm run test:watch`  | Run tests in watch mode                          |
| `npm run test:coverage` | Run tests with V8 coverage report              |
| `npm run format:check`| Check formatting via Prettier (no writes)        |
| `npm run format`      | Auto-format source files                         |
| `npm run checks`      | Typecheck + unit tests (fast pre-push gate)      |
| `npm run checks:all`  | Typecheck + tests + format check (full gate)     |

Run `npm run checks` before pushing to ensure CI will pass.

## Project Structure

```
securenexus/
├── client/src/          # React frontend (Vite + Tailwind)
├── server/              # Express backend
│   ├── __tests__/       # Unit tests (Vitest)
│   ├── routes/          # Domain-scoped route modules
│   ├── connectors/      # Third-party security connectors
│   ├── ai/              # AI subsystem (model gateway, budget, prompts)
│   └── ...
├── shared/              # Shared types and DB schema (Drizzle)
├── k8s/                 # Kubernetes manifests (staging, uat, production)
├── scripts/             # Dev and ops scripts
├── .github/workflows/   # CI/CD pipeline
├── docker-compose.yml   # Local dev services
├── vitest.config.ts     # Test configuration
└── .env.example         # Environment variable template
```

## CI Pipeline

On every PR:
- **Lint and Typecheck** — `tsc --noEmit` (blocking)
- **Unit Tests** — Vitest with coverage report
- **Secret Scanning** — Gitleaks + custom pattern scan
- **CodeQL Analysis** — GitHub security scanning
- **Bundle Size Check** — JS budget enforcement
- **Docker Build + Trivy** — Container vulnerability scan
- **Dependency Audit** — npm audit for high/critical CVEs
- **SBOM Generation** — CycloneDX bill of materials
- **License Compliance** — Deny AGPL/GPL/SSPL

On merge to main:
- All PR checks above
- **Build and Push** to ECR
- **Deploy to Staging** with smoke test
- **Deploy to UAT**
- **Deploy to Production** via Argo Rollouts (canary)

## Writing Tests

Tests live alongside their modules in `server/__tests__/`:

```typescript
import { describe, it, expect, vi } from "vitest";

describe("myFunction", () => {
  it("does the expected thing", () => {
    expect(myFunction("input")).toBe("output");
  });
});
```

Run a single test file:

```bash
npx vitest run server/__tests__/my-module.test.ts
```

## Environment Variables

See `.env.example` for the full list with descriptions. Required vars:

| Variable         | Description                     |
|------------------|---------------------------------|
| `DATABASE_URL`   | PostgreSQL connection string    |
| `SESSION_SECRET` | Session encryption key          |
| `S3_BUCKET_NAME` | AWS S3 bucket for file uploads  |

All other variables have sensible defaults for local development.

## Stopping Services

```bash
npm run dev:services:down
```

This stops PostgreSQL and LocalStack. Data persists in Docker volumes.
To fully reset:

```bash
docker compose down -v
```
