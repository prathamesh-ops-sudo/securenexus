# Technology Stack

**Analysis Date:** 2026-03-25

## Languages

**Primary:**
- TypeScript 5.6.3 - Used throughout frontend (`client/src/**`), backend (`server/**`), and shared code (`shared/**`)
- JavaScript - Node.js runtime for server execution

**Secondary:**
- HTML/CSS - React + TailwindCSS for frontend
- SQL - PostgreSQL queries via Drizzle ORM

## Runtime

**Environment:**
- Node.js 20 (from Dockerfile: `node:20-slim`)

**Package Manager:**
- npm (with `package-lock.json`)
- Lockfile: present

## Frameworks

**Core:**
- Express.js 5.0.1 - HTTP server framework (`server/index.ts` is entry point)
- React 18.3.1 - Frontend UI library
- Vite 7.3.0 - Frontend build tool and dev server
- Drizzle ORM 0.39.3 - SQL ORM for PostgreSQL

**Testing:**
- Vitest 4.0.18 - Test runner and framework (config: `vitest.config.ts`)
- @vitest/coverage-v8 4.0.18 - Code coverage
- @playwright/test 1.58.2 - E2E testing (config: `playwright.config.ts`)

**Build/Dev:**
- tsx 4.20.5 - TypeScript executor for Node.js scripts
- esbuild 0.25.0 - Fast JavaScript bundler (used by Vite)
- Drizzle Kit 0.31.8 - Database migration tool

## Key Dependencies

**Critical:**
- pg 8.16.3 - PostgreSQL client for connection pooling
- pgvector 0.2.1 - PostgreSQL vector type support for embeddings
- @aws-sdk/* - AWS service clients for Bedrock, SageMaker, S3, SES, GuardDuty, RDS, EC2, IAM, STS, AppRunner, ECR
- Stripe 20.4.0 - Payment processing

**Frontend UI:**
- @radix-ui/* - Accessible UI component primitives (accordion, dialog, dropdown, select, etc.)
- shadcn/ui - Built on Radix UI with TailwindCSS integration
- recharts 2.15.4 - Charting library for analytics
- lucide-react 0.453.0 - Icon library
- wouter 3.3.5 - Lightweight client-side router
- @tanstack/react-query 5.60.5 - Data fetching and caching
- framer-motion 12.35.2 - Animation library

**Infrastructure:**
- @aws-sdk/client-bedrock-runtime 3.988.0 - AWS Bedrock for LLM inference
- @aws-sdk/client-sagemaker-runtime 3.988.0 - AWS SageMaker for ML models
- @aws-sdk/s3-request-presigner 3.990.0 - Pre-signed S3 URLs
- Helmet 8.1.0 - Security headers middleware
- compression 1.8.1 - gzip/deflate response compression
- express-rate-limit 8.2.1 - API rate limiting
- express-session 1.19.0 - Session management
- connect-pg-simple 10.0.0 - PostgreSQL session store

**Authentication:**
- passport 0.7.0 - Authentication middleware
- passport-local 1.0.0 - Local username/password strategy
- passport-google-oauth20 2.0.0 - Google OAuth2 strategy
- passport-github2 0.1.12 - GitHub OAuth2 strategy
- otplib 13.3.0 - One-time password (TOTP/HOTP) generation
- input-otp 1.4.2 - OTP input UI component

**Security & Encryption:**
- jose 6.1.3 - JOSE (JSON Web Signature and Encryption) implementation
- xml-crypto 6.1.2 - XML signing and encryption
- @xmldom/xmldom 0.8.11 - XML DOM implementation

**Utilities:**
- zod 3.24.2 - TypeScript-first schema validation
- drizzle-zod 0.7.0 - Zod integration with Drizzle ORM
- date-fns 3.6.0 - Date manipulation utility
- qrcode 1.5.4 - QR code generation
- pdfkit 0.17.2 - PDF generation
- rss-parser 3.13.0 - RSS feed parsing
- multer 2.0.2 - File upload handling
- canvas-confetti 1.9.4 - Confetti animation effect
- @octokit/rest 22.0.0 - GitHub API client
- ws 8.18.0 - WebSocket library
- memorystore 1.6.7 - In-memory session store for development
- js-tiktoken 1.0.21 - Token counting for LLMs

**Form & UI:**
- react-hook-form 7.55.0 - Lightweight form state management
- react-day-picker 8.10.1 - Date picker component
- embla-carousel-react 8.6.0 - Carousel/slider component
- react-resizable-panels 2.1.7 - Resizable panel layout
- cmdk 1.1.1 - Command/search palette component
- vaul 1.1.2 - Sheet/drawer component
- clsx 2.1.1 - Class name utility
- tailwind-merge 2.6.0 - Merge Tailwind class conflicts
- class-variance-authority 0.7.1 - Type-safe component variants

## Configuration

**Environment:**
- `.env.example` - Template for required environment variables
- Critical configs:
  - `DATABASE_URL` - PostgreSQL connection string
  - `SESSION_SECRET` - Encryption key for sessions (32+ chars in production)
  - `S3_BUCKET_NAME` - AWS S3 bucket name
  - `AWS_REGION` - AWS region (default: us-east-1)
  - `NODE_ENV` - development|staging|uat|production
  - `PORT` - Server port (default: 5000)
  - `AI_BACKEND` - bedrock|sagemaker (default: bedrock)
  - `AI_MODEL_ID` - Bedrock model (default: anthropic.claude-sonnet-4-20250514-v1:0)

**Build:**
- `tsconfig.json` - TypeScript compiler options with path aliases (`@`, `@shared`)
- `vite.config.ts` - Frontend build configuration with React plugin and manual chunk splitting
- `vitest.config.ts` - Test runner configuration with node environment and v8 coverage
- `eslint.config.js` - ESLint rules for TypeScript, React hooks, and Prettier integration
- `.prettierrc` - Code formatting configuration
- `tailwind.config.ts` - Tailwind CSS customization
- `postcss.config.js` - PostCSS configuration for Tailwind

## Platform Requirements

**Development:**
- Node.js 20
- PostgreSQL 16 (via docker-compose.yml)
- LocalStack 3 for local S3 testing (optional)
- Docker and docker-compose for services

**Production:**
- AWS EKS (Kubernetes 1.31)
- AWS RDS PostgreSQL
- AWS S3 for file storage
- AWS Bedrock or SageMaker for LLM inference
- AWS SES for email delivery
- AWS security services (GuardDuty, IAM role-based access)
- Deployment via Docker container, Argo Rollouts for canary releases

## Database

**Connection:**
- PostgreSQL 16 via `pg` client
- Configured via `DATABASE_URL` environment variable
- Connection pool: 20 max (production), 5 max (development)
- Statement timeout: 30s (production), 60s (development)
- Health monitoring via `startPoolHealthMonitor()` in `server/db.ts`

**ORM:**
- Drizzle ORM 0.39.3 for type-safe database queries
- Schema defined in `shared/schema.ts`
- Migrations in `migrations/` directory
- Drizzle Kit for schema generation and migrations

## External Runtime Services

**Email:**
- AWS SES v2 (Simple Email Service) - Production/staging only
- Configured via `@aws-sdk/client-sesv2`
- From address: `noreply@aricatech.xyz`

**Storage:**
- AWS S3 via `@aws-sdk/client-s3`
- Pre-signed URLs via `@aws-sdk/s3-request-presigner`
- Bucket: `S3_BUCKET_NAME` environment variable

**AI/ML:**
- AWS Bedrock Runtime - Primary LLM backend
  - Model: `anthropic.claude-sonnet-4-20250514-v1:0` (main)
  - Model: `anthropic.claude-opus-4-20250514-v1:0` (investigation)
  - Model: Mistral Large 2 (optional)
- AWS SageMaker Runtime - Alternative ML endpoint
  - Configured via `SAGEMAKER_ENDPOINT` and `SAGEMAKER_TRIAGE_ENDPOINT`

**Cloud Security Scanning:**
- AWS GuardDuty - Threat detection
- AWS RDS - Database listing for CSPM
- AWS EC2 - Compute resource enumeration
- AWS IAM - Permission analysis

---

*Stack analysis: 2026-03-25*
