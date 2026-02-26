# SecureNexus Infrastructure Architecture

## Overview

SecureNexus runs on AWS with a Kubernetes-based deployment pipeline. The architecture supports three environments (staging, UAT, production) with progressive delivery via Argo Rollouts canary deployments.

## Infrastructure Map

```
GitHub Actions CI/CD
  push to main -> lint/typecheck -> build Docker -> push ECR
  -> deploy staging -> smoke test -> deploy UAT -> deploy production

                         |
                Amazon ECR (securenexus:tag)
                         |
                    Amazon EKS
              Cluster: securenexus
              Region: us-east-1
        +-----------+-----------+
        |           |           |
   staging ns   uat ns    production ns
   (1 pod)      (1 pod)   (2 pods, Argo Canary)
                           PDB: minAvailable=1
                           Canary: 20->50->80

              monitoring ns
           Prometheus + Grafana

                         |
                  AWS Services
        RDS PostgreSQL (securenexus-db)
        S3 (securenexus-uploads)
        Secrets Manager
        ECR
```

## Environments

| Environment | Namespace | Replicas | Strategy | Domain |
|---|---|---|---|---|
| Staging | staging | 1 | Rolling update | staging.aricatech.xyz |
| UAT | uat | 1 | Rolling update | - |
| Production | production | 2 | Argo Canary (20->50->80) | nexus.aricatech.xyz |

## CI/CD Pipeline

**Trigger:** Push to main or workflow_dispatch

```
lint-and-typecheck
  +-- build-check (PR only: Docker build + Trivy scan)
  +-- build-and-push (main only: Docker build -> ECR)
        +-- deploy-staging (+ smoke test)
              +-- deploy-uat
                    +-- deploy-production (Argo Rollout + smoke test)
```

### Pipeline Jobs

1. **lint-and-typecheck**: TypeScript compilation check, npm audit (high severity)
2. **build-check** (PRs only): Docker build + Trivy vulnerability scan (CRITICAL/HIGH)
3. **build-and-push**: Docker buildx with GHA layer caching, push to ECR
4. **deploy-staging**: Sync secrets from Secrets Manager, apply manifests, smoke test health endpoint
5. **deploy-uat**: Same pattern as staging
6. **deploy-production**: Install Argo Rollouts plugin, sync secrets, apply PDB + rollout, wait for canary completion, smoke test

### Security Scanning

- **Trivy**: Container image vulnerability scanning on every PR
- **npm audit**: Dependency vulnerability check (high severity threshold)
- **Docker buildx**: Reproducible multi-stage builds with layer caching

## Kubernetes Architecture

### Pod Security

All pods run with hardened security contexts:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1001
  runAsGroup: 1001
  fsGroup: 1001
  seccompProfile:
    type: RuntimeDefault
containers:
  - securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: [ALL]
```

### Network Policies

Default-deny ingress/egress per namespace with explicit allow rules:
- **Ingress**: Port 5000 (app HTTP)
- **Egress**: Port 5432 (PostgreSQL), Port 443 (HTTPS/AWS APIs), Port 53 (DNS)

### Resource Allocation

| Environment | CPU Request | CPU Limit | Memory Request | Memory Limit |
|---|---|---|---|---|
| Staging | 100m | 500m | 128Mi | 512Mi |
| UAT | 100m | 500m | 128Mi | 512Mi |
| Production | 200m | 1000m | 256Mi | 1Gi |

### Health Probes

Each pod has three probes:
- **Startup**: /api/ops/health (failureThreshold: 30, period: 2s) - gives 60s for cold start
- **Liveness**: /api/ops/health (period: 15s, timeout: 5s)
- **Readiness**: /api/ops/health (period: 5s, timeout: 3s)

### Production Availability

- **PodDisruptionBudget**: minAvailable: 1 - ensures at least one pod during node drains
- **Argo Canary**: maxSurge: 1, maxUnavailable: 0 - zero-downtime deployments
- **terminationGracePeriodSeconds**: 30s - allows in-flight requests to complete

## Docker Image

Multi-stage build for minimal attack surface:

```
Stage 1 (base):    node:20-slim
Stage 2 (deps):    npm ci
Stage 3 (builder): npm run build
Stage 4 (runner):  npm ci --omit=dev + dist/ only
```

Security features:
- Non-root user (securenexus:1001)
- HEALTHCHECK instruction for orchestrator-independent monitoring
- OCI labels for image provenance
- .dockerignore excludes secrets, docs, k8s manifests, IDE configs

## Secrets Management

Secrets flow: **AWS Secrets Manager -> CI/CD sync -> K8s Secrets -> Pod env vars**

Secrets are stored in AWS Secrets Manager under:
- securenexus/staging
- securenexus/uat
- securenexus/production

Each CI/CD deployment job syncs secrets to the target K8s namespace using idempotent kubectl create secret with --dry-run=client.

Required secrets per environment:
- DATABASE_URL - PostgreSQL connection string
- SESSION_SECRET - Express session signing key
- S3_BUCKET_NAME - Upload storage bucket
- AWS_REGION - AWS region for SDK calls

## Monitoring and Alerting

### Prometheus

- **Scrape interval**: 15s
- **Storage**: 10Gi PVC (gp2)
- **Targets**: Kubernetes pods with prometheus.io/scrape annotation

### Alerting Rules

| Alert | Condition | Severity |
|---|---|---|
| SecureNexusDown | up == 0 for 2m | Critical |
| HighErrorRate | 5xx rate > 5% for 5m | Warning |
| HighResponseLatency | p95 > 2s for 5m | Warning |
| HighMemoryUsage | > 85% of limit for 5m | Warning |
| HighCpuUsage | > 80% of limit for 10m | Warning |
| PodRestartLooping | > 3 restarts/hour | Critical |
| SLOAvailabilityBreach | < 99.9% over 1h | Critical |

### Grafana

- **Storage**: 5Gi PVC (gp2) - persistent dashboards
- **Service**: ClusterIP (accessed via kubectl port-forward or Ingress)
- **Default credentials**: admin / GRAFANA_ADMIN_PASSWORD from Secrets Manager

## IAM and RBAC

### AWS IAM

- EKS node role: AmazonEKSWorkerNodePolicy, AmazonEKS_CNI_Policy, AmazonEC2ContainerRegistryReadOnly
- Application role: AmazonBedrockReadOnly, AmazonS3ReadOnlyAccess (least-privilege)
- RDS: VPC-only access (10.0.0.0/8 CIDR - no public internet exposure)

### Kubernetes RBAC

- automountServiceAccountToken: false on all application pods
- Network policies enforce namespace isolation
- No cluster-admin bindings for application workloads

## Deployment Script (scripts/deploy-aws.ts)

Provisions the full AWS stack:
1. VPC + subnets
2. RDS PostgreSQL (with deletion protection)
3. EKS cluster + node group
4. ECR repository
5. S3 bucket
6. IAM roles with least-privilege policies

Security hardening:
- Password generation uses crypto.randomBytes() (not Math.random())
- RDS security group restricted to VPC CIDR (10.0.0.0/8)
- RDS deletion protection enabled
- All AWS SDK calls have proper error handling

## EKS Bootstrap (scripts/setup-eks.sh)

Idempotent setup script:
1. Update kubeconfig
2. Create namespaces
3. Install Argo Rollouts
4. Apply network policies
5. Sync secrets from AWS Secrets Manager
6. Deploy monitoring stack (Prometheus + Grafana + alerting rules)
7. Apply production PDB

## SDLC Governance

- **PR Template**: Enforces type of change, testing checklist, deployment notes
- **CODEOWNERS**: Auto-assigns @prathamesh-ops-sudo for all infrastructure and code reviews
- **Issue Templates**: Structured bug reports with severity and environment fields
- **Branch Protection**: Requires PR reviews before merge to main
- **Concurrency Control**: CI/CD uses concurrency.group to prevent parallel deploys

## Network Architecture

```
Internet -> ALB/ELB -> K8s Service -> Pods (port 5000)
                                        |
                                RDS (port 5432, VPC-only)
                                S3 (port 443, HTTPS)
                                Secrets Manager (port 443)
                                Bedrock (port 443)
```

All egress from pods is restricted by NetworkPolicy to:
- PostgreSQL (5432)
- HTTPS/AWS APIs (443)
- DNS resolution (53)

## Security Model and Trust Boundaries

### Trust Zones

```
┌─────────────────────────────────────────────────────────────────┐
│ ZONE 1: Public Internet (Untrusted)                             │
│   Browsers, API consumers, attackers                            │
├─────────────────────────────────────────────────────────────────┤
│ ZONE 2: Edge / Load Balancer (Semi-trusted)                     │
│   AWS ELB (staging, production)                                 │
│   TLS termination, DDoS absorption                              │
│   CNAME: staging.aricatech.xyz -> ELB                           │
│   CNAME: nexus.aricatech.xyz   -> ELB                           │
├─────────────────────────────────────────────────────────────────┤
│ ZONE 3: Application (Trusted, namespace-isolated)               │
│   K8s pods running as non-root (UID 1001)                       │
│   Read-only root filesystem, all capabilities dropped           │
│   Network policies restrict ingress to port 5000 only           │
│   No service account token mounted                              │
├─────────────────────────────────────────────────────────────────┤
│ ZONE 4: Data (Highest trust, VPC-only)                          │
│   RDS PostgreSQL (10.0.0.0/8 CIDR, no public access)           │
│   S3 bucket (IAM-authenticated, least-privilege)                │
│   AWS Secrets Manager (IAM-authenticated)                       │
│   AWS Bedrock (IAM-authenticated, us-east-1)                    │
└─────────────────────────────────────────────────────────────────┘
```

### Boundary Enforcement

| Boundary | Mechanism | Policy |
|---|---|---|
| Internet → ELB | Security Group | Port 80/443 only |
| ELB → Pod | K8s NetworkPolicy | Port 5000 ingress only |
| Pod → RDS | Security Group + NetworkPolicy | Port 5432, VPC CIDR only |
| Pod → AWS APIs | NetworkPolicy egress | Port 443 only |
| Pod → DNS | NetworkPolicy egress | Port 53 (TCP+UDP) |
| Pod filesystem | securityContext | readOnlyRootFilesystem: true |
| Pod privileges | securityContext | runAsNonRoot, drop ALL caps |
| Secrets | AWS Secrets Manager → K8s Secret | CI/CD sync, never in Git |

### Authentication Flow

1. **Email/password**: Passport.js local strategy → scrypt hash → PostgreSQL session store
2. **Google OAuth**: Passport.js Google strategy → redirect → callback → session
3. **GitHub OAuth**: Passport.js GitHub strategy → redirect → callback → session
4. **Session management**: express-session with PostgreSQL store, httpOnly + secure cookies
5. **RBAC**: Application-level role checks (owner / admin / analyst / viewer) per organization

### Data Protection

- Secrets never committed to Git (placeholder-only in k8s/base/secrets.yml)
- Session secrets rotated via Secrets Manager (manual rotation, no automation yet)
- Database credentials scoped per environment (separate Secrets Manager entries)
- S3 uploads authenticated via IAM (no pre-signed public URLs)
- AI model calls go through AWS Bedrock (no third-party API keys stored)

## Operational Runbook Pointers

### Accessing Environments

```bash
# Configure kubectl for the cluster
aws eks update-kubeconfig --name securenexus --region us-east-1

# Check pod status across all namespaces
kubectl get pods -l app=securenexus --all-namespaces

# View logs for staging
kubectl logs -n staging -l app=securenexus --tail=100 -f

# View logs for production (stable pods)
kubectl logs -n production -l app=securenexus,role=stable --tail=100 -f
```

### Monitoring Access

```bash
# Port-forward Grafana
kubectl port-forward -n monitoring svc/grafana 3000:80

# Port-forward Prometheus
kubectl port-forward -n monitoring svc/prometheus 9090:9090
```

### Common Incident Responses

**Pod crash-looping:**
```bash
kubectl describe pod -n <namespace> -l app=securenexus
kubectl logs -n <namespace> -l app=securenexus --previous
```

**Staging down after deploy:**
```bash
# Check deployment status
kubectl -n staging rollout status deployment/securenexus
# Rollback if needed
kubectl -n staging rollout undo deployment/securenexus
```

**Production canary failure:**
```bash
# Check rollout status
kubectl argo rollouts status securenexus -n production
# Abort canary and rollback
kubectl argo rollouts abort securenexus -n production
```

**Secret rotation:**
```bash
# Update secret in AWS Secrets Manager (console or CLI)
aws secretsmanager update-secret --secret-id securenexus/<env> --secret-string '...'
# Re-run the CI/CD pipeline or manually sync:
# (pipeline sync command from ci-cd.yml deploy step)
# Then restart pods to pick up new secrets:
kubectl rollout restart deployment/securenexus -n <namespace>
```

**Database connection issues:**
```bash
# Check RDS status in AWS console or CLI
aws rds describe-db-instances --db-instance-identifier securenexus-db
# Verify pod can reach RDS (exec into pod)
kubectl exec -n <namespace> -it <pod-name> -- node -e "require('net').connect(5432,'<rds-host>').on('connect',()=>{console.log('OK');process.exit(0)}).on('error',e=>{console.log(e.message);process.exit(1)})"
```

**Scaling production:**
```bash
# Scale replicas (minimum 2 for HA)
kubectl argo rollouts set replicas securenexus -n production 3
```

### Health Check Endpoints

| Endpoint | Purpose | Expected Response |
|---|---|---|
| GET /api/ops/health | Liveness + readiness | 200 with DB status |
| GET /api/ops/health (Prometheus) | Scrape target | 200 |

### Log Locations

| Source | Location |
|---|---|
| Application logs | kubectl logs -n <namespace> |
| CI/CD logs | GitHub Actions → workflow runs |
| RDS logs | AWS Console → RDS → Logs & events |
| ELB access logs | S3 (if enabled) or CloudWatch |

## Changes & Rationale

This section documents every significant infrastructure and UI change made to SecureNexus, with reasoning for each decision.

### Infrastructure Changes

| Change | What was done | Why |
|---|---|---|
| **Replit → AWS migration** | Replaced Replit hosting, Replit Auth, Replit DB with AWS EKS, Passport.js local auth, RDS PostgreSQL | Replit is a development environment, not production infrastructure. AWS provides SLAs, VPC isolation, and enterprise compliance (SOC 2, HIPAA eligible). |
| **App Runner → EKS** | Migrated from AWS App Runner to EKS with Argo Rollouts | App Runner lacks canary deployments, network policies, and fine-grained pod security contexts. EKS provides namespace isolation, progressive delivery, and PodDisruptionBudgets. |
| **Multi-stage Docker build** | Added non-root user (UID 1001), HEALTHCHECK, OCI labels, read-only filesystem | Running as root is a container escape risk. HEALTHCHECK provides orchestrator-independent monitoring. OCI labels improve image provenance tracking. |
| **Network policies** | Added default-deny ingress/egress per namespace with explicit allow rules | Without network policies, any pod can talk to any other pod. Default-deny ensures least-privilege network access. |
| **Pod security hardening** | runAsNonRoot, readOnlyRootFilesystem, drop ALL capabilities, seccomp RuntimeDefault | Defense-in-depth. Even if the application is compromised, the attacker cannot escalate privileges, write to the filesystem, or use kernel syscalls. |
| **Secrets Manager integration** | Moved all secrets from env vars / hardcoded values to AWS Secrets Manager with CI/CD sync | Secrets in Git or plain env vars are a data breach waiting to happen. Secrets Manager provides encryption at rest, audit trails, and rotation capability. |
| **Centralized config validation** | Added Zod-based config.ts with startup validation | Fail-fast on misconfiguration. Previously, missing env vars caused cryptic runtime errors minutes after startup. Now the app refuses to start with a clear error message. |
| **Prometheus + Grafana** | Deployed monitoring stack with 7 alerting rules and persistent storage | Without monitoring, incidents are discovered by users. Prometheus provides real-time metrics, and alerting rules catch issues (crash loops, SLO breaches) before users notice. |
| **PodDisruptionBudget** | Added PDB with minAvailable: 1 for production | Without a PDB, Kubernetes node drains can take down all pods simultaneously. PDB ensures at least one pod remains during maintenance. |
| **Canary deployments** | Argo Rollouts with 20% → 50% → 80% weight progression and 2-minute pauses | Big-bang deployments are risky. Canary lets you catch issues (error spikes, latency) at 20% traffic before they affect all users. |
| **Concurrency control** | CI/CD uses concurrency.group: deploy-${{ github.ref }} | Prevents parallel deployments that could cause race conditions (two deploys writing to the same namespace simultaneously). |
| **Trivy scanning** | Container vulnerability scanning on every PR | Catches known CVEs in base images and dependencies before they reach production. |
| **SDLC governance** | Added PR template, CODEOWNERS, issue templates, branch protection | Enforces code review, structured change management, and accountability. Required for SOC 2 compliance. |

### Landing Page Changes

| Change | What was done | Why |
|---|---|---|
| **CTA consolidation** | Removed "Get Started" button from nav, kept "Log in" as text link + "Start Free Trial" as primary button | Two competing buttons ("Get Started" and "Log in") create decision fatigue. One clear primary CTA reduces cognitive load and improves conversion. |
| **Removed dead "View Live Demo" button** | Replaced non-functional demo button with "See how it works" scroll link | A button that does nothing erodes trust. Replacing it with a smooth-scroll link to the How It Works section provides value without broken UX. |
| **Added "The Problem" section** | 4 pain-point cards (4000+ alerts/day, 45 min triage, 70% false positives, 3.5x tool sprawl) | High-converting pages establish pain before showing the solution. Without problem agitation, visitors don't understand why they need the product. |
| **Added "How It Works" section** | 3-step process (Connect tools → AI correlates → Respond with confidence) | Visitors need to understand the path from signup to value. Without this, the product feels abstract and the CTA feels risky. |
| **Outcome-focused feature copy** | Changed feature titles from capability-based ("AI-Powered Correlation") to outcome-based ("Cut triage time by 90%") | Users buy outcomes, not technology. "Cut triage time by 90%" answers "what's in it for me?" while "AI-Powered Correlation" does not. |
| **Added metrics bar** | 4 KPIs (90% faster triage, 70% fewer false positives, 35% lower MTTR, 50+ SOC teams) | Social proof and concrete numbers build credibility immediately below the hero. Visitors scanning the page see proof of impact before reading details. |
| **Added integrations marquee** | 24 security tool logos with infinite scroll animation | Reduces the #1 objection ("does it work with my tools?") without requiring the visitor to click into a separate page. |
| **Conversion funnel structure** | Reorganized sections: Hero → Metrics → Problem → How It Works → Integrations → Capabilities → Testimonials → FAQ → Final CTA | Follows the awareness → interest → action framework. Each section builds on the previous one, guiding the visitor toward signup with decreasing friction. |
| **Trust signals in final CTA** | Added "14-day free trial", "No credit card", "SOC 2 compliant", "Live in 30 minutes" | Addresses the four most common objections at the point of conversion: cost, commitment, security, and time-to-value. |
| **Footer with compliance badges** | SOC 2 Type II, ISO 27001, GDPR badges + copyright | Enterprise buyers check for compliance before evaluating features. Visible badges reduce procurement friction. |

### Configuration Changes

| Change | What was done | Why |
|---|---|---|
| **NODE_ENV enum expansion** | Added "staging" and "uat" to the allowed NODE_ENV values | Config validation was rejecting valid environment values, causing staging deployments to crash on startup. |
| **AI backend default** | Set default AI backend to "bedrock" with Mistral model | AWS Bedrock is the most cost-effective option for the current scale. Mistral provides strong performance at lower cost than Claude/GPT-4. |
| **OAuth optional fields** | Made Google/GitHub OAuth credentials optional in config schema | OAuth is not required for basic operation. Making these required would break deployments that don't need social login. |
