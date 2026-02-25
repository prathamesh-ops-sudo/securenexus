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
