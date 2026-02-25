# SecureNexus Multi-Region Backup/Restore Strategy

## Recovery Objectives

| Metric | Target | Justification |
|--------|--------|---------------|
| **RPO (Recovery Point Objective)** | 1 hour | Automated RDS snapshots every hour + WAL archiving; S3 versioning provides near-zero RPO for object data |
| **RTO (Recovery Time Objective)** | 30 minutes | RDS point-in-time restore ~15 min, EKS redeployment ~10 min, DNS failover ~5 min |

---

## Infrastructure Inventory

| Component | Service | Region | Backup Mechanism |
|-----------|---------|--------|------------------|
| Primary Database | RDS PostgreSQL (`securenexus-db`) | us-east-1 | Automated snapshots + cross-region replication |
| Object Storage | S3 (`securenexus-platform-557845624595`) | us-east-1 | Versioning + cross-region replication |
| Application | EKS (staging + production) | us-east-1 | Container images in ECR, manifests in Git |
| Secrets | AWS Secrets Manager (`securenexus/secrets`) | us-east-1 | Multi-region replication |
| Monitoring | Grafana on EKS | us-east-1 | Config stored in Git, dashboards exportable |

---

## RDS Backup Strategy

### Automated Backups
- **Retention period**: 35 days (maximum)
- **Backup window**: 03:00-04:00 UTC (low-traffic period)
- **Type**: Continuous WAL archiving with periodic full snapshots
- **Point-in-time recovery**: Granularity down to 1 second within retention window

### Cross-Region Read Replica
- **Target region**: us-west-2
- **Replication**: Asynchronous (typically <1s lag)
- **Promotion time**: ~5 minutes to promote replica to standalone primary
- **Purpose**: Disaster recovery failover + read scaling

### Manual Snapshots
- **Frequency**: Before every schema migration and major release
- **Naming convention**: `securenexus-db-YYYYMMDD-HHmm-{reason}`
- **Retention**: Indefinite for migration snapshots; 90 days for release snapshots
- **Cross-region copy**: All manual snapshots copied to us-west-2

### Setup Commands
```bash
# Enable automated backups (35-day retention)
aws rds modify-db-instance \
  --db-instance-identifier securenexus-db \
  --backup-retention-period 35 \
  --preferred-backup-window "03:00-04:00" \
  --apply-immediately

# Create cross-region read replica
aws rds create-db-instance-read-replica \
  --db-instance-identifier securenexus-db-replica-west \
  --source-db-instance-identifier arn:aws:rds:us-east-1:557845624595:db:securenexus-db \
  --region us-west-2 \
  --db-instance-class db.t3.medium

# Take manual snapshot before migration
aws rds create-db-snapshot \
  --db-instance-identifier securenexus-db \
  --db-snapshot-identifier "securenexus-db-$(date +%Y%m%d-%H%M)-pre-migration"

# Copy snapshot to DR region
aws rds copy-db-snapshot \
  --source-db-snapshot-identifier "securenexus-db-SNAPSHOT_ID" \
  --target-db-snapshot-identifier "securenexus-db-SNAPSHOT_ID-dr" \
  --region us-west-2
```

---

## S3 Backup Strategy

### Versioning
- **Status**: Enabled on `securenexus-platform-557845624595`
- **MFA Delete**: Enabled for production bucket
- **Lifecycle rules**:
  - Non-current versions transition to Glacier after 30 days
  - Non-current versions expire after 365 days

### Cross-Region Replication (CRR)
- **Source**: `securenexus-platform-557845624595` (us-east-1)
- **Destination**: `securenexus-platform-dr-557845624595` (us-west-2)
- **Replication scope**: Entire bucket
- **Replication time**: Typically <15 minutes (S3 Replication Time Control for SLA)

### Setup Commands
```bash
# Enable versioning
aws s3api put-bucket-versioning \
  --bucket securenexus-platform-557845624595 \
  --versioning-configuration Status=Enabled

# Create DR bucket
aws s3api create-bucket \
  --bucket securenexus-platform-dr-557845624595 \
  --region us-west-2 \
  --create-bucket-configuration LocationConstraint=us-west-2

# Enable versioning on DR bucket (required for CRR)
aws s3api put-bucket-versioning \
  --bucket securenexus-platform-dr-557845624595 \
  --versioning-configuration Status=Enabled
```

---

## Secrets Manager Replication

```bash
# Replicate secrets to DR region
aws secretsmanager replicate-secret-to-regions \
  --secret-id securenexus/secrets \
  --add-replica-regions Region=us-west-2
```

---

## Disaster Recovery Runbooks

### Runbook 1: RDS Failover (Primary DB Failure)

**Trigger**: Primary RDS instance unavailable or degraded performance >5 minutes

| Step | Action | Expected Duration |
|------|--------|-------------------|
| 1 | Verify primary DB is truly unavailable (check CloudWatch, attempt connection) | 2 min |
| 2 | Promote cross-region read replica to standalone: `aws rds promote-read-replica --db-instance-identifier securenexus-db-replica-west --region us-west-2` | 5 min |
| 3 | Update Secrets Manager with new DB endpoint: `aws secretsmanager update-secret --secret-id securenexus/secrets --region us-west-2` | 1 min |
| 4 | Update EKS deployment to use new DB endpoint (or deploy DR EKS cluster) | 5 min |
| 5 | Update DNS to point to DR region load balancer | 2 min |
| 6 | Verify application health via `/api/health` endpoint | 2 min |
| 7 | Notify stakeholders via incident channel | 1 min |

**Total estimated RTO**: ~18 minutes

### Runbook 2: Full Region Failure (us-east-1 outage)

**Trigger**: AWS us-east-1 region unavailable

| Step | Action | Expected Duration |
|------|--------|-------------------|
| 1 | Confirm region-level outage via AWS Health Dashboard | 2 min |
| 2 | Promote RDS read replica in us-west-2 | 5 min |
| 3 | Deploy EKS cluster in us-west-2 using stored manifests from Git | 15 min |
| 4 | Pull latest container images from ECR (cross-region replicated) | 3 min |
| 5 | Apply K8s manifests with DR-region secrets | 5 min |
| 6 | Update Route 53 DNS failover records to us-west-2 load balancer | 2 min |
| 7 | Verify all services healthy | 3 min |
| 8 | Run smoke tests against DR deployment | 5 min |

**Total estimated RTO**: ~40 minutes

### Runbook 3: Data Corruption Recovery

**Trigger**: Data integrity issue detected (bad migration, accidental deletion, etc.)

| Step | Action | Expected Duration |
|------|--------|-------------------|
| 1 | Identify corruption scope and timestamp of last known good state | 5 min |
| 2 | Take snapshot of current (corrupted) state for forensics | 3 min |
| 3 | Restore RDS to point-in-time before corruption: `aws rds restore-db-instance-to-point-in-time --source-db-instance-identifier securenexus-db --target-db-instance-identifier securenexus-db-restored --restore-time "YYYY-MM-DDTHH:MM:SSZ"` | 15 min |
| 4 | Verify restored data integrity | 5 min |
| 5 | Update application to point to restored instance | 3 min |
| 6 | Run schema validation: `npm run db:push --dry-run` | 2 min |
| 7 | Verify application functionality | 5 min |

**Total estimated RTO**: ~38 minutes

### Runbook 4: S3 Object Recovery

**Trigger**: Critical files deleted or corrupted in S3

| Step | Action | Expected Duration |
|------|--------|-------------------|
| 1 | Identify affected objects and versions | 3 min |
| 2 | Restore from version history: `aws s3api get-object --bucket securenexus-platform-557845624595 --key {key} --version-id {version-id} {output}` | 2 min |
| 3 | Or restore from CRR bucket: `aws s3 sync s3://securenexus-platform-dr-557845624595/{prefix} s3://securenexus-platform-557845624595/{prefix}` | 5 min |
| 4 | Verify restored objects | 2 min |

**Total estimated RTO**: ~12 minutes

---

## Backup/Restore Drill Schedule

| Drill | Frequency | Last Run | Next Scheduled | Owner |
|-------|-----------|----------|----------------|-------|
| RDS point-in-time restore | Monthly | - | First drill after deployment | Platform Team |
| Cross-region failover | Quarterly | - | First drill after DR setup | Platform Team |
| S3 object recovery | Monthly | - | First drill after deployment | Platform Team |
| Full region failover | Semi-annually | - | First drill after DR setup | Platform Team + SRE |
| Data corruption recovery | Quarterly | - | First drill after deployment | Platform Team |

### Drill Execution via API

SecureNexus provides a DR drill execution API for automated testing:

```bash
# List available runbooks
curl -s https://nexus.aricatech.xyz/api/v1/dr/runbooks \
  -H "Cookie: connect.sid=SESSION_ID"

# Execute a dry-run drill
curl -s -X POST https://nexus.aricatech.xyz/api/v1/dr/run-drill \
  -H "Content-Type: application/json" \
  -H "Cookie: connect.sid=SESSION_ID" \
  -d '{"runbookId": "RUNBOOK_ID", "dryRun": true}'
```

---

## Monitoring and Alerting

### CloudWatch Alarms

| Alarm | Condition | Action |
|-------|-----------|--------|
| RDS replication lag | ReplicaLag > 60 seconds for 5 min | SNS notification to ops team |
| RDS free storage | FreeStorageSpace < 5 GB | SNS notification + auto-scaling |
| S3 replication pending | ReplicationLatency > 900 seconds | SNS notification to ops team |
| Backup completion | BackupRetentionPeriodStorageAllocated changes | CloudWatch log |

### Grafana Dashboard Panels
- RDS replication lag (real-time)
- Backup completion status
- S3 replication metrics
- DR drill execution history (from `/api/v1/dr/run-drill` results)
- SLO compliance for backup/restore operations

---

## Multi-Region Architecture Diagram

```
us-east-1 (Primary)                    us-west-2 (DR)
+------------------+                   +------------------+
| EKS Cluster      |                   | EKS Cluster (DR) |
| - staging        |                   | - standby        |
| - production     |                   |                  |
+--------+---------+                   +--------+---------+
         |                                      |
+--------+---------+    Async Repl    +--------+---------+
| RDS PostgreSQL   |  ------------->  | RDS Read Replica |
| (Primary)        |                  | (Promotable)     |
+--------+---------+                  +--------+---------+
         |                                      |
+--------+---------+    CRR           +--------+---------+
| S3 Bucket        |  ------------->  | S3 DR Bucket     |
| (Versioned)      |                  | (Versioned)      |
+------------------+                  +------------------+
         |                                      |
+--------+---------+    Replication   +--------+---------+
| Secrets Manager  |  ------------->  | Secrets Manager  |
+------------------+                  +------------------+
         |                                      |
+--------+---------+                  +--------+---------+
| ECR Images       |  Cross-region    | ECR Images       |
|                  |  replication     | (replicated)     |
+------------------+                  +------------------+
```

---

## Compliance Notes

- All backups encrypted at rest using AWS KMS (AES-256)
- Cross-region replication uses TLS in transit
- Backup access restricted to Platform Team IAM role
- Audit trail for all backup/restore operations via CloudTrail
- Retention policies comply with SOC 2 Type II requirements
