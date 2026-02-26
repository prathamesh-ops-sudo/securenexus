# IAM Policies — Least-Privilege per Subsystem

This document defines the minimum IAM permissions required by each SecureNexus subsystem. On EKS, these policies are attached to IAM roles assumed via IRSA (IAM Roles for Service Accounts). The pod's ServiceAccount is annotated with the role ARN, and the AWS SDK credential chain picks up temporary credentials automatically — no static keys required.

## Credential Model

SecureNexus uses the AWS SDK default credential chain. On EKS the chain resolves in this order:

1. Environment variables (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY) — deprecated, local dev only
2. Web identity token (IRSA) — the preferred production path
3. EC2 instance metadata / ECS task role — fallback for non-EKS compute

When IRSA is configured the SDK never reaches step 1 or 3.

## Trust Policy (shared across all roles)

Each role uses the same OIDC trust policy, scoped to the namespace and service account.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::<ACCOUNT_ID>:oidc-provider/oidc.eks.<REGION>.amazonaws.com/id/<OIDC_ID>"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "oidc.eks.<REGION>.amazonaws.com/id/<OIDC_ID>:sub": "system:serviceaccount:<NAMESPACE>:securenexus",
          "oidc.eks.<REGION>.amazonaws.com/id/<OIDC_ID>:aud": "sts.amazonaws.com"
        }
      }
    }
  ]
}
```

Replace `<ACCOUNT_ID>`, `<REGION>`, `<OIDC_ID>`, and `<NAMESPACE>` (staging / uat / production) with actual values.

## S3 — Report and Evidence Storage

Used by: `server/s3.ts` (upload, download, delete, list)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3ReadWrite",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::<BUCKET_NAME>",
        "arn:aws:s3:::<BUCKET_NAME>/*"
      ]
    }
  ]
}
```

Scope: Read/write to the single SecureNexus bucket. No cross-bucket access, no admin actions (CreateBucket, DeleteBucket, PutBucketPolicy).

## Bedrock — AI Model Invocation

Used by: `server/ai.ts` (alert triage, correlation, narrative generation)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "BedrockInvoke",
      "Effect": "Allow",
      "Action": [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream"
      ],
      "Resource": [
        "arn:aws:bedrock:*::foundation-model/anthropic.claude-*",
        "arn:aws:bedrock:*::foundation-model/meta.llama*",
        "arn:aws:bedrock:*::foundation-model/amazon.titan-*"
      ]
    }
  ]
}
```

Scope: Invoke only, scoped to specific model families. No model management, no custom model training.

## SageMaker — Custom Model Inference

Used by: `server/ai.ts` (optional SageMaker-backed triage)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SageMakerInvoke",
      "Effect": "Allow",
      "Action": [
        "sagemaker:InvokeEndpoint"
      ],
      "Resource": "arn:aws:sagemaker:<REGION>:<ACCOUNT_ID>:endpoint/<ENDPOINT_NAME>"
    }
  ]
}
```

Scope: Invoke a single named endpoint. No endpoint creation, model deployment, or training.

## GuardDuty — Threat Detection Findings

Used by: `server/connector-engine.ts` (GuardDuty connector)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "GuardDutyReadOnly",
      "Effect": "Allow",
      "Action": [
        "guardduty:ListDetectors",
        "guardduty:ListFindings",
        "guardduty:GetFindings"
      ],
      "Resource": "*"
    }
  ]
}
```

Scope: Read-only. No detector creation, no finding archival, no IP set management.

## STS — Identity Verification

Used by: AWS SDK credential chain (automatic)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "STSCallerIdentity",
      "Effect": "Allow",
      "Action": "sts:GetCallerIdentity",
      "Resource": "*"
    }
  ]
}
```

Scope: Read-only identity verification for health checks.

## Secrets Manager — Runtime Config

Used by: CI/CD pipeline (secret sync to K8s secrets)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SecretsRead",
      "Effect": "Allow",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": [
        "arn:aws:secretsmanager:<REGION>:<ACCOUNT_ID>:secret:securenexus/*"
      ]
    }
  ]
}
```

Scope: Read-only, scoped to the securenexus/* prefix. Pods do not read Secrets Manager at runtime — secrets are synced to K8s secrets by CI/CD.

## Composite Role

In practice each environment uses a single IAM role with all the above policies attached. The role name follows the pattern `securenexus-<env>` (e.g. `securenexus-staging`, `securenexus-production`). The K8s ServiceAccount annotation references this role:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: securenexus
  namespace: staging
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::<ACCOUNT_ID>:role/securenexus-staging
```

See `k8s/base/service-account.yml` for the full manifest.

## Migration from Static Keys

1. Create the IAM role with the policies above
2. Enable the EKS OIDC provider (`eksctl utils associate-iam-oidc-provider`)
3. Annotate the K8s ServiceAccount (see `k8s/base/service-account.yml`)
4. Remove `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` from Secrets Manager
5. Redeploy — the SDK will automatically use IRSA
6. Deactivate and delete the old static access key from IAM
