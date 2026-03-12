/**
 * Auto-Remediation Engine
 * Executes remediation playbooks for cloud misconfigurations
 * Supports AWS, Azure, GCP with approval workflow integration
 */

import {
  S3Client,
  PutPublicAccessBlockCommand,
  PutBucketEncryptionCommand,
  PutBucketVersioningCommand,
} from "@aws-sdk/client-s3";

import { EC2Client, RevokeSecurityGroupIngressCommand } from "@aws-sdk/client-ec2";

import { IAMClient, DetachUserPolicyCommand } from "@aws-sdk/client-iam";

import type { AwsConnectorConfig } from "./aws";

export interface RemediationPlaybook {
  id: string;
  ruleId: string;
  name: string;
  description: string;
  provider: "aws" | "azure" | "gcp";
  resourceType: string;
  actions: RemediationAction[];
  requiresApproval: boolean;
  riskLevel: "safe" | "moderate" | "dangerous";
  estimatedImpact: string;
}

export interface RemediationAction {
  step: number;
  action: string;
  description: string;
  parameters: Record<string, unknown>;
  rollbackAction?: string;
}

export interface RemediationResult {
  playbook: string;
  ruleId: string;
  resourceId: string;
  status: "success" | "failed" | "partial" | "skipped";
  actionsExecuted: number;
  actionsTotal: number;
  error?: string;
  executedAt: Date;
  details: Record<string, unknown>;
}

/** Built-in remediation playbooks for common misconfigurations */
const PLAYBOOKS: RemediationPlaybook[] = [
  {
    id: "aws-s3-block-public",
    ruleId: "AWS-S3-001",
    name: "Block S3 Public Access",
    description: "Enable all four S3 Block Public Access settings on the bucket",
    provider: "aws",
    resourceType: "aws:s3:bucket",
    actions: [
      {
        step: 1,
        action: "PutPublicAccessBlock",
        description: "Enable BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls, RestrictPublicBuckets",
        parameters: {
          BlockPublicAcls: true,
          BlockPublicPolicy: true,
          IgnorePublicAcls: true,
          RestrictPublicBuckets: true,
        },
        rollbackAction: "Remove public access block configuration",
      },
    ],
    requiresApproval: false,
    riskLevel: "safe",
    estimatedImpact:
      "Applications relying on public bucket access will be blocked. Verify no legitimate public access is needed.",
  },
  {
    id: "aws-s3-enable-encryption",
    ruleId: "AWS-S3-002",
    name: "Enable S3 Default Encryption",
    description: "Enable AES-256 server-side encryption as the default for the bucket",
    provider: "aws",
    resourceType: "aws:s3:bucket",
    actions: [
      {
        step: 1,
        action: "PutBucketEncryption",
        description: "Set default encryption to AES-256 (SSE-S3)",
        parameters: { algorithm: "AES256" },
      },
    ],
    requiresApproval: false,
    riskLevel: "safe",
    estimatedImpact: "New objects will be encrypted by default. Existing unencrypted objects remain unchanged.",
  },
  {
    id: "aws-s3-enable-versioning",
    ruleId: "AWS-S3-003",
    name: "Enable S3 Versioning",
    description: "Enable versioning on the S3 bucket to protect against accidental deletion",
    provider: "aws",
    resourceType: "aws:s3:bucket",
    actions: [
      {
        step: 1,
        action: "PutBucketVersioning",
        description: "Enable bucket versioning",
        parameters: { status: "Enabled" },
      },
    ],
    requiresApproval: false,
    riskLevel: "safe",
    estimatedImpact: "Storage costs may increase as all object versions are retained. Configure lifecycle rules.",
  },
  {
    id: "aws-sg-revoke-ssh",
    ruleId: "AWS-EC2-002",
    name: "Revoke Unrestricted SSH Access",
    description: "Remove the 0.0.0.0/0 ingress rule for port 22 from the security group",
    provider: "aws",
    resourceType: "aws:ec2:security-group",
    actions: [
      {
        step: 1,
        action: "RevokeSecurityGroupIngress",
        description: "Remove inbound rule allowing SSH (port 22) from 0.0.0.0/0",
        parameters: { port: 22, protocol: "tcp", cidr: "0.0.0.0/0" },
        rollbackAction: "Re-add SSH rule with restricted IP range",
      },
    ],
    requiresApproval: true,
    riskLevel: "moderate",
    estimatedImpact:
      "SSH access via public IP will be blocked. Ensure alternative access method (SSM, bastion) is available.",
  },
  {
    id: "aws-sg-revoke-rdp",
    ruleId: "AWS-EC2-003",
    name: "Revoke Unrestricted RDP Access",
    description: "Remove the 0.0.0.0/0 ingress rule for port 3389 from the security group",
    provider: "aws",
    resourceType: "aws:ec2:security-group",
    actions: [
      {
        step: 1,
        action: "RevokeSecurityGroupIngress",
        description: "Remove inbound rule allowing RDP (port 3389) from 0.0.0.0/0",
        parameters: { port: 3389, protocol: "tcp", cidr: "0.0.0.0/0" },
        rollbackAction: "Re-add RDP rule with restricted IP range",
      },
    ],
    requiresApproval: true,
    riskLevel: "moderate",
    estimatedImpact: "RDP access via public IP will be blocked. Use VPN or AWS Client VPN for remote desktop.",
  },
  {
    id: "aws-iam-detach-admin",
    ruleId: "AWS-IAM-003",
    name: "Detach AdministratorAccess Policy",
    description: "Remove the AdministratorAccess policy from the IAM user",
    provider: "aws",
    resourceType: "aws:iam:user",
    actions: [
      {
        step: 1,
        action: "DetachUserPolicy",
        description: "Detach arn:aws:iam::aws:policy/AdministratorAccess from the user",
        parameters: { policyArn: "arn:aws:iam::aws:policy/AdministratorAccess" },
        rollbackAction: "Re-attach AdministratorAccess policy",
      },
    ],
    requiresApproval: true,
    riskLevel: "dangerous",
    estimatedImpact: "User will lose all administrative access. Ensure replacement permissions are configured first.",
  },
];

export class RemediationEngine {
  /** Get available playbooks for a finding */
  getPlaybooks(ruleId: string): RemediationPlaybook[] {
    return PLAYBOOKS.filter((p) => p.ruleId === ruleId);
  }

  /** Get all available playbooks */
  getAllPlaybooks(): RemediationPlaybook[] {
    return [...PLAYBOOKS];
  }

  /** Execute a remediation playbook on a specific resource */
  async executePlaybook(
    playbookId: string,
    resourceId: string,
    config: AwsConnectorConfig,
  ): Promise<RemediationResult> {
    const playbook = PLAYBOOKS.find((p) => p.id === playbookId);
    if (!playbook) {
      return {
        playbook: playbookId,
        ruleId: "unknown",
        resourceId,
        status: "failed",
        actionsExecuted: 0,
        actionsTotal: 0,
        error: `Playbook '${playbookId}' not found`,
        executedAt: new Date(),
        details: {},
      };
    }

    if (playbook.provider !== "aws") {
      return {
        playbook: playbookId,
        ruleId: playbook.ruleId,
        resourceId,
        status: "skipped",
        actionsExecuted: 0,
        actionsTotal: playbook.actions.length,
        error: `Remediation for ${playbook.provider} requires provider-specific credentials`,
        executedAt: new Date(),
        details: { provider: playbook.provider },
      };
    }

    const credentials =
      config.accessKeyId && config.secretAccessKey
        ? { accessKeyId: config.accessKeyId, secretAccessKey: config.secretAccessKey }
        : undefined;

    const region = extractRegionFromArn(resourceId) || config.regions[0] || "us-east-1";
    let actionsExecuted = 0;
    const details: Record<string, unknown> = {};

    try {
      for (const action of playbook.actions) {
        await this.executeAction(action, resourceId, region, credentials);
        actionsExecuted++;
        details[`step_${action.step}`] = { status: "success", action: action.action };
      }

      return {
        playbook: playbookId,
        ruleId: playbook.ruleId,
        resourceId,
        status: "success",
        actionsExecuted,
        actionsTotal: playbook.actions.length,
        executedAt: new Date(),
        details,
      };
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : "Unknown error";
      return {
        playbook: playbookId,
        ruleId: playbook.ruleId,
        resourceId,
        status: actionsExecuted > 0 ? "partial" : "failed",
        actionsExecuted,
        actionsTotal: playbook.actions.length,
        error: errorMessage,
        executedAt: new Date(),
        details,
      };
    }
  }

  /** Execute a single remediation action */
  private async executeAction(
    action: RemediationAction,
    resourceId: string,
    region: string,
    credentials?: { accessKeyId: string; secretAccessKey: string },
  ): Promise<void> {
    const clientConfig = { region, ...(credentials ? { credentials } : {}) };

    switch (action.action) {
      case "PutPublicAccessBlock": {
        const bucketName = extractBucketName(resourceId);
        if (!bucketName) throw new Error(`Cannot extract bucket name from ${resourceId}`);
        const s3 = new S3Client(clientConfig);
        await s3.send(
          new PutPublicAccessBlockCommand({
            Bucket: bucketName,
            PublicAccessBlockConfiguration: {
              BlockPublicAcls: true,
              BlockPublicPolicy: true,
              IgnorePublicAcls: true,
              RestrictPublicBuckets: true,
            },
          }),
        );
        break;
      }

      case "PutBucketEncryption": {
        const bucketName = extractBucketName(resourceId);
        if (!bucketName) throw new Error(`Cannot extract bucket name from ${resourceId}`);
        const s3 = new S3Client(clientConfig);
        await s3.send(
          new PutBucketEncryptionCommand({
            Bucket: bucketName,
            ServerSideEncryptionConfiguration: {
              Rules: [
                {
                  ApplyServerSideEncryptionByDefault: {
                    SSEAlgorithm: "AES256",
                  },
                },
              ],
            },
          }),
        );
        break;
      }

      case "PutBucketVersioning": {
        const bucketName = extractBucketName(resourceId);
        if (!bucketName) throw new Error(`Cannot extract bucket name from ${resourceId}`);
        const s3 = new S3Client(clientConfig);
        await s3.send(
          new PutBucketVersioningCommand({
            Bucket: bucketName,
            VersioningConfiguration: { Status: "Enabled" },
          }),
        );
        break;
      }

      case "RevokeSecurityGroupIngress": {
        const sgId = extractSecurityGroupId(resourceId);
        if (!sgId) throw new Error(`Cannot extract security group ID from ${resourceId}`);
        const ec2 = new EC2Client(clientConfig);
        const params = action.parameters;
        await ec2.send(
          new RevokeSecurityGroupIngressCommand({
            GroupId: sgId,
            IpPermissions: [
              {
                IpProtocol: (params.protocol as string) || "tcp",
                FromPort: (params.port as number) || 22,
                ToPort: (params.port as number) || 22,
                IpRanges: [{ CidrIp: (params.cidr as string) || "0.0.0.0/0" }],
              },
            ],
          }),
        );
        break;
      }

      case "DetachUserPolicy": {
        const userName = extractUserName(resourceId);
        if (!userName) throw new Error(`Cannot extract user name from ${resourceId}`);
        const iam = new IAMClient({ ...clientConfig, region: "us-east-1" });
        await iam.send(
          new DetachUserPolicyCommand({
            UserName: userName,
            PolicyArn: (action.parameters.policyArn as string) || "arn:aws:iam::aws:policy/AdministratorAccess",
          }),
        );
        break;
      }

      default:
        throw new Error(`Unknown remediation action: ${action.action}`);
    }
  }
}

// Helper functions

function extractBucketName(resourceId: string): string | null {
  // arn:aws:s3:::bucket-name
  const match = resourceId.match(/arn:aws:s3:::(.+)/);
  return match ? match[1] : null;
}

function extractSecurityGroupId(resourceId: string): string | null {
  // arn:aws:ec2:region::security-group/sg-xxxxx
  const match = resourceId.match(/security-group\/(sg-[a-z0-9]+)/);
  return match ? match[1] : null;
}

function extractUserName(resourceId: string): string | null {
  // arn:aws:iam::account:user/username
  const match = resourceId.match(/user\/(.+)/);
  return match ? match[1] : null;
}

function extractRegionFromArn(arn: string): string | null {
  // arn:aws:service:region:account:...
  const parts = arn.split(":");
  return parts.length >= 4 && parts[3] ? parts[3] : null;
}
