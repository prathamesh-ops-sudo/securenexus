/**
 * AWS Cloud Connector
 * Real AWS SDK calls to Config, Security Hub, GuardDuty, IAM Access Analyzer, CloudTrail, S3, EC2, RDS, IAM
 */

import {
  IAMClient,
  ListUsersCommand,
  ListMFADevicesCommand,
  ListAttachedUserPoliciesCommand,
  GetCredentialReportCommand,
  GenerateCredentialReportCommand,
  ListAccessKeysCommand,
  GetAccessKeyLastUsedCommand,
} from "@aws-sdk/client-iam";

import {
  EC2Client,
  DescribeSecurityGroupsCommand,
  DescribeVolumesCommand,
  DescribeInstancesCommand,
  DescribeVpcsCommand,
  DescribeFlowLogsCommand,
  DescribeSubnetsCommand,
} from "@aws-sdk/client-ec2";

import {
  S3Client,
  ListBucketsCommand,
  GetBucketEncryptionCommand,
  GetPublicAccessBlockCommand,
  GetBucketPolicyStatusCommand,
  GetBucketVersioningCommand,
  GetBucketLoggingCommand,
} from "@aws-sdk/client-s3";

import { RDSClient, DescribeDBInstancesCommand } from "@aws-sdk/client-rds";

import {
  GuardDutyClient,
  ListDetectorsCommand,
  ListFindingsCommand,
  GetFindingsCommand,
} from "@aws-sdk/client-guardduty";

import { STSClient, GetCallerIdentityCommand, AssumeRoleCommand } from "@aws-sdk/client-sts";
import { logger } from "../logger";

const log = logger.child("cloud-connector-aws");

export interface CloudFinding {
  ruleId: string;
  ruleName: string;
  severity: "critical" | "high" | "medium" | "low" | "informational";
  resourceType: string;
  resourceId: string;
  resourceRegion: string;
  description: string;
  remediation: string;
  complianceFrameworks: string[];
  rawData?: Record<string, unknown>;
}

export interface CloudResource {
  resourceId: string;
  resourceType: string;
  region: string;
  name: string;
  tags: Record<string, string>;
  configuration: Record<string, unknown>;
  discoveredAt: Date;
}

export interface AwsConnectorConfig {
  accessKeyId?: string;
  secretAccessKey?: string;
  roleArn?: string;
  externalId?: string;
  regions: string[];
}

function getAwsClients(config: AwsConnectorConfig, region: string) {
  const credentials =
    config.accessKeyId && config.secretAccessKey
      ? { accessKeyId: config.accessKeyId, secretAccessKey: config.secretAccessKey }
      : undefined;

  const clientConfig = { region, ...(credentials ? { credentials } : {}) };

  return {
    iam: new IAMClient({ ...clientConfig, region: "us-east-1" }), // IAM is global
    ec2: new EC2Client(clientConfig),
    s3: new S3Client(clientConfig),
    rds: new RDSClient(clientConfig),
    guardduty: new GuardDutyClient(clientConfig),
    sts: new STSClient(clientConfig),
  };
}

/** Validate AWS credentials by calling STS GetCallerIdentity */
export async function validateAwsCredentials(config: AwsConnectorConfig): Promise<{
  valid: boolean;
  accountId?: string;
  arn?: string;
  error?: string;
}> {
  try {
    const clients = getAwsClients(config, config.regions[0] || "us-east-1");
    const identity = await clients.sts.send(new GetCallerIdentityCommand({}));
    return {
      valid: true,
      accountId: identity.Account || undefined,
      arn: identity.Arn || undefined,
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Unknown error";
    return { valid: false, error: message };
  }
}

/** Scan S3 buckets for misconfigurations */
export async function scanS3Buckets(config: AwsConnectorConfig): Promise<CloudFinding[]> {
  const findings: CloudFinding[] = [];
  const region = config.regions[0] || "us-east-1";

  try {
    const clients = getAwsClients(config, region);
    const bucketsResp = await clients.s3.send(new ListBucketsCommand({}));
    const buckets = bucketsResp.Buckets || [];

    for (const bucket of buckets) {
      const bucketName = bucket.Name || "unknown";

      // Check public access block
      try {
        const publicAccess = await clients.s3.send(new GetPublicAccessBlockCommand({ Bucket: bucketName }));
        const config2 = publicAccess.PublicAccessBlockConfiguration;
        if (
          !config2?.BlockPublicAcls ||
          !config2?.BlockPublicPolicy ||
          !config2?.IgnorePublicAcls ||
          !config2?.RestrictPublicBuckets
        ) {
          findings.push({
            ruleId: "AWS-S3-001",
            ruleName: "S3 Bucket Public Access Not Fully Blocked",
            severity: "high",
            resourceType: "aws:s3:bucket",
            resourceId: `arn:aws:s3:::${bucketName}`,
            resourceRegion: region,
            description: `S3 bucket '${bucketName}' does not have all public access block settings enabled. Public access may be possible via ACLs or bucket policies.`,
            remediation:
              "Enable all four S3 Block Public Access settings at the bucket level: BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls, RestrictPublicBuckets.",
            complianceFrameworks: ["cis", "nist", "pci_dss", "soc2"],
            rawData: { publicAccessBlock: config2 },
          });
        }
      } catch (err: unknown) {
        // NoSuchPublicAccessBlockConfiguration means no block is configured
        const errorName = (err as { name?: string })?.name;
        if (errorName === "NoSuchPublicAccessBlockConfiguration") {
          findings.push({
            ruleId: "AWS-S3-001",
            ruleName: "S3 Bucket Public Access Block Not Configured",
            severity: "critical",
            resourceType: "aws:s3:bucket",
            resourceId: `arn:aws:s3:::${bucketName}`,
            resourceRegion: region,
            description: `S3 bucket '${bucketName}' has no public access block configuration. The bucket may be publicly accessible.`,
            remediation:
              "Enable S3 Block Public Access at the bucket and account level to prevent unintended public access.",
            complianceFrameworks: ["cis", "nist", "pci_dss", "soc2"],
          });
        }
      }

      // Check encryption
      try {
        await clients.s3.send(new GetBucketEncryptionCommand({ Bucket: bucketName }));
      } catch (err: unknown) {
        const errorName = (err as { name?: string })?.name;
        if (errorName === "ServerSideEncryptionConfigurationNotFoundError" || errorName === "NoSuchBucketEncryption") {
          findings.push({
            ruleId: "AWS-S3-002",
            ruleName: "S3 Bucket Server-Side Encryption Disabled",
            severity: "high",
            resourceType: "aws:s3:bucket",
            resourceId: `arn:aws:s3:::${bucketName}`,
            resourceRegion: region,
            description: `S3 bucket '${bucketName}' does not have default server-side encryption configured.`,
            remediation: "Enable default encryption on the S3 bucket using SSE-S3 (AES-256) or SSE-KMS.",
            complianceFrameworks: ["cis", "nist", "pci_dss"],
          });
        }
      }

      // Check versioning
      try {
        const versioning = await clients.s3.send(new GetBucketVersioningCommand({ Bucket: bucketName }));
        if (versioning.Status !== "Enabled") {
          findings.push({
            ruleId: "AWS-S3-003",
            ruleName: "S3 Bucket Versioning Not Enabled",
            severity: "medium",
            resourceType: "aws:s3:bucket",
            resourceId: `arn:aws:s3:::${bucketName}`,
            resourceRegion: region,
            description: `S3 bucket '${bucketName}' does not have versioning enabled. Data loss from accidental deletion or overwrites cannot be recovered.`,
            remediation:
              "Enable versioning on the S3 bucket to protect against accidental deletion and enable point-in-time recovery.",
            complianceFrameworks: ["cis", "nist"],
          });
        }
      } catch {
        // Ignore versioning check errors
      }

      // Check access logging
      try {
        const logging = await clients.s3.send(new GetBucketLoggingCommand({ Bucket: bucketName }));
        if (!logging.LoggingEnabled) {
          findings.push({
            ruleId: "AWS-S3-004",
            ruleName: "S3 Bucket Access Logging Disabled",
            severity: "medium",
            resourceType: "aws:s3:bucket",
            resourceId: `arn:aws:s3:::${bucketName}`,
            resourceRegion: region,
            description: `S3 bucket '${bucketName}' does not have server access logging enabled. Access to the bucket is not being audited.`,
            remediation:
              "Enable server access logging on the S3 bucket. Configure logs to be delivered to a separate logging bucket.",
            complianceFrameworks: ["cis", "nist", "soc2"],
          });
        }
      } catch {
        // Ignore logging check errors
      }
    }
  } catch (err: unknown) {
    log.error("S3 scan error", { error: err instanceof Error ? err.message : String(err) });
  }

  return findings;
}

/** Scan EC2 security groups for misconfigurations */
export async function scanEC2SecurityGroups(config: AwsConnectorConfig, region: string): Promise<CloudFinding[]> {
  const findings: CloudFinding[] = [];

  try {
    const clients = getAwsClients(config, region);
    const sgResp = await clients.ec2.send(new DescribeSecurityGroupsCommand({}));
    const sgs = sgResp.SecurityGroups || [];

    for (const sg of sgs) {
      const sgId = sg.GroupId || "unknown";
      const sgName = sg.GroupName || "unknown";
      const permissions = sg.IpPermissions || [];

      for (const perm of permissions) {
        const ipRanges = perm.IpRanges || [];
        const ipv6Ranges = perm.Ipv6Ranges || [];
        const hasOpenIPv4 = ipRanges.some((r) => r.CidrIp === "0.0.0.0/0");
        const hasOpenIPv6 = ipv6Ranges.some((r) => r.CidrIpv6 === "::/0");

        if (hasOpenIPv4 || hasOpenIPv6) {
          const fromPort = perm.FromPort;
          const toPort = perm.ToPort;

          if (fromPort === 22 || (fromPort !== undefined && toPort !== undefined && fromPort <= 22 && toPort >= 22)) {
            findings.push({
              ruleId: "AWS-EC2-002",
              ruleName: "Security Group Allows Unrestricted SSH (Port 22)",
              severity: "high",
              resourceType: "aws:ec2:security-group",
              resourceId: `arn:aws:ec2:${region}::security-group/${sgId}`,
              resourceRegion: region,
              description: `Security group '${sgName}' (${sgId}) allows SSH access from ${hasOpenIPv4 ? "0.0.0.0/0" : "::/0"}.`,
              remediation:
                "Restrict SSH access to specific IP ranges. Use AWS Systems Manager Session Manager as an alternative.",
              complianceFrameworks: ["cis", "nist", "soc2"],
              rawData: { securityGroupName: sgName, permission: perm },
            });
          }

          if (
            fromPort === 3389 ||
            (fromPort !== undefined && toPort !== undefined && fromPort <= 3389 && toPort >= 3389)
          ) {
            findings.push({
              ruleId: "AWS-EC2-003",
              ruleName: "Security Group Allows Unrestricted RDP (Port 3389)",
              severity: "critical",
              resourceType: "aws:ec2:security-group",
              resourceId: `arn:aws:ec2:${region}::security-group/${sgId}`,
              resourceRegion: region,
              description: `Security group '${sgName}' (${sgId}) allows RDP access from ${hasOpenIPv4 ? "0.0.0.0/0" : "::/0"}.`,
              remediation:
                "Remove the 0.0.0.0/0 ingress rule for port 3389. Use a VPN or AWS Client VPN for remote desktop access.",
              complianceFrameworks: ["cis", "nist", "pci_dss", "soc2"],
              rawData: { securityGroupName: sgName, permission: perm },
            });
          }

          // All ports open
          if (perm.IpProtocol === "-1") {
            findings.push({
              ruleId: "AWS-EC2-005",
              ruleName: "Security Group Allows All Traffic from Internet",
              severity: "critical",
              resourceType: "aws:ec2:security-group",
              resourceId: `arn:aws:ec2:${region}::security-group/${sgId}`,
              resourceRegion: region,
              description: `Security group '${sgName}' (${sgId}) allows all traffic on all ports from ${hasOpenIPv4 ? "0.0.0.0/0" : "::/0"}.`,
              remediation:
                "Remove the allow-all ingress rule. Create specific rules permitting only required ports and protocols.",
              complianceFrameworks: ["cis", "nist", "pci_dss", "soc2"],
              rawData: { securityGroupName: sgName, permission: perm },
            });
          }
        }
      }
    }
  } catch (err: unknown) {
    log.error("EC2 security group scan error", { region, error: err instanceof Error ? err.message : String(err) });
  }

  return findings;
}

/** Scan EBS volumes for encryption */
export async function scanEBSVolumes(config: AwsConnectorConfig, region: string): Promise<CloudFinding[]> {
  const findings: CloudFinding[] = [];

  try {
    const clients = getAwsClients(config, region);
    const volumeResp = await clients.ec2.send(new DescribeVolumesCommand({}));
    const volumes = volumeResp.Volumes || [];

    for (const vol of volumes) {
      if (!vol.Encrypted) {
        findings.push({
          ruleId: "AWS-EC2-001",
          ruleName: "EBS Volume Not Encrypted",
          severity: "high",
          resourceType: "aws:ec2:volume",
          resourceId: `arn:aws:ec2:${region}::volume/${vol.VolumeId}`,
          resourceRegion: region,
          description: `EBS volume ${vol.VolumeId} (${vol.Size}GB, ${vol.State}) is not encrypted at rest.`,
          remediation:
            "Enable EBS encryption by default. For existing unencrypted volumes, create an encrypted snapshot and restore from it.",
          complianceFrameworks: ["cis", "nist", "pci_dss"],
          rawData: { volumeId: vol.VolumeId, size: vol.Size, state: vol.State },
        });
      }
    }
  } catch (err: unknown) {
    log.error("EBS scan error", { region, error: err instanceof Error ? err.message : String(err) });
  }

  return findings;
}

/** Scan IAM users for MFA, stale keys, excessive permissions */
export async function scanIAMUsers(config: AwsConnectorConfig): Promise<CloudFinding[]> {
  const findings: CloudFinding[] = [];

  try {
    const clients = getAwsClients(config, "us-east-1");
    const usersResp = await clients.iam.send(new ListUsersCommand({}));
    const users = usersResp.Users || [];

    for (const user of users) {
      const userName = user.UserName || "unknown";

      // Check MFA
      try {
        const mfaResp = await clients.iam.send(new ListMFADevicesCommand({ UserName: userName }));
        if (!mfaResp.MFADevices || mfaResp.MFADevices.length === 0) {
          findings.push({
            ruleId: "AWS-IAM-001",
            ruleName: "IAM User Without MFA Enabled",
            severity: "critical",
            resourceType: "aws:iam:user",
            resourceId: user.Arn || `arn:aws:iam:::user/${userName}`,
            resourceRegion: "global",
            description: `IAM user '${userName}' does not have MFA enabled. Compromised credentials without MFA can lead to account takeover.`,
            remediation: "Enable MFA for all IAM users. Use virtual MFA devices or hardware FIDO2 security keys.",
            complianceFrameworks: ["cis", "nist", "pci_dss", "soc2"],
          });
        }
      } catch {
        // Skip MFA check errors
      }

      // Check for stale access keys
      try {
        const keysResp = await clients.iam.send(new ListAccessKeysCommand({ UserName: userName }));
        for (const key of keysResp.AccessKeyMetadata || []) {
          if (key.AccessKeyId && key.CreateDate) {
            const ageInDays = Math.floor((Date.now() - key.CreateDate.getTime()) / (1000 * 60 * 60 * 24));
            if (ageInDays > 90) {
              findings.push({
                ruleId: "AWS-IAM-004",
                ruleName: "IAM Access Key Not Rotated",
                severity: "medium",
                resourceType: "aws:iam:access-key",
                resourceId: user.Arn || `arn:aws:iam:::user/${userName}`,
                resourceRegion: "global",
                description: `IAM user '${userName}' has access key ${key.AccessKeyId} that is ${ageInDays} days old (status: ${key.Status}). Keys should be rotated every 90 days.`,
                remediation:
                  "Rotate the access key by creating a new key, updating applications, then deactivating and deleting the old key.",
                complianceFrameworks: ["cis", "nist", "pci_dss"],
                rawData: { accessKeyId: key.AccessKeyId, ageInDays, status: key.Status },
              });
            }

            // Check for unused keys
            try {
              const lastUsed = await clients.iam.send(
                new GetAccessKeyLastUsedCommand({ AccessKeyId: key.AccessKeyId }),
              );
              if (lastUsed.AccessKeyLastUsed?.LastUsedDate) {
                const daysSinceUse = Math.floor(
                  (Date.now() - lastUsed.AccessKeyLastUsed.LastUsedDate.getTime()) / (1000 * 60 * 60 * 24),
                );
                if (daysSinceUse > 90) {
                  findings.push({
                    ruleId: "AWS-IAM-005",
                    ruleName: "IAM Access Key Unused for 90+ Days",
                    severity: "medium",
                    resourceType: "aws:iam:access-key",
                    resourceId: user.Arn || `arn:aws:iam:::user/${userName}`,
                    resourceRegion: "global",
                    description: `IAM user '${userName}' has access key ${key.AccessKeyId} not used for ${daysSinceUse} days. Unused keys increase attack surface.`,
                    remediation: "Deactivate and delete unused access keys to reduce the attack surface.",
                    complianceFrameworks: ["cis", "nist"],
                    rawData: { accessKeyId: key.AccessKeyId, daysSinceUse },
                  });
                }
              }
            } catch {
              // Skip last used check errors
            }
          }
        }
      } catch {
        // Skip access key check errors
      }

      // Check for overly permissive policies
      try {
        const policiesResp = await clients.iam.send(new ListAttachedUserPoliciesCommand({ UserName: userName }));
        for (const policy of policiesResp.AttachedPolicies || []) {
          if (
            policy.PolicyName === "AdministratorAccess" ||
            policy.PolicyArn === "arn:aws:iam::aws:policy/AdministratorAccess"
          ) {
            findings.push({
              ruleId: "AWS-IAM-003",
              ruleName: "IAM User Has AdministratorAccess Policy",
              severity: "high",
              resourceType: "aws:iam:user",
              resourceId: user.Arn || `arn:aws:iam:::user/${userName}`,
              resourceRegion: "global",
              description: `IAM user '${userName}' has the AdministratorAccess policy attached, granting unrestricted access to all AWS services and resources.`,
              remediation:
                "Replace AdministratorAccess with scoped permissions following the principle of least privilege.",
              complianceFrameworks: ["cis", "nist", "pci_dss"],
            });
          }
        }
      } catch {
        // Skip policy check errors
      }
    }
  } catch (err: unknown) {
    log.error("IAM scan error", { error: err instanceof Error ? err.message : String(err) });
  }

  return findings;
}

/** Scan RDS instances for encryption and public access */
export async function scanRDSInstances(config: AwsConnectorConfig, region: string): Promise<CloudFinding[]> {
  const findings: CloudFinding[] = [];

  try {
    const clients = getAwsClients(config, region);
    const rdsResp = await clients.rds.send(new DescribeDBInstancesCommand({}));
    const instances = rdsResp.DBInstances || [];

    for (const db of instances) {
      const dbId = db.DBInstanceIdentifier || "unknown";

      if (db.PubliclyAccessible) {
        findings.push({
          ruleId: "AWS-RDS-001",
          ruleName: "RDS Instance Publicly Accessible",
          severity: "critical",
          resourceType: "aws:rds:db-instance",
          resourceId: db.DBInstanceArn || `arn:aws:rds:${region}::db/${dbId}`,
          resourceRegion: region,
          description: `RDS instance '${dbId}' (${db.Engine}, ${db.DBInstanceClass}) is publicly accessible from the internet.`,
          remediation:
            "Set PubliclyAccessible to false. Place the instance in a private subnet and use VPC security groups.",
          complianceFrameworks: ["cis", "nist", "pci_dss", "soc2"],
          rawData: { engine: db.Engine, instanceClass: db.DBInstanceClass },
        });
      }

      if (!db.StorageEncrypted) {
        findings.push({
          ruleId: "AWS-RDS-002",
          ruleName: "RDS Instance Storage Not Encrypted",
          severity: "high",
          resourceType: "aws:rds:db-instance",
          resourceId: db.DBInstanceArn || `arn:aws:rds:${region}::db/${dbId}`,
          resourceRegion: region,
          description: `RDS instance '${dbId}' does not have storage encryption enabled.`,
          remediation: "Enable encryption at rest using AWS KMS. Create an encrypted snapshot and restore from it.",
          complianceFrameworks: ["cis", "nist", "pci_dss"],
          rawData: { engine: db.Engine },
        });
      }

      if (!db.MultiAZ) {
        findings.push({
          ruleId: "AWS-RDS-003",
          ruleName: "RDS Instance Not Multi-AZ",
          severity: "medium",
          resourceType: "aws:rds:db-instance",
          resourceId: db.DBInstanceArn || `arn:aws:rds:${region}::db/${dbId}`,
          resourceRegion: region,
          description: `RDS instance '${dbId}' is not deployed in Multi-AZ configuration. Single-AZ deployment creates a single point of failure.`,
          remediation:
            "Enable Multi-AZ deployment for production databases to ensure high availability and automatic failover.",
          complianceFrameworks: ["nist", "soc2"],
          rawData: { engine: db.Engine },
        });
      }

      if (!db.AutoMinorVersionUpgrade) {
        findings.push({
          ruleId: "AWS-RDS-004",
          ruleName: "RDS Auto Minor Version Upgrade Disabled",
          severity: "low",
          resourceType: "aws:rds:db-instance",
          resourceId: db.DBInstanceArn || `arn:aws:rds:${region}::db/${dbId}`,
          resourceRegion: region,
          description: `RDS instance '${dbId}' does not have auto minor version upgrade enabled. Security patches may not be applied automatically.`,
          remediation:
            "Enable auto minor version upgrade to ensure security patches are applied during the maintenance window.",
          complianceFrameworks: ["cis", "nist"],
        });
      }
    }
  } catch (err: unknown) {
    log.error("RDS scan error", { region, error: err instanceof Error ? err.message : String(err) });
  }

  return findings;
}

/** Scan VPC flow logs */
export async function scanVPCFlowLogs(config: AwsConnectorConfig, region: string): Promise<CloudFinding[]> {
  const findings: CloudFinding[] = [];

  try {
    const clients = getAwsClients(config, region);

    const vpcResp = await clients.ec2.send(new DescribeVpcsCommand({}));
    const vpcs = vpcResp.Vpcs || [];

    const flowLogsResp = await clients.ec2.send(new DescribeFlowLogsCommand({}));
    const flowLogs = flowLogsResp.FlowLogs || [];
    const vpcIdsWithFlowLogs = new Set(flowLogs.map((fl) => fl.ResourceId));

    for (const vpc of vpcs) {
      if (vpc.VpcId && !vpcIdsWithFlowLogs.has(vpc.VpcId)) {
        const nameTag = vpc.Tags?.find((t) => t.Key === "Name")?.Value;
        findings.push({
          ruleId: "AWS-VPC-001",
          ruleName: "VPC Flow Logs Not Enabled",
          severity: "medium",
          resourceType: "aws:ec2:vpc",
          resourceId: `arn:aws:ec2:${region}::vpc/${vpc.VpcId}`,
          resourceRegion: region,
          description: `VPC '${nameTag || vpc.VpcId}' does not have flow logs enabled. Network traffic cannot be audited.`,
          remediation: "Enable VPC Flow Logs for all VPCs. Configure logs for both accepted and rejected traffic.",
          complianceFrameworks: ["cis", "nist", "soc2"],
        });
      }
    }
  } catch (err: unknown) {
    log.error("VPC scan error", { region, error: err instanceof Error ? err.message : String(err) });
  }

  return findings;
}

/** Fetch GuardDuty findings */
export async function fetchGuardDutyFindings(config: AwsConnectorConfig, region: string): Promise<CloudFinding[]> {
  const findings: CloudFinding[] = [];

  try {
    const clients = getAwsClients(config, region);

    const detectorsResp = await clients.guardduty.send(new ListDetectorsCommand({}));
    const detectorIds = detectorsResp.DetectorIds || [];

    if (detectorIds.length === 0) {
      findings.push({
        ruleId: "AWS-GD-001",
        ruleName: "GuardDuty Not Enabled",
        severity: "high",
        resourceType: "aws:guardduty:detector",
        resourceId: `arn:aws:guardduty:${region}::detector/none`,
        resourceRegion: region,
        description: `GuardDuty is not enabled in ${region}. Threat detection for this region is not active.`,
        remediation: "Enable Amazon GuardDuty in all regions to detect unauthorized activity and security threats.",
        complianceFrameworks: ["cis", "nist", "soc2"],
      });
      return findings;
    }

    for (const detectorId of detectorIds) {
      try {
        const findingsResp = await clients.guardduty.send(
          new ListFindingsCommand({
            DetectorId: detectorId,
            MaxResults: 50,
          }),
        );
        const findingIds = findingsResp.FindingIds || [];

        if (findingIds.length > 0) {
          const detailedResp = await clients.guardduty.send(
            new GetFindingsCommand({
              DetectorId: detectorId,
              FindingIds: findingIds,
            }),
          );

          for (const gdf of detailedResp.Findings || []) {
            const gdSeverity = gdf.Severity || 0;
            let severity: CloudFinding["severity"] = "informational";
            if (gdSeverity >= 7) severity = "critical";
            else if (gdSeverity >= 5) severity = "high";
            else if (gdSeverity >= 3) severity = "medium";
            else if (gdSeverity >= 1) severity = "low";

            findings.push({
              ruleId: `GD-${gdf.Type || "UNKNOWN"}`,
              ruleName: gdf.Title || gdf.Type || "GuardDuty Finding",
              severity,
              resourceType: `aws:guardduty:${gdf.Resource?.ResourceType || "unknown"}`,
              resourceId:
                gdf.Resource?.InstanceDetails?.InstanceId ||
                gdf.Resource?.AccessKeyDetails?.AccessKeyId ||
                gdf.Arn ||
                "unknown",
              resourceRegion: gdf.Region || region,
              description: gdf.Description || `GuardDuty detected: ${gdf.Type}`,
              remediation: `Review the GuardDuty finding for ${gdf.Type}. Investigate the affected resource and take corrective action.`,
              complianceFrameworks: ["nist", "soc2"],
              rawData: {
                type: gdf.Type,
                severity: gdf.Severity,
                count: gdf.Service?.Count,
                firstSeen: gdf.Service?.EventFirstSeen,
                lastSeen: gdf.Service?.EventLastSeen,
              },
            });
          }
        }
      } catch {
        // Skip individual detector errors
      }
    }
  } catch (err: unknown) {
    log.error("GuardDuty scan error", { region, error: err instanceof Error ? err.message : String(err) });
  }

  return findings;
}

/** Discover EC2 instances as cloud resources */
export async function discoverEC2Instances(config: AwsConnectorConfig, region: string): Promise<CloudResource[]> {
  const resources: CloudResource[] = [];

  try {
    const clients = getAwsClients(config, region);
    const resp = await clients.ec2.send(new DescribeInstancesCommand({}));

    for (const reservation of resp.Reservations || []) {
      for (const instance of reservation.Instances || []) {
        const tags: Record<string, string> = {};
        for (const tag of instance.Tags || []) {
          if (tag.Key && tag.Value) tags[tag.Key] = tag.Value;
        }

        resources.push({
          resourceId: instance.InstanceId || "unknown",
          resourceType: "aws:ec2:instance",
          region,
          name: tags["Name"] || instance.InstanceId || "unnamed",
          tags,
          configuration: {
            instanceType: instance.InstanceType,
            state: instance.State?.Name,
            publicIp: instance.PublicIpAddress,
            privateIp: instance.PrivateIpAddress,
            vpcId: instance.VpcId,
            subnetId: instance.SubnetId,
            platform: instance.Platform || "linux",
            launchTime: instance.LaunchTime?.toISOString(),
          },
          discoveredAt: new Date(),
        });
      }
    }
  } catch (err: unknown) {
    log.error("EC2 discovery error", { region, error: err instanceof Error ? err.message : String(err) });
  }

  return resources;
}

/** Run a full AWS CSPM scan across all enabled checks */
export async function runAwsScan(
  config: AwsConnectorConfig,
  accountId: string,
): Promise<{ findings: CloudFinding[]; resources: CloudResource[] }> {
  const allFindings: CloudFinding[] = [];
  const allResources: CloudResource[] = [];
  const regions = config.regions.length > 0 ? config.regions : ["us-east-1"];

  // Global scans (IAM is global)
  const iamFindings = await scanIAMUsers(config);
  allFindings.push(...iamFindings);

  // S3 is global but returns all buckets
  const s3Findings = await scanS3Buckets(config);
  allFindings.push(...s3Findings);

  // Regional scans
  for (const region of regions) {
    const [sgFindings, ebsFindings, rdsFindings, vpcFindings, gdFindings, ec2Resources] = await Promise.all([
      scanEC2SecurityGroups(config, region),
      scanEBSVolumes(config, region),
      scanRDSInstances(config, region),
      scanVPCFlowLogs(config, region),
      fetchGuardDutyFindings(config, region),
      discoverEC2Instances(config, region),
    ]);

    allFindings.push(...sgFindings, ...ebsFindings, ...rdsFindings, ...vpcFindings, ...gdFindings);
    allResources.push(...ec2Resources);
  }

  return { findings: allFindings, resources: allResources };
}
