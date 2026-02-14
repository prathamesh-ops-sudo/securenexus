import { storage } from "./storage";
import type { InsertCspmScan, InsertCspmFinding } from "@shared/schema";

interface FindingTemplate {
  ruleId: string;
  ruleName: string;
  resourceType: string;
  description: string;
  remediation: string;
  complianceFrameworks: string[];
}

const AWS_FINDINGS: FindingTemplate[] = [
  {
    ruleId: "AWS-S3-001",
    ruleName: "S3 Bucket Public Access Enabled",
    resourceType: "aws:s3:bucket",
    description: "S3 bucket has public access enabled via bucket policy or ACL. This allows unauthenticated users to list or read objects, potentially exposing sensitive data.",
    remediation: "Enable S3 Block Public Access at the account and bucket level. Review and restrict bucket policies and ACLs to remove public access grants.",
    complianceFrameworks: ["cis", "nist", "pci_dss", "soc2"],
  },
  {
    ruleId: "AWS-S3-002",
    ruleName: "S3 Bucket Server-Side Encryption Disabled",
    resourceType: "aws:s3:bucket",
    description: "S3 bucket does not have default server-side encryption configured. Objects stored without explicit encryption are unprotected at rest.",
    remediation: "Enable default encryption on the S3 bucket using SSE-S3 (AES-256) or SSE-KMS. Apply a bucket policy that denies s3:PutObject requests without encryption headers.",
    complianceFrameworks: ["cis", "nist", "pci_dss"],
  },
  {
    ruleId: "AWS-EC2-001",
    ruleName: "EBS Volume Not Encrypted",
    resourceType: "aws:ec2:volume",
    description: "EBS volume is not encrypted at rest. Unencrypted volumes expose data if the underlying storage hardware is compromised or the snapshot is shared.",
    remediation: "Enable EBS encryption by default in the AWS account settings. For existing unencrypted volumes, create an encrypted snapshot and restore from it.",
    complianceFrameworks: ["cis", "nist", "pci_dss"],
  },
  {
    ruleId: "AWS-EC2-002",
    ruleName: "Security Group Allows Unrestricted Ingress on SSH (Port 22)",
    resourceType: "aws:ec2:security-group",
    description: "Security group rule allows inbound SSH access from 0.0.0.0/0. This exposes instances to brute-force and credential-stuffing attacks from the internet.",
    remediation: "Restrict SSH access to known IP ranges or CIDR blocks. Use AWS Systems Manager Session Manager as an alternative to direct SSH access.",
    complianceFrameworks: ["cis", "nist", "soc2"],
  },
  {
    ruleId: "AWS-EC2-003",
    ruleName: "Security Group Allows Unrestricted Ingress on RDP (Port 3389)",
    resourceType: "aws:ec2:security-group",
    description: "Security group allows inbound RDP access from 0.0.0.0/0. Publicly accessible RDP endpoints are a primary target for ransomware operators.",
    remediation: "Remove the 0.0.0.0/0 ingress rule for port 3389. Use a VPN or AWS Client VPN for remote desktop access.",
    complianceFrameworks: ["cis", "nist", "pci_dss", "soc2"],
  },
  {
    ruleId: "AWS-EC2-004",
    ruleName: "EC2 Instance with Public IP in Non-DMZ Subnet",
    resourceType: "aws:ec2:instance",
    description: "EC2 instance has a public IPv4 address assigned in a subnet that is not designated as a DMZ. Internal workloads should not be directly internet-facing.",
    remediation: "Move the instance to a private subnet and use a NAT gateway or Application Load Balancer for outbound/inbound traffic respectively.",
    complianceFrameworks: ["cis", "nist"],
  },
  {
    ruleId: "AWS-IAM-001",
    ruleName: "IAM User Without MFA Enabled",
    resourceType: "aws:iam:user",
    description: "IAM user with console access does not have multi-factor authentication enabled. Compromised credentials without MFA can lead to full account takeover.",
    remediation: "Enable MFA for all IAM users with console access. Use virtual MFA devices or hardware FIDO2 security keys. Consider enforcing MFA via IAM policy conditions.",
    complianceFrameworks: ["cis", "nist", "pci_dss", "soc2"],
  },
  {
    ruleId: "AWS-IAM-002",
    ruleName: "Root Account Used for Daily Operations",
    resourceType: "aws:iam:root",
    description: "AWS root account credentials were used for API calls or console sign-in within the last 30 days. Root account usage bypasses IAM policies and audit controls.",
    remediation: "Create individual IAM users or IAM Identity Center identities for daily operations. Enable MFA on the root account and store credentials in a secure vault.",
    complianceFrameworks: ["cis", "nist", "soc2"],
  },
  {
    ruleId: "AWS-IAM-003",
    ruleName: "IAM Policy Allows Full Administrative Privileges",
    resourceType: "aws:iam:policy",
    description: "IAM policy grants Action:* on Resource:*, effectively providing unrestricted administrator access. Over-privileged policies violate the principle of least privilege.",
    remediation: "Replace wildcard policies with scoped permissions. Use AWS managed policies or create custom policies that grant only the permissions required for the role.",
    complianceFrameworks: ["cis", "nist", "pci_dss"],
  },
  {
    ruleId: "AWS-CT-001",
    ruleName: "CloudTrail Not Enabled in All Regions",
    resourceType: "aws:cloudtrail:trail",
    description: "CloudTrail is not configured as a multi-region trail. API activity in regions without CloudTrail enabled cannot be audited, creating blind spots for incident investigation.",
    remediation: "Enable a multi-region CloudTrail trail with management event logging. Enable log file validation and deliver logs to a centralized S3 bucket with lifecycle policies.",
    complianceFrameworks: ["cis", "nist", "pci_dss", "soc2"],
  },
  {
    ruleId: "AWS-RDS-001",
    ruleName: "RDS Instance Publicly Accessible",
    resourceType: "aws:rds:db-instance",
    description: "RDS database instance is configured with public accessibility enabled. This allows direct connections from the internet to the database endpoint.",
    remediation: "Set PubliclyAccessible to false on the RDS instance. Place the instance in a private subnet and use VPC security groups to restrict access.",
    complianceFrameworks: ["cis", "nist", "pci_dss", "soc2"],
  },
  {
    ruleId: "AWS-RDS-002",
    ruleName: "RDS Instance Storage Not Encrypted",
    resourceType: "aws:rds:db-instance",
    description: "RDS database instance does not have storage encryption enabled. Data at rest in the database is unprotected against unauthorized physical access.",
    remediation: "Enable encryption at rest using AWS KMS. Note: encryption cannot be enabled on an existing unencrypted instance. Create an encrypted snapshot and restore from it.",
    complianceFrameworks: ["cis", "nist", "pci_dss"],
  },
  {
    ruleId: "AWS-LAMBDA-001",
    ruleName: "Lambda Function Not Configured with VPC",
    resourceType: "aws:lambda:function",
    description: "Lambda function is not associated with a VPC. Functions outside a VPC cannot access private resources and their outbound traffic is not controlled by security groups.",
    remediation: "Configure the Lambda function to run within a VPC with appropriate subnet and security group assignments. Ensure the VPC has a NAT gateway for internet access if needed.",
    complianceFrameworks: ["nist", "soc2"],
  },
  {
    ruleId: "AWS-KMS-001",
    ruleName: "KMS Key Rotation Not Enabled",
    resourceType: "aws:kms:key",
    description: "Customer-managed KMS key does not have automatic key rotation enabled. Without rotation, a compromised key material remains valid indefinitely.",
    remediation: "Enable automatic key rotation for all customer-managed KMS keys. AWS rotates the backing key material every year while preserving the key ID and ARN.",
    complianceFrameworks: ["cis", "nist", "pci_dss"],
  },
  {
    ruleId: "AWS-CW-001",
    ruleName: "CloudWatch Log Group Without Retention Policy",
    resourceType: "aws:logs:log-group",
    description: "CloudWatch Log Group has no retention period configured, resulting in indefinite log storage and increasing costs. Lack of retention policy may also violate data governance requirements.",
    remediation: "Set an appropriate retention period (e.g., 90, 180, or 365 days) on the CloudWatch Log Group based on compliance and operational requirements.",
    complianceFrameworks: ["cis", "nist"],
  },
  {
    ruleId: "AWS-VPC-001",
    ruleName: "VPC Flow Logs Not Enabled",
    resourceType: "aws:ec2:vpc",
    description: "VPC does not have flow logs enabled. Without flow logs, network traffic analysis and forensic investigation of security incidents are significantly hindered.",
    remediation: "Enable VPC Flow Logs for all VPCs. Configure logs to be delivered to CloudWatch Logs or S3 for centralized analysis. Enable flow logs for both accepted and rejected traffic.",
    complianceFrameworks: ["cis", "nist", "soc2"],
  },
];

const AZURE_FINDINGS: FindingTemplate[] = [
  {
    ruleId: "AZ-STOR-001",
    ruleName: "Storage Account Allows Public Blob Access",
    resourceType: "azure:storage:account",
    description: "Azure Storage account has public blob access enabled. Anonymous users can read blob data in public containers without authentication.",
    remediation: "Set 'Allow Blob public access' to disabled on the storage account. Review container access levels and set them to 'Private' unless public access is explicitly required.",
    complianceFrameworks: ["cis", "nist", "pci_dss", "soc2"],
  },
  {
    ruleId: "AZ-STOR-002",
    ruleName: "Storage Account HTTPS-Only Traffic Not Enforced",
    resourceType: "azure:storage:account",
    description: "Storage account allows HTTP (unencrypted) traffic. Data transmitted over HTTP is vulnerable to interception and man-in-the-middle attacks.",
    remediation: "Enable 'Secure transfer required' on the storage account to enforce HTTPS-only access for all storage service endpoints.",
    complianceFrameworks: ["cis", "nist", "pci_dss"],
  },
  {
    ruleId: "AZ-NSG-001",
    ruleName: "NSG Rule Allows All Inbound Traffic",
    resourceType: "azure:network:nsg",
    description: "Network Security Group contains a rule allowing inbound traffic from any source (0.0.0.0/0) on all ports. This effectively disables network-level access control.",
    remediation: "Remove or restrict the allow-all inbound rule. Create specific NSG rules that permit only required ports and source IP ranges following the principle of least privilege.",
    complianceFrameworks: ["cis", "nist", "pci_dss", "soc2"],
  },
  {
    ruleId: "AZ-NSG-002",
    ruleName: "NSG Allows SSH from Internet",
    resourceType: "azure:network:nsg",
    description: "Network Security Group allows inbound SSH (port 22) from any source address. This exposes virtual machines to brute-force attacks from the internet.",
    remediation: "Restrict SSH access to specific IP ranges. Use Azure Bastion or Just-In-Time VM access for secure remote management.",
    complianceFrameworks: ["cis", "nist", "soc2"],
  },
  {
    ruleId: "AZ-KV-001",
    ruleName: "Key Vault Soft Delete Not Enabled",
    resourceType: "azure:keyvault:vault",
    description: "Azure Key Vault does not have soft delete enabled. Accidental or malicious deletion of secrets, keys, or certificates is irreversible without soft delete protection.",
    remediation: "Enable soft delete and purge protection on the Key Vault. Note: soft delete is now enabled by default for new vaults but existing vaults may need manual configuration.",
    complianceFrameworks: ["cis", "nist", "soc2"],
  },
  {
    ruleId: "AZ-KV-002",
    ruleName: "Key Vault Purge Protection Disabled",
    resourceType: "azure:keyvault:vault",
    description: "Key Vault does not have purge protection enabled. Without purge protection, a soft-deleted vault can be permanently purged before the retention period expires.",
    remediation: "Enable purge protection on the Key Vault to prevent permanent deletion of the vault and its objects during the retention period.",
    complianceFrameworks: ["cis", "nist"],
  },
  {
    ruleId: "AZ-SQL-001",
    ruleName: "SQL Database Transparent Data Encryption Disabled",
    resourceType: "azure:sql:database",
    description: "Azure SQL Database does not have Transparent Data Encryption (TDE) enabled. Database files, backups, and transaction logs are stored unencrypted at rest.",
    remediation: "Enable Transparent Data Encryption on the SQL database. TDE encrypts data at rest using a database encryption key protected by a built-in server certificate or Azure Key Vault.",
    complianceFrameworks: ["cis", "nist", "pci_dss", "soc2"],
  },
  {
    ruleId: "AZ-SQL-002",
    ruleName: "SQL Server Auditing Not Enabled",
    resourceType: "azure:sql:server",
    description: "Azure SQL Server does not have auditing enabled. Database operations are not being logged, preventing forensic analysis and compliance reporting.",
    remediation: "Enable auditing on the Azure SQL Server. Configure audit logs to be sent to a storage account, Log Analytics workspace, or Event Hub.",
    complianceFrameworks: ["cis", "nist", "pci_dss"],
  },
  {
    ruleId: "AZ-APP-001",
    ruleName: "App Service Allows HTTP Traffic",
    resourceType: "azure:web:app",
    description: "Azure App Service does not enforce HTTPS-only traffic. Users can access the application over unencrypted HTTP connections, exposing session tokens and data.",
    remediation: "Enable 'HTTPS Only' on the App Service. This automatically redirects all HTTP requests to HTTPS, ensuring encrypted communication.",
    complianceFrameworks: ["cis", "nist", "pci_dss"],
  },
  {
    ruleId: "AZ-APP-002",
    ruleName: "App Service Using Outdated TLS Version",
    resourceType: "azure:web:app",
    description: "App Service is configured to accept TLS 1.0 or TLS 1.1 connections. These older protocol versions have known vulnerabilities and are deprecated.",
    remediation: "Set the minimum TLS version to 1.2 on the App Service. Update client applications that do not support TLS 1.2.",
    complianceFrameworks: ["cis", "nist", "pci_dss"],
  },
  {
    ruleId: "AZ-DIAG-001",
    ruleName: "Diagnostic Settings Not Configured",
    resourceType: "azure:monitor:diagnostic",
    description: "Azure resource does not have diagnostic settings configured. Activity logs and metrics are not being forwarded to a centralized monitoring solution.",
    remediation: "Configure diagnostic settings to send platform logs and metrics to a Log Analytics workspace, storage account, or Event Hub for centralized monitoring and alerting.",
    complianceFrameworks: ["cis", "nist", "soc2"],
  },
  {
    ruleId: "AZ-VM-001",
    ruleName: "Virtual Machine Disk Encryption Not Enabled",
    resourceType: "azure:compute:vm",
    description: "Azure Virtual Machine OS and data disks are not encrypted using Azure Disk Encryption. Unencrypted disks expose data if the underlying storage is compromised.",
    remediation: "Enable Azure Disk Encryption using BitLocker (Windows) or DM-Crypt (Linux) with keys stored in Azure Key Vault.",
    complianceFrameworks: ["cis", "nist", "pci_dss"],
  },
];

const GCP_FINDINGS: FindingTemplate[] = [
  {
    ruleId: "GCP-GCS-001",
    ruleName: "Cloud Storage Bucket Uniform Access Disabled",
    resourceType: "gcp:storage:bucket",
    description: "Cloud Storage bucket does not have uniform bucket-level access enabled. Mixed ACL and IAM permissions create complexity and potential for unintended public exposure.",
    remediation: "Enable uniform bucket-level access to use IAM exclusively for access control. This simplifies permission management and prevents accidental public access through legacy ACLs.",
    complianceFrameworks: ["cis", "nist", "soc2"],
  },
  {
    ruleId: "GCP-GCS-002",
    ruleName: "Cloud Storage Bucket Publicly Accessible",
    resourceType: "gcp:storage:bucket",
    description: "Cloud Storage bucket grants access to allUsers or allAuthenticatedUsers. Objects in the bucket can be read by anyone on the internet.",
    remediation: "Remove allUsers and allAuthenticatedUsers from bucket IAM bindings. Use signed URLs or IAM conditions for controlled temporary access.",
    complianceFrameworks: ["cis", "nist", "pci_dss", "soc2"],
  },
  {
    ruleId: "GCP-FW-001",
    ruleName: "Firewall Rule Allows Ingress from 0.0.0.0/0",
    resourceType: "gcp:compute:firewall",
    description: "VPC firewall rule allows inbound traffic from all IP addresses (0.0.0.0/0) on one or more ports. This exposes instances to unauthorized access attempts from the internet.",
    remediation: "Restrict source IP ranges in the firewall rule to known addresses. Use Identity-Aware Proxy (IAP) for SSH/RDP access instead of direct internet exposure.",
    complianceFrameworks: ["cis", "nist", "pci_dss", "soc2"],
  },
  {
    ruleId: "GCP-FW-002",
    ruleName: "Firewall Rule Allows All Protocols and Ports",
    resourceType: "gcp:compute:firewall",
    description: "VPC firewall rule allows traffic on all protocols and ports. Overly permissive rules undermine defense-in-depth and network segmentation controls.",
    remediation: "Specify allowed protocols and port ranges in the firewall rule. Follow the principle of least privilege by only allowing required traffic.",
    complianceFrameworks: ["cis", "nist"],
  },
  {
    ruleId: "GCP-SQL-001",
    ruleName: "Cloud SQL Instance Has Public IP Address",
    resourceType: "gcp:sql:instance",
    description: "Cloud SQL database instance is configured with a public IP address. Even with authorized networks configured, a public IP increases the attack surface.",
    remediation: "Configure the Cloud SQL instance to use a private IP address only. Use Cloud SQL Auth Proxy for secure connections from external applications.",
    complianceFrameworks: ["cis", "nist", "pci_dss", "soc2"],
  },
  {
    ruleId: "GCP-SQL-002",
    ruleName: "Cloud SQL Instance Allows Connections from Any IP",
    resourceType: "gcp:sql:instance",
    description: "Cloud SQL authorized networks include 0.0.0.0/0, allowing connection attempts from any IP address on the internet.",
    remediation: "Remove the 0.0.0.0/0 entry from authorized networks. Restrict access to specific IP addresses or use private IP with VPC peering.",
    complianceFrameworks: ["cis", "nist", "pci_dss"],
  },
  {
    ruleId: "GCP-API-001",
    ruleName: "API Key Not Restricted to Specific APIs",
    resourceType: "gcp:apikeys:key",
    description: "Google Cloud API key is not restricted to specific APIs. An unrestricted API key can be used to call any enabled API in the project, increasing the blast radius of a key compromise.",
    remediation: "Apply API restrictions to limit the key to only the specific APIs it needs to access. Consider using service accounts with OAuth 2.0 instead of API keys.",
    complianceFrameworks: ["cis", "nist", "soc2"],
  },
  {
    ruleId: "GCP-API-002",
    ruleName: "API Key Not Restricted by Application",
    resourceType: "gcp:apikeys:key",
    description: "API key does not have application restrictions (HTTP referrer, IP address, or Android/iOS app). Stolen keys can be used from any application or network.",
    remediation: "Apply application restrictions (HTTP referrer, IP address, or mobile app) to the API key to prevent unauthorized usage from unknown sources.",
    complianceFrameworks: ["cis", "nist"],
  },
  {
    ruleId: "GCP-NET-001",
    ruleName: "Legacy Network in Use",
    resourceType: "gcp:compute:network",
    description: "Project uses a legacy network instead of a VPC network. Legacy networks do not support subnets, firewall rules at the subnet level, or private Google access.",
    remediation: "Migrate workloads from the legacy network to a VPC network with custom subnets. Legacy networks cannot be converted and must be recreated.",
    complianceFrameworks: ["cis", "nist"],
  },
  {
    ruleId: "GCP-IAM-001",
    ruleName: "Service Account with Owner or Editor Role",
    resourceType: "gcp:iam:service-account",
    description: "Service account has been granted the Owner or Editor basic role at the project level. These roles provide broad permissions that violate the principle of least privilege.",
    remediation: "Replace basic roles (Owner/Editor) with predefined or custom IAM roles that grant only the specific permissions required by the service account.",
    complianceFrameworks: ["cis", "nist", "soc2"],
  },
  {
    ruleId: "GCP-LOG-001",
    ruleName: "Audit Logging Not Enabled for All Services",
    resourceType: "gcp:logging:config",
    description: "Cloud Audit Logs are not configured for data access logging across all services. Without comprehensive audit logging, unauthorized data access may go undetected.",
    remediation: "Enable Data Access audit logs for all services in the project's IAM audit configuration. Configure log sinks to export logs for long-term retention.",
    complianceFrameworks: ["cis", "nist", "pci_dss", "soc2"],
  },
];

function getRandomInt(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function pickRandom<T>(arr: T[], count: number): T[] {
  const shuffled = [...arr].sort(() => Math.random() - 0.5);
  return shuffled.slice(0, Math.min(count, shuffled.length));
}

function weightedSeverity(): string {
  const r = Math.random();
  if (r < 0.10) return "critical";
  if (r < 0.30) return "high";
  if (r < 0.70) return "medium";
  return "low";
}

function pickComplianceFrameworks(base: string[]): string[] {
  if (base.length === 0) return ["cis"];
  const count = getRandomInt(1, base.length);
  return pickRandom(base, count);
}

function generateAwsResourceId(resourceType: string, region: string): string {
  const accountNum = `${getRandomInt(100000000000, 999999999999)}`;
  const suffix = `${getRandomInt(10000, 99999)}`;
  const hex = Math.random().toString(16).substring(2, 10);

  switch (resourceType) {
    case "aws:s3:bucket":
      return `arn:aws:s3:::prod-data-${["assets", "logs", "backup", "uploads", "config", "analytics"][getRandomInt(0, 5)]}-${suffix}`;
    case "aws:ec2:volume":
      return `arn:aws:ec2:${region}:${accountNum}:volume/vol-${hex}${suffix}`;
    case "aws:ec2:security-group":
      return `arn:aws:ec2:${region}:${accountNum}:security-group/sg-${hex}${suffix}`;
    case "aws:ec2:instance":
      return `arn:aws:ec2:${region}:${accountNum}:instance/i-${hex}${suffix}`;
    case "aws:iam:user":
      return `arn:aws:iam::${accountNum}:user/${["dev-ops", "ci-deploy", "admin-user", "service-account", "backup-agent"][getRandomInt(0, 4)]}`;
    case "aws:iam:root":
      return `arn:aws:iam::${accountNum}:root`;
    case "aws:iam:policy":
      return `arn:aws:iam::${accountNum}:policy/${["AdminAccess", "FullAccess", "PowerUserPolicy", "LegacyAdminRole"][getRandomInt(0, 3)]}`;
    case "aws:cloudtrail:trail":
      return `arn:aws:cloudtrail:${region}:${accountNum}:trail/management-trail`;
    case "aws:rds:db-instance":
      return `arn:aws:rds:${region}:${accountNum}:db/${["prod-db", "staging-mysql", "analytics-pg", "app-postgres"][getRandomInt(0, 3)]}-${suffix}`;
    case "aws:lambda:function":
      return `arn:aws:lambda:${region}:${accountNum}:function:${["data-processor", "api-handler", "event-trigger", "cron-job"][getRandomInt(0, 3)]}-${suffix}`;
    case "aws:kms:key":
      return `arn:aws:kms:${region}:${accountNum}:key/${crypto.randomUUID?.() || hex + "-" + suffix}`;
    case "aws:logs:log-group":
      return `arn:aws:logs:${region}:${accountNum}:log-group:/aws/lambda/${["api-handler", "data-processor", "auth-service"][getRandomInt(0, 2)]}`;
    case "aws:ec2:vpc":
      return `arn:aws:ec2:${region}:${accountNum}:vpc/vpc-${hex}`;
    default:
      return `arn:aws:unknown:${region}:${accountNum}:resource/${hex}`;
  }
}

function generateAzureResourceId(resourceType: string): string {
  const sub = `${Math.random().toString(16).substring(2, 10)}-${Math.random().toString(16).substring(2, 6)}-${Math.random().toString(16).substring(2, 6)}-${Math.random().toString(16).substring(2, 6)}-${Math.random().toString(16).substring(2, 14)}`;
  const rg = ["rg-production", "rg-staging", "rg-shared-services", "rg-data", "rg-webapp"][getRandomInt(0, 4)];
  const suffix = getRandomInt(100, 999);

  switch (resourceType) {
    case "azure:storage:account":
      return `/subscriptions/${sub}/resourceGroups/${rg}/providers/Microsoft.Storage/storageAccounts/${ ["proddata", "appassets", "backupstor", "logsarchive"][getRandomInt(0, 3)]}${suffix}`;
    case "azure:network:nsg":
      return `/subscriptions/${sub}/resourceGroups/${rg}/providers/Microsoft.Network/networkSecurityGroups/nsg-${["web", "app", "db", "mgmt"][getRandomInt(0, 3)]}-${suffix}`;
    case "azure:keyvault:vault":
      return `/subscriptions/${sub}/resourceGroups/${rg}/providers/Microsoft.KeyVault/vaults/kv-${["prod", "staging", "shared"][getRandomInt(0, 2)]}-${suffix}`;
    case "azure:sql:database":
      return `/subscriptions/${sub}/resourceGroups/${rg}/providers/Microsoft.Sql/servers/sql-${["prod", "staging"][getRandomInt(0, 1)]}-${suffix}/databases/db-${["users", "orders", "analytics"][getRandomInt(0, 2)]}`;
    case "azure:sql:server":
      return `/subscriptions/${sub}/resourceGroups/${rg}/providers/Microsoft.Sql/servers/sql-${["prod", "staging"][getRandomInt(0, 1)]}-${suffix}`;
    case "azure:web:app":
      return `/subscriptions/${sub}/resourceGroups/${rg}/providers/Microsoft.Web/sites/${["webapp", "api", "portal"][getRandomInt(0, 2)]}-${suffix}`;
    case "azure:monitor:diagnostic":
      return `/subscriptions/${sub}/resourceGroups/${rg}/providers/Microsoft.Insights/diagnosticSettings/ds-${suffix}`;
    case "azure:compute:vm":
      return `/subscriptions/${sub}/resourceGroups/${rg}/providers/Microsoft.Compute/virtualMachines/vm-${["web", "app", "worker"][getRandomInt(0, 2)]}-${suffix}`;
    default:
      return `/subscriptions/${sub}/resourceGroups/${rg}/providers/Microsoft.Unknown/resources/resource-${suffix}`;
  }
}

function generateGcpResourceId(resourceType: string, region: string): string {
  const project = ["prod-platform", "staging-env", "data-analytics", "shared-services"][getRandomInt(0, 3)];
  const suffix = getRandomInt(1000, 9999);

  switch (resourceType) {
    case "gcp:storage:bucket":
      return `projects/${project}/buckets/${project}-${["data", "assets", "backups", "logs", "uploads"][getRandomInt(0, 4)]}-${suffix}`;
    case "gcp:compute:firewall":
      return `projects/${project}/global/firewalls/${["allow-ssh", "allow-http", "allow-internal", "legacy-allow-all"][getRandomInt(0, 3)]}-${suffix}`;
    case "gcp:sql:instance":
      return `projects/${project}/instances/${["prod-mysql", "staging-pg", "analytics-db", "app-cloudsql"][getRandomInt(0, 3)]}-${suffix}`;
    case "gcp:apikeys:key":
      return `projects/${project}/locations/global/keys/key-${suffix}`;
    case "gcp:compute:network":
      return `projects/${project}/global/networks/legacy-network-${suffix}`;
    case "gcp:iam:service-account":
      return `projects/${project}/serviceAccounts/${["deploy", "compute", "data-pipeline", "ci-cd"][getRandomInt(0, 3)]}-sa@${project}.iam.gserviceaccount.com`;
    case "gcp:logging:config":
      return `projects/${project}/locations/global/auditConfigs/default`;
    default:
      return `projects/${project}/locations/${region}/resources/resource-${suffix}`;
  }
}

export async function runCspmScan(orgId: string, accountId: string): Promise<void> {
  const scanData: InsertCspmScan = {
    orgId,
    accountId,
    status: "running",
    findingsCount: 0,
    summary: {},
  };
  const scan = await storage.createCspmScan(scanData);

  const account = await storage.getCspmAccount(accountId);
  if (!account) {
    await storage.updateCspmScan(scan.id, {
      status: "failed",
      completedAt: new Date(),
      summary: { error: "Account not found" },
    });
    return;
  }

  const provider = account.cloudProvider;
  const regions = account.regions && account.regions.length > 0
    ? account.regions
    : provider === "aws" ? ["us-east-1", "us-west-2", "eu-west-1"]
    : provider === "azure" ? ["eastus", "westus2", "westeurope"]
    : ["us-central1", "us-east1", "europe-west1"];

  let templates: FindingTemplate[];
  switch (provider) {
    case "azure":
      templates = AZURE_FINDINGS;
      break;
    case "gcp":
      templates = GCP_FINDINGS;
      break;
    default:
      templates = AWS_FINDINGS;
  }

  const findingCount = getRandomInt(15, 30);
  const selectedTemplates = pickRandom(templates, findingCount);
  while (selectedTemplates.length < findingCount) {
    selectedTemplates.push(templates[getRandomInt(0, templates.length - 1)]);
  }

  const severityCounts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };

  for (const template of selectedTemplates) {
    const region = regions[getRandomInt(0, regions.length - 1)];
    const severity = weightedSeverity();
    severityCounts[severity]++;

    let resourceId: string;
    switch (provider) {
      case "azure":
        resourceId = generateAzureResourceId(template.resourceType);
        break;
      case "gcp":
        resourceId = generateGcpResourceId(template.resourceType, region);
        break;
      default:
        resourceId = generateAwsResourceId(template.resourceType, region);
    }

    const finding: InsertCspmFinding = {
      orgId,
      scanId: scan.id,
      accountId,
      ruleId: template.ruleId,
      ruleName: template.ruleName,
      severity,
      resourceType: template.resourceType,
      resourceId,
      resourceRegion: region,
      description: template.description,
      remediation: template.remediation,
      complianceFrameworks: pickComplianceFrameworks(template.complianceFrameworks),
      status: "open",
    };

    await storage.createCspmFinding(finding);
  }

  await storage.updateCspmScan(scan.id, {
    status: "completed",
    findingsCount: findingCount,
    completedAt: new Date(),
    summary: {
      severityCounts,
      totalFindings: findingCount,
      provider,
      regionsScanned: regions,
    },
  });

  await storage.updateCspmAccount(accountId, {
    lastScanAt: new Date(),
  });
}
