import {
  AppRunnerClient,
  CreateServiceCommand,
  DescribeServiceCommand,
  ListServicesCommand,
  CreateAutoScalingConfigurationCommand,
  CreateVpcConnectorCommand,
  ListVpcConnectorsCommand,
  type SourceConfiguration,
} from "@aws-sdk/client-apprunner";
import {
  RDSClient,
  CreateDBInstanceCommand,
  DescribeDBInstancesCommand,
  ModifyDBInstanceCommand,
} from "@aws-sdk/client-rds";
import {
  EC2Client,
  DescribeSubnetsCommand,
  DescribeSecurityGroupsCommand,
  CreateSecurityGroupCommand,
  AuthorizeSecurityGroupIngressCommand,
  DescribeVpcsCommand,
} from "@aws-sdk/client-ec2";
import {
  IAMClient,
  CreateRoleCommand,
  AttachRolePolicyCommand,
  GetRoleCommand,
} from "@aws-sdk/client-iam";
import {
  STSClient,
  GetCallerIdentityCommand,
} from "@aws-sdk/client-sts";
import {
  ECRClient,
  CreateRepositoryCommand,
  DescribeRepositoriesCommand,
  GetAuthorizationTokenCommand,
} from "@aws-sdk/client-ecr";

const REGION = process.env.AWS_REGION || "us-east-1";
const APP_NAME = "securenexus";
const DB_INSTANCE_ID = `${APP_NAME}-db`;
const DB_NAME = "securenexus";
const DB_USERNAME = "securenexus_admin";
const DB_PASSWORD = process.env.RDS_DB_PASSWORD || generatePassword();
const ECR_REPO_NAME = APP_NAME;

const appRunner = new AppRunnerClient({ region: REGION });
const rds = new RDSClient({ region: REGION });
const ec2 = new EC2Client({ region: REGION });
const iam = new IAMClient({ region: REGION });
const sts = new STSClient({ region: REGION });
const ecr = new ECRClient({ region: REGION });

function generatePassword(): string {
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
  const bytes = require("crypto").randomBytes(32);
  let result = "";
  for (let i = 0; i < 32; i++) {
    result += chars.charAt(bytes[i] % chars.length);
  }
  return result;
}

function log(msg: string) {
  console.log(`[deploy] ${new Date().toISOString()} ${msg}`);
}

function logError(msg: string, err: any) {
  console.error(`[deploy] ERROR: ${msg}`, err?.message || err);
}

async function getAccountId(): Promise<string> {
  const identity = await sts.send(new GetCallerIdentityCommand({}));
  return identity.Account!;
}

async function getDefaultVpc(): Promise<{ vpcId: string; subnetIds: string[] }> {
  log("Finding default VPC and subnets...");
  const vpcs = await ec2.send(new DescribeVpcsCommand({ Filters: [{ Name: "isDefault", Values: ["true"] }] }));
  const vpcId = vpcs.Vpcs?.[0]?.VpcId;
  if (!vpcId) throw new Error("No default VPC found. Create one or specify VPC_ID env var.");

  const subnets = await ec2.send(new DescribeSubnetsCommand({ Filters: [{ Name: "vpc-id", Values: [vpcId] }] }));
  const subnetIds = subnets.Subnets?.map((s) => s.SubnetId!) || [];
  if (subnetIds.length === 0) throw new Error("No subnets found in default VPC.");

  log(`Found VPC ${vpcId} with ${subnetIds.length} subnets`);
  return { vpcId, subnetIds };
}

async function createOrGetSecurityGroup(vpcId: string): Promise<string> {
  log("Setting up security group...");
  const sgName = `${APP_NAME}-db-sg`;

  try {
    const existing = await ec2.send(new DescribeSecurityGroupsCommand({
      Filters: [
        { Name: "group-name", Values: [sgName] },
        { Name: "vpc-id", Values: [vpcId] },
      ],
    }));
    if (existing.SecurityGroups?.length) {
      log(`Using existing security group: ${existing.SecurityGroups[0].GroupId}`);
      return existing.SecurityGroups[0].GroupId!;
    }
  } catch (err: unknown) {
    const errName = (err as { name?: string })?.name;
    if (errName && !errName.includes("NotFound")) {
      throw err;
    }
  }

  const sg = await ec2.send(new CreateSecurityGroupCommand({
    GroupName: sgName,
    Description: "SecureNexus RDS security group - allows PostgreSQL from VPC",
    VpcId: vpcId,
  }));
  const sgId = sg.GroupId!;

  await ec2.send(new AuthorizeSecurityGroupIngressCommand({
    GroupId: sgId,
    IpPermissions: [
      {
        IpProtocol: "tcp",
        FromPort: 5432,
        ToPort: 5432,
        IpRanges: [{ CidrIp: "10.0.0.0/8", Description: "Allow PostgreSQL from VPC private range" }],
      },
    ],
  }));

  log(`Created security group: ${sgId}`);
  return sgId;
}

async function createOrGetRdsInstance(sgId: string): Promise<string> {
  log("Setting up RDS PostgreSQL database...");

  try {
    const existing = await rds.send(new DescribeDBInstancesCommand({
      DBInstanceIdentifier: DB_INSTANCE_ID,
    }));
    const instance = existing.DBInstances?.[0];
    if (instance) {
      const endpoint = instance.Endpoint?.Address;
      const port = instance.Endpoint?.Port || 5432;
      if (endpoint) {
        const dbUrl = `postgresql://${DB_USERNAME}:${DB_PASSWORD}@${endpoint}:${port}/${DB_NAME}`;
        log(`RDS instance already exists: ${endpoint}:${port}`);
        log(`Status: ${instance.DBInstanceStatus}`);
        return dbUrl;
      }
      log(`RDS instance exists but endpoint not available yet. Status: ${instance.DBInstanceStatus}`);
      return await waitForRds();
    }
  } catch (err: any) {
    if (!err.name?.includes("DBInstanceNotFound") && !err.message?.includes("not found")) {
      throw err;
    }
  }

  log("Creating new RDS instance (this takes 5-10 minutes)...");
  await rds.send(new CreateDBInstanceCommand({
    DBInstanceIdentifier: DB_INSTANCE_ID,
    DBName: DB_NAME,
    Engine: "postgres",
    EngineVersion: "16.4",
    DBInstanceClass: "db.t3.micro",
    AllocatedStorage: 20,
    MasterUsername: DB_USERNAME,
    MasterUserPassword: DB_PASSWORD,
    VpcSecurityGroupIds: [sgId],
    PubliclyAccessible: true,
    StorageType: "gp3",
    BackupRetentionPeriod: 7,
    MultiAZ: false,
    StorageEncrypted: true,
    DeletionProtection: true,
    Tags: [
      { Key: "Application", Value: APP_NAME },
      { Key: "Environment", Value: "production" },
    ],
  }));

  log("RDS instance creation started. Waiting for it to become available...");
  return await waitForRds();
}

async function waitForRds(): Promise<string> {
  const maxAttempts = 60;
  for (let i = 0; i < maxAttempts; i++) {
    const result = await rds.send(new DescribeDBInstancesCommand({
      DBInstanceIdentifier: DB_INSTANCE_ID,
    }));
    const instance = result.DBInstances?.[0];
    const status = instance?.DBInstanceStatus;
    const endpoint = instance?.Endpoint?.Address;
    const port = instance?.Endpoint?.Port || 5432;

    log(`RDS status: ${status} (attempt ${i + 1}/${maxAttempts})`);

    if (status === "available" && endpoint) {
      const dbUrl = `postgresql://${DB_USERNAME}:${DB_PASSWORD}@${endpoint}:${port}/${DB_NAME}`;
      log(`RDS ready at ${endpoint}:${port}`);
      return dbUrl;
    }

    await new Promise((r) => setTimeout(r, 15000));
  }
  throw new Error("RDS instance did not become available within timeout");
}

async function createEcrRepo(): Promise<string> {
  log("Setting up ECR repository...");
  const accountId = await getAccountId();

  try {
    const existing = await ecr.send(new DescribeRepositoriesCommand({
      repositoryNames: [ECR_REPO_NAME],
    }));
    if (existing.repositories?.length) {
      const uri = existing.repositories[0].repositoryUri!;
      log(`ECR repo already exists: ${uri}`);
      return uri;
    }
  } catch (err: unknown) {
    const errName = (err as { name?: string })?.name;
    if (errName && !errName.includes("RepositoryNotFoundException")) {
      throw err;
    }
  }

  const repo = await ecr.send(new CreateRepositoryCommand({
    repositoryName: ECR_REPO_NAME,
    imageScanningConfiguration: { scanOnPush: true },
    imageTagMutability: "MUTABLE",
  }));

  const uri = repo.repository?.repositoryUri!;
  log(`Created ECR repo: ${uri}`);
  return uri;
}

async function createAppRunnerAccessRole(): Promise<string> {
  const roleName = `${APP_NAME}-apprunner-ecr-role`;
  const accountId = await getAccountId();

  try {
    const existing = await iam.send(new GetRoleCommand({ RoleName: roleName }));
    if (existing.Role) {
      log(`IAM role already exists: ${existing.Role.Arn}`);
      return existing.Role.Arn!;
    }
  } catch (err: unknown) {
    const errName = (err as { name?: string })?.name;
    if (errName !== "NoSuchEntityException") {
      throw err;
    }
  }

  log("Creating IAM role for App Runner ECR access...");
  const trustPolicy = {
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Principal: { Service: "build.apprunner.amazonaws.com" },
        Action: "sts:AssumeRole",
      },
    ],
  };

  const role = await iam.send(new CreateRoleCommand({
    RoleName: roleName,
    AssumeRolePolicyDocument: JSON.stringify(trustPolicy),
    Description: "Allows App Runner to pull images from ECR",
    Tags: [{ Key: "Application", Value: APP_NAME }],
  }));

  await iam.send(new AttachRolePolicyCommand({
    RoleName: roleName,
    PolicyArn: "arn:aws:iam::aws:policy/service-role/AWSAppRunnerServicePolicyForECRAccess",
  }));

  log(`Created IAM role: ${role.Role?.Arn}`);
  await new Promise((r) => setTimeout(r, 10000));
  return role.Role?.Arn!;
}

async function createAppRunnerInstanceRole(): Promise<string> {
  const roleName = `${APP_NAME}-apprunner-instance-role`;

  try {
    const existing = await iam.send(new GetRoleCommand({ RoleName: roleName }));
    if (existing.Role) {
      log(`Instance role already exists: ${existing.Role.Arn}`);
      return existing.Role.Arn!;
    }
  } catch (err: unknown) {
    const errName = (err as { name?: string })?.name;
    if (errName !== "NoSuchEntityException") {
      throw err;
    }
  }

  log("Creating App Runner instance role...");
  const trustPolicy = {
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Principal: { Service: "tasks.apprunner.amazonaws.com" },
        Action: "sts:AssumeRole",
      },
    ],
  };

  const role = await iam.send(new CreateRoleCommand({
    RoleName: roleName,
    AssumeRolePolicyDocument: JSON.stringify(trustPolicy),
    Description: "SecureNexus App Runner instance role for AWS service access",
    Tags: [{ Key: "Application", Value: APP_NAME }],
  }));

  const policies = [
    "arn:aws:iam::aws:policy/AmazonBedrockReadOnly",
    "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
  ];

  for (const policyArn of policies) {
    try {
      await iam.send(new AttachRolePolicyCommand({ RoleName: roleName, PolicyArn: policyArn }));
    } catch (err: any) {
      log(`Warning: Could not attach policy ${policyArn}: ${err.message}`);
    }
  }

  log(`Created instance role: ${role.Role?.Arn}`);
  await new Promise((r) => setTimeout(r, 10000));
  return role.Role?.Arn!;
}

async function createOrGetVpcConnector(subnetIds: string[], sgId: string): Promise<string> {
  const connectorName = `${APP_NAME}-vpc-connector`;

  try {
    const existing = await appRunner.send(new ListVpcConnectorsCommand({}));
    const found = existing.VpcConnectors?.find((v) => v.VpcConnectorName === connectorName && v.Status === "ACTIVE");
    if (found) {
      log(`VPC connector already exists: ${found.VpcConnectorArn}`);
      return found.VpcConnectorArn!;
    }
  } catch (err: unknown) {
    logError("Error listing VPC connectors", err);
  }

  log("Creating VPC connector for App Runner to reach RDS...");
  const connector = await appRunner.send(new CreateVpcConnectorCommand({
    VpcConnectorName: connectorName,
    Subnets: subnetIds.slice(0, 3),
    SecurityGroups: [sgId],
    Tags: [{ Key: "Application", Value: APP_NAME }],
  }));

  log(`Created VPC connector: ${connector.VpcConnector?.VpcConnectorArn}`);
  return connector.VpcConnector?.VpcConnectorArn!;
}

async function createAppRunnerService(
  ecrUri: string,
  accessRoleArn: string,
  instanceRoleArn: string,
  vpcConnectorArn: string,
  databaseUrl: string,
  sessionSecret: string,
): Promise<string> {
  log("Setting up App Runner service...");

  try {
    const existing = await appRunner.send(new ListServicesCommand({}));
    const found = existing.ServiceSummaryList?.find(
      (s) => s.ServiceName === APP_NAME && s.Status !== "DELETED",
    );
    if (found) {
      log(`App Runner service already exists: ${found.ServiceUrl}`);
      log(`Status: ${found.Status}`);
      return `https://${found.ServiceUrl}`;
    }
  } catch (err: unknown) {
    logError("Error listing App Runner services", err);
  }

  const imageTag = "latest";
  const sourceConfig: SourceConfiguration = {
    ImageRepository: {
      ImageIdentifier: `${ecrUri}:${imageTag}`,
      ImageRepositoryType: "ECR",
      ImageConfiguration: {
        Port: "5000",
        RuntimeEnvironmentVariables: {
          NODE_ENV: "production",
          PORT: "5000",
          DATABASE_URL: databaseUrl,
          SESSION_SECRET: sessionSecret,
          AWS_REGION: REGION,
        },
      },
    },
    AuthenticationConfiguration: {
      AccessRoleArn: accessRoleArn,
    },
    AutoDeploymentsEnabled: true,
  };

  const autoScaling = await appRunner.send(new CreateAutoScalingConfigurationCommand({
    AutoScalingConfigurationName: `${APP_NAME}-scaling`,
    MinSize: 1,
    MaxSize: 3,
    MaxConcurrency: 100,
  }));

  const service = await appRunner.send(new CreateServiceCommand({
    ServiceName: APP_NAME,
    SourceConfiguration: sourceConfig,
    InstanceConfiguration: {
      Cpu: "1 vCPU",
      Memory: "2 GB",
      InstanceRoleArn: instanceRoleArn,
    },
    HealthCheckConfiguration: {
      Protocol: "HTTP",
      Path: "/api/ops/health",
      Interval: 10,
      Timeout: 5,
      HealthyThreshold: 1,
      UnhealthyThreshold: 3,
    },
    AutoScalingConfigurationArn: autoScaling.AutoScalingConfiguration?.AutoScalingConfigurationArn,
    NetworkConfiguration: {
      EgressConfiguration: {
        EgressType: "VPC",
        VpcConnectorArn: vpcConnectorArn,
      },
    },
    Tags: [
      { Key: "Application", Value: APP_NAME },
      { Key: "Environment", Value: "production" },
    ],
  }));

  const serviceUrl = `https://${service.Service?.ServiceUrl}`;
  log(`App Runner service created: ${serviceUrl}`);
  log(`Service ARN: ${service.Service?.ServiceArn}`);
  log(`Status: ${service.Service?.Status}`);

  return serviceUrl;
}

async function main() {
  log("=== SecureNexus AWS Deployment ===");
  log(`Region: ${REGION}`);

  try {
    const accountId = await getAccountId();
    log(`AWS Account: ${accountId}`);
  } catch (err) {
    logError("Cannot authenticate with AWS. Check AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.", err);
    process.exit(1);
  }

  const sessionSecret = process.env.SESSION_SECRET || generatePassword();

  const { vpcId, subnetIds } = await getDefaultVpc();

  const sgId = await createOrGetSecurityGroup(vpcId);

  const [databaseUrl, ecrUri, accessRoleArn, instanceRoleArn] = await Promise.all([
    createOrGetRdsInstance(sgId),
    createEcrRepo(),
    createAppRunnerAccessRole(),
    createAppRunnerInstanceRole(),
  ]);

  const vpcConnectorArn = await createOrGetVpcConnector(subnetIds, sgId);

  const serviceUrl = await createAppRunnerService(
    ecrUri,
    accessRoleArn,
    instanceRoleArn,
    vpcConnectorArn,
    databaseUrl,
    sessionSecret,
  );

  log("");
  log("=== Deployment Summary ===");
  log(`App URL: ${serviceUrl}`);
  log(`ECR Repository: ${ecrUri}`);
  log(`Database: ${DB_INSTANCE_ID}`);
  log(`Region: ${REGION}`);
  log("");
  log("=== Next Steps ===");
  log("1. Build and push Docker image to ECR:");
  log(`   docker build -t ${ecrUri}:latest .`);
  log(`   aws ecr get-login-password --region ${REGION} | docker login --username AWS --password-stdin ${ecrUri.split('/')[0]}`);
  log(`   docker push ${ecrUri}:latest`);
  log("");
  log("2. Run database migrations:");
  log(`   DATABASE_URL="${databaseUrl}" npx drizzle-kit push`);
  log("");
  log("3. App Runner will auto-deploy when new images are pushed to ECR");
  log("");
  log("=== Environment Variables Set ===");
  log("NODE_ENV=production");
  log("PORT=5000");
  log("DATABASE_URL=<configured>");
  log("SESSION_SECRET=<configured>");
  log(`AWS_REGION=${REGION}`);
}

main().catch((err) => {
  logError("Deployment failed", err);
  process.exit(1);
});
