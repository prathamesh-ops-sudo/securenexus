import { logger } from "./logger";
import { config } from "./config";

export interface SecretEntry {
  name: string;
  source: "env" | "secrets_manager" | "k8s_secret";
  lastRotated: Date | null;
  rotationIntervalDays: number;
  owner: string;
  verifyFn?: () => Promise<boolean>;
}

export interface RotationResult {
  name: string;
  status: "ok" | "due" | "overdue" | "unverified";
  daysSinceRotation: number | null;
  nextRotationDate: Date | null;
  message: string;
}

const SECRET_REGISTRY: SecretEntry[] = [
  {
    name: "SESSION_SECRET",
    source: "secrets_manager",
    lastRotated: null,
    rotationIntervalDays: 90,
    owner: "platform-team",
    verifyFn: async () => {
      return typeof config.session.secret === "string" && config.session.secret.length >= 32;
    },
  },
  {
    name: "DATABASE_URL",
    source: "secrets_manager",
    lastRotated: null,
    rotationIntervalDays: 90,
    owner: "platform-team",
    verifyFn: async () => {
      return typeof config.databaseUrl === "string" && config.databaseUrl.startsWith("postgres");
    },
  },
  {
    name: "AWS_ACCESS_KEY_ID",
    source: "secrets_manager",
    lastRotated: null,
    rotationIntervalDays: 90,
    owner: "infra-team",
    verifyFn: async () => {
      const { getCredentialMode } = await import("./aws-credentials");
      if (getCredentialMode() === "irsa") return true;
      return !config.aws.accessKeyId || config.aws.accessKeyId.startsWith("AKIA");
    },
  },
  {
    name: "AWS_SECRET_ACCESS_KEY",
    source: "secrets_manager",
    lastRotated: null,
    rotationIntervalDays: 90,
    owner: "infra-team",
    verifyFn: async () => {
      const { getCredentialMode } = await import("./aws-credentials");
      return getCredentialMode() === "irsa" || !!config.aws.secretAccessKey;
    },
  },
  {
    name: "GOOGLE_CLIENT_SECRET",
    source: "secrets_manager",
    lastRotated: null,
    rotationIntervalDays: 180,
    owner: "platform-team",
    verifyFn: async () => {
      return !config.oauth.google.clientId || !!config.oauth.google.clientSecret;
    },
  },
  {
    name: "GITHUB_CLIENT_SECRET",
    source: "secrets_manager",
    lastRotated: null,
    rotationIntervalDays: 180,
    owner: "platform-team",
    verifyFn: async () => {
      return !config.oauth.github.clientId || !!config.oauth.github.clientSecret;
    },
  },
  {
    name: "GITHUB_TOKEN",
    source: "secrets_manager",
    lastRotated: null,
    rotationIntervalDays: 90,
    owner: "platform-team",
  },
];

const log = logger.child("secret-rotation");

function daysBetween(a: Date, b: Date): number {
  return Math.floor(Math.abs(b.getTime() - a.getTime()) / (1000 * 60 * 60 * 24));
}

export function checkRotationStatus(now: Date = new Date()): RotationResult[] {
  const results: RotationResult[] = [];

  for (const entry of SECRET_REGISTRY) {
    if (!entry.lastRotated) {
      results.push({
        name: entry.name,
        status: "unverified",
        daysSinceRotation: null,
        nextRotationDate: null,
        message: `No rotation history recorded. Owner: ${entry.owner}. Rotate immediately and record the date.`,
      });
      continue;
    }

    const days = daysBetween(entry.lastRotated, now);
    const nextDate = new Date(entry.lastRotated.getTime() + entry.rotationIntervalDays * 24 * 60 * 60 * 1000);
    const overdueThreshold = entry.rotationIntervalDays * 1.2;

    let status: RotationResult["status"];
    let message: string;

    if (days > overdueThreshold) {
      status = "overdue";
      message = `OVERDUE: ${entry.name} was last rotated ${days} days ago (limit: ${entry.rotationIntervalDays}d). Owner: ${entry.owner}. Rotate NOW.`;
    } else if (days > entry.rotationIntervalDays) {
      status = "due";
      message = `DUE: ${entry.name} needs rotation. Last rotated ${days} days ago. Owner: ${entry.owner}.`;
    } else {
      status = "ok";
      message = `OK: ${entry.name} was rotated ${days} days ago. Next rotation by ${nextDate.toISOString().split("T")[0]}.`;
    }

    results.push({
      name: entry.name,
      status,
      daysSinceRotation: days,
      nextRotationDate: nextDate,
      message,
    });
  }

  return results;
}

export async function verifySecrets(): Promise<Array<{ name: string; valid: boolean; error?: string }>> {
  const results: Array<{ name: string; valid: boolean; error?: string }> = [];

  for (const entry of SECRET_REGISTRY) {
    if (!entry.verifyFn) {
      results.push({ name: entry.name, valid: true });
      continue;
    }

    try {
      const valid = await entry.verifyFn();
      results.push({ name: entry.name, valid });
      if (!valid) {
        log.warn(`Secret verification failed for ${entry.name}`, { owner: entry.owner });
      }
    } catch (err) {
      results.push({ name: entry.name, valid: false, error: String(err) });
      log.error(`Secret verification error for ${entry.name}`, { error: String(err) });
    }
  }

  return results;
}

export function getRotationRunbook(secretName: string): string {
  const runbooks: Record<string, string> = {
    SESSION_SECRET: [
      "1. Generate a new 64-character random hex string: openssl rand -hex 32",
      "2. Update the secret in AWS Secrets Manager: securenexus/staging, securenexus/uat, securenexus/production",
      "3. Trigger a rolling restart of all pods: kubectl rollout restart deployment/securenexus -n <namespace>",
      "4. Verify active sessions still work (existing sessions will be invalidated)",
      "5. Monitor error rates for 15 minutes post-rotation",
      "6. Update the lastRotated date in the secret registry",
    ].join("\n"),
    DATABASE_URL: [
      "1. Create a new RDS user with the same permissions as the current user",
      "2. Update the DATABASE_URL in AWS Secrets Manager with the new credentials",
      "3. Deploy with rolling restart to pick up new credentials",
      "4. Verify database connectivity via /api/ops/health",
      "5. After confirming all pods use new credentials, drop the old user",
      "6. Update the lastRotated date in the secret registry",
    ].join("\n"),
    AWS_ACCESS_KEY_ID: [
      "PREFERRED: Migrate to IRSA (IAM Roles for Service Accounts) and remove static keys entirely.",
      "  - Annotate the K8s ServiceAccount with eks.amazonaws.com/role-arn",
      "  - Remove AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY from Secrets Manager",
      "  - The SDK credential chain will automatically use the pod's IRSA role",
      "",
      "LEGACY (if still using static keys):",
      "1. Create a new IAM access key for the service account in AWS Console",
      "2. Update AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in Secrets Manager",
      "3. Deploy with rolling restart",
      "4. Verify S3 and Bedrock operations work via health check",
      "5. Deactivate the old access key in IAM",
      "6. After 24h with no errors, delete the old access key",
      "7. Update the lastRotated date in the secret registry",
    ].join("\n"),
    AWS_SECRET_ACCESS_KEY: [
      "Same runbook as AWS_ACCESS_KEY_ID — these must be rotated together.",
      "Prefer IRSA migration over key rotation.",
    ].join("\n"),
    GOOGLE_CLIENT_SECRET: [
      "1. Go to Google Cloud Console > APIs & Services > Credentials",
      "2. Create a new OAuth 2.0 client secret for the existing client ID",
      "3. Update GOOGLE_CLIENT_SECRET in AWS Secrets Manager",
      "4. Deploy with rolling restart",
      "5. Test Google OAuth login flow end-to-end",
      "6. Delete the old client secret from Google Cloud Console",
      "7. Update the lastRotated date in the secret registry",
    ].join("\n"),
    GITHUB_CLIENT_SECRET: [
      "1. Go to GitHub > Settings > Developer settings > OAuth Apps",
      "2. Generate a new client secret",
      "3. Update GITHUB_CLIENT_SECRET in AWS Secrets Manager",
      "4. Deploy with rolling restart",
      "5. Test GitHub OAuth login flow end-to-end",
      "6. The old secret is automatically invalidated when a new one is generated",
      "7. Update the lastRotated date in the secret registry",
    ].join("\n"),
    GITHUB_TOKEN: [
      "1. Go to GitHub > Settings > Developer settings > Personal access tokens",
      "2. Generate a new fine-grained token with the same permissions",
      "3. Update GITHUB_TOKEN in AWS Secrets Manager",
      "4. Deploy with rolling restart",
      "5. Revoke the old token",
      "6. Update the lastRotated date in the secret registry",
    ].join("\n"),
  };

  return runbooks[secretName] ?? `No runbook available for ${secretName}. Contact the platform team.`;
}

export function logRotationAudit(): void {
  const results = checkRotationStatus();
  const overdue = results.filter(r => r.status === "overdue");
  const due = results.filter(r => r.status === "due");
  const unverified = results.filter(r => r.status === "unverified");

  if (overdue.length > 0) {
    log.error("Secret rotation OVERDUE", {
      count: overdue.length,
      secrets: overdue.map(r => r.name),
    });
  }

  if (due.length > 0) {
    log.warn("Secrets due for rotation", {
      count: due.length,
      secrets: due.map(r => r.name),
    });
  }

  if (unverified.length > 0) {
    log.warn("Secrets with no rotation history", {
      count: unverified.length,
      secrets: unverified.map(r => r.name),
    });
  }

  const ok = results.filter(r => r.status === "ok");
  if (ok.length > 0) {
    log.info("Secrets rotation status OK", {
      count: ok.length,
      secrets: ok.map(r => r.name),
    });
  }
}

let rotationCheckInterval: ReturnType<typeof setInterval> | null = null;

export function startRotationScheduler(intervalHours: number = 24): void {
  logRotationAudit();

  rotationCheckInterval = setInterval(() => {
    logRotationAudit();
  }, intervalHours * 60 * 60 * 1000);

  log.info("Secret rotation scheduler started", { intervalHours });
}

export function stopRotationScheduler(): void {
  if (rotationCheckInterval) {
    clearInterval(rotationCheckInterval);
    rotationCheckInterval = null;
    log.info("Secret rotation scheduler stopped");
  }
}
