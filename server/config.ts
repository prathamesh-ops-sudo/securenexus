import { z } from "zod";
import { logger } from "./logger";

const nodeEnvSchema = z.enum(["development", "staging", "uat", "production", "test"]).default("development");
const aiBackendSchema = z.enum(["bedrock", "sagemaker"]).default("bedrock");

const PRODUCTION_ENVS = new Set(["production", "staging", "uat"]);

const configSchema = z.object({
  nodeEnv: nodeEnvSchema,
  port: z.coerce.number().int().positive().default(5000),

  databaseUrl: z.string().min(1, "DATABASE_URL is required"),

  session: z.object({
    secret: z.string().min(1, "SESSION_SECRET is required"),
    forceHttps: z.boolean().default(false),
  }),

  aws: z.object({
    region: z.string().min(1).default("us-east-1"),
    accessKeyId: z.string().optional(),
    secretAccessKey: z.string().optional(),
    s3BucketName: z.string().min(1, "S3_BUCKET_NAME is required"),
  }),

  ai: z.object({
    backend: aiBackendSchema,
    modelId: z.string().default("mistral.mistral-large-2402-v1:0"),
    sagemakerEndpoint: z.string().optional(),
    maxTokens: z.coerce.number().int().positive().default(4096),
    temperature: z.coerce.number().min(0).max(2).default(0.1),
    topP: z.coerce.number().min(0).max(1).default(0.9),
    triage: z.object({
      modelId: z.string().default("mistral.mistral-large-2402-v1:0"),
      sagemakerEndpoint: z.string().optional(),
      maxTokens: z.coerce.number().int().positive().default(2048),
      temperature: z.coerce.number().min(0).max(2).default(0.05),
    }),
  }),

  oauth: z.object({
    google: z.object({
      clientId: z.string().optional(),
      clientSecret: z.string().optional(),
      callbackUrl: z.string().default("/api/auth/google/callback"),
    }),
    github: z.object({
      clientId: z.string().optional(),
      clientSecret: z.string().optional(),
      callbackUrl: z.string().default("/api/auth/github/callback"),
    }),
    cognitoUserPoolId: z.string().optional(),
  }),

  githubToken: z.string().optional(),
});

export type AppConfig = z.infer<typeof configSchema>;

function loadConfig(): AppConfig {
  const env = process.env;

  const raw = {
    nodeEnv: env.NODE_ENV,
    port: env.PORT,
    databaseUrl: env.DATABASE_URL,
    session: {
      secret: env.SESSION_SECRET,
      forceHttps: env.FORCE_HTTPS === "true",
    },
    aws: {
      region: env.AWS_REGION,
      accessKeyId: env.AWS_ACCESS_KEY_ID || undefined,
      secretAccessKey: env.AWS_SECRET_ACCESS_KEY || undefined,
      s3BucketName: env.S3_BUCKET_NAME,
    },
    ai: {
      backend: env.AI_BACKEND,
      modelId: env.AI_MODEL_ID,
      sagemakerEndpoint: env.SAGEMAKER_ENDPOINT || undefined,
      maxTokens: env.AI_MAX_TOKENS,
      temperature: env.AI_TEMPERATURE,
      topP: env.AI_TOP_P,
      triage: {
        modelId: env.AI_TRIAGE_MODEL_ID,
        sagemakerEndpoint: env.SAGEMAKER_TRIAGE_ENDPOINT || undefined,
        maxTokens: env.AI_TRIAGE_MAX_TOKENS,
        temperature: env.AI_TRIAGE_TEMPERATURE,
      },
    },
    oauth: {
      google: {
        clientId: env.GOOGLE_CLIENT_ID || undefined,
        clientSecret: env.GOOGLE_CLIENT_SECRET || undefined,
        callbackUrl: env.GOOGLE_CALLBACK_URL,
      },
      github: {
        clientId: env.GITHUB_CLIENT_ID || undefined,
        clientSecret: env.GITHUB_CLIENT_SECRET || undefined,
        callbackUrl: env.GITHUB_CALLBACK_URL,
      },
      cognitoUserPoolId: env.COGNITO_USER_POOL_ID || undefined,
    },
    githubToken: env.GITHUB_TOKEN || undefined,
  };

  const result = configSchema.safeParse(raw);

  if (!result.success) {
    const errors = result.error.issues.map(
      (issue) => `  - ${issue.path.join(".")}: ${issue.message}`
    );
    logger.child("config").error(`\n[Config] Fatal: invalid configuration.\n${errors.join("\n")}\n`);
    process.exit(1);
  }

  const cfg = result.data;
  const warnings: string[] = [];

  if (PRODUCTION_ENVS.has(cfg.nodeEnv)) {
    if (!cfg.session.forceHttps) {
      warnings.push("FORCE_HTTPS is not enabled — cookies will not have the Secure flag");
    }
    if (cfg.session.secret.length < 32) {
      logger.child("config").error("SESSION_SECRET must be at least 32 characters in production environments");
      process.exit(1);
    }
  }

  if (cfg.ai.backend === "sagemaker") {
    if (!cfg.ai.sagemakerEndpoint) {
      logger.child("config").error("SAGEMAKER_ENDPOINT is required when AI_BACKEND=sagemaker");
      process.exit(1);
    }
    if (!cfg.ai.triage.sagemakerEndpoint) {
      warnings.push("SAGEMAKER_TRIAGE_ENDPOINT not set — triage will fail when AI_BACKEND=sagemaker");
    }
  }

  if (cfg.oauth.google.clientId && !cfg.oauth.google.clientSecret) {
    warnings.push("GOOGLE_CLIENT_ID is set but GOOGLE_CLIENT_SECRET is missing — Google OAuth will not work");
  }
  if (cfg.oauth.github.clientId && !cfg.oauth.github.clientSecret) {
    warnings.push("GITHUB_CLIENT_ID is set but GITHUB_CLIENT_SECRET is missing — GitHub OAuth will not work");
  }

  for (const w of warnings) {
    logger.child("config").warn(w);
  }

  return cfg;
}

export const config = loadConfig();

/**
 * ┌─────────────────────────────────────────────────────────────────────┐
 * │                  ENVIRONMENT VARIABLE REFERENCE                     │
 * ├──────────────────────────┬──────────┬──────────────────────────────┤
 * │ Variable                 │ Required │ Description                  │
 * ├──────────────────────────┼──────────┼──────────────────────────────┤
 * │ DATABASE_URL             │ Yes      │ PostgreSQL connection string │
 * │ SESSION_SECRET           │ Yes      │ Session encryption key       │
 * │ S3_BUCKET_NAME           │ Yes      │ AWS S3 bucket for uploads    │
 * │ PORT                     │ No       │ Server port (default 5000)   │
 * │ NODE_ENV                 │ No       │ development|staging|uat|prod │
 * │ FORCE_HTTPS              │ No       │ Set "true" for secure cookie │
 * │ AWS_REGION               │ No       │ AWS region (default us-east-1│
 * │ AWS_ACCESS_KEY_ID        │ No*      │ AWS key (use IRSA on EKS)    │
 * │ AWS_SECRET_ACCESS_KEY    │ No*      │ AWS secret (use IRSA on EKS) │
 * │ AI_BACKEND               │ No       │ bedrock | sagemaker          │
 * │ AI_MODEL_ID              │ No       │ Bedrock model ID             │
 * │ SAGEMAKER_ENDPOINT       │ No**     │ Required when backend=sage.  │
 * │ AI_MAX_TOKENS            │ No       │ Max tokens (default 4096)    │
 * │ AI_TEMPERATURE           │ No       │ Model temp (default 0.1)     │
 * │ AI_TOP_P                 │ No       │ Nucleus sampling (default 0.9│
 * │ AI_TRIAGE_MODEL_ID       │ No       │ Triage model ID              │
 * │ SAGEMAKER_TRIAGE_ENDPOINT│ No**     │ Required when backend=sage.  │
 * │ AI_TRIAGE_MAX_TOKENS     │ No       │ Triage max tokens (def 2048) │
 * │ AI_TRIAGE_TEMPERATURE    │ No       │ Triage temp (default 0.05)   │
 * │ GOOGLE_CLIENT_ID         │ No       │ Google OAuth client ID       │
 * │ GOOGLE_CLIENT_SECRET     │ No       │ Google OAuth client secret   │
 * │ GOOGLE_CALLBACK_URL      │ No       │ Google OAuth callback path   │
 * │ GITHUB_CLIENT_ID         │ No       │ GitHub OAuth client ID       │
 * │ GITHUB_CLIENT_SECRET     │ No       │ GitHub OAuth client secret   │
 * │ GITHUB_CALLBACK_URL      │ No       │ GitHub OAuth callback path   │
 * │ COGNITO_USER_POOL_ID     │ No       │ AWS Cognito user pool ID     │
 * │ GITHUB_TOKEN             │ No       │ GitHub API token             │
 * └──────────────────────────┴──────────┴──────────────────────────────┘
 *
 * *  AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY are DEPRECATED for EKS.
 *    Use IRSA (IAM Roles for Service Accounts) instead. The SDK
 *    automatically picks up credentials from the pod's service account
 *    via the default credential chain. Static keys are only needed
 *    for local development outside AWS.
 *
 * ** SAGEMAKER_ENDPOINT / SAGEMAKER_TRIAGE_ENDPOINT are required only
 *    when AI_BACKEND is set to "sagemaker".
 */
