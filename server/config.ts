import { z } from "zod";

const nodeEnvSchema = z.enum(["development", "staging", "uat", "production", "test"]).default("development");
const aiBackendSchema = z.enum(["bedrock", "sagemaker"]).default("bedrock");

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
    console.error(
      `\n[Config] Fatal: invalid configuration.\n${errors.join("\n")}\n`
    );
    process.exit(1);
  }

  return result.data;
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
 * *  AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY are only needed when
 *    NOT running on EKS with IRSA (IAM Roles for Service Accounts).
 *    On EKS the SDK picks up credentials from the pod's service account.
 *
 * ** SAGEMAKER_ENDPOINT / SAGEMAKER_TRIAGE_ENDPOINT are required only
 *    when AI_BACKEND is set to "sagemaker".
 */
