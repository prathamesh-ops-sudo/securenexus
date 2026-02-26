import { fromNodeProviderChain } from "@aws-sdk/credential-providers";
import type { AwsCredentialIdentityProvider } from "@aws-sdk/types";
import { config } from "./config";
import { logger } from "./logger";

const log = logger.child("aws-credentials");

const CREDENTIAL_MODE: "static" | "irsa" =
  config.aws.accessKeyId && config.aws.secretAccessKey ? "static" : "irsa";

if (CREDENTIAL_MODE === "static") {
  log.warn(
    "Using static AWS credentials (AWS_ACCESS_KEY_ID). Migrate to IRSA for EKS workloads to reduce blast radius.",
  );
} else {
  log.info("Using default credential chain (IRSA / instance profile / env).");
}

const sharedCredentialProvider: AwsCredentialIdentityProvider = fromNodeProviderChain({
  clientConfig: { region: config.aws.region },
});

export function getAwsCredentialProvider(): AwsCredentialIdentityProvider {
  return sharedCredentialProvider;
}

export function getCredentialMode(): "static" | "irsa" {
  return CREDENTIAL_MODE;
}

export function getAwsClientConfig(regionOverride?: string): {
  region: string;
  credentials: AwsCredentialIdentityProvider;
} {
  return {
    region: regionOverride || config.aws.region,
    credentials: sharedCredentialProvider,
  };
}

export function getConnectorAwsClientConfig(
  connectorRegion?: string,
  connectorAccessKeyId?: string,
  connectorSecretAccessKey?: string,
): { region: string; credentials?: AwsCredentialIdentityProvider | { accessKeyId: string; secretAccessKey: string } } {
  const region = connectorRegion || config.aws.region;
  if (connectorAccessKeyId && connectorSecretAccessKey) {
    return {
      region,
      credentials: {
        accessKeyId: connectorAccessKeyId,
        secretAccessKey: connectorSecretAccessKey,
      },
    };
  }
  return {
    region,
    credentials: sharedCredentialProvider,
  };
}
