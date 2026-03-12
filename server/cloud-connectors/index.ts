/**
 * Cloud Connectors Index
 * Unified interface for multi-cloud CSPM scanning
 */

export type { CloudFinding, CloudResource, AwsConnectorConfig } from "./aws";
export {
  validateAwsCredentials,
  runAwsScan,
  scanS3Buckets,
  scanEC2SecurityGroups,
  scanEBSVolumes,
  scanIAMUsers,
  scanRDSInstances,
  scanVPCFlowLogs,
  fetchGuardDutyFindings,
  discoverEC2Instances,
} from "./aws";

export type { AzureConnectorConfig } from "./azure";
export {
  validateAzureCredentials,
  runAzureScan,
  scanAzureDefender,
  scanAzurePolicy,
  scanAzureStorage,
  scanAzureNSGs,
} from "./azure";

export type { GcpConnectorConfig } from "./gcp";
export {
  validateGcpCredentials,
  runGcpScan,
  scanGcpSCC,
  scanGcpFirewalls,
  scanGcpStorage,
  scanGcpCloudSQL,
} from "./gcp";

export { DriftDetector } from "./drift-detector";
export { DspmScanner } from "./dspm-scanner";
export { AttackPathAnalyzer } from "./attack-path-analyzer";
export { RemediationEngine } from "./remediation-engine";
