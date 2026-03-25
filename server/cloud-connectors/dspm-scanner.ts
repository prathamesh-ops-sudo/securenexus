/**
 * DSPM (Data Security Posture Management) Scanner
 * Discovers and classifies sensitive data in cloud storage (S3, Azure Blob, GCS)
 * Scans object metadata, names, and samples for PII, PHI, PCI, credentials
 */

import {
  S3Client,
  ListBucketsCommand,
  ListObjectsV2Command,
  GetObjectCommand,
  HeadObjectCommand,
} from "@aws-sdk/client-s3";

import type { AwsConnectorConfig } from "./aws";
import { logger } from "../logger";

const log = logger.child("dspm-scanner");

export interface DspmFinding {
  resourceId: string;
  resourceType: string;
  region: string;
  dataClassification: string;
  sensitivityLevel: "critical" | "high" | "medium" | "low";
  dataCategories: string[];
  objectCount: number;
  sampleObjects: string[];
  description: string;
  remediation: string;
  detectedAt: Date;
}

export interface DspmScanResult {
  accountId: string;
  provider: string;
  totalBuckets: number;
  totalObjects: number;
  sensitiveObjects: number;
  findings: DspmFinding[];
  scannedAt: Date;
}

/** File extension patterns indicating sensitive data */
const SENSITIVE_EXTENSIONS: Record<
  string,
  { classification: string; categories: string[]; sensitivity: DspmFinding["sensitivityLevel"] }
> = {
  ".pem": { classification: "Credential", categories: ["credentials", "pki"], sensitivity: "critical" },
  ".key": { classification: "Private Key", categories: ["credentials", "pki"], sensitivity: "critical" },
  ".pfx": { classification: "Certificate Bundle", categories: ["credentials", "pki"], sensitivity: "critical" },
  ".p12": { classification: "Certificate", categories: ["credentials", "pki"], sensitivity: "critical" },
  ".env": { classification: "Environment Variables", categories: ["credentials", "config"], sensitivity: "critical" },
  ".credentials": { classification: "Credentials File", categories: ["credentials"], sensitivity: "critical" },
  ".htpasswd": { classification: "Password File", categories: ["credentials"], sensitivity: "critical" },
  ".sql": { classification: "Database Dump", categories: ["database", "pii"], sensitivity: "high" },
  ".bak": { classification: "Backup File", categories: ["backup"], sensitivity: "high" },
  ".dump": { classification: "Database Dump", categories: ["database", "pii"], sensitivity: "high" },
  ".csv": { classification: "Tabular Data", categories: ["data"], sensitivity: "medium" },
  ".xlsx": { classification: "Spreadsheet", categories: ["data"], sensitivity: "medium" },
  ".json": { classification: "JSON Data", categories: ["data"], sensitivity: "low" },
  ".log": { classification: "Log File", categories: ["logs"], sensitivity: "low" },
};

/** Filename patterns indicating sensitive content */
const SENSITIVE_NAME_PATTERNS: Array<{
  pattern: RegExp;
  classification: string;
  categories: string[];
  sensitivity: DspmFinding["sensitivityLevel"];
}> = [
  { pattern: /password/i, classification: "Password File", categories: ["credentials"], sensitivity: "critical" },
  { pattern: /secret/i, classification: "Secrets File", categories: ["credentials"], sensitivity: "critical" },
  { pattern: /api[_-]?key/i, classification: "API Key File", categories: ["credentials"], sensitivity: "critical" },
  { pattern: /token/i, classification: "Token File", categories: ["credentials"], sensitivity: "critical" },
  {
    pattern: /private[_-]?key/i,
    classification: "Private Key",
    categories: ["credentials", "pki"],
    sensitivity: "critical",
  },
  { pattern: /credential/i, classification: "Credentials", categories: ["credentials"], sensitivity: "critical" },
  { pattern: /ssn|social[_-]?security/i, classification: "SSN Data", categories: ["pii"], sensitivity: "critical" },
  {
    pattern: /credit[_-]?card|cc[_-]?num/i,
    classification: "Credit Card Data",
    categories: ["pci"],
    sensitivity: "critical",
  },
  {
    pattern: /patient|medical|health|hipaa/i,
    classification: "Healthcare Data",
    categories: ["phi"],
    sensitivity: "critical",
  },
  { pattern: /passport/i, classification: "Passport Data", categories: ["pii"], sensitivity: "critical" },
  { pattern: /customer|user[_-]?data|pii/i, classification: "Customer PII", categories: ["pii"], sensitivity: "high" },
  {
    pattern: /employee|hr[_-]?data|payroll/i,
    classification: "Employee Data",
    categories: ["pii"],
    sensitivity: "high",
  },
  {
    pattern: /financial|invoice|billing/i,
    classification: "Financial Data",
    categories: ["financial"],
    sensitivity: "high",
  },
  { pattern: /backup|export|dump/i, classification: "Data Export", categories: ["backup"], sensitivity: "high" },
  { pattern: /config|setting/i, classification: "Configuration", categories: ["config"], sensitivity: "medium" },
  {
    pattern: /terraform|cloudformation|ansible/i,
    classification: "IaC Template",
    categories: ["iac", "config"],
    sensitivity: "medium",
  },
];

/** Content patterns for sampling (regex patterns to detect in file content) */
const CONTENT_PATTERNS: Array<{
  pattern: RegExp;
  classification: string;
  categories: string[];
  sensitivity: DspmFinding["sensitivityLevel"];
}> = [
  { pattern: /\b\d{3}-\d{2}-\d{4}\b/, classification: "SSN", categories: ["pii"], sensitivity: "critical" },
  {
    pattern: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/,
    classification: "Credit Card Number",
    categories: ["pci"],
    sensitivity: "critical",
  },
  {
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/,
    classification: "Email Address",
    categories: ["pii"],
    sensitivity: "medium",
  },
  {
    pattern: /AKIA[0-9A-Z]{16}/,
    classification: "AWS Access Key",
    categories: ["credentials"],
    sensitivity: "critical",
  },
  {
    pattern: /-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----/,
    classification: "Private Key",
    categories: ["credentials", "pki"],
    sensitivity: "critical",
  },
  {
    pattern: /ghp_[A-Za-z0-9_]{36,}/,
    classification: "GitHub Token",
    categories: ["credentials"],
    sensitivity: "critical",
  },
  {
    pattern: /sk-[A-Za-z0-9]{48,}/,
    classification: "API Secret Key",
    categories: ["credentials"],
    sensitivity: "critical",
  },
];

export class DspmScanner {
  /** Scan AWS S3 buckets for sensitive data */
  async scanAwsS3(config: AwsConnectorConfig): Promise<DspmScanResult> {
    const findings: DspmFinding[] = [];
    let totalBuckets = 0;
    let totalObjects = 0;
    let sensitiveObjects = 0;

    const credentials =
      config.accessKeyId && config.secretAccessKey
        ? { accessKeyId: config.accessKeyId, secretAccessKey: config.secretAccessKey }
        : undefined;

    const s3Client = new S3Client({
      region: config.regions[0] || "us-east-1",
      ...(credentials ? { credentials } : {}),
    });

    try {
      const bucketsResp = await s3Client.send(new ListBucketsCommand({}));
      const buckets = bucketsResp.Buckets || [];
      totalBuckets = buckets.length;

      // Group findings by bucket
      const bucketFindings = new Map<
        string,
        {
          classifications: Set<string>;
          categories: Set<string>;
          sensitivity: DspmFinding["sensitivityLevel"];
          sampleObjects: string[];
          count: number;
        }
      >();

      for (const bucket of buckets) {
        const bucketName = bucket.Name || "unknown";

        try {
          // List objects (first 1000) to scan for sensitive patterns
          const objectsResp = await s3Client.send(
            new ListObjectsV2Command({
              Bucket: bucketName,
              MaxKeys: 1000,
            }),
          );

          const objects = objectsResp.Contents || [];
          totalObjects += objects.length;

          for (const obj of objects) {
            const key = obj.Key || "";
            const match = classifyObjectByName(key);

            if (match) {
              sensitiveObjects++;
              const existing = bucketFindings.get(bucketName);

              if (existing) {
                existing.classifications.add(match.classification);
                for (const cat of match.categories) existing.categories.add(cat);
                if (severityRank(match.sensitivity) > severityRank(existing.sensitivity)) {
                  existing.sensitivity = match.sensitivity;
                }
                if (existing.sampleObjects.length < 5) {
                  existing.sampleObjects.push(key);
                }
                existing.count++;
              } else {
                bucketFindings.set(bucketName, {
                  classifications: new Set([match.classification]),
                  categories: new Set(match.categories),
                  sensitivity: match.sensitivity,
                  sampleObjects: [key],
                  count: 1,
                });
              }
            }
          }

          // Sample first few text-like objects for content scanning
          const textObjects = objects
            .filter((o) => {
              const key = o.Key || "";
              return (
                key.endsWith(".txt") ||
                key.endsWith(".csv") ||
                key.endsWith(".json") ||
                key.endsWith(".log") ||
                key.endsWith(".env") ||
                key.endsWith(".yml") ||
                key.endsWith(".yaml") ||
                key.endsWith(".xml") ||
                key.endsWith(".conf") ||
                key.endsWith(".cfg")
              );
            })
            .slice(0, 5);

          for (const obj of textObjects) {
            try {
              const getResp = await s3Client.send(
                new GetObjectCommand({
                  Bucket: bucketName,
                  Key: obj.Key,
                  Range: "bytes=0-4096", // Only read first 4KB
                }),
              );
              const body = await getResp.Body?.transformToString();
              if (body) {
                const contentMatch = classifyByContent(body);
                if (contentMatch) {
                  sensitiveObjects++;
                  const existing = bucketFindings.get(bucketName);
                  if (existing) {
                    existing.classifications.add(contentMatch.classification);
                    for (const cat of contentMatch.categories) existing.categories.add(cat);
                    if (severityRank(contentMatch.sensitivity) > severityRank(existing.sensitivity)) {
                      existing.sensitivity = contentMatch.sensitivity;
                    }
                    if (existing.sampleObjects.length < 5) {
                      existing.sampleObjects.push(obj.Key || "");
                    }
                    existing.count++;
                  } else {
                    bucketFindings.set(bucketName, {
                      classifications: new Set([contentMatch.classification]),
                      categories: new Set(contentMatch.categories),
                      sensitivity: contentMatch.sensitivity,
                      sampleObjects: [obj.Key || ""],
                      count: 1,
                    });
                  }
                }
              }
            } catch {
              // Skip individual object read errors
            }
          }
        } catch (err: unknown) {
          log.error("Error scanning bucket", { bucketName, error: err instanceof Error ? err.message : String(err) });
        }
      }

      // Convert grouped findings to DspmFinding objects
      for (const [bucketName, data] of Array.from(bucketFindings.entries())) {
        findings.push({
          resourceId: `arn:aws:s3:::${bucketName}`,
          resourceType: "aws:s3:bucket",
          region: config.regions[0] || "us-east-1",
          dataClassification: Array.from(data.classifications).join(", "),
          sensitivityLevel: data.sensitivity,
          dataCategories: Array.from(data.categories),
          objectCount: data.count,
          sampleObjects: data.sampleObjects,
          description: `S3 bucket '${bucketName}' contains ${data.count} potentially sensitive object(s) classified as: ${Array.from(data.classifications).join(", ")}.`,
          remediation: `Review the ${data.count} flagged objects in bucket '${bucketName}'. Apply appropriate encryption, access controls, and data retention policies. Consider using S3 Object Lock for compliance-sensitive data.`,
          detectedAt: new Date(),
        });
      }
    } catch (err: unknown) {
      log.error("S3 scan error", { error: err instanceof Error ? err.message : String(err) });
    }

    return {
      accountId: "aws",
      provider: "aws",
      totalBuckets,
      totalObjects,
      sensitiveObjects,
      findings,
      scannedAt: new Date(),
    };
  }
}

// Helper functions

function classifyObjectByName(key: string): {
  classification: string;
  categories: string[];
  sensitivity: DspmFinding["sensitivityLevel"];
} | null {
  const fileName = key.split("/").pop() || key;

  // Check extension
  for (const [ext, info] of Object.entries(SENSITIVE_EXTENSIONS)) {
    if (fileName.toLowerCase().endsWith(ext)) {
      return info;
    }
  }

  // Check name patterns
  for (const { pattern, classification, categories, sensitivity } of SENSITIVE_NAME_PATTERNS) {
    if (pattern.test(fileName)) {
      return { classification, categories, sensitivity };
    }
  }

  return null;
}

function classifyByContent(content: string): {
  classification: string;
  categories: string[];
  sensitivity: DspmFinding["sensitivityLevel"];
} | null {
  for (const { pattern, classification, categories, sensitivity } of CONTENT_PATTERNS) {
    if (pattern.test(content)) {
      return { classification, categories, sensitivity };
    }
  }
  return null;
}

function severityRank(severity: DspmFinding["sensitivityLevel"]): number {
  switch (severity) {
    case "critical":
      return 4;
    case "high":
      return 3;
    case "medium":
      return 2;
    case "low":
      return 1;
    default:
      return 0;
  }
}
