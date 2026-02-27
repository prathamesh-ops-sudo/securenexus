import { buildOpenApiSpec } from "../server/openapi";

const MIN_PATHS = 100;
const MIN_OPERATIONS = 150;

interface PathItem {
  get?: { operationId?: string; responses?: Record<string, unknown>; security?: unknown[] };
  post?: { operationId?: string; responses?: Record<string, unknown>; security?: unknown[] };
  put?: { operationId?: string; responses?: Record<string, unknown>; security?: unknown[] };
  patch?: { operationId?: string; responses?: Record<string, unknown>; security?: unknown[] };
  delete?: { operationId?: string; responses?: Record<string, unknown>; security?: unknown[] };
}

function validate(): void {
  const spec = buildOpenApiSpec();
  const paths = spec.paths as Record<string, PathItem>;
  const errors: string[] = [];
  const warnings: string[] = [];

  const pathCount = Object.keys(paths).length;
  if (pathCount < MIN_PATHS) {
    errors.push(`OpenAPI spec has only ${pathCount} paths, minimum required is ${MIN_PATHS}`);
  }

  let operationCount = 0;
  const operationIds = new Set<string>();
  const methods = ["get", "post", "put", "patch", "delete"] as const;

  for (const [path, pathItem] of Object.entries(paths)) {
    for (const method of methods) {
      const operation = pathItem[method];
      if (!operation) continue;
      operationCount++;

      if (!operation.operationId) {
        errors.push(`${method.toUpperCase()} ${path}: missing operationId`);
      } else if (operationIds.has(operation.operationId)) {
        errors.push(`Duplicate operationId: ${operation.operationId}`);
      } else {
        operationIds.add(operation.operationId);
      }

      if (!operation.responses || Object.keys(operation.responses).length === 0) {
        errors.push(`${method.toUpperCase()} ${path}: missing responses`);
      }

      const hasAuth = operation.security !== undefined;
      if (
        !hasAuth &&
        !path.includes("health") &&
        !path.includes("version-policy") &&
        !path.includes("migration-guide") &&
        !path.includes("pagination-contract") &&
        !path.includes("/api/v1/status")
      ) {
        warnings.push(`${method.toUpperCase()} ${path}: no explicit security defined (inherits global)`);
      }
    }
  }

  if (operationCount < MIN_OPERATIONS) {
    errors.push(`OpenAPI spec has only ${operationCount} operations, minimum required is ${MIN_OPERATIONS}`);
  }

  const info = spec.info as Record<string, unknown>;
  if (!info.title) errors.push("Missing spec title");
  if (!info.version) errors.push("Missing spec version");

  const components = spec.components as Record<string, unknown>;
  if (!components?.securitySchemes) errors.push("Missing security schemes");

  console.log(`OpenAPI Validation Results:`);
  console.log(`  Paths: ${pathCount}`);
  console.log(`  Operations: ${operationCount}`);
  console.log(`  Unique operationIds: ${operationIds.size}`);
  console.log(`  Version: ${info.version}`);

  if (warnings.length > 0) {
    console.log(`\n  Warnings (${warnings.length}):`);
    for (const w of warnings.slice(0, 10)) console.log(`    - ${w}`);
    if (warnings.length > 10) console.log(`    ... and ${warnings.length - 10} more`);
  }

  if (errors.length > 0) {
    console.error(`\n  ERRORS (${errors.length}):`);
    for (const e of errors) console.error(`    - ${e}`);
    process.exit(1);
  }

  console.log(`\n  PASSED: OpenAPI spec is complete and consistent.`);
}

validate();
