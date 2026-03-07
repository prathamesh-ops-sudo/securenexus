import { randomUUID, randomBytes } from "crypto";

export type SecretClassification = "critical" | "high" | "medium" | "low";
export type SecretType =
  | "api_key"
  | "database_credential"
  | "ssh_key"
  | "tls_cert"
  | "oauth_token"
  | "encryption_key"
  | "service_account"
  | "other";
export type AccessRequestStatus = "pending" | "approved" | "denied" | "active" | "released" | "expired" | "revoked";
export type ShareStatus = "active" | "consumed" | "expired" | "revoked";
export type OwnershipAction = "transfer" | "reclaim";
export type BreakGlassStatus = "active" | "expired" | "reviewed" | "revoked";

export interface ManagedSecret {
  id: string;
  orgId: string;
  name: string;
  description: string;
  secretType: SecretType;
  classification: SecretClassification;
  ownerId: string;
  ownerName: string;
  environment: string;
  service: string;
  lastRotatedAt: string;
  rotationIntervalDays: number;
  needsRotation: boolean;
  noPlaintextSharing: boolean;
  accessCount: number;
  activeAccessors: number;
  createdAt: string;
  updatedAt: string;
}

export interface AccessRequest {
  id: string;
  orgId: string;
  secretId: string;
  secretName: string;
  requesterId: string;
  requesterName: string;
  reason: string;
  durationMinutes: number;
  status: AccessRequestStatus;
  approverRole: "manager" | "security" | "owner";
  approvedBy: string | null;
  approvedAt: string | null;
  deniedBy: string | null;
  deniedReason: string | null;
  ephemeralToken: string | null;
  tokenExpiresAt: string | null;
  releasedAt: string | null;
  createdAt: string;
  auditTrail: AuditEntry[];
}

export interface ExternalShare {
  id: string;
  orgId: string;
  secretId: string;
  secretName: string;
  createdBy: string;
  recipientEmail: string;
  shareToken: string;
  expiresAt: string;
  maxUses: number;
  currentUses: number;
  status: ShareStatus;
  noPlaintext: boolean;
  createdAt: string;
  consumedAt: string | null;
  auditTrail: AuditEntry[];
}

export interface OwnershipTransfer {
  id: string;
  orgId: string;
  secretId: string;
  secretName: string;
  fromOwnerId: string;
  fromOwnerName: string;
  toOwnerId: string;
  toOwnerName: string;
  action: OwnershipAction;
  reason: string;
  isOffboarding: boolean;
  initiatedBy: string;
  completedAt: string;
  auditTrail: AuditEntry[];
}

export interface BreakGlassAccess {
  id: string;
  orgId: string;
  secretId: string;
  secretName: string;
  requesterId: string;
  requesterName: string;
  justification: string;
  incidentId: string | null;
  status: BreakGlassStatus;
  ephemeralToken: string;
  expiresAt: string;
  durationMinutes: number;
  retroactiveReviewRequired: boolean;
  reviewedBy: string | null;
  reviewedAt: string | null;
  reviewNotes: string | null;
  createdAt: string;
  auditTrail: AuditEntry[];
}

export interface AuditEntry {
  action: string;
  actor: string;
  timestamp: string;
  details?: string;
}

export interface JitSecretStats {
  totalSecrets: number;
  criticalSecrets: number;
  secretsNeedingRotation: number;
  pendingRequests: number;
  activeAccesses: number;
  activeShares: number;
  breakGlassActive: number;
  pendingReviews: number;
  transfersThisMonth: number;
  accessRequestsToday: number;
  deniedToday: number;
  avgApprovalTimeMinutes: number;
}

function genId(prefix: string): string {
  return `${prefix}-${randomUUID().slice(0, 8)}`;
}

function ephemeralToken(): string {
  return `eph_${randomBytes(24).toString("hex")}`;
}

function shareToken(): string {
  return `shr_${randomBytes(16).toString("hex")}`;
}

const MAX_AUDIT_LOG_SIZE = 10000;

const CATALOG_SECRETS: ManagedSecret[] = [
  {
    id: "js-cat-1",
    orgId: "__catalog__",
    name: "Prod DB Credential (RDS)",
    description: "Primary credential for the PostgreSQL RDS instance. Rotated every 30 days via managed rotation.",
    secretType: "database_credential",
    classification: "critical",
    ownerId: "user-infra-lead",
    ownerName: "Sarah Chen",
    environment: "production",
    service: "core-api",
    lastRotatedAt: "2026-02-20T00:00:00Z",
    rotationIntervalDays: 30,
    needsRotation: false,
    noPlaintextSharing: true,
    accessCount: 47,
    activeAccessors: 2,
    createdAt: "2025-06-15T00:00:00Z",
    updatedAt: "2026-02-20T00:00:00Z",
  },
  {
    id: "js-cat-2",
    orgId: "__catalog__",
    name: "Payment Gateway Credential",
    description: "Production payment processor credential. Restricted to billing service only.",
    secretType: "api_key",
    classification: "critical",
    ownerId: "user-billing-eng",
    ownerName: "Marcus Rivera",
    environment: "production",
    service: "billing-service",
    lastRotatedAt: "2026-01-10T00:00:00Z",
    rotationIntervalDays: 90,
    needsRotation: false,
    noPlaintextSharing: true,
    accessCount: 12,
    activeAccessors: 1,
    createdAt: "2025-09-01T00:00:00Z",
    updatedAt: "2026-01-10T00:00:00Z",
  },
  {
    id: "js-cat-3",
    orgId: "__catalog__",
    name: "CI/CD Deploy Credential",
    description: "Deploy credential used by CI/CD pipeline for production deployments. Read-only access to main repo.",
    secretType: "ssh_key",
    classification: "high",
    ownerId: "user-devops-lead",
    ownerName: "Alex Kim",
    environment: "ci_cd",
    service: "github-actions",
    lastRotatedAt: "2026-03-01T00:00:00Z",
    rotationIntervalDays: 180,
    needsRotation: false,
    noPlaintextSharing: true,
    accessCount: 230,
    activeAccessors: 0,
    createdAt: "2025-04-10T00:00:00Z",
    updatedAt: "2026-03-01T00:00:00Z",
  },
  {
    id: "js-cat-4",
    orgId: "__catalog__",
    name: "Staging OAuth Credential",
    description: "OAuth credential for staging environment SSO integration.",
    secretType: "oauth_token",
    classification: "medium",
    ownerId: "user-frontend-lead",
    ownerName: "Priya Patel",
    environment: "staging",
    service: "auth-service",
    lastRotatedAt: "2025-12-15T00:00:00Z",
    rotationIntervalDays: 90,
    needsRotation: true,
    noPlaintextSharing: false,
    accessCount: 8,
    activeAccessors: 3,
    createdAt: "2025-08-20T00:00:00Z",
    updatedAt: "2025-12-15T00:00:00Z",
  },
  {
    id: "js-cat-5",
    orgId: "__catalog__",
    name: "TLS Wildcard Cert Material",
    description: "Certificate material for *.securenexus.io wildcard TLS. Used by ALB and CloudFront.",
    secretType: "tls_cert",
    classification: "critical",
    ownerId: "user-infra-lead",
    ownerName: "Sarah Chen",
    environment: "production",
    service: "infrastructure",
    lastRotatedAt: "2026-01-01T00:00:00Z",
    rotationIntervalDays: 365,
    needsRotation: false,
    noPlaintextSharing: true,
    accessCount: 5,
    activeAccessors: 0,
    createdAt: "2025-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
  },
  {
    id: "js-cat-6",
    orgId: "__catalog__",
    name: "Data Encryption Material",
    description: "AES-256 material for encrypting PII fields at rest. Wrapped by KMS.",
    secretType: "encryption_key",
    classification: "critical",
    ownerId: "user-security-eng",
    ownerName: "David Okafor",
    environment: "production",
    service: "data-platform",
    lastRotatedAt: "2026-02-01T00:00:00Z",
    rotationIntervalDays: 90,
    needsRotation: false,
    noPlaintextSharing: true,
    accessCount: 3,
    activeAccessors: 0,
    createdAt: "2025-03-15T00:00:00Z",
    updatedAt: "2026-02-01T00:00:00Z",
  },
];

const CATALOG_ACCESS_REQUESTS: AccessRequest[] = [
  {
    id: "jar-cat-1",
    orgId: "__catalog__",
    secretId: "js-cat-1",
    secretName: "Production Database Master Password",
    requesterId: "user-backend-eng",
    requesterName: "Jordan Lee",
    reason:
      "Need to run migration script for v3.2 schema update. Requires direct DB access for ALTER TABLE operations.",
    durationMinutes: 60,
    status: "approved",
    approverRole: "owner",
    approvedBy: "Sarah Chen",
    approvedAt: "2026-03-06T10:15:00Z",
    deniedBy: null,
    deniedReason: null,
    ephemeralToken: "[REDACTED_DEMO_TOKEN]",
    tokenExpiresAt: "2026-03-06T11:15:00Z",
    releasedAt: null,
    createdAt: "2026-03-06T10:00:00Z",
    auditTrail: [
      {
        action: "access_requested",
        actor: "Jordan Lee",
        timestamp: "2026-03-06T10:00:00Z",
        details: "Duration: 60min",
      },
      {
        action: "access_approved",
        actor: "Sarah Chen",
        timestamp: "2026-03-06T10:15:00Z",
        details: "Ephemeral token issued",
      },
    ],
  },
  {
    id: "jar-cat-2",
    orgId: "__catalog__",
    secretId: "js-cat-2",
    secretName: "Payment Gateway Credential",
    requesterId: "user-qa-eng",
    requesterName: "Emma Watson",
    reason: "Testing payment webhook integration in production-like environment.",
    durationMinutes: 30,
    status: "denied",
    approverRole: "security",
    approvedBy: null,
    approvedAt: null,
    deniedBy: "David Okafor",
    deniedReason:
      "QA should use staging credential, not production. Staging environment is available for this purpose.",
    ephemeralToken: null,
    tokenExpiresAt: null,
    releasedAt: null,
    createdAt: "2026-03-05T14:00:00Z",
    auditTrail: [
      { action: "access_requested", actor: "Emma Watson", timestamp: "2026-03-05T14:00:00Z" },
      {
        action: "access_denied",
        actor: "David Okafor",
        timestamp: "2026-03-05T14:30:00Z",
        details: "Use staging credential instead",
      },
    ],
  },
  {
    id: "jar-cat-3",
    orgId: "__catalog__",
    secretId: "js-cat-6",
    secretName: "Data Encryption Material",
    requesterId: "user-data-eng",
    requesterName: "Lisa Zhang",
    reason: "Rotating encryption material for GDPR data deletion batch job.",
    durationMinutes: 120,
    status: "pending",
    approverRole: "security",
    approvedBy: null,
    approvedAt: null,
    deniedBy: null,
    deniedReason: null,
    ephemeralToken: null,
    tokenExpiresAt: null,
    releasedAt: null,
    createdAt: "2026-03-07T02:00:00Z",
    auditTrail: [
      {
        action: "access_requested",
        actor: "Lisa Zhang",
        timestamp: "2026-03-07T02:00:00Z",
        details: "Duration: 120min, Approver: security",
      },
    ],
  },
  {
    id: "jar-cat-4",
    orgId: "__catalog__",
    secretId: "js-cat-3",
    secretName: "CI/CD Deploy Credential",
    requesterId: "user-devops-jr",
    requesterName: "Tom Nguyen",
    reason: "Setting up new deployment pipeline for microservice split.",
    durationMinutes: 240,
    status: "released",
    approverRole: "owner",
    approvedBy: "Alex Kim",
    approvedAt: "2026-03-04T09:00:00Z",
    deniedBy: null,
    deniedReason: null,
    ephemeralToken: "[REDACTED_DEMO_TOKEN]",
    tokenExpiresAt: "2026-03-04T13:00:00Z",
    releasedAt: "2026-03-04T11:30:00Z",
    createdAt: "2026-03-04T08:30:00Z",
    auditTrail: [
      { action: "access_requested", actor: "Tom Nguyen", timestamp: "2026-03-04T08:30:00Z" },
      { action: "access_approved", actor: "Alex Kim", timestamp: "2026-03-04T09:00:00Z" },
      {
        action: "access_released",
        actor: "Tom Nguyen",
        timestamp: "2026-03-04T11:30:00Z",
        details: "Released 1.5h before expiry",
      },
    ],
  },
];

const CATALOG_SHARES: ExternalShare[] = [
  {
    id: "jsh-cat-1",
    orgId: "__catalog__",
    secretId: "js-cat-4",
    secretName: "Staging OAuth Credential",
    createdBy: "Priya Patel",
    recipientEmail: "vendor-sso@integrations.example.com",
    shareToken: "[REDACTED_DEMO_SHARE]",
    expiresAt: "2026-03-08T00:00:00Z",
    maxUses: 1,
    currentUses: 0,
    status: "active",
    noPlaintext: false,
    createdAt: "2026-03-06T16:00:00Z",
    consumedAt: null,
    auditTrail: [
      {
        action: "share_created",
        actor: "Priya Patel",
        timestamp: "2026-03-06T16:00:00Z",
        details: "Recipient: vendor-sso@integrations.example.com, Expires: 24h",
      },
    ],
  },
  {
    id: "jsh-cat-2",
    orgId: "__catalog__",
    secretId: "js-cat-3",
    secretName: "CI/CD Deploy Credential",
    createdBy: "Alex Kim",
    recipientEmail: "contractor@devops-partner.com",
    shareToken: "[REDACTED_DEMO_SHARE]",
    expiresAt: "2026-03-05T12:00:00Z",
    maxUses: 1,
    currentUses: 1,
    status: "consumed",
    noPlaintext: true,
    createdAt: "2026-03-05T08:00:00Z",
    consumedAt: "2026-03-05T09:15:00Z",
    auditTrail: [
      { action: "share_created", actor: "Alex Kim", timestamp: "2026-03-05T08:00:00Z" },
      { action: "share_consumed", actor: "contractor@devops-partner.com", timestamp: "2026-03-05T09:15:00Z" },
    ],
  },
];

const CATALOG_TRANSFERS: OwnershipTransfer[] = [
  {
    id: "jot-cat-1",
    orgId: "__catalog__",
    secretId: "js-cat-2",
    secretName: "Payment Gateway Credential",
    fromOwnerId: "user-departed-eng",
    fromOwnerName: "Chris Morgan (Departed)",
    toOwnerId: "user-billing-eng",
    toOwnerName: "Marcus Rivera",
    action: "reclaim",
    reason: "Employee offboarding — Chris Morgan departed on 2026-01-15. All owned secrets reclaimed by team lead.",
    isOffboarding: true,
    initiatedBy: "HR Automation",
    completedAt: "2026-01-15T17:00:00Z",
    auditTrail: [
      {
        action: "ownership_reclaim_initiated",
        actor: "HR Automation",
        timestamp: "2026-01-15T16:30:00Z",
        details: "Offboarding trigger for Chris Morgan",
      },
      {
        action: "ownership_reclaimed",
        actor: "system",
        timestamp: "2026-01-15T17:00:00Z",
        details: "Transferred to Marcus Rivera (billing-eng lead)",
      },
      {
        action: "rotation_prompted",
        actor: "system",
        timestamp: "2026-01-15T17:00:00Z",
        details: "Rotation required within 24h post-reclaim",
      },
    ],
  },
];

const CATALOG_BREAK_GLASS: BreakGlassAccess[] = [
  {
    id: "jbg-cat-1",
    orgId: "__catalog__",
    secretId: "js-cat-1",
    secretName: "Prod DB Credential (RDS)",
    requesterId: "user-oncall-eng",
    requesterName: "Mike Torres",
    justification:
      "P1 incident INC-2026-0342: Production database connection pool exhausted, need direct access to kill long-running queries and resize pool.",
    incidentId: "INC-2026-0342",
    status: "reviewed",
    ephemeralToken: "[REDACTED_DEMO_TOKEN]",
    expiresAt: "2026-03-02T03:30:00Z",
    durationMinutes: 30,
    retroactiveReviewRequired: true,
    reviewedBy: "Sarah Chen",
    reviewedAt: "2026-03-02T10:00:00Z",
    reviewNotes:
      "Confirmed legitimate P1 response. Connection pool issue verified in CloudWatch. Access was appropriate and minimal.",
    createdAt: "2026-03-02T03:00:00Z",
    auditTrail: [
      {
        action: "break_glass_activated",
        actor: "Mike Torres",
        timestamp: "2026-03-02T03:00:00Z",
        details: "Incident: INC-2026-0342, Duration: 30min",
      },
      { action: "break_glass_expired", actor: "system", timestamp: "2026-03-02T03:30:00Z" },
      {
        action: "break_glass_reviewed",
        actor: "Sarah Chen",
        timestamp: "2026-03-02T10:00:00Z",
        details: "Approved — legitimate P1 response",
      },
    ],
  },
];

const CATALOG_AUDIT: AuditEntry[] = [
  {
    action: "secret_registered",
    actor: "Sarah Chen",
    timestamp: "2026-03-06T08:00:00Z",
    details: "Prod DB Credential (RDS)",
  },
  {
    action: "access_requested",
    actor: "Jordan Lee",
    timestamp: "2026-03-06T10:00:00Z",
    details: "Prod DB Credential (RDS), Duration: 60min",
  },
  {
    action: "access_approved",
    actor: "Sarah Chen",
    timestamp: "2026-03-06T10:15:00Z",
    details: "Ephemeral token issued to Jordan Lee",
  },
  {
    action: "share_created",
    actor: "Priya Patel",
    timestamp: "2026-03-06T16:00:00Z",
    details: "One-time share to vendor-sso@integrations.example.com",
  },
  {
    action: "access_denied",
    actor: "David Okafor",
    timestamp: "2026-03-05T14:30:00Z",
    details: "Denied Emma Watson: use staging credential",
  },
  {
    action: "share_consumed",
    actor: "contractor@devops-partner.com",
    timestamp: "2026-03-05T09:15:00Z",
    details: "CI/CD Deploy Credential share consumed",
  },
  {
    action: "break_glass_activated",
    actor: "Mike Torres",
    timestamp: "2026-03-02T03:00:00Z",
    details: "P1 incident INC-2026-0342",
  },
  {
    action: "break_glass_reviewed",
    actor: "Sarah Chen",
    timestamp: "2026-03-02T10:00:00Z",
    details: "Retroactive review: approved",
  },
  {
    action: "ownership_reclaimed",
    actor: "HR Automation",
    timestamp: "2026-01-15T17:00:00Z",
    details: "Chris Morgan offboarding — payment credential to Marcus Rivera",
  },
  {
    action: "access_released",
    actor: "Tom Nguyen",
    timestamp: "2026-03-04T11:30:00Z",
    details: "Early release of CI/CD Deploy Credential access",
  },
];

const orgSecretStores = new Map<string, Map<string, ManagedSecret>>();
const orgAccessRequestStores = new Map<string, AccessRequest[]>();
const orgShareStores = new Map<string, ExternalShare[]>();
const orgTransferStores = new Map<string, OwnershipTransfer[]>();
const orgBreakGlassStores = new Map<string, BreakGlassAccess[]>();
const orgAuditStores = new Map<string, AuditEntry[]>();

function getOrgSecretStore(orgId: string): Map<string, ManagedSecret> {
  if (!orgSecretStores.has(orgId)) {
    orgSecretStores.set(orgId, new Map());
  }
  return orgSecretStores.get(orgId)!;
}

function getOrgAccessRequestStore(orgId: string): AccessRequest[] {
  if (!orgAccessRequestStores.has(orgId)) {
    orgAccessRequestStores.set(orgId, []);
  }
  return orgAccessRequestStores.get(orgId)!;
}

function getOrgShareStore(orgId: string): ExternalShare[] {
  if (!orgShareStores.has(orgId)) {
    orgShareStores.set(orgId, []);
  }
  return orgShareStores.get(orgId)!;
}

function getOrgTransferStore(orgId: string): OwnershipTransfer[] {
  if (!orgTransferStores.has(orgId)) {
    orgTransferStores.set(orgId, []);
  }
  return orgTransferStores.get(orgId)!;
}

function getOrgBreakGlassStore(orgId: string): BreakGlassAccess[] {
  if (!orgBreakGlassStores.has(orgId)) {
    orgBreakGlassStores.set(orgId, []);
  }
  return orgBreakGlassStores.get(orgId)!;
}

function getOrgAuditStore(orgId: string): AuditEntry[] {
  if (!orgAuditStores.has(orgId)) {
    orgAuditStores.set(orgId, []);
  }
  return orgAuditStores.get(orgId)!;
}

function appendAudit(orgId: string, entry: AuditEntry): void {
  const store = getOrgAuditStore(orgId);
  store.push(entry);
  if (store.length > MAX_AUDIT_LOG_SIZE) {
    store.splice(0, store.length - MAX_AUDIT_LOG_SIZE);
  }
}

export function getSecrets(orgId: string): ManagedSecret[] {
  const store = getOrgSecretStore(orgId);
  const merged = new Map<string, ManagedSecret>();
  for (const s of CATALOG_SECRETS) {
    merged.set(s.id, { ...s, orgId });
  }
  store.forEach((s, id) => {
    merged.set(id, s);
  });
  return Array.from(merged.values());
}

export function getSecretById(orgId: string, secretId: string): ManagedSecret | undefined {
  const store = getOrgSecretStore(orgId);
  if (store.has(secretId)) return store.get(secretId);
  const cat = CATALOG_SECRETS.find((s) => s.id === secretId);
  if (cat) return { ...cat, orgId };
  return undefined;
}

export function registerSecret(
  orgId: string,
  input: {
    name: string;
    description: string;
    secretType: SecretType;
    classification: SecretClassification;
    ownerId: string;
    ownerName: string;
    environment: string;
    service: string;
    rotationIntervalDays: number;
    noPlaintextSharing: boolean;
  },
): ManagedSecret {
  const now = new Date().toISOString();
  const secret: ManagedSecret = {
    id: genId("js"),
    orgId,
    name: input.name,
    description: input.description,
    secretType: input.secretType,
    classification: input.classification,
    ownerId: input.ownerId,
    ownerName: input.ownerName,
    environment: input.environment,
    service: input.service,
    lastRotatedAt: now,
    rotationIntervalDays: input.rotationIntervalDays,
    needsRotation: false,
    noPlaintextSharing: input.noPlaintextSharing,
    accessCount: 0,
    activeAccessors: 0,
    createdAt: now,
    updatedAt: now,
  };
  const store = getOrgSecretStore(orgId);
  store.set(secret.id, secret);

  appendAudit(orgId, {
    action: "secret_registered",
    actor: input.ownerName,
    timestamp: now,
    details: `Registered: ${input.name} (${input.classification})`,
  });

  return secret;
}

export function requestAccess(
  orgId: string,
  input: {
    secretId: string;
    requesterId: string;
    requesterName: string;
    reason: string;
    durationMinutes: number;
    approverRole: "manager" | "security" | "owner";
  },
): AccessRequest {
  const secret = getSecretById(orgId, input.secretId);
  if (!secret) throw new Error("SECRET_NOT_FOUND");

  if (input.durationMinutes < 1 || input.durationMinutes > 1440) {
    throw new Error("INVALID_DURATION");
  }
  if (input.reason.trim().length < 10) {
    throw new Error("REASON_TOO_SHORT");
  }

  const now = new Date().toISOString();
  const request: AccessRequest = {
    id: genId("jar"),
    orgId,
    secretId: input.secretId,
    secretName: secret.name,
    requesterId: input.requesterId,
    requesterName: input.requesterName,
    reason: input.reason,
    durationMinutes: input.durationMinutes,
    status: "pending",
    approverRole: input.approverRole,
    approvedBy: null,
    approvedAt: null,
    deniedBy: null,
    deniedReason: null,
    ephemeralToken: null,
    tokenExpiresAt: null,
    releasedAt: null,
    createdAt: now,
    auditTrail: [
      {
        action: "access_requested",
        actor: input.requesterName,
        timestamp: now,
        details: `Secret: ${secret.name}, Duration: ${input.durationMinutes}min, Approver: ${input.approverRole}`,
      },
    ],
  };

  const store = getOrgAccessRequestStore(orgId);
  store.push(request);
  if (store.length > MAX_AUDIT_LOG_SIZE) {
    store.splice(0, store.length - MAX_AUDIT_LOG_SIZE);
  }

  appendAudit(orgId, {
    action: "access_requested",
    actor: input.requesterName,
    timestamp: now,
    details: `Secret: ${secret.name}, Duration: ${input.durationMinutes}min`,
  });

  return request;
}

export function approveAccessRequest(orgId: string, requestId: string, approverName: string): AccessRequest {
  const store = getOrgAccessRequestStore(orgId);
  const allRequests = [
    ...CATALOG_ACCESS_REQUESTS.filter((r) => r.orgId === "__catalog__").map((r) => ({
      ...r,
      orgId,
      auditTrail: [...r.auditTrail],
    })),
    ...store,
  ];
  const request = allRequests.find((r) => r.id === requestId);
  if (!request) throw new Error("REQUEST_NOT_FOUND");
  if (request.status !== "pending") throw new Error("REQUEST_NOT_PENDING");

  const now = new Date().toISOString();
  const token = ephemeralToken();
  const expiresAt = new Date(Date.now() + request.durationMinutes * 60 * 1000).toISOString();

  request.status = "active";
  request.approvedBy = approverName;
  request.approvedAt = now;
  request.ephemeralToken = token;
  request.tokenExpiresAt = expiresAt;
  request.auditTrail.push({
    action: "access_approved",
    actor: approverName,
    timestamp: now,
    details: `Ephemeral token issued, expires: ${expiresAt}`,
  });

  if (!store.some((r) => r.id === request.id)) {
    store.push(request);
  }

  const secret = getSecretById(orgId, request.secretId);
  if (secret) {
    secret.accessCount += 1;
    secret.activeAccessors += 1;
  }

  appendAudit(orgId, {
    action: "access_approved",
    actor: approverName,
    timestamp: now,
    details: `Approved access for ${request.requesterName} to ${request.secretName}`,
  });

  return request;
}

export function denyAccessRequest(orgId: string, requestId: string, denierName: string, reason: string): AccessRequest {
  const store = getOrgAccessRequestStore(orgId);
  const allRequests = [
    ...CATALOG_ACCESS_REQUESTS.filter((r) => r.orgId === "__catalog__").map((r) => ({
      ...r,
      orgId,
      auditTrail: [...r.auditTrail],
    })),
    ...store,
  ];
  const request = allRequests.find((r) => r.id === requestId);
  if (!request) throw new Error("REQUEST_NOT_FOUND");
  if (request.status !== "pending") throw new Error("REQUEST_NOT_PENDING");

  const now = new Date().toISOString();
  request.status = "denied";
  request.deniedBy = denierName;
  request.deniedReason = reason;
  request.auditTrail.push({
    action: "access_denied",
    actor: denierName,
    timestamp: now,
    details: reason,
  });

  if (!store.some((r) => r.id === request.id)) {
    store.push(request);
  }

  appendAudit(orgId, {
    action: "access_denied",
    actor: denierName,
    timestamp: now,
    details: `Denied ${request.requesterName} access to ${request.secretName}: ${reason}`,
  });

  return request;
}

export function releaseAccess(orgId: string, requestId: string, releaserName: string): AccessRequest {
  const store = getOrgAccessRequestStore(orgId);
  const allRequests = [
    ...CATALOG_ACCESS_REQUESTS.filter((r) => r.orgId === "__catalog__").map((r) => ({
      ...r,
      orgId,
      auditTrail: [...r.auditTrail],
    })),
    ...store,
  ];
  const request = allRequests.find((r) => r.id === requestId);
  if (!request) throw new Error("REQUEST_NOT_FOUND");
  if (request.status !== "active" && request.status !== "approved") throw new Error("REQUEST_NOT_ACTIVE");

  const now = new Date().toISOString();
  request.status = "released";
  request.releasedAt = now;
  request.ephemeralToken = null;
  request.auditTrail.push({
    action: "access_released",
    actor: releaserName,
    timestamp: now,
    details: "Early release of access",
  });

  if (!store.some((r) => r.id === request.id)) {
    store.push(request);
  }

  const secret = getSecretById(orgId, request.secretId);
  if (secret && secret.activeAccessors > 0) {
    secret.activeAccessors -= 1;
  }

  appendAudit(orgId, {
    action: "access_released",
    actor: releaserName,
    timestamp: now,
    details: `Released access to ${request.secretName}`,
  });

  return request;
}

export function getAccessRequests(orgId: string): AccessRequest[] {
  const store = getOrgAccessRequestStore(orgId);
  const storeIds = new Set(store.map((r) => r.id));
  const catalog = CATALOG_ACCESS_REQUESTS.filter((r) => !storeIds.has(r.id)).map((r) => ({ ...r, orgId }));
  return [...catalog, ...store];
}

export function createShare(
  orgId: string,
  input: {
    secretId: string;
    createdBy: string;
    recipientEmail: string;
    expiresInHours: number;
    maxUses: number;
  },
): ExternalShare {
  const secret = getSecretById(orgId, input.secretId);
  if (!secret) throw new Error("SECRET_NOT_FOUND");

  if (input.expiresInHours < 1 || input.expiresInHours > 168) {
    throw new Error("INVALID_EXPIRY");
  }
  if (input.maxUses < 1 || input.maxUses > 10) {
    throw new Error("INVALID_MAX_USES");
  }
  if (!input.recipientEmail.includes("@")) {
    throw new Error("INVALID_EMAIL");
  }

  const now = new Date().toISOString();
  const expiresAt = new Date(Date.now() + input.expiresInHours * 60 * 60 * 1000).toISOString();
  const token = shareToken();

  const share: ExternalShare = {
    id: genId("jsh"),
    orgId,
    secretId: input.secretId,
    secretName: secret.name,
    createdBy: input.createdBy,
    recipientEmail: input.recipientEmail,
    shareToken: token,
    expiresAt,
    maxUses: input.maxUses,
    currentUses: 0,
    status: "active",
    noPlaintext: secret.noPlaintextSharing,
    createdAt: now,
    consumedAt: null,
    auditTrail: [
      {
        action: "share_created",
        actor: input.createdBy,
        timestamp: now,
        details: `Recipient: ${input.recipientEmail}, Expires: ${input.expiresInHours}h, Max uses: ${input.maxUses}`,
      },
    ],
  };

  const store = getOrgShareStore(orgId);
  store.push(share);
  if (store.length > MAX_AUDIT_LOG_SIZE) {
    store.splice(0, store.length - MAX_AUDIT_LOG_SIZE);
  }

  appendAudit(orgId, {
    action: "share_created",
    actor: input.createdBy,
    timestamp: now,
    details: `One-time share of ${secret.name} to ${input.recipientEmail}`,
  });

  return share;
}

export function consumeShare(orgId: string, shareId: string, consumerIdentity: string): ExternalShare {
  const store = getOrgShareStore(orgId);
  const allShares = [...CATALOG_SHARES.map((s) => ({ ...s, orgId, auditTrail: [...s.auditTrail] })), ...store];
  const share = allShares.find((s) => s.id === shareId);
  if (!share) throw new Error("SHARE_NOT_FOUND");
  if (share.status !== "active") throw new Error("SHARE_NOT_ACTIVE");

  if (new Date(share.expiresAt) <= new Date()) {
    share.status = "expired";
    share.auditTrail.push({
      action: "share_expired",
      actor: "system",
      timestamp: new Date().toISOString(),
    });
    if (!store.some((s) => s.id === share.id)) {
      store.push(share);
    }
    throw new Error("SHARE_EXPIRED");
  }

  const now = new Date().toISOString();
  share.currentUses += 1;
  share.consumedAt = now;
  if (share.currentUses >= share.maxUses) {
    share.status = "consumed";
  }
  share.auditTrail.push({
    action: "share_consumed",
    actor: consumerIdentity,
    timestamp: now,
  });

  if (!store.some((s) => s.id === share.id)) {
    store.push(share);
  }

  appendAudit(orgId, {
    action: "share_consumed",
    actor: consumerIdentity,
    timestamp: now,
    details: `Share ${share.id} for ${share.secretName} consumed`,
  });

  return share;
}

export function getShares(orgId: string): ExternalShare[] {
  const store = getOrgShareStore(orgId);
  const storeIds = new Set(store.map((s) => s.id));
  const catalog = CATALOG_SHARES.filter((s) => !storeIds.has(s.id)).map((s) => ({ ...s, orgId }));
  return [...catalog, ...store];
}

export function transferOwnership(
  orgId: string,
  input: {
    secretId: string;
    toOwnerId: string;
    toOwnerName: string;
    reason: string;
    isOffboarding: boolean;
    initiatedBy: string;
  },
): OwnershipTransfer {
  const secret = getSecretById(orgId, input.secretId);
  if (!secret) throw new Error("SECRET_NOT_FOUND");

  if (input.reason.trim().length < 10) {
    throw new Error("REASON_TOO_SHORT");
  }

  const now = new Date().toISOString();
  const transfer: OwnershipTransfer = {
    id: genId("jot"),
    orgId,
    secretId: input.secretId,
    secretName: secret.name,
    fromOwnerId: secret.ownerId,
    fromOwnerName: secret.ownerName,
    toOwnerId: input.toOwnerId,
    toOwnerName: input.toOwnerName,
    action: "transfer",
    reason: input.reason,
    isOffboarding: input.isOffboarding,
    initiatedBy: input.initiatedBy,
    completedAt: now,
    auditTrail: [
      {
        action: "ownership_transfer_initiated",
        actor: input.initiatedBy,
        timestamp: now,
        details: `From ${secret.ownerName} to ${input.toOwnerName}`,
      },
      {
        action: "ownership_transferred",
        actor: "system",
        timestamp: now,
        details: input.isOffboarding ? "Offboarding transfer" : "Voluntary transfer",
      },
    ],
  };

  secret.ownerId = input.toOwnerId;
  secret.ownerName = input.toOwnerName;
  secret.updatedAt = now;

  const orgStore = getOrgSecretStore(orgId);
  orgStore.set(secret.id, secret);

  const store = getOrgTransferStore(orgId);
  store.push(transfer);
  if (store.length > MAX_AUDIT_LOG_SIZE) {
    store.splice(0, store.length - MAX_AUDIT_LOG_SIZE);
  }

  appendAudit(orgId, {
    action: input.isOffboarding ? "ownership_reclaimed" : "ownership_transferred",
    actor: input.initiatedBy,
    timestamp: now,
    details: `${secret.name}: ${transfer.fromOwnerName} -> ${input.toOwnerName}${input.isOffboarding ? " (offboarding)" : ""}`,
  });

  return transfer;
}

export function reclaimOwnership(
  orgId: string,
  input: {
    secretId: string;
    toOwnerId: string;
    toOwnerName: string;
    reason: string;
    initiatedBy: string;
  },
): OwnershipTransfer {
  const secret = getSecretById(orgId, input.secretId);
  if (!secret) throw new Error("SECRET_NOT_FOUND");

  if (input.reason.trim().length < 10) {
    throw new Error("REASON_TOO_SHORT");
  }

  const now = new Date().toISOString();
  const transfer: OwnershipTransfer = {
    id: genId("jot"),
    orgId,
    secretId: input.secretId,
    secretName: secret.name,
    fromOwnerId: secret.ownerId,
    fromOwnerName: secret.ownerName,
    toOwnerId: input.toOwnerId,
    toOwnerName: input.toOwnerName,
    action: "reclaim",
    reason: input.reason,
    isOffboarding: true,
    initiatedBy: input.initiatedBy,
    completedAt: now,
    auditTrail: [
      {
        action: "ownership_reclaim_initiated",
        actor: input.initiatedBy,
        timestamp: now,
        details: `Forced reclaim from ${secret.ownerName}`,
      },
      {
        action: "ownership_reclaimed",
        actor: "system",
        timestamp: now,
        details: `Reclaimed to ${input.toOwnerName}`,
      },
      {
        action: "rotation_prompted",
        actor: "system",
        timestamp: now,
        details: "Rotation required within 24h post-reclaim",
      },
    ],
  };

  secret.ownerId = input.toOwnerId;
  secret.ownerName = input.toOwnerName;
  secret.needsRotation = true;
  secret.updatedAt = now;

  const orgStore = getOrgSecretStore(orgId);
  orgStore.set(secret.id, secret);

  const store = getOrgTransferStore(orgId);
  store.push(transfer);
  if (store.length > MAX_AUDIT_LOG_SIZE) {
    store.splice(0, store.length - MAX_AUDIT_LOG_SIZE);
  }

  appendAudit(orgId, {
    action: "ownership_reclaimed",
    actor: input.initiatedBy,
    timestamp: now,
    details: `Forced reclaim of ${secret.name} from ${transfer.fromOwnerName} to ${input.toOwnerName}`,
  });

  return transfer;
}

export function getTransfers(orgId: string): OwnershipTransfer[] {
  const store = getOrgTransferStore(orgId);
  const catalog = CATALOG_TRANSFERS.map((t) => ({ ...t, orgId }));
  return [...catalog, ...store];
}

export function breakGlassAccess(
  orgId: string,
  input: {
    secretId: string;
    requesterId: string;
    requesterName: string;
    justification: string;
    incidentId: string | null;
    durationMinutes: number;
  },
): BreakGlassAccess {
  const secret = getSecretById(orgId, input.secretId);
  if (!secret) throw new Error("SECRET_NOT_FOUND");

  if (input.justification.trim().length < 20) {
    throw new Error("JUSTIFICATION_TOO_SHORT");
  }
  if (input.durationMinutes < 5 || input.durationMinutes > 120) {
    throw new Error("INVALID_DURATION");
  }

  const now = new Date().toISOString();
  const token = ephemeralToken();
  const expiresAt = new Date(Date.now() + input.durationMinutes * 60 * 1000).toISOString();

  const access: BreakGlassAccess = {
    id: genId("jbg"),
    orgId,
    secretId: input.secretId,
    secretName: secret.name,
    requesterId: input.requesterId,
    requesterName: input.requesterName,
    justification: input.justification,
    incidentId: input.incidentId,
    status: "active",
    ephemeralToken: token,
    expiresAt,
    durationMinutes: input.durationMinutes,
    retroactiveReviewRequired: true,
    reviewedBy: null,
    reviewedAt: null,
    reviewNotes: null,
    createdAt: now,
    auditTrail: [
      {
        action: "break_glass_activated",
        actor: input.requesterName,
        timestamp: now,
        details: `Incident: ${input.incidentId || "N/A"}, Duration: ${input.durationMinutes}min, Justification: ${input.justification.slice(0, 100)}`,
      },
    ],
  };

  secret.accessCount += 1;
  secret.activeAccessors += 1;

  const store = getOrgBreakGlassStore(orgId);
  store.push(access);
  if (store.length > MAX_AUDIT_LOG_SIZE) {
    store.splice(0, store.length - MAX_AUDIT_LOG_SIZE);
  }

  appendAudit(orgId, {
    action: "break_glass_activated",
    actor: input.requesterName,
    timestamp: now,
    details: `Break-glass on ${secret.name}, Incident: ${input.incidentId || "N/A"}`,
  });

  return access;
}

export function reviewBreakGlass(
  orgId: string,
  breakGlassId: string,
  reviewerName: string,
  notes: string,
): BreakGlassAccess {
  const store = getOrgBreakGlassStore(orgId);
  const allEntries = [...CATALOG_BREAK_GLASS.map((b) => ({ ...b, orgId, auditTrail: [...b.auditTrail] })), ...store];
  const entry = allEntries.find((b) => b.id === breakGlassId);
  if (!entry) throw new Error("BREAK_GLASS_NOT_FOUND");
  if (entry.status === "reviewed") throw new Error("ALREADY_REVIEWED");

  const now = new Date().toISOString();
  entry.status = "reviewed";
  entry.reviewedBy = reviewerName;
  entry.reviewedAt = now;
  entry.reviewNotes = notes;
  entry.retroactiveReviewRequired = false;
  entry.auditTrail.push({
    action: "break_glass_reviewed",
    actor: reviewerName,
    timestamp: now,
    details: notes.slice(0, 200),
  });

  if (!store.some((b) => b.id === entry.id)) {
    store.push(entry);
  }

  appendAudit(orgId, {
    action: "break_glass_reviewed",
    actor: reviewerName,
    timestamp: now,
    details: `Reviewed break-glass ${entry.id} for ${entry.secretName}`,
  });

  return entry;
}

export function getBreakGlassEntries(orgId: string): BreakGlassAccess[] {
  const store = getOrgBreakGlassStore(orgId);
  const storeIds = new Set(store.map((b) => b.id));
  const catalog = CATALOG_BREAK_GLASS.filter((b) => !storeIds.has(b.id)).map((b) => ({ ...b, orgId }));
  return [...catalog, ...store];
}

export function getAuditLog(orgId: string): AuditEntry[] {
  const store = getOrgAuditStore(orgId);
  const catalog = CATALOG_AUDIT.map((a) => ({ ...a }));
  return [...catalog, ...store];
}

export function getStats(orgId: string): JitSecretStats {
  const secrets = getSecrets(orgId);
  const requests = getAccessRequests(orgId);
  const shares = getShares(orgId);
  const breakGlass = getBreakGlassEntries(orgId);
  const transfers = getTransfers(orgId);

  const today = new Date().toISOString().slice(0, 10);
  const thisMonth = new Date().toISOString().slice(0, 7);

  const requestsToday = requests.filter((r) => r.createdAt.startsWith(today));
  const approvedRequests = requests.filter((r) => r.approvedAt !== null);
  const avgApproval =
    approvedRequests.length > 0
      ? approvedRequests.reduce((sum, r) => {
          const created = new Date(r.createdAt).getTime();
          const approved = new Date(r.approvedAt!).getTime();
          return sum + (approved - created) / 60000;
        }, 0) / approvedRequests.length
      : 0;

  return {
    totalSecrets: secrets.length,
    criticalSecrets: secrets.filter((s) => s.classification === "critical").length,
    secretsNeedingRotation: secrets.filter((s) => s.needsRotation).length,
    pendingRequests: requests.filter((r) => r.status === "pending").length,
    activeAccesses: requests.filter((r) => r.status === "active" || r.status === "approved").length,
    activeShares: shares.filter((s) => s.status === "active").length,
    breakGlassActive: breakGlass.filter((b) => b.status === "active").length,
    pendingReviews: breakGlass.filter((b) => b.retroactiveReviewRequired && b.status !== "reviewed").length,
    transfersThisMonth: transfers.filter((t) => t.completedAt.startsWith(thisMonth)).length,
    accessRequestsToday: requestsToday.length,
    deniedToday: requestsToday.filter((r) => r.status === "denied").length,
    avgApprovalTimeMinutes: Math.round(avgApproval),
  };
}
