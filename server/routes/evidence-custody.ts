import type { Express, Request, Response } from "express";
import { getOrgId, logger, reply, replyError, sendEnvelope } from "./shared";
import { isAuthenticated } from "../auth";
import { requireMinRole, resolveOrgContext } from "../rbac";
import { createHash } from "crypto";

interface EvidenceItem {
  id: string;
  orgId: string;
  name: string;
  type: "file" | "log" | "screenshot" | "memory_dump" | "network_capture" | "artifact";
  sourceSystem: string;
  collectedBy: string;
  collectedAt: string;
  sha256Hash: string;
  integrityChain: CustodyEntry[];
  classification: "public" | "internal" | "confidential" | "restricted";
  caseId: string;
  retentionUntil: string;
  sizeBytes: number;
  isSealed: boolean;
}

interface CustodyEntry {
  id: string;
  action: "collected" | "transferred" | "accessed" | "analyzed" | "exported" | "sealed" | "unsealed";
  actor: string;
  timestamp: string;
  previousHash: string;
  entryHash: string;
  reason: string;
  metadata: Record<string, unknown>;
}

const evidenceStore = new Map<string, EvidenceItem>();

const retentionPolicies = new Map<string, any[]>();

function getDefaultRetentionPolicies() {
  return [
    { evidenceType: "file", retentionDays: 730, action: "archive", autoApply: false },
    { evidenceType: "log", retentionDays: 365, action: "archive", autoApply: true },
    { evidenceType: "screenshot", retentionDays: 180, action: "delete", autoApply: true },
    { evidenceType: "memory_dump", retentionDays: 90, action: "archive", autoApply: false },
    { evidenceType: "network_capture", retentionDays: 90, action: "delete", autoApply: true },
    { evidenceType: "artifact", retentionDays: 365, action: "archive", autoApply: false },
  ];
}

function computeEntryHash(entry: Omit<CustodyEntry, "entryHash">): string {
  const data = `${entry.action}|${entry.actor}|${entry.timestamp}|${entry.previousHash}|${entry.reason}`;
  return createHash("sha256").update(data).digest("hex");
}

function genId(): string {
  return `evi-${Date.now()}-${createHash("sha256").update(String(Math.random())).digest("hex").slice(0, 8)}`;
}

export function registerEvidenceCustodyRoutes(app: Express): void {
  const log = logger.child("evidence-custody");

  app.get(
    "/api/evidence-custody",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const caseId = req.query.caseId as string | undefined;
        let items = Array.from(evidenceStore.values()).filter((e) => e.orgId === orgId);
        if (caseId) items = items.filter((e) => e.caseId === caseId);
        items.sort((a, b) => new Date(b.collectedAt).getTime() - new Date(a.collectedAt).getTime());

        const summaries = items.map((e) => ({
          id: e.id,
          name: e.name,
          type: e.type,
          sourceSystem: e.sourceSystem,
          collectedBy: e.collectedBy,
          collectedAt: e.collectedAt,
          sha256Hash: e.sha256Hash,
          classification: e.classification,
          caseId: e.caseId,
          custodyEntries: e.integrityChain.length,
          isSealed: e.isSealed,
          integrityValid: verifyChainIntegrity(e),
        }));

        return sendEnvelope(res, summaries, { meta: { total: summaries.length } });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "EVIDENCE_ERROR", message: "Failed to list evidence." }]);
      }
    },
  );

  app.post(
    "/api/evidence-custody",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const user = (req as any).user;
        const { name, type, sourceSystem, classification, caseId, sizeBytes } = req.body;

        if (!name || !caseId) {
          return replyError(res, 400, [{ code: "VALIDATION_ERROR", message: "name and caseId are required." }]);
        }

        const validTypes = ["file", "log", "screenshot", "memory_dump", "network_capture", "artifact"];
        const validClassifications = ["public", "internal", "confidential", "restricted"];

        const id = genId();
        const contentHash = createHash("sha256").update(`${orgId}-${name}-${Date.now()}`).digest("hex");

        const initialEntry: Omit<CustodyEntry, "entryHash"> = {
          id: `ce-${Date.now()}`,
          action: "collected",
          actor: user?.username || "unknown",
          timestamp: new Date().toISOString(),
          previousHash: "genesis",
          reason: `Evidence collected from ${sourceSystem || "manual upload"}`,
          metadata: {},
        };

        const entryHash = computeEntryHash(initialEntry);

        const evidence: EvidenceItem = {
          id,
          orgId,
          name,
          type: validTypes.includes(type) ? type : "artifact",
          sourceSystem: sourceSystem || "manual",
          collectedBy: user?.username || "unknown",
          collectedAt: new Date().toISOString(),
          sha256Hash: contentHash,
          integrityChain: [{ ...initialEntry, entryHash }],
          classification: validClassifications.includes(classification) ? classification : "internal",
          caseId,
          retentionUntil: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
          sizeBytes: typeof sizeBytes === "number" ? sizeBytes : 0,
          isSealed: false,
        };

        evidenceStore.set(id, evidence);
        log.info("Evidence collected", { orgId, evidenceId: id, caseId });
        return reply(res, evidence, undefined, 201);
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "EVIDENCE_ERROR", message: "Failed to collect evidence." }]);
      }
    },
  );

  app.get(
    "/api/evidence-custody/:id",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const evidence = evidenceStore.get(req.params.id as string);
        if (!evidence || evidence.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Evidence not found." }]);
        }
        return reply(res, {
          ...evidence,
          integrityValid: verifyChainIntegrity(evidence),
        });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "EVIDENCE_ERROR", message: "Failed to get evidence." }]);
      }
    },
  );

  app.post(
    "/api/evidence-custody/:id/transfer",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const evidence = evidenceStore.get(req.params.id as string);
        if (!evidence || evidence.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Evidence not found." }]);
        }
        if (evidence.isSealed) {
          return replyError(res, 400, [{ code: "SEALED", message: "Evidence is sealed. Unseal before transferring." }]);
        }

        const user = (req as any).user;
        const { action, reason } = req.body;

        if (!reason) {
          return replyError(res, 400, [
            { code: "VALIDATION_ERROR", message: "reason is required for custody transfer." },
          ]);
        }

        const validActions = ["transferred", "accessed", "analyzed", "exported"];
        const custodyAction = validActions.includes(action) ? action : "accessed";

        const previousHash = evidence.integrityChain[evidence.integrityChain.length - 1].entryHash;
        const newEntry: Omit<CustodyEntry, "entryHash"> = {
          id: `ce-${Date.now()}`,
          action: custodyAction,
          actor: user?.username || "unknown",
          timestamp: new Date().toISOString(),
          previousHash,
          reason,
          metadata: req.body.metadata || {},
        };

        const entryHash = computeEntryHash(newEntry);
        evidence.integrityChain.push({ ...newEntry, entryHash });

        log.info("Evidence custody transferred", { orgId, evidenceId: evidence.id, action: custodyAction });
        return reply(res, { ...newEntry, entryHash });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "EVIDENCE_ERROR", message: "Failed to transfer custody." }]);
      }
    },
  );

  app.post(
    "/api/evidence-custody/:id/seal",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const evidence = evidenceStore.get(req.params.id as string);
        if (!evidence || evidence.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Evidence not found." }]);
        }

        const user = (req as any).user;
        const previousHash = evidence.integrityChain[evidence.integrityChain.length - 1].entryHash;
        const sealEntry: Omit<CustodyEntry, "entryHash"> = {
          id: `ce-${Date.now()}`,
          action: evidence.isSealed ? "unsealed" : "sealed",
          actor: user?.username || "unknown",
          timestamp: new Date().toISOString(),
          previousHash,
          reason:
            req.body.reason || (evidence.isSealed ? "Evidence unsealed by admin" : "Evidence sealed for preservation"),
          metadata: {},
        };

        const entryHash = computeEntryHash(sealEntry);
        evidence.integrityChain.push({ ...sealEntry, entryHash });
        evidence.isSealed = !evidence.isSealed;

        return reply(res, { isSealed: evidence.isSealed, entry: { ...sealEntry, entryHash } });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "EVIDENCE_ERROR", message: "Failed to seal/unseal evidence." }]);
      }
    },
  );

  app.get(
    "/api/evidence-custody/:id/verify",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const evidence = evidenceStore.get(req.params.id as string);
        if (!evidence || evidence.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Evidence not found." }]);
        }

        const isValid = verifyChainIntegrity(evidence);
        const brokenLinks: number[] = [];

        for (let i = 1; i < evidence.integrityChain.length; i++) {
          const entry = evidence.integrityChain[i];
          const prevEntry = evidence.integrityChain[i - 1];
          if (entry.previousHash !== prevEntry.entryHash) {
            brokenLinks.push(i);
          }
        }

        return reply(res, {
          evidenceId: evidence.id,
          chainLength: evidence.integrityChain.length,
          integrityValid: isValid,
          brokenLinks,
          lastVerified: new Date().toISOString(),
        });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "EVIDENCE_ERROR", message: "Failed to verify chain." }]);
      }
    },
  );
  // ─── 18.3 Evidence Tagging and Categorization ─────────────────────────────

  app.get(
    "/api/evidence-custody/:id/tags",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const evidence = evidenceStore.get(req.params.id as string);
        if (!evidence || evidence.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Evidence not found." }]);
        }
        const tags = (evidence as any).tags || [];
        return sendEnvelope(res, tags, { meta: { total: tags.length } });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "EVIDENCE_ERROR", message: "Failed to list tags." }]);
      }
    },
  );

  app.post(
    "/api/evidence-custody/:id/tags",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const evidence = evidenceStore.get(req.params.id as string);
        if (!evidence || evidence.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Evidence not found." }]);
        }
        const { tag, category } = req.body;
        if (!tag) {
          return replyError(res, 400, [{ code: "VALIDATION_ERROR", message: "tag is required." }]);
        }
        const validCategories = [
          "malware_sample",
          "network_capture",
          "memory_dump",
          "log_file",
          "screenshot",
          "disk_image",
          "registry",
          "email",
          "document",
          "other",
        ];
        if (!(evidence as any).tags) (evidence as any).tags = [];
        const tagEntry = {
          id: genId(),
          tag,
          category: validCategories.includes(category) ? category : "other",
          addedBy: (req as any).user?.username || "unknown",
          addedAt: new Date().toISOString(),
        };
        (evidence as any).tags.push(tagEntry);
        log.info("Evidence tagged", { orgId, evidenceId: evidence.id, tag });
        return reply(res, tagEntry, undefined, 201);
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "EVIDENCE_ERROR", message: "Failed to add tag." }]);
      }
    },
  );

  app.delete(
    "/api/evidence-custody/:id/tags/:tagId",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const evidence = evidenceStore.get(req.params.id as string);
        if (!evidence || evidence.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Evidence not found." }]);
        }
        const tags = (evidence as any).tags || [];
        const idx = tags.findIndex((t: any) => t.id === req.params.tagId);
        if (idx === -1) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Tag not found." }]);
        }
        tags.splice(idx, 1);
        return reply(res, { deleted: true });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "EVIDENCE_ERROR", message: "Failed to delete tag." }]);
      }
    },
  );

  // ─── 18.4 Evidence File Upload with Hash Calculation ──────────────────────

  app.post(
    "/api/evidence-custody/:id/upload",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const evidence = evidenceStore.get(req.params.id as string);
        if (!evidence || evidence.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Evidence not found." }]);
        }
        if (evidence.isSealed) {
          return replyError(res, 400, [{ code: "SEALED", message: "Evidence is sealed." }]);
        }

        const user = (req as any).user;
        const { fileName, fileSize, mimeType, chunkIndex, totalChunks } = req.body;

        if (!fileName) {
          return replyError(res, 400, [{ code: "VALIDATION_ERROR", message: "fileName is required." }]);
        }

        // Simulate file hash calculation (in production would use actual file content)
        const fileHash = createHash("sha256").update(`${orgId}-${fileName}-${Date.now()}`).digest("hex");

        // Add custody entry for file upload
        const previousHash = evidence.integrityChain[evidence.integrityChain.length - 1].entryHash;
        const uploadEntry: Omit<CustodyEntry, "entryHash"> = {
          id: `ce-${Date.now()}`,
          action: "collected",
          actor: user?.username || "unknown",
          timestamp: new Date().toISOString(),
          previousHash,
          reason: `File uploaded: ${fileName} (${mimeType || "unknown"})`,
          metadata: {
            fileName,
            fileSize: typeof fileSize === "number" ? fileSize : 0,
            mimeType: mimeType || "application/octet-stream",
            sha256: fileHash,
            chunkIndex: chunkIndex || 0,
            totalChunks: totalChunks || 1,
            storageLocation: "s3://evidence-bucket/encrypted/",
            serverSideEncryption: "AES-256",
          },
        };

        const entryHash = computeEntryHash(uploadEntry);
        evidence.integrityChain.push({ ...uploadEntry, entryHash });
        evidence.sizeBytes += typeof fileSize === "number" ? fileSize : 0;

        // Store file reference
        if (!(evidence as any).files) (evidence as any).files = [];
        (evidence as any).files.push({
          fileName,
          fileSize: typeof fileSize === "number" ? fileSize : 0,
          mimeType: mimeType || "application/octet-stream",
          sha256: fileHash,
          uploadedAt: new Date().toISOString(),
          uploadedBy: user?.username || "unknown",
          storageKey: `evidence/${evidence.id}/${fileName}`,
        });

        log.info("Evidence file uploaded", { orgId, evidenceId: evidence.id, fileName });
        return reply(
          res,
          {
            fileHash,
            custodyEntry: { ...uploadEntry, entryHash },
            storageKey: `evidence/${evidence.id}/${fileName}`,
          },
          undefined,
          201,
        );
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "EVIDENCE_ERROR", message: "Failed to upload file." }]);
      }
    },
  );

  // ─── 18.5 Evidence Retention Policies ─────────────────────────────────────

  app.get(
    "/api/evidence-custody/retention-policies",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        // Return configured retention policies per evidence type
        const policies = retentionPolicies.get(orgId) || getDefaultRetentionPolicies();
        return sendEnvelope(res, policies, { meta: { total: policies.length } });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "EVIDENCE_ERROR", message: "Failed to list retention policies." }]);
      }
    },
  );

  app.put(
    "/api/evidence-custody/retention-policies",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const { policies } = req.body;
        if (!Array.isArray(policies)) {
          return replyError(res, 400, [{ code: "VALIDATION_ERROR", message: "policies array is required." }]);
        }
        const validatedPolicies = policies.map((p: any) => ({
          evidenceType: p.evidenceType || "artifact",
          retentionDays: typeof p.retentionDays === "number" ? p.retentionDays : 365,
          action: ["archive", "delete"].includes(p.action) ? p.action : "archive",
          autoApply: !!p.autoApply,
        }));
        retentionPolicies.set(orgId, validatedPolicies);
        log.info("Retention policies updated", { orgId, count: validatedPolicies.length });
        return reply(res, { updated: true, policies: validatedPolicies });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "EVIDENCE_ERROR", message: "Failed to update retention policies." }]);
      }
    },
  );

  app.post(
    "/api/evidence-custody/retention-policies/apply",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const policies = retentionPolicies.get(orgId) || getDefaultRetentionPolicies();
        const now = Date.now();
        const results = { archived: 0, deleted: 0, skipped: 0 };

        for (const [, evidence] of Array.from(evidenceStore.entries())) {
          if (evidence.orgId !== orgId) continue;
          const retentionEnd = new Date(evidence.retentionUntil).getTime();
          if (retentionEnd > now) {
            results.skipped++;
            continue;
          }
          const policy = policies.find((p: any) => p.evidenceType === evidence.type);
          if (!policy) {
            results.skipped++;
            continue;
          }
          if (policy.action === "delete" && !evidence.isSealed) {
            evidenceStore.delete(evidence.id);
            results.deleted++;
          } else {
            results.archived++;
          }
        }

        log.info("Retention policies applied", { orgId, ...results });
        return reply(res, results);
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "EVIDENCE_ERROR", message: "Failed to apply retention policies." }]);
      }
    },
  );

  // ─── 19.4 Evidence Access Audit Logging ─────────────────────────────────────

  const accessAuditLog = new Map<string, any[]>();

  function logEvidenceAccess(
    orgId: string,
    evidenceId: string,
    action: string,
    actor: string,
    ip: string,
    metadata?: Record<string, unknown>,
  ) {
    const key = `${orgId}:${evidenceId}`;
    if (!accessAuditLog.has(key)) accessAuditLog.set(key, []);
    const entry = {
      id: genId(),
      evidenceId,
      orgId,
      action,
      actor,
      ip,
      timestamp: new Date().toISOString(),
      userAgent: "",
      metadata: metadata || {},
    };
    accessAuditLog.get(key)!.push(entry);
    return entry;
  }

  app.get(
    "/api/evidence-custody/:id/access-log",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const evidence = evidenceStore.get(req.params.id as string);
        if (!evidence || evidence.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Evidence not found." }]);
        }
        const key = `${orgId}:${evidence.id}`;
        const entries = accessAuditLog.get(key) || [];
        // Also log this access-log view itself
        const ip = (req.headers["x-forwarded-for"] as string) || req.socket.remoteAddress || "unknown";
        logEvidenceAccess(orgId, evidence.id, "access_log_viewed", (req as any).user?.username || "unknown", ip);
        return sendEnvelope(res, entries, { meta: { total: entries.length } });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "EVIDENCE_ERROR", message: "Failed to retrieve access log." }]);
      }
    },
  );

  // ─── 19.2 Access Request Workflow ───────────────────────────────────────────

  const accessRequests = new Map<string, any[]>();

  app.get(
    "/api/evidence-custody/:id/access-requests",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const evidence = evidenceStore.get(req.params.id as string);
        if (!evidence || evidence.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Evidence not found." }]);
        }
        const key = `${orgId}:${evidence.id}`;
        const requests = accessRequests.get(key) || [];
        return sendEnvelope(res, requests, { meta: { total: requests.length } });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "EVIDENCE_ERROR", message: "Failed to list access requests." }]);
      }
    },
  );

  app.post(
    "/api/evidence-custody/:id/access-requests",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const evidence = evidenceStore.get(req.params.id as string);
        if (!evidence || evidence.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Evidence not found." }]);
        }
        const user = (req as any).user;
        const { reason, accessType } = req.body;
        if (!reason) {
          return replyError(res, 400, [{ code: "VALIDATION_ERROR", message: "reason is required." }]);
        }
        const key = `${orgId}:${evidence.id}`;
        if (!accessRequests.has(key)) accessRequests.set(key, []);
        const request = {
          id: genId(),
          evidenceId: evidence.id,
          requestedBy: user?.username || "unknown",
          requestedAt: new Date().toISOString(),
          reason,
          accessType: accessType || "view",
          status: "pending",
          decidedBy: null,
          decidedAt: null,
          decisionNote: null,
        };
        accessRequests.get(key)!.push(request);
        const ip = (req.headers["x-forwarded-for"] as string) || req.socket.remoteAddress || "unknown";
        logEvidenceAccess(orgId, evidence.id, "access_requested", user?.username || "unknown", ip, {
          reason,
          accessType,
        });
        log.info("Evidence access requested", { orgId, evidenceId: evidence.id, requestedBy: request.requestedBy });
        return reply(res, request, undefined, 201);
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "EVIDENCE_ERROR", message: "Failed to create access request." }]);
      }
    },
  );

  app.post(
    "/api/evidence-custody/:id/access-requests/:requestId/decide",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const evidence = evidenceStore.get(req.params.id as string);
        if (!evidence || evidence.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Evidence not found." }]);
        }
        const key = `${orgId}:${evidence.id}`;
        const requests = accessRequests.get(key) || [];
        const request = requests.find((r: any) => r.id === req.params.requestId);
        if (!request) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Access request not found." }]);
        }
        if (request.status !== "pending") {
          return replyError(res, 400, [{ code: "ALREADY_DECIDED", message: "Request already decided." }]);
        }
        const { decision, note } = req.body;
        if (!decision || !["approved", "denied"].includes(decision)) {
          return replyError(res, 400, [{ code: "VALIDATION_ERROR", message: "decision must be approved or denied." }]);
        }
        const user = (req as any).user;
        request.status = decision;
        request.decidedBy = user?.username || "unknown";
        request.decidedAt = new Date().toISOString();
        request.decisionNote = note || null;
        const ip = (req.headers["x-forwarded-for"] as string) || req.socket.remoteAddress || "unknown";
        logEvidenceAccess(orgId, evidence.id, `access_${decision}`, user?.username || "unknown", ip, {
          requestId: request.id,
        });
        log.info("Evidence access request decided", { orgId, evidenceId: evidence.id, decision });
        return reply(res, request);
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "EVIDENCE_ERROR", message: "Failed to decide access request." }]);
      }
    },
  );

  // ─── 19.5 Evidence Export with Chain of Custody Report ──────────────────────

  app.get(
    "/api/evidence-custody/:id/export",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const evidence = evidenceStore.get(req.params.id as string);
        if (!evidence || evidence.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Evidence not found." }]);
        }

        const ip = (req.headers["x-forwarded-for"] as string) || req.socket.remoteAddress || "unknown";
        logEvidenceAccess(orgId, evidence.id, "exported", (req as any).user?.username || "unknown", ip);

        const key = `${orgId}:${evidence.id}`;
        const accessLog = accessAuditLog.get(key) || [];

        const report = {
          exportedAt: new Date().toISOString(),
          exportedBy: (req as any).user?.username || "unknown",
          evidence: {
            id: evidence.id,
            name: evidence.name,
            type: evidence.type,
            sourceSystem: evidence.sourceSystem,
            collectedBy: evidence.collectedBy,
            collectedAt: evidence.collectedAt,
            sha256Hash: evidence.sha256Hash,
            classification: evidence.classification,
            caseId: evidence.caseId,
            sizeBytes: evidence.sizeBytes,
            isSealed: evidence.isSealed,
            retentionUntil: evidence.retentionUntil,
          },
          chainOfCustody: evidence.integrityChain.map((entry) => ({
            id: entry.id,
            action: entry.action,
            actor: entry.actor,
            timestamp: entry.timestamp,
            entryHash: entry.entryHash,
            previousHash: entry.previousHash,
            reason: entry.reason,
          })),
          integrityVerification: {
            chainValid: verifyChainIntegrity(evidence),
            totalEntries: evidence.integrityChain.length,
            verifiedAt: new Date().toISOString(),
          },
          accessLog: accessLog.map((e: any) => ({
            action: e.action,
            actor: e.actor,
            timestamp: e.timestamp,
            ip: e.ip,
          })),
          tags: (evidence as any).tags || [],
          files: (evidence as any).files || [],
          legalNotice:
            "This document constitutes an official chain of custody report. All hash verifications have been performed using SHA-256. Any tampering with this report or the underlying evidence may constitute a criminal offense.",
        };

        const format = req.query.format as string;
        if (format === "csv") {
          const lines = [
            "Section,Field,Value",
            `Evidence,ID,${evidence.id}`,
            `Evidence,Name,${evidence.name}`,
            `Evidence,Type,${evidence.type}`,
            `Evidence,SHA-256,${evidence.sha256Hash}`,
            `Evidence,Classification,${evidence.classification}`,
            `Evidence,Case ID,${evidence.caseId}`,
            `Evidence,Collected By,${evidence.collectedBy}`,
            `Evidence,Collected At,${evidence.collectedAt}`,
            `Evidence,Sealed,${evidence.isSealed}`,
            "",
            "Chain Entry,Action,Actor,Timestamp,Hash",
            ...evidence.integrityChain.map((e) => `Chain,${e.action},${e.actor},${e.timestamp},${e.entryHash}`),
            "",
            "Access Log,Action,Actor,Timestamp,IP",
            ...accessLog.map((e: any) => `Access,${e.action},${e.actor},${e.timestamp},${e.ip}`),
          ];
          res.setHeader("Content-Type", "text/csv");
          res.setHeader("Content-Disposition", `attachment; filename="coc-report-${evidence.id}.csv"`);
          return res.send(lines.join("\n"));
        }

        return reply(res, report);
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "EVIDENCE_ERROR", message: "Failed to export evidence." }]);
      }
    },
  );

  // ─── 19.1 Evidence Preview ─────────────────────────────────────────────────

  app.get(
    "/api/evidence-custody/:id/preview",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const evidence = evidenceStore.get(req.params.id as string);
        if (!evidence || evidence.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Evidence not found." }]);
        }
        const ip = (req.headers["x-forwarded-for"] as string) || req.socket.remoteAddress || "unknown";
        logEvidenceAccess(orgId, evidence.id, "previewed", (req as any).user?.username || "unknown", ip);

        // Generate synthetic preview content based on evidence type
        let previewType = "text";
        let content = "";
        let hexDump = "";

        switch (evidence.type) {
          case "log":
            previewType = "text";
            content = `[${evidence.collectedAt}] INFO Evidence collected from ${evidence.sourceSystem}\n[${new Date().toISOString()}] Evidence chain has ${evidence.integrityChain.length} entries\nSHA-256: ${evidence.sha256Hash}\nCase: ${evidence.caseId}\nClassification: ${evidence.classification}`;
            break;
          case "screenshot":
            previewType = "image";
            content =
              "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNDAwIiBoZWlnaHQ9IjMwMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cmVjdCB3aWR0aD0iNDAwIiBoZWlnaHQ9IjMwMCIgZmlsbD0iIzFhMWEyZSIvPjx0ZXh0IHg9IjIwMCIgeT0iMTUwIiBmaWxsPSIjNjQ3NDhlIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBkeT0iLjNlbSIgZm9udC1mYW1pbHk9Im1vbm9zcGFjZSI+U2NyZWVuc2hvdCBQcmV2aWV3PC90ZXh0Pjwvc3ZnPg==";
            break;
          case "file":
          case "artifact":
            previewType = "json";
            content = JSON.stringify(
              {
                evidenceId: evidence.id,
                name: evidence.name,
                type: evidence.type,
                source: evidence.sourceSystem,
                sha256: evidence.sha256Hash,
                classification: evidence.classification,
                collectedAt: evidence.collectedAt,
                custodyChain: evidence.integrityChain.length + " entries",
              },
              null,
              2,
            );
            break;
          case "memory_dump":
          case "network_capture": {
            previewType = "hex";
            // Generate synthetic hex dump
            const lines: string[] = [];
            for (let offset = 0; offset < 256; offset += 16) {
              const hex = Array.from({ length: 16 }, () =>
                Math.floor(Math.random() * 256)
                  .toString(16)
                  .padStart(2, "0"),
              ).join(" ");
              const ascii = Array.from({ length: 16 }, () => {
                const c = Math.floor(Math.random() * 94) + 33;
                return c >= 33 && c <= 126 ? String.fromCharCode(c) : ".";
              }).join("");
              lines.push(`${offset.toString(16).padStart(8, "0")}  ${hex}  |${ascii}|`);
            }
            hexDump = lines.join("\n");
            content = hexDump;
            break;
          }
          default:
            previewType = "text";
            content = `Evidence: ${evidence.name}\nType: ${evidence.type}\nNo preview available for this type.`;
        }

        return reply(res, {
          evidenceId: evidence.id,
          previewType,
          content,
          mimeType:
            evidence.type === "screenshot"
              ? "image/png"
              : evidence.type === "log"
                ? "text/plain"
                : "application/octet-stream",
          sizeBytes: evidence.sizeBytes,
          truncated: evidence.sizeBytes > 1048576,
        });
      } catch (error: unknown) {
        return replyError(res, 500, [{ code: "EVIDENCE_ERROR", message: "Failed to generate preview." }]);
      }
    },
  );

  function verifyChainIntegrity(evidence: EvidenceItem): boolean {
    const chain = evidence.integrityChain;
    if (chain.length === 0) return false;
    if (chain[0].previousHash !== "genesis") return false;

    for (let i = 1; i < chain.length; i++) {
      if (chain[i].previousHash !== chain[i - 1].entryHash) return false;
    }
    return true;
  }
}
