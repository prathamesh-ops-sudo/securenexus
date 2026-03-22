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
}

function verifyChainIntegrity(evidence: EvidenceItem): boolean {
  const chain = evidence.integrityChain;
  if (chain.length === 0) return false;
  if (chain[0].previousHash !== "genesis") return false;

  for (let i = 1; i < chain.length; i++) {
    if (chain[i].previousHash !== chain[i - 1].entryHash) return false;
  }
  return true;
}
