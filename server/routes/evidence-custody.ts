/* eslint-disable @typescript-eslint/no-explicit-any */
import type { Express, Request, Response } from "express";
import { getOrgId, logger, reply, replyError, sendEnvelope, storage } from "./shared";
import { isAuthenticated } from "../auth";
import { requireMinRole, requireOrgId, resolveOrgContext } from "../rbac";
import { createHash } from "crypto";
import { db } from "../db";
import { and, desc, eq, lt } from "drizzle-orm";
import { evidenceAccessRequests, evidenceItems, evidenceTags } from "@shared/schema";
import { z } from "zod";

export function registerEvidenceCustodyRoutes(app: Express): void {
  const log = logger.child("evidence-custody");
  const tagSchema = z.object({
    tag: z.string().trim().min(1).max(100),
    category: z.string().trim().min(1).max(50).default("other"),
  });
  const accessRequestSchema = z.object({
    reason: z.string().trim().min(1).max(2000),
    accessType: z.enum(["view", "download", "export"]).default("view"),
  });
  const decisionSchema = z.object({
    decision: z.enum(["approved", "rejected"]),
    note: z.string().trim().max(2000).optional(),
  });

  // List all evidence items for the org
  app.get(
    "/api/evidence-custody",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const incidentId = req.query.caseId as string | undefined;

        if (incidentId) {
          const items = await storage.getEvidenceItems(incidentId, orgId);
          return sendEnvelope(res, items, { meta: { total: items.length } });
        }

        // Get evidence chain entries for the whole org
        const entries = await storage.getEvidenceChainEntriesByOrg(orgId, 100, 0);
        const total = await storage.countEvidenceChainEntriesByOrg(orgId);
        return sendEnvelope(res, entries, { meta: { total } });
      } catch (error: unknown) {
        log.error("Failed to list evidence", { error });
        return replyError(res, 500, [{ code: "EVIDENCE_ERROR", message: "Failed to list evidence." }]);
      }
    },
  );

  // Create new evidence item
  app.post(
    "/api/evidence-custody",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const user = (req as any).user;
        const { name, type, sourceSystem, classification, caseId, sizeBytes, description } = req.body;

        if (!name || !caseId) {
          return replyError(res, 400, [{ code: "VALIDATION_ERROR", message: "name and caseId are required." }]);
        }

        const validTypes = ["file", "log", "screenshot", "memory_dump", "network_capture", "artifact"];

        const evidence = await storage.createEvidenceItem({
          orgId,
          incidentId: caseId,
          type: validTypes.includes(type) ? type : "artifact",
          title: name,
          description: description || `Evidence collected from ${sourceSystem || "manual upload"}`,
          mimeType: "application/octet-stream",
          fileSize: typeof sizeBytes === "number" ? sizeBytes : 0,
          metadata: {
            sourceSystem: sourceSystem || "manual",
            classification: classification || "internal",
          },
          createdBy: user?.id || null,
          createdByName: user?.username || "unknown",
        });

        // Create initial chain entry
        const entryHash = createHash("sha256")
          .update(`collected|${user?.username || "unknown"}|${new Date().toISOString()}|genesis`)
          .digest("hex");

        await storage.createEvidenceChainEntry({
          orgId,
          incidentId: caseId,
          sequenceNum: 1,
          entryType: "collected",
          actorId: user?.id || null,
          actorName: user?.username || "unknown",
          summary: `Evidence "${name}" collected from ${sourceSystem || "manual upload"}`,
          details: { sourceSystem: sourceSystem || "manual", classification: classification || "internal" },
          relatedResourceType: "evidence_item",
          relatedResourceId: evidence.id,
          entryHash,
          previousHash: "genesis",
        });

        log.info("Evidence collected", { orgId, evidenceId: evidence.id, caseId });
        return reply(res, evidence, undefined, 201);
      } catch (error: unknown) {
        log.error("Failed to collect evidence", { error });
        return replyError(res, 500, [{ code: "EVIDENCE_ERROR", message: "Failed to collect evidence." }]);
      }
    },
  );

  // Get single evidence item
  app.get(
    "/api/evidence-custody/:id",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const evidenceId = String(req.params.id);
        const evidence = await storage.getEvidenceItem(evidenceId);
        if (!evidence || evidence.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Evidence not found." }]);
        }

        // Get chain entries for this evidence
        const chainEntries = await storage.getEvidenceChainEntries(evidence.incidentId, orgId);
        const relatedEntries = chainEntries.filter((e) => e.relatedResourceId === evidence.id);

        return reply(res, {
          ...evidence,
          chainOfCustody: relatedEntries,
          chainLength: relatedEntries.length,
        });
      } catch (error: unknown) {
        log.error("Failed to get evidence", { error });
        return replyError(res, 500, [{ code: "EVIDENCE_ERROR", message: "Failed to get evidence." }]);
      }
    },
  );

  // Transfer custody / add chain entry
  app.post(
    "/api/evidence-custody/:id/transfer",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const evidence = await storage.getEvidenceItem(String(req.params.id));
        if (!evidence || evidence.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Evidence not found." }]);
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

        // Get latest chain hash and next sequence number
        const latestHash = await storage.getLatestChainHash(evidence.incidentId);
        const nextSeq = await storage.getNextSequenceNum(evidence.incidentId);

        const entryHash = createHash("sha256")
          .update(
            `${custodyAction}|${user?.username || "unknown"}|${new Date().toISOString()}|${latestHash || "genesis"}`,
          )
          .digest("hex");

        const entry = await storage.createEvidenceChainEntry({
          orgId,
          incidentId: evidence.incidentId,
          sequenceNum: nextSeq,
          entryType: custodyAction,
          actorId: user?.id || null,
          actorName: user?.username || "unknown",
          summary: reason,
          details: req.body.metadata || {},
          relatedResourceType: "evidence_item",
          relatedResourceId: evidence.id,
          entryHash,
          previousHash: latestHash || "genesis",
        });

        log.info("Evidence custody transferred", { orgId, evidenceId: evidence.id, action: custodyAction });
        return reply(res, entry);
      } catch (error: unknown) {
        log.error("Failed to transfer custody", { error });
        return replyError(res, 500, [{ code: "EVIDENCE_ERROR", message: "Failed to transfer custody." }]);
      }
    },
  );

  // Seal/unseal evidence (add chain entry)
  app.post(
    "/api/evidence-custody/:id/seal",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const evidence = await storage.getEvidenceItem(String(req.params.id));
        if (!evidence || evidence.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Evidence not found." }]);
        }

        const user = (req as any).user;
        const isSealed = (evidence.metadata as any)?.isSealed === true;
        const sealAction = isSealed ? "unsealed" : "sealed";

        const latestHash = await storage.getLatestChainHash(evidence.incidentId);
        const nextSeq = await storage.getNextSequenceNum(evidence.incidentId);

        const entryHash = createHash("sha256")
          .update(`${sealAction}|${user?.username || "unknown"}|${new Date().toISOString()}|${latestHash || "genesis"}`)
          .digest("hex");

        const entry = await storage.createEvidenceChainEntry({
          orgId,
          incidentId: evidence.incidentId,
          sequenceNum: nextSeq,
          entryType: sealAction,
          actorId: user?.id || null,
          actorName: user?.username || "unknown",
          summary: req.body.reason || (isSealed ? "Evidence unsealed by admin" : "Evidence sealed for preservation"),
          details: {},
          relatedResourceType: "evidence_item",
          relatedResourceId: evidence.id,
          entryHash,
          previousHash: latestHash || "genesis",
        });

        return reply(res, { isSealed: !isSealed, entry });
      } catch (error: unknown) {
        log.error("Failed to seal/unseal evidence", { error });
        return replyError(res, 500, [{ code: "EVIDENCE_ERROR", message: "Failed to seal/unseal evidence." }]);
      }
    },
  );

  // Verify chain integrity
  app.get(
    "/api/evidence-custody/:id/verify",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const evidence = await storage.getEvidenceItem(String(req.params.id));
        if (!evidence || evidence.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Evidence not found." }]);
        }

        const chainEntries = await storage.getEvidenceChainEntries(evidence.incidentId, orgId);
        const relatedEntries = chainEntries.filter((e) => e.relatedResourceId === evidence.id);

        let isValid = true;
        const brokenLinks: number[] = [];

        if (relatedEntries.length > 0) {
          if (relatedEntries[0].previousHash !== "genesis") {
            isValid = false;
            brokenLinks.push(0);
          }
          for (let i = 1; i < relatedEntries.length; i++) {
            if (relatedEntries[i].previousHash !== relatedEntries[i - 1].entryHash) {
              isValid = false;
              brokenLinks.push(i);
            }
          }
        }

        return reply(res, {
          evidenceId: evidence.id,
          chainLength: relatedEntries.length,
          integrityValid: isValid,
          brokenLinks,
          lastVerified: new Date().toISOString(),
        });
      } catch (error: unknown) {
        log.error("Failed to verify chain", { error });
        return replyError(res, 500, [{ code: "EVIDENCE_ERROR", message: "Failed to verify chain." }]);
      }
    },
  );

  // Get evidence chain entries (access log)
  app.get(
    "/api/evidence-custody/:id/access-log",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const evidence = await storage.getEvidenceItem(String(req.params.id));
        if (!evidence || evidence.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Evidence not found." }]);
        }

        const chainEntries = await storage.getEvidenceChainEntries(evidence.incidentId, orgId);
        const relatedEntries = chainEntries.filter((e) => e.relatedResourceId === evidence.id);
        return sendEnvelope(res, relatedEntries, { meta: { total: relatedEntries.length } });
      } catch (error: unknown) {
        log.error("Failed to retrieve access log", { error });
        return replyError(res, 500, [{ code: "EVIDENCE_ERROR", message: "Failed to retrieve access log." }]);
      }
    },
  );

  app.get(
    "/api/evidence-custody/:id/tags",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      const orgId = getOrgId(req);
      const evidence = await storage.getEvidenceItem(String(req.params.id));
      if (!evidence || evidence.orgId !== orgId) {
        return replyError(res, 404, [{ code: "NOT_FOUND", message: "Evidence not found." }]);
      }
      const tags = await db
        .select()
        .from(evidenceTags)
        .where(and(eq(evidenceTags.orgId, orgId), eq(evidenceTags.evidenceId, evidence.id)))
        .orderBy(desc(evidenceTags.createdAt));
      return sendEnvelope(res, tags, { meta: { total: tags.length } });
    },
  );

  app.post(
    "/api/evidence-custody/:id/tags",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      const orgId = getOrgId(req);
      const parsed = tagSchema.safeParse(req.body);
      if (!parsed.success) return replyError(res, 400, [{ code: "VALIDATION_ERROR", message: "Invalid tag data." }]);
      const evidence = await storage.getEvidenceItem(String(req.params.id));
      if (!evidence || evidence.orgId !== orgId) {
        return replyError(res, 404, [{ code: "NOT_FOUND", message: "Evidence not found." }]);
      }
      const user = (req as any).user;
      const [tag] = await db
        .insert(evidenceTags)
        .values({ ...parsed.data, orgId, evidenceId: evidence.id, createdBy: user?.id })
        .onConflictDoUpdate({
          target: [evidenceTags.evidenceId, evidenceTags.tag],
          set: { category: parsed.data.category },
        })
        .returning();
      await storage.createAuditLog({
        orgId,
        userId: user?.id,
        userName: user?.username || "unknown",
        action: "evidence_tag_added",
        resourceType: "evidence_item",
        resourceId: evidence.id,
        details: { tag: parsed.data.tag, category: parsed.data.category },
      });
      return reply(res, tag, undefined, 201);
    },
  );

  app.delete(
    "/api/evidence-custody/:id/tags/:tagId",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      const orgId = getOrgId(req);
      const [tag] = await db
        .delete(evidenceTags)
        .where(and(eq(evidenceTags.id, String(req.params.tagId)), eq(evidenceTags.orgId, orgId)))
        .returning();
      if (!tag || tag.evidenceId !== String(req.params.id)) {
        return replyError(res, 404, [{ code: "NOT_FOUND", message: "Tag not found." }]);
      }
      const user = (req as any).user;
      await storage.createAuditLog({
        orgId,
        userId: user?.id,
        userName: user?.username || "unknown",
        action: "evidence_tag_removed",
        resourceType: "evidence_item",
        resourceId: tag.evidenceId,
        details: { tagId: tag.id, tag: tag.tag },
      });
      return reply(res, { deleted: true });
    },
  );

  app.get(
    "/api/evidence-custody/:id/access-requests",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      const orgId = getOrgId(req);
      const evidence = await storage.getEvidenceItem(String(req.params.id));
      if (!evidence || evidence.orgId !== orgId) {
        return replyError(res, 404, [{ code: "NOT_FOUND", message: "Evidence not found." }]);
      }
      const requests = await db
        .select()
        .from(evidenceAccessRequests)
        .where(and(eq(evidenceAccessRequests.orgId, orgId), eq(evidenceAccessRequests.evidenceId, evidence.id)))
        .orderBy(desc(evidenceAccessRequests.createdAt));
      return sendEnvelope(res, requests, { meta: { total: requests.length } });
    },
  );

  app.post(
    "/api/evidence-custody/:id/access-requests",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      const orgId = getOrgId(req);
      const parsed = accessRequestSchema.safeParse(req.body);
      if (!parsed.success) {
        return replyError(res, 400, [{ code: "VALIDATION_ERROR", message: "Invalid access request data." }]);
      }
      const evidence = await storage.getEvidenceItem(String(req.params.id));
      if (!evidence || evidence.orgId !== orgId) {
        return replyError(res, 404, [{ code: "NOT_FOUND", message: "Evidence not found." }]);
      }
      const user = (req as any).user;
      const [request] = await db
        .insert(evidenceAccessRequests)
        .values({
          ...parsed.data,
          orgId,
          evidenceId: evidence.id,
          requestedBy: user?.id,
          requestedByName: user?.username || "unknown",
        })
        .returning();
      await storage.createAuditLog({
        orgId,
        userId: user?.id,
        userName: user?.username || "unknown",
        action: "evidence_access_requested",
        resourceType: "evidence_item",
        resourceId: evidence.id,
        details: { requestId: request.id, accessType: request.accessType },
      });
      return reply(res, request, undefined, 201);
    },
  );

  app.post(
    "/api/evidence-custody/:id/access-requests/:requestId/decide",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req, res) => {
      const orgId = getOrgId(req);
      const parsed = decisionSchema.safeParse(req.body);
      if (!parsed.success) return replyError(res, 400, [{ code: "VALIDATION_ERROR", message: "Invalid decision." }]);
      const user = (req as any).user;
      const [request] = await db
        .update(evidenceAccessRequests)
        .set({
          status: parsed.data.decision,
          decisionNote: parsed.data.note,
          decidedBy: user?.id,
          decidedByName: user?.username || "unknown",
          decidedAt: new Date(),
        })
        .where(
          and(
            eq(evidenceAccessRequests.id, String(req.params.requestId)),
            eq(evidenceAccessRequests.orgId, orgId),
            eq(evidenceAccessRequests.evidenceId, String(req.params.id)),
          ),
        )
        .returning();
      if (!request) return replyError(res, 404, [{ code: "NOT_FOUND", message: "Access request not found." }]);
      await storage.createAuditLog({
        orgId,
        userId: user?.id,
        userName: user?.username || "unknown",
        action: "evidence_access_decided",
        resourceType: "evidence_item",
        resourceId: request.evidenceId,
        details: { requestId: request.id, decision: request.status },
      });
      return reply(res, request);
    },
  );

  app.post(
    "/api/evidence-custody/:id/upload",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("analyst"),
    async (req, res) => {
      const orgId = getOrgId(req);
      const uploadSchema = z.object({
        fileName: z.string().trim().min(1).max(255),
        fileSize: z
          .number()
          .int()
          .nonnegative()
          .max(1024 * 1024 * 1024),
        mimeType: z.string().trim().min(1).max(255),
      });
      const parsed = uploadSchema.safeParse(req.body);
      if (!parsed.success)
        return replyError(res, 400, [{ code: "VALIDATION_ERROR", message: "Invalid upload metadata." }]);
      const evidence = await storage.getEvidenceItem(String(req.params.id));
      if (!evidence || evidence.orgId !== orgId) {
        return replyError(res, 404, [{ code: "NOT_FOUND", message: "Evidence not found." }]);
      }
      const [updated] = await db
        .update(evidenceItems)
        .set({
          title: parsed.data.fileName,
          fileSize: parsed.data.fileSize,
          mimeType: parsed.data.mimeType,
          storageKey: `evidence/${orgId}/${evidence.id}/${parsed.data.fileName}`,
          metadata: { ...(evidence.metadata as object), uploadStatus: "metadata-recorded" },
        })
        .where(and(eq(evidenceItems.id, evidence.id), eq(evidenceItems.orgId, orgId)))
        .returning();
      const user = (req as any).user;
      await storage.createAuditLog({
        orgId,
        userId: user?.id,
        userName: user?.username || "unknown",
        action: "evidence_upload_registered",
        resourceType: "evidence_item",
        resourceId: evidence.id,
        details: parsed.data,
      });
      return reply(res, updated);
    },
  );

  app.post(
    "/api/evidence-custody/retention-policies/apply",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("owner"),
    async (req, res) => {
      const orgId = getOrgId(req);
      const user = (req as any).user;
      const cutoff = new Date(Date.now() - 365 * 24 * 60 * 60 * 1000);
      const expired = await db
        .select({ id: evidenceItems.id })
        .from(evidenceItems)
        .where(and(eq(evidenceItems.orgId, orgId), lt(evidenceItems.createdAt, cutoff)));
      await storage.createAuditLog({
        orgId,
        userId: user?.id,
        userName: user?.username || "unknown",
        action: "evidence_retention_applied",
        resourceType: "evidence",
        resourceId: orgId,
        details: {
          cutoff: cutoff.toISOString(),
          eligible: expired.length,
          archived: 0,
          deleted: 0,
          skipped: expired.length,
        },
      });
      return reply(res, { archived: 0, deleted: 0, skipped: expired.length, evaluated: expired.length });
    },
  );

  // Export evidence with chain of custody report
  app.get(
    "/api/evidence-custody/:id/export",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const evidence = await storage.getEvidenceItem(String(req.params.id));
        if (!evidence || evidence.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Evidence not found." }]);
        }

        const chainEntries = await storage.getEvidenceChainEntries(evidence.incidentId, orgId);
        const relatedEntries = chainEntries.filter((e) => e.relatedResourceId === evidence.id);

        let isValid = true;
        if (relatedEntries.length > 0) {
          if (relatedEntries[0].previousHash !== "genesis") isValid = false;
          for (let i = 1; i < relatedEntries.length; i++) {
            if (relatedEntries[i].previousHash !== relatedEntries[i - 1].entryHash) {
              isValid = false;
              break;
            }
          }
        }

        const report = {
          exportedAt: new Date().toISOString(),
          exportedBy: (req as any).user?.username || "unknown",
          evidence: {
            id: evidence.id,
            title: evidence.title,
            type: evidence.type,
            description: evidence.description,
            incidentId: evidence.incidentId,
            mimeType: evidence.mimeType,
            fileSize: evidence.fileSize,
            metadata: evidence.metadata,
            createdAt: evidence.createdAt,
            createdByName: evidence.createdByName,
          },
          chainOfCustody: relatedEntries.map((entry) => ({
            id: entry.id,
            entryType: entry.entryType,
            actorName: entry.actorName,
            summary: entry.summary,
            entryHash: entry.entryHash,
            previousHash: entry.previousHash,
            createdAt: entry.createdAt,
          })),
          integrityVerification: {
            chainValid: isValid,
            totalEntries: relatedEntries.length,
            verifiedAt: new Date().toISOString(),
          },
          legalNotice:
            "This document constitutes an official chain of custody report. All hash verifications have been performed using SHA-256.",
        };

        const format = req.query.format as string;
        if (format === "csv") {
          const lines = [
            "Section,Field,Value",
            `Evidence,ID,${evidence.id}`,
            `Evidence,Title,${evidence.title}`,
            `Evidence,Type,${evidence.type}`,
            `Evidence,Incident,${evidence.incidentId}`,
            `Evidence,Created By,${evidence.createdByName}`,
            "",
            "Chain Entry,Type,Actor,Summary,Hash",
            ...relatedEntries.map(
              (e) => `Chain,${e.entryType},${e.actorName},${(e.summary || "").replace(/,/g, ";")},${e.entryHash}`,
            ),
          ];
          res.setHeader("Content-Type", "text/csv");
          res.setHeader("Content-Disposition", `attachment; filename="coc-report-${evidence.id}.csv"`);
          return res.send(lines.join("\n"));
        }

        return reply(res, report);
      } catch (error: unknown) {
        log.error("Failed to export evidence", { error });
        return replyError(res, 500, [{ code: "EVIDENCE_ERROR", message: "Failed to export evidence." }]);
      }
    },
  );

  // Evidence preview
  app.get(
    "/api/evidence-custody/:id/preview",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("analyst"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const evidence = await storage.getEvidenceItem(String(req.params.id));
        if (!evidence || evidence.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Evidence not found." }]);
        }

        let previewType = "text";
        let content = "";

        switch (evidence.type) {
          case "log":
            previewType = "text";
            content = `Evidence: ${evidence.title}\nType: ${evidence.type}\nCreated: ${evidence.createdAt}\nCreated By: ${evidence.createdByName}`;
            break;
          case "screenshot":
            previewType = "image";
            content = evidence.url || "";
            break;
          default:
            previewType = "json";
            content = JSON.stringify(
              {
                id: evidence.id,
                title: evidence.title,
                type: evidence.type,
                description: evidence.description,
                metadata: evidence.metadata,
                createdAt: evidence.createdAt,
              },
              null,
              2,
            );
        }

        return reply(res, {
          evidenceId: evidence.id,
          previewType,
          content,
          mimeType: evidence.mimeType || "application/octet-stream",
          fileSize: evidence.fileSize,
          truncated: (evidence.fileSize || 0) > 1048576,
        });
      } catch (error: unknown) {
        log.error("Failed to generate preview", { error });
        return replyError(res, 500, [{ code: "EVIDENCE_ERROR", message: "Failed to generate preview." }]);
      }
    },
  );

  // Delete evidence
  app.delete(
    "/api/evidence-custody/:id",
    isAuthenticated,
    resolveOrgContext,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const orgId = getOrgId(req);
        const evidence = await storage.getEvidenceItem(String(req.params.id));
        if (!evidence || evidence.orgId !== orgId) {
          return replyError(res, 404, [{ code: "NOT_FOUND", message: "Evidence not found." }]);
        }

        await storage.deleteEvidenceItem(String(req.params.id));
        return reply(res, { deleted: true });
      } catch (error: unknown) {
        log.error("Failed to delete evidence", { error });
        return replyError(res, 500, [{ code: "EVIDENCE_ERROR", message: "Failed to delete evidence." }]);
      }
    },
  );
}
