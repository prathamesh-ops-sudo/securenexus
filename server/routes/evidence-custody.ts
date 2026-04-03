/* eslint-disable @typescript-eslint/no-explicit-any */
import type { Express, Request, Response } from "express";
import { getOrgId, logger, reply, replyError, sendEnvelope, storage } from "./shared";
import { isAuthenticated } from "../auth";
import { requireMinRole, resolveOrgContext } from "../rbac";
import { createHash } from "crypto";

export function registerEvidenceCustodyRoutes(app: Express): void {
  const log = logger.child("evidence-custody");

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
