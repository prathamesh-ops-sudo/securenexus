import type { Express } from "express";
import { getOrgId, logger, p, sendEnvelope, storage } from "./shared";
import { isAuthenticated } from "../auth";
import {
  insertReportTemplateVersionSchema,
  insertEvidenceAttachmentSchema,
  insertComplianceControlHelperSchema,
} from "@shared/schema";

export function registerReportGovernanceRoutes(app: Express): void {
  // ==========================================
  // Report Template Versioning
  // ==========================================

  app.get("/api/report-templates/:templateId/versions", isAuthenticated, async (req, res) => {
    try {
      const user = req.user as any;
      const template = await storage.getReportTemplate(p(req.params.templateId));
      if (!template) return res.status(404).json({ message: "Template not found" });
      if (template.orgId && user?.orgId && template.orgId !== user.orgId) {
        return res.status(403).json({ message: "Access denied" });
      }
      const versions = await storage.getReportTemplateVersions(template.id, user?.orgId);
      res.json(versions);
    } catch (error) {
      logger.child("report-governance").error("Failed to fetch template versions", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch template versions" });
    }
  });

  app.get("/api/report-template-versions/:id", isAuthenticated, async (req, res) => {
    try {
      const version = await storage.getReportTemplateVersion(p(req.params.id));
      if (!version) return res.status(404).json({ message: "Version not found" });
      const user = req.user as any;
      if (user?.orgId && version.orgId !== user.orgId) {
        return res.status(403).json({ message: "Access denied" });
      }
      res.json(version);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch template version" });
    }
  });

  app.post("/api/report-templates/:templateId/versions", isAuthenticated, async (req, res) => {
    try {
      const user = req.user as any;
      const orgId = getOrgId(req);
      const template = await storage.getReportTemplate(p(req.params.templateId));
      if (!template) return res.status(404).json({ message: "Template not found" });
      if (template.orgId && user?.orgId && template.orgId !== user.orgId) {
        return res.status(403).json({ message: "Access denied" });
      }
      const latest = await storage.getLatestTemplateVersion(template.id);
      const nextVersion = latest ? latest.version + 1 : 1;
      const parsed = insertReportTemplateVersionSchema.safeParse({
        ...req.body,
        orgId,
        templateId: template.id,
        version: nextVersion,
        createdBy: user?.id || null,
      });
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid version data", errors: parsed.error.flatten() });
      }
      const version = await storage.createReportTemplateVersion(parsed.data);
      await storage.createAuditLog({
        orgId,
        userId: user?.id,
        userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst",
        action: "report_template_version_created",
        resourceType: "report_template_version",
        resourceId: version.id,
        details: { templateId: template.id, version: nextVersion, changeDescription: version.changeDescription },
      });
      res.status(201).json(version);
    } catch (error: any) {
      if (error.message === "ORG_CONTEXT_MISSING")
        return res.status(403).json({ message: "Organization context required" });
      logger.child("report-governance").error("Failed to create template version", { error: String(error) });
      res.status(500).json({ message: "Failed to create template version" });
    }
  });

  app.patch("/api/report-template-versions/:id", isAuthenticated, async (req, res) => {
    try {
      const user = req.user as any;
      const existing = await storage.getReportTemplateVersion(p(req.params.id));
      if (!existing) return res.status(404).json({ message: "Version not found" });
      if (user?.orgId && existing.orgId !== user.orgId) {
        return res.status(403).json({ message: "Access denied" });
      }
      const allowedFields = ["status", "changeDescription", "config", "format", "approvedBy", "approvedAt"];
      const sanitized: Record<string, any> = {};
      for (const key of allowedFields) {
        if (req.body[key] !== undefined) sanitized[key] = req.body[key];
      }
      if (sanitized.status === "active" && !sanitized.approvedBy) {
        sanitized.approvedBy = user?.id;
        sanitized.approvedAt = new Date();
      }
      const updated = await storage.updateReportTemplateVersion(p(req.params.id), sanitized);
      res.json(updated);
    } catch (error) {
      res.status(500).json({ message: "Failed to update template version" });
    }
  });

  // ==========================================
  // Evidence Attachments (S3-backed)
  // ==========================================

  app.get("/api/evidence-attachments", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const controlMappingId = req.query.controlMappingId as string | undefined;
      const attachments = await storage.getEvidenceAttachments(orgId, controlMappingId);
      res.json(attachments);
    } catch (error: any) {
      if (error.message === "ORG_CONTEXT_MISSING")
        return res.status(403).json({ message: "Organization context required" });
      res.status(500).json({ message: "Failed to fetch evidence attachments" });
    }
  });

  app.get("/api/evidence-attachments/:id", isAuthenticated, async (req, res) => {
    try {
      const attachment = await storage.getEvidenceAttachment(p(req.params.id));
      if (!attachment) return res.status(404).json({ message: "Attachment not found" });
      const user = req.user as any;
      if (user?.orgId && attachment.orgId !== user.orgId) {
        return res.status(403).json({ message: "Access denied" });
      }
      res.json(attachment);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch evidence attachment" });
    }
  });

  app.post("/api/evidence-attachments", isAuthenticated, async (req, res) => {
    try {
      const user = req.user as any;
      const orgId = getOrgId(req);
      const parsed = insertEvidenceAttachmentSchema.safeParse({
        fileName: req.body.fileName,
        mimeType: req.body.mimeType,
        controlMappingId: req.body.controlMappingId || null,
        evidenceLockerId: req.body.evidenceLockerId || null,
        orgId,
        uploadedBy: user?.id || null,
        uploadedByName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : null,
      });
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid attachment data", errors: parsed.error.flatten() });
      }
      const attachment = await storage.createEvidenceAttachment(parsed.data);
      await storage.createAuditLog({
        orgId,
        userId: user?.id,
        userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst",
        action: "evidence_attachment_created",
        resourceType: "evidence_attachment",
        resourceId: attachment.id,
        details: { fileName: attachment.fileName, controlMappingId: attachment.controlMappingId },
      });
      res.status(201).json(attachment);
    } catch (error: any) {
      if (error.message === "ORG_CONTEXT_MISSING")
        return res.status(403).json({ message: "Organization context required" });
      logger.child("report-governance").error("Failed to create evidence attachment", { error: String(error) });
      res.status(500).json({ message: "Failed to create evidence attachment" });
    }
  });

  app.post("/api/evidence-attachments/:id/presign", isAuthenticated, async (req, res) => {
    try {
      const user = req.user as any;
      const attachment = await storage.getEvidenceAttachment(p(req.params.id));
      if (!attachment) return res.status(404).json({ message: "Attachment not found" });
      if (user?.orgId && attachment.orgId !== user.orgId) {
        return res.status(403).json({ message: "Access denied" });
      }
      const action = (req.body.action as string) || "upload";
      const evidenceBucket = process.env.EVIDENCE_S3_BUCKET || "securenexus-evidence";
      const bucket = attachment.s3Bucket === evidenceBucket ? attachment.s3Bucket : evidenceBucket;
      const sanitizedFileName = (attachment.fileName || "file").replace(/[^a-zA-Z0-9._-]/g, "_");
      const key =
        attachment.s3Key && attachment.s3Key.startsWith(`evidence/${attachment.orgId}/`)
          ? attachment.s3Key
          : `evidence/${attachment.orgId}/${attachment.id}/${sanitizedFileName}`;
      try {
        const { S3Client, PutObjectCommand, GetObjectCommand } = await import("@aws-sdk/client-s3");
        const { getSignedUrl } = await import("@aws-sdk/s3-request-presigner");
        const s3 = new S3Client({ region: process.env.AWS_REGION || "us-east-1" });
        const command =
          action === "download"
            ? new GetObjectCommand({ Bucket: bucket, Key: key })
            : new PutObjectCommand({
                Bucket: bucket,
                Key: key,
                ContentType: attachment.mimeType || "application/octet-stream",
              });
        const presignedUrl = await getSignedUrl(s3, command, { expiresIn: 3600 });
        if (action === "upload" && !attachment.s3Bucket) {
          await storage.updateEvidenceAttachment(attachment.id, { s3Bucket: bucket, s3Key: key });
        }
        res.json({ url: presignedUrl, bucket, key, expiresIn: 3600, action });
      } catch (s3Error) {
        logger.child("report-governance").warn("S3 presign failed, returning placeholder", { error: String(s3Error) });
        res.json({
          url: `https://${bucket}.s3.amazonaws.com/${key}?placeholder=true`,
          bucket,
          key,
          expiresIn: 3600,
          action,
          note: "S3 presigning unavailable — use this key for manual upload",
        });
      }
    } catch (error: any) {
      if (error.message === "ORG_CONTEXT_MISSING")
        return res.status(403).json({ message: "Organization context required" });
      res.status(500).json({ message: "Failed to generate presigned URL" });
    }
  });

  app.patch("/api/evidence-attachments/:id", isAuthenticated, async (req, res) => {
    try {
      const user = req.user as any;
      const existing = await storage.getEvidenceAttachment(p(req.params.id));
      if (!existing) return res.status(404).json({ message: "Attachment not found" });
      if (user?.orgId && existing.orgId !== user.orgId) {
        return res.status(403).json({ message: "Access denied" });
      }
      const allowedFields = ["status", "reviewedBy", "reviewedAt", "reviewNotes", "checksum", "fileSize", "mimeType"];
      const sanitized: Record<string, any> = {};
      for (const key of allowedFields) {
        if (req.body[key] !== undefined) sanitized[key] = req.body[key];
      }
      if (sanitized.status === "verified" && !sanitized.reviewedBy) {
        sanitized.reviewedBy = user?.id;
        sanitized.reviewedAt = new Date();
      }
      const updated = await storage.updateEvidenceAttachment(p(req.params.id), sanitized);
      res.json(updated);
    } catch (error) {
      res.status(500).json({ message: "Failed to update evidence attachment" });
    }
  });

  app.delete("/api/evidence-attachments/:id", isAuthenticated, async (req, res) => {
    try {
      const user = req.user as any;
      const existing = await storage.getEvidenceAttachment(p(req.params.id));
      if (!existing) return res.status(404).json({ message: "Attachment not found" });
      if (user?.orgId && existing.orgId !== user.orgId) {
        return res.status(403).json({ message: "Access denied" });
      }
      await storage.deleteEvidenceAttachment(p(req.params.id));
      await storage.createAuditLog({
        orgId: existing.orgId,
        userId: user?.id,
        userName: user?.firstName ? `${user.firstName} ${user.lastName || ""}`.trim() : "Analyst",
        action: "evidence_attachment_deleted",
        resourceType: "evidence_attachment",
        resourceId: existing.id,
        details: { fileName: existing.fileName },
      });
      res.json({ message: "Attachment deleted" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete evidence attachment" });
    }
  });

  // ==========================================
  // Compliance Control Mapping Helpers
  // ==========================================

  app.get("/api/compliance-helpers", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const helperType = req.query.helperType as string | undefined;
      const helpers = await storage.getComplianceControlHelpers(orgId, helperType);
      res.json(helpers);
    } catch (error: any) {
      if (error.message === "ORG_CONTEXT_MISSING")
        return res.status(403).json({ message: "Organization context required" });
      res.status(500).json({ message: "Failed to fetch compliance helpers" });
    }
  });

  app.get("/api/compliance-helpers/coverage-summary", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const frameworks = ["NIST CSF", "ISO 27001", "CIS", "SOC 2"];
      const summary: any[] = [];

      const mappings = await storage.getComplianceControlMappings(orgId);
      const mappedControlIds = new Set(mappings.map((m: any) => m.controlId));

      for (const framework of frameworks) {
        const controls = await storage.getComplianceControls(framework);
        const coveredCount = controls.filter((c: any) => mappedControlIds.has(c.id)).length;

        summary.push({
          framework,
          totalControls: controls.length,
          coveredCount,
          gapCount: controls.length - coveredCount,
          coveragePercent: controls.length > 0 ? Math.round((coveredCount / controls.length) * 100) : 0,
        });
      }

      res.json({ frameworks: summary, generatedAt: new Date().toISOString() });
    } catch (error: any) {
      if (error.message === "ORG_CONTEXT_MISSING")
        return res.status(403).json({ message: "Organization context required" });
      res.status(500).json({ message: "Failed to generate coverage summary" });
    }
  });

  app.get("/api/compliance-helpers/:id", isAuthenticated, async (req, res) => {
    try {
      const helper = await storage.getComplianceControlHelper(p(req.params.id));
      if (!helper) return res.status(404).json({ message: "Helper not found" });
      const user = req.user as any;
      if (user?.orgId && helper.orgId !== user.orgId) {
        return res.status(403).json({ message: "Access denied" });
      }
      res.json(helper);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch compliance helper" });
    }
  });

  app.post("/api/compliance-helpers", isAuthenticated, async (req, res) => {
    try {
      const user = req.user as any;
      const orgId = getOrgId(req);
      const parsed = insertComplianceControlHelperSchema.safeParse({
        ...req.body,
        orgId,
        createdBy: user?.id || null,
      });
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid helper data", errors: parsed.error.flatten() });
      }
      const helper = await storage.createComplianceControlHelper(parsed.data);
      res.status(201).json(helper);
    } catch (error: any) {
      if (error.message === "ORG_CONTEXT_MISSING")
        return res.status(403).json({ message: "Organization context required" });
      res.status(500).json({ message: "Failed to create compliance helper" });
    }
  });

  app.post("/api/compliance-helpers/run-gap-analysis", isAuthenticated, async (req, res) => {
    try {
      const user = req.user as any;
      const orgId = getOrgId(req);
      const { framework } = req.body;
      if (!framework || typeof framework !== "string") {
        return res.status(400).json({ message: "framework is required" });
      }

      const controls = await storage.getComplianceControls(framework);
      const mappings = await storage.getComplianceControlMappings(orgId);
      const mappedControlIds = new Set(mappings.map((m: any) => m.controlId));

      const gaps: any[] = [];
      const covered: any[] = [];
      for (const control of controls) {
        if (mappedControlIds.has(control.id)) {
          const controlMappings = mappings.filter((m: any) => m.controlId === control.id);
          covered.push({
            controlId: control.controlId,
            title: control.title,
            category: control.category,
            mappingCount: controlMappings.length,
            statuses: controlMappings.map((m: any) => m.status),
          });
        } else {
          gaps.push({
            controlId: control.controlId,
            title: control.title,
            category: control.category,
            description: control.description,
          });
        }
      }

      const result = {
        framework,
        totalControls: controls.length,
        coveredCount: covered.length,
        gapCount: gaps.length,
        coveragePercent: controls.length > 0 ? Math.round((covered.length / controls.length) * 100) : 0,
        gaps,
        covered,
      };

      const helper = await storage.createComplianceControlHelper({
        orgId,
        helperType: "gap_analysis",
        sourceFramework: framework,
        result,
        status: "completed",
        createdBy: user?.id || null,
      });
      await storage.updateComplianceControlHelper(helper.id, { completedAt: new Date() });

      res.json({ helper, result });
    } catch (error: any) {
      if (error.message === "ORG_CONTEXT_MISSING")
        return res.status(403).json({ message: "Organization context required" });
      logger.child("report-governance").error("Gap analysis failed", { error: String(error) });
      res.status(500).json({ message: "Failed to run gap analysis" });
    }
  });

  app.post("/api/compliance-helpers/run-cross-map", isAuthenticated, async (req, res) => {
    try {
      const user = req.user as any;
      const orgId = getOrgId(req);
      const { sourceFramework, targetFramework } = req.body;
      if (!sourceFramework || !targetFramework) {
        return res.status(400).json({ message: "sourceFramework and targetFramework are required" });
      }

      const sourceControls = await storage.getComplianceControls(sourceFramework);
      const targetControls = await storage.getComplianceControls(targetFramework);
      const crossMap: any[] = [];

      for (const src of sourceControls) {
        const matches = targetControls.filter(
          (tgt: any) =>
            tgt.category?.toLowerCase() === src.category?.toLowerCase() ||
            tgt.title?.toLowerCase().includes(src.category?.toLowerCase() || "___no_match___"),
        );
        crossMap.push({
          sourceControlId: src.controlId,
          sourceTitle: src.title,
          sourceCategory: src.category,
          potentialTargetMappings: matches.map((m: any) => ({
            targetControlId: m.controlId,
            targetTitle: m.title,
            targetCategory: m.category,
          })),
          mappedCount: matches.length,
        });
      }

      const result = {
        sourceFramework,
        targetFramework,
        totalSourceControls: sourceControls.length,
        totalTargetControls: targetControls.length,
        mappedCount: crossMap.filter((c: any) => c.mappedCount > 0).length,
        unmappedCount: crossMap.filter((c: any) => c.mappedCount === 0).length,
        crossMap,
      };

      const helper = await storage.createComplianceControlHelper({
        orgId,
        helperType: "cross_map",
        sourceFramework,
        targetFramework,
        result,
        status: "completed",
        createdBy: user?.id || null,
      });
      await storage.updateComplianceControlHelper(helper.id, { completedAt: new Date() });

      res.json({ helper, result });
    } catch (error: any) {
      if (error.message === "ORG_CONTEXT_MISSING")
        return res.status(403).json({ message: "Organization context required" });
      logger.child("report-governance").error("Cross-map failed", { error: String(error) });
      res.status(500).json({ message: "Failed to run cross-map" });
    }
  });
}
