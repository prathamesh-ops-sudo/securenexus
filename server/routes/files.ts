import type { Express, Request, Response } from "express";
import multer from "multer";
import { getOrgId, logger } from "./shared";
import { isAuthenticated } from "../auth";
import { deleteFile, getSignedUrl, listFiles, uploadFile } from "../s3";

const MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024;
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: MAX_FILE_SIZE_BYTES } });

export function registerFilesRoutes(app: Express): void {
  app.post("/api/files/upload", isAuthenticated, upload.single("file"), async (req, res) => {
    try {
      if (!req.file) return res.status(400).json({ message: "No file provided" });
      const orgId = getOrgId(req);
      const key = `orgs/${orgId}/uploads/${Date.now()}-${req.file.originalname}`;
      const result = await uploadFile(key, req.file.buffer, req.file.mimetype);
      res.status(201).json(result);
    } catch (error) {
      logger.child("routes").error("File upload error", { error: String(error) });
      res.status(500).json({ message: "Failed to upload file" });
    }
  });

  app.get("/api/files", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const subPrefix = req.query.prefix as string | undefined;
      const prefix = `orgs/${orgId}/${subPrefix || ""}`;
      const files = await listFiles(prefix);
      res.json(files);
    } catch (error) {
      res.status(500).json({ message: "Failed to list files" });
    }
  });

  app.get("/api/files/download", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const key = req.query.key as string;
      if (!key) return res.status(400).json({ message: "key query param required" });
      if (!key.startsWith(`orgs/${orgId}/`)) return res.status(403).json({ message: "Access denied" });
      const url = await getSignedUrl(key);
      res.json({ url });
    } catch (error) {
      res.status(500).json({ message: "Failed to get signed URL" });
    }
  });

  app.delete("/api/files/remove", isAuthenticated, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const key = req.query.key as string;
      if (!key) return res.status(400).json({ message: "key query param required" });
      if (!key.startsWith(`orgs/${orgId}/`)) return res.status(403).json({ message: "Access denied" });
      const result = await deleteFile(key);
      res.json(result);
    } catch (error) {
      res.status(500).json({ message: "Failed to delete file" });
    }
  });

}
