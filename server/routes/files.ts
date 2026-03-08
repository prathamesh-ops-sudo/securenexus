import type { Express } from "express";
import multer from "multer";
import { getOrgId, logger } from "./shared";
import { isAuthenticated } from "../auth";
import { deleteFile, getSignedUrl, listFiles, uploadFile } from "../s3";

const MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024;
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: MAX_FILE_SIZE_BYTES } });

const BLOCKED_EXTENSIONS = new Set([
  "exe",
  "bat",
  "cmd",
  "com",
  "msi",
  "scr",
  "pif",
  "vbs",
  "vbe",
  "js",
  "jse",
  "wsf",
  "wsh",
  "ps1",
  "psm1",
  "sh",
  "bash",
  "dll",
  "sys",
  "drv",
]);

function sanitizePrefix(raw: string, opts?: { allowEmpty?: boolean }): string | null {
  const allowEmpty = opts?.allowEmpty ?? false;

  let decoded: string;
  try {
    decoded = decodeURIComponent(raw);
  } catch {
    return null;
  }

  let s = decoded.replace(/\\/g, "/").replace(/^\/+/, "");
  s = s.replace(/\/{2,}/g, "/");

  if (!s) return allowEmpty ? "" : null;
  if (s.length > 200) return null;
  if (s.includes("..") || s.includes("\u0000")) return null;
  if (s.startsWith("orgs/")) return null;
  if (!/^[a-zA-Z0-9/_-]+\/?$/.test(s)) return null;

  if (!s.endsWith("/")) s += "/";
  return s;
}

function isValidS3Key(key: string, orgId: string | number): boolean {
  if (!key || typeof key !== "string") return false;
  if (key.includes("\0")) return false;
  if (key.includes("..")) return false;
  if (key.length > 1024) return false;
  const normalized = key.replace(/\\+/g, "/").replace(/\/{2,}/g, "/");
  if (normalized !== key) return false;
  return normalized.startsWith(`orgs/${orgId}/`);
}

function sanitizeFilename(raw: string): string {
  const base = raw.split(/[\\/\\\\]/).pop() || "file";
  const cleaned = base
    .replace(/[\u0000-\u001F\u007F]/g, "_")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\.{2,}/g, ".")
    .replace(/[^a-zA-Z0-9._\- ]/g, "_")
    .slice(0, 255);

  return cleaned || "file";
}

export function registerFilesRoutes(app: Express): void {
  app.post("/api/files/upload", isAuthenticated, upload.single("file"), async (req, res) => {
    try {
      if (!req.file) return res.status(400).json({ message: "No file provided" });
      const orgId = getOrgId(req);
      const rawPrefix = (req.query.prefix as string) || (req.body?.prefix as string) || "uploads/";
      const prefix = sanitizePrefix(rawPrefix);
      if (!prefix) {
        return res.status(400).json({ message: "Invalid prefix" });
      }

      const baseName = req.file.originalname.split(/[/\\]/).pop() || req.file.originalname;
      const ext = baseName.split(".").pop()?.toLowerCase().trim() || "";
      if (BLOCKED_EXTENSIONS.has(ext)) {
        return res.status(400).json({ message: `File type .${ext} is not allowed` });
      }

      const safeName = sanitizeFilename(baseName);
      const key = `orgs/${orgId}/${prefix}${Date.now()}-${safeName}`;
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
      const rawSub = (req.query.prefix as string) || "";
      const subPrefix = sanitizePrefix(rawSub, { allowEmpty: true });
      if (subPrefix === null) {
        return res.status(400).json({ message: "Invalid prefix" });
      }
      const prefix = `orgs/${orgId}/${subPrefix}`;
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
      if (!isValidS3Key(key, orgId)) return res.status(403).json({ message: "Access denied" });
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
      if (!isValidS3Key(key, orgId)) return res.status(403).json({ message: "Access denied" });
      const result = await deleteFile(key);
      res.json(result);
    } catch (error) {
      res.status(500).json({ message: "Failed to delete file" });
    }
  });
}
