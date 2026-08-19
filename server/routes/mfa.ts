import type { Express, Request, Response } from "express";
import { isAuthenticated } from "../auth";
import { resolveOrgContext, requireOrgId, requireMinRole } from "../rbac";
import { logger } from "../logger";
import { eq } from "drizzle-orm";
import { db } from "../db";
import { users } from "@shared/models/auth";
import { generateSecret, generateURI, verifySync } from "otplib";
import QRCode from "qrcode";
import { encryptSsoSecret, decryptSsoSecret } from "../sso-crypto";

export function registerMfaRoutes(app: Express): void {
  const log = logger.child("mfa");

  app.get("/api/mfa/status", isAuthenticated, resolveOrgContext, async (req: Request, res: Response) => {
    try {
      const user = req.user as Express.User & { id: string };
      if (!user?.id) return res.status(401).json({ message: "Not authenticated" });
      const [dbUser] = await db.select().from(users).where(eq(users.id, user.id)).limit(1);
      if (!dbUser) return res.status(404).json({ message: "User not found" });
      res.json({
        mfaEnabled: dbUser.mfaEnabled,
        mfaVerifiedAt: dbUser.mfaVerifiedAt,
      });
    } catch (error) {
      log.error("Failed to get MFA status", { error: String(error) });
      res.status(500).json({ message: "Failed to get MFA status" });
    }
  });

  app.post(
    "/api/mfa/setup",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const user = req.user as Express.User & { id: string };
        if (!user?.id) return res.status(401).json({ message: "Not authenticated" });
        const [dbUser] = await db.select().from(users).where(eq(users.id, user.id)).limit(1);
        if (!dbUser) return res.status(404).json({ message: "User not found" });
        if (dbUser.mfaEnabled) return res.status(400).json({ message: "MFA is already enabled" });

        const secret = generateSecret();
        const encryptedSecret = encryptSsoSecret(secret);
        await db.update(users).set({ mfaSecret: encryptedSecret }).where(eq(users.id, user.id));

        const issuer = "SecureNexus";
        const accountName = dbUser.email || user.id;
        const otpauthUrl = generateURI({ issuer, label: accountName, secret });
        const qrCodeDataUrl = await QRCode.toDataURL(otpauthUrl);

        res.json({ secret, otpauthUrl, qrCodeDataUrl });
      } catch (error) {
        log.error("Failed to setup MFA", { error: String(error) });
        res.status(500).json({ message: "Failed to setup MFA" });
      }
    },
  );

  app.post(
    "/api/mfa/verify",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const user = req.user as Express.User & { id: string };
        if (!user?.id) return res.status(401).json({ message: "Not authenticated" });
        const { token } = req.body;
        if (!token || typeof token !== "string" || !/^\d{6}$/.test(token)) {
          return res.status(400).json({ message: "Invalid token format. Must be 6 digits." });
        }

        const [dbUser] = await db.select().from(users).where(eq(users.id, user.id)).limit(1);
        if (!dbUser) return res.status(404).json({ message: "User not found" });
        if (!dbUser.mfaSecret) return res.status(400).json({ message: "MFA not set up. Call /api/mfa/setup first." });

        const decryptedSecret = decryptSsoSecret(dbUser.mfaSecret);
        const result1 = verifySync({ token, secret: decryptedSecret });
        if (!result1.valid) return res.status(400).json({ message: "Invalid verification code" });

        await db.update(users).set({ mfaEnabled: true, mfaVerifiedAt: new Date() }).where(eq(users.id, user.id));

        log.info("MFA enabled", { userId: user.id });
        res.json({ success: true, message: "MFA enabled successfully" });
      } catch (error) {
        log.error("Failed to verify MFA", { error: String(error) });
        res.status(500).json({ message: "Failed to verify MFA" });
      }
    },
  );

  app.post(
    "/api/mfa/disable",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const user = req.user as Express.User & { id: string };
        if (!user?.id) return res.status(401).json({ message: "Not authenticated" });
        const { token } = req.body;
        if (!token || typeof token !== "string" || !/^\d{6}$/.test(token)) {
          return res.status(400).json({ message: "Invalid token format. Must be 6 digits." });
        }

        const [dbUser] = await db.select().from(users).where(eq(users.id, user.id)).limit(1);
        if (!dbUser) return res.status(404).json({ message: "User not found" });
        if (!dbUser.mfaEnabled || !dbUser.mfaSecret) {
          return res.status(400).json({ message: "MFA is not enabled" });
        }

        const decryptedSecret = decryptSsoSecret(dbUser.mfaSecret);
        const result2 = verifySync({ token, secret: decryptedSecret });
        if (!result2.valid) return res.status(400).json({ message: "Invalid verification code" });

        await db
          .update(users)
          .set({ mfaEnabled: false, mfaSecret: null, mfaVerifiedAt: null })
          .where(eq(users.id, user.id));

        log.info("MFA disabled", { userId: user.id });
        res.json({ success: true, message: "MFA disabled successfully" });
      } catch (error) {
        log.error("Failed to disable MFA", { error: String(error) });
        res.status(500).json({ message: "Failed to disable MFA" });
      }
    },
  );

  app.post(
    "/api/mfa/validate",
    isAuthenticated,
    resolveOrgContext,
    requireOrgId,
    requireMinRole("admin"),
    async (req: Request, res: Response) => {
      try {
        const user = req.user as Express.User & { id: string };
        if (!user?.id) return res.status(401).json({ message: "Not authenticated" });
        const { token } = req.body;
        if (!token || typeof token !== "string" || !/^\d{6}$/.test(token)) {
          return res.status(400).json({ message: "Invalid token format" });
        }

        const [dbUser] = await db.select().from(users).where(eq(users.id, user.id)).limit(1);
        if (!dbUser || !dbUser.mfaEnabled || !dbUser.mfaSecret) {
          return res.status(400).json({ message: "MFA not configured" });
        }

        const decryptedSecret = decryptSsoSecret(dbUser.mfaSecret);
        const result3 = verifySync({ token, secret: decryptedSecret });
        if (!result3.valid) return res.status(401).json({ message: "Invalid MFA code" });

        res.json({ success: true });
      } catch (error) {
        log.error("Failed to validate MFA", { error: String(error) });
        res.status(500).json({ message: "Failed to validate MFA" });
      }
    },
  );
}
