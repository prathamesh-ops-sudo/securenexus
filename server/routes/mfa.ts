import type { Express, Request, Response } from "express";
import { isAuthenticated } from "../auth";
import { resolveOrgContext } from "../rbac";
import { logger } from "../logger";
import { eq } from "drizzle-orm";
import { db } from "../db";
import { users } from "@shared/models/auth";
import crypto from "crypto";

function generateBase32Secret(length = 20): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes = crypto.randomBytes(length);
  let result = "";
  for (let i = 0; i < length; i++) {
    result += chars[bytes[i] % 32];
  }
  return result;
}

function generateTOTP(secret: string, timeStep = 30, digits = 6): string {
  const epoch = Math.floor(Date.now() / 1000);
  const counter = Math.floor(epoch / timeStep);
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeUInt32BE(0, 0);
  counterBuffer.writeUInt32BE(counter, 4);

  const decodedSecret = base32Decode(secret);
  const hmac = crypto.createHmac("sha1", decodedSecret);
  hmac.update(counterBuffer);
  const hmacResult = hmac.digest();

  const offset = hmacResult[hmacResult.length - 1] & 0xf;
  const code =
    ((hmacResult[offset] & 0x7f) << 24) |
    ((hmacResult[offset + 1] & 0xff) << 16) |
    ((hmacResult[offset + 2] & 0xff) << 8) |
    (hmacResult[offset + 3] & 0xff);

  const otp = code % Math.pow(10, digits);
  return otp.toString().padStart(digits, "0");
}

function base32Decode(encoded: string): Buffer {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of encoded.toUpperCase()) {
    const val = chars.indexOf(c);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, "0");
  }
  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.substring(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

function verifyTOTP(secret: string, token: string, window = 1): boolean {
  for (let i = -window; i <= window; i++) {
    const epoch = Math.floor(Date.now() / 1000) + i * 30;
    const counter = Math.floor(epoch / 30);
    const counterBuffer = Buffer.alloc(8);
    counterBuffer.writeUInt32BE(0, 0);
    counterBuffer.writeUInt32BE(counter, 4);

    const decodedSecret = base32Decode(secret);
    const hmac = crypto.createHmac("sha1", decodedSecret);
    hmac.update(counterBuffer);
    const hmacResult = hmac.digest();

    const offset = hmacResult[hmacResult.length - 1] & 0xf;
    const code =
      ((hmacResult[offset] & 0x7f) << 24) |
      ((hmacResult[offset + 1] & 0xff) << 16) |
      ((hmacResult[offset + 2] & 0xff) << 8) |
      (hmacResult[offset + 3] & 0xff);

    const otp = (code % 1000000).toString().padStart(6, "0");
    if (otp === token) return true;
  }
  return false;
}

export function registerMfaRoutes(app: Express): void {
  const log = logger.child("mfa");

  app.get("/api/mfa/status", isAuthenticated, resolveOrgContext, async (req: Request, res: Response) => {
    try {
      const user = req.user as any;
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

  app.post("/api/mfa/setup", isAuthenticated, resolveOrgContext, async (req: Request, res: Response) => {
    try {
      const user = req.user as any;
      if (!user?.id) return res.status(401).json({ message: "Not authenticated" });
      const [dbUser] = await db.select().from(users).where(eq(users.id, user.id)).limit(1);
      if (!dbUser) return res.status(404).json({ message: "User not found" });
      if (dbUser.mfaEnabled) return res.status(400).json({ message: "MFA is already enabled" });

      const secret = generateBase32Secret();
      await db.update(users).set({ mfaSecret: secret }).where(eq(users.id, user.id));

      const issuer = "SecureNexus";
      const accountName = dbUser.email || user.id;
      const otpauthUrl = `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(accountName)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;

      res.json({ secret, otpauthUrl });
    } catch (error) {
      log.error("Failed to setup MFA", { error: String(error) });
      res.status(500).json({ message: "Failed to setup MFA" });
    }
  });

  app.post("/api/mfa/verify", isAuthenticated, resolveOrgContext, async (req: Request, res: Response) => {
    try {
      const user = req.user as any;
      if (!user?.id) return res.status(401).json({ message: "Not authenticated" });
      const { token } = req.body;
      if (!token || typeof token !== "string" || !/^\d{6}$/.test(token)) {
        return res.status(400).json({ message: "Invalid token format. Must be 6 digits." });
      }

      const [dbUser] = await db.select().from(users).where(eq(users.id, user.id)).limit(1);
      if (!dbUser) return res.status(404).json({ message: "User not found" });
      if (!dbUser.mfaSecret) return res.status(400).json({ message: "MFA not set up. Call /api/mfa/setup first." });

      const isValid = verifyTOTP(dbUser.mfaSecret, token);
      if (!isValid) return res.status(400).json({ message: "Invalid verification code" });

      await db.update(users).set({ mfaEnabled: true, mfaVerifiedAt: new Date() }).where(eq(users.id, user.id));

      log.info("MFA enabled", { userId: user.id });
      res.json({ success: true, message: "MFA enabled successfully" });
    } catch (error) {
      log.error("Failed to verify MFA", { error: String(error) });
      res.status(500).json({ message: "Failed to verify MFA" });
    }
  });

  app.post("/api/mfa/disable", isAuthenticated, resolveOrgContext, async (req: Request, res: Response) => {
    try {
      const user = req.user as any;
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

      const isValid = verifyTOTP(dbUser.mfaSecret, token);
      if (!isValid) return res.status(400).json({ message: "Invalid verification code" });

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
  });

  app.post("/api/mfa/validate", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const user = req.user as any;
      if (!user?.id) return res.status(401).json({ message: "Not authenticated" });
      const { token } = req.body;
      if (!token || typeof token !== "string" || !/^\d{6}$/.test(token)) {
        return res.status(400).json({ message: "Invalid token format" });
      }

      const [dbUser] = await db.select().from(users).where(eq(users.id, user.id)).limit(1);
      if (!dbUser || !dbUser.mfaEnabled || !dbUser.mfaSecret) {
        return res.status(400).json({ message: "MFA not configured" });
      }

      const isValid = verifyTOTP(dbUser.mfaSecret, token);
      if (!isValid) return res.status(401).json({ message: "Invalid MFA code" });

      res.json({ success: true });
    } catch (error) {
      log.error("Failed to validate MFA", { error: String(error) });
      res.status(500).json({ message: "Failed to validate MFA" });
    }
  });
}
