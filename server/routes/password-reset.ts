import type { Express } from "express";
import { randomBytes } from "crypto";
import { logger, storage } from "./shared";
import { authStorage } from "../auth/storage";
import { hashPassword } from "../auth/session";
import { sendEmail } from "../email-service";
import { passwordResetEmail } from "../email-templates";
import { reply, replyValidation, replyBadRequest, replyInternal } from "../api-response";

const RESET_TOKEN_EXPIRY_MS = 60 * 60 * 1000; // 1 hour
const RESET_TOKEN_EXPIRY_MINUTES = 60;

const PASSWORD_MIN_LENGTH = 8;
const EMAIL_MAX_LENGTH = 254;

function isValidEmail(email: string): boolean {
  if (email.length > EMAIL_MAX_LENGTH) return false;
  const atIndex = email.indexOf("@");
  if (atIndex < 1 || atIndex !== email.lastIndexOf("@")) return false;
  const domain = email.slice(atIndex + 1);
  if (domain.length < 3 || !domain.includes(".")) return false;
  const dotIndex = domain.lastIndexOf(".");
  if (dotIndex < 1 || dotIndex >= domain.length - 1) return false;
  return true;
}

function getAppBaseUrl(): string {
  return process.env.APP_BASE_URL || "https://nexus.aricatech.xyz";
}

export function registerPasswordResetRoutes(app: Express): void {
  app.post("/api/auth/forgot-password", async (req, res) => {
    const { email } = req.body;
    if (!email || typeof email !== "string" || !isValidEmail(email.trim())) {
      return replyValidation(res, [{ message: "A valid email address is required", field: "email" }]);
    }

    const normalizedEmail = email.trim().toLowerCase();

    reply(res, { message: "If an account with that email exists, a password reset link has been sent." });

    (async () => {
      try {
        const user = await authStorage.getUserByEmail(normalizedEmail);
        if (!user || !user.passwordHash) return;

        const token = randomBytes(32).toString("hex");
        const expiresAt = new Date(Date.now() + RESET_TOKEN_EXPIRY_MS);

        await storage.createPasswordResetToken({
          userId: user.id,
          token,
          expiresAt,
        });

        const baseUrl = getAppBaseUrl();
        const resetUrl = `${baseUrl}/reset-password?token=${token}`;

        const emailContent = passwordResetEmail({
          firstName: user.firstName || undefined,
          resetUrl,
          expiresInMinutes: RESET_TOKEN_EXPIRY_MINUTES,
        });

        await sendEmail({
          to: normalizedEmail,
          subject: emailContent.subject,
          html: emailContent.html,
          text: emailContent.text,
        });

        logger.child("password-reset").info("Password reset token created", {
          userId: user.id,
          email: normalizedEmail,
        });
      } catch (error) {
        logger.child("password-reset").error("Background forgot-password failed", { error: String(error) });
      }
    })();
  });

  app.post("/api/auth/reset-password", async (req, res) => {
    try {
      const { token, password } = req.body;

      if (!token || typeof token !== "string") {
        return replyValidation(res, [{ message: "Reset token is required", field: "token" }]);
      }

      if (!password || typeof password !== "string" || password.length < PASSWORD_MIN_LENGTH) {
        return replyValidation(res, [
          {
            message: `Password must be at least ${PASSWORD_MIN_LENGTH} characters`,
            field: "password",
          },
        ]);
      }

      const resetToken = await storage.consumePasswordResetToken(token);

      if (!resetToken) {
        return replyBadRequest(res, "Invalid, expired, or already used reset token");
      }

      const user = await authStorage.getUser(resetToken.userId);
      if (!user) {
        return replyBadRequest(res, "Invalid reset token");
      }

      const hashedPassword = await hashPassword(password);

      await authStorage.upsertUser({
        ...user,
        passwordHash: hashedPassword,
      });

      await storage.invalidateAllUserPasswordResetTokens(user.id);

      await storage.createAuditLog({
        userId: user.id,
        userName: user.email || "unknown",
        action: "password_reset",
        resourceType: "user",
        resourceId: user.id,
      });

      logger.child("password-reset").info("Password reset completed", { userId: user.id });

      return reply(res, {
        message: "Password has been reset successfully. You can now log in with your new password.",
      });
    } catch (error) {
      logger.child("password-reset").error("Failed to reset password", { error: String(error) });
      return replyInternal(res, "Failed to reset password");
    }
  });

  app.get("/api/auth/reset-password/validate", async (req, res) => {
    try {
      const token = req.query.token as string;
      if (!token) {
        return replyValidation(res, [{ message: "Token is required", field: "token" }]);
      }

      const resetToken = await storage.getPasswordResetToken(token);

      if (!resetToken || resetToken.usedAt || new Date(resetToken.expiresAt) < new Date()) {
        return reply(res, { valid: false });
      }

      return reply(res, { valid: true });
    } catch (error) {
      logger.child("password-reset").error("Failed to validate reset token", { error: String(error) });
      return replyInternal(res, "Failed to validate token");
    }
  });
}
