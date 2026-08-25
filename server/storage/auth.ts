import {
  type ApiKey,
  type IdempotencyKey,
  type InsertApiKey,
  type InsertIdempotencyKey,
  type InsertPasswordResetToken,
  type PasswordResetToken,
  apiKeys,
  idempotencyKeys,
  passwordResetTokens,
} from "@shared/schema";
import { db } from "../db";
import { and, desc, eq, gt, isNull, lte, sql } from "drizzle-orm";

export async function createApiKey(key: InsertApiKey): Promise<ApiKey> {
  const [created] = await db.insert(apiKeys).values(key).returning();
  return created;
}

export async function getApiKeys(orgId?: string): Promise<ApiKey[]> {
  if (orgId) {
    return db.select().from(apiKeys).where(eq(apiKeys.orgId, orgId)).orderBy(desc(apiKeys.createdAt));
  }
  return db.select().from(apiKeys).orderBy(desc(apiKeys.createdAt));
}

export async function getApiKeyByHash(hash: string): Promise<ApiKey | undefined> {
  const [key] = await db.select().from(apiKeys).where(eq(apiKeys.keyHash, hash));
  return key;
}

export async function getApiKeyById(id: string): Promise<ApiKey | undefined> {
  const [key] = await db.select().from(apiKeys).where(eq(apiKeys.id, id)).limit(1);
  return key;
}

export async function revokeApiKey(id: string): Promise<ApiKey | undefined> {
  const [updated] = await db
    .update(apiKeys)
    .set({ isActive: false, revokedAt: new Date() })
    .where(eq(apiKeys.id, id))
    .returning();
  return updated;
}

export async function deprecateApiKey(keyId: string, replacedByKeyId: string): Promise<void> {
  const now = new Date();
  const graceExpires = new Date(now.getTime() + 24 * 60 * 60 * 1000); // 24 hours
  await db
    .update(apiKeys)
    .set({
      isActive: false,
      deprecatedAt: now,
      graceExpiresAt: graceExpires,
      replacedByKeyId: replacedByKeyId,
    })
    .where(eq(apiKeys.id, keyId));
}

export async function updateApiKeyLastUsed(id: string): Promise<void> {
  await db.update(apiKeys).set({ lastUsedAt: new Date() }).where(eq(apiKeys.id, id));
}

export async function createPasswordResetToken(token: InsertPasswordResetToken): Promise<PasswordResetToken> {
  const [created] = await db.insert(passwordResetTokens).values(token).returning();
  return created;
}

export async function replacePasswordResetToken(token: InsertPasswordResetToken): Promise<PasswordResetToken> {
  return db.transaction(async (tx) => {
    await tx
      .update(passwordResetTokens)
      .set({ usedAt: new Date() })
      .where(and(eq(passwordResetTokens.userId, token.userId), isNull(passwordResetTokens.usedAt)));
    const [created] = await tx.insert(passwordResetTokens).values(token).returning();
    return created;
  });
}

export async function getPasswordResetToken(token: string): Promise<PasswordResetToken | undefined> {
  const [row] = await db.select().from(passwordResetTokens).where(eq(passwordResetTokens.token, token));
  return row;
}

export async function markPasswordResetTokenAsUsed(token: string): Promise<void> {
  await db.update(passwordResetTokens).set({ usedAt: new Date() }).where(eq(passwordResetTokens.token, token));
}

export async function consumePasswordResetToken(token: string): Promise<PasswordResetToken | undefined> {
  const [row] = await db
    .update(passwordResetTokens)
    .set({ usedAt: new Date() })
    .where(
      and(
        eq(passwordResetTokens.token, token),
        isNull(passwordResetTokens.usedAt),
        gt(passwordResetTokens.expiresAt, new Date()),
      ),
    )
    .returning();
  return row;
}

export async function invalidateAllUserPasswordResetTokens(userId: string): Promise<void> {
  await db
    .update(passwordResetTokens)
    .set({ usedAt: new Date() })
    .where(and(eq(passwordResetTokens.userId, userId), isNull(passwordResetTokens.usedAt)));
}

export async function deleteExpiredPasswordResetTokens(): Promise<number> {
  const result = await db.delete(passwordResetTokens).where(lte(passwordResetTokens.expiresAt, new Date()));
  return result.rowCount ?? 0;
}

// Phase 7: MSSP / Parent-Child Organizations

export async function getIdempotencyKey(
  orgId: string,
  key: string,
  endpoint: string,
): Promise<IdempotencyKey | undefined> {
  const [found] = await db
    .select()
    .from(idempotencyKeys)
    .where(
      and(
        eq(idempotencyKeys.orgId, orgId),
        eq(idempotencyKeys.idempotencyKey, key),
        eq(idempotencyKeys.endpoint, endpoint),
      ),
    );
  return found;
}

export async function createIdempotencyKey(key: InsertIdempotencyKey): Promise<IdempotencyKey> {
  const [created] = await db.insert(idempotencyKeys).values(key).returning();
  return created;
}

export async function cleanupExpiredIdempotencyKeys(): Promise<number> {
  const result = await db
    .delete(idempotencyKeys)
    .where(sql`${idempotencyKeys.expiresAt} < NOW()`)
    .returning();
  return result.length;
}
