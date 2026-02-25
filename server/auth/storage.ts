import { users, type User, type UpsertUser } from "@shared/models/auth";
import { db } from "../db";
import { eq } from "drizzle-orm";

export interface IAuthStorage {
  getUser(id: string): Promise<User | undefined>;
  getUserByEmail(email: string): Promise<User | undefined>;
  upsertUser(user: UpsertUser): Promise<User>;
}

class AuthStorage implements IAuthStorage {
  async getUser(id: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user;
  }

  async getUserByEmail(email: string): Promise<User | undefined> {
    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.email, email));
    return user;
  }

  async upsertUser(userData: UpsertUser): Promise<User> {
    try {
      const [user] = await db
        .insert(users)
        .values(userData)
        .onConflictDoUpdate({
          target: users.id,
          set: {
            ...userData,
            updatedAt: new Date(),
          },
        })
        .returning();
      return user;
    } catch (err: any) {
      if (err?.code === "23505" && userData.email) {
        const [existing] = await db.select().from(users).where(eq(users.email, userData.email));
        if (existing) {
          const [updated] = await db
            .update(users)
            .set({ ...userData, id: existing.id, updatedAt: new Date() })
            .where(eq(users.id, existing.id))
            .returning();
          return updated;
        }
      }
      throw err;
    }
  }
}

export const authStorage = new AuthStorage();
