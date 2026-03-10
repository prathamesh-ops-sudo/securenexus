import { sql } from "drizzle-orm";
import { boolean, index, integer, jsonb, pgTable, text, timestamp, varchar } from "drizzle-orm/pg-core";

// Session storage table.
export const sessions = pgTable(
  "sessions",
  {
    sid: varchar("sid").primaryKey(),
    sess: jsonb("sess").notNull(),
    expire: timestamp("expire").notNull(),
  },
  (table) => [index("IDX_session_expire").on(table.expire)],
);

// User storage table.
export const users = pgTable("users", {
  id: varchar("id")
    .primaryKey()
    .default(sql`gen_random_uuid()`),
  email: varchar("email").unique(),
  passwordHash: varchar("password_hash"),
  firstName: varchar("first_name"),
  lastName: varchar("last_name"),
  profileImageUrl: varchar("profile_image_url"),
  isSuperAdmin: boolean("is_super_admin").default(false).notNull(),
  disabledAt: timestamp("disabled_at"),
  lastLoginAt: timestamp("last_login_at"),
  passwordChangedAt: timestamp("password_changed_at"),
  lockedUntil: timestamp("locked_until"),
  failedLoginCount: integer("failed_login_count").default(0).notNull(),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export type UpsertUser = typeof users.$inferInsert;
export type User = typeof users.$inferSelect;

export const impersonationSessions = pgTable(
  "impersonation_sessions",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    superAdminId: varchar("super_admin_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    targetUserId: varchar("target_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    sessionSid: varchar("session_sid").notNull(),
    expiresAt: timestamp("expires_at").notNull(),
    endedAt: timestamp("ended_at"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_impersonation_admin").on(table.superAdminId),
    index("idx_impersonation_target").on(table.targetUserId),
    index("idx_impersonation_session").on(table.sessionSid),
  ],
);

export type ImpersonationSession = typeof impersonationSessions.$inferSelect;

export const failedLoginAttempts = pgTable(
  "failed_login_attempts",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    userId: varchar("user_id").references(() => users.id, { onDelete: "cascade" }),
    email: varchar("email").notNull(),
    ipAddress: text("ip_address").notNull(),
    userAgent: text("user_agent"),
    reason: text("reason").notNull(),
    attemptedAt: timestamp("attempted_at").defaultNow().notNull(),
  },
  (table) => [
    index("idx_failed_login_email").on(table.email),
    index("idx_failed_login_user").on(table.userId),
    index("idx_failed_login_ip").on(table.ipAddress),
    index("idx_failed_login_attempted").on(table.attemptedAt),
  ],
);

export type FailedLoginAttempt = typeof failedLoginAttempts.$inferSelect;
