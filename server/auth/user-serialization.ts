import type { AuthenticatedUser, User } from "@shared/models/auth";

export type OrganizationMemberUser = Pick<User, "firstName" | "lastName" | "email">;

export interface UserSerializationOptions {
  orgId?: string | null;
  role?: string | null;
  mfaRequired?: boolean;
  passwordExpired?: boolean;
}

export function serializeUserForMember(user: User): OrganizationMemberUser {
  return {
    firstName: user.firstName,
    lastName: user.lastName,
    email: user.email,
  };
}

/**
 * Convert a database user into the allowlisted shape that API clients may see.
 * Authentication material must never be copied from the database row into a response.
 */
export function serializeUser(user: User, options: UserSerializationOptions = {}): AuthenticatedUser {
  return {
    id: user.id,
    email: user.email,
    firstName: user.firstName,
    lastName: user.lastName,
    profileImageUrl: user.profileImageUrl,
    isSuperAdmin: user.isSuperAdmin,
    disabledAt: user.disabledAt,
    lastLoginAt: user.lastLoginAt,
    passwordChangedAt: user.passwordChangedAt,
    passwordChangeRequired: user.passwordChangeRequired,
    mfaEnabled: user.mfaEnabled,
    mfaVerifiedAt: user.mfaVerifiedAt,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
    hasLocalPassword: Boolean(user.passwordHash),
    ...(options.orgId !== undefined ? { orgId: options.orgId } : {}),
    ...(options.role !== undefined ? { role: options.role } : {}),
    ...(options.mfaRequired !== undefined ? { mfaRequired: options.mfaRequired } : {}),
    ...(options.passwordExpired !== undefined ? { passwordExpired: options.passwordExpired } : {}),
  };
}
