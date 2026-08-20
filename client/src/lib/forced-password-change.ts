import type { AuthenticatedUser } from "@shared/models/auth";

export type ChangePasswordInput = {
  currentPassword?: string;
  newPassword: string;
};

export type ForcedPasswordChangeAccountState = "loading" | "error" | "unknown" | "ready";

export function resolveForcedPasswordChangeAccountState({
  user,
  isLoading,
  isError,
}: {
  user: AuthenticatedUser | null | undefined;
  isLoading: boolean;
  isError: boolean;
}): ForcedPasswordChangeAccountState {
  if (isLoading) return "loading";
  if (isError) return "error";
  if (!user || typeof user.hasLocalPassword !== "boolean") return "unknown";
  return "ready";
}

export function resolveLocalPasswordState({
  user,
  isLoading,
  isError,
}: {
  user: AuthenticatedUser | null | undefined;
  isLoading: boolean;
  isError: boolean;
}): boolean | undefined {
  if (isLoading || isError || !user || typeof user.hasLocalPassword !== "boolean") {
    return undefined;
  }

  return user.hasLocalPassword;
}

export function buildChangePasswordInput({
  currentPassword,
  newPassword,
  hasLocalPassword,
}: {
  currentPassword: string;
  newPassword: string;
  hasLocalPassword: boolean;
}): ChangePasswordInput {
  return {
    ...(hasLocalPassword && currentPassword ? { currentPassword } : {}),
    newPassword,
  };
}
