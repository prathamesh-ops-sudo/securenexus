import type { AuthenticatedUser } from "@shared/models/auth";

export type ChangePasswordInput = {
  currentPassword?: string;
  newPassword: string;
};

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
