export type ChangePasswordInput = {
  currentPassword?: string;
  newPassword: string;
};

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
