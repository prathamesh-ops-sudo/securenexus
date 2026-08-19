export interface PasswordPolicyValidationResult {
  valid: boolean;
  errors: string[];
}

export function validatePasswordComplexityWithoutOrganization(password: string): PasswordPolicyValidationResult {
  const errors: string[] = [];
  const minLength = 8;

  if (password.length < minLength) {
    errors.push(`Password must be at least ${minLength} characters`);
  }

  return { valid: errors.length === 0, errors };
}
