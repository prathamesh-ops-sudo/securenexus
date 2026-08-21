export function getOrglessDestination(isSuperAdmin: boolean): "/no-organization" | null {
  return isSuperAdmin ? null : "/no-organization";
}
