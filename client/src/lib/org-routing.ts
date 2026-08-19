export function getOrglessDestination(isSuperAdmin: boolean): "/platform-admin" | "/no-organization" {
  return isSuperAdmin ? "/platform-admin" : "/no-organization";
}
