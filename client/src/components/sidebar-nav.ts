export interface SidebarNavItem {
  title: string;
  url: string;
}

const ADMIN_ONLY_URLS = ["/team", "/onboarding", "/settings", "/compliance"];
const ANALYST_HIDDEN_URLS = ["/team", "/onboarding"];

export type SidebarRole = "super_admin" | "owner" | "admin" | "read_only" | "analyst" | string | null;

export function filterNavItems<T extends SidebarNavItem>(
  items: T[],
  userRole: SidebarRole,
  hasTenantContext = true,
): T[] {
  if (!hasTenantContext) return [];
  if (userRole === "super_admin" || userRole === "owner" || userRole === "admin") return items;
  if (userRole === "read_only") return items.filter((item) => !ADMIN_ONLY_URLS.includes(item.url));
  return items.filter((item) => !ANALYST_HIDDEN_URLS.includes(item.url));
}
