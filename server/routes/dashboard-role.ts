export type DashboardRole = "ciso" | "soc_manager" | "analyst";

export function isDashboardRole(role: string): role is DashboardRole {
  return role === "ciso" || role === "soc_manager" || role === "analyst";
}
