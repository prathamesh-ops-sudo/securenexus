const OBSOLETE_AUTH_ROUTES = new Set(["/login", "/register", "/forgot-password", "/reset-password"]);

export function getAuthenticatedRouteDestination(path: string): "/" | null {
  return OBSOLETE_AUTH_ROUTES.has(path.split("?", 1)[0]) ? "/" : null;
}
