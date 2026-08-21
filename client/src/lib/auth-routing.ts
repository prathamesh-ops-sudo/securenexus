const OBSOLETE_AUTH_ROUTES = new Set(["/login", "/register"]);

function getPathname(path: string): string {
  return path.split("?", 1)[0];
}

export function hasPasswordResetToken(path: string): boolean {
  const [pathname, search = ""] = path.split("?", 2);
  return pathname === "/reset-password" && Boolean(new URLSearchParams(search).get("token"));
}

export function isPasswordRecoveryRoute(path: string): boolean {
  return getPathname(path) === "/forgot-password" || hasPasswordResetToken(path);
}

export function getAuthenticatedRouteDestination(path: string): "/" | null {
  return OBSOLETE_AUTH_ROUTES.has(getPathname(path)) ||
    (getPathname(path) === "/reset-password" && !hasPasswordResetToken(path))
    ? "/"
    : null;
}
