import type { Express } from "express";

/**
 * RFC 9116 security.txt + robots.txt + other well-known endpoints.
 * Registered before auth middleware so they are always accessible.
 */
export function registerWellKnownRoutes(app: Express): void {
  // RFC 9116 — Security vulnerability disclosure contact
  const securityTxt = [
    "Contact: mailto:security@aricatech.com",
    "Expires: 2027-01-01T00:00:00.000Z",
    "Preferred-Languages: en",
    "Canonical: https://staging.aricatech.xyz/.well-known/security.txt",
    "Policy: https://aricatech.com/security-policy",
  ].join("\n");

  app.get("/.well-known/security.txt", (_req, res) => {
    res.type("text/plain").send(securityTxt);
  });

  // Prevent search engines from crawling API endpoints
  const robotsTxt = [
    "User-agent: *",
    "Disallow: /api/",
    "Disallow: /auth/",
    "Allow: /",
    "",
    "# Sitemap: https://staging.aricatech.xyz/sitemap.xml",
  ].join("\n");

  app.get("/robots.txt", (_req, res) => {
    res.type("text/plain").send(robotsTxt);
  });

  // Basic status endpoint for uptime monitors (no auth required)
  app.get("/ping", (_req, res) => {
    res.type("text/plain").send("pong");
  });
}
