import express, { type Express } from "express";
import fs from "fs";
import path from "path";

function injectNonces(html: string, nonce: string): string {
  return html
    .replace(/<script(?=[\s>])((?!nonce=)[^>]*)>/gi, `<script nonce="${nonce}"$1>`)
    .replace(/<style(?=[\s>])((?!nonce=)[^>]*)>/gi, `<style nonce="${nonce}"$1>`);
}

export function serveStatic(app: Express) {
  const distPath = path.resolve(__dirname, "public");
  if (!fs.existsSync(distPath)) {
    throw new Error(`Could not find the build directory: ${distPath}, make sure to build the client first`);
  }

  // Hashed assets (JS/CSS with content hashes in filename) — immutable cache
  app.use(
    "/assets",
    express.static(path.join(distPath, "assets"), {
      maxAge: "1y",
      immutable: true,
    }),
  );

  // Other static files (favicon, images, fonts) — short cache with revalidation
  app.use(
    express.static(distPath, {
      maxAge: "1h",
      etag: true,
      lastModified: true,
    }),
  );

  const indexPath = path.resolve(distPath, "index.html");
  let cachedHtml: string | null = null;

  app.use("/{*path}", (_req, res) => {
    if (!cachedHtml) {
      cachedHtml = fs.readFileSync(indexPath, "utf-8");
    }
    const nonce: string = res.locals.cspNonce ?? "";
    const html = injectNonces(cachedHtml, nonce);
    // HTML must never be cached — always serve fresh for CSP nonces and SPA routing
    res
      .status(200)
      .set({
        "Content-Type": "text/html",
        "Cache-Control": "no-cache, no-store, must-revalidate",
        Pragma: "no-cache",
        Expires: "0",
      })
      .end(html);
  });
}
