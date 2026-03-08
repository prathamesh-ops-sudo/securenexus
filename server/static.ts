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

  app.use(express.static(distPath));

  const indexPath = path.resolve(distPath, "index.html");
  let cachedHtml: string | null = null;

  app.use("/{*path}", (_req, res) => {
    if (!cachedHtml) {
      cachedHtml = fs.readFileSync(indexPath, "utf-8");
    }
    const nonce: string = res.locals.cspNonce ?? "";
    const html = injectNonces(cachedHtml, nonce);
    res.status(200).set({ "Content-Type": "text/html" }).end(html);
  });
}
