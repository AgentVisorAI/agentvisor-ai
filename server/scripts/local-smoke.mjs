/*
 * Same as live-site-smoke.mjs but serves the LOCAL docs/app/ files
 * so we can verify changes before pushing. Serves on 127.0.0.1:44120.
 */
import { chromium } from "playwright";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, resolve, extname } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const DOCS_ROOT = resolve(__dirname, "../../docs");
const port = 44120;
const mime = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".json": "application/json", ".svg": "image/svg+xml", ".png": "image/png" };
const srv = createServer(async (req, res) => {
  let p = decodeURIComponent(new URL(req.url, "http://x").pathname);
  if (p === "/" || p === "/app" || p === "/app/") p = "/app/index.html";
  try {
    const data = await readFile(DOCS_ROOT + p);
    res.setHeader("content-type", mime[extname(p)] || "application/octet-stream");
    res.end(data);
  } catch { res.statusCode = 404; res.end("not found: " + p); }
});
await new Promise((r) => srv.listen(port, "127.0.0.1", r));
const SITE = `http://127.0.0.1:${port}/app/`;
console.log("Serving local docs at", SITE);

process.env.SITE = SITE;
await import("./live-site-smoke.mjs");

srv.close();
