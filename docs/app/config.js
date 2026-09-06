// Deployment configuration for the SPA.
//
// MOCK_MODE: when true the console shows built-in Northwind Traders fixtures
// so investors and prospects see a fully populated workspace immediately.
// Set to false and point API_BASE at a deployed backend to run against the
// real hosted API. See server/README.md for the deploy runbook.
//
// SELF-HOSTERS: index.html ships a strict meta CSP whose connect-src
// allows only 'self' and https://api.agentvisorai.me. If your API_BASE
// is any other origin, the browser will silently block every fetch —
// add your API origin to the connect-src list in index.html in the
// same change that edits this file (CI's "Browser E2E" job makes
// exactly these two edits; see .github/workflows/console-api.yml).
//
// Extracted from index.html so that a strict Content-Security-Policy
// (`script-src 'self'`) can be enforced without allowing 'unsafe-inline'.
window.MOCK_MODE = true;
window.API_BASE = "";

// Live-mode override: `?live=1` flips this page to the hosted API at
// https://api.agentvisorai.me (already permitted by the CSP connect-src
// above) and remembers the choice in localStorage; `?live=0` reverts to
// the mock fixtures. The default stays MOCK_MODE=true so the public
// demo keeps its fully populated Northwind workspace.
try {
  var __live = new URLSearchParams(location.search).get("live");
  if (__live === "1") localStorage.setItem("av_live_mode", "1");
  else if (__live === "0") localStorage.removeItem("av_live_mode");
  if (localStorage.getItem("av_live_mode") === "1") {
    window.MOCK_MODE = false;
    window.API_BASE = "https://api.agentvisorai.me";
  }
} catch (e) {}

// Apply the SAVED theme before first paint. Without this, a user who
// explicitly chose the theme opposite their OS scheme got a full-page
// flash on every load (CSS defaults follow prefers-color-scheme; the
// explicit data-theme attribute only landed after app.js booted).
// Lives here because the strict CSP (script-src 'self') forbids an
// inline <head> snippet — config.js is the first script to run.
try {
  var __t = localStorage.getItem("av_theme");
  if (__t === "light" || __t === "dark") document.documentElement.setAttribute("data-theme", __t);
} catch (e) {}
