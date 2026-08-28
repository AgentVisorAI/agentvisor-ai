// Deployment configuration for the SPA.
//
// MOCK_MODE: when true the console shows built-in Northwind Traders fixtures
// so investors and prospects see a fully populated workspace immediately.
// Set to false and point API_BASE at a deployed backend to run against the
// real hosted API. See server/README.md for the deploy runbook.
//
// Extracted from index.html so that a strict Content-Security-Policy
// (`script-src 'self'`) can be enforced without allowing 'unsafe-inline'.
window.MOCK_MODE = true;
window.API_BASE = "";

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
