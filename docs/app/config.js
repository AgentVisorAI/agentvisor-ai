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
