/**
 * Shared redaction sentinels.
 *
 * When a role=member caller requests a session/receipt view, the
 * server keeps the shape of the response identical to the
 * owner/admin view but replaces payload-bearing fields with a
 * sentinel string. That keeps the SPA's rendering pipeline stable
 * (no branch for "field is null vs missing vs redacted") while
 * still hiding the actual bytes.
 *
 * The SPA recognizes this literal in two places:
 *   - docs/app/app.js — event-body render pill + receipt verifier guard
 *   - docs/app/datasource.js — try/catch around JSON.parse(rec.body)
 *
 * The SPA hardcodes the literal (it has no build step / no shared
 * imports with the server). This module is the single source of
 * truth on the server: R101 F2, R117 F1, R118 F3 all touched this
 * value. Changing it here without updating the SPA's REDACT
 * constant in app.js would break the guard — keep in sync.
 */
export const MEMBER_REDACTED = "[redacted-member-view]" as const;
