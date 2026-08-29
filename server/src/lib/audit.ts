/**
 * Compliance audit trail helper.
 *
 * Every sensitive action calls `writeAudit()`. The write is
 * fire-and-forget by default (the caller doesn't wait for it) so a
 * slow DB doesn't block user-facing responses. Failures log at warn
 * so ops can spot a broken audit path but never fail the actual
 * operation — losing an audit row is annoying, losing a login is
 * catastrophic.
 *
 * `event` is a stable machine-readable slug:
 *   auth.login, auth.logout, auth.signup, auth.oauth_signin
 *   auth.reset_request, auth.reset_confirm, auth.account_deleted,
 *     auth.step_up_denied
 *   saml.signin, saml.config_created, saml.config_updated,
 *     saml.config_deleted, saml.keypair_rotated
 *   deployment.create, deployment.delete, deployment.token_rotated
 *   member.invited, member.role_changed
 *   org.created, org.exported
 *   audit.exported_csv, audit.viewed
 *   mfa.credential_registered, mfa.credential_revoked,
 *     mfa.credential_register_denied, mfa.credential_revoke_denied
 *
 * `target` is a human-readable label the log viewer shows.
 * `metadata` carries structured fields for machine consumption.
 */

import type { FastifyBaseLogger, FastifyRequest } from "fastify";
import { db } from "../db.js";

export interface AuditInput {
  orgId: string;
  event: string;
  actorId?: string | null;
  actorEmail?: string | null;
  target?: string | null;
  note?: string | null;
  metadata?: Record<string, unknown> | null;
  req?: FastifyRequest;
}

export function writeAudit(input: AuditInput, log?: FastifyBaseLogger): void {
  const ip = input.req?.ip ?? null;
  const ua =
    typeof input.req?.headers["user-agent"] === "string"
      ? (input.req.headers["user-agent"] as string).slice(0, 512)
      : null;
  void db.auditEntry
    .create({
      data: {
        orgId: input.orgId,
        event: input.event,
        actorId: input.actorId ?? null,
        actorEmail: input.actorEmail ?? null,
        target: input.target ?? null,
        note: input.note ?? null,
        metadata: (input.metadata as never) ?? undefined,
        ip,
        userAgent: ua,
      },
    })
    .catch((err) => {
      if (log) {
        log.warn({ err, event: input.event, orgId: input.orgId }, "audit_write_failed");
      } else {
        // eslint-disable-next-line no-console
        console.warn("audit_write_failed", { err, event: input.event, orgId: input.orgId });
      }
    });
}
