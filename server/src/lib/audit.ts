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
 * `event` is a stable machine-readable slug. Comprehensive list
 * (regenerate via
 *   grep -rhoE '"(auth|saml|mfa|deployment|member|apikey|webhook|org|audit|policy)\.[a-z._]+"' server/src \
 *     | sort -u
 * — note the pattern also catches non-slug string literals like the
 * `webhook.office.com` hostname in webhook-adapters.ts and the
 * `org.retention.narrow` / `org.retention.sweep_now` /
 * `org.ip_allowlist.write` `metadata.endpoint` values in
 * auth.step_up_denied rows; those are NOT event slugs. R145 F4's
 * prior `grep -oE 'event: "[a-z._]+"'` regex missed slugs inside
 * ternaries — e.g. members.ts:310 `event: sub === userId ? "member.left" : "member.removed"`
 * — so the R146 F3 regen catches them.):
 *   auth.login, auth.login_denied, auth.logout, auth.logout.apikey_noop,
 *     auth.signup, auth.oauth_signin, auth.oauth_refused_mfa_required,
 *     auth.password_ok_mfa_required, auth.reset_request, auth.reset_confirm,
 *     auth.saml.slo, auth.step_up_denied
 *   saml.signin, saml.config_created, saml.config_updated,
 *     saml.config_deleted, saml.keypair_rotated
 *   mfa.authenticate, mfa.credential_registered, mfa.credential_revoked,
 *     mfa.credential_register_denied, mfa.credential_revoke_denied,
 *     mfa.credential_relabeled
 *   deployment.create, deployment.delete, deployment.delete_conflict,
 *     deployment.token_rotated, deployment.direct_seal_refused,
 *     deployment.pubkey_first_set, deployment.pubkey_rotation_refused,
 *     deployment.receipt_overwrite_refused, deployment.receipt_key_id_mismatch
 *   member.invited, member.invite_accepted, member.invite_accepted_requires_login,
 *     member.invite_revoked, member.role_changed, member.left, member.removed
 *   apikey.created, apikey.revoked
 *   webhook.created, webhook.updated, webhook.deleted, webhook.test_fired,
 *     webhook.secret_rotated, webhook.delivery_redelivered
 *   org.created, org.exported, org.delete.initiated, org.delete.committed,
 *     org.ip_allowlist_updated, org.retention_updated, org.retention_swept
 *   audit.viewed, audit.exported_csv
 *
 * Note: `policy.block` is NOT an audit slug — it's a webhook
 * fan-out event dispatched via lib/webhooks.ts dispatchEvent()
 * from ingest.ts. R146 F3's regen regex picks it up but it's
 * one of the documented false-positive classes (alongside the
 * webhook.office.com hostname and the metadata.endpoint values
 * on auth.step_up_denied rows). Filter when regenerating.
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

/**
 * Resolve the SessionClaims subject to actorId + actorEmail for
 * audit rows. For cookie sessions the sub is a user cuid; a
 * lightweight db.user.findUnique enriches actorEmail so the read.ts
 * audit renderer surfaces the email instead of "user:<cuid>".
 * For api-key sessions (`apikey:<K.id>`) the sub is the parent-key
 * id and there's no user row to enrich; return actorId only.
 *
 * Callers that want the enriched email pattern should:
 *   const actor = await resolveActor(claims.sub);
 *   writeAudit({ ...actor, orgId, event, ... }, req.log);
 *
 * R145 F3: introduced to close the "8+ audit sites drop actorEmail"
 * forensic-hygiene regression the R141 F1 audit surfaced. Every
 * cookie-authenticated privileged action (deployment.token_rotated,
 * apikey.created, org.retention_updated, etc.) used to render as
 * "user:<cuid>" post-R144 F3 because the callers never enriched
 * actorEmail. This helper eliminates the drift.
 */
export async function resolveActor(
  sub: string,
): Promise<{ actorId: string; actorEmail: string | undefined }> {
  if (sub.startsWith("apikey:")) {
    return { actorId: sub, actorEmail: undefined };
  }
  const user = await db.user
    .findUnique({ where: { id: sub }, select: { email: true } })
    .catch(() => null);
  return { actorId: sub, actorEmail: user?.email ?? undefined };
}
