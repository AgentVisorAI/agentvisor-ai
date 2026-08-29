import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { db } from "../db.js";
import { env } from "../env.js";
import {
  SESSION_COOKIE_OPTS,
  getDummyPasswordHash,
  hashPassword,
  mintSession,
  randomToken,
  verifyPassword,
} from "../lib/auth.js";
import { writeAudit } from "../lib/audit.js";
import { authEventsTotal } from "../lib/metrics.js";
import { perIpCookieOnly } from "../lib/rate-limit.js";
import { getMailer, passwordResetMail, welcomeMail } from "../lib/mail.js";
import {
  clearSessionCookie,
  requireSession,
} from "../lib/session-middleware.js";

// Zod's built-in .email() uses a strict allow-list of TLDs and rejects
// legitimate ones (.vc, .travel, .app). Practical constraint: local-part +
// @ + domain with at least one dot, no whitespace, ≤320 total.
const emailSchema = z
  .string()
  .max(320)
  .trim()
  .toLowerCase()
  .regex(/^[^\s@]+@[^\s@]+\.[^\s@]+$/, "Invalid email");
const passwordSchema = z.string().min(12).max(1024);
// R184 F1: CRLF/NUL rejection on user-controlled strings that flow
// into email subject/body. inviteMail (mail.ts:202-228) interpolates
// `orgName`, `inviterEmail`, and `link` into the subject line
// verbatim; welcomeMail interpolates `displayName` into the HTML
// body via escHtml. HTML escape closes the phishing-injection vector
// R99 F1 documented, but a CRLF in orgName would still slip past
// escHtml into the SMTP `Subject:` header — subject values are
// header fields, not HTML body, and `\r\n` in a header value
// injects arbitrary follow-on headers (`Bcc:`, `Reply-To:`,
// `Content-Type:`) at the mail gateway. Resend / nodemailer / SES
// typically strip these, but that's out of our control on any
// swap; defense-in-depth means rejecting the input at Zod time so
// a mail-library regression can't lift the attack. `\s` in
// emailSchema already covers this class for the email field
// (auth.ts:29 uses `[^\s@]+` which excludes CRLF), but orgName
// and displayName were only `.trim()`ed (leading/trailing only,
// not middle). Refuse any control char in [\r\n\u0000].
const noCrlfNul = (v: string): boolean => !/[\r\n\u0000]/.test(v);
// R211 F1: chain order matters. `.min(1).max(80).trim()` runs
// `.trim()` LAST, AFTER the `.min(1)` check on the untrimmed
// value — so a whitespace-only string like "    " passes
// (length 4) and the trim step then reduces it to "". Zod's
// order-of-operations for chained string checks is strictly
// left-to-right in v3.24.2. Concrete manifestation:
//   POST /signup { orgName: "    ", … } → org.create({ name: "" })
//   welcomeMail(user.displayName ?? user.email) with
//   displayName === "" → email addressed to "" (nullish
//   coalescing does not coalesce empty strings).
//   All subsequent audit / email / SPA renders show "" for
//   the org name with no self-service edit path to fix.
// Reordering to `.max(80).trim().min(1)` runs trim BEFORE
// min, so whitespace-only inputs are properly refused as
// too_small. Sibling emailSchema at :24-29 is unaffected —
// its final .regex(...) runs after .trim().toLowerCase() and
// rejects the empty result. Sibling displayName sites without
// .trim() (members.ts:641 invite-accept) aren't affected.
const orgNameSchema = z
  .string()
  .max(80)
  .trim()
  .min(1)
  .refine(noCrlfNul, "must not contain CR/LF/NUL");

function orgSlug(name: string, salt: string): string {
  const base = name
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40);
  return base ? `${base}-${salt}` : `org-${salt}`;
}

export async function authRoutes(app: FastifyInstance): Promise<void> {
  // Per-endpoint rate limits are tighter than the global 300rpm backstop.
  // Anonymous auth endpoints get a per-IP cap because there's no user
  // identity to rate-limit against yet. Numbers here are conservative
  // for a real product (Auth0 defaults to 300/hr on signup; Cognito
  // is 5/min on login). See OWASP ASVS 4.0 §11.1.4.
  //
  // Note: when @fastify/rate-limit's `config` accessor sees a route
  // definition, it overrides the global keyGenerator + budget for that
  // route only. Everything else on the API still uses the 300rpm global.
  const perIp = (max: number, windowMs: number) => ({
    max,
    timeWindow: windowMs,
    keyGenerator: (req: { ip: string }) => `ip:${req.ip}`,
  });

  app.post("/signup", {
    // 5/min per IP — signup is an expensive path (argon2 + org create).
    config: { rateLimit: perIp(5, 60_000) },
  }, async (req, reply) => {
    const parsed = z
      .object({
        email: emailSchema,
        password: passwordSchema,
        // R184 F1: reject CRLF/NUL — see orgNameSchema above.
        // R211 F1: reorder `.max(80).trim().min(1)` so trim
        // runs BEFORE min-1, otherwise whitespace-only names
        // like "    " pass min-1 on the untrimmed 4-char string
        // then get trimmed to "" and stored (welcomeMail then
        // renders "Welcome, " with an empty greeting).
        displayName: z.string().max(80).trim().min(1).refine(noCrlfNul, "must not contain CR/LF/NUL").optional(),
        orgName: orgNameSchema,
      })
      .safeParse(req.body);
    if (!parsed.success) {
      // Never log the request body — it contains the plaintext password.
      // The flatten()'d issues describe field paths + messages only.
      req.log.warn(
        { issues: parsed.error.flatten() },
        "signup_reject",
      );
      return reply
        .code(400)
        .send({ error: "invalid_input", issues: parsed.error.flatten() });
    }
    const { email, password, displayName, orgName } = parsed.data;

    // Reject if email is already registered. Do not disclose which case in
    // production — this handler is only reached anonymously, so returning 409
    // is acceptable here. The findUnique check is a fast-path; the create
    // below is wrapped in try/catch to also catch the TOCTOU race where two
    // concurrent signups slip past the check.
    const existing = await db.user.findUnique({ where: { email } });
    if (existing) {
      return reply.code(409).send({ error: "email_in_use" });
    }

    const passwordHash = await hashPassword(password);
    // R108 F2: use randomToken (Node crypto CSPRNG) instead of
    // Math.random() (~30 bits of predictable output). Matches
    // sibling oauth.ts:96 signup slug salt. Prior shape was
    // easy to guess for a slug-squatting attacker, and the
    // salt only bought a small extra entropy budget on top of
    // the base orgName.
    const salt = randomToken(4).toLowerCase().slice(0, 6);
    const slug = orgSlug(orgName, salt);

    let user, org;
    try {
      const result = await db.$transaction(async (tx) => {
        const org = await tx.org.create({
          data: { name: orgName, slug },
        });
        const user = await tx.user.create({
          data: {
            email,
            passwordHash,
            displayName,
            memberships: {
              create: { orgId: org.id, role: "owner" },
            },
          },
        });
        return { user, org };
      });
      user = result.user;
      org = result.org;
    } catch (err) {
      // R108 F2: distinguish P2002 by the unique constraint that
      // fired (`err.meta.target`) — a slug collision is a
      // different failure than an email collision, and previous
      // shape mis-mapped BOTH to `email_in_use` (409). A signup
      // with a brand-new email but a slug that clashed at the
      // 40-char prefix was told 'email in use' and had no path
      // to retry — only an org-name change or waiting helped,
      // with no signal to the operator. Now: only User_email_key
      // collisions map to email_in_use; slug collisions map to
      // a distinct 409 org_slug_conflict slug so the client can
      // retry with a fresh org name suggestion.
      if (
        typeof err === "object" && err !== null &&
        (err as { code?: string }).code === "P2002"
      ) {
        const target = (err as { meta?: { target?: string[] | string } }).meta?.target;
        const targetStr = Array.isArray(target) ? target.join(",") : (target ?? "");
        if (targetStr.includes("email")) {
          return reply.code(409).send({ error: "email_in_use" });
        }
        if (targetStr.includes("slug")) {
          return reply.code(409).send({ error: "org_slug_conflict" });
        }
        // Unknown P2002 target: default to email-in-use to
        // preserve the pre-R108 behavior for edge cases
        // (avoids leaking Prisma internals via a generic slug).
        return reply.code(409).send({ error: "email_in_use" });
      }
      throw err;
    }

    const token = await mintSession({
      sub: user.id,
      orgId: org.id,
      membershipRole: "owner",
    });
    reply.setCookie(env.SESSION_COOKIE_NAME, token, SESSION_COOKIE_OPTS);
    writeAudit(
      {
        orgId: org.id,
        event: "auth.signup",
        actorId: user.id,
        actorEmail: user.email,
        target: user.email,
        note: `Org "${org.name}" created`,
        req,
      },
      req.log,
    );
    // R213 F1: increment the previously-dead Prometheus
    // `agentvisor_api_auth_events_total{event,result}` counter
    // (declared at lib/metrics.ts:52 with the comment
    // "high-signal for spotting brute-force sprays and
    // organic-growth graphs alike" — nothing was wired up, so
    // Grafana dashboards / brute-force alerts on this metric
    // rendered flat zero forever).
    authEventsTotal.inc({ event: "signup", result: "ok" });
    // R136 F2: also emit org.created so a forensic query
    // "which orgs came into existence via unattended OAuth
    // callback vs. explicit /signup" can distinguish the two
    // by event slug alone (rather than parsing the freeform
    // note field). Post-R135 F4 the OAuth-JIT branch already
    // emitted org.created — without this counterpart, the
    // query would return only OAuth-JIT orgs and silently
    // miss every password-signup org. Same double-emit shape
    // R135 F4 established.
    writeAudit(
      {
        orgId: org.id,
        event: "org.created",
        actorId: user.id,
        actorEmail: user.email,
        target: org.name,
        metadata: { viaSignup: true, orgSlug: org.slug },
        req,
      },
      req.log,
    );
    // Fire-and-forget welcome email. Failures don't block the signup
    // response — a stuck mailer would otherwise turn a hot-path signup
    // into a 30s timeout.
    void (async () => {
      try {
        const mail = getMailer(req.log);
        const template = welcomeMail(user.displayName ?? user.email);
        await mail.send({
          to: user.email,
          subject: template.subject,
          text: template.text,
          html: template.html,
        });
      } catch (err) {
        req.log.warn({ err, userId: user.id }, "welcome_email_failed");
      }
    })();
    return reply.code(201).send({
      user: { id: user.id, email: user.email, displayName: user.displayName },
      org: { id: org.id, slug: org.slug, name: org.name, role: "owner" },
    });
  });

  app.post("/login", {
    // 10/min per IP is deliberate: a shared NAT still has plenty of
    // budget for legitimate users, but credential-stuffing bursts get
    // cut off quickly. Combine with argon2's built-in ~100ms cost per
    // attempt for a hard ceiling on brute-force throughput.
    config: { rateLimit: perIp(10, 60_000) },
  }, async (req, reply) => {
    // Login accepts any well-formed input and lets the credential check
    // return a uniform 401. Rejecting on password length would leak the
    // signup constraint and give attackers a legit-vs-typo distinguisher.
    const body = z
      .object({ email: emailSchema, password: z.string().min(1).max(1024) })
      .safeParse(req.body);
    if (!body.success) {
      return reply.code(400).send({ error: "invalid_input" });
    }
    const { email, password } = body.data;
    const user = await db.user.findUnique({
      where: { email },
      // R105 F4: deterministic membership ordering. Prior shape
      // used Prisma's default DB row order which is unstable
      // across Postgres restarts / VACUUM / replica failover.
      // A multi-org user (rare today but on-trajectory as SAML
      // JIT lands users in additional orgs) could log in and
      // land in a different org each restart. Prefer the
      // OLDEST membership (createdAt asc) so 'the first org I
      // ever joined' is the stable landing pad; the console
      // will need an org-switcher UI to move between them,
      // but at least the login pin is deterministic.
      //
      // R109 F2: also pull the passkey count in the SAME query
      // so both the wrong-password branch and the correct-
      // password+MFA branch pay identical DB cost. Prior
      // shape ran an ADDITIONAL webauthnCredential.count only
      // on the correct-password branch — that extra ~5-30 ms
      // Postgres RTT re-opened the wall-clock 'did I guess
      // the password?' oracle R85 F3 closed on the wire-shape
      // dimension. Now the count is present regardless of
      // hit/miss (for a missing user Prisma's findUnique
      // returns null so the _count is moot — but the join
      // cost is paid on the DB either way and the wrong-
      // password branch has to enter the same code path
      // below).
      include: {
        memberships: { include: { org: true }, orderBy: { createdAt: "asc" } },
        _count: { select: { webauthnCredentials: true } },
      },
    });
    // Uniform response time by always running argon2 verify, even when
    // the user doesn't exist. The dummy is a real precomputed argon2id
    // hash (from getDummyPasswordHash) so verify actually spends its
    // full ~100ms — the previous ill-formed dummy failed decode in
    // <1ms and defeated the entire posture.
    const hashToCheck = user?.passwordHash ?? (await getDummyPasswordHash());
    const ok = await verifyPassword(hashToCheck, password);
    // R85 F3: close the password-validity oracle for MFA-enabled
    // accounts. Prior shape returned 401 `invalid_credentials` on
    // wrong-password / unknown-email but 200 `{mfaRequired:true,
    // email}` on correct-password + MFA-enabled — a
    // credential-stuffing attacker observing the response shape
    // learned that a candidate password was CORRECT for a
    // WebAuthn-protected account even though they couldn't
    // complete the ceremony. The password is directly reusable
    // as a credential-stuffing input against non-AgentVisor
    // services. Post R85 F3: uniformly respond
    // `{mfaRequired:true}` (no email leaked; client already
    // has it) on unknown-email, wrong-password, no-membership,
    // AND correct-password+MFA. The only response shape that
    // reveals password validity is the FULL LOGIN SUCCESS shape
    // — and that only occurs on correct-password + NO MFA, at
    // which point the attacker has fully authenticated and the
    // "password validity" bit is the least of the concerns.
    // UX cost: users typing a wrong password on a no-MFA
    // account still see 401 (this branch); users typing a wrong
    // password on an MFA account will be routed into the
    // WebAuthn ceremony, which fails at /authenticate/verify.
    const mfaGateResponse = () => reply.send({ mfaRequired: true });
    if (!user || !ok) {
      // Uniform shape whether email exists or not — closes the
      // "does this account exist" oracle for callers who
      // otherwise would try /authenticate/challenge (which
      // returns decoys uniformly per R76 F4). Also closes the
      // "did I get the password" oracle if the target has MFA.
      // R142 F3: emit auth.login_denied ONLY when user is real
      // AND has a membership — preserves the R77 F4 / R85 F3
      // no-enumeration wire uniformity (audit is server-internal,
      // never surfaces to the attacker). Blast radius is
      // higher than any of R140 F3 / R141 F1 / R141 F2's sites:
      // /login is the primary credential-stuffing target and
      // perIp(10, 60_000) still permits 600 guesses/min per
      // victim account. Same shape R141 F2 used for
      // /reset-confirm. Absent this audit, an admin
      // investigating "who tried to log into ceo@corp on Nov 5"
      // gets nothing from audit_entries.
      if (user) {
        const membership = user.memberships[0];
        if (membership) {
          writeAudit(
            {
              orgId: membership.orgId,
              event: "auth.login_denied",
              actorId: user.id,
              actorEmail: user.email,
              note: "invalid_password",
              req,
            },
            req.log,
          );
        }
      }
      // R213 F1: fail-branch counter — see signup site above.
      // Always incremented (regardless of whether we could
      // attach a membership audit) so brute-force sprays
      // against nonexistent emails are still visible in
      // Prometheus.
      authEventsTotal.inc({ event: "login", result: "fail" });
      return mfaGateResponse();
    }
    const membership = user.memberships[0];
    if (!membership) {
      // R77 F4 (MEDIUM): return the SAME shape as
      // `!user || !ok` above so a credential-stuffing attacker
      // cannot distinguish "password correct + user has no org"
      // from "email or password wrong". Prior shape returned 403
      // `no_org` here, giving the attacker a bit ("password OK,
      // no org") they could resell. A user reaching this branch
      // is a genuine data-integrity issue (every user should
      // have a membership by construction — SAML/OAuth JIT and
      // signup both provision one atomically), so surfacing the
      // underlying reason to the operator via a durable log
      // line is preserved, but the wire response reveals
      // nothing.
      // R137 F3: prior shape ALSO called writeAudit here with
      // orgId: "system" — but AuditEntry.orgId is a required FK
      // (schema.prisma:161 org Org @relation(fields: [orgId],
      // references: [id], onDelete: Cascade)) and there is no
      // bootstrap Org row with id "system" anywhere in the
      // codebase or migrations. Every call landed a Prisma
      // P2003 that audit.ts swallowed into audit_write_failed
      // warn. The "audit + logging" invariant the R77 F4
      // comment claimed was only ever satisfied by the log
      // side; the audit was dead code. Same rationale
      // /me/delete-account uses (auth.ts:963-967 "writeAudit into
      // audit_entries would itself be nuked … SOC-2 evidence
      // for tenant erasure comes from those logs") applies
      // symmetrically here — no orgId to attach to by
      // construction. Rely on the req.log.error below for
      // durable forensic capture.
      req.log.error(
        { userId: user.id, email: user.email },
        "user_authenticated_password_but_has_no_membership",
      );
      return mfaGateResponse();
    }

    // MFA gate — if the user has any WebAuthn credentials, we do NOT
    // mint the session cookie here. Instead we return { mfaRequired:
    // true } and the SPA runs the WebAuthn ceremony to complete auth.
    // Password alone is not sufficient once a passkey exists.
    //
    // R109 F2: credentialCount comes from the SAME findUnique above
    // via Prisma's _count-select, so no additional round trip fires
    // on the correct-password + MFA branch. That equalizes the
    // wall-clock time between wrong-password (returns from
    // mfaGateResponse above) and correct-password + MFA (returns
    // here) — both paths spend the same argon2 + Prisma budget
    // and can't be timed apart. R85 F3's wire-shape unification
    // now has matching wall-clock unification.
    const credentialCount = user._count.webauthnCredentials;
    if (credentialCount > 0) {
      writeAudit(
        {
          orgId: membership.orgId,
          event: "auth.password_ok_mfa_required",
          actorId: user.id,
          actorEmail: user.email,
          target: user.email,
          req,
        },
        req.log,
      );
      return mfaGateResponse();
    }

    const token = await mintSession({
      sub: user.id,
      orgId: membership.orgId,
      membershipRole: membership.role as "owner" | "admin" | "member",
    });
    reply.setCookie(env.SESSION_COOKIE_NAME, token, SESSION_COOKIE_OPTS);
    writeAudit(
      {
        orgId: membership.orgId,
        event: "auth.login",
        actorId: user.id,
        actorEmail: user.email,
        target: user.email,
        req,
      },
      req.log,
    );
    // R213 F1: ok-branch counter for successful cookie mint.
    authEventsTotal.inc({ event: "login", result: "ok" });
    return reply.send({
      user: { id: user.id, email: user.email, displayName: user.displayName },
      org: {
        id: membership.org.id,
        slug: membership.org.slug,
        name: membership.org.name,
        role: membership.role,
      },
    });
  });

  app.post("/logout", async (req, reply) => {
    // Bump the user's sessionRevokedAt fence so a captured cookie can't
    // be replayed after logout, even though the JWT itself is still
    // cryptographically valid until its 7-day exp. authenticate()
    // checks jwt.iat < user.sessionRevokedAt and rejects.
    if (req.session) {
      // R106 F3: API-key sessions have no cookie to clear and no
      // user row to fence — the auth identity is the plaintext
      // av_srv_ token in the Authorization header, which the
      // holder still has. Clearing the client's av_session
      // cookie is a no-op for them. Prior shape (a) called
      // user.update on 'apikey:<id>' → threw P2025 → swallowed
      // by .catch(), noisy log line for every API-key /logout
      // hit; (b) wrote an audit entry with
      // actorId='apikey:<id>' but no correlation to a real
      // ApiKey row for forensics. Fix: sniff the prefix. For
      // an API-key session, log a warn breadcrumb, write an
      // audit entry that carries the apiKeyId as metadata
      // (correlates to a real row), and skip the user.update
      // + cookie clear entirely.
      if (req.session.sub.startsWith("apikey:")) {
        const apiKeyId = req.session.sub.slice("apikey:".length);
        req.log.warn(
          { apiKeyId, orgId: req.session.orgId },
          "logout_called_on_apikey_session",
        );
        writeAudit(
          {
            orgId: req.session.orgId,
            event: "auth.logout.apikey_noop",
            actorId: req.session.sub,
            metadata: { apiKeyId },
            req,
          },
          req.log,
        );
        return reply.send({ ok: true, message: "api_key_session_no_cookie_to_clear" });
      }
      await db.user
        .update({
          where: { id: req.session.sub },
          data: { sessionRevokedAt: new Date() },
        })
        .catch((err) => {
          // Log but don't fail logout — clearing the cookie is the
          // essential piece; the fence bump is defense in depth.
          req.log.warn({ err }, "logout_revoke_bump_failed");
        });
      writeAudit(
        {
          orgId: req.session.orgId,
          event: "auth.logout",
          actorId: req.session.sub,
          req,
        },
        req.log,
      );
    }
    clearSessionCookie(reply);
    return reply.send({ ok: true });
  });

  app.get("/me", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    const user = await db.user.findUnique({
      where: { id: claims.sub },
      include: { memberships: { include: { org: true } } },
    });
    if (!user) {
      clearSessionCookie(reply);
      return reply.code(401).send({ error: "user_not_found" });
    }
    const active = user.memberships.find((m) => m.orgId === claims.orgId);
    if (!active) {
      clearSessionCookie(reply);
      return reply.code(403).send({ error: "membership_revoked" });
    }
    return reply.send({
      user: { id: user.id, email: user.email, displayName: user.displayName },
      org: {
        id: active.org.id,
        slug: active.org.slug,
        name: active.org.name,
        role: active.role,
      },
    });
  });

  // GDPR data export. Returns everything the org has stored:
  // deployments, sessions, events, receipts, memberships, users.
  // Password hashes and reset tokens are excluded — the export is meant
  // for the customer, not an attacker with a stolen session.
  //
  // Gated on a fresh password check so a stolen session cookie can't
  // extract the whole org history in one call.
  app.post("/me/export", {
    // R142 F2: perIpCookieOnly skips the bucket for api-key
    // requests so an attacker with any valid av_srv_ token on
    // the same IP can't burn the legitimate owner's export
    // budget by hammering with a Bearer header — see
    // lib/rate-limit.ts for the shared helper rationale.
    config: { rateLimit: perIpCookieOnly(3, 60_000) },
  }, async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    // R91 F1: gate on owner only. This endpoint streams the ENTIRE
    // org history: every deployment (with publicKeyHex), every
    // member (email + displayName), every session, every event
    // body (up to 8000 chars of daemon-forwarded LLM prompts/
    // responses) and sub, every receipt. A plain member could
    // supply their own password and exfil the whole org.
    // Compare the sibling /me/delete-account which correctly
    // owner-only-gates at auth.ts:897-905. GDPR data-portability is
    // an org-level right exercised by the owner; a per-user
    // export would need to filter by actorId on every table
    // (out of scope for this hardening — this endpoint is
    // whole-org by design and should be owner-only accordingly).
    if (claims.membershipRole !== "owner") {
      // R143 F2: forensic breadcrumb for non-owner attempts on
      // R136 F1's "single largest-blast-radius endpoint." Prior
      // shape returned 403 silently — an admin investigating
      // "who tried to export our org history at 03:12 without
      // owner rights" got nothing. Same slug as R142 F1's
      // password branch; note distinguishes the wire cause so
      // an owner audit trail can grep both "invalid_password"
      // and "not_owner" against the endpoint metadata.
      // R144 F3: drop actorEmail=claims.sub. claims.sub is a
      // user cuid (lib/auth.ts SessionClaims: "sub: string; //
      // user id"), NOT an email. Downstream read.ts /audit
      // renderers use `r.actorEmail || (r.actorId ? "user:" +
      // r.actorId : "system")` — a non-null actorEmail skips
      // the "user:" prefix and emits a raw cuid, breaking the
      // "email | user:<id> | system" convention every peer
      // step_up_denied row uses (after db.user.findUnique).
      // Sibling R141 F1 on webauthn.ts:820 already omits
      // actorEmail in this exact "no user loaded" case.
      writeAudit(
        {
          orgId: claims.orgId,
          event: "auth.step_up_denied",
          actorId: claims.sub,
          note: "not_owner",
          metadata: { endpoint: "me.export" },
          req,
        },
        req.log,
      );
      return reply.code(403).send({ error: "only_owner_can_export" });
    }
    const body = z
      .object({ password: z.string().min(1).max(1024) })
      .safeParse(req.body);
    if (!body.success) {
      return reply.code(400).send({ error: "password_required" });
    }
    const user = await db.user.findUnique({ where: { id: claims.sub } });
    if (!user) return reply.code(401).send({ error: "unauthenticated" });
    const ok = await verifyPassword(user.passwordHash, body.data.password);
    if (!ok) {
      // R142 F1: R141 F2's commit message documented three sites
      // (/me/export, /me/delete-account, /reset-confirm) but the
      // diff only patched the latter two. This is
      // R136 F1's "single largest-blast-radius endpoint" (whole-
      // org JSONL exfil) with R140 F2's perIp(3, 60_000) at
      // line 493 — a proxy-pool attacker can grind ~5 argon2/sec
      // against a stolen owner cookie with zero forensic
      // breadcrumb until success (org.exported fires only on
      // success). Same auth.step_up_denied slug as the other
      // two siblings.
      writeAudit(
        {
          orgId: claims.orgId,
          event: "auth.step_up_denied",
          actorId: claims.sub,
          actorEmail: user.email,
          note: "invalid_password",
          metadata: { endpoint: "me.export" },
          req,
        },
        req.log,
      );
      return reply.code(401).send({ error: "invalid_password" });
    }

    // R136 F1: single largest-blast-radius endpoint in the tree.
    // R91 F1 comment: "streams the ENTIRE org history: every
    // deployment (with publicKeyHex), every member (email +
    // displayName), every session, every event body (up to 8000
    // chars of daemon-forwarded LLM prompts/responses) and sub,
    // every receipt." Owner-only + password-reauthed, but a
    // stolen owner cookie exfils the whole org in one JSONL
    // stream. Prior shape emitted zero writeAudit and only a
    // req.log.error on stream failure — an admin investigating
    // "was our org's whole event stream siphoned via /me/export
    // at 03:12" got nothing forensic. Sibling of R135 F1's
    // /reset-confirm gap: emit the breadcrumb AFTER the
    // owner-check + password verify pass so no oracle leaks,
    // BEFORE reply.raw.flushHeaders so the audit fires whether
    // the stream completes or not. Distinct from /me/delete-
    // account which is deliberately non-audited (auth.ts:718:
    // "would itself be nuked by the same cascade") — no
    // cascade concern applies here (nothing is deleted).
    writeAudit(
      {
        orgId: claims.orgId,
        event: "org.exported",
        actorId: claims.sub,
        actorEmail: user.email,
        target: claims.orgId,
        metadata: { streamingStartedAt: new Date().toISOString() },
        req,
      },
      req.log,
    );

    // Streaming JSON-Lines export. Each line is a self-contained JSON
    // object; the first line is a header. Sessions and events are
    // paged (batch size below) so we NEVER materialize the whole org
    // in memory — a 1M-session tenant streams safely on a 256 MB Fly
    // machine. Long TTL friendly: consumers can restart mid-download
    // by discarding the header and resuming.
    //
    // Password hashes and reset tokens are excluded — the export is
    // meant for the customer, not for anyone with a stolen session.
    const SESSION_PAGE = 500;
    const EVENT_PAGE = 1000;

    // R110 F2: set Content-Type and Content-Disposition directly
    // on reply.raw before flushHeaders(). Prior R109 F1 shape
    // called reply.header('Content-Disposition') and reply.type()
    // which stash into Fastify's kReplyHeaders — those only
    // reach the wire when reply.send() calls safeWriteHead().
    // After reply.raw.end() runs, reply.sent becomes true, so
    // the follow-up reply.send(reply) from wrap-thenable
    // short-circuits with a warn log and writeHead never
    // fires. Effect: only Cache-Control (set on raw directly)
    // reached the client — no Content-Type / Content-Disposition,
    // so browsers rendered NDJSON inline as plain text, the
    // .jsonl filename hint was missing, and consumers that
    // content-negotiate on application/x-ndjson (data-portability
    // tooling, SOC-2 audit ingesters) rejected the download.
    // Same class R110 F1 closed at /audit.csv; correct hijack
    // pattern matches stream.ts.
    reply.raw.setHeader("Content-Type", "application/x-ndjson");
    reply.raw.setHeader(
      "Content-Disposition",
      `attachment; filename="agentvisor-export-${claims.orgId}-${Date.now()}.jsonl"`,
    );
    reply.raw.setHeader("Cache-Control", "no-store");
    reply.raw.flushHeaders();
    // R109 F1: honor socket back-pressure. Prior write() discarded
    // the reply.raw.write(...) return value; when the socket
    // write buffer exceeds highWaterMark (16 KiB default),
    // Node's writable stream returns false but keeps queueing
    // bytes. A slow / throttled client (or a hostile
    // owner-tier session; perIp(3,60_000) is the only gate)
    // therefore causes RSS to grow linearly with tenant size —
    // OOMs a small pod. Mirror the stream.ts R83 F3 pattern:
    // on write()=false, await 'drain' before the next write.
    // Also honor client close so we stop mid-loop instead of
    // buffering the rest of the org into memory.
    let clientClosed = false;
    reply.raw.on("close", () => {
      clientClosed = true;
    });
    const write = async (obj: unknown): Promise<void> => {
      if (clientClosed) return;
      const ok = reply.raw.write(JSON.stringify(obj) + "\n");
      if (!ok) {
        await new Promise<void>((resolve) => {
          const onDrain = () => {
            reply.raw.off("drain", onDrain);
            reply.raw.off("close", onClose);
            resolve();
          };
          const onClose = () => {
            reply.raw.off("drain", onDrain);
            reply.raw.off("close", onClose);
            resolve();
          };
          reply.raw.once("drain", onDrain);
          reply.raw.once("close", onClose);
        });
      }
    };

    try {
      // Row 1: header. Consumers key on schemaVersion for future
      // evolutions of this format.
      const org = await db.org.findUnique({
        where: { id: claims.orgId },
        include: {
          members: {
            include: {
              user: { select: { id: true, email: true, displayName: true } },
            },
          },
          deployments: {
            select: {
              id: true,
              name: true,
              environment: true,
              publicKeyHex: true,
              createdAt: true,
            },
          },
        },
      });
      await write({
        type: "header",
        exportedAt: new Date().toISOString(),
        schemaVersion: 2,
        org,
      });

      // Rows 2..N: sessions paginated by (openedAt, id). Same cursor
      // pattern as the /sessions endpoint — O(log N) per page.
      let lastKey: { openedAt: Date; id: string } | null = null;
      // Loop until an empty page. Guard against runaway loops via a
      // sanity cap on iterations — 1M sessions / SESSION_PAGE = 2000
      // pages, and even 10M would be 20k pages, well below this.
      for (let iter = 0; iter < 200_000; iter++) {
        if (clientClosed) break;
        // Typed as any-ish: Prisma infers the generic from the where,
        // and TS complains about self-referential inference in the
        // control-flow analysis. The runtime type is
        // (Session & { receipt: Receipt | null })[].
        const sessions: Array<{
          id: string;
          openedAt: Date;
          costUsdMicros: bigint;
          payoutUsdMicros: bigint;
          blockedPayoutUsdMicros: bigint;
          [k: string]: unknown;
        }> = await db.session.findMany({
          where: { orgId: claims.orgId },
          orderBy: [{ openedAt: "asc" }, { id: "asc" }],
          take: SESSION_PAGE,
          ...(lastKey
            ? {
                skip: 1,
                cursor: { id: lastKey.id },
              }
            : {}),
          include: { receipt: true },
        });
        if (sessions.length === 0) break;
        for (const s of sessions) {
          if (clientClosed) break;
          await write({
            type: "session",
            session: {
              ...s,
              costUsdMicros: s.costUsdMicros.toString(),
              payoutUsdMicros: s.payoutUsdMicros.toString(),
              blockedPayoutUsdMicros: s.blockedPayoutUsdMicros.toString(),
            },
          });
          // Events for this session in EVENT_PAGE-sized pages.
          let lastEventSeq: number | null = null;
          for (let ei = 0; ei < 20_000; ei++) {
            if (clientClosed) break;
            const events: Array<{ seq: number; [k: string]: unknown }> = await db.event.findMany({
              where: {
                sessionId: s.id,
                ...(lastEventSeq !== null ? { seq: { gt: lastEventSeq } } : {}),
              },
              orderBy: { seq: "asc" },
              take: EVENT_PAGE,
            });
            if (events.length === 0) break;
            const nextLast = events[events.length - 1];
            if (!nextLast) break;
            for (const ev of events) {
              if (clientClosed) break;
              await write({ type: "event", sessionId: s.id, event: ev });
            }
            lastEventSeq = nextLast.seq;
            if (events.length < EVENT_PAGE) break;
          }
        }
        const last = sessions[sessions.length - 1];
        if (!last || sessions.length < SESSION_PAGE) break;
        lastKey = { openedAt: last.openedAt, id: last.id };
      }
      await write({ type: "trailer", exportCompleteAt: new Date().toISOString() });
    } catch (err) {
      // Write a trailer so consumers can distinguish a truncated
      // download from a completed one. Then close.
      req.log.error({ err, orgId: claims.orgId }, "export_stream_failed");
      await write({
        type: "error",
        message: err instanceof Error ? err.message : "export_failed",
        exportFailedAt: new Date().toISOString(),
      });
    } finally {
      try { reply.raw.end(); } catch { /* already ended */ }
    }
    return reply;
  });

  // Account + org deletion. Owner-only. Requires password + explicit
  // confirmation string to prevent a mis-click from nuking a whole
  // tenant.
  //
  // Cascading deletes fire down the tree — Prisma's onDelete:Cascade
  // handles deployments → sessions → events → receipts. Memberships
  // and Users are removed last.
  app.post("/me/delete-account", {
    // R142 F2: perIpCookieOnly — same rationale as /me/export.
    config: { rateLimit: perIpCookieOnly(3, 60_000) },
  }, async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    if (claims.membershipRole !== "owner") {
      // R143 F2: same forensic breadcrumb as /me/export non-owner
      // above — this endpoint deletes the whole org, so
      // non-owner attempts merit an audit row.
      // R144 F3: drop actorEmail=claims.sub (was a cuid, not
      // an email — see /me/export comment above).
      writeAudit(
        {
          orgId: claims.orgId,
          event: "auth.step_up_denied",
          actorId: claims.sub,
          note: "not_owner",
          metadata: { endpoint: "me.delete_account" },
          req,
        },
        req.log,
      );
      return reply.code(403).send({ error: "only_owner_can_delete" });
    }
    const body = z
      .object({
        password: z.string().min(1).max(1024),
        confirm: z.literal("DELETE MY ACCOUNT"),
      })
      .safeParse(req.body);
    if (!body.success) {
      return reply.code(400).send({ error: "confirmation_required" });
    }
    const user = await db.user.findUnique({ where: { id: claims.sub } });
    if (!user) return reply.code(401).send({ error: "unauthenticated" });
    const ok = await verifyPassword(user.passwordHash, body.data.password);
    if (!ok) {
      // R141 F2: step-up failure audit. This branch runs BEFORE
      // the org cascade so writeAudit still lands in
      // audit_entries (unlike the success branch, whose audit
      // gets cascade-nuked and relies on req.log.warn for
      // external log capture per the R97 F-A comment below).
      writeAudit(
        {
          orgId: claims.orgId,
          event: "auth.step_up_denied",
          actorId: claims.sub,
          actorEmail: user.email,
          note: "invalid_password",
          metadata: { endpoint: "me.delete_account" },
          req,
        },
        req.log,
      );
      return reply.code(401).send({ error: "invalid_password" });
    }

    // R97 F-A: emit a forensic breadcrumb BEFORE the tx runs. This
    // is the most catastrophic action in the whole codebase — the
    // org row + every child cascades (deployments, sessions,
    // events, receipts, memberships, api keys, webhooks, saml
    // configs, invites, saml replay records, AND every
    // AuditEntry scoped to this org because AuditEntry.orgId is
    // onDelete: Cascade). writeAudit() into audit_entries would
    // itself be nuked by the same cascade, leaving zero
    // server-side forensic trail. Log at 'warn' with a stable
    // machine-parseable slug so external log retention (Datadog,
    // Loki, CloudWatch) captures the event with an
    // externally-durable record: who invoked, when, from where.
    // SOC-2 evidence for tenant erasure comes from those logs.
    req.log.warn(
      {
        // R97 F-A + R98 F3: distinct 'initiated' vs 'committed'
        // slugs. Prior R97 shape used event: 'org.deleted' for
        // BOTH the pre-tx and post-commit lines; log-aggregator
        // rules index on the typed `event` field and don't parse
        // the freeform pino msg, so successful deletes emitted
        // TWO 'org.deleted' records (metrics doubled) and failed
        // txs emitted ONE (alerts fired for a delete that never
        // happened; SOC-2 evidence claimed a still-present org
        // was erased). Now: 'org.delete.initiated' pre-tx,
        // 'org.delete.committed' post-commit. Each slug means
        // exactly what it says.
        event: "org.delete.initiated",
        orgId: claims.orgId,
        userId: claims.sub,
        actorEmail: user.email,
        ip: req.ip,
        userAgent: typeof req.headers["user-agent"] === "string"
          ? req.headers["user-agent"].slice(0, 200)
          : undefined,
        at: new Date().toISOString(),
      },
      "org_delete_initiated",
    );

    await db.$transaction(async (tx) => {
      // Delete the org first — cascades to deployments, sessions,
      // events, receipts, receipts, memberships, api keys,
      // webhooks (+ deliveries), saml configs, saml replay
      // records, invites, and this org's audit_entries. The
      // R97 F-A log line above is the durable forensic trace.
      await tx.org.delete({ where: { id: claims.orgId } });
      // Then remove the user. Other orgs they belonged to (unlikely
      // at MVP; multi-org membership not exposed yet) would keep them.
      const otherMemberships = await tx.membership.count({
        where: { userId: claims.sub },
      });
      if (otherMemberships === 0) {
        await tx.user.delete({ where: { id: claims.sub } });
      }
    }, {
      // R98 F1: Prisma's default $transaction timeout is 5 s, which
      // is not survivable for the whole-org cascade tree on any
      // realistic tenant (a month of steady ingest = 100k+ events,
      // a handful of deployments). Prior shape tripped P2028 and
      // rolled back — org survived, user got a 500, but the R97
      // F-A org_delete_initiated warn line was already durable in
      // Datadog/Loki. SOC-2 evidence for tenant erasure asserted
      // a delete that never happened → worse than nothing. Bump
      // to 60 s (matches R95 F1 shape); maxWait 10 s prevents
      // queue-storm 429s under contention.
      timeout: 60_000,
      maxWait: 10_000,
    });

    req.log.warn(
      {
        event: "org.delete.committed",
        orgId: claims.orgId,
        userId: claims.sub,
        at: new Date().toISOString(),
      },
      "org_delete_committed",
    );

    clearSessionCookie(reply);
    return reply.send({ ok: true });
  });

  // Password reset — two-step flow. The first endpoint always returns 202,
  // regardless of whether the email exists, so we don't leak account
  // membership. The plaintext token is delivered ONLY via the configured
  // email path; it is never logged in production (log-read access would
  // otherwise be sufficient to take over any account).
  app.post("/reset-request", {
    // 3/hour per IP. Reset-request is anonymous, so an attacker could
    // spam it to burn our mail budget or DOS a specific mailbox.
    config: { rateLimit: perIp(3, 60 * 60_000) },
  }, async (req, reply) => {
    const body = z.object({ email: emailSchema }).safeParse(req.body);
    // Uniform response even on malformed input — no oracle for enumeration.
    if (!body.success) return reply.code(202).send({ ok: true });
    // R98 F2: return 202 IMMEDIATELY, then run the expensive
    // work (findUnique + argon2 hashPassword + user.update +
    // mail.send RTT) in a detached async block. Prior shape
    // awaited the whole chain on the existing-user branch
    // (~200-2000 ms) but not on the missing-user branch (~5-20
    // ms), giving a wall-clock enumeration oracle that
    // trivially defeated the perIp(3, 1h) rate limit via
    // residential-proxy rotation. Sibling /signup at line 151
    // already documents this exact pattern for welcome-email
    // send. UX cost: the 202 fires before the mail actually
    // lands in the target inbox, but that's already true from
    // the user's perspective (Resend/SMTP take seconds), and
    // the previous await didn't guarantee delivery either
    // (the mailer try/catch swallowed failures).
    const emailAddr = body.data.email;
    void (async () => {
      try {
        const user = await db.user.findUnique({ where: { email: emailAddr } });
        if (!user) return;
        const plaintextToken = randomToken(32);
        const resetTokenHash = await hashPassword(plaintextToken);
        await db.user.update({
          where: { id: user.id },
          data: { resetTokenHash, resetTokenAt: new Date() },
        });
        // R136 F3: forensic breadcrumb — R135 F1 wired the
        // /reset-confirm audit; the /reset-request counterpart was
        // reserved in audit.ts:13 docstring (auth.reset_request)
        // but never emitted. An admin investigating "who initiated
        // the reset flow from IP X at 03:12" needs BOTH sides to
        // reconstruct the chain. Fire-and-forget inside the
        // already-detached background block so the 202 response
        // wall-clock is unchanged. Guarded by the `if (!user)
        // return` above so an anonymous caller can't induce
        // audit noise for arbitrary email guessing (also
        // preserves the R98 F2 no-enumeration-oracle posture).
        const firstMembership = await db.membership.findFirst({
          where: { userId: user.id },
          orderBy: { createdAt: "asc" },
          select: { orgId: true },
        });
        if (firstMembership) {
          writeAudit(
            {
              orgId: firstMembership.orgId,
              event: "auth.reset_request",
              actorId: user.id,
              actorEmail: user.email,
              target: user.email,
              req,
            },
            req.log,
          );
        }
        // R213 F1: reset_request counter — see signup site
        // above. Only incremented when a real user + membership
        // exists (matching the audit posture) to preserve the
        // R98 F2 no-enumeration-oracle guarantee against
        // arbitrary email guessing.
        authEventsTotal.inc({ event: "reset_request", result: "ok" });
        // Build the reset link the user will click.
        const resetLink = `${env.APP_BASE_URL.replace(/\/$/, "")}/app/#/reset?token=${encodeURIComponent(plaintextToken)}&email=${encodeURIComponent(user.email)}`;
        // Send it. Uses whichever mailer driver is configured
        // (Resend, SMTP, or dev-stub). We never log the token
        // itself — only the driver + message id — so a log
        // leak can't lead to account takeover.
        const mail = getMailer(req.log);
        const template = passwordResetMail(resetLink);
        const result = await mail.send({
          to: user.email,
          subject: template.subject,
          text: template.text,
          html: template.html,
        });
        req.log.info(
          { userId: user.id, mailer: result.driver, messageId: result.id },
          "password_reset_email_sent",
        );
      } catch (err) {
        req.log.error(
          { err },
          "password_reset_deferred_failed",
        );
      }
    })();
    return reply.code(202).send({ ok: true });
  });

  const resetTtlMs = 24 * 60 * 60 * 1000;
  app.post("/reset-confirm", {
    // 10/min per IP. Consumes a random-looking 32-byte token, so brute
    // force is already infeasible cryptographically; this just prevents
    // an attacker from burning API budget while spraying candidate tokens.
    config: { rateLimit: perIp(10, 60_000) },
  }, async (req, reply) => {
    const body = z
      .object({
        email: emailSchema,
        token: z.string().min(16).max(256),
        newPassword: passwordSchema,
      })
      .safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: "invalid_token" });
    // R87 F2: close the "reset-in-progress ⇒ email is real"
    // oracle. Prior shape had three distinct exits:
    //   (a) !user || no reset outstanding → invalid_token, sub-ms
    //   (b) reset > 24 h old              → expired_token, sub-ms
    //   (c) reset within TTL, wrong token → invalid_token, ~100 ms
    // Both the error-string (expired_token appears only when the
    // account exists AND has a stale reset) and the argon2
    // timing gap (~100 ms vs sub-ms) let an attacker detect
    // "email is a real account with reset outstanding" — which
    // /reset-request (3/h/IP but no per-account gate) can be
    // used to INDUCE. Sibling of the R86 F3 /login oracle. Fix
    // pattern is the same: always run argon2 verify against a
    // valid PHC hash (dummy when the real state doesn't
    // qualify), collapse all failure exits to a single
    // invalid_token 401.
    const user = await db.user.findUnique({ where: { email: body.data.email } });
    const resetFresh =
      !!(user?.resetTokenHash &&
        user.resetTokenAt &&
        Date.now() - user.resetTokenAt.getTime() <= resetTtlMs);
    const hashForCompare = resetFresh
      ? (user!.resetTokenHash as string)
      : await getDummyPasswordHash();
    const ok = await verifyPassword(hashForCompare, body.data.token);
    if (!ok || !resetFresh || !user) {
      // R141 F2: step-up failure audit — only when we have a
      // real user row to attach the orgId (otherwise there's
      // nothing to audit against). Preserves the R98 F2 no-
      // enumeration-oracle posture: an attacker guessing
      // email+token combinations for accounts that don't exist
      // triggers no audit, matching the wire-response uniformity.
      // For legit-email + wrong-token, this is the forensic trail
      // R135 F1's success-side audit needed for symmetry.
      if (user) {
        const firstMembership = await db.membership.findFirst({
          where: { userId: user.id },
          orderBy: { createdAt: "asc" },
          select: { orgId: true },
        });
        if (firstMembership) {
          writeAudit(
            {
              orgId: firstMembership.orgId,
              event: "auth.step_up_denied",
              actorId: user.id,
              actorEmail: user.email,
              note: "invalid_token",
              metadata: { endpoint: "reset_confirm" },
              req,
            },
            req.log,
          );
        }
      }
      return reply.code(401).send({ error: "invalid_token" });
    }
    const passwordHash = await hashPassword(body.data.newPassword);
    // R123 F3: password reset is a break-glass event. R90 F1
    // bumps sessionRevokedAt to fence every live cookie JWT, but
    // session-middleware's API-key auth path (lib/session-middleware.ts)
    // does NOT consult user.sessionRevokedAt when synthesizing a
    // membershipRole from ApiKey.role — so a leaked `av_srv_`
    // token that predates the reset still authenticates at prior
    // privilege indefinitely. Same fence gap R103 F1 closed for
    // /members PATCH+DELETE role changes, at the reset-confirm
    // scope. Concrete threat: victim's laptop is compromised with
    // browser autofill + a checked-in av_srv_ token in dotfiles →
    // attacker forces a password reset via the compromised
    // mailbox → all cookies die → victim believes account is
    // safe → attacker keeps hitting the API with the pre-reset
    // token until the victim manually revokes each one.
    // Auto-revoke the user's active-created API keys inside the
    // same transaction so a crash between the two writes can't
    // leave the passwordHash rotated but the tokens still live.
    await db.$transaction([
      db.user.update({
        where: { id: user.id },
        data: {
          passwordHash,
          resetTokenHash: null,
          resetTokenAt: null,
          sessionRevokedAt: new Date(),
        },
      }),
      db.apiKey.updateMany({
        where: { createdById: user.id, revokedAt: null },
        data: { revokedAt: new Date() },
      }),
    ]);
    // R135 F1: password reset is the strongest break-glass primitive
    // in the auth pipeline (R123 F3 auto-revokes every av_srv_
    // token org-wide + R90 F1 fences all cookies). Prior shape
    // emitted zero writeAudit — an admin investigating "who reset
    // user X's password at 03:12 from IP Y, and which av_srv_
    // tokens just went dead" got nothing from audit_entries.
    // Every other authentication-material mutation audits
    // (auth.login, auth.signup, auth.oauth_signin,
    // mfa.credential_registered, mfa.credential_revoked,
    // saml.keypair_rotated) — the auth.reset_confirm slug was
    // reserved in audit.ts:15 but never wired. Lightweight
    // membership lookup for the orgId scope; fire-and-forget
    // matches R134 F1/F2 shape.
    const firstMembership = await db.membership.findFirst({
      where: { userId: user.id },
      orderBy: { createdAt: "asc" },
      select: { orgId: true },
    });
    if (firstMembership) {
      writeAudit(
        {
          orgId: firstMembership.orgId,
          event: "auth.reset_confirm",
          actorId: user.id,
          actorEmail: user.email,
          target: user.email,
          metadata: { revokedApiKeys: true },
          req,
        },
        req.log,
      );
    }
    // R213 F1: reset_confirm counter — see signup site above.
    authEventsTotal.inc({ event: "reset_confirm", result: "ok" });
    return reply.send({ ok: true });
  });
}
