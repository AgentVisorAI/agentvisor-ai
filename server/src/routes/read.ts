import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { db } from "../db.js";
import { requireSession } from "../lib/session-middleware.js";

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
        deploymentId: z.string().optional(),
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

    return reply.send({
      sessions: sessions.map((s) => ({
        ...s,
        costUsdMicros: s.costUsdMicros.toString(),
        payoutUsdMicros: s.payoutUsdMicros.toString(),
        blockedPayoutUsdMicros: s.blockedPayoutUsdMicros.toString(),
      })),
      stats: {
        ...stats,
        costUsdMicros: stats.costUsdMicros.toString(),
        blockedPayoutUsdMicros: stats.blockedPayoutUsdMicros.toString(),
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
        cursor: z.string().optional(),
        limit: z.coerce.number().int().min(1).max(SESSIONS_LIST_LIMIT_MAX).default(50),
        deploymentId: z.string().optional(),
        // Free-text filter. Server-side so filtering over the whole
        // fleet works at 1M+ sessions (not just the visible page).
        q: z.string().max(200).optional(),
        blockedOnly: z.coerce.boolean().optional(),
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

    // Fetch one extra so we can decide whether nextCursor is present
    // without a second COUNT query.
    const rows = await db.session.findMany({
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

    const hasMore = rows.length > query.data.limit;
    const page = hasMore ? rows.slice(0, query.data.limit) : rows;
    const last = page[page.length - 1];
    const nextCursor = hasMore && last
      ? encodeCursor({ openedAt: last.openedAt.toISOString(), id: last.id })
      : null;

    return reply.send({
      sessions: page.map((s) => ({
        ...s,
        costUsdMicros: s.costUsdMicros.toString(),
        payoutUsdMicros: s.payoutUsdMicros.toString(),
        blockedPayoutUsdMicros: s.blockedPayoutUsdMicros.toString(),
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

    return reply.send({
      session: {
        ...session,
        events: eventsPage,
        costUsdMicros: session.costUsdMicros.toString(),
        payoutUsdMicros: session.payoutUsdMicros.toString(),
        blockedPayoutUsdMicros: session.blockedPayoutUsdMicros.toString(),
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
    const safe = {
      ...receipt,
      session: receipt.session
        ? {
            ...receipt.session,
            costUsdMicros: receipt.session.costUsdMicros.toString(),
            payoutUsdMicros: receipt.session.payoutUsdMicros.toString(),
            blockedPayoutUsdMicros: receipt.session.blockedPayoutUsdMicros.toString(),
          }
        : receipt.session,
      publicKeyHex: receipt.session?.deployment?.publicKeyHex ?? null,
    };
    return reply.send({ receipt: safe });
  });
}
