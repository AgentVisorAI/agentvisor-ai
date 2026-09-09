import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { createHash, createPublicKey, randomUUID, verify as cryptoVerify } from "node:crypto";
import { Prisma } from "@prisma/client";
import { db } from "../db.js";
import { verifyPassword } from "../lib/auth.js";
import { bus } from "../lib/bus.js";
import { dispatchEvent } from "../lib/webhooks.js";
import { writeAudit } from "../lib/audit.js";

// ── Auth for the ingest endpoint ────────────────────────────────────────────
//
// Daemons authenticate with `Authorization: Bearer <ingest_token>` plus the
// deployment id in a header. We verify the plaintext token against the
// argon2 hash on file. This lookup is intentionally by deployment id (fast,
// indexed) — never by scanning every deployment.

async function authenticateDaemon(
  req: FastifyRequest,
  reply: FastifyReply,
): Promise<{ deploymentId: string; orgId: string } | null> {
  const deploymentId = req.headers["x-av-deployment"];
  const auth = req.headers.authorization;
  if (typeof deploymentId !== "string" || !auth?.startsWith("Bearer ")) {
    reply.code(401).send({ error: "unauthenticated" });
    return null;
  }
  const token = auth.slice("Bearer ".length);
  const deployment = await db.deployment.findUnique({
    where: { id: deploymentId },
    select: { id: true, orgId: true, ingestTokenHash: true },
  });
  if (!deployment) {
    reply.code(401).send({ error: "unauthenticated" });
    return null;
  }
  const ok = await verifyPassword(deployment.ingestTokenHash, token);
  if (!ok) {
    reply.code(401).send({ error: "unauthenticated" });
    return null;
  }
  // Best-effort — don't fail ingest if the timestamp write races.
  db.deployment
    .update({
      where: { id: deployment.id },
      data: { lastIngestAt: new Date() },
    })
    .catch(() => void 0);
  return { deploymentId: deployment.id, orgId: deployment.orgId };
}

// ── Payload schemas ─────────────────────────────────────────────────────────

// Round-124 (R15 hunt): refuse control (Cc) and format (Cf) characters
// in IDENTIFIER fields. Cf includes the bidi controls (U+202A-202E,
// U+2066-2069, U+061C) behind Trojan-Source-style display spoofing —
// an attacker with a leaked ingest token (the R119/R124/R125 threat
// model) could otherwise mint sessions/events whose agent or tag
// renders REVERSED or with invisible characters in the console and
// the audit CSV, spoofing the very evidence trail this product sells.
// Free-content fields (body, sub) are deliberately exempt: daemons
// capture model output verbatim there and the SPA HTML-escapes them;
// identifiers have no legitimate use for invisible characters. Same
// refusal family as auth.ts noCrlfNul (R211).
const noControlOrFormatChars = (v: string): boolean => !/[\p{Cc}\p{Cf}]/u.test(v);
const identifier = (max: number) =>
  z
    .string()
    .min(1)
    .max(max)
    .refine(noControlOrFormatChars, "must not contain control or format characters");

const sessionUpsert = z.object({
  externalId: identifier(128),
  // Round-123: NFC like every other identity-ish string (#381 pattern)
  // so server-side session search matches regardless of the daemon
  // host's composition form.
  agent: identifier(80).transform((v) => v.normalize("NFC")),
  workflow: z.enum(["signed", "unsigned"]).default("signed"),
  status: z.enum(["live", "sealed", "blocked"]).default("live"),
  // R161 F1: cap at 1M policy versions. Prior shape was
  // unbounded — Session.policyVersion is Postgres int4 (max
  // 2^31-1 ≈ 2.1e9), so an attacker or runaway daemon posting
  // `policyVersion: 3_000_000_000` on the CREATE branch of the
  // R151 F1 updateMany fallthrough at :~340 triggers
  // numeric_value_out_of_range → same 500-livelock class R160
  // F1 closed for the event rollup. Realistic policy versions
  // increment 1 per config change; 1M is far above any realistic
  // deployment's lifetime bumps.
  policyVersion: z.number().int().min(0).max(1_000_000).default(1),
  openedAt: z.coerce.date(),
  closedAt: z.coerce.date().optional(),
});

const eventPayload = z.object({
  sessionExternalId: identifier(128),
  // R161 F1: cap seq at 100M. Prior shape was unbounded —
  // Event.seq is Postgres int4 and every batch's WHERE seq: {gt}
  // /IN clauses and rollup writes flow through it. 100M is
  // 6+ orders above any realistic session event count (typical
  // is 10-1000); attacker sending `seq: 3_000_000_000` triggers
  // numeric_value_out_of_range on event.create → same 500-
  // livelock class R160 F1 closed for the rollup fields.
  seq: z.number().int().min(0).max(100_000_000),
  kind: z.enum(["sys", "user", "llm", "tool", "block", "guard", "audit"]),
  tag: identifier(32),
  body: z.string().max(8000),
  sub: z.string().max(2000).optional(),
  // Which policy this event fired under, when the daemon attributes
  // one (block verdicts, allowlist hits). Free-form name matched
  // against Policy.name for the console's per-policy 24h counters —
  // unknown names are stored as-is so counters appear as soon as the
  // operator creates the matching policy row.
  policyName: z
    .string()
    .trim()
    .min(1)
    .max(80)
    .refine(noControlOrFormatChars, "must not contain control or format characters")
    .optional(),
  occurredAt: z.coerce.date(),
  // R160 F1: per-field upper bounds on all numeric increments.
  // Prior shape used `z.number().int().min(0)` with NO upper
  // bound — z.number().int() accepts anything up to
  // Number.MAX_SAFE_INTEGER (2^53 - 1 ≈ 9e15). The rollup
  // updateMany at :679-690 fires:
  //   tx.session.updateMany({
  //     where: { id: session.id, status: { not: "sealed" } },
  //     data: { promptTokens: { increment: dPrompt }, ... },
  //   })
  // against `Session.promptTokens: Int` (Prisma Int → Postgres
  // int4, max 2^31 - 1 ≈ 2.1e9). A single event with
  // `addPromptTokens: 3_000_000_000` (well within Zod's default
  // ceiling) triggers Postgres `numeric_value_out_of_range` on
  // the UPDATE. The R152 F1 catch handles only the sealed-tx
  // sentinel; every other error re-throws as 500 → daemon
  // retries → same error → **session livelock**, the exact
  // class R95 F1 closed for the tx-timeout case. Threat model:
  // leaked AV_INGEST_TOKEN or a runaway daemon, same as R119
  // F2 / R144 F1 / R151 F1 / R152 F1.
  //
  // Caps sized so a full 500-event batch fits comfortably
  // inside int4 for the Int columns and inside 2^53 for the
  // BigInt-accumulator JS variables (which R152 F1 wraps via
  // BigInt(dCost) before increment):
  //   * Tokens (Int in DB): 1_000_000 per event × 500 events =
  //     5e8 per batch, well below 2^31-1. Realistic LLM events
  //     carry low-thousands of tokens; even Gemini 1.5 Pro's
  //     2M-context whole-window prompt is 2× the cap — a legit
  //     agent hitting this ceiling should raise the bound
  //     explicitly, not fail-open into livelock.
  //   * Cost/payout micros (BigInt in DB): 100_000_000_000 per
  //     event (= $100k per event) is 12× the smoke test's
  //     $8400 high-value blocked-refund case, covering
  //     realistic ceiling for expensive tool calls / refund
  //     blocks without capping legitimate high-cost operations.
  //     R124 F3's MAX_PER_EVENT_BLOCKED_PAYOUT=1e9 remains the
  //     SIEM-fanout clamp (fan-out is more DoS-sensitive than
  //     the DB); this Zod bound is the wider outer envelope for
  //     what the DB will accept at all. Per-batch: 500 × 1e11 =
  //     5e13 < 2^53 (9e15) so JS number arithmetic stays
  //     precise before BigInt().
  //   * Tools counters (Int in DB): 1_000 per event × 500 =
  //     5e5, comfortably under int4. Realistic per-event tool
  //     calls are 0-10.
  //   * journalCount (Int in DB): capped at 1_000_000 —
  //     aggregating >1M journal entries into a single row is
  //     already an extreme edge case.
  //
  // Note on the deeper fix: the Int columns
  // (promptTokens/completionTokens/toolsAllowed/toolsBlocked)
  // could still overflow int4 across MANY sequential batches
  // in a very long-running session. Migrating those to BigInt
  // is the durable fix but is a separate schema-migration
  // scope. The caps here close the immediate attacker-injected
  // DoS and the per-batch overflow leg.
  journalCount: z.number().int().min(0).max(1_000_000).default(1),
  // Delta rollups the daemon reports for this event, if any.
  addPromptTokens: z.number().int().min(0).max(1_000_000).default(0),
  addCompletionTokens: z.number().int().min(0).max(1_000_000).default(0),
  addCostUsdMicros: z.number().int().min(0).max(100_000_000_000).default(0),
  addPayoutUsdMicros: z.number().int().min(0).max(100_000_000_000).default(0),
  addBlockedPayoutUsdMicros: z.number().int().min(0).max(100_000_000_000).default(0),
  addToolsAllowed: z.number().int().min(0).max(1_000).default(0),
  addToolsBlocked: z.number().int().min(0).max(1_000).default(0),
});

// ── Server-side Ed25519 receipt verification ────────────────────────────────
//
// Mirrors the byte framing of the Rust `av-receipts` crate
// (crates/av-receipts/src/receipt.rs `signing_message`) and the JS
// verifier (docs/verify/verify.js `receiptSigningMessage`):
//   * v1 → bare canonical body bytes
//   * v2 → b"agentvisor-receipt-v2\0" || u64_be(body.len) || body
// Without this check, the key-id comparison alone gated storage: any
// holder of a leaked ingest token could POST a receipt whose sigB64 is
// random bytes; first-write-wins then permanently sealed the session
// against the LEGITIMATE receipt, and every downstream verifier
// (console, /verify page, avctl) reported an invalid compliance
// artifact for a session the customer trusted.
const RECEIPT_DOMAIN_TAG_V2 = Buffer.from("agentvisor-receipt-v2\0", "utf8");

function receiptSigningMessage(rawBody: string): Buffer {
  const canonical = Buffer.from(rawBody, "utf8");
  let receiptVersion = 1;
  try {
    const parsed: unknown = JSON.parse(rawBody);
    if (
      typeof parsed === "object" &&
      parsed !== null &&
      typeof (parsed as { receipt_version?: unknown }).receipt_version === "number"
    ) {
      receiptVersion = (parsed as { receipt_version: number }).receipt_version;
    }
  } catch {
    // Not JSON — treat as v1; the signature check will fail, which is
    // the correct verdict for garbage.
  }
  if (receiptVersion === 1) return canonical;
  if (receiptVersion === 2) {
    const len = Buffer.alloc(8);
    len.writeBigUInt64BE(BigInt(canonical.length), 0);
    return Buffer.concat([RECEIPT_DOMAIN_TAG_V2, len, canonical]);
  }
  // Unknown version — fail closed with an empty message that can never
  // verify, rather than guessing a future framing.
  return Buffer.alloc(0);
}

/** SPKI DER prefix for a raw 32-byte Ed25519 public key. */
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function verifyReceiptSignature(
  publicKeyHex: string,
  sigB64: string,
  rawBody: string,
): boolean {
  try {
    const rawKey = Buffer.from(publicKeyHex, "hex");
    if (rawKey.length !== 32) return false;
    const sig = Buffer.from(sigB64, "base64");
    if (sig.length !== 64) return false;
    const key = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, rawKey]),
      format: "der",
      type: "spki",
    });
    return cryptoVerify(null, receiptSigningMessage(rawBody), key, sig);
  } catch {
    return false;
  }
}

const receiptPayload = z.object({
  sessionExternalId: identifier(128),
  receiptId: identifier(128),
  body: z.string().min(1).max(65_536),
  sigB64: z.string().min(1).max(4096),
  keyIdHex: z.string().min(1).max(128),
  // R161 F1: cap eventCount at 100M. Prior shape was unbounded
  // — Receipt.eventCount is Postgres int4. Same overflow vector
  // as eventPayload.seq above; receipt.body's signed eventCount
  // should match the row-count anyway, so bounding here also
  // catches attacker/runaway daemons committing receipts with
  // impossible counts (nonsense audit trail).
  eventCount: z.number().int().min(0).max(100_000_000),
  issuedAt: z.coerce.date(),
  // R161 F1: cap stopReasonId to [0, 1M]. Prior shape had NO
  // min AND NO max — accepted negative numbers and the full
  // MAX_SAFE_INTEGER range. Session.stopReasonId is Postgres
  // int4?; a negative value would trip R79 F1's stopReason
  // resolver logic in unexpected ways, and 3e9 would trip
  // numeric_value_out_of_range. Realistic stop reason IDs are
  // a small enum (<100 today); 1M is a safe outer envelope.
  stopReasonId: z.number().int().min(0).max(1_000_000).optional(),
  stopReason: z.string().max(80).optional(),
});

const publicKeyPayload = z.object({
  publicKeyHex: z.string().regex(/^[0-9a-f]{64}$/),
  // Self-reported daemon build version. Display metadata only — it is
  // NEVER part of the trust decision below, so it updates on every
  // check-in even when the anchor logic refuses a key change.
  daemonVersion: z
    .string()
    .max(40)
    .regex(/^[0-9A-Za-z][0-9A-Za-z.+_-]*$/)
    .optional(),
});

export async function ingestRoutes(app: FastifyInstance): Promise<void> {
  app.post("/pubkey", async (req, reply) => {
    const daemon = await authenticateDaemon(req, reply);
    if (!daemon) return;
    const body = publicKeyPayload.safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: "invalid_input" });
    // Version is informational — record it best-effort on every
    // authenticated check-in, independent of the trust-anchor outcome
    // (errors are swallowed like the lastIngestAt touch in
    // authenticateDaemon). Unlike that unobserved heartbeat, the write
    // IS awaited: a daemon that checks in and immediately appears in
    // the deployments list must show its version, and the previous
    // fire-and-forget form let the route return 200 before the row
    // committed (flaky "deployment reports daemon version" e2e).
    if (body.data.daemonVersion) {
      await db.deployment
        .update({
          where: { id: daemon.deploymentId },
          data: { daemonVersion: body.data.daemonVersion },
        })
        .catch(() => void 0);
    }
    // R91 F3: silent trust-anchor rotation is the exact class the
    // R78 pinning + R79 verifier hardening tried to close, and
    // this endpoint was silently ROTATING the anchor without any
    // audit entry or admin approval flow. A stolen ingest token
    // (or a routinely re-provisioned daemon) could:
    //   1. POST /pubkey {publicKeyHex: <attacker key>}
    //   2. All prior receipts for that deployment now fail verify
    //      (the console + /verify page compare against the
    //      current deployment.publicKeyHex, not the receipt's
    //      own keyIdHex).
    //   3. Forged sessions/events signed with the attacker's new
    //      key verify GREEN.
    // Fix: allow FIRST-SET (empty column → new key) without
    // ceremony but require the ingest layer to reject any
    // subsequent CHANGE to a different key. A legitimate rotation
    // needs an owner/admin-authenticated console flow (out of
    // scope for this hardening — the endpoint isn't wired up
    // yet — so rejecting mid-flight rotation is the correct
    // fail-closed posture). Always emit an audit entry so
    // operators see first-set events.
    const dep = await db.deployment.findUnique({
      where: { id: daemon.deploymentId },
      select: { orgId: true, name: true, publicKeyHex: true },
    });
    if (!dep) return reply.code(404).send({ error: "deployment_not_found" });
    // R92 F3: fold the check + write into a conditional atomic
    // updateMany scoped by `publicKeyHex: null` so that two
    // concurrent /pubkey calls at first-set time can't both
    // observe null and both silently win with last-writer
    // semantics. The daemon-vs-stolen-token race (daemon on
    // first boot, attacker holding the same ingest token) is
    // real: whoever's write reached Postgres LAST previously
    // won the trust anchor and BOTH would then log
    // `deployment.pubkey_first_set`, letting an operator
    // misread the audit trail as "the daemon just retried".
    // With the conditional predicate, exactly one first-set
    // wins; the loser gets `count === 0` and falls into the
    // existing "already-set" branch (409 if different key,
    // idempotent 200 if same key).
    if (!dep.publicKeyHex) {
      const upd = await db.deployment.updateMany({
        where: { id: daemon.deploymentId, publicKeyHex: null },
        data: { publicKeyHex: body.data.publicKeyHex },
      });
      if (upd.count === 1) {
        writeAudit(
          {
            orgId: dep.orgId,
            event: "deployment.pubkey_first_set",
            actorId: `daemon:${daemon.deploymentId}`,
            actorEmail: `daemon@${dep.name}`,
            target: dep.name,
            metadata: {
              deploymentId: daemon.deploymentId,
              publicKeyHex: body.data.publicKeyHex,
            },
            req,
          },
          req.log,
        );
        return reply.send({ ok: true });
      }
      // Lost the first-set race. Re-fetch the current key and
      // fall through to the same-key vs different-key branch.
      const refetched = await db.deployment.findUnique({
        where: { id: daemon.deploymentId },
        select: { publicKeyHex: true },
      });
      dep.publicKeyHex = refetched?.publicKeyHex ?? null;
    }
    if (dep.publicKeyHex && dep.publicKeyHex !== body.data.publicKeyHex) {
      // Refuse silent rotation. Log at warn so an operator can
      // investigate a rogue daemon or a stolen token.
      req.log.warn(
        {
          deploymentId: daemon.deploymentId,
          orgId: dep.orgId,
          old: dep.publicKeyHex,
          proposed: body.data.publicKeyHex,
        },
        "ingest_pubkey_rotation_refused",
      );
      writeAudit(
        {
          orgId: dep.orgId,
          event: "deployment.pubkey_rotation_refused",
          actorId: `daemon:${daemon.deploymentId}`,
          actorEmail: `daemon@${dep.name}`,
          target: dep.name,
          metadata: {
            deploymentId: daemon.deploymentId,
            currentPublicKeyHex: dep.publicKeyHex,
            proposedPublicKeyHex: body.data.publicKeyHex,
          },
          req,
        },
        req.log,
      );
      return reply.code(409).send({ error: "pubkey_already_set" });
    }
    // Idempotent same-key repost is a no-op.
    return reply.send({ ok: true });
  });

  // Upsert a session (idempotent on externalId).
  app.post("/sessions", async (req, reply) => {
    const daemon = await authenticateDaemon(req, reply);
    if (!daemon) return;
    const body = sessionUpsert.safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: "invalid_input" });
    const s = body.data;
    // Round-105: clamp session clocks the same way the events path
    // guards occurredAt (now+5min / Jan 1 2000). openedAt is
    // client-supplied, so a TZ-misconfigured daemon (local time
    // written as UTC) or a hostile token holder could post a +6h
    // session that pins the list top for hours, renders "live" the
    // whole time (the stalled heuristic needs now-openedAt > 30min),
    // and postpones retention (`openedAt < cutoff` never matches).
    // Events are dropped; sessions are CLAMPED instead — dropping
    // would lose an honest-but-skewed deployment's entire audit
    // trail, while the signed receipt remains the cryptographic
    // record of the daemon's own clock claim.
    {
      const nowMs = Date.now();
      const maxMs = nowMs + 5 * 60_000;
      const minMs = new Date("2000-01-01T00:00:00Z").getTime();
      const clampDate = (d: Date) =>
        new Date(Math.min(Math.max(d.getTime(), minMs), maxMs));
      s.openedAt = clampDate(s.openedAt);
      if (s.closedAt) s.closedAt = clampDate(s.closedAt);
    }
    // Look up existing session first so we can protect a sealed status
    // from being "un-sealed" by a buggy daemon retrying with status=live.
    // Once a session is sealed the totals are finalized and the receipt
    // is signed; reverting the status would corrupt the audit trail.
    const existing = await db.session.findUnique({
      where: {
        deploymentId_externalId: {
          deploymentId: daemon.deploymentId,
          externalId: s.externalId,
        },
      },
      select: { status: true },
    });
    // R119 F2: post-seal metadata freeze. R93 F4 + R118 F2
    // locked the receipt row and session.stopReason once sealed.
    // Prior shape here only locked `status` (via nextStatus) —
    // an ingest-token holder could re-POST /ingest/sessions with
    // status:"sealed" (satisfies the gate) and mutated agent /
    // workflow / policyVersion / closedAt to relabel a sealed
    // session. The signed receipt.body is unchanged so the
    // Ed25519 verifier at /verify still passes, but the SPA
    // session list + /me/export render session.agent /
    // session.workflow / session.policyVersion — post-seal
    // audit-trail defacement (e.g. mutating workflow to
    // "unsigned" makes a legitimately signed session appear
    // unsigned in the list). Same threat model as R92 F2 / R93
    // F4 / R118 F2 (leaked AV_INGEST_TOKEN). First-write-wins
    // matches the sealed-receipt posture across the file.
    // R141 F3: refuse pre-sealed CREATE. The R119 F2 update-branch
    // freeze covered rewrites of already-sealed rows, but the
    // create branch (row didn't exist yet) had no such guard. If
    // retention purges Session rows (sessionRetentionDays elapsed)
    // but preserves audit rows referencing them, a compromised
    // ingest-token holder can POST /ingest/sessions with the
    // historical externalId + status:"sealed" + attacker-chosen
    // agent/openedAt — Prisma happily inserts. Downstream
    // /read/sessions/:id then renders a "sealed but no receipt"
    // row (Receipt was cascade-purged), producing plausible-
    // deniability defacement of forensic history. Same threat
    // model as R118 F2 / R119 F2 (leaked AV_INGEST_TOKEN). The
    // seal transition is by design the receipt row's job
    // (/ingest/receipts sets status:"sealed" atomically with
    // the receipt) — an ingest client should never POST a new
    // session that's already sealed. Refuse cleanly.
    // R144 F1: refuse ANY POST /ingest/sessions with
    // s.status === "sealed" — not just the CREATE case. R141 F3
    // only guarded `!existing`; on an existing live session
    // nextStatus would collapse to s.status="sealed" and the
    // UPDATE branch flipped the row without ever running
    // /ingest/receipts. Result: session.status="sealed" with NO
    // Receipt row, stopReason/stopReasonId null, /events guard at
    // ingest.ts:362 silently drops all further events for that
    // session — a compromised AV_INGEST_TOKEN holder can race an
    // in-flight session, force-seal it, and censor the rest of
    // the trail. Same threat model as R141 F3; the invariant
    // needs to hold on UPDATE too.
    if (s.status === "sealed") {
      req.log.warn(
        {
          deploymentId: daemon.deploymentId,
          externalId: s.externalId,
          existingStatus: existing?.status ?? null,
        },
        "ingest_session_direct_seal_refused",
      );
      writeAudit(
        {
          orgId: daemon.orgId,
          event: "deployment.direct_seal_refused",
          actorId: `daemon:${daemon.deploymentId}`,
          actorEmail: `daemon@${daemon.deploymentId}`,
          target: s.externalId,
          metadata: {
            deploymentId: daemon.deploymentId,
            externalId: s.externalId,
            existingStatus: existing?.status ?? null,
          },
          req,
        },
        req.log,
      );
      return reply
        .code(400)
        .send({ error: "cannot_direct_seal_session" });
    }
    // R151 F1: atomic sealed-guard via conditional updateMany.
    // Prior shape branched on `isSealed = existing?.status ===
    // "sealed"` read from findUnique above, then chose
    // `upsert.update = isSealed ? {} : {full field set}`. TOCTOU
    // race with /ingest/receipts's concurrent seal at :~1025:
    // if the receipt handler commits `session.update({status:
    // "sealed"})` between our findUnique and the upsert, our
    // JS snapshot showed "live", `isSealed=false`, and Postgres'
    // ON CONFLICT DO UPDATE has no sealed guard — it blindly
    // overwrote the just-sealed row back to "live" with the
    // attacker-supplied agent / workflow / policyVersion /
    // closedAt fields. Signed receipt.eventCount then mismatched
    // session.events, the /events guard at :531 stopped
    // rejecting further appends, and the SPA/exports rendered
    // the mutated fields — the same post-seal defacement class
    // R119 F2 / R141 F3 / R144 F1 closed for the non-concurrent
    // paths. R144's own header comment named the invariant but
    // enforced it only against attacker-supplied s.status ===
    // "sealed"; a race against a legitimate concurrent seal
    // slipped through. Fix: move the sealed guard onto the DB
    // WHERE clause. Postgres evaluates `status: { not: "sealed" }`
    // under the same row lock the UPDATE takes, so no snapshot
    // can lie about the sealed state.
    const upd = await db.session.updateMany({
      where: {
        deploymentId: daemon.deploymentId,
        externalId: s.externalId,
        status: { not: "sealed" },
      },
      data: {
        agent: s.agent,
        workflow: s.workflow,
        status: s.status,
        policyVersion: s.policyVersion,
        closedAt: s.closedAt,
      },
    });
    let session: { id: string; externalId: string; agent: string };
    if (upd.count === 0) {
      // Two cases collapse here:
      //   1. Row doesn't exist yet → CREATE branch.
      //   2. Row exists AND is sealed → R119 F2 freeze; leave
      //      it untouched via `update: {}`.
      // Upsert.create handles case 1 atomically; if a concurrent
      // writer wins the create race the `update: {}` no-op keeps
      // us safe on case 2 as well.
      session = await db.session.upsert({
        where: {
          deploymentId_externalId: {
            deploymentId: daemon.deploymentId,
            externalId: s.externalId,
          },
        },
        create: {
          deploymentId: daemon.deploymentId,
          orgId: daemon.orgId,
          externalId: s.externalId,
          agent: s.agent,
          workflow: s.workflow,
          status: s.status,
          policyVersion: s.policyVersion,
          openedAt: s.openedAt,
          closedAt: s.closedAt,
        },
        update: {},
        // R123 F2: return the PERSISTED agent (which is the
        // pre-seal canonical value on a sealed row) rather than
        // the caller-supplied s.agent, so bus.publish below
        // doesn't forward attacker-controlled agent on the
        // no-op branch.
        select: { id: true, externalId: true, agent: true },
      });
    } else {
      const found = await db.session.findUnique({
        where: {
          deploymentId_externalId: {
            deploymentId: daemon.deploymentId,
            externalId: s.externalId,
          },
        },
        // R123 F2: forward the persisted agent (matches the
        // no-op branch above).
        select: { id: true, externalId: true, agent: true },
      });
      if (!found) {
        // updateMany reported 1 row updated but the row is gone
        // by the time we look it up — a retention purge or a
        // hard delete raced in between. Treat as no-op.
        return reply.code(409).send({ error: "session_race" });
      }
      session = found;
    }
    bus.publish({
      type: "session.upsert",
      orgId: daemon.orgId,
      deploymentId: daemon.deploymentId,
      sessionId: session.id,
      externalId: session.externalId,
      agent: session.agent,
    });
    return reply.send({ session });
  });

  // Append events. Idempotent per (session, seq) — a retrying daemon can't
  // duplicate rows.
  app.post("/events", async (req, reply) => {
    const daemon = await authenticateDaemon(req, reply);
    if (!daemon) return;
    const body = z.array(eventPayload).max(500).safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: "invalid_input" });
    const events = body.data;
    if (events.length === 0) return reply.send({ inserted: 0 });

    // Group by sessionExternalId so we do one lookup per session.
    const byExt = new Map<string, typeof events>();
    for (const ev of events) {
      const arr = byExt.get(ev.sessionExternalId) ?? [];
      arr.push(ev);
      byExt.set(ev.sessionExternalId, arr);
    }

    let inserted = 0;
    const rejectedSealed: string[] = [];
    // Reject events whose occurredAt is more than 5 minutes in the future
    // (allows NTP drift + reasonable batch send delay). Similarly reject
    // events dated before Jan 1 2000 — no legitimate agent runs predate
    // that. Both are silent per-event drops rather than a whole-batch 400
    // so a mostly-good batch still lands.
    const now = Date.now();
    const maxFutureMs = 5 * 60_000;
    const minPastMs = new Date("2000-01-01T00:00:00Z").getTime();
    let droppedSkewed = 0;
    let droppedAncient = 0;

    for (const [externalId, batch] of byExt) {
      const session = await db.session.findUnique({
        where: {
          deploymentId_externalId: {
            deploymentId: daemon.deploymentId,
            externalId,
          },
        },
        select: { id: true, status: true },
      });
      if (!session) continue; // ignore events for a session the daemon didn't upsert first

      // A sealed session's totals were finalized when the daemon issued
      // the receipt. Allowing more events after that would silently
      // corrupt the rollup. Reject the batch for this session; the
      // daemon should never send more events for a session it sealed.
      if (session.status === "sealed") {
        rejectedSealed.push(externalId);
        continue;
      }

      // Idempotency: filter the batch down to *new* seqs before touching
      // the rollup counters. A retrying daemon that sends the same events
      // twice must not double-count tokens / cost / payout — this was a
      // real bug where session totals grew every retry even though the
      // event rows were skipped by createMany.skipDuplicates.
      const existing = await db.event.findMany({
        where: { sessionId: session.id, seq: { in: batch.map((e) => e.seq) } },
        select: { seq: true },
      });
      const existingSeqs = new Set(existing.map((e) => e.seq));
      // R96 F2: dedupe within the batch itself before touching the
      // rollup. Prior shape filtered ONLY against DB-existing seqs
      // — an intra-batch duplicate seq passed the guard, hit
      // event.create (first succeeds, second throws P2002 caught +
      // continue), then the rollup loop ran twice for the same seq
      // because `insertedSeqs.has(e.seq)` was true for both
      // iterations. A daemon (buggy or malicious with a compromised
      // ingest token) that posts [{seq:5, addCostUsdMicros:1000},
      // {seq:5, addCostUsdMicros:9000}] committed one event row but
      // inflated session.costUsdMicros by 10 000. The receipt then
      // signed the inflated total — same compliance-story downgrade
      // class R93 F2 / R94 F1 closed for the inter-batch race,
      // just via the intra-batch vector. Keep first occurrence.
      const seenSeqs = new Set<number>();
      const fresh = batch.filter((e) => {
        if (existingSeqs.has(e.seq)) return false;
        if (seenSeqs.has(e.seq)) return false;
        seenSeqs.add(e.seq);
        const t = e.occurredAt.getTime();
        if (t > now + maxFutureMs) { droppedSkewed++; return false; }
        if (t < minPastMs) { droppedAncient++; return false; }
        return true;
      });
      if (fresh.length === 0) continue;

      const rows = fresh.map((e) => ({
        sessionId: session.id,
        seq: e.seq,
        kind: e.kind,
        tag: e.tag,
        body: e.body,
        sub: e.sub,
        policyName: e.policyName,
        occurredAt: e.occurredAt,
        journalCount: e.journalCount,
      }));
      // R93 F2: prior shape ran createMany({skipDuplicates:true}) then
      // computed rollup deltas over the FULL `fresh` array. Two
      // concurrent POSTs (daemon retry vs live daemon, spool replay
      // vs live) both saw existingSeqs=∅, both computed the full
      // deltas, one won the unique-constraint insert, the other's
      // createMany.count went to 0 — but BOTH called session.update
      // with the full deltas. Session totals silently doubled; the
      // finalized receipt then signed the inflated numbers, breaking
      // the compliance story. Fix: single INSERT … ON CONFLICT
      // ("sessionId","seq") DO NOTHING RETURNING seq, so the database
      // itself reports which seqs are OURS. Rollup deltas are computed
      // only over the actually-inserted subset; concurrent duplicates
      // count once.
      //
      // Why raw SQL and not a per-row create() loop catching P2002:
      // PostgreSQL aborts the ENTIRE transaction after any statement
      // error (25P02 "current transaction is aborted") — Prisma issues
      // no savepoints inside interactive transactions, so catching the
      // loser's P2002 and continuing made every subsequent statement
      // (the remaining inserts + the guarded rollup) fail, 500ing the
      // whole batch exactly in the benign concurrent-retry case this
      // path exists to absorb. ON CONFLICT DO NOTHING never raises, so
      // the tx stays healthy. Ids are minted client-side because the
      // schema's cuid() default is Prisma-client-side, not a DB
      // default.
      // R93 F2 + R94 F1: the insert AND the rollup update share ONE
      // transaction so a mid-batch failure (P1001 connection lost,
      // P2024 pool timeout, statement timeout, DB restart) rolls back
      // every row that already succeeded. A partial commit would make
      // the daemon's next retry pull the committed rows into
      // `existingSeqs`, skip their deltas as "already applied", and
      // PERMANENTLY under-count promptTokens/costUsdMicros/
      // toolsBlocked — the sealed receipt then signs the undercount,
      // breaking the compliance story from the OTHER direction. With
      // the tx wrapper, either every fresh row + the rollup increment
      // commit together, or nothing does.
      const insertedSeqs = new Set<number>();
      let dPrompt = 0;
      let dCompletion = 0;
      let dCost = 0;
      let dPayout = 0;
      let dBlockedPayout = 0;
      let dToolsOk = 0;
      let dToolsBad = 0;
      // R152 F1: guard the rollup update on the sealed status
      // via a DB-side WHERE clause, mirroring the R151 F1 shape
      // used on POST /ingest/sessions. Prior shape checked
      // `session.status === "sealed"` at :531 OUTSIDE any
      // transaction, then created event rows + incremented
      // rollup inside a tx that only pinned `{id: session.id}`
      // — no `status` predicate. If /ingest/receipts committed
      // `session.update({ status:"sealed" })` (via its own tx at
      // :~1025) between our findUnique (:516) and the rollup
      // update, event.create rows AND the increment landed on
      // the now-sealed row: signed `receipt.eventCount` /
      // `receipt.body` totals then mismatched
      // `session.events` / session totals, breaking the
      // compliance story from the OTHER direction R144 F1 /
      // R151 F1 closed for POST /ingest/sessions. Same
      // threat model (leaked AV_INGEST_TOKEN or benign daemon
      // racing its own seal). Fix: convert the rollup to
      // updateMany with `status: { not: "sealed" }`, throw
      // inside the tx when the guard fails so the whole batch
      // (event.creates + rollup) rolls back atomically, and
      // account the batch as `rejectedSealed` outside.
      let sealedMidTx = false;
      try {
        await db.$transaction(async (tx) => {
          const returned = await tx.$queryRaw<{ seq: number }[]>`
            INSERT INTO "events"
              ("id", "sessionId", "seq", "kind", "tag", "body", "sub", "policyName", "occurredAt", "journalCount")
            VALUES ${Prisma.join(
              rows.map(
                (row) =>
                  Prisma.sql`(${randomUUID()}, ${row.sessionId}, ${row.seq}, ${row.kind}, ${row.tag}, ${row.body}, ${row.sub ?? null}, ${row.policyName ?? null}, ${row.occurredAt}, ${row.journalCount})`,
              ),
            )}
            ON CONFLICT ("sessionId", "seq") DO NOTHING
            RETURNING "seq"`;
          for (const row of returned) {
            insertedSeqs.add(row.seq);
          }
          for (const e of fresh) {
            if (!insertedSeqs.has(e.seq)) continue;
            dPrompt += e.addPromptTokens;
            dCompletion += e.addCompletionTokens;
            dCost += e.addCostUsdMicros;
            dPayout += e.addPayoutUsdMicros;
            dBlockedPayout += e.addBlockedPayoutUsdMicros;
            dToolsOk += e.addToolsAllowed;
            dToolsBad += e.addToolsBlocked;
          }
          if (insertedSeqs.size > 0) {
            // Always call the guarded updateMany when we've
            // inserted event rows — even when the rollup deltas
            // are all zero (a pure-log batch). Increment-by-zero
            // is still a valid UPDATE, so Postgres evaluates the
            // `status: { not: "sealed" }` WHERE under the row
            // lock; if the row is sealed we get upd.count===0
            // and throw to abort the tx (event.create rows roll
            // back too).
            const upd = await tx.session.updateMany({
              where: { id: session.id, status: { not: "sealed" } },
              data: {
                promptTokens: { increment: dPrompt },
                completionTokens: { increment: dCompletion },
                costUsdMicros: { increment: BigInt(dCost) },
                payoutUsdMicros: { increment: BigInt(dPayout) },
                blockedPayoutUsdMicros: { increment: BigInt(dBlockedPayout) },
                toolsAllowed: { increment: dToolsOk },
                toolsBlocked: { increment: dToolsBad },
              },
            });
            if (upd.count === 0) {
              // Session was sealed by a concurrent
              // /ingest/receipts between our pre-tx status
              // check at :531 and this update. Abort the tx
              // so every event.create above rolls back.
              throw new Error("__session_sealed_mid_tx__");
            }
          }
        }, {
          // R95 F1: Prisma's default $transaction timeout is 5 s.
          // The route's zod cap is .max(500), and each event.create
          // is a serial round trip inside the tx. On hosted Postgres
          // (Neon, Supabase, RDS) with 10-20 ms RTT the tx spans
          // 5-10 s for a full 500-row single-session batch and
          // consistently throws P2028 'Transaction already closed'.
          // The route re-raises → 500 → daemon retries the same
          // batch → hits the same timeout → session livelocked
          // FOREVER. Exchanging the R93 F2 double-count for hard
          // stuck is worse. Bump the tx timeout to 30 s (covers
          // 500 rows × 60 ms RTT × 2 safety) and maxWait to 10 s
          // (default 2 s risks queue-storm 429s under contention).
          timeout: 30_000,
          maxWait: 10_000,
        });
      } catch (err) {
        if (
          typeof err === "object" &&
          err !== null &&
          (err as { message?: string }).message === "__session_sealed_mid_tx__"
        ) {
          // R152 F1: concurrent seal detected inside the tx.
          // Tx already rolled back; treat the batch the same
          // way as the pre-tx sealed check at :449 — surface
          // via rejectedSealed and skip the rest of the loop
          // body (inserted counter, bus.publish, policy.block
          // dispatch — none of those effects landed).
          sealedMidTx = true;
        } else if (
          err instanceof Error &&
          (err.message.includes("22003") ||
            err.message.includes("out of range for type integer"))
        ) {
          // Postgres numeric_value_out_of_range: a cumulative int4
          // counter (promptTokens/completionTokens/toolsAllowed/
          // toolsBlocked) crossed 2^31-1. Only reachable by a
          // hostile/runaway daemon spamming per-event maxima
          // (~2.1B tokens on ONE session); a 500 here made the
          // daemon retry the identical batch forever — permanent
          // livelock + log spam. 422 is terminal: the daemon drops
          // the batch and the operator sees the audit line.
          req.log.warn(
            { sessionExternalId: externalId, deploymentId: daemon.deploymentId },
            "ingest_counter_overflow_batch_refused",
          );
          writeAudit(
            {
              orgId: daemon.orgId,
              event: "deployment.ingest_counter_overflow",
              actorId: `daemon:${daemon.deploymentId}`,
              actorEmail: `daemon@${daemon.deploymentId}`,
              target: externalId,
              metadata: { deploymentId: daemon.deploymentId, sessionExternalId: externalId },
              req,
            },
            req.log,
          );
          return reply.code(422).send({ error: "counter_overflow" });
        } else {
          throw err;
        }
      }
      if (sealedMidTx) {
        rejectedSealed.push(externalId);
        continue;
      }
      inserted += insertedSeqs.size;

      if (insertedSeqs.size > 0 || dToolsOk || dToolsBad) {
        // R124 F3: cap dToolsBad / dBlockedPayout for the OUTBOUND
        // webhook fan-out. Prior shape forwarded the raw sums
        // verbatim, but they are integer accumulations of the
        // request-supplied addToolsBlocked / addBlockedPayoutUsdMicros
        // fields (line ~455) — NOT re-derived from the DB. On the
        // ingest-token-leak threat model that R119 F2 / R123 F2 close
        // for session.upsert, an attacker POSTing a batch with
        // inflated blocked counts fans out policy.block webhooks
        // to Slack / PagerDuty / Datadog with the poisoned numbers.
        // Downstream consumers key blockedCount for severity and
        // blockedPayoutUsdMicros for financial impact — a fake
        // "blocked $9,999,999" wakes on-call and burns SIEM ingest.
        // Sanity ceiling: you can't block more tools than events
        // in the batch (one event = one tool call attempt), so
        // clamp dToolsBad to insertedSeqs.size. blockedPayout is
        // similarly clamped by insertedSeqs.size × a per-event
        // payout ceiling; here we forward the smaller of the
        // supplied sum and (blocked-count × MAX_PER_EVENT_PAYOUT)
        // where MAX_PER_EVENT_PAYOUT is set high enough not to
        // clip legitimate traffic (1e9 micros = $1000 per tool
        // call, well above realistic single-call spend). SIEM
        // consumers now can't be waked by a fabricated $9M block.
        const clampedBlockedCount = Math.min(dToolsBad, insertedSeqs.size);
        const MAX_PER_EVENT_BLOCKED_PAYOUT = 1_000_000_000;
        const clampedBlockedPayout = Math.min(
          dBlockedPayout,
          clampedBlockedCount * MAX_PER_EVENT_BLOCKED_PAYOUT,
        );
        bus.publish({
          type: "events.appended",
          orgId: daemon.orgId,
          deploymentId: daemon.deploymentId,
          sessionId: session.id,
          count: insertedSeqs.size,
          allowed: dToolsOk,
          blocked: clampedBlockedCount,
        });
        // Any block in this batch triggers policy.block webhooks so
        // Slack / PagerDuty / Datadog can wake an on-call responder.
        if (clampedBlockedCount > 0) {
          dispatchEvent({
            orgId: daemon.orgId,
            event: "policy.block",
            data: {
              deploymentId: daemon.deploymentId,
              sessionId: session.id,
              sessionExternalId: externalId,
              blockedCount: clampedBlockedCount,
              blockedPayoutUsdMicros: clampedBlockedPayout,
            },
            logger: req.log,
          });
        }
      }
    }
    return reply.send({
      inserted,
      ...(rejectedSealed.length > 0 ? { rejectedSealed } : {}),
      ...(droppedSkewed > 0 ? { droppedFuture: droppedSkewed } : {}),
      ...(droppedAncient > 0 ? { droppedAncient } : {}),
    });
  });

  // Post a signed receipt at session seal.
  app.post("/receipts", async (req, reply) => {
    const daemon = await authenticateDaemon(req, reply);
    if (!daemon) return;
    const body = receiptPayload.safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: "invalid_input" });
    const r = body.data;
    // R195 F1: validate `keyIdHex` against the deployment's
    // registered pubkey. `derive_key_id(pubkey)` = first 32 hex
    // chars of SHA-256(pubkey_bytes) per Rust
    // crates/av-receipts/src/keys.rs:115-118. The daemon signs
    // receipts with the same keypair whose pubkey it posted via
    // /ingest/pubkey (R91 F3 blocks silent rotation). If the
    // daemon posts a receipt whose `keyIdHex` doesn't match the
    // stored pubkey's derived id, that's either a daemon bug
    // (wrong key material at signing time) or a compromised-
    // token holder posting under a fake identity — either way,
    // the resulting `keyIdHint` in the SPA session drawer (from
    // ingest.ts:955 `r.keyIdHex.slice(0, 8)`) would display an
    // attribution claim that doesn't match the pubkey the SPA
    // client-verifier uses. R193 catches the sibling gap on the
    // JS side (body.key_id must derive from pubkey), and this
    // closes the wire-level sibling. If deployment.publicKeyHex
    // isn't set yet (daemon hasn't posted /pubkey), we can't
    // validate — refuse with 409 to force the boot-order (post
    // /pubkey before /receipts).
    const dep = await db.deployment.findUnique({
      where: { id: daemon.deploymentId },
      select: { publicKeyHex: true },
    });
    if (!dep?.publicKeyHex) {
      req.log.warn(
        {
          deploymentId: daemon.deploymentId,
          sessionExternalId: r.sessionExternalId,
        },
        "ingest_receipt_refused_pubkey_not_set",
      );
      return reply.code(409).send({ error: "pubkey_not_registered" });
    }
    const derivedKeyId = createHash("sha256")
      .update(Buffer.from(dep.publicKeyHex, "hex"))
      .digest("hex")
      .slice(0, 32);
    if (r.keyIdHex.toLowerCase().slice(0, 32) !== derivedKeyId) {
      req.log.warn(
        {
          deploymentId: daemon.deploymentId,
          proposedKeyIdHex: r.keyIdHex,
          derivedKeyId,
        },
        "ingest_receipt_key_id_mismatch",
      );
      writeAudit(
        {
          orgId: daemon.orgId,
          event: "deployment.receipt_key_id_mismatch",
          actorId: `daemon:${daemon.deploymentId}`,
          actorEmail: `daemon@${daemon.deploymentId}`,
          target: r.sessionExternalId,
          metadata: {
            deploymentId: daemon.deploymentId,
            sessionExternalId: r.sessionExternalId,
            proposedKeyIdHex: r.keyIdHex,
            derivedKeyId,
          },
          req,
        },
        req.log,
      );
      return reply.code(400).send({ error: "key_id_mismatch" });
    }
    // Verify the Ed25519 signature against the deployment's pinned
    // pubkey BEFORE any DB write. The key-id check above only proves
    // the daemon CLAIMED the right key; without verifying sigB64 over
    // body, a leaked-ingest-token holder could seal the session with
    // garbage bytes and first-write-wins would then refuse the
    // legitimate receipt forever (see the R93 F4 comment below for
    // why sealed receipts are immutable). Same framing as the JS
    // verifier and `avctl receipt-verify`.
    if (!verifyReceiptSignature(dep.publicKeyHex, r.sigB64, r.body)) {
      req.log.warn(
        {
          deploymentId: daemon.deploymentId,
          sessionExternalId: r.sessionExternalId,
          receiptId: r.receiptId,
        },
        "ingest_receipt_signature_invalid",
      );
      writeAudit(
        {
          orgId: daemon.orgId,
          event: "deployment.receipt_signature_invalid",
          actorId: `daemon:${daemon.deploymentId}`,
          actorEmail: `daemon@${daemon.deploymentId}`,
          target: r.sessionExternalId,
          metadata: {
            deploymentId: daemon.deploymentId,
            sessionExternalId: r.sessionExternalId,
            receiptId: r.receiptId,
          },
          req,
        },
        req.log,
      );
      return reply.code(400).send({ error: "signature_invalid" });
    }
    // Bind the SIGNED body's identity claims to the top-level fields
    // that become queryable columns. The signature only proves the
    // bytes are an authentic receipt — not that they belong to THIS
    // row: a token holder could file session A's validly-signed
    // receipt under sessionExternalId=B with arbitrary receiptId/
    // eventCount, and the console would render 'verified' evidence
    // whose body contradicts the row it hangs on. Enforced for fields
    // PRESENT in the body: every real receipt (receipt-v2 schema)
    // carries receipt_id + session_id, so a genuine receipt can never
    // be re-homed; bodies without them (nothing to bind) still seal —
    // an attacker who can sign fieldless blobs holds the daemon key
    // and needs no re-homing trick.
    let signedBody: {
      receipt_id?: unknown;
      session_id?: unknown;
      subject?: { kind?: unknown; event_count?: unknown };
      issued_at?: unknown;
      stop_reason_id?: unknown;
      stop_reason?: unknown;
    };
    try {
      signedBody = JSON.parse(r.body) as typeof signedBody;
    } catch {
      return reply.code(400).send({ error: "receipt_body_not_json" });
    }
    const bodyEventCount =
      signedBody.subject && signedBody.subject.kind === "event_chain"
        ? signedBody.subject.event_count
        : undefined;
    if (
      (signedBody.receipt_id !== undefined && signedBody.receipt_id !== r.receiptId) ||
      (signedBody.session_id !== undefined && signedBody.session_id !== r.sessionExternalId) ||
      (bodyEventCount !== undefined && bodyEventCount !== r.eventCount)
    ) {
      req.log.warn(
        {
          deploymentId: daemon.deploymentId,
          sessionExternalId: r.sessionExternalId,
          receiptId: r.receiptId,
          bodyReceiptId: signedBody.receipt_id,
          bodySessionId: signedBody.session_id,
          bodyEventCount,
        },
        "ingest_receipt_body_binding_mismatch",
      );
      writeAudit(
        {
          orgId: daemon.orgId,
          event: "deployment.receipt_body_binding_mismatch",
          actorId: `daemon:${daemon.deploymentId}`,
          actorEmail: `daemon@${daemon.deploymentId}`,
          target: r.sessionExternalId,
          metadata: {
            deploymentId: daemon.deploymentId,
            sessionExternalId: r.sessionExternalId,
            receiptId: r.receiptId,
            bodySessionId: typeof signedBody.session_id === "string" ? signedBody.session_id : null,
            bodyReceiptId: typeof signedBody.receipt_id === "string" ? signedBody.receipt_id : null,
          },
          req,
        },
        req.log,
      );
      return reply.code(400).send({ error: "receipt_body_binding_mismatch" });
    }
    // Signed-body-first sealing metadata. issuedAt / stopReasonId /
    // stopReason become queryable columns and the console's rendered
    // truth for a sealed session, but they arrive in the UNSIGNED
    // envelope: a token holder could seal a legitimately-signed body
    // alongside a contradictory envelope (issuedAt in 2099, "Stop"
    // instead of the signed budget-exceeded caption). First-write-wins
    // then made the lie immutable AND 409'd the honest daemon's retry
    // (its envelope differs byte-for-byte from the attacker's). Every
    // real receipt body (receipt-v1/v2 schemas) carries issued_at
    // (epoch ms) / stop_reason_id / stop_reason as REQUIRED fields, so
    // when present the signed values ARE the row — the envelope copy
    // is reduced to a fallback for fieldless test blobs, which carry
    // nothing to contradict. Signed values of the wrong type or
    // outside the columns' vetted envelope ranges are refused outright
    // (a signature over garbage metadata is attacker-shaped, never a
    // production daemon).
    let sealIssuedAt = r.issuedAt;
    let sealStopReasonId = r.stopReasonId;
    let sealStopReason = r.stopReason;
    let sealMetadataViolation: string | null = null;
    if (signedBody.issued_at !== undefined) {
      const ms = signedBody.issued_at;
      if (typeof ms !== "number" || !Number.isSafeInteger(ms) || ms < 0) {
        sealMetadataViolation = "issued_at";
      } else {
        sealIssuedAt = new Date(ms);
        if (Number.isNaN(sealIssuedAt.getTime())) sealMetadataViolation = "issued_at";
      }
    }
    if (signedBody.stop_reason_id !== undefined) {
      const id = signedBody.stop_reason_id;
      if (typeof id !== "number" || !Number.isInteger(id) || id < 0 || id > 1_000_000) {
        sealMetadataViolation = "stop_reason_id";
      } else {
        sealStopReasonId = id;
      }
    }
    if (signedBody.stop_reason !== undefined) {
      if (typeof signedBody.stop_reason !== "string") {
        sealMetadataViolation = "stop_reason";
      } else {
        // Same 80-unit display bound the envelope schema enforces (the
        // daemon truncates its own envelope copy identically).
        sealStopReason = signedBody.stop_reason.slice(0, 80);
      }
    }
    if (sealMetadataViolation !== null) {
      req.log.warn(
        {
          deploymentId: daemon.deploymentId,
          sessionExternalId: r.sessionExternalId,
          receiptId: r.receiptId,
          field: sealMetadataViolation,
        },
        "ingest_receipt_signed_metadata_invalid",
      );
      writeAudit(
        {
          orgId: daemon.orgId,
          event: "deployment.receipt_body_binding_mismatch",
          actorId: `daemon:${daemon.deploymentId}`,
          actorEmail: `daemon@${daemon.deploymentId}`,
          target: r.sessionExternalId,
          metadata: {
            deploymentId: daemon.deploymentId,
            sessionExternalId: r.sessionExternalId,
            receiptId: r.receiptId,
            invalidSignedField: sealMetadataViolation,
          },
          req,
        },
        req.log,
      );
      return reply.code(400).send({ error: "receipt_body_binding_mismatch" });
    }
    const session = await db.session.findUnique({
      where: {
        deploymentId_externalId: {
          deploymentId: daemon.deploymentId,
          externalId: r.sessionExternalId,
        },
      },
      select: { id: true },
    });
    if (!session) return reply.code(404).send({ error: "unknown_session" });
    // R93 F4: first-write-wins on the receipt row. Prior shape ran
    // an unconditional upsert, so an ingest-token holder (or an
    // attacker with a leaked token — the same threat model R92 F2
    // named for `ingestTokenHint`) could POST /receipts a second
    // time for a session that already sealed and silently replace
    // the body / sigB64 / keyIdHint / eventCount / receiptId.
    // Because the session status was already 'sealed' and stayed
    // 'sealed', no other guard fired. Overwriting a sealed
    // receipt destroys the prior authentic row a customer/auditor
    // may already have referenced, and can replace it with a
    // body whose signature no longer verifies against the pinned
    // pubkey — a downgrade attack on the compliance story
    // (verifier now renders 'verify failed' against the same
    // sessionId the customer trusted).
    //
    // Legitimate daemon retry semantics: mid-flight seal retries
    // carry the SAME receiptId, so match by receiptId to preserve
    // idempotency. A different receiptId means an intentional
    // rewrite → refuse with 409 + audit so a compromised token
    // surfaces in the trail.
    // R93 F4 + R94 F2: same-receiptId path must be BYTE-EXACT
    // idempotent — a legitimate daemon retry sends the SAME body
    // + sigB64 + keyIdHex, so a value-equal re-post is a no-op.
    // Prior R93 shape guarded only on receiptId inequality; an
    // attacker who observed the legitimate receiptId (via CI log,
    // Dockerfile leak, or an insider's own prior sealing) could
    // then POST {receiptId: <same>, body: <forged>,
    // sigB64: attacker_sign(forged)} — the guard passed, upsert
    // rewrote all payload fields, verifier now returns 'signature
    // does not verify' against the pinned pubkey for a sessionId
    // the customer already accepted. Downgrade attack that R93 F4
    // was supposed to close. Now: on any existing receipt, fetch
    // ALL fields and reject with 409 if any of {receiptId, body,
    // sigB64, keyIdHint, eventCount, issuedAt} differ from the
    // stored row. Byte-exact re-post → 200 (idempotent no-op).
    const existingReceipt = await db.receipt.findUnique({
      where: { sessionId: session.id },
      select: {
        receiptId: true,
        body: true,
        sigB64: true,
        keyIdHint: true,
        eventCount: true,
        issuedAt: true,
      },
    });
    if (existingReceipt) {
      const proposedKeyIdHint = r.keyIdHex.slice(0, 8);
      const differs =
        existingReceipt.receiptId !== r.receiptId ||
        existingReceipt.body !== r.body ||
        existingReceipt.sigB64 !== r.sigB64 ||
        existingReceipt.keyIdHint !== proposedKeyIdHint ||
        existingReceipt.eventCount !== r.eventCount ||
        existingReceipt.issuedAt.getTime() !== sealIssuedAt.getTime();
      if (differs) {
        req.log.warn(
          {
            deploymentId: daemon.deploymentId,
            sessionId: session.id,
            existingReceiptId: existingReceipt.receiptId,
            proposedReceiptId: r.receiptId,
          },
          "ingest_receipt_overwrite_refused",
        );
        writeAudit(
          {
            orgId: daemon.orgId,
            event: "deployment.receipt_overwrite_refused",
            actorId: `daemon:${daemon.deploymentId}`,
            actorEmail: `daemon@${daemon.deploymentId}`,
            target: session.id,
            metadata: {
              deploymentId: daemon.deploymentId,
              sessionId: session.id,
              currentReceiptId: existingReceipt.receiptId,
              proposedReceiptId: r.receiptId,
              // Distinguish 'different-id' from 'same-id-different-payload'
              // in the trail so ops sees the exact bypass class.
              sameReceiptIdDifferentPayload:
                existingReceipt.receiptId === r.receiptId,
            },
            req,
          },
          req.log,
        );
        return reply.code(409).send({ error: "receipt_already_sealed" });
      }
      // R118 F2: byte-exact idempotent re-post. Return the
      // idempotent 200 WITHOUT touching session.stopReason /
      // stopReasonId — those aren't part of the byte-equality
      // check above (which only compares receiptId, body,
      // sigB64, keyIdHint, eventCount, issuedAt per R93 F4), so
      // an ingest-token holder could otherwise re-POST the
      // byte-identical receipt payload with a mutated top-level
      // stopReason to flip an already-sealed session's stop
      // reason indefinitely (e.g., relabel a legitimate
      // 'normal' completion as 'policy_block'). The signed
      // receipt.body is unchanged so the crypto verifier still
      // passes, but session.stopReason is what the SPA session
      // drawer + /me/export display — post-seal audit-trail
      // defacement, same class as R93 F4 at a sibling scope.
      // First-write-wins matches the receipt-row posture.
      bus.publish({
        type: "receipt.finalized",
        orgId: daemon.orgId,
        deploymentId: daemon.deploymentId,
        sessionId: session.id,
        receiptId: r.receiptId,
      });
      return reply.send({ ok: true });
    } else {
      // R120 F1: receipt.create + session.update MUST be atomic.
      // Prior shape was two independent DB round trips with no
      // $transaction wrapping. If the process died between them
      // (P1001 connection lost, P2024 pool timeout, statement
      // timeout, container SIGTERM during rolling deploy) or the
      // second call threw, the receipt row would commit but the
      // session would stay status="live" with stopReason=null.
      // On the daemon's next retry, the byte-exact check at
      // :~919 would match the committed receipt → return idempotent
      // 200 at :994 WITHOUT re-running session.update, leaving
      // the session permanently "live" with a fully-signed receipt.
      // Downstream: POST /ingest/events (:486 handler, sealed
      // guard :531) only rejects on status==="sealed" so a "live"
      // session accepts arbitrary post-seal events, drifting
      // session.promptTokens / costUsdMicros away from the
      // signed receipt.body's totals — compliance defect. Same
      // class as R94 F1 (events tx) and R93 F4 / R118 F2 /
      // R119 F2 (post-seal defacement).
      try {
        await db.$transaction(async (tx) => {
          await tx.receipt.create({
            data: {
              sessionId: session.id,
              receiptId: r.receiptId,
              body: r.body,
              sigB64: r.sigB64,
              keyIdHint: r.keyIdHex.slice(0, 8),
              eventCount: r.eventCount,
              issuedAt: sealIssuedAt,
            },
          });
          await tx.session.update({
            where: { id: session.id },
            data: {
              status: "sealed",
              stopReasonId: sealStopReasonId,
              stopReason: sealStopReason,
            },
          });
        });
      } catch (err) {
        if (
          typeof err !== "object" ||
          err === null ||
          (err as { code?: string }).code !== "P2002"
        ) {
          throw err;
        }
        // Concurrent seal of the same session: the existingReceipt
        // read above ran before either racer committed, so both took
        // this fresh-seal branch and the loser's receipt.create hit
        // the sessionId unique index. An at-least-once daemon retry
        // in flight beside the original is the benign shape; treat
        // it exactly like the sequential re-post path — byte-exact
        // ⇒ idempotent 200, anything else ⇒ the 409 refusal — never
        // an unhandled P2002 → 500 (the winner already sealed the
        // session correctly; the loser's tx rolled back cleanly).
        const raced = await db.receipt.findUnique({
          where: { sessionId: session.id },
          select: {
            receiptId: true,
            body: true,
            sigB64: true,
            keyIdHint: true,
            eventCount: true,
            issuedAt: true,
          },
        });
        if (!raced) throw err;
        const identical =
          raced.receiptId === r.receiptId &&
          raced.body === r.body &&
          raced.sigB64 === r.sigB64 &&
          raced.keyIdHint === r.keyIdHex.slice(0, 8) &&
          raced.eventCount === r.eventCount &&
          raced.issuedAt.getTime() === sealIssuedAt.getTime();
        if (!identical) {
          req.log.warn(
            {
              deploymentId: daemon.deploymentId,
              sessionId: session.id,
              existingReceiptId: raced.receiptId,
              proposedReceiptId: r.receiptId,
            },
            "ingest_receipt_overwrite_refused",
          );
          writeAudit(
            {
              orgId: daemon.orgId,
              event: "deployment.receipt_overwrite_refused",
              actorId: `daemon:${daemon.deploymentId}`,
              actorEmail: `daemon@${daemon.deploymentId}`,
              target: session.id,
              metadata: {
                deploymentId: daemon.deploymentId,
                sessionId: session.id,
                currentReceiptId: raced.receiptId,
                proposedReceiptId: r.receiptId,
                sameReceiptIdDifferentPayload: raced.receiptId === r.receiptId,
                racedConcurrentSeal: true,
              },
              req,
            },
            req.log,
          );
          return reply.code(409).send({ error: "receipt_already_sealed" });
        }
      }
    }
    bus.publish({
      type: "receipt.finalized",
      orgId: daemon.orgId,
      deploymentId: daemon.deploymentId,
      sessionId: session.id,
      receiptId: r.receiptId,
    });
    return reply.send({ ok: true });
  });
}
