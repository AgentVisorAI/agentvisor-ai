/**
 * Data retention sweeper.
 *
 * Every N hours (default 6h), we scan every org and purge:
 *
 *   * Sessions older than org.sessionRetentionDays → cascades to
 *     events + receipts via FK ON DELETE CASCADE.
 *   * AuditEntry rows older than org.auditRetentionDays.
 *   * WebhookDelivery rows older than 30 days (fixed policy — these
 *     are pure observability data, no compliance requirement).
 *
 * A value of 0 means "retain forever". The default is 90 days for
 * operational data and 365 days for the audit log — matches what
 * SOC-2 / ISO 27001 auditors typically expect.
 *
 * All deletes happen in chunks of 1000 rows so a huge tenant doesn't
 * lock a table for minutes. The sweeper never blocks reads because
 * we walk each org sequentially with small batches.
 */
import type { FastifyBaseLogger } from "fastify";
import { db } from "../db.js";

const DEFAULT_INTERVAL_MS = 6 * 60 * 60 * 1000; // 6h
const CHUNK = 1000;
const WEBHOOK_DELIVERY_RETENTION_DAYS = 30;

let sweeperTimer: NodeJS.Timeout | null = null;

const RETENTION_INTERVAL_MS = Number(
  process.env.RETENTION_SWEEPER_INTERVAL_MS ?? DEFAULT_INTERVAL_MS,
);

export interface RetentionSweepResult {
  orgId: string;
  sessionsPurged: number;
  auditPurged: number;
  webhookDeliveriesPurged: number;
}

/**
 * Sweep a single org. Exported so tests / admin tools can call it
 * directly and get the counts back rather than fishing them out of
 * logs.
 */
export async function sweepRetentionForOrg(
  orgId: string,
  logger?: FastifyBaseLogger,
): Promise<RetentionSweepResult> {
  const org = await db.org.findUnique({
    where: { id: orgId },
    select: { sessionRetentionDays: true, auditRetentionDays: true },
  });
  if (!org) {
    return { orgId, sessionsPurged: 0, auditPurged: 0, webhookDeliveriesPurged: 0 };
  }

  const now = Date.now();
  let sessionsPurged = 0;
  let auditPurged = 0;

  if (org.sessionRetentionDays > 0) {
    const cutoff = new Date(now - org.sessionRetentionDays * 86_400_000);
    // Cascade via deployment -> session; we want ONLY sessions whose
    // deployments belong to this org, so filter through deployment.
    while (true) {
      const rows = await db.session.findMany({
        where: {
          openedAt: { lt: cutoff },
          orgId,
        },
        take: CHUNK,
        select: { id: true },
      });
      if (rows.length === 0) break;
      const result = await db.session.deleteMany({
        where: { id: { in: rows.map((r) => r.id) } },
      });
      sessionsPurged += result.count;
      if (rows.length < CHUNK) break;
    }
  }

  if (org.auditRetentionDays > 0) {
    const cutoff = new Date(now - org.auditRetentionDays * 86_400_000);
    // Delete in chunks so a huge audit log doesn't hold the table lock
    // for long. deleteMany doesn't take a `limit`, so we walk with
    // findMany + deleteMany.
    while (true) {
      const rows = await db.auditEntry.findMany({
        where: { orgId, at: { lt: cutoff } },
        take: CHUNK,
        select: { id: true },
      });
      if (rows.length === 0) break;
      const result = await db.auditEntry.deleteMany({
        where: { id: { in: rows.map((r) => r.id) } },
      });
      auditPurged += result.count;
      if (rows.length < CHUNK) break;
    }
  }

  // Webhook deliveries: fixed 30-day retention across the board.
  const webhookCutoff = new Date(now - WEBHOOK_DELIVERY_RETENTION_DAYS * 86_400_000);
  let webhookDeliveriesPurged = 0;
  while (true) {
    const rows = await db.webhookDelivery.findMany({
      where: {
        createdAt: { lt: webhookCutoff },
        endpoint: { orgId },
      },
      take: CHUNK,
      select: { id: true },
    });
    if (rows.length === 0) break;
    const result = await db.webhookDelivery.deleteMany({
      where: { id: { in: rows.map((r) => r.id) } },
    });
    webhookDeliveriesPurged += result.count;
    if (rows.length < CHUNK) break;
  }

  if (sessionsPurged || auditPurged || webhookDeliveriesPurged) {
    logger?.info(
      { orgId, sessionsPurged, auditPurged, webhookDeliveriesPurged },
      "retention_sweep",
    );
  }
  return { orgId, sessionsPurged, auditPurged, webhookDeliveriesPurged };
}

/**
 * Sweep every org sequentially. Sequential (not concurrent) so we
 * don't stampede the DB.
 */
export async function sweepRetentionAll(
  logger?: FastifyBaseLogger,
): Promise<RetentionSweepResult[]> {
  const orgs = await db.org.findMany({ select: { id: true } });
  const results: RetentionSweepResult[] = [];
  for (const o of orgs) {
    results.push(await sweepRetentionForOrg(o.id, logger));
  }
  return results;
}

/**
 * Start the periodic sweeper. Runs immediately on boot (with a small
 * random delay so a k8s rolling restart doesn't have every replica
 * sweeping simultaneously), then every RETENTION_INTERVAL_MS.
 */
export function startRetentionSweeper(logger?: FastifyBaseLogger): void {
  if (sweeperTimer) return;
  const jitter = Math.floor(Math.random() * 30_000);
  setTimeout(() => {
    void sweepRetentionAll(logger).catch((err) =>
      logger?.warn({ err }, "retention_sweep_initial_failed"),
    );
    sweeperTimer = setInterval(() => {
      void sweepRetentionAll(logger).catch((err) =>
        logger?.warn({ err }, "retention_sweep_failed"),
      );
    }, RETENTION_INTERVAL_MS);
  }, jitter);
}

export function stopRetentionSweeper(): void {
  if (sweeperTimer) {
    clearInterval(sweeperTimer);
    sweeperTimer = null;
  }
}
