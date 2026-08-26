//! Redis-backed `StateStore` — the distributed budget/state layer for
//! multi-replica deployments.
//!
//! Check-and-spend runs as a server-side Lua script so it is atomic across
//! distributed clients — same contract as `InMemoryStore::try_spend`.
//! Contract tests live in `tests/redis_contract.rs`, gated on `AV_REDIS_URL`
//! (skipped loudly when unset — a skipped gate prints, never silently passes).

use crate::store::{Spend, StateError, StateStore};
use redis::Commands;

/// TTL (seconds) applied to every counter key this store touches (the
/// spend/add INCRBY paths and the refund clamp). 24 h: counters are
/// session-scoped and the TTL is the backstop that keeps abandoned
/// sessions from leaking Redis memory forever. NOTE the prod/dev
/// divergence this creates: `InMemoryStore` never expires, so a session
/// idle longer than this window has its budget counters silently reset
/// against Redis only. Callers must keep session lifetimes within this
/// window (or persist budgets elsewhere) — see the `StateStore` trait
/// docs on counter lifetime.
const BUDGET_COUNTER_TTL_SECS: u64 = 86_400;

/// Atomic check-and-spend using subtraction so `current + amount` never rounds.
static TRY_SPEND_LUA: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    format!(
        r"
for i, key in ipairs(KEYS) do
    local current = tonumber(redis.call('GET', key) or '0')
    local amount = tonumber(ARGV[(i - 1) * 2 + 1])
    local limit = tonumber(ARGV[(i - 1) * 2 + 2])
    if current > limit or amount > limit - current then
        -- Refresh TTL on every EXISTING key
        -- in this invocation before returning the refusal. Without
        -- this, a session that hit its cap and keeps retrying (every
        -- attempt refused, commit loop never reached) has its counter
        -- expire {BUDGET_COUNTER_TTL_SECS}s after the last SUCCESSFUL
        -- spend — the next attempt then sees current=0 and the cap
        -- silently RESETS mid-session, doubling the budget. The TTL's
        -- purpose is reclaiming ABANDONED sessions; an actively
        -- retrying session is not abandoned.
        for j, k in ipairs(KEYS) do
            if redis.call('EXISTS', k) == 1 then
                redis.call('EXPIRE', k, {BUDGET_COUNTER_TTL_SECS})
            end
        end
        -- Refusal shape: {{-1, refusal_index_1_based}}.
        -- The leading -1 discriminates from the commit shape
        -- ({{post_commit_min_remaining, 0}}). See TrySpendOutcome
        -- in store.rs for rationale.
        return {{-1, i}}
    end
end
-- R66 F3: compute post-commit min-headroom inside the SAME atomic
-- EVAL that commits the spends, so `BudgetDecision::Allowed
-- {{ remaining }}` cannot race with a concurrent
-- remove_prefix/spend/refund on the same keys. Every key shares
-- the caller's session hash tag, so the whole script runs on ONE
-- server-side slot.
local min_remaining = -1
for i, key in ipairs(KEYS) do
    local amount = tonumber(ARGV[(i - 1) * 2 + 1])
    local limit = tonumber(ARGV[(i - 1) * 2 + 2])
    local new = redis.call('INCRBY', key, amount)
    redis.call('EXPIRE', key, {BUDGET_COUNTER_TTL_SECS})
    local remaining = limit - new
    if remaining < 0 then
        remaining = 0
    end
    if min_remaining == -1 or remaining < min_remaining then
        min_remaining = remaining
    end
end
if min_remaining == -1 then
    -- Empty KEYS: sentinel meaning `u64::MAX` on the client side.
    min_remaining = -1
end
-- Commit shape: {{min_remaining, 0}}. See TRY_SPEND_LUA_REFUSED_SENTINEL
-- in redis_store.rs.
return {{min_remaining, 0}}
"
    )
});

static ADD_LUA: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    format!(
        r"
local current = tonumber(redis.call('GET', KEYS[1]) or '0')
local amount = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
if current > limit or amount > limit - current then
    -- Keep an actively-refused counter
    -- alive — see the twin comment in TRY_SPEND_LUA.
    if redis.call('EXISTS', KEYS[1]) == 1 then
        redis.call('EXPIRE', KEYS[1], {BUDGET_COUNTER_TTL_SECS})
    end
    return -1
end
local result = redis.call('INCRBY', KEYS[1], ARGV[1])
-- Match TRY_SPEND_LUA's TTL. Without this, any counter touched
-- only through `add()` (bookkeeping, telemetry, non-budget spending)
-- persists forever in Redis; over a long-running deployment that
-- silently leaks memory until Redis OOMs. The two APIs must be
-- interchangeable from the persistence perspective.
redis.call('EXPIRE', KEYS[1], {BUDGET_COUNTER_TTL_SECS})
return result
"
    )
});

/// Saturating single-key refund. `EXISTS`-gated to never resurrect
/// a `remove_prefix`-cleared cell; `SET key 0 EX {BUDGET_COUNTER_TTL_SECS}`
/// on underflow keeps the counter TTL-aligned; `EXPIRE` on the
/// non-underflow path matches the same discipline. Extracted to a
/// static (R69) so `every_counter_script_applies_the_shared_ttl`
/// enrolls it in the TTL-drift regression test (R67 review L3).
static REFUND_LUA: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    format!(
        r"
if redis.call('EXISTS', KEYS[1]) == 0 then
    return 0
end
local new = redis.call('DECRBY', KEYS[1], ARGV[1])
if new < 0 then
    redis.call('SET', KEYS[1], 0, 'EX', {BUDGET_COUNTER_TTL_SECS})
    return 0
end
redis.call('EXPIRE', KEYS[1], {BUDGET_COUNTER_TTL_SECS})
return new
"
    )
});

/// Atomic multi-key refund. Per-key semantics match `REFUND_LUA`
/// exactly (EXISTS gate + DECRBY + clamp-at-zero via SET with
/// fresh TTL / EXPIRE refresh on non-underflow). Extracted to a
/// static (R69) so the same TTL-drift test enrolls it.
static REFUND_MANY_LUA: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    format!(
        r"
for i, key in ipairs(KEYS) do
    if redis.call('EXISTS', key) == 1 then
        local amount = tonumber(ARGV[i])
        local new = redis.call('DECRBY', key, amount)
        if new < 0 then
            redis.call('SET', key, 0, 'EX', {BUDGET_COUNTER_TTL_SECS})
        else
            redis.call('EXPIRE', key, {BUDGET_COUNTER_TTL_SECS})
        end
    end
end
return 0
"
    )
});

/// Redis-backed store. Connections are pooled internally (r2d2 for both
/// single-node and cluster; the redis crate implements
/// `r2d2::ManageConnection` for `ClusterClient` directly).
///
/// **EVAL uncertainty on network drop.** `try_spend_many` / `add` invoke
/// atomic Lua scripts server-side; if the connection breaks between the
/// server's INCRBY commit and the client's response read, the caller
/// sees `StateError::Backend` and cannot distinguish "commit succeeded,
/// response lost" from "commit never ran". Sandbox path treats
/// backend-error as blocked (fails closed for the request) — but a
/// subsequent client retry that lands with the same intent then hits a
/// pre-debited counter and cumulates the two spends into one intended
/// tool call, overcharging the budget by the retry's amount. The
/// 24 h counter TTL bounds unbounded growth, and refund-on-loss-race
/// (`refund_tool_call`) recovers the common cases, but the strictly
/// idempotent shape would require a client-supplied request nonce
/// stored briefly in Redis — deferred as a design change.
pub struct RedisStore {
    backend: RedisBackend,
}

enum RedisBackend {
    Single(r2d2::Pool<RedisConnectionManager>),
    Cluster(r2d2::Pool<redis::cluster::ClusterClient>),
}

struct RedisConnectionManager {
    client: redis::Client,
    timeout: std::time::Duration,
}

impl r2d2::ManageConnection for RedisConnectionManager {
    type Connection = redis::Connection;
    type Error = redis::RedisError;

    fn connect(&self) -> Result<Self::Connection, Self::Error> {
        let connection = self.client.get_connection_with_timeout(self.timeout)?;
        connection.set_read_timeout(Some(self.timeout))?;
        connection.set_write_timeout(Some(self.timeout))?;
        Ok(connection)
    }

    fn is_valid(&self, connection: &mut Self::Connection) -> Result<(), Self::Error> {
        redis::cmd("PING").query(connection)
    }

    fn has_broken(&self, _connection: &mut Self::Connection) -> bool {
        false
    }
}

impl RedisStore {
    /// Connect to `url` (e.g. `redis://127.0.0.1:6379`).
    /// Comma-separated URLs select Redis Cluster mode.
    pub fn connect(url: &str) -> Result<Self, StateError> {
        let nodes: Vec<String> = url
            .split(',')
            .map(str::trim)
            .filter(|node| !node.is_empty())
            .map(str::to_owned)
            .collect();
        if nodes.len() > 1 {
            // Previously one `ClusterConnection` behind a mutex —
            // every quota/budget operation across all sessions serialized on
            // a single socket, which under 10k-connection load stalled
            // admission long enough to blow upstream timeouts (observed as
            // 502 "upstream timed out" in the 10k SLA gate). Pool cluster
            // connections exactly like the single-node path.
            let client = redis::cluster::ClusterClientBuilder::new(nodes)
                .connection_timeout(std::time::Duration::from_secs(2))
                .response_timeout(std::time::Duration::from_secs(2))
                .build()
                .map_err(|e| StateError::Backend(e.to_string()))?;
            let pool = r2d2::Pool::builder()
                .max_size(32)
                .connection_timeout(std::time::Duration::from_secs(2))
                .build(client)
                .map_err(|e| StateError::Backend(e.to_string()))?;
            return Ok(Self {
                backend: RedisBackend::Cluster(pool),
            });
        }
        let client = redis::Client::open(url).map_err(|e| StateError::Backend(e.to_string()))?;
        let manager = RedisConnectionManager {
            client,
            timeout: std::time::Duration::from_secs(2),
        };
        let pool = r2d2::Pool::builder()
            .max_size(32)
            .connection_timeout(std::time::Duration::from_secs(2))
            .build(manager)
            .map_err(|e| StateError::Backend(e.to_string()))?;
        Ok(Self {
            backend: RedisBackend::Single(pool),
        })
    }
}

fn add_on<C: redis::ConnectionLike>(conn: &mut C, key: &str, delta: u64) -> Result<u64, StateError> {
    if delta > av_core::error::JCS_SAFE_MAX {
        return Err(StateError::Overflow(key.to_owned()));
    }
    let value: i64 = redis::Script::new(&ADD_LUA)
        .key(key)
        .arg(delta)
        .arg(av_core::error::JCS_SAFE_MAX)
        .invoke(conn)
        .map_err(|e| StateError::Backend(e.to_string()))?;
    if value < 0 {
        return Err(StateError::Overflow(key.to_owned()));
    }
    u64::try_from(value).map_err(|_| StateError::Overflow(key.to_owned()))
}

fn get_on<C: redis::ConnectionLike>(conn: &mut C, key: &str) -> Result<u64, StateError> {
    let value: Option<i64> = conn.get(key).map_err(|e| StateError::Backend(e.to_string()))?;
    let value = match value {
        None => 0,
        Some(v) if v < 0 => return Err(StateError::Overflow(key.to_owned())),
        Some(v) => u64::try_from(v).map_err(|_| StateError::Overflow(key.to_owned()))?,
    };
    if value > av_core::error::JCS_SAFE_MAX {
        return Err(StateError::Overflow(key.to_owned()));
    }
    Ok(value)
}

fn spend_many_on<C: redis::ConnectionLike>(
    conn: &mut C,
    spends: &[Spend],
) -> Result<crate::TrySpendOutcome, StateError> {
    // Shared duplicate-key guard: the Lua script reads
    // GET(key) once per iteration in the check phase, so two spends on
    // the same key each see the pre-commit value — same hazard as the
    // in-memory backend, one implementation.
    crate::store::refuse_duplicate_spend_keys(spends)?;
    for spend in spends {
        if spend.amount > av_core::error::JCS_SAFE_MAX || spend.limit > av_core::error::JCS_SAFE_MAX {
            return Err(StateError::Overflow(spend.key.clone()));
        }
    }
    if spends.is_empty() {
        // Match the sentinel InMemoryStore returns for the empty-
        // slice case. No EVAL round-trip; nothing to spend.
        return Ok(crate::TrySpendOutcome::Committed {
            post_commit_min_remaining: u64::MAX,
        });
    }
    let script = redis::Script::new(&TRY_SPEND_LUA);
    let mut invocation = script.prepare_invoke();
    for spend in spends {
        invocation.key(&spend.key).arg(spend.amount).arg(spend.limit);
    }
    // Return shape: [i64, i64]. Two disjoint carriers:
    //   Commit:  [post_commit_min_remaining, 0]  (min_remaining
    //            may be -1 to sentinel u64::MAX for empty KEYS;
    //            spends.is_empty() short-circuits above so we
    //            should not see -1 here).
    //   Refusal: [-1, refusal_index_1_based]
    let outcome: (i64, i64) = invocation
        .invoke(conn)
        .map_err(|e| StateError::Backend(e.to_string()))?;
    match outcome {
        (-1, refused) => {
            let refused = usize::try_from(refused - 1)
                .map_err(|_| StateError::Backend(format!("invalid Lua failure index {refused}")))?;
            Ok(crate::TrySpendOutcome::Refused { index: refused })
        }
        (min_remaining, 0) => {
            // -1 is the empty-KEYS sentinel (see the Lua); in practice
            // unreachable here (guarded above) but honour it.
            let remaining = if min_remaining < 0 {
                u64::MAX
            } else {
                u64::try_from(min_remaining).unwrap_or(0)
            };
            Ok(crate::TrySpendOutcome::Committed {
                post_commit_min_remaining: remaining,
            })
        }
        (a, b) => Err(StateError::Backend(format!(
            "TRY_SPEND_LUA returned unrecognised shape [{a}, {b}]"
        ))),
    }
}

impl StateStore for RedisStore {
    fn counter_ttl_secs(&self) -> Option<u64> {
        Some(BUDGET_COUNTER_TTL_SECS)
    }

    fn add(&self, key: &str, delta: u64) -> Result<u64, StateError> {
        match &self.backend {
            RedisBackend::Single(pool) => add_on(
                &mut pool.get().map_err(|e| StateError::Backend(e.to_string()))?,
                key,
                delta,
            ),
            RedisBackend::Cluster(pool) => add_on(
                &mut *pool.get().map_err(|e| StateError::Backend(e.to_string()))?,
                key,
                delta,
            ),
        }
    }

    fn get(&self, key: &str) -> Result<u64, StateError> {
        match &self.backend {
            RedisBackend::Single(pool) => get_on(
                &mut pool.get().map_err(|e| StateError::Backend(e.to_string()))?,
                key,
            ),
            RedisBackend::Cluster(pool) => get_on(
                &mut *pool.get().map_err(|e| StateError::Backend(e.to_string()))?,
                key,
            ),
        }
    }

    // `try_spend` uses the default trait impl (routes through
    // `try_spend_many` with a 1-element slice). Removed the standalone
    // wrapper in R68 — the default is exactly the same shape.

    fn try_spend_many(&self, spends: &[Spend]) -> Result<crate::TrySpendOutcome, StateError> {
        match &self.backend {
            RedisBackend::Single(pool) => spend_many_on(
                &mut pool.get().map_err(|e| StateError::Backend(e.to_string()))?,
                spends,
            ),
            RedisBackend::Cluster(pool) => spend_many_on(
                &mut *pool.get().map_err(|e| StateError::Backend(e.to_string()))?,
                spends,
            ),
        }
    }

    fn remove(&self, key: &str) {
        // Mirror the `refund` treatment
        // — best-effort by contract, but a completely-silent Redis
        // failure on the cleanup path leaves an operator with no
        // signal that a session's stale key wasn't removed. The next
        // recycled-session-id can then inherit the counter. Warn on
        // both pool-get and DEL failure with structured fields.
        let outcome: Result<(), redis::RedisError> = match &self.backend {
            RedisBackend::Single(pool) => match pool.get() {
                Ok(mut connection) => connection.del(key),
                Err(error) => Err(redis::RedisError::from((
                    redis::ErrorKind::IoError,
                    "connection pool exhausted",
                    error.to_string(),
                ))),
            },
            RedisBackend::Cluster(pool) => match pool.get() {
                Ok(mut connection) => connection.del(key),
                Err(error) => Err(redis::RedisError::from((
                    redis::ErrorKind::IoError,
                    "connection pool exhausted",
                    error.to_string(),
                ))),
            },
        };
        if let Err(error) = outcome {
            let error_kind = error.kind();
            tracing::warn!(
                target: "av_state::redis",
                kind = ?error_kind,
                detail = %error,
                "Redis remove failed silently; per-key cleanup was not applied — \
                 a subsequent session recycling this key may inherit its counter \
                 until the 24 h TTL expires"
            );
        }
    }

    /// Saturating refund via `DECRBY` + a MAX(0) clamp.
    /// Best-effort — errors are silently swallowed so a Redis blip on
    /// the compensation path can never turn a lost-race response into
    /// a 5xx.
    ///
    /// NEVER resurrect a key that was already `DEL`'d
    /// by a concurrent `remove_prefix`. The prior implementation
    /// called `DECRBY` on the raw key: Redis initialises a missing
    /// key to 0 first, so `DECRBY` returned `-amount` and the
    /// `MAX(0)` clamp branch did `SET key 0` (no `EX`), producing
    /// a permanent TTL-less key. Under the lost-claim-
    /// plus-idle-close ordering (mcp_call sandbox-gate debit
    /// races with the reconciler's clear_budget_state), the
    /// refund path leaked one-to-three TTL-less keys per session
    /// — attacker-choosable memory growth against the exact class
    /// the `clear_budget_state` doc in reconciler.rs documents as
    /// impossible. Fix: gate
    /// the whole DECRBY on `EXISTS`. If the session was cleared,
    /// the budget is already gone and there is nothing to
    /// compensate; the refund is a silent no-op. If the session
    /// is alive, we DECRBY-clamp AND refresh the counter TTL to
    /// match `TRY_SPEND_LUA` (a plain DECRBY does not refresh).
    fn refund(&self, key: &str, amount: u64) {
        // Redis DECRBY takes i64. Cap at i64::MAX so a caller passing
        // u64::MAX cannot silently wrap into a negative value.
        let amount = i64::try_from(amount).unwrap_or(i64::MAX);
        // Refund is best-effort by the trait contract, but
        // its silent-swallow used to be COMPLETELY invisible — no log,
        // no metric — so an operator seeing budget depletion during a
        // Redis outage had no signal that compensation had been
        // failing. Log the failed refund with structured fields so
        // downstream aggregators (Vector → OTLP → SIEM) can alert on
        // it. The response path still stays 200 OK so the caller
        // never learns a compensation failure as a 5xx.
        let outcome: Result<i64, redis::RedisError> = match &self.backend {
            RedisBackend::Single(pool) => match pool.get() {
                Ok(mut connection) => redis::Script::new(&REFUND_LUA)
                    .key(key)
                    .arg(amount)
                    .invoke(&mut *connection),
                Err(error) => Err(redis::RedisError::from((
                    redis::ErrorKind::IoError,
                    "connection pool exhausted",
                    error.to_string(),
                ))),
            },
            RedisBackend::Cluster(pool) => match pool.get() {
                Ok(mut connection) => redis::Script::new(&REFUND_LUA)
                    .key(key)
                    .arg(amount)
                    .invoke(&mut *connection),
                Err(error) => Err(redis::RedisError::from((
                    redis::ErrorKind::IoError,
                    "connection pool exhausted",
                    error.to_string(),
                ))),
            },
        };
        if let Err(error) = outcome {
            let error_kind = error.kind();
            tracing::warn!(
                target: "av_state::redis",
                kind = ?error_kind,
                detail = %error,
                "Redis refund failed silently; per-key compensation was not applied — \
                 budget counter may remain over-charged until the 24 h TTL expires or a \
                 successful spend/refund lands"
            );
        }
    }

    /// R66 F2: atomic multi-key refund via a single Lua script.
    /// All keys share the caller's Redis Cluster hash tag (guaranteed
    /// by `ActionBudget::session_prefix` which wraps its digest in
    /// `{...}`), so cross-slot dispatch is impossible and the script
    /// runs on ONE server-side EVAL. Per-key semantics match
    /// `refund` exactly: EXISTS gate (never resurrect a
    /// remove_prefix-cleared cell), DECRBY, clamp-at-zero via SET
    /// with fresh TTL on underflow, EXPIRE refresh on non-underflow.
    /// Best-effort like `refund` — Redis errors log-warn but never
    /// propagate.
    fn refund_many(&self, refunds: &[crate::Refund]) {
        if refunds.is_empty() {
            return;
        }
        let outcome: Result<i64, redis::RedisError> = match &self.backend {
            RedisBackend::Single(pool) => match pool.get() {
                Ok(mut connection) => {
                    let script = redis::Script::new(&REFUND_MANY_LUA);
                    let mut invocation = script.prepare_invoke();
                    for r in refunds {
                        invocation.key(&r.key);
                        // Cap at i64::MAX so a caller passing u64::MAX
                        // cannot silently wrap into a negative value.
                        invocation.arg(i64::try_from(r.amount).unwrap_or(i64::MAX));
                    }
                    invocation.invoke(&mut *connection)
                }
                Err(error) => Err(redis::RedisError::from((
                    redis::ErrorKind::IoError,
                    "connection pool exhausted",
                    error.to_string(),
                ))),
            },
            RedisBackend::Cluster(pool) => match pool.get() {
                Ok(mut connection) => {
                    let script = redis::Script::new(&REFUND_MANY_LUA);
                    let mut invocation = script.prepare_invoke();
                    for r in refunds {
                        invocation.key(&r.key);
                        invocation.arg(i64::try_from(r.amount).unwrap_or(i64::MAX));
                    }
                    invocation.invoke(&mut *connection)
                }
                Err(error) => Err(redis::RedisError::from((
                    redis::ErrorKind::IoError,
                    "connection pool exhausted",
                    error.to_string(),
                ))),
            },
        };
        if let Err(error) = outcome {
            let error_kind = error.kind();
            tracing::warn!(
                target: "av_state::redis",
                kind = ?error_kind,
                detail = %error,
                refunds = refunds.len(),
                "Redis refund_many failed silently; per-key compensation was not applied — \
                 budget counters may remain over-charged until the 24 h TTL expires or a \
                 successful spend/refund lands"
            );
        }
    }

    /// Whole-session counter cleanup. Previously left as the
    /// trait's default no-op on the assumption that the 24 h TTL made it
    /// pure hygiene — but `SessionRegistry::get_or_open` recycles a
    /// finalized session id into a fresh open session, which then spends
    /// against the SAME hash-tagged keys. Against `InMemoryStore` (dev,
    /// CI, and every budget test) the recycled incarnation starts from
    /// zero; against Redis it silently inherited up to 24 h of the prior
    /// incarnation's `tokens`/`total_calls`/`tool:*`/`payout` counters —
    /// the exact cross-backend divergence class the
    /// `add`/`try_spend_many` alignment closed.
    ///
    /// All of a session's keys share one cluster slot by construction
    /// (`ActionBudget::session_prefix` wraps the digest in a `{hash-tag}`),
    /// so a SCAN cursor + bounded DEL batches — routed by the prefix
    /// pattern's hash-tag to the owning master in cluster mode — reach
    /// every key on both single-node and cluster backends.
    ///
    /// SCAN, not KEYS. The first take used
    /// `redis.call('KEYS', pattern)` inside a Lua script, which is
    /// O(entire keyspace per node) AND blocks the Redis event loop
    /// atomically for the whole scan+delete. On a shared Redis with high
    /// session churn or attacker-chosen ids, every close stalled all
    /// other Redis clients (including hot-path `try_spend_many` gates)
    /// for the duration. SCAN is O(matches) amortized and yields between
    /// batches, so per-session cleanup no longer blocks concurrent
    /// traffic.
    ///
    /// `route_command` with an explicit slot for cluster
    /// mode. An intermediate revision used
    /// `Commands::scan_match` on the cluster connection, but bare
    /// `SCAN` has no key argument — `RoutingInfo::for_routable` returns
    /// `None`, and `ClusterConnection::request` treats that as an
    /// immediate `UNROUTABLE_ERROR`. The iterator failed on
    /// construction, the `Err(_) => return` arm swallowed it, and
    /// cleanup silently did nothing on every cluster deployment.
    /// Best-effort like `remove`/`refund`: any Redis blip on the
    /// cleanup path must not fail the close.
    fn remove_prefix(&self, prefix: &str) {
        // `MATCH` glob treats `* ? [ ] \` as metacharacters. The prefix
        // is `budget:{<32 hex>}:` today (no metacharacters), but escape
        // defensively so a future prefix shape cannot over-match.
        let mut pattern = String::with_capacity(prefix.len() + 1);
        for c in prefix.chars() {
            if matches!(c, '*' | '?' | '[' | ']' | '\\') {
                pattern.push('\\');
            }
            pattern.push(c);
        }
        pattern.push('*');
        match &self.backend {
            RedisBackend::Single(pool) => {
                if let Ok(mut connection) = pool.get() {
                    scan_and_delete_single(&mut connection, &pattern);
                }
            }
            RedisBackend::Cluster(pool) => {
                if let Ok(mut connection) = pool.get() {
                    // Route by the ORIGINAL (unescaped) prefix so the
                    // hash-tag slot matches the one Redis derives from
                    // the on-cluster keys. If the future adds a prefix
                    // shape that contains any glob metachar, computing
                    // the slot from the ESCAPED pattern would embed
                    // `\` characters that never appear in the on-cluster
                    // keys — SCAN would route to a slot no key lives on
                    // and `remove_prefix` would silently no-op, letting
                    // budget counters survive up to the 24 h TTL. Today's
                    // prefix is metachar-free so escaping is a no-op and
                    // this bug is latent; the fix protects against the
                    // future shape change.
                    scan_and_delete_cluster(&mut connection, &pattern, prefix);
                }
            }
        }
    }
}

/// Bounded SCAN+DEL loop against a single-node connection. Each SCAN
/// call is O(COUNT) at the server; the loop terminates when the cursor
/// returns to 0. DEL is batched so one round-trip retires up to
/// `SCAN_COUNT` keys.
fn scan_and_delete_single(conn: &mut redis::Connection, pattern: &str) {
    const SCAN_COUNT: usize = 500;
    let mut cursor: u64 = 0;
    loop {
        let scan: Result<(u64, Vec<String>), _> = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(pattern)
            .arg("COUNT")
            .arg(SCAN_COUNT)
            .query(conn);
        let (next, batch) = match scan {
            Ok(pair) => pair,
            Err(error) => {
                // SCAN failing means we bail
                // out mid-cleanup — the remaining keys survive with
                // their TTLs, and a future session recycling this id
                // (within 24 h) would inherit the leftover counters
                // silently. Log with structured fields so an operator
                // aggregating warns can spot chronic backend outages.
                let error_kind = error.kind();
                tracing::warn!(
                    target: "av_state::redis",
                    kind = ?error_kind,
                    detail = %error,
                    "Redis SCAN failed during remove_prefix; partial cleanup — surviving \
                     keys will expire at the 24 h TTL or on the next successful \
                     remove_prefix for the same prefix"
                );
                return;
            }
        };
        if !batch.is_empty() {
            let mut del = redis::cmd("DEL");
            for key in &batch {
                del.arg(key);
            }
            let outcome: Result<i64, _> = del.query(conn);
            if let Err(error) = outcome {
                let error_kind = error.kind();
                tracing::warn!(
                    target: "av_state::redis",
                    kind = ?error_kind,
                    detail = %error,
                    batch_len = batch.len(),
                    "Redis DEL batch failed during remove_prefix; these keys survive \
                     until the 24 h TTL expires"
                );
            }
        }
        if next == 0 {
            return;
        }
        cursor = next;
    }
}

/// Cluster variant: bare `SCAN` has no key argument so
/// `redis::cluster_routing::RoutingInfo::for_routable` returns `None`
/// on it (the sync ClusterConnection then fails with
/// `UNROUTABLE_ERROR`, silently deleting nothing — the
/// regression this replaces). All matches share one hash-slot by
/// construction (`ActionBudget::session_prefix` wraps the digest in
/// `{hash-tag}`), so compute the slot from the prefix and route both
/// SCAN and DEL through `route_command` to that specific master.
///
/// `pattern` carries the ESCAPED glob (metachars prefixed with `\`)
/// for the SCAN MATCH argument. `route_prefix` carries the ORIGINAL
/// unescaped prefix used SOLELY for slot computation — the hash-tag
/// content Redis extracts from an on-cluster key is the RAW bytes,
/// so a slot computed from an escaped pattern would miss on any
/// prefix shape containing a glob metachar. Today's prefix is
/// metachar-free so escape is a no-op; the separation protects
/// against a future prefix shape change.
fn scan_and_delete_cluster(conn: &mut redis::cluster::ClusterConnection, pattern: &str, route_prefix: &str) {
    use redis::cluster_routing::{Route, RoutingInfo, SingleNodeRoutingInfo, SlotAddr};
    const SCAN_COUNT: usize = 500;
    let route_key = route_prefix.trim_end_matches('*');
    let slot = redis::cluster_routing::get_slot(route_key.as_bytes());
    let routing = RoutingInfo::SingleNode(SingleNodeRoutingInfo::SpecificNode(Route::new(
        slot,
        SlotAddr::Master,
    )));
    let mut cursor: u64 = 0;
    loop {
        let scan_cmd = {
            let mut cmd = redis::cmd("SCAN");
            cmd.arg(cursor)
                .arg("MATCH")
                .arg(pattern)
                .arg("COUNT")
                .arg(SCAN_COUNT);
            cmd
        };
        let value = match conn.route_command(&scan_cmd, routing.clone()) {
            Ok(value) => value,
            Err(error) => {
                // Parity with
                // `scan_and_delete_single`. Cluster-mode SCAN failure
                // was completely silent, so an operator watching
                // `av_state::redis::warn` for cleanup problems saw
                // nothing on cluster deployments even under Redis
                // slowdown.
                let error_kind = error.kind();
                tracing::warn!(
                    target: "av_state::redis",
                    kind = ?error_kind,
                    detail = %error,
                    slot,
                    "Redis cluster SCAN failed during remove_prefix; partial cleanup — \
                     surviving keys will expire at the 24 h TTL or on the next successful \
                     remove_prefix for the same prefix"
                );
                return;
            }
        };
        let parsed: Result<(u64, Vec<String>), _> = redis::FromRedisValue::from_redis_value(&value);
        let (next, batch) = match parsed {
            Ok(pair) => pair,
            Err(error) => {
                let error_kind = error.kind();
                tracing::warn!(
                    target: "av_state::redis",
                    kind = ?error_kind,
                    detail = %error,
                    "Redis cluster SCAN returned an unparsable response during remove_prefix; \
                     aborting further cleanup for this prefix"
                );
                return;
            }
        };
        if !batch.is_empty() {
            let mut del = redis::cmd("DEL");
            for key in &batch {
                del.arg(key);
            }
            // Multi-key DEL is safe here because every match shares the
            // slot we already computed above — route it explicitly so
            // the driver does not need to inspect the keys again.
            if let Err(error) = conn.route_command(&del, routing.clone()) {
                let error_kind = error.kind();
                tracing::warn!(
                    target: "av_state::redis",
                    kind = ?error_kind,
                    detail = %error,
                    slot,
                    batch_len = batch.len(),
                    "Redis cluster DEL batch failed during remove_prefix; these keys survive \
                     until the 24 h TTL expires"
                );
            }
        }
        if next == 0 {
            return;
        }
        cursor = next;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// Every Lua script that mutates a counter must apply the single
    /// shared TTL constant — a hardcoded-literal drift between the
    /// spend/add/refund paths would make some counters outlive others
    /// and silently split the session-expiry policy.
    ///
    /// R69: extended to enrol REFUND_LUA and REFUND_MANY_LUA. Both
    /// were inline `format!` strings pre-R69 (a per-call allocation);
    /// extraction to statics closed R67 review L3's coverage gap so
    /// a future edit that drops `EXPIRE` from either would be caught
    /// here.
    #[test]
    fn every_counter_script_applies_the_shared_ttl() {
        let ttl = BUDGET_COUNTER_TTL_SECS.to_string();
        for (name, script) in [
            ("TRY_SPEND_LUA", TRY_SPEND_LUA.as_str()),
            ("ADD_LUA", ADD_LUA.as_str()),
            ("REFUND_LUA", REFUND_LUA.as_str()),
            ("REFUND_MANY_LUA", REFUND_MANY_LUA.as_str()),
        ] {
            assert!(
                script.contains(&format!("EXPIRE', KEYS[1], {ttl}"))
                    || script.contains(&format!("EXPIRE', key, {ttl}")),
                "{name} must EXPIRE with BUDGET_COUNTER_TTL_SECS: {script}"
            );
            assert!(
                !script.contains('{'),
                "{name} has an unexpanded format placeholder"
            );
        }
    }
}
