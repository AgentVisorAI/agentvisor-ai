//! Redis-backed `StateStore` (brief §8 "Redis Cluster" layer).
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
        return i
    end
end
for i, key in ipairs(KEYS) do
    redis.call('INCRBY', key, ARGV[(i - 1) * 2 + 1])
    redis.call('EXPIRE', key, {BUDGET_COUNTER_TTL_SECS})
end
return 0
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

/// Redis-backed store. Connections are pooled internally (r2d2 for both
/// single-node and cluster; the redis crate implements
/// `r2d2::ManageConnection` for `ClusterClient` directly).
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
            // Round-45: previously one `ClusterConnection` behind a mutex —
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
) -> Result<Option<usize>, StateError> {
    // Same duplicate-key guard as `InMemoryStore::try_spend_many`: the Lua
    // script reads GET(key) once per iteration in the check phase, so two
    // spends on the same key each see the pre-commit value and pass their
    // independent limit checks, then the commit phase INCRBYs both.
    let mut seen = std::collections::HashSet::with_capacity(spends.len());
    for spend in spends {
        if !seen.insert(spend.key.as_str()) {
            return Err(StateError::Backend(format!(
                "try_spend_many received duplicate key {:?}",
                spend.key,
            )));
        }
    }
    for spend in spends {
        if spend.amount > av_core::error::JCS_SAFE_MAX || spend.limit > av_core::error::JCS_SAFE_MAX {
            return Err(StateError::Overflow(spend.key.clone()));
        }
    }
    let script = redis::Script::new(&TRY_SPEND_LUA);
    let mut invocation = script.prepare_invoke();
    for spend in spends {
        invocation.key(&spend.key).arg(spend.amount).arg(spend.limit);
    }
    let failed: i64 = invocation
        .invoke(conn)
        .map_err(|e| StateError::Backend(e.to_string()))?;
    if failed == 0 {
        Ok(None)
    } else {
        usize::try_from(failed - 1)
            .map(Some)
            .map_err(|_| StateError::Backend(format!("invalid Lua failure index {failed}")))
    }
}

impl StateStore for RedisStore {
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

    fn try_spend(&self, key: &str, amount: u64, limit: u64) -> Result<bool, StateError> {
        Ok(self
            .try_spend_many(&[Spend {
                key: key.to_owned(),
                amount,
                limit,
            }])?
            .is_none())
    }

    fn try_spend_many(&self, spends: &[Spend]) -> Result<Option<usize>, StateError> {
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
        match &self.backend {
            RedisBackend::Single(pool) => {
                if let Ok(mut connection) = pool.get() {
                    let _: Result<(), _> = connection.del(key);
                }
            }
            RedisBackend::Cluster(pool) => {
                if let Ok(mut connection) = pool.get() {
                    let _: Result<(), _> = connection.del(key);
                }
            }
        }
    }

    /// Round-33 F1: saturating refund via `DECRBY` + a MAX(0) clamp.
    /// Best-effort — errors are silently swallowed so a Redis blip on
    /// the compensation path can never turn a lost-race response into
    /// a 5xx.
    ///
    /// Round-34 F1: NEVER resurrect a key that was already `DEL`'d
    /// by a concurrent `remove_prefix`. The prior implementation
    /// called `DECRBY` on the raw key: Redis initialises a missing
    /// key to 0 first, so `DECRBY` returned `-amount` and the
    /// `MAX(0)` clamp branch did `SET key 0` (no `EX`), producing
    /// a permanent TTL-less key. Under the round-33 lost-claim-
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
        let clamp_script = format!(
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
        );
        match &self.backend {
            RedisBackend::Single(pool) => {
                if let Ok(mut connection) = pool.get() {
                    let _: Result<i64, _> = redis::Script::new(&clamp_script)
                        .key(key)
                        .arg(amount)
                        .invoke(&mut *connection);
                }
            }
            RedisBackend::Cluster(pool) => {
                if let Ok(mut connection) = pool.get() {
                    let _: Result<i64, _> = redis::Script::new(&clamp_script)
                        .key(key)
                        .arg(amount)
                        .invoke(&mut *connection);
                }
            }
        }
    }

    /// Whole-session counter cleanup. Round-46: previously left as the
    /// trait's default no-op on the assumption that the 24 h TTL made it
    /// pure hygiene — but `SessionRegistry::get_or_open` recycles a
    /// finalized session id into a fresh open session, which then spends
    /// against the SAME hash-tagged keys. Against `InMemoryStore` (dev,
    /// CI, and every budget test) the recycled incarnation starts from
    /// zero; against Redis it silently inherited up to 24 h of the prior
    /// incarnation's `tokens`/`total_calls`/`tool:*`/`payout` counters —
    /// the exact cross-backend divergence class rounds 20/21 aligned
    /// `add`/`try_spend_many` for.
    ///
    /// All of a session's keys share one cluster slot by construction
    /// (`ActionBudget::session_prefix` wraps the digest in a `{hash-tag}`),
    /// so a single script routed by the prefix reaches every key on both
    /// single-node and cluster backends. `KEYS` inside the script is
    /// bounded by the node's keyspace (session-scoped counters, a handful
    /// per live session under TTL) and runs once per session finalization.
    /// Best-effort like `remove`/`refund`: a Redis blip on the cleanup
    /// path must not fail the close.
    fn remove_prefix(&self, prefix: &str) {
        // `KEYS`' glob treats `* ? [ ] \` as metacharacters. The prefix is
        // `budget:{<32 hex>}:` today (no metacharacters), but escape
        // defensively so a future prefix shape cannot over-match.
        let mut pattern = String::with_capacity(prefix.len() + 1);
        for c in prefix.chars() {
            if matches!(c, '*' | '?' | '[' | ']' | '\\') {
                pattern.push('\\');
            }
            pattern.push(c);
        }
        pattern.push('*');
        const REMOVE_PREFIX_LUA: &str = r"
            local removed = 0
            for _, key in ipairs(redis.call('KEYS', ARGV[1])) do
                redis.call('DEL', key)
                removed = removed + 1
            end
            return removed
        ";
        match &self.backend {
            RedisBackend::Single(pool) => {
                if let Ok(mut connection) = pool.get() {
                    let _: Result<i64, _> = redis::Script::new(REMOVE_PREFIX_LUA)
                        .key(prefix)
                        .arg(&pattern)
                        .invoke(&mut *connection);
                }
            }
            RedisBackend::Cluster(pool) => {
                if let Ok(mut connection) = pool.get() {
                    let _: Result<i64, _> = redis::Script::new(REMOVE_PREFIX_LUA)
                        .key(prefix)
                        .arg(&pattern)
                        .invoke(&mut *connection);
                }
            }
        }
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
    #[test]
    fn every_counter_script_applies_the_shared_ttl() {
        let ttl = BUDGET_COUNTER_TTL_SECS.to_string();
        for (name, script) in [
            ("TRY_SPEND_LUA", TRY_SPEND_LUA.as_str()),
            ("ADD_LUA", ADD_LUA.as_str()),
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
