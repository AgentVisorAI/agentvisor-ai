//! Redis-backed `StateStore` (brief §8 "Redis Cluster" layer).
//!
//! Check-and-spend runs as a server-side Lua script so it is atomic across
//! distributed clients — same contract as `InMemoryStore::try_spend`.
//! Contract tests live in `tests/redis_contract.rs`, gated on `AB_REDIS_URL`
//! (skipped loudly when unset — a skipped gate prints, never silently passes).

use crate::store::{StateError, StateStore};
use redis::Commands;

/// Atomic check-and-spend: spends `amount` only if `current + amount <= limit`.
const TRY_SPEND_LUA: &str = r"
local current = tonumber(redis.call('GET', KEYS[1]) or '0')
local amount = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
if current + amount <= limit then
  redis.call('INCRBY', KEYS[1], amount)
  return 1
else
  return 0
end
";

/// Redis-backed store. Cheap to clone via internal client pooling.
pub struct RedisStore {
    client: redis::Client,
}

impl RedisStore {
    /// Connect to `url` (e.g. `redis://127.0.0.1:6379`).
    pub fn connect(url: &str) -> Result<Self, StateError> {
        let client = redis::Client::open(url).map_err(|e| StateError::Backend(e.to_string()))?;
        Ok(Self { client })
    }

    fn conn(&self) -> Result<redis::Connection, StateError> {
        self.client.get_connection().map_err(|e| StateError::Backend(e.to_string()))
    }
}

impl StateStore for RedisStore {
    fn add(&self, key: &str, delta: u64) -> Result<u64, StateError> {
        let mut conn = self.conn()?;
        let v: i64 = conn
            .incr(key, i64::try_from(delta).map_err(|_| StateError::Overflow(key.to_owned()))?)
            .map_err(|e| StateError::Backend(e.to_string()))?;
        u64::try_from(v).map_err(|_| StateError::Overflow(key.to_owned()))
    }

    fn get(&self, key: &str) -> Result<u64, StateError> {
        let mut conn = self.conn()?;
        let v: Option<i64> = conn.get(key).map_err(|e| StateError::Backend(e.to_string()))?;
        Ok(v.and_then(|x| u64::try_from(x).ok()).unwrap_or(0))
    }

    fn try_spend(&self, key: &str, amount: u64, limit: u64) -> Result<bool, StateError> {
        let mut conn = self.conn()?;
        let granted: i64 = redis::Script::new(TRY_SPEND_LUA)
            .key(key)
            .arg(amount)
            .arg(limit)
            .invoke(&mut conn)
            .map_err(|e| StateError::Backend(e.to_string()))?;
        Ok(granted == 1)
    }

    fn remove(&self, key: &str) {
        if let Ok(mut conn) = self.conn() {
            let _: Result<(), _> = conn.del(key);
        }
    }
}
