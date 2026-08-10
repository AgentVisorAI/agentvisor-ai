//! Dependency-free metrics registry rendering Prometheus text exposition
//! format. Counters and histograms only (what the SLA criteria need), all
//! lock-free on the hot path (atomics; registration takes a short mutex).

use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// A monotonically increasing counter.
#[derive(Debug, Default)]
pub struct Counter {
    value: AtomicU64,
}

impl Counter {
    /// Increment by 1.
    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment by `n`.
    pub fn add(&self, n: u64) {
        self.value.fetch_add(n, Ordering::Relaxed);
    }

    /// Current value.
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

/// Fixed-bucket latency histogram (microsecond samples).
///
/// Buckets are cumulative on render, per Prometheus convention.
#[derive(Debug)]
pub struct Histogram {
    bounds_us: Vec<u64>,
    buckets: Vec<AtomicU64>,
    count: AtomicU64,
    sum_us: AtomicU64,
}

/// Default latency bucket upper bounds in microseconds: 50µs … 10s.
pub const DEFAULT_LATENCY_BOUNDS_US: &[u64] =
    &[50, 100, 250, 500, 1_000, 2_000, 5_000, 8_000, 10_000, 25_000, 50_000, 100_000, 1_000_000, 10_000_000];

impl Histogram {
    /// Create a histogram with the given bucket upper bounds (µs, ascending).
    pub fn new(bounds_us: &[u64]) -> Self {
        Self {
            bounds_us: bounds_us.to_vec(),
            buckets: bounds_us.iter().map(|_| AtomicU64::new(0)).collect(),
            count: AtomicU64::new(0),
            sum_us: AtomicU64::new(0),
        }
    }

    /// Record a sample in microseconds.
    pub fn observe_us(&self, us: u64) {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_us.fetch_add(us, Ordering::Relaxed);
        for (i, b) in self.bounds_us.iter().enumerate() {
            if us <= *b {
                if let Some(bucket) = self.buckets.get(i) {
                    bucket.fetch_add(1, Ordering::Relaxed);
                }
                break;
            }
        }
    }

    /// Total number of samples.
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    /// Approximate quantile (µs) from bucket boundaries. Returns the upper
    /// bound of the bucket containing quantile `q` (0.0–1.0), or the max bound
    /// if the sample landed above every bucket.
    pub fn quantile_us(&self, q: f64) -> u64 {
        let total = self.count();
        if total == 0 {
            return 0;
        }
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_precision_loss)]
        let target = ((total as f64) * q.clamp(0.0, 1.0)).ceil() as u64;
        let mut cum = 0u64;
        for (i, b) in self.bounds_us.iter().enumerate() {
            cum += self.buckets.get(i).map_or(0, |x| x.load(Ordering::Relaxed));
            if cum >= target {
                return *b;
            }
        }
        self.bounds_us.last().copied().unwrap_or(0)
    }
}

enum Metric {
    Counter(Arc<Counter>),
    Histogram(Arc<Histogram>),
}

/// A registry mapping metric names (+ optional fixed labels) to metrics.
#[derive(Default)]
pub struct Registry {
    metrics: Mutex<BTreeMap<String, (String, Metric)>>,
}

impl Registry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register (or fetch) a counter. `key` must be a valid Prometheus series
    /// name with optional `{label="v"}` suffix.
    pub fn counter(&self, key: &str, help: &str) -> Arc<Counter> {
        let mut m = self.metrics.lock();
        match m.get(key) {
            Some((_, Metric::Counter(c))) => Arc::clone(c),
            _ => {
                let c = Arc::new(Counter::default());
                m.insert(key.to_owned(), (help.to_owned(), Metric::Counter(Arc::clone(&c))));
                c
            }
        }
    }

    /// Register (or fetch) a histogram with default latency buckets.
    pub fn histogram(&self, key: &str, help: &str) -> Arc<Histogram> {
        let mut m = self.metrics.lock();
        match m.get(key) {
            Some((_, Metric::Histogram(h))) => Arc::clone(h),
            _ => {
                let h = Arc::new(Histogram::new(DEFAULT_LATENCY_BOUNDS_US));
                m.insert(key.to_owned(), (help.to_owned(), Metric::Histogram(Arc::clone(&h))));
                h
            }
        }
    }

    /// Render the registry in Prometheus text exposition format.
    pub fn render(&self) -> String {
        let m = self.metrics.lock();
        let mut out = String::new();
        for (key, (help, metric)) in m.iter() {
            let (base, labels) = split_key(key);
            match metric {
                Metric::Counter(c) => {
                    out.push_str(&format!("# HELP {base} {help}\n# TYPE {base} counter\n"));
                    out.push_str(&format!("{key} {}\n", c.get()));
                }
                Metric::Histogram(h) => {
                    out.push_str(&format!("# HELP {base} {help}\n# TYPE {base} histogram\n"));
                    let mut cum = 0u64;
                    for (i, b) in h.bounds_us.iter().enumerate() {
                        cum += h.buckets.get(i).map_or(0, |x| x.load(Ordering::Relaxed));
                        let le = (*b as f64) / 1_000_000.0;
                        out.push_str(&format!(
                            "{base}_bucket{{{}le=\"{le}\"}} {cum}\n",
                            join_labels(labels)
                        ));
                    }
                    out.push_str(&format!(
                        "{base}_bucket{{{}le=\"+Inf\"}} {}\n",
                        join_labels(labels),
                        h.count()
                    ));
                    let sum_s = (h.sum_us.load(Ordering::Relaxed) as f64) / 1_000_000.0;
                    out.push_str(&format!("{base}_sum{labels_block} {sum_s}\n", labels_block = labels_suffix(labels)));
                    out.push_str(&format!("{base}_count{labels_block} {}\n", h.count(), labels_block = labels_suffix(labels)));
                }
            }
        }
        out
    }
}

/// Split `name{l="v"}` into (`name`, `l="v"`); no labels → (`key`, ``).
fn split_key(key: &str) -> (&str, &str) {
    match key.find('{') {
        Some(i) => {
            let base = key.get(..i).unwrap_or(key);
            let labels = key.get(i + 1..key.len().saturating_sub(1)).unwrap_or("");
            (base, labels)
        }
        None => (key, ""),
    }
}

fn join_labels(labels: &str) -> String {
    if labels.is_empty() {
        String::new()
    } else {
        format!("{labels},")
    }
}

fn labels_suffix(labels: &str) -> String {
    if labels.is_empty() {
        String::new()
    } else {
        format!("{{{labels}}}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_roundtrip() {
        let r = Registry::new();
        let c = r.counter("ab_test_total", "test counter");
        c.inc();
        c.add(4);
        assert_eq!(c.get(), 5);
        let text = r.render();
        assert!(text.contains("# TYPE ab_test_total counter"), "{text}");
        assert!(text.contains("ab_test_total 5"), "{text}");
    }

    #[test]
    fn counter_with_labels_renders_base_name_in_type() {
        let r = Registry::new();
        let c = r.counter("ab_drops_total{stage=\"publish\"}", "drops");
        c.inc();
        let text = r.render();
        assert!(text.contains("# TYPE ab_drops_total counter"), "{text}");
        assert!(text.contains("ab_drops_total{stage=\"publish\"} 1"), "{text}");
    }

    #[test]
    fn histogram_quantiles() {
        let h = Histogram::new(DEFAULT_LATENCY_BOUNDS_US);
        for _ in 0..99 {
            h.observe_us(80); // ≤ 100µs bucket
        }
        h.observe_us(9_000); // ≤ 10ms bucket
        assert_eq!(h.count(), 100);
        assert_eq!(h.quantile_us(0.5), 100);
        assert_eq!(h.quantile_us(0.99), 100);
        assert_eq!(h.quantile_us(1.0), 10_000);
    }

    #[test]
    fn histogram_renders_cumulative_buckets() {
        let r = Registry::new();
        let h = r.histogram("ab_lat", "latency");
        h.observe_us(60);
        h.observe_us(60);
        h.observe_us(600);
        let text = r.render();
        // 50µs bucket: 0, 100µs bucket: 2, ..., 1ms bucket: 3
        assert!(text.contains("ab_lat_bucket{le=\"0.0001\"} 2"), "{text}");
        assert!(text.contains("ab_lat_bucket{le=\"0.001\"} 3"), "{text}");
        assert!(text.contains("ab_lat_bucket{le=\"+Inf\"} 3"), "{text}");
        assert!(text.contains("ab_lat_count 3"), "{text}");
    }

    #[test]
    fn same_key_returns_same_metric() {
        let r = Registry::new();
        let a = r.counter("x_total", "x");
        let b = r.counter("x_total", "x");
        a.inc();
        assert_eq!(b.get(), 1);
    }
}
