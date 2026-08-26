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

/// A signed gauge whose value may go up, down, or be `set` to an
/// absolute number. Backed by `AtomicI64` because Prometheus gauges
/// are unrestricted-sign floats; we clamp to i64 here because every
/// data-plane gauge in the workspace (open sessions, queue depth,
/// spool bytes) is a non-negative count that fits comfortably in
/// 63 bits, and the signed representation lets `sub_saturating`
/// bottom out at 0 rather than wrap.
#[derive(Debug, Default)]
pub struct Gauge {
    value: std::sync::atomic::AtomicI64,
}

impl Gauge {
    /// Set the gauge to an absolute value. Truncates to `i64::MAX`
    /// on overflow — no data-plane count in the workspace is even
    /// close to that ceiling, and silently overflowing to a
    /// negative value would produce misleading dashboards.
    pub fn set(&self, value: u64) {
        let clamped = i64::try_from(value).unwrap_or(i64::MAX);
        self.value.store(clamped, Ordering::Relaxed);
    }

    /// Increment by 1. Saturates at `i64::MAX`.
    pub fn inc(&self) {
        self.add(1);
    }

    /// Decrement by 1. Saturates at 0 — a gauge going negative is
    /// almost always a lifecycle bookkeeping bug (dec called twice
    /// for one inc), and rendering `-1 open_sessions` would confuse
    /// every dashboard downstream.
    pub fn dec(&self) {
        self.sub(1);
    }

    /// Increment by `n`. Saturates at `i64::MAX`.
    pub fn add(&self, n: u64) {
        let delta = i64::try_from(n).unwrap_or(i64::MAX);
        // A signed `fetch_add` with a positive delta saturates
        // silently to `i64::MIN` on overflow (two's complement
        // wrap). Loop-CAS to a saturated add so overflow lands at
        // `i64::MAX` — never negative.
        let mut current = self.value.load(Ordering::Relaxed);
        loop {
            let next = current.saturating_add(delta);
            match self
                .value
                .compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return,
                Err(observed) => current = observed,
            }
        }
    }

    /// Decrement by `n`. Saturates at 0.
    pub fn sub(&self, n: u64) {
        let delta = i64::try_from(n).unwrap_or(i64::MAX);
        let mut current = self.value.load(Ordering::Relaxed);
        loop {
            let next = current.saturating_sub(delta).max(0);
            match self
                .value
                .compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return,
                Err(observed) => current = observed,
            }
        }
    }

    /// Current value as an unsigned integer — the saturating math
    /// above guarantees non-negativity so the cast never truncates
    /// a real observation.
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed).max(0) as u64
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
    /// Samples above every declared bucket. Represents the implicit
    /// `le="+Inf"` bucket in Prometheus terms and lets `quantile_us`
    /// distinguish "quantile equals the top bound" from "quantile lies
    /// beyond the top bound".
    overflow: AtomicU64,
}

/// Default latency bucket upper bounds in microseconds: 50µs … 10s.
///
/// Sized for fast internal stages (identity check, quota, sanitize,
/// dashboard endpoints, receipt sign). Long-running histograms — the
/// upstream `dispatch` call which includes provider streaming, and the
/// filesystem-scan reconciler / finalize paths — must use
/// [`WIDE_LATENCY_BOUNDS_US`] instead, or every observation lands in
/// the `+Inf` overflow bucket and p95/p99 renders as `u64::MAX`.
pub const DEFAULT_LATENCY_BOUNDS_US: &[u64] = &[
    50, 100, 250, 500, 1_000, 2_000, 5_000, 8_000, 10_000, 25_000, 50_000, 100_000, 1_000_000, 10_000_000,
];

/// Wide latency bucket upper bounds in microseconds: 1ms … 300s.
///
/// Use for histograms that measure spans dominated by network I/O
/// (upstream LLM streaming, reconciler recovery scans, finalisation
/// under load). Provider p99 for GPT-4o / Claude regularly sits in the
/// 15–90 s band; the top bound of 300 s covers pathological long
/// contexts without saturating for realistic operator SLA use.
pub const WIDE_LATENCY_BOUNDS_US: &[u64] = &[
    1_000,
    5_000,
    10_000,
    100_000,
    500_000,
    1_000_000,
    5_000_000,
    10_000_000,
    30_000_000,
    60_000_000,
    120_000_000,
    300_000_000,
];

impl Histogram {
    /// Create a histogram with the given bucket upper bounds (µs, ascending).
    pub fn new(bounds_us: &[u64]) -> Self {
        Self {
            bounds_us: bounds_us.to_vec(),
            buckets: bounds_us.iter().map(|_| AtomicU64::new(0)).collect(),
            count: AtomicU64::new(0),
            sum_us: AtomicU64::new(0),
            overflow: AtomicU64::new(0),
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
                return;
            }
        }
        // Sample landed above every declared bucket. Track it so the
        // renderer can emit the standard Prometheus `le="+Inf"` bucket
        // (bounded-bucket sum otherwise equals `count` minus the tail,
        // which is invalid Prometheus text) and so operators can spot a
        // regime where the true P99 is beyond the top bound.
        self.overflow.fetch_add(1, Ordering::Relaxed);
    }

    /// Total number of samples.
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    /// Approximate quantile (µs) from bucket boundaries. Returns the upper
    /// bound of the bucket containing quantile `q` (0.0–1.0); a target that
    /// lands above every bounded bucket returns the sentinel below.
    ///
    /// A `q` whose target is served only by samples in the implicit +Inf
    /// bucket returns `u64::MAX` as a sentinel: this signals "beyond top
    /// bucket" instead of silently under-reporting `bounds_us.last()`.
    pub fn quantile_us(&self, q: f64) -> u64 {
        let total = self.count();
        if total == 0 {
            return 0;
        }
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss
        )]
        let target = ((total as f64) * q.clamp(0.0, 1.0)).ceil() as u64;
        let mut cum = 0u64;
        for (i, b) in self.bounds_us.iter().enumerate() {
            cum += self.buckets.get(i).map_or(0, |x| x.load(Ordering::Relaxed));
            if cum >= target {
                return *b;
            }
        }
        // Bounded buckets could not reach the target: the target must sit in
        // the +Inf overflow bucket. Surface that with u64::MAX rather than
        // returning bounds_us.last() and silently under-reporting.
        if self.overflow.load(Ordering::Relaxed) > 0 {
            return u64::MAX;
        }
        self.bounds_us.last().copied().unwrap_or(0)
    }
}

enum Metric {
    Counter(Arc<Counter>),
    Gauge(Arc<Gauge>),
    Histogram(Arc<Histogram>),
}

/// A registry mapping metric names (+ optional fixed labels) to metrics.
#[derive(Default)]
pub struct Registry {
    metrics: Mutex<BTreeMap<String, (String, Metric)>>,
    /// Track the metric KIND (counter vs histogram) per base name — the
    /// full-key type-collision guard in `counter`/`histogram_with_bounds`
    /// only catches same-key clashes, but Prometheus text exposition
    /// requires that ALL variants of a base name (across every label
    /// combination) share the same type. Two contributors registering
    /// `av_foo_total{stage="a"}` as a counter and
    /// `av_foo_total{stage="b"}` as a histogram would produce an
    /// invalid `# TYPE` header and Prometheus's parser would reject
    /// the whole scrape.
    base_kinds: Mutex<BTreeMap<String, MetricKind>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MetricKind {
    Counter,
    Gauge,
    Histogram,
}

impl MetricKind {
    fn label(self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::Gauge => "gauge",
            Self::Histogram => "histogram",
        }
    }
}

impl Registry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register (or fetch) a counter. `key` must be a valid Prometheus series
    /// name with optional `{label="v"}` suffix.
    ///
    /// Panics if `key` is already registered as a histogram; a silent
    /// overwrite would detach the existing metric from the registry and
    /// lose every observation collected against it. Also panics if `key`
    /// contains a byte that would corrupt Prometheus text exposition
    /// (cross-line bytes anywhere; `"` or `\\` in the base name — both
    /// stay legal inside the label section) — this catches accidental
    /// interpolation of
    /// attacker-controlled strings into a metric key at registration
    /// rather than surfacing corrupt scrape output later.
    #[allow(clippy::panic)]
    pub fn counter(&self, key: &str, help: &str) -> Arc<Counter> {
        validate_metric_key(key);
        self.reserve_base_kind(key, MetricKind::Counter);
        let mut m = self.metrics.lock();
        match m.get(key) {
            Some((_, Metric::Counter(c))) => Arc::clone(c),
            Some((_, Metric::Gauge(_))) => panic!(
                "metric name conflict: {key:?} is already registered as a gauge, \
                 cannot register as a counter",
            ),
            Some((_, Metric::Histogram(_))) => panic!(
                "metric name conflict: {key:?} is already registered as a histogram, \
                 cannot register as a counter",
            ),
            None => {
                let c = Arc::new(Counter::default());
                m.insert(key.to_owned(), (help.to_owned(), Metric::Counter(Arc::clone(&c))));
                c
            }
        }
    }

    /// Register (or fetch) a gauge. Same key/label conventions as
    /// [`Self::counter`]; gauges may go up, down, and be reset via
    /// [`Gauge::set`]. Panics on kind conflict with an existing
    /// counter or histogram registered under the same base name.
    #[allow(clippy::panic)]
    pub fn gauge(&self, key: &str, help: &str) -> Arc<Gauge> {
        validate_metric_key(key);
        self.reserve_base_kind(key, MetricKind::Gauge);
        let mut m = self.metrics.lock();
        match m.get(key) {
            Some((_, Metric::Gauge(g))) => Arc::clone(g),
            Some((_, Metric::Counter(_))) => panic!(
                "metric name conflict: {key:?} is already registered as a counter, \
                 cannot register as a gauge",
            ),
            Some((_, Metric::Histogram(_))) => panic!(
                "metric name conflict: {key:?} is already registered as a histogram, \
                 cannot register as a gauge",
            ),
            None => {
                let g = Arc::new(Gauge::default());
                m.insert(key.to_owned(), (help.to_owned(), Metric::Gauge(Arc::clone(&g))));
                g
            }
        }
    }

    /// Register (or fetch) a histogram with default latency buckets.
    ///
    /// Panics if `key` is already registered as a counter; a silent overwrite
    /// would detach the existing metric from the registry and lose every
    /// observation collected against it. Same key-byte guard as
    /// [`Self::counter`].
    #[allow(clippy::panic)]
    pub fn histogram(&self, key: &str, help: &str) -> Arc<Histogram> {
        self.histogram_with_bounds(key, help, DEFAULT_LATENCY_BOUNDS_US)
    }

    /// Register (or fetch) a histogram with explicit bucket bounds. Use
    /// [`WIDE_LATENCY_BOUNDS_US`] for spans dominated by network I/O
    /// (upstream LLM streaming, reconciler filesystem scans); use
    /// [`DEFAULT_LATENCY_BOUNDS_US`] for fast internal stages.
    ///
    /// # Panics
    ///
    /// Panics if `key` is already registered as a counter; a silent
    /// overwrite would detach the existing metric from the registry
    /// and lose every observation collected against it. Same
    /// key-byte guard as [`Self::counter`] applies.
    #[allow(clippy::panic)]
    pub fn histogram_with_bounds(&self, key: &str, help: &str, bounds_us: &[u64]) -> Arc<Histogram> {
        validate_metric_key(key);
        self.reserve_base_kind(key, MetricKind::Histogram);
        let mut m = self.metrics.lock();
        match m.get(key) {
            Some((_, Metric::Histogram(h))) => Arc::clone(h),
            Some((_, Metric::Counter(_))) => panic!(
                "metric name conflict: {key:?} is already registered as a counter, \
                 cannot register as a histogram",
            ),
            Some((_, Metric::Gauge(_))) => panic!(
                "metric name conflict: {key:?} is already registered as a gauge, \
                 cannot register as a histogram",
            ),
            None => {
                let h = Arc::new(Histogram::new(bounds_us));
                m.insert(
                    key.to_owned(),
                    (help.to_owned(), Metric::Histogram(Arc::clone(&h))),
                );
                h
            }
        }
    }

    /// Enforce that a base name (the metric name up to `{`) is only
    /// ever registered as one metric kind across every label
    /// combination — a Prometheus text-exposition invariant. Panics
    /// with a clear message on mismatch. Called from `counter` and
    /// `histogram_with_bounds` before the per-key type check.
    #[allow(clippy::panic)]
    fn reserve_base_kind(&self, key: &str, kind: MetricKind) {
        let (base, _labels) = split_key(key);
        let mut kinds = self.base_kinds.lock();
        match kinds.get(base) {
            Some(existing) if *existing != kind => panic!(
                "metric base-name kind conflict: {base:?} is already registered as \
                 `{}` at another label combination; cannot register {key:?} as `{}`. \
                 Prometheus rejects mismatched TYPE headers across variants of the \
                 same base name and the whole scrape becomes invalid text exposition.",
                existing.label(),
                kind.label(),
            ),
            _ => {
                kinds.insert(base.to_owned(), kind);
            }
        }
    }

    /// Render the registry in Prometheus text exposition format.
    ///
    /// Histogram observations are stored internally in microseconds but
    /// rendered in seconds (`le` bounds and `_sum`), per Prometheus base-unit
    /// convention. Histogram metric names should therefore end in `_seconds`.
    ///
    /// HELP text is escaped per the Prometheus text format
    /// spec (`\` → `\\`, LF → `\n`). A future counter/histogram
    /// registration whose HELP contained a newline would otherwise
    /// silently corrupt the scrape response — Prometheus would parse
    /// the remainder of the HELP text as metric samples and fail.
    pub fn render(&self) -> String {
        let m = self.metrics.lock();
        let mut out = String::new();
        let mut declared = std::collections::BTreeSet::new();
        for (key, (help, metric)) in m.iter() {
            let (base, labels) = split_key(key);
            let help = escape_prom_help(help);
            match metric {
                Metric::Counter(c) => {
                    if declared.insert(base.to_owned()) {
                        out.push_str(&format!("# HELP {base} {help}\n# TYPE {base} counter\n"));
                    }
                    out.push_str(&format!("{key} {}\n", c.get()));
                }
                Metric::Gauge(g) => {
                    if declared.insert(base.to_owned()) {
                        out.push_str(&format!("# HELP {base} {help}\n# TYPE {base} gauge\n"));
                    }
                    out.push_str(&format!("{key} {}\n", g.get()));
                }
                Metric::Histogram(h) => {
                    if declared.insert(base.to_owned()) {
                        out.push_str(&format!("# HELP {base} {help}\n# TYPE {base} histogram\n"));
                    }
                    // Snapshot the count ONCE before rendering either
                    // the `+Inf` bucket or the `_count` line, AND
                    // clamp the cumulative bucket sum against the
                    // snapshot. Two invariants strict OpenMetrics
                    // parsers enforce:
                    //
                    //   (a) `_count == cum(bucket{le="+Inf"})`
                    //   (b) `bucket{le=X} <= bucket{le=Y}` for X < Y,
                    //       and `bucket{le=X} <= _count` for all X
                    //
                    // `observe_us` writes `count.fetch_add` BEFORE
                    // `bucket.fetch_add` (metrics.rs:176 → :181), so
                    // a naive render that reads count first and
                    // buckets after can see MORE bucket increments
                    // than count increments — a concurrent observe
                    // that completed both fetches between the
                    // count snapshot and the bucket load. The
                    // previous fix (R24 review) snapshotted count
                    // once but didn't clamp; that closed invariant
                    // (a) but re-opened invariant (b), because
                    // `cum` could exceed `count_snapshot` on the
                    // very next bucket iteration and get emitted
                    // verbatim.
                    //
                    // Clamping cum against count_snapshot preserves
                    // both invariants: bucket lines are monotone
                    // non-decreasing (cum is monotone, `.min(K)` of
                    // a monotone sequence is monotone), and every
                    // bucket line is `<= count_snapshot` by
                    // construction. Under a race, a bucket that
                    // truly holds `N+1` observations may render as
                    // `N` for one scrape; the missing observation
                    // shows up on the next scrape. This is the same
                    // "eventually consistent under concurrent
                    // observation" contract every Prometheus client
                    // library the ecosystem trusts uses.
                    let count_snapshot = h.count();
                    let mut cum = 0u64;
                    for (i, b) in h.bounds_us.iter().enumerate() {
                        cum += h.buckets.get(i).map_or(0, |x| x.load(Ordering::Relaxed));
                        let clamped = cum.min(count_snapshot);
                        let le = (*b as f64) / 1_000_000.0;
                        out.push_str(&format!(
                            "{base}_bucket{{{}le=\"{le}\"}} {clamped}\n",
                            join_labels(labels)
                        ));
                    }
                    out.push_str(&format!(
                        "{base}_bucket{{{}le=\"+Inf\"}} {count_snapshot}\n",
                        join_labels(labels),
                    ));
                    let sum_s = (h.sum_us.load(Ordering::Relaxed) as f64) / 1_000_000.0;
                    out.push_str(&format!(
                        "{base}_sum{labels_block} {sum_s}\n",
                        labels_block = labels_suffix(labels)
                    ));
                    out.push_str(&format!(
                        "{base}_count{labels_block} {count_snapshot}\n",
                        labels_block = labels_suffix(labels)
                    ));
                }
            }
        }
        out
    }
}

/// Escape a HELP text per the Prometheus text exposition
/// format spec. Backslash and line-feed are the only two chars the
/// format reserves in HELP lines. A future counter/histogram
/// registration whose HELP contained a newline would otherwise
/// silently corrupt the scrape response — Prometheus would parse
/// the remainder of the HELP text as metric samples and fail.
fn escape_prom_help(help: &str) -> String {
    let mut out = String::with_capacity(help.len());
    for c in help.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            // Replace CR
            // and every other C0 control (0x00–0x1F except LF
            // which we just escaped) with a literal space.
            // `validate_metric_key` already refuses these bytes
            // in metric keys; the HELP-side didn't. NUL trips
            // promtool lint / grafana-agent; ESC (0x1B) lets a
            // caller who controls HELP text inject ANSI codes
            // into operator terminals via `avctl` piped
            // `/metrics`. The substitution also covers DEL (0x7F) and the C1 range (0x80..=0x9F) —
            // CSI (0x9B) is a valid single-byte ANSI escape
            // prefix under 8-bit terminal emulation, so a HELP
            // text carrying a `\u{9b}...` sequence renders the
            // same way in an 8-bit-clean terminal as the C0
            // ESC+`[` prefix we already scrub. Space is the
            // same convention prometheus_client-python's
            // `_ESCAPE_RE` uses.
            c if (c as u32) < 0x20 || (c as u32) == 0x7f || (0x80..=0x9f).contains(&(c as u32)) => {
                out.push(' ');
            }
            other => out.push(other),
        }
    }
    out
}

/// Reject metric keys that would corrupt the Prometheus text exposition
/// format. Legitimate keys carry label values like `{stage="identity"}` and
/// must be allowed to contain double quotes and `=`, but a newline,
/// carriage return, backslash, or NUL byte inside a key would split the
/// scrape line and produce invalid text. These bytes arrive only from
/// callers accidentally interpolating attacker-influenced strings into a
/// series name; catch that at registration.
#[allow(clippy::panic)]
fn validate_metric_key(key: &str) {
    // Split the key into base + labels first, then apply
    // strict byte checks to the base name only. Label values are
    // enclosed in double quotes by convention (`{stage="worker_queue"}`)
    // so a global `"` ban would panic on every labelled counter
    // registration (see the labelled-counter tests). The
    // real hazard is a base-name that carries `"` / `\` / `\n` / `\r`
    // / NUL — those would produce unbalanced quotes or split-line
    // output that Prometheus rejects as invalid text exposition.
    // Label values carry no render-time escaper: cross-line bytes
    // (`\n` / `\r` / NUL) anywhere in the labels section are refused
    // at registration by the loop below; this validator is the only
    // guard, and its job covers both the base and the labels bytes.
    let (base, labels) = split_key(key);
    for byte in base.bytes() {
        if matches!(byte, b'\n' | b'\r' | b'\\' | b'"' | 0x00) {
            panic!(
                "metric base name {base:?} contains a byte (0x{byte:02x}) that would corrupt \
                 Prometheus text exposition; interpolating attacker-controlled strings \
                 into metric names is unsafe",
            );
        }
    }
    // Also refuse the raw cross-line bytes anywhere in the labels
    // section — Prometheus parses one metric per line, so any bare
    // `\n`, `\r`, or NUL slips a synthetic line into the scrape.
    // Backslash and double quote stay legal here because the quotes
    // are structural to the `l="v"` convention and label sections are
    // built from code-controlled constants (never attacker input);
    // labels render verbatim — there is no render-time escaper for
    // them (only HELP text gets `escape_prom_help`).
    for byte in labels.bytes() {
        if matches!(byte, b'\n' | b'\r' | 0x00) {
            panic!(
                "metric label section {labels:?} contains a byte (0x{byte:02x}) that would \
                 corrupt Prometheus text exposition; interpolating attacker-controlled \
                 strings into metric labels is unsafe",
            );
        }
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
        let c = r.counter("av_test_total", "test counter");
        c.inc();
        c.add(4);
        assert_eq!(c.get(), 5);
        let text = r.render();
        assert!(text.contains("# TYPE av_test_total counter"), "{text}");
        assert!(text.contains("av_test_total 5"), "{text}");
    }

    /// Mutation-run hardening: `validate_metric_key` replaced with a no-op
    /// survived — nothing pinned that a base name carrying a scrape-
    /// corrupting byte actually panics at registration.
    #[test]
    #[should_panic(expected = "corrupt")]
    fn metric_key_with_newline_panics_at_registration() {
        let r = Registry::new();
        let _ = r.counter("av_bad\nname_total", "bad");
    }

    /// Mutation-run hardening: `escape_prom_help`'s C0/DEL/C1 replacement
    /// boundary was untested beyond `\n` — ESC (terminal injection via
    /// piped /metrics), NUL (promtool lint), CR and CSI must all become
    /// spaces, while printable ASCII from 0x20 up passes through.
    #[test]
    fn help_text_scrubs_all_control_bytes_to_spaces() {
        let scrubbed = escape_prom_help("a\u{1b}[2Jb\u{0}c\rd\u{9b}e");
        assert_eq!(scrubbed, "a [2Jb c d e");
        assert_eq!(escape_prom_help(" printable ~"), " printable ~");
        assert_eq!(escape_prom_help("line\nbreak\\slash"), "line\\nbreak\\\\slash");
    }

    /// Mutation-run hardening: the `_sum` line converts accumulated
    /// microseconds to SECONDS via division; a `/`→`*` mutant survived
    /// because no test pinned the rendered sum value.
    #[test]
    fn histogram_sum_renders_in_seconds() {
        let r = Registry::new();
        let h = r.histogram("av_test_lat_seconds", "test latency");
        h.observe_us(1_500_000);
        h.observe_us(500_000);
        let text = r.render();
        assert!(
            text.contains("av_test_lat_seconds_sum 2\n"),
            "2_000_000 us must render as 2 seconds: {text}"
        );
    }

    #[test]
    fn gauge_add_sub_set_and_render() {
        let r = Registry::new();
        let g = r.gauge("av_test_gauge", "test gauge");
        g.set(10);
        g.inc();
        g.add(3);
        g.dec();
        g.sub(2);
        assert_eq!(g.get(), 11);
        let text = r.render();
        assert!(text.contains("# TYPE av_test_gauge gauge"), "{text}");
        assert!(text.contains("av_test_gauge 11"), "{text}");
    }

    #[test]
    fn gauge_saturates_at_zero_not_negative() {
        let g = Gauge::default();
        g.set(3);
        g.sub(100);
        assert_eq!(
            g.get(),
            0,
            "gauge went negative — dashboards would be misleading and the review's data-plane counters would report bogus values"
        );
    }

    #[test]
    fn gauge_saturates_at_i64_max_not_wrap() {
        let g = Gauge::default();
        g.add(u64::MAX);
        g.add(u64::MAX);
        // Any positive number is a passing signal (proves no wrap);
        // the specific ceiling is i64::MAX under the current impl.
        assert!(g.get() > 0, "gauge wrapped through overflow");
    }

    #[test]
    #[should_panic(expected = "already registered as `counter`")]
    fn gauge_refuses_conflict_with_counter() {
        let r = Registry::new();
        let _c = r.counter("av_conflict", "conflict");
        let _g = r.gauge("av_conflict", "conflict");
    }

    #[test]
    #[should_panic(expected = "already registered as `gauge`")]
    fn counter_refuses_conflict_with_gauge() {
        let r = Registry::new();
        let _g = r.gauge("av_conflict2", "conflict");
        let _c = r.counter("av_conflict2", "conflict");
    }

    /// HELP text with an embedded newline must be escaped
    /// so the Prometheus text-format scraper does not interpret the
    /// second half as a metric sample. Backslash must also be
    /// escaped per the spec.
    #[test]
    #[allow(clippy::expect_used)]
    fn render_escapes_newlines_and_backslashes_in_help_text() {
        let r = Registry::new();
        r.counter("av_dangerous_total", "line1\nline2\\path");
        let text = r.render();
        // A rendered HELP line must not contain the raw newline —
        // any newline in the HELP must appear as literal `\n`.
        let help_line = text
            .lines()
            .find(|line| line.starts_with("# HELP av_dangerous_total"))
            .expect("HELP line present");
        assert!(help_line.contains(r"\n"), "help was not escaped: {help_line:?}");
        assert!(
            help_line.contains(r"\\"),
            "backslash was not escaped: {help_line:?}"
        );
        // And the "line2" fragment must not be on its own line.
        assert!(
            !text.contains("\nline2\\path"),
            "unescaped fragment leaked into scrape: {text}"
        );
    }

    #[test]
    fn counter_with_labels_renders_base_name_in_type() {
        let r = Registry::new();
        let c = r.counter("av_drops_total{stage=\"publish\"}", "drops");
        c.inc();
        let text = r.render();
        assert!(text.contains("# TYPE av_drops_total counter"), "{text}");
        assert!(text.contains("av_drops_total{stage=\"publish\"} 1"), "{text}");
    }

    #[test]
    fn labeled_family_is_declared_once() {
        let r = Registry::new();
        r.histogram("av_stage_duration_seconds{stage=\"identity\"}", "stage latency");
        r.histogram("av_stage_duration_seconds{stage=\"quota\"}", "stage latency");
        let text = r.render();
        assert_eq!(
            text.matches("# HELP av_stage_duration_seconds ").count(),
            1,
            "{text}"
        );
        assert_eq!(
            text.matches("# TYPE av_stage_duration_seconds histogram").count(),
            1,
            "{text}"
        );
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
        let h = r.histogram("av_lat", "latency");
        h.observe_us(60);
        h.observe_us(60);
        h.observe_us(600);
        let text = r.render();
        // 50µs bucket: 0, 100µs bucket: 2, ..., 1ms bucket: 3
        assert!(text.contains("av_lat_bucket{le=\"0.0001\"} 2"), "{text}");
        assert!(text.contains("av_lat_bucket{le=\"0.001\"} 3"), "{text}");
        assert!(text.contains("av_lat_bucket{le=\"+Inf\"} 3"), "{text}");
        assert!(text.contains("av_lat_count 3"), "{text}");
    }

    /// Prometheus text format requires `_count == cum(bucket{le="+Inf"})`.
    /// Pre-fix, the render read `h.count()` TWICE — once for the `+Inf`
    /// bucket, once for the `_count` line — with `sum_us.load(...)` in
    /// between. A concurrent `observe_us` completing between the two
    /// loads left the scrape with `_count = N+1` and `+Inf = N`, which
    /// strict OpenMetrics parsers reject and `histogram_quantile`
    /// interprets as off-by-one quantile artifacts. Hammer both a
    /// writer and a reader in parallel and assert the invariant on
    /// EVERY scrape.
    /// Prometheus text format enforces two invariants strict
    /// OpenMetrics parsers reject on:
    ///
    ///   (a) `_count == cum(bucket{le="+Inf"})`
    ///   (b) `bucket{le=X} <= bucket{le=Y}` for X < Y, and
    ///       `bucket{le=X} <= _count` for all X
    ///
    /// R25 closed (a) by snapshotting count once, but LEFT (b) open
    /// because `observe_us` writes count-then-bucket — a snapshot-
    /// count-then-read-buckets order could see MORE bucket
    /// increments than count increments (a concurrent observe that
    /// completed both fetches between the count snapshot and the
    /// bucket load). The current fix ALSO clamps cum against the
    /// snapshot to preserve (b). Hammer a writer + reader in
    /// parallel and assert BOTH invariants on EVERY scrape.
    #[test]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    fn histogram_scrape_preserves_all_invariants_under_concurrent_observe() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::thread;

        let r = Arc::new(Registry::new());
        // Diverse bucket bounds so a busy writer spreads observations
        // across several buckets — increases the chance of catching a
        // mid-loop race between the bucket loop and the count snapshot.
        let h = r.histogram_with_bounds(
            "av_race",
            "concurrent scrape probe",
            &[10, 100, 1_000, 10_000, 100_000],
        );
        let stop = Arc::new(AtomicBool::new(false));

        let writer = {
            let h = h.clone();
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                // Rotate through values that hit different buckets.
                let mut i: u64 = 0;
                while !stop.load(Ordering::Relaxed) {
                    let us = (i % 5 + 1) * 50; // 50, 100, 150, 200, 250
                    h.observe_us(us);
                    i = i.wrapping_add(1);
                }
            })
        };

        let start = std::time::Instant::now();
        let mut scrapes = 0usize;
        while start.elapsed() < std::time::Duration::from_millis(300) {
            let text = r.render();
            let mut buckets: Vec<(f64, u64)> = Vec::new();
            let mut count: Option<u64> = None;
            for line in text.lines() {
                if line.starts_with("av_race_bucket") {
                    let le_start = line.find("le=\"").unwrap() + 4;
                    let le_end = le_start + line[le_start..].find('"').unwrap();
                    let le_str = &line[le_start..le_end];
                    let val: u64 = line.rsplit(' ').next().and_then(|s| s.parse().ok()).unwrap();
                    let le_f = if le_str == "+Inf" {
                        f64::INFINITY
                    } else {
                        le_str.parse().unwrap()
                    };
                    buckets.push((le_f, val));
                } else if line.starts_with("av_race_count") {
                    count = Some(line.rsplit(' ').next().and_then(|s| s.parse().ok()).unwrap());
                }
            }
            let count = count.expect("_count line missing");
            buckets.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
            let mut prev = 0u64;
            for (le, val) in &buckets {
                // Invariant (b1): buckets monotone non-decreasing.
                assert!(
                    *val >= prev,
                    "monotonicity violated at le={le}: {val} < prev {prev} on scrape {scrapes}"
                );
                // Invariant (b2): every bucket <= _count.
                assert!(
                    *val <= count,
                    "bucket at le={le} = {val} > _count = {count} on scrape {scrapes}"
                );
                prev = *val;
            }
            // Invariant (a): +Inf bucket == _count.
            let inf = buckets
                .iter()
                .find(|(le, _)| le.is_infinite())
                .expect("+Inf bucket missing")
                .1;
            assert_eq!(
                inf, count,
                "invariant (a) violated: +Inf = {inf} != _count = {count} on scrape {scrapes}"
            );
            scrapes = scrapes.saturating_add(1);
        }
        stop.store(true, Ordering::Relaxed);
        writer.join().unwrap();
        assert!(scrapes > 100, "should have taken > 100 scrapes; got {scrapes}");
    }

    #[test]
    fn same_key_returns_same_metric() {
        let r = Registry::new();
        let a = r.counter("x_total", "x");
        let b = r.counter("x_total", "x");
        a.inc();
        assert_eq!(b.get(), 1);
    }

    #[test]
    fn labeled_histogram_renders_labels_on_every_series_line() {
        // Catches `split_key`, `join_labels`, and `labels_suffix` stubs.
        // A labeled histogram must emit label pairs on _bucket, _sum, and
        // _count — the label prefix must land BEFORE the `le=` in buckets
        // and the entire `{labels}` block must land after _sum/_count.
        let r = Registry::new();
        let h = r.histogram("av_lat{route=\"chat\"}", "lat");
        h.observe_us(60);
        let text = r.render();
        assert!(
            text.contains("av_lat_bucket{route=\"chat\",le=\"0.0001\"} 1"),
            "join_labels lost the route label: {text}"
        );
        assert!(
            text.contains("av_lat_sum{route=\"chat\"} "),
            "labels_suffix lost the route label on _sum: {text}"
        );
        assert!(
            text.contains("av_lat_count{route=\"chat\"} 1"),
            "labels_suffix lost the route label on _count: {text}"
        );
    }

    /// Vicious registry bug: `counter()` used to silently
    /// insert a fresh Counter over an existing Histogram at the same key,
    /// detaching the histogram from the registry and losing every prior
    /// observation. A metric name registered as one type must never be
    /// silently repurposed as the other — panic loudly instead.
    #[test]
    #[should_panic(expected = "kind conflict")]
    fn counter_over_existing_histogram_panics_instead_of_overwriting() {
        let r = Registry::new();
        r.histogram("av_metric", "help");
        r.counter("av_metric", "help");
    }

    #[test]
    #[should_panic(expected = "kind conflict")]
    fn histogram_over_existing_counter_panics_instead_of_overwriting() {
        let r = Registry::new();
        r.counter("av_metric", "help");
        r.histogram("av_metric", "help");
    }

    /// Cross-label type collision on the same base name: `foo{a="1"}`
    /// registered as counter, `foo{a="2"}` registered as histogram.
    /// Prometheus TYPE header would be ambiguous — reject at
    /// registration.
    #[test]
    #[should_panic(expected = "kind conflict")]
    fn different_labels_same_base_name_type_collision_panics() {
        let r = Registry::new();
        r.counter("av_metric{shard=\"a\"}", "help");
        r.histogram("av_metric{shard=\"b\"}", "help");
    }

    /// Same-type re-registration must still work (idempotent) — the panic
    /// guard only fires on genuine type conflicts.
    #[test]
    fn same_type_re_registration_returns_existing_arc() {
        let r = Registry::new();
        let c1 = r.counter("av_metric", "help");
        let c2 = r.counter("av_metric", "help");
        c1.inc();
        assert_eq!(c2.get(), 1, "must return the same underlying counter");

        let h1 = r.histogram("av_other", "help");
        let h2 = r.histogram("av_other", "help");
        h1.observe_us(50);
        assert_eq!(h2.count(), 1, "must return the same underlying histogram");
    }

    /// HELP text escaper substitutes DEL (0x7F) and every
    /// C1 control (0x80..=0x9F) with a literal space. C0 controls
    /// were handled first; C1 was left through and CSI (0x9B) is a
    /// valid single-byte ANSI escape prefix under 8-bit terminal
    /// emulation. A future counter registration with operator-
    /// influenced HELP text (charter name / model name / SSE error
    /// snippet) that happened to include a C1 byte could otherwise
    /// inject terminal-escape sequences through `curl /metrics | less`.
    #[test]
    fn escape_prom_help_scrubs_del_and_c1_controls() {
        let dangerous = "help\u{7f}with\u{9b}csi\u{80}c1\u{9f}end";
        let out = escape_prom_help(dangerous);
        for c in ['\u{7f}', '\u{9b}', '\u{80}', '\u{9f}'] {
            assert!(!out.contains(c), "escape_prom_help left {c:?} in {out:?}");
        }
        // The safe chars are preserved.
        assert!(out.contains("help"));
        assert!(out.contains("csi"));
        assert!(out.contains("end"));
    }
}

#[cfg(test)]
mod histogram_boundary_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// Mutation-run hardening: the overflow-bucket branch of
    /// `quantile_us` and the seconds conversion in `_sum` rendering were
    /// unpinned. A sample past the last bound must surface as u64::MAX
    /// (never silently under-report as the last bound), and the rendered
    /// sum must be the microsecond total divided by exactly 1e6.
    #[test]
    fn quantile_overflow_reports_max_and_sum_renders_in_seconds() {
        let r = Registry::new();
        let h = r.histogram_with_bounds("av_overflow_probe", "probe", &[10, 100]);
        h.observe_us(1_000_000); // beyond the last bound: overflow bucket
        assert_eq!(h.quantile_us(0.99), u64::MAX);
        h.observe_us(2_000_000);
        let text = r.render();
        assert!(
            text.contains("av_overflow_probe_sum 3"),
            "sum must be 3 seconds (3_000_000 us / 1e6), got:\n{text}"
        );
    }
}
