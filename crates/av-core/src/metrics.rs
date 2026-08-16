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
    /// bound of the bucket containing quantile `q` (0.0–1.0), or the max bound
    /// if the sample landed above every bucket.
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
    Histogram,
}

impl MetricKind {
    fn label(self) -> &'static str {
        match self {
            Self::Counter => "counter",
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
    /// (`"`, `\n`, `\\`) — this catches accidental interpolation of
    /// attacker-controlled strings into a metric key at registration
    /// rather than surfacing corrupt scrape output later.
    #[allow(clippy::panic)]
    pub fn counter(&self, key: &str, help: &str) -> Arc<Counter> {
        validate_metric_key(key);
        self.reserve_base_kind(key, MetricKind::Counter);
        let mut m = self.metrics.lock();
        match m.get(key) {
            Some((_, Metric::Counter(c))) => Arc::clone(c),
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
    /// Round-19: HELP text is escaped per the Prometheus text format
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
                Metric::Histogram(h) => {
                    if declared.insert(base.to_owned()) {
                        out.push_str(&format!("# HELP {base} {help}\n# TYPE {base} histogram\n"));
                    }
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
                    out.push_str(&format!(
                        "{base}_sum{labels_block} {sum_s}\n",
                        labels_block = labels_suffix(labels)
                    ));
                    out.push_str(&format!(
                        "{base}_count{labels_block} {}\n",
                        h.count(),
                        labels_block = labels_suffix(labels)
                    ));
                }
            }
        }
        out
    }
}

/// Round-19: escape a HELP text per the Prometheus text exposition
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
            // Round-20 F3 + round-21 F4 + round-26 F4: replace CR
            // and every other C0 control (0x00–0x1F except LF
            // which we just escaped) with a literal space.
            // `validate_metric_key` already refuses these bytes
            // in metric keys; the HELP-side didn't. NUL trips
            // promtool lint / grafana-agent; ESC (0x1B) lets a
            // caller who controls HELP text inject ANSI codes
            // into operator terminals via `avctl` piped
            // `/metrics`. Round-26 F4 widens the substitution to
            // cover DEL (0x7F) and the C1 range (0x80..=0x9F) —
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
    // Round-33 F4: split the key into base + labels first, then apply
    // strict byte checks to the base name only. Label values are
    // enclosed in double quotes by convention (`{stage="worker_queue"}`)
    // so a global `"` ban would panic on every labelled counter
    // registration (see round-14 the labelled-counter tests). The
    // real hazard is a base-name that carries `"` / `\` / `\n` / `\r`
    // / NUL — those would produce unbalanced quotes or split-line
    // output that Prometheus rejects as invalid text exposition.
    // Label values carry their own escape discipline (round-14 F7's
    // `escape_prom_label_value` fires at render time and covers the
    // cross-line bytes there); this validator's job is the base.
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
    // Backslash and double quote are legal inside labels because the
    // render-time escaper handles them.
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

    /// Round-19: HELP text with an embedded newline must be escaped
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

    /// Vicious bug caught in review round 18: `counter()` used to silently
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

    /// Round-26 F4: HELP text escaper substitutes DEL (0x7F) and every
    /// C1 control (0x80..=0x9F) with a literal space. Round-20/21
    /// hardened C0 already; C1 was left through and CSI (0x9B) is a
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
