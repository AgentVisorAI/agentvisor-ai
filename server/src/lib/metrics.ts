/*
 * Prometheus metrics. Scrapeable at /metrics; the endpoint is gated
 * behind an internal-only allow-list because production metrics leak
 * traffic patterns to whoever can hit them.
 *
 * The Prometheus text format is understood by every scraper (Grafana
 * Cloud, Prometheus, Datadog Agent, VictoriaMetrics, Uptrace, Uptime
 * Kuma) — no vendor lock-in, same $0 free tier story as the rest of
 * the stack.
 */

import { Registry, collectDefaultMetrics, Counter, Histogram } from "prom-client";

// Fresh registry per process so tests can spin up isolated instances.
export const registry = new Registry();

// Node process metrics (heap, event loop lag, GC pauses, RSS…) —
// standard baseline every backend Prometheus target should emit.
collectDefaultMetrics({ register: registry, prefix: "agentvisor_api_" });

// HTTP request counter with method + route + status labels. `route`
// uses Fastify's routerPath so `/api/v1/sessions/:id` is grouped rather
// than exploding cardinality per session id.
export const httpRequestsTotal = new Counter({
  name: "agentvisor_api_http_requests_total",
  help: "HTTP requests handled by the API, labeled by method + route + status class",
  labelNames: ["method", "route", "status"],
  registers: [registry],
});

// Latency histogram — bucket boundaries chosen for a web API's
// operational range (from very-cheap /healthz through the slow argon2
// password verify at ~100 ms up to the tail).
export const httpRequestDurationSeconds = new Histogram({
  name: "agentvisor_api_http_request_duration_seconds",
  help: "HTTP request latency in seconds",
  labelNames: ["method", "route", "status"],
  buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
  registers: [registry],
});

// Cross-instance bus reconnect count — useful signal that Neon or
// whichever managed PG we're on is bouncing our LISTEN socket.
export const pgBusReconnectsTotal = new Counter({
  name: "agentvisor_api_pg_bus_reconnects_total",
  help: "Number of pg LISTEN/NOTIFY reconnect attempts",
  registers: [registry],
});

// Signup/login counters — high-signal for spotting brute-force sprays
// and organic-growth graphs alike.
export const authEventsTotal = new Counter({
  name: "agentvisor_api_auth_events_total",
  help: "Auth events (signup, login, reset-request, reset-confirm) with result",
  labelNames: ["event", "result"],
  registers: [registry],
});
