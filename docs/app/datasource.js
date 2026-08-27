/*
 * AgentVisor AI console. Data source layer.
 *
 * MockDataSource (Northwind Traders fixtures) and ApiDataSource (real API
 * adapter). Choice driven by window.MOCK_MODE from index.html.
 *
 * The mock is dense on purpose: charts need shape, filters need volume,
 * the receipt needs cryptographic detail, sessions need policy links.
 */

(function () {
  "use strict";

  var mockState = {
    session: null,
    // Ed25519 keypair for the mock signing key. Generated once at module
    // load so the "Signature verified" badge on the pitch demo is
    // cryptographically real, not a lie. If Web Crypto doesn't support
    // Ed25519 in this browser we fall back to a placeholder signature and
    // the verify step will honestly report "unsupported curve".
    mockKeyPair: null,
    mockPublicKeyHex: null,
    // Monotonic counter for "Simulate an attack" injected sessions.
    liveAttackSeq: 0,
  };

  var NOW = Date.now();
  var HOUR = 3600000;
  var MIN = 60000;
  function iso(delta) { return new Date(NOW - delta).toISOString(); }
  function isoMinsAgo(m) { return iso(m * MIN); }

  function bytesToHex(bytes) {
    var s = "";
    for (var i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, "0");
    return s;
  }
  function hexToBytes(hex) {
    var out = new Uint8Array(hex.length / 2);
    for (var i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }
  function bytesToB64(bytes) {
    var s = ""; for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }
  function b64ToBytes(b64) {
    var s = atob(b64); var out = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  }

  async function ensureMockKey() {
    if (mockState.mockKeyPair) return;
    try {
      // Fixed demo keypair, NOT a secret. The private key below is
      // intentionally public: this is a mock console signing fake demo
      // data, and pinning the key lets receipts downloaded from the demo
      // verify GREEN ("trusted key") on /verify/, which ships the same
      // public key in its trust anchor list. Anything signed by this key
      // proves nothing except "came from the public demo".
      var DEMO_PRIV_PKCS8_B64 = "MC4CAQAwBQYDK2VwBCIEILgB0YgZaAezId215njwdk9j+ZyR8Kz/gYV2oIQnZh8W";
      var DEMO_PUB_HEX = "573c8f249012fbb08b3d79973411bb93141f32719c86ada25306fde5e59e8d57";
      var priv = await crypto.subtle.importKey(
        "pkcs8", b64ToBytes(DEMO_PRIV_PKCS8_B64), { name: "Ed25519" }, false, ["sign"]);
      var pub = await crypto.subtle.importKey(
        "raw", hexToBytes(DEMO_PUB_HEX), { name: "Ed25519" }, true, ["verify"]);
      mockState.mockKeyPair = { privateKey: priv, publicKey: pub };
      mockState.mockPublicKeyHex = DEMO_PUB_HEX;
    } catch (e) {
      // Browser doesn't support Ed25519. Leave as null. The receipt panel
      // will detect this and honestly say verification isn't available.
      mockState.mockPublicKeyHex = null;
    }
  }
  async function signBodyEd25519(bodyStr) {
    if (!mockState.mockKeyPair) return null;
    var enc = new TextEncoder().encode(bodyStr);
    var sig = await crypto.subtle.sign("Ed25519", mockState.mockKeyPair.privateKey, enc);
    return bytesToB64(new Uint8Array(sig));
  }

  // Publicly exposed verifier so app.js can produce the real green/red badge
  // instead of a hardcoded string. Cached results per (pubKey, sig, body)
  // so re-rendering a session doesn't re-run the crypto. Cache key uses the
  // full sig + a SHA-256 digest of the body so a one-byte flip anywhere
  // still produces a miss.
  var verifyCache = new Map();
  async function _cacheKey(pub, sig, body) {
    var digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(body));
    return pub + "|" + sig + "|" + bytesToHex(new Uint8Array(digest));
  }
  async function verifyReceiptSignature(publicKeyHex, sigB64, bodyStr) {
    if (!publicKeyHex || !sigB64 || !bodyStr) return { supported: false, ok: false };
    var cacheKey;
    try { cacheKey = await _cacheKey(publicKeyHex, sigB64, bodyStr); } catch (e) {}
    if (cacheKey && verifyCache.has(cacheKey)) return verifyCache.get(cacheKey);
    try {
      var pub = await crypto.subtle.importKey("raw", hexToBytes(publicKeyHex), { name: "Ed25519" }, false, ["verify"]);
      var ok = await crypto.subtle.verify("Ed25519", pub, b64ToBytes(sigB64), new TextEncoder().encode(bodyStr));
      var result = { supported: true, ok: !!ok };
      if (cacheKey) verifyCache.set(cacheKey, result);
      return result;
    } catch (e) {
      var errResult = { supported: false, ok: false, error: (e && e.message) || String(e) };
      if (cacheKey) verifyCache.set(cacheKey, errResult);
      return errResult;
    }
  }
  window.avVerifyReceipt = verifyReceiptSignature;


  /* ============================================================
   * ORG + USERS (mock)
   * ============================================================ */

  var MOCK_ORGS = {
    org_northwind: {
      id: "org_northwind",
      name: "Northwind Traders",
      slug: "northwind",
      createdAt: iso(42 * 24 * HOUR),
    },
  };

  var MOCK_MEMBERS = [
    { id: "usr_olivia", userId: "usr_olivia", email: "olivia.tan@northwind.com", displayName: "Olivia Tan", role: "owner", lastActive: iso(2 * MIN) },
    { id: "usr_raj", userId: "usr_raj", email: "raj.patel@northwind.com", displayName: "Raj Patel", role: "admin", lastActive: iso(18 * MIN) },
    { id: "usr_sam", userId: "usr_sam", email: "sam.lee@northwind.com", displayName: "Sam Lee", role: "member", lastActive: iso(4 * HOUR) },
    { id: "usr_priya", userId: "usr_priya", email: "priya.iyer@northwind.com", displayName: "Priya Iyer", role: "member", lastActive: iso(2 * 24 * HOUR) },
    { id: "usr_marc", userId: "usr_marc", email: "marc.dubois@northwind.com", displayName: "Marc Dubois", role: "member", lastActive: iso(6 * 24 * HOUR) },
  ];

  var MOCK_INVITES = [
    { id: "inv_kate", email: "kate.chen@northwind.com", role: "admin", invitedByEmail: "olivia.tan@northwind.com", expiresAt: iso(-5 * 24 * HOUR), createdAt: iso(2 * 24 * HOUR) },
  ];

  var MOCK_API_KEYS = [
    { id: "key_ci", name: "CI runner", createdAt: iso(14 * 24 * HOUR), lastUsedAt: iso(28 * MIN), hint: "av_srv_a091…" },
    { id: "key_ops", name: "Ops dashboard", createdAt: iso(3 * 24 * HOUR), lastUsedAt: iso(6 * HOUR), hint: "av_srv_c412…" },
  ];

  var MOCK_WEBHOOKS = [
    {
      id: "wh_slack_ops",
      name: "Slack #ops",
      url: "https://hooks.slack.com/services/T5H2G3F/B7Q9R2X/vgFKm2XQ3s",
      events: ["policy.block", "webhook.test_fired"],
      isActive: true,
      createdAt: iso(21 * 24 * HOUR),
      updatedAt: iso(2 * 24 * HOUR),
    },
    {
      id: "wh_pd_oncall",
      name: "PagerDuty on-call",
      url: "https://events.pagerduty.com/v2/enqueue",
      events: ["policy.block"],
      isActive: true,
      createdAt: iso(10 * 24 * HOUR),
      updatedAt: iso(4 * 24 * HOUR),
    },
    {
      id: "wh_dd_events",
      name: "Datadog events",
      url: "https://api.datadoghq.com/api/v1/events",
      events: ["*"],
      isActive: false,
      createdAt: iso(45 * 24 * HOUR),
      updatedAt: iso(12 * 24 * HOUR),
    },
  ];

  /* ============================================================
   * DEPLOYMENTS
   * ============================================================ */

  var MOCK_DEPLOYMENTS = [
    {
      id: "dep_prod",
      orgId: "org_northwind",
      name: "northwind-prod",
      environment: "production",
      region: "us-east-1",
      status: "connected",
      version: "0.4.2",
      lastSeenAt: iso(1 * MIN),
      createdAt: iso(38 * 24 * HOUR),
      ingestTokenHint: "av_live_9HpD…",
      publicKeyHex: "573c8f249012fbb08b3d79973411bb93141f32719c86ada25306fde5e59e8d57",
      keyFingerprint: "kf_573c8f24",
      sessions24h: 18,
      spend24h: "$0.62",
    },
    {
      id: "dep_stage",
      orgId: "org_northwind",
      name: "northwind-staging",
      environment: "staging",
      region: "us-east-1",
      status: "connected",
      version: "0.4.2",
      lastSeenAt: iso(4 * MIN),
      createdAt: iso(38 * 24 * HOUR),
      ingestTokenHint: "av_live_7bK2…",
      publicKeyHex: "8c9b0a1e2f3d4c5b6a7e8f9d0c1b2a3e3a5f7e2d1b8c9a4e6f1d2c3b4a5e6f7d",
      keyFingerprint: "kf_8c9b0a1e",
      sessions24h: 9,
      spend24h: "$0.14",
    },
    {
      id: "dep_dev",
      orgId: "org_northwind",
      name: "northwind-dev",
      environment: "development",
      region: "eu-west-1",
      status: "connected",
      version: "0.4.1",
      lastSeenAt: iso(38 * MIN),
      createdAt: iso(11 * 24 * HOUR),
      ingestTokenHint: "av_live_3xF9…",
      publicKeyHex: "1e2f3d4c5b6a7e8f9d0c1b2a3e3a5f7e2d1b8c9a4e6f1d2c3b4a5e6f7d8c9b0a1",
      keyFingerprint: "kf_1e2f3d4c",
      sessions24h: 3,
      spend24h: "$0.02",
    },
  ];

  /* ============================================================
   * POLICIES
   * ============================================================ */

  var MOCK_POLICIES = [
    {
      id: "pol_procurement_allowed_vendors",
      name: "procurement.allowed_vendors",
      kind: "allowlist",
      scope: "tool.create_purchase_order",
      enabled: true,
      hits24h: 41,
      blocks24h: 3,
      updatedAt: iso(5 * 24 * HOUR),
      updatedBy: "raj.patel@northwind.com",
      description: "Only pre-approved vendors may receive purchase orders.",
      body: [
        "policy \"procurement.allowed_vendors\" {",
        "  applies_to = tool(\"create_purchase_order\")",
        "  when { arg.vendor not in [\"Contoso\", \"AdventureWorks\", \"Fabrikam\"] }",
        "  effect = block",
        "  reason = \"Vendor {{arg.vendor}} not in procurement allowlist.\"",
        "}",
      ].join("\n"),
    },
    {
      id: "pol_runtime_write_scope",
      name: "runtime.write_scope",
      kind: "guardrail",
      scope: "tool.*",
      enabled: true,
      hits24h: 118,
      blocks24h: 0,
      updatedAt: iso(11 * 24 * HOUR),
      updatedBy: "olivia.tan@northwind.com",
      description: "Only tools tagged 'write' may mutate systems of record.",
      body: [
        "policy \"runtime.write_scope\" {",
        "  applies_to = tool(\"*\")",
        "  when { tool.tag == \"write\" and session.trust_level < 2 }",
        "  effect = require_human_approval",
        "  reason = \"Write-tier tools require a reviewer at trust < 2.\"",
        "}",
      ].join("\n"),
    },
    {
      id: "pol_rate_per_session_usd",
      name: "rate.per_session_usd:10",
      kind: "budget",
      scope: "session",
      enabled: true,
      hits24h: 27,
      blocks24h: 0,
      updatedAt: iso(3 * 24 * HOUR),
      updatedBy: "olivia.tan@northwind.com",
      description: "Cap total LLM + tool payout per session at $10 USD.",
      body: [
        "policy \"rate.per_session_usd:10\" {",
        "  applies_to = session",
        "  when { session.cost_usd > 10.00 }",
        "  effect = seal",
        "  reason = \"Session exceeded $10 budget.\"",
        "}",
      ].join("\n"),
    },
    {
      id: "pol_pii_redaction",
      name: "runtime.pii_redaction",
      kind: "transform",
      scope: "llm.request",
      enabled: true,
      hits24h: 218,
      blocks24h: 0,
      updatedAt: iso(19 * 24 * HOUR),
      updatedBy: "raj.patel@northwind.com",
      description: "Redact SSN / card / IBAN patterns from prompts before egress.",
      body: [
        "policy \"runtime.pii_redaction\" {",
        "  applies_to = llm.request",
        "  transform = redact([\"ssn\", \"credit_card\", \"iban\"])",
        "  effect = allow_after_transform",
        "}",
      ].join("\n"),
    },
    {
      id: "pol_egress_allowlist",
      name: "network.egress_allowlist",
      kind: "allowlist",
      scope: "tool.http_request",
      enabled: true,
      hits24h: 62,
      blocks24h: 1,
      updatedAt: iso(9 * 24 * HOUR),
      updatedBy: "priya.iyer@northwind.com",
      description: "Restrict outbound HTTP to approved hostnames.",
      body: [
        "policy \"network.egress_allowlist\" {",
        "  applies_to = tool(\"http_request\")",
        "  when { arg.url.host not in vault(\"approved_hosts\") }",
        "  effect = block",
        "  reason = \"Egress to {{arg.url.host}} not in allowlist.\"",
        "}",
      ].join("\n"),
    },
    {
      id: "pol_prompt_injection",
      name: "runtime.prompt_injection_guard",
      kind: "guardrail",
      scope: "llm.request",
      enabled: false,
      hits24h: 0,
      blocks24h: 0,
      updatedAt: iso(28 * 24 * HOUR),
      updatedBy: "raj.patel@northwind.com",
      description: "Detect prompt-injection patterns in tool results before feeding to the model. Disabled: waiting on false-positive threshold tuning.",
      body: [
        "policy \"runtime.prompt_injection_guard\" {",
        "  applies_to = tool_result",
        "  when { classifier(\"prompt_injection\") > 0.75 }",
        "  effect = block",
        "}",
      ].join("\n"),
    },
  ];

  /* ============================================================
   * SESSIONS (denser corpus for filters)
   * ============================================================ */

  var AGENTS = [
    { name: "supply-planner", user: "olivia.tan@northwind.com", model: "gpt-4o" },
    { name: "returns-triage", user: "raj.patel@northwind.com", model: "gpt-4o-mini" },
    { name: "vendor-onboarding", user: "priya.iyer@northwind.com", model: "claude-3-5-sonnet" },
    { name: "customer-emailer", user: "sam.lee@northwind.com", model: "gpt-4o-mini" },
    { name: "invoice-reconciler", user: "marc.dubois@northwind.com", model: "gpt-4o" },
  ];

  function generateMockSessions() {
    // 32 sessions across the last 24h, with a small blocked pool for a
    // meaningful bar chart and a filterable "blocked-only" view.
    var rng = mulberry32(42);
    var out = [];
    var blockedIdxs = { 0: 1, 6: 2, 11: 1, 17: 1, 22: 1, 28: 1 };
    for (var i = 0; i < 32; i++) {
      var agent = AGENTS[Math.floor(rng() * AGENTS.length)];
      var dep = MOCK_DEPLOYMENTS[Math.floor(rng() * 3)];
      var mins = Math.floor(rng() * 24 * 60);
      var events = 12 + Math.floor(rng() * 30);
      var allowed = Math.floor(events * 0.35 + rng() * 3);
      var blocked = blockedIdxs[i] || 0;
      var cost = Math.floor(30000 + rng() * 200000);
      var blockedValue = blocked > 0 ? Math.floor((1000 + rng() * 8000) * 1e6) : 0;
      out.push({
        id: "sess_" + (i === 0 ? "01H9K" : ("s" + (100 + i))),
        externalId: i === 0 ? "sess_01H9K7GRPX" : ("sess_" + rngHex(rng, 10)).toUpperCase(),
        deploymentId: dep.id,
        deploymentName: dep.name,
        agent: agent.name,
        user: agent.user,
        model: agent.model,
        status: rng() < 0.02 ? "in_progress" : "completed",
        startedAt: isoMinsAgo(mins + Math.floor(events / 6)),
        endedAt: isoMinsAgo(Math.max(0, mins - Math.floor(events / 12))),
        events: events,
        toolsAllowed: allowed,
        toolsBlocked: blocked,
        costUsdMicros: String(cost),
        payoutUsdMicros: String(cost),
        blockedPayoutUsdMicros: String(blockedValue),
        receiptHash: "sha256:" + rngHex(rng, 12) + "…",
        policiesFired: blocked > 0 ? ["pol_procurement_allowed_vendors"] : [],
      });
    }
    // Make the featured session the biggest blocked-value story.
    out[0].externalId = "sess_01H9K7GRPX";
    out[0].agent = "supply-planner";
    out[0].user = "olivia.tan@northwind.com";
    out[0].model = "gpt-4o";
    out[0].deploymentId = "dep_prod";
    out[0].deploymentName = "northwind-prod";
    out[0].startedAt = isoMinsAgo(6);
    out[0].endedAt = isoMinsAgo(2);
    out[0].events = 42;
    out[0].toolsAllowed = 18;
    out[0].toolsBlocked = 1;
    out[0].costUsdMicros = "184000";
    out[0].payoutUsdMicros = "184000";
    out[0].blockedPayoutUsdMicros = "8400000000";
    out[0].receiptHash = "sha256:90db55…";
    out[0].policiesFired = ["pol_procurement_allowed_vendors"];

    out.sort(function (a, b) { return new Date(b.startedAt) - new Date(a.startedAt); });
    return out;
  }

  function mulberry32(a) {
    return function () {
      var t = (a += 0x6d2b79f5);
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
  function rngHex(rng, n) {
    var s = "";
    while (s.length < n) s += Math.floor(rng() * 16).toString(16);
    return s.slice(0, n);
  }

  var MOCK_SESSIONS = generateMockSessions();

  /* ============================================================
   * TIMESERIES for charts
   * ============================================================ */

  function bucketSessions(range) {
    // Range → bucket count / span. All are sensible for the fixture size.
    var spec = {
      "1h":  { bucketMs: 60000, count: 60, fmt: function (d) { return d.getHours().toString().padStart(2, "0") + ":" + d.getMinutes().toString().padStart(2, "0"); } },
      "24h": { bucketMs: HOUR, count: 24, fmt: function (d) { return d.getHours().toString().padStart(2, "0") + ":00"; } },
      "7d":  { bucketMs: 24 * HOUR, count: 7, fmt: function (d) { return ["Sun","Mon","Tue","Wed","Thu","Fri","Sat"][d.getDay()]; } },
      "30d": { bucketMs: 24 * HOUR, count: 30, fmt: function (d) { return (d.getMonth() + 1) + "/" + d.getDate(); } },
    }[range] || { bucketMs: HOUR, count: 24, fmt: function (d) { return d.getHours() + ":00"; } };

    // Anchor buckets to the wall clock, not the module-load NOW —
    // sessions injected after page load (simulateAttack) must land in
    // the current bucket instead of falling off the end of the series.
    var now = Date.now();
    var buckets = new Array(spec.count).fill(0).map(function () {
      return { t: 0, allowed: 0, blocked: 0, spendUsd: 0, blockedValueUsd: 0, label: "" };
    });
    for (var i = 0; i < spec.count; i++) {
      var d = new Date(now - (spec.count - 1 - i) * spec.bucketMs);
      buckets[i].t = d.toISOString();
      buckets[i].label = spec.fmt(d);
    }
    // For ranges longer than the fixture spans, we probabilistically extend the
    // signal so the chart isn't all zeros. The fixture only covers ~24h.
    MOCK_SESSIONS.forEach(function (s) {
      var t = new Date(s.startedAt).getTime();
      var age = now - t;
      var idx = spec.count - 1 - Math.floor(age / spec.bucketMs);
      if (idx < 0 || idx > spec.count - 1) return;
      buckets[idx].allowed += s.toolsAllowed;
      buckets[idx].blocked += s.toolsBlocked;
      buckets[idx].spendUsd += parseInt(s.costUsdMicros, 10) / 1e6;
      buckets[idx].blockedValueUsd += parseInt(s.blockedPayoutUsdMicros, 10) / 1e6;
    });
    // Simulate historical activity for 7d/30d so the demo isn't sparse.
    if (spec.count >= 7 && spec.bucketMs >= 24 * HOUR) {
      var rng = mulberry32(range === "30d" ? 31 : 71);
      for (var b = 0; b < spec.count - 1; b++) {
        buckets[b].allowed += Math.floor(20 + rng() * 90);
        buckets[b].blocked += Math.floor(rng() * 3);
        buckets[b].spendUsd += 0.4 + rng() * 3;
        buckets[b].blockedValueUsd += rng() < 0.15 ? Math.floor(500 + rng() * 4000) : 0;
      }
    }
    return buckets;
  }
  var MOCK_SERIES = bucketSessions("24h");

  /* ============================================================
   * FEATURED EVENT STREAM (with prompts & durations)
   * ============================================================ */

  var MOCK_EVENTS_FEATURED = [
    {
      seq: 1, ts: isoMinsAgo(6), kind: "session", tag: "start",
      msg: "Session opened",
      sub: "agent=supply-planner  user=olivia.tan@northwind.com",
      severity: "info", durationMs: 0,
    },
    {
      seq: 2, ts: isoMinsAgo(6), kind: "llm", tag: "request",
      msg: "gpt-4o · 812 tokens in",
      sub: "prompt hash = 0x7f2a…",
      severity: "info", durationMs: 1204,
      details: {
        model: "gpt-4o",
        promptTokens: 812,
        prompt: "System: You are the Northwind supply-planning agent. Reorder low-stock SKUs.\n\nUser: Check inventory for SKU NW-1240 and place a purchase order if we're under safety stock.",
        response: "I'll first check current inventory levels for NW-1240 with search_inventory.",
      },
    },
    {
      seq: 3, ts: isoMinsAgo(6), kind: "tool", tag: "call",
      msg: "search_inventory(sku=\"NW-1240\")",
      severity: "info", durationMs: 128,
    },
    {
      seq: 4, ts: isoMinsAgo(6), kind: "guard", tag: "TOOL ✓ allow",
      msg: "Read-only tool · budget $0.02 / $10.00",
      sub: "policy=runtime.write_scope",
      severity: "ok", durationMs: 3,
      policyId: "pol_runtime_write_scope",
    },
    {
      seq: 5, ts: isoMinsAgo(5), kind: "tool", tag: "result",
      msg: "inventory returned 4 rows in 128 ms",
      sub: "on-hand=12  safety=50  reorder_qty=100",
      severity: "info", durationMs: 128,
    },
    {
      seq: 6, ts: isoMinsAgo(5), kind: "llm", tag: "request",
      msg: "gpt-4o · 1,204 tokens in",
      severity: "info", durationMs: 942,
      details: {
        model: "gpt-4o",
        promptTokens: 1204,
        prompt: "…prior tool result…\n\nUser: Place a purchase order with NexusParts for 100 units at $84 each.",
        response: "I'll call create_purchase_order for vendor NexusParts, 100 units at $84.",
      },
    },
    {
      seq: 7, ts: isoMinsAgo(5), kind: "tool", tag: "call",
      msg: "create_purchase_order(vendor=\"NexusParts\", total=$8,400)",
      severity: "info", durationMs: 4,
    },
    {
      seq: 8, ts: isoMinsAgo(5), kind: "block", tag: "BLOCKED",
      msg: "Vendor \"NexusParts\" not in procurement allowlist",
      sub: "policy=procurement.allowed_vendors · would-have-spent=$8,400",
      severity: "err", durationMs: 6,
      policyId: "pol_procurement_allowed_vendors",
      blockedValueUsd: 8400,
    },
    {
      seq: 9, ts: isoMinsAgo(5), kind: "llm", tag: "request",
      msg: "gpt-4o · retry with an allowed vendor",
      severity: "info", durationMs: 1102,
      details: {
        model: "gpt-4o",
        promptTokens: 1451,
        prompt: "…prior block…\n\nSystem: NexusParts not allowed. Choose from: Contoso, AdventureWorks, Fabrikam.\n\nAssistant: Retrying with Contoso.",
        response: "Retrying with Contoso as the vendor.",
      },
    },
    {
      seq: 10, ts: isoMinsAgo(4), kind: "tool", tag: "call",
      msg: "create_purchase_order(vendor=\"Contoso\", total=$8,400)",
      severity: "info", durationMs: 4,
    },
    {
      seq: 11, ts: isoMinsAgo(4), kind: "guard", tag: "TOOL ✓ allow",
      msg: "Allowlist ✓ · budget check ✓ · human approval not required",
      sub: "policies=procurement.allowed_vendors, rate.per_session_usd:10",
      severity: "ok", durationMs: 8,
      policyId: "pol_procurement_allowed_vendors",
    },
    {
      seq: 12, ts: isoMinsAgo(4), kind: "tool", tag: "result",
      msg: "PO #29841 created · $8,400",
      severity: "info", durationMs: 314,
    },
    {
      seq: 13, ts: isoMinsAgo(2), kind: "session", tag: "end",
      msg: "Sealed · 42 events · receipt sha256:90db55…",
      severity: "ok", durationMs: 0,
    },
  ];

  var MOCK_RECEIPT_FEATURED = {
    schemaVersion: "1.0",
    receiptId: "rcpt_01H9K7GRPX_finalized",
    sessionId: "sess_01H9K7GRPX",
    orgId: "org_northwind",
    deploymentId: "dep_prod",
    startedAt: isoMinsAgo(6),
    endedAt: isoMinsAgo(2),
    eventCount: 42,
    tools: { allowed: 18, blocked: 1 },
    spend: { llmUsdMicros: "184000", blockedActionsUsdMicros: "8400000000" },
    policiesEnforced: [
      "procurement.allowed_vendors",
      "runtime.write_scope",
      "rate.per_session_usd:10",
      "runtime.pii_redaction",
    ],
    contentHash: "sha256:90db551a2a7330b4aeeead934c8fc584da8f70a659e91a489a0fb0b331467baf",
    signature: "ed25519:LmZk3TpJ2r0aQxvXbYc7WdRnSfE1UgHkO0pIiV8mAcNyBt6Zh4uFj9zKlP+g/ExampleSignature==",
    signingKeyFingerprint: "kf_3a5f7e2d1b8c9a4e",
    verificationStatus: "verified",
  };

  /* ============================================================
   * AUDIT LOG
   * ============================================================ */

  var MOCK_AUDIT = [
    { at: iso(8 * MIN), actor: "raj.patel@northwind.com", event: "policy.updated", target: "procurement.allowed_vendors", note: "Added Fabrikam to vendor allowlist." },
    { at: iso(2 * HOUR), actor: "olivia.tan@northwind.com", event: "member.role_changed", target: "sam.lee@northwind.com", note: "member → viewer" },
    { at: iso(6 * HOUR), actor: "system", event: "deployment.token_rotated", target: "northwind-prod" },
    { at: iso(1 * 24 * HOUR), actor: "olivia.tan@northwind.com", event: "policy.created", target: "runtime.pii_redaction" },
    { at: iso(3 * 24 * HOUR), actor: "olivia.tan@northwind.com", event: "settings.sso_configured", target: "google-workspace" },
    { at: iso(11 * 24 * HOUR), actor: "olivia.tan@northwind.com", event: "org.created", target: "Northwind Traders" },
  ];

  // Northwind's Okta SAML config. Realistic-looking sample so the settings
  // page feels populated in the pitch demo.
  var MOCK_SAML_CONFIGS = [
    {
      id: "saml_okta_prod",
      displayName: "Okta production",
      ssoUrl: "https://northwind.okta.com/app/agentvisor_prod_1/sso/saml",
      sloUrl: "https://northwind.okta.com/app/agentvisor_prod_1/slo/saml",
      entityIdIdp: "http://www.okta.com/exkA1B2C3D4E5F6G7H8",
      x509Cert: "-----BEGIN CERTIFICATE-----\nMIIDpDCCAoygAwIBAgIGAX0EXAMPLE\n...(truncated)...\n-----END CERTIFICATE-----",
      wantAssertionsSigned: true,
      wantResponseSigned: false,
      allowEncryptedAssertions: true,
      signatureAlgorithm: "sha256",
      digestAlgorithm: "sha256",
      nameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
      jitEnabled: true,
      jitDefaultRole: "member",
      allowedDomains: "northwind.com,northwind-traders.com",
      isActive: true,
      hasSpKeypair: true,
      spCertPem: "-----BEGIN CERTIFICATE-----\nMIIDazCCAlOgAwIBAgIUX9c5\n...(truncated)...\n-----END CERTIFICATE-----",
      spEntityId: "https://agentvisorai.me/api/v1/auth/saml/saml_okta_prod",
      spAcsUrl: "https://agentvisorai.me/api/v1/auth/saml/saml_okta_prod/acs",
      spSloUrl: "https://agentvisorai.me/api/v1/auth/saml/saml_okta_prod/slo",
      spLoginUrl: "https://agentvisorai.me/api/v1/auth/saml/saml_okta_prod/login",
      spMetadataUrl: "https://agentvisorai.me/api/v1/auth/saml/saml_okta_prod/metadata.xml",
      x509CertFingerprint: "d4:3f:6a:b2:81:29:57:83:19:04:af:c3:76:98:ea:d5:78:14:5c:7d",
      createdAt: iso(20 * 24 * HOUR),
      updatedAt: iso(3 * 24 * HOUR),
    },
  ];

  var MOCK_PASSKEYS = [
    {
      id: "pk_yubikey",
      label: "Zach's YubiKey 5C",
      transports: ["usb", "nfc"],
      aaguid: "6d44ba9b-f6ec-2e49-b930-0c8fe920cb73",
      createdAt: iso(90 * 24 * HOUR),
      lastUsedAt: iso(3 * HOUR),
    },
    {
      id: "pk_iphone",
      label: "iPhone 15 Pro",
      transports: ["internal", "hybrid"],
      aaguid: null,
      createdAt: iso(21 * 24 * HOUR),
      lastUsedAt: iso(2 * 24 * HOUR),
    },
  ];

  /* ============================================================
   * OVERVIEW
   * ============================================================ */

  /* ── FRESH-WORKSPACE SIMULATION (first-user story) ───────────
   * When av_mock_fresh_t0 is set (by signup), the org starts empty:
   * no deployments until the daemon "connects" (FRESH_CONNECT_MS),
   * then the first sessions stream in one at a time. The featured
   * blocked session arrives second, bringing the first $8,400 save.
   * The demo auto-signin clears the flag, so /app/ visitors still
   * get the full showcase data. */
  var FRESH_CONNECT_MS = 12000;
  var FRESH_SESSION_AT = [16000, 21000, 26000];
  function freshElapsed() {
    try {
      var v = localStorage.getItem("av_mock_fresh_t0");
      return v ? Date.now() - +v : null;
    } catch (e) { return null; }
  }
  function freshSessions() {
    var el = freshElapsed();
    if (el == null) return null;
    var t0 = Date.now() - el;
    // clean first, then the featured block, then one more
    var order = [MOCK_SESSIONS[3], MOCK_SESSIONS[0], MOCK_SESSIONS[4]];
    var out = [];
    for (var i = 0; i < FRESH_SESSION_AT.length; i++) {
      if (el >= FRESH_SESSION_AT[i] && order[i]) {
        var s = Object.assign({}, order[i]);
        // Times must read "just arrived", and receipts sign these
        // values live, so display and signature stay consistent.
        s.startedAt = new Date(t0 + FRESH_SESSION_AT[i] - 45000).toISOString();
        s.endedAt = new Date(t0 + FRESH_SESSION_AT[i] - 4000).toISOString();
        out.push(s);
      }
    }
    out.sort(function (a, b) { return new Date(b.startedAt) - new Date(a.startedAt); });
    return out;
  }
  function freshPolicy(pol) {
    var el = freshElapsed();
    if (el == null) return pol;
    var out = Object.assign({}, pol);
    var t0 = Date.now() - el;
    out.updatedAt = new Date(t0 + 2000).toISOString();
    var sess = freshSessions() || [];
    var blocked = sess.some(function (s) { return s.toolsBlocked > 0; });
    if (out.id === "pol_procurement_allowed_vendors") {
      out.hits24h = blocked ? 2 : 0;
      out.blocks24h = blocked ? 1 : 0;
    } else {
      out.hits24h = Math.min(out.hits24h, sess.length * 9);
      out.blocks24h = 0;
    }
    return out;
  }

  function freshDeployments() {
    var el = freshElapsed();
    if (el == null) return null;
    if (el < FRESH_CONNECT_MS) return [];
    var d = Object.assign({}, MOCK_DEPLOYMENTS[0]);
    d.lastSeenAt = new Date(Date.now() - 5000).toISOString();
    d.createdAt = new Date(Date.now() - el).toISOString();
    var fs = freshSessions() || [];
    d.sessions24h = fs.length;
    d.spend24h = "$" + fs.reduce(function (a, s) { return a + (+s.costUsdMicros || 0) / 1e6; }, 0).toFixed(2);
    return [d];
  }
  function freshOverview(range) {
    var sess = freshSessions() || [];
    var deps = freshDeployments() || [];
    var series = bucketSessions(range || "24h");
    series.forEach(function (b) { b.allowed = 0; b.blocked = 0; b.spendUsd = 0; b.blockedValueUsd = 0; });
    var last = series[series.length - 1];
    sess.forEach(function (s) {
      last.allowed += s.toolsAllowed;
      last.blocked += s.toolsBlocked;
      last.spendUsd += (+s.costUsdMicros || 0) / 1e6;
      last.blockedValueUsd += (+s.blockedPayoutUsdMicros || 0) / 1e6;
    });
    return {
      period: range || "24h",
      sessions: sess.length,
      events: sess.reduce(function (a, s) { return a + s.events; }, 0),
      toolsAllowed: last.allowed,
      toolsBlocked: last.blocked,
      llmSpendUsd: last.spendUsd.toFixed(2),
      blockedSpendUsd: last.blockedValueUsd.toFixed(0),
      deployments: deps.length,
      deploymentsHealthy: deps.filter(function (d) { return d.status === "connected"; }).length,
      series: series,
    };
  }

  function mockOverview(range) {
    var series = bucketSessions(range || "24h");
    var sessions24h = MOCK_SESSIONS.length;
    // For long ranges, boost the top-line KPIs to match the extended series.
    var boost = { "1h": 0.04, "24h": 1, "7d": 6.2, "30d": 24.5 }[range || "24h"] || 1;
    return {
      period: range || "24h",
      sessions: Math.round(sessions24h * boost),
      events: Math.round(MOCK_SESSIONS.reduce(function (a, s) { return a + s.events; }, 0) * boost),
      toolsAllowed: series.reduce(function (a, b) { return a + b.allowed; }, 0),
      toolsBlocked: series.reduce(function (a, b) { return a + b.blocked; }, 0),
      llmSpendUsd: series.reduce(function (a, b) { return a + b.spendUsd; }, 0).toFixed(2),
      blockedSpendUsd: series.reduce(function (a, b) { return a + b.blockedValueUsd; }, 0).toFixed(0),
      deployments: MOCK_DEPLOYMENTS.length,
      deploymentsHealthy: MOCK_DEPLOYMENTS.filter(function (d) { return d.status === "connected"; }).length,
      series: series,
    };
  }

  function delay(ms) {
    // Video-recording aid: av_mock_fastload collapses the simulated
    // network latency so re-renders never flash skeletons on camera.
    // Never set in normal browsing.
    try { if (localStorage.getItem("av_mock_fastload")) ms = Math.min(ms, 15); } catch (e) {}
    return new Promise(function (r) { setTimeout(r, ms); });
  }

  function synthesizeEvents(s) {
    var out = [
      { seq: 1, ts: s.startedAt, kind: "session", tag: "start", msg: s.agent + " opened session", severity: "info", durationMs: 0 },
    ];
    var n = Math.min(s.events - 2, 12);
    for (var i = 2; i < 2 + n; i++) {
      var isTool = i % 3 === 0;
      out.push({
        seq: i,
        ts: s.startedAt,
        kind: isTool ? "tool" : "llm",
        tag: isTool ? "call" : "request",
        msg: isTool ? "search_inventory()" : (s.model + " · " + (400 + i * 30) + " tokens"),
        severity: "info",
        durationMs: isTool ? 90 + Math.floor(i * 12) : 300 + Math.floor(i * 40),
      });
    }
    if (s.toolsBlocked > 0) {
      out.push({
        seq: 2 + n, ts: s.endedAt, kind: "block", tag: "BLOCKED",
        msg: "Vendor not in allowlist",
        severity: "err", durationMs: 6,
        policyId: "pol_procurement_allowed_vendors",
      });
    }
    out.push({
      seq: 2 + n + 1, ts: s.endedAt, kind: "session", tag: "end",
      msg: "Sealed · " + s.events + " events",
      severity: "ok", durationMs: 0,
    });
    return out;
  }

  /* ============================================================
   * MOCK DATASOURCE
   * ============================================================ */

  var MockDataSource = {
    mode: "mock",
    async getSession() {
      try { if (localStorage.getItem("av_mock_signed_out") === "1") return null; } catch (e) {}
      if (!mockState.session) {
        mockState.session = {
          user: { id: "usr_olivia", email: "olivia.tan@northwind.com", displayName: "Olivia Tan" },
          org: MOCK_ORGS.org_northwind,
        };
      }
      return mockState.session;
    },
    async signup(input) {
      await delay(400);
      try {
        localStorage.removeItem("av_mock_signed_out");
        // First-user story: a brand-new workspace starts EMPTY, the
        // first deployment connects after the install step, and the
        // first sessions stream in after that (see FRESH_* below).
        localStorage.setItem("av_mock_fresh_t0", String(Date.now()));
      } catch (e) {}
      mockState.session = {
        user: { id: "usr_new", email: input.email, displayName: input.email.split("@")[0] },
        org: MOCK_ORGS.org_northwind,
      };
      return mockState.session;
    },
    async login(input) {
      await delay(400);
      try {
        localStorage.removeItem("av_mock_signed_out");
        localStorage.removeItem("av_mock_fresh_t0");
      } catch (e) {}
      mockState.session = {
        user: { id: "usr_new", email: input.email, displayName: input.email.split("@")[0] },
        org: MOCK_ORGS.org_northwind,
      };
      return mockState.session;
    },
    async loginWithProvider(provider) {
      await delay(500);
      try { localStorage.removeItem("av_mock_signed_out"); } catch (e) {}
      mockState.session = {
        user: { id: "usr_olivia", email: "olivia.tan@northwind.com", displayName: "Olivia Tan" },
        org: MOCK_ORGS.org_northwind,
      };
      return mockState.session;
    },
    // Mock mode: pretend all providers are configured so investors see the buttons.
    async getSSO() {
      return { providers: [
        { id: "google", displayName: "Google" },
        { id: "microsoft", displayName: "Microsoft" },
      ] };
    },
    async discoverSaml(_email) { return { ssoConfig: null }; },
    async listSamlConfigs() {
      if (freshElapsed() != null) return { configs: [] };
      return { configs: MOCK_SAML_CONFIGS.slice() };
    },
    async createSamlConfig(input) {
      var cfg = Object.assign({
        id: "saml_" + Math.random().toString(36).slice(2, 8),
        sloUrl: null,
        wantAssertionsSigned: true,
        wantResponseSigned: false,
        allowEncryptedAssertions: true,
        signatureAlgorithm: "sha256",
        digestAlgorithm: "sha256",
        nameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        jitEnabled: true,
        jitDefaultRole: "member",
        allowedDomains: "",
        isActive: true,
        hasSpKeypair: false,
        spCertPem: null,
        spEntityId: "https://mock/api/v1/auth/saml/new",
        spAcsUrl: "https://mock/api/v1/auth/saml/new/acs",
        spSloUrl: "https://mock/api/v1/auth/saml/new/slo",
        spLoginUrl: "https://mock/api/v1/auth/saml/new/login",
        spMetadataUrl: "https://mock/api/v1/auth/saml/new/metadata.xml",
        x509CertFingerprint: "de:mo:fp",
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      }, input);
      MOCK_SAML_CONFIGS.push(cfg);
      return { config: cfg };
    },
    async updateSamlConfig(id, input) {
      var i = MOCK_SAML_CONFIGS.findIndex(function (c) { return c.id === id; });
      if (i < 0) throw new Error("not_found");
      MOCK_SAML_CONFIGS[i] = Object.assign({}, MOCK_SAML_CONFIGS[i], input, { updatedAt: new Date().toISOString() });
      return { config: MOCK_SAML_CONFIGS[i] };
    },
    async deleteSamlConfig(id) {
      MOCK_SAML_CONFIGS = MOCK_SAML_CONFIGS.filter(function (c) { return c.id !== id; });
    },
    async regenerateSamlSpKeypair(id) {
      var i = MOCK_SAML_CONFIGS.findIndex(function (c) { return c.id === id; });
      if (i < 0) throw new Error("not_found");
      MOCK_SAML_CONFIGS[i] = Object.assign({}, MOCK_SAML_CONFIGS[i], {
        hasSpKeypair: true,
        spCertPem: "-----BEGIN CERTIFICATE-----\nMIIDazCCAlOgAwIBAgIUX9c5\n...(mock)...\n-----END CERTIFICATE-----",
      });
      return { config: MOCK_SAML_CONFIGS[i], spCertPem: MOCK_SAML_CONFIGS[i].spCertPem };
    },
    // Mock passkeys. A fake yubikey + a fake iCloud passkey so the
    // settings page in the demo looks real.
    async webauthnListCredentials() {
      if (freshElapsed() != null) return { credentials: [] };
      return { credentials: MOCK_PASSKEYS.slice() };
    },
    async webauthnRegisterStart() { throw new Error("mock_no_real_authenticator"); },
    async webauthnRegisterFinish() { throw new Error("mock_no_real_authenticator"); },
    async webauthnRevoke(id) {
      MOCK_PASSKEYS = MOCK_PASSKEYS.filter(function (p) { return p.id !== id; });
    },
    async webauthnAuthStart() { return { options: { challenge: "mock" }, hasCredential: false }; },
    async webauthnAuthFinish() { throw new Error("mock_no_real_authenticator"); },
    async logout() {
      try { localStorage.setItem("av_mock_signed_out", "1"); } catch (e) {}
      mockState.session = null;
    },
    async requestPasswordReset(input) {
      await delay(500);
      // Store a deterministic mock token in-memory so confirm can verify it.
      mockState.mockResetToken = "mocktok_" + Math.random().toString(36).slice(2, 18);
      mockState.mockResetEmail = input.email;
      return { ok: true, mockToken: mockState.mockResetToken };
    },
    async confirmPasswordReset(input) {
      await delay(400);
      if (!mockState.mockResetToken || input.email !== mockState.mockResetEmail || input.token !== mockState.mockResetToken) {
        var err = new Error("invalid_token"); err.status = 401; throw err;
      }
      mockState.mockResetToken = null;
      mockState.mockResetEmail = null;
      return { ok: true };
    },

    async listDeployments() {
      await delay(120);
      var f = freshDeployments();
      return f !== null ? f : MOCK_DEPLOYMENTS.slice();
    },
    async getDeployment(id) {
      await delay(120);
      var f = freshDeployments();
      if (f !== null) {
        var fd = f.find(function (x) { return x.id === id; });
        if (!fd) throw new Error("not_found");
        return fd;
      }
      var d = MOCK_DEPLOYMENTS.find(function (x) { return x.id === id; });
      if (!d) throw new Error("not_found");
      return d;
    },
    async createDeployment(input) {
      await delay(300);
      var id = "dep_" + Math.random().toString(36).slice(2, 8);
      var token = "av_live_" + Math.random().toString(36).slice(2, 10) + Math.random().toString(36).slice(2, 10);
      var dep = {
        id: id, orgId: "org_northwind",
        name: input.name,
        environment: input.environment || "production",
        region: input.region || "us-east-1",
        status: "pending",
        version: null,
        lastSeenAt: null,
        createdAt: new Date().toISOString(),
        ingestTokenHint: "av_live_" + token.slice(8, 12) + "…",
        publicKeyHex: null,
        keyFingerprint: null,
        sessions24h: 0, spend24h: "$0.00",
      };
      MOCK_DEPLOYMENTS.push(dep);
      return { deployment: dep, ingestToken: token };
    },
    async rotateDeploymentToken(id) {
      await delay(200);
      var token = "av_live_" + Math.random().toString(36).slice(2, 10) + Math.random().toString(36).slice(2, 10);
      var d = MOCK_DEPLOYMENTS.find(function (x) { return x.id === id; });
      if (d) d.ingestTokenHint = "av_live_" + token.slice(8, 12) + "…";
      return { ingestToken: token };
    },
    async deleteDeployment(id) {
      await delay(200);
      var i = MOCK_DEPLOYMENTS.findIndex(function (x) { return x.id === id; });
      if (i >= 0) MOCK_DEPLOYMENTS.splice(i, 1);
    },

    async getOverview(range) {
      await delay(140);
      if (freshElapsed() != null) return freshOverview(range || "24h");
      return mockOverview(range || "24h");
    },

    async listSessions(params) {
      await delay(160);
      params = params || {};
      var fresh = freshSessions();
      var results = fresh !== null ? fresh : MOCK_SESSIONS.slice();
      if (params.deploymentId) results = results.filter(function (s) { return s.deploymentId === params.deploymentId; });
      if (params.agent) results = results.filter(function (s) { return s.agent === params.agent; });
      if (params.blockedOnly) results = results.filter(function (s) { return s.toolsBlocked > 0; });
      if (params.q) {
        var q = params.q.toLowerCase();
        results = results.filter(function (s) {
          return (s.externalId && s.externalId.toLowerCase().indexOf(q) >= 0) ||
                 (s.agent && s.agent.toLowerCase().indexOf(q) >= 0) ||
                 (s.user && s.user.toLowerCase().indexOf(q) >= 0);
        });
      }
      if (params.sinceHours) {
        var cutoff = Date.now() - params.sinceHours * HOUR;
        results = results.filter(function (s) { return new Date(s.startedAt).getTime() >= cutoff; });
      }
      // Mock cursor pagination to match the real API shape. Cursor is
      // the numeric offset serialized. The console renders "Load more"
      // via nextCursor exactly like the api-mode datasource.
      var limit = Math.min((params.limit || 50), 100);
      var offset = 0;
      if (params.cursor) {
        try { offset = parseInt(atob(params.cursor), 10) || 0; } catch (e) { offset = 0; }
      }
      var page = results.slice(offset, offset + limit);
      var nextCursor = (offset + limit) < results.length ? btoa(String(offset + limit)) : null;
      return { sessions: page, nextCursor: nextCursor };
    },
    async getSessionById(id) {
      await delay(180);
      var s = MOCK_SESSIONS.find(function (x) { return x.id === id; });
      if (!s) throw new Error("not_found");
      var events = s._events || (id === "sess_01H9K" ? MOCK_EVENTS_FEATURED : synthesizeEvents(s));
      return { session: s, events: events };
    },

    /* Live-demo aid: stage the blocked-payment story in real time.
     * Injects an in_progress purchase session; ~3 s later the payment
     * gets blocked on camera and the session seals with a custom event
     * trail. Every aggregate (overview stats, charts, policy hit
     * counts) recomputes from MOCK_SESSIONS, so the whole console
     * reacts. Returns the timeline so the UI can pace its toasts. */
    async simulateAttack() {
      var n = ++mockState.liveAttackSeq;
      var value = [4750, 2980, 6200, 1840, 9300][(n - 1) % 5];
      var vendor = ["Apex Supply Co", "Meridian Parts", "BlueRiver Trading", "Quantum Goods", "Vertex Wholesale"][(n - 1) % 5];
      var now = Date.now();
      var s = {
        id: "sess_live" + n,
        externalId: ("sess_live" + rngHex(mulberry32(now % 100000), 8) + n).toUpperCase(),
        deploymentId: "dep_prod",
        deploymentName: "northwind-prod",
        agent: "vendor-onboarding",
        user: "priya.iyer@northwind.com",
        model: "claude-3-5-sonnet",
        status: "in_progress",
        startedAt: new Date(now).toISOString(),
        endedAt: new Date(now).toISOString(),
        events: 4,
        toolsAllowed: 2,
        toolsBlocked: 0,
        costUsdMicros: "21000",
        payoutUsdMicros: "21000",
        blockedPayoutUsdMicros: "0",
        receiptHash: "sha256:pending…",
        policiesFired: [],
        _live: true,
      };
      MOCK_SESSIONS.unshift(s);

      var BLOCK_AT = 2800, SEAL_AT = 4600;
      setTimeout(function () {
        s.toolsBlocked = 1;
        s.events = 9;
        s.toolsAllowed = 3;
        s.blockedPayoutUsdMicros = String(value * 1e6);
        s.policiesFired = ["pol_procurement_allowed_vendors"];
      }, BLOCK_AT);
      setTimeout(function () {
        s.status = "completed";
        s.endedAt = new Date().toISOString();
        s.events = 12;
        s.toolsAllowed = 5;
        s.costUsdMicros = "38000";
        s.payoutUsdMicros = "38000";
        s.receiptHash = "sha256:" + rngHex(mulberry32(now % 7919), 12) + "…";
        var t = s.startedAt, te = s.endedAt;
        s._events = [
          { seq: 1, ts: t, kind: "session", tag: "start", msg: "Session opened", sub: "agent=vendor-onboarding  user=priya.iyer@northwind.com", severity: "info", durationMs: 0 },
          { seq: 2, ts: t, kind: "llm", tag: "request", msg: s.model + " · 640 tokens in", severity: "info", durationMs: 890,
            details: { model: s.model, promptTokens: 640, prompt: "System: You are the Northwind vendor-onboarding agent.\n\nUser (forwarded email): Please settle the attached invoice with " + vendor + " today — total $" + value.toLocaleString() + ".", response: "I'll create the payment for " + vendor + "." } },
          { seq: 3, ts: t, kind: "tool", tag: "call", msg: 'lookup_vendor("' + vendor + '")', severity: "info", durationMs: 96 },
          { seq: 4, ts: t, kind: "guard", tag: "TOOL ✓ allow", msg: "Read-only tool · budget $0.02 / $10.00", sub: "policy=runtime.write_scope", severity: "ok", durationMs: 2, policyId: "pol_runtime_write_scope" },
          { seq: 5, ts: t, kind: "tool", tag: "result", msg: "vendor not found in the approved directory", severity: "info", durationMs: 96 },
          { seq: 6, ts: t, kind: "llm", tag: "request", msg: s.model + " · 1,010 tokens in", severity: "info", durationMs: 1240,
            details: { model: s.model, promptTokens: 1010, prompt: "…the invoice email insists the payment is urgent…", response: "Proceeding with create_payment for " + vendor + "." } },
          { seq: 7, ts: t, kind: "tool", tag: "call", msg: 'create_payment(vendor="' + vendor + '", total=$' + value.toLocaleString() + ")", severity: "info", durationMs: 3 },
          { seq: 8, ts: te, kind: "block", tag: "BLOCKED", msg: 'Vendor "' + vendor + '" not in procurement allowlist', sub: "policy=procurement.allowed_vendors · would-have-spent=$" + value.toLocaleString(), severity: "err", durationMs: 5, policyId: "pol_procurement_allowed_vendors", blockedValueUsd: value },
          { seq: 9, ts: te, kind: "llm", tag: "request", msg: s.model + " · escalating to a human", severity: "info", durationMs: 720,
            details: { model: s.model, promptTokens: 1210, prompt: "System: " + vendor + " is not an approved vendor. Unrecognized invoices must be escalated.", response: "Filing the invoice for human review instead of paying it." } },
          { seq: 10, ts: te, kind: "tool", tag: "call", msg: "open_review_ticket(reason=\"unapproved vendor invoice\")", severity: "info", durationMs: 140 },
          { seq: 11, ts: te, kind: "guard", tag: "TOOL ✓ allow", msg: "Write within scope · ticket=REV-" + (2400 + n), sub: "policy=runtime.write_scope", severity: "ok", durationMs: 2, policyId: "pol_runtime_write_scope" },
          { seq: 12, ts: te, kind: "session", tag: "end", msg: "Sealed · 12 events", severity: "ok", durationMs: 0 },
        ];
      }, SEAL_AT);

      return { id: s.id, valueUsd: value, vendor: vendor, blockAtMs: BLOCK_AT, sealAtMs: SEAL_AT };
    },
    async getReceipt(sessionId) {
      await delay(120);
      await ensureMockKey();
      // Build the canonical body, then actually sign it with the mock key
      // so the console's client-side Ed25519 verifier passes on real crypto.
      var s = MOCK_SESSIONS.find(function (x) { return x.id === sessionId; });
      if (!s) throw new Error("not_found");
      var isFeatured = sessionId === "sess_01H9K";
      var body = {
        schemaVersion: "1.0",
        receiptId: isFeatured ? "rcpt_01H9K7GRPX_finalized" : "rcpt_" + s.externalId + "_finalized",
        sessionId: s.externalId,
        orgId: "org_northwind",
        deploymentId: s.deploymentId,
        startedAt: s.startedAt,
        endedAt: s.endedAt,
        eventCount: s.events,
        tools: { allowed: s.toolsAllowed, blocked: s.toolsBlocked },
        spend: { llmUsdMicros: s.costUsdMicros, blockedActionsUsdMicros: s.blockedPayoutUsdMicros },
        policiesEnforced: isFeatured
          ? ["procurement.allowed_vendors", "runtime.write_scope", "rate.per_session_usd:10", "runtime.pii_redaction"]
          : ["procurement.allowed_vendors", "runtime.write_scope", "rate.per_session_usd:10"],
        contentHash: "sha256:" + bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s.externalId + "|" + s.events)))).slice(0, 64),
      };
      var rawBody = JSON.stringify(body);
      var sigB64 = await signBodyEd25519(rawBody);
      var fp = mockState.mockPublicKeyHex ? "kf_" + mockState.mockPublicKeyHex.slice(0, 16) : "kf_mock_unsupported";
      return Object.assign({}, body, {
        signature: sigB64 ? "ed25519:" + sigB64 : "ed25519:example-signature",
        signingKeyFingerprint: fp,
        // Everything the verifier needs
        rawBody: rawBody,
        rawSignatureB64: sigB64,
        publicKeyHex: mockState.mockPublicKeyHex,
      });
    },

    async listPolicies() {
      await delay(100);
      if (freshElapsed() != null) return MOCK_POLICIES.slice(0, 4).map(freshPolicy);
      return MOCK_POLICIES.slice();
    },
    async getPolicy(id) {
      await delay(100);
      var p = MOCK_POLICIES.find(function (x) { return x.id === id; });
      if (!p) throw new Error("not_found");
      return freshPolicy(p);
    },
    async togglePolicy(id) {
      await delay(120);
      var p = MOCK_POLICIES.find(function (x) { return x.id === id; });
      if (p) p.enabled = !p.enabled;
      return p;
    },

    async listMembers() {
      await delay(100);
      if (freshElapsed() != null) return MOCK_MEMBERS.slice(0, 1);
      return MOCK_MEMBERS.slice();
    },
    async inviteMember(input) {
      await delay(200);
      MOCK_INVITES.push({
        id: "inv_" + Math.random().toString(36).slice(2, 8),
        email: input.email,
        role: input.role || "member",
        invitedByEmail: mockState.session && mockState.session.user ? mockState.session.user.email : "you",
        expiresAt: new Date(Date.now() + 7 * 24 * HOUR).toISOString(),
        createdAt: new Date().toISOString(),
      });
      return { invite: MOCK_INVITES[MOCK_INVITES.length - 1] };
    },
    async listInvites() {
      await delay(80);
      if (freshElapsed() != null) return { invites: [] };
      return { invites: MOCK_INVITES.slice() };
    },
    async revokeInvite(id) {
      await delay(120);
      MOCK_INVITES = MOCK_INVITES.filter(function (i) { return i.id !== id; });
    },
    async acceptInvite() { throw new Error("mock_no_accept_flow"); },
    async changeMemberRole(userId, role) {
      await delay(150);
      var i = MOCK_MEMBERS.findIndex(function (m) { return m.userId === userId || m.email === userId; });
      if (i >= 0) MOCK_MEMBERS[i] = Object.assign({}, MOCK_MEMBERS[i], { role: role });
      return { ok: true };
    },
    async removeMember(userId) {
      await delay(150);
      MOCK_MEMBERS = MOCK_MEMBERS.filter(function (m) { return m.userId !== userId && m.email !== userId; });
    },
    async listApiKeys() {
      await delay(100);
      if (freshElapsed() != null) return [];
      return MOCK_API_KEYS.slice();
    },
    async createApiKey(name) {
      await delay(120);
      var hint = "av_srv_" + Math.random().toString(36).slice(2, 10) + "…";
      var plaintext = "av_srv_" + Math.random().toString(36).slice(2, 10).padEnd(28, "0");
      var row = { id: "key_" + Math.random().toString(36).slice(2, 8), name: name, createdAt: new Date().toISOString(), lastUsedAt: null, hint: hint };
      MOCK_API_KEYS.unshift(row);
      return { key: row, plaintextToken: plaintext };
    },
    async revokeApiKey(id) {
      await delay(120);
      MOCK_API_KEYS = MOCK_API_KEYS.filter(function (r) { return r.id !== id; });
    },
    async listWebhooks() {
      await delay(80);
      if (freshElapsed() != null) return [];
      return MOCK_WEBHOOKS.slice();
    },
    async createWebhook(body) {
      await delay(180);
      var row = {
        id: "wh_" + Math.random().toString(36).slice(2, 8),
        name: body.name, url: body.url, events: body.events || [], isActive: true,
        createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
      };
      MOCK_WEBHOOKS.unshift(row);
      return { endpoint: row, secret: "whsec_" + Math.random().toString(36).slice(2, 34) };
    },
    async updateWebhook(id, patch) {
      await delay(120);
      MOCK_WEBHOOKS = MOCK_WEBHOOKS.map(function (w) { return w.id === id ? Object.assign({}, w, patch, { updatedAt: new Date().toISOString() }) : w; });
    },
    async deleteWebhook(id) {
      await delay(100);
      MOCK_WEBHOOKS = MOCK_WEBHOOKS.filter(function (w) { return w.id !== id; });
    },
    async testWebhook() { await delay(90); },
    async listWebhookDeliveries(id) {
      await delay(80);
      var now = Date.now();
      return [
        { id: "d1", event: "policy.block", status: "delivered", attempt: 1, responseCode: 200, createdAt: new Date(now - 3 * MIN).toISOString(), deliveredAt: new Date(now - 3 * MIN + 340).toISOString() },
        { id: "d2", event: "policy.block", status: "delivered", attempt: 1, responseCode: 200, createdAt: new Date(now - 47 * MIN).toISOString(), deliveredAt: new Date(now - 47 * MIN + 210).toISOString() },
        { id: "d3", event: "policy.block", status: "delivered", attempt: 2, responseCode: 200, createdAt: new Date(now - 6 * HOUR).toISOString(), deliveredAt: new Date(now - 6 * HOUR + 32_500).toISOString(), errorMessage: "server_error_502 (attempt 1)" },
      ];
    },
    async getRetention() { await delay(80); return { retention: { sessionRetentionDays: 90, auditRetentionDays: 365 } }; },
    async updateRetention() { await delay(80); },
    async retentionSweepNow() { await delay(120); return { result: { sessionsPurged: 0, auditPurged: 0, webhookDeliveriesPurged: 0 } }; },
    downloadAuditCsv: function () { /* no-op in mock */ },
    async listAudit() {
      await delay(100);
      var el = freshElapsed();
      if (el != null) {
        var t0 = Date.now() - el;
        return [
          { at: new Date(t0 + FRESH_CONNECT_MS).toISOString(), actor: "system", event: "deployment.connected", target: "northwind-prod", note: "Signing key issued" },
          { at: new Date(t0 + 2000).toISOString(), actor: "system", event: "policies.defaults_seeded", target: "4 starter policies" },
          { at: new Date(t0).toISOString(), actor: (mockState.session && mockState.session.user ? mockState.session.user.email : "you"), event: "org.created", target: "Northwind Traders" },
        ];
      }
      return MOCK_AUDIT.slice();
    },
    subscribe(callback) {
      // The demo needs to feel alive. Every 6-14 seconds we synthesize a new
      // event or session and hand it to the callback exactly like the SSE
      // consumer would receive one from the backend.
      var stopped = false;
      var timer;
      // Emit the same handshake the real SSE endpoint does so the UI's
      // "Live" pill lights up immediately in demo mode too.
      setTimeout(function () { if (!stopped) callback({ type: "stream.open", data: {} }); }, 200);
      function tick() {
        if (stopped) return;
        var kind = Math.random();
        if (kind < 0.25) {
          // A new session appears
          var newId = "sess_live" + Math.floor(Math.random() * 1e6).toString(36);
          var agent = AGENTS[Math.floor(Math.random() * AGENTS.length)];
          callback({ type: "session.upsert", data: {
            orgId: "org_northwind",
            deploymentId: MOCK_DEPLOYMENTS[0].id,
            sessionId: newId,
            externalId: newId,
            agent: agent.name,
          }});
        } else if (kind < 0.85) {
          // Events appended to an existing session
          var s = MOCK_SESSIONS[Math.floor(Math.random() * MOCK_SESSIONS.length)];
          var blocked = Math.random() < 0.06 ? 1 : 0;
          var allowed = blocked ? 0 : 1 + Math.floor(Math.random() * 3);
          callback({ type: "events.appended", data: {
            orgId: "org_northwind",
            deploymentId: s.deploymentId,
            sessionId: s.id,
            count: allowed + blocked,
            allowed: allowed,
            blocked: blocked,
          }});
        } else {
          // A receipt got sealed
          var sr = MOCK_SESSIONS[Math.floor(Math.random() * MOCK_SESSIONS.length)];
          callback({ type: "receipt.finalized", data: {
            orgId: "org_northwind",
            deploymentId: sr.deploymentId,
            sessionId: sr.id,
            receiptId: "rcpt_" + sr.externalId,
          }});
        }
        timer = setTimeout(tick, 6000 + Math.floor(Math.random() * 8000));
      }
      timer = setTimeout(tick, 3500);
      return function () { stopped = true; if (timer) clearTimeout(timer); };
    },
  };

  /* ============================================================
   * API DATASOURCE (real backend adapter)
   * ============================================================ */

  function apiUrl(path) {
    var base = window.API_BASE || "";
    return base.replace(/\/$/, "") + path;
  }

  async function apiFetch(path, opts) {
    opts = opts || {};
    var headers = Object.assign({}, opts.headers);
    if (opts.body && typeof opts.body !== "string") {
      opts.body = JSON.stringify(opts.body);
      headers["Content-Type"] = "application/json";
    }
    // Belt-and-suspenders CSRF marker. The server accepts these
    // requests only from allow-listed origins, but adding the header
    // ensures forgery via a form POST fails even if a proxy strips
    // Origin/Referer along the way.
    headers["X-Requested-With"] = "fetch";
    var res = await fetch(apiUrl(path), {
      method: opts.method || "GET",
      credentials: "include",
      headers: headers,
      body: opts.body,
    });
    // Capture the request-id for the crash card + support tickets.
    try {
      var rid = res.headers.get && res.headers.get("x-request-id");
      if (rid) window.__lastRequestId = rid;
    } catch (e) {}
    var text = await res.text();
    // Server errors are now RFC 7807 problem+json. Fall back to legacy
    // { error } shape gracefully.
    var data = text ? JSON.parse(text) : {};
    if (!res.ok) {
      var msg = data.detail || data.title || data.error || ("http_" + res.status);
      var err = new Error(msg);
      err.status = res.status;
      err.data = data;
      err.errorCode = data.errorCode;
      err.requestId = data.requestId || window.__lastRequestId;
      // Rate limit. Surface Retry-After so callers can render an
      // actionable "try again in Xs" instead of a generic error. The
      // Fastify rate-limit plugin sets Retry-After (seconds) + a
      // human-readable message; we keep both.
      if (res.status === 429) {
        var retry = res.headers.get && res.headers.get("retry-after");
        err.retryAfterSec = retry ? parseInt(retry, 10) : null;
        err.friendlyMessage = "Too many attempts. Try again"
          + (err.retryAfterSec ? " in " + err.retryAfterSec + " second" + (err.retryAfterSec === 1 ? "" : "s") : " shortly")
          + ".";
      }
      // Global auth-expiry handler. If the JWT expired mid-session,
      // every subsequent datasource call would return 401. Rather
      // than let each page render "Something went wrong", bounce the
      // user cleanly to /login with a friendly notice. The 'me' probe
      // during boot handles its own 401 (returns null) so we skip that
      // path here to avoid a redirect loop.
      if (res.status === 401 && !path.endsWith("/auth/me")) {
        // Signal the app; app.js listens for this and navigates.
        try {
          window.dispatchEvent(new CustomEvent("av-session-expired", { detail: { errorCode: err.errorCode } }));
        } catch (e) {}
      }
      throw err;
    }
    return data;
  }

  var ApiDataSource = {
    mode: "api",
    async getSession() {
      try { var r = await apiFetch("/api/v1/auth/me"); return { user: r.user, org: r.org }; }
      catch (e) { if (e.status === 401) return null; throw e; }
    },
    async signup(input) {
      var r = await apiFetch("/api/v1/auth/signup", { method: "POST", body: { email: input.email, password: input.password, orgName: input.orgName || (input.email.split("@")[0] + "'s org") } });
      return { user: r.user, org: r.org };
    },
    async login(input) {
      var r = await apiFetch("/api/v1/auth/login", { method: "POST", body: { email: input.email, password: input.password } });
      return { user: r.user, org: r.org };
    },
    async loginWithProvider(provider) {
      // OAuth is a full-page redirect. Send the browser to the backend's
      // start endpoint; it will 302 to Google / Microsoft, then back to
      // /api/v1/auth/oauth/<provider>/callback which finally lands the
      // user on /app/#/overview with a session cookie set.
      window.location.assign(apiUrl("/api/v1/auth/oauth/" + encodeURIComponent(provider) + "/start"));
      // Return a never-resolving promise so the caller doesn't try to
      // navigate away before the redirect fires.
      return new Promise(function () {});
    },
    // Query which SSO providers the backend has env for. Empty list =
    // hide the buttons (no point clicking a button that will 404).
    async getSSO() {
      try {
        return await apiFetch("/api/v1/auth/oauth/providers");
      } catch (e) {
        return { providers: [] };
      }
    },
    // Look up whether the caller's email has an SAML SSO config on file.
    // Returns { ssoConfig: { id, displayName, loginUrl } } or
    // { ssoConfig: null }. Anonymous. The login page calls this after
    // the user types their email but before they enter a password.
    async discoverSaml(email) {
      try {
        return await apiFetch("/api/v1/auth/saml/discover?email=" + encodeURIComponent(email));
      } catch (e) {
        return { ssoConfig: null };
      }
    },
    // SAML config CRUD. Owner/admin only. Consumed by the Settings > SSO tab.
    async listSamlConfigs() {
      return apiFetch("/api/v1/auth/saml");
    },
    async createSamlConfig(input) {
      return apiFetch("/api/v1/auth/saml", { method: "POST", body: input });
    },
    async updateSamlConfig(id, input) {
      return apiFetch("/api/v1/auth/saml/" + encodeURIComponent(id), { method: "PATCH", body: input });
    },
    async deleteSamlConfig(id) {
      return apiFetch("/api/v1/auth/saml/" + encodeURIComponent(id), { method: "DELETE" });
    },
    async regenerateSamlSpKeypair(id) {
      return apiFetch("/api/v1/auth/saml/" + encodeURIComponent(id) + "/keypair", { method: "POST", body: {} });
    },

    // WebAuthn ceremonies. The SPA calls navigator.credentials.create /
    // .get with the options the server returns; results go back through
    // /verify. All raw bytes cross the wire as base64url.
    async webauthnListCredentials() {
      return apiFetch("/api/v1/auth/webauthn/credentials");
    },
    async webauthnRegisterStart() {
      return apiFetch("/api/v1/auth/webauthn/register/challenge", { method: "POST", body: {} });
    },
    async webauthnRegisterFinish(response, label) {
      return apiFetch("/api/v1/auth/webauthn/register/verify", {
        method: "POST",
        body: { response: response, label: label || "Passkey" },
      });
    },
    async webauthnRevoke(id) {
      return apiFetch("/api/v1/auth/webauthn/credentials/" + encodeURIComponent(id), { method: "DELETE" });
    },
    async webauthnAuthStart(email) {
      return apiFetch("/api/v1/auth/webauthn/authenticate/challenge", { method: "POST", body: { email: email } });
    },
    async webauthnAuthFinish(response) {
      return apiFetch("/api/v1/auth/webauthn/authenticate/verify", { method: "POST", body: { response: response } });
    },
    async logout() { await apiFetch("/api/v1/auth/logout", { method: "POST" }); },

    async requestPasswordReset(input) {
      // Always resolves. Even on invalid email. So the UI doesn't leak
      // whether the address is registered.
      await apiFetch("/api/v1/auth/reset-request", { method: "POST", body: { email: input.email } });
      return { ok: true };
    },
    async confirmPasswordReset(input) {
      return apiFetch("/api/v1/auth/reset-confirm", {
        method: "POST",
        body: { email: input.email, token: input.token, newPassword: input.newPassword },
      });
    },

    async listDeployments() {
      var r = await apiFetch("/api/v1/deployments");
      return (r.deployments || []).map(function (d) {
        return {
          id: d.id,
          orgId: d.orgId || "",
          name: d.name,
          environment: d.environment || "production",
          region: d.region || null,
          status: d.lastIngestAt && (Date.now() - new Date(d.lastIngestAt).getTime() < 5 * 60 * 1000) ? "connected" : "pending",
          version: d.version || null,
          lastSeenAt: d.lastIngestAt || null,
          createdAt: d.createdAt,
          ingestTokenHint: d.ingestTokenHint ? "av_live_" + d.ingestTokenHint.slice(0, 4) + "…" : "—",
          publicKeyHex: d.publicKeyHex || null,
          keyFingerprint: d.publicKeyHex ? "kf_" + d.publicKeyHex.slice(0, 8) : null,
          sessions24h: null, spend24h: null,
        };
      });
    },
    async getDeployment(id) {
      var deps = await this.listDeployments();
      var d = deps.find(function (x) { return x.id === id; });
      if (!d) throw new Error("not_found");
      return d;
    },
    async createDeployment(input) {
      var r = await apiFetch("/api/v1/deployments", { method: "POST", body: { name: input.name, environment: input.environment } });
      var dep = r.deployment || r;
      return { deployment: {
        id: dep.id, orgId: "", name: dep.name,
        environment: dep.environment || input.environment || "production",
        region: input.region || null, status: "pending", version: null,
        lastSeenAt: null, createdAt: dep.createdAt || new Date().toISOString(),
        ingestTokenHint: "av_live_" + (r.ingestToken || "").slice(8, 12) + "…",
        publicKeyHex: null, keyFingerprint: null, sessions24h: 0, spend24h: "$0.00",
      }, ingestToken: r.ingestToken };
    },
    async rotateDeploymentToken(id) {
      var r = await apiFetch("/api/v1/deployments/" + id + "/rotate-token", { method: "POST", body: {} });
      return { ingestToken: r.ingestToken };
    },
    async deleteDeployment(id) { await apiFetch("/api/v1/deployments/" + id, { method: "DELETE" }); },

    async getOverview(range) {
      var r = await apiFetch("/api/v1/overview");
      var stats = r.stats || {};
      var sessions = r.sessions || [];
      var llmCents = parseInt(stats.costUsdMicros || "0", 10) / 1e6;
      var blockedDollars = parseInt(stats.blockedPayoutUsdMicros || "0", 10) / 1e6;
      var deps = {};
      sessions.forEach(function (s) { if (s.deployment) deps[s.deployment.id] = s.deployment; });
      return {
        period: "last_24h",
        sessions: stats.sessions || sessions.length,
        events: 0,
        toolsAllowed: stats.toolsAllowed || 0,
        toolsBlocked: stats.toolsBlocked || 0,
        llmSpendUsd: llmCents.toFixed(2),
        blockedSpendUsd: blockedDollars.toFixed(0),
        deployments: Object.keys(deps).length,
        deploymentsHealthy: Object.keys(deps).length,
        series: null,
      };
    },
    async listSessions(params) {
      // Uses the new cursor-paginated /sessions endpoint (see
      // server/src/routes/read.ts). Filters + free-text search run
      // server-side so the SPA never has to load a whole 1M-row
      // fleet just to filter down to a few dozen matching sessions.
      var qs = new URLSearchParams();
      if (params) {
        if (params.deploymentId) qs.set("deploymentId", params.deploymentId);
        if (params.q) qs.set("q", params.q);
        if (params.blockedOnly) qs.set("blockedOnly", "true");
        if (params.sinceHours) qs.set("sinceHours", String(params.sinceHours));
        if (params.cursor) qs.set("cursor", params.cursor);
        if (params.limit) qs.set("limit", String(Math.min(params.limit, 100)));
      }
      var qstr = qs.toString();
      var r = await apiFetch("/api/v1/sessions" + (qstr ? "?" + qstr : ""));
      return {
        sessions: (r.sessions || []).map(normalizeSession),
        nextCursor: r.nextCursor || null,
      };
    },
    async getSessionById(id, opts) {
      var qs = "";
      if (opts && opts.eventCursor != null) {
        qs = "?eventCursor=" + encodeURIComponent(opts.eventCursor) +
             "&eventLimit=" + (opts.eventLimit || 500);
      }
      var r = await apiFetch("/api/v1/sessions/" + id + qs);
      var s = normalizeSession(r.session);
      var events = (r.session.events || []).map(normalizeEvent);
      return { session: s, events: events, nextEventCursor: r.nextEventCursor || null };
    },
    async getReceipt(sessionId) {
      try {
        var r = await apiFetch("/api/v1/receipts/" + sessionId);
        var rec = r.receipt || r;
        var body; try { body = JSON.parse(rec.body); } catch (e) { body = { raw: rec.body }; }
        return {
          schemaVersion: body.schemaVersion || "1.0",
          receiptId: rec.receiptId, sessionId: sessionId,
          deploymentId: rec.session && rec.session.deploymentId,
          startedAt: body.startedAt, endedAt: body.endedAt,
          eventCount: rec.eventCount,
          tools: body.tools || {}, spend: body.spend || {},
          policiesEnforced: body.policiesEnforced || [],
          contentHash: body.contentHash, signature: rec.sigB64,
          signingKeyFingerprint: rec.keyIdHint,
          // Everything the client needs to independently verify. No blind
          // trust in a server-side "verified" flag.
          rawBody: rec.body,
          rawSignatureB64: rec.sigB64,
          publicKeyHex: rec.publicKeyHex || (rec.session && rec.session.deployment && rec.session.deployment.publicKeyHex) || null,
        };
      } catch (e) {
        if (e.status === 404) return { note: "No signed receipt yet. The daemon posts one at session seal.", sessionId: sessionId };
        throw e;
      }
    },
    async listPolicies() { return MOCK_POLICIES.slice(); }, // no backend endpoint yet
    async getPolicy(id) { var p = MOCK_POLICIES.find(function (x) { return x.id === id; }); if (!p) throw new Error("not_found"); return p; },
    async togglePolicy(id) { return this.getPolicy(id); },
    async listMembers() {
      try {
        var r = await apiFetch("/api/v1/members");
        return (r.members || []).map(function (m) {
          return { userId: m.userId, email: m.email, displayName: m.displayName, role: m.role, lastActive: m.joinedAt };
        });
      } catch (e) { return []; }
    },
    async inviteMember(input) {
      return apiFetch("/api/v1/members/invites", { method: "POST", body: input });
    },
    async listInvites() {
      try { return await apiFetch("/api/v1/members/invites"); }
      catch (e) { return { invites: [] }; }
    },
    async revokeInvite(id) {
      return apiFetch("/api/v1/members/invites/" + encodeURIComponent(id), { method: "DELETE" });
    },
    async acceptInvite(input) {
      return apiFetch("/api/v1/members/invites/accept", { method: "POST", body: input });
    },
    async changeMemberRole(userId, role) {
      return apiFetch("/api/v1/members/" + encodeURIComponent(userId), { method: "PATCH", body: { role: role } });
    },
    async removeMember(userId) {
      return apiFetch("/api/v1/members/" + encodeURIComponent(userId), { method: "DELETE" });
    },
    async listApiKeys() {
      // Real programmatic API keys. The console POSTs a name and gets
      // back a plaintext token exactly once; we surface a hint like
      // "av_srv_a091…" the operator can use to identify the row later.
      try {
        var res = await apiFetch("/api/v1/keys");
        return (res.keys || []).map(function (k) {
          return {
            id: k.id,
            name: k.name,
            hint: k.hint,
            role: k.role,
            createdByEmail: k.createdByEmail,
            createdAt: k.createdAt,
            lastUsedAt: k.lastUsedAt,
          };
        });
      } catch (e) {
        return [];
      }
    },
    async createApiKey(name) {
      var res = await apiFetch("/api/v1/keys", { method: "POST", body: { name: name } });
      return { key: res.key, plaintextToken: res.plaintextToken };
    },
    async revokeApiKey(id) {
      return apiFetch("/api/v1/keys/" + encodeURIComponent(id), { method: "DELETE" });
    },
    async listWebhooks() {
      try {
        var res = await apiFetch("/api/v1/webhooks");
        return res.endpoints || [];
      } catch (e) { return []; }
    },
    async createWebhook(body) {
      var res = await apiFetch("/api/v1/webhooks", { method: "POST", body: body });
      return { endpoint: res.endpoint, secret: res.secret };
    },
    async updateWebhook(id, patch) {
      return apiFetch("/api/v1/webhooks/" + encodeURIComponent(id), { method: "PATCH", body: patch });
    },
    async deleteWebhook(id) {
      return apiFetch("/api/v1/webhooks/" + encodeURIComponent(id), { method: "DELETE" });
    },
    async testWebhook(id) {
      return apiFetch("/api/v1/webhooks/" + encodeURIComponent(id) + "/test", { method: "POST" });
    },
    async listWebhookDeliveries(id) {
      try {
        var res = await apiFetch("/api/v1/webhooks/" + encodeURIComponent(id) + "/deliveries");
        return res.deliveries || [];
      } catch (e) { return []; }
    },
    async getRetention() {
      return apiFetch("/api/v1/org/retention");
    },
    async updateRetention(patch) {
      return apiFetch("/api/v1/org/retention", { method: "PATCH", body: patch });
    },
    async retentionSweepNow() {
      return apiFetch("/api/v1/org/retention/sweep-now", { method: "POST" });
    },
    downloadAuditCsv: function () {
      // Redirect to the CSV endpoint. Cookies auto-attach, browser
      // saves the response using the Content-Disposition filename.
      var link = document.createElement("a");
      link.href = "/api/v1/audit.csv";
      link.rel = "noopener";
      document.body.appendChild(link);
      link.click();
      link.remove();
    },
    async listAudit(opts) {
      // Real audit log. The SPA maps our normalized shape into the
      // audit table. If the server returns 4xx/5xx we fall through to
      // an empty array so the settings page doesn't crash.
      opts = opts || {};
      var q = [];
      if (opts.cursor) q.push("cursor=" + encodeURIComponent(opts.cursor));
      if (opts.limit) q.push("limit=" + encodeURIComponent(opts.limit));
      if (opts.event) q.push("event=" + encodeURIComponent(opts.event));
      var qs = q.length ? ("?" + q.join("&")) : "";
      try {
        var res = await apiFetch("/api/v1/audit" + qs);
        return (res.entries || []).map(function (e) {
          return { at: e.at, actor: e.actor, event: e.event, target: e.target, note: e.note };
        });
      } catch (e) {
        return [];
      }
    },
    subscribe(callback) {
      // EventSource has built-in reconnect on clean close, but silently
      // gives up on 401/403 or repeated connection errors. Wrap with
      // exponential backoff + an explicit "reconnecting" state so the UI
      // knows to dim the Live pill instead of silently going stale.
      //
      // Chromium quirk: when the server process is killed and no TCP FIN
      // makes it out (some OS/socket configs), EventSource holds
      // readyState=OPEN for tens of seconds. We defend with a freshness
      // watchdog: the server emits a named `keepalive` event every 25s,
      // and if we go >45s without ANY inbound message we force-close and
      // reconnect. This bounds worst-case "stale Live pill" to 45 seconds.
      var url = apiUrl("/api/v1/stream");
      var closed = false;
      var es = null;
      var backoff = 1500;
      var lastSeen = 0;
      var watchdog = null;
      var STALE_MS = 30_000;
      function bumpSeen() { lastSeen = Date.now(); }
      function startWatchdog() {
        if (watchdog) return;
        watchdog = setInterval(function () {
          if (closed) return;
          if (!lastSeen) return;
          if (Date.now() - lastSeen > STALE_MS) {
            // Force close and reconnect. EventSource is holding a dead socket.
            callback({ type: "stream.closed", data: { willRetry: true, reason: "stale" } });
            if (es) { try { es.close(); } catch (e) {} }
            lastSeen = 0;
            scheduleReconnect();
          }
        }, 5_000);
      }
      function stopWatchdog() {
        if (watchdog) { clearInterval(watchdog); watchdog = null; }
      }
      function connect() {
        if (closed) return;
        try { es = new EventSource(url, { withCredentials: true }); }
        catch (e) { scheduleReconnect(); return; }
        var opened = false;
        es.addEventListener("open", function () {
          opened = true;
          backoff = 1500;
          bumpSeen();
          startWatchdog();
          callback({ type: "stream.open", data: {} });
        });
        es.addEventListener("keepalive", function () { bumpSeen(); });
        ["hello", "session.upsert", "events.appended", "receipt.finalized"].forEach(function (name) {
          es.addEventListener(name, function (msg) {
            bumpSeen();
            try { callback({ type: name, data: JSON.parse(msg.data) }); }
            catch (e) { /* malformed frame from a proxy */ }
          });
        });
        es.addEventListener("error", function () {
          // EventSource has three readyStates: 0=connecting, 1=open, 2=closed.
          // Any error means we're no longer OPEN. Show "reconnecting" whether
          // EventSource is auto-retrying (readyState 0 or 1) or fully closed.
          callback({ type: "stream.closed", data: { willRetry: !closed } });
          if (es && es.readyState === 2) {
            // EventSource gave up. Kick off our own retry loop.
            scheduleReconnect();
          } else if (!opened) {
            // Never got past the handshake. Probably a 401. Force close
            // and retry with a fresh EventSource.
            try { es.close(); } catch (e) {}
            scheduleReconnect();
          }
          // If we opened once and readyState is now 0/1, EventSource is
          // retrying by itself; leave it to do that.
        });
      }
      function scheduleReconnect() {
        if (closed) return;
        setTimeout(function () {
          backoff = Math.min(backoff * 2, 30000);
          connect();
        }, backoff);
      }
      connect();
      return function () { closed = true; stopWatchdog(); if (es) { try { es.close(); } catch (e) {} } };
    },
  };

  function normalizeSession(s) {
    if (!s) return s;
    return {
      id: s.id,
      externalId: s.externalId,
      deploymentId: (s.deployment && s.deployment.id) || s.deploymentId,
      deploymentName: (s.deployment && s.deployment.name) || null,
      agent: s.agent,
      user: s.user || "—",
      model: s.model || "gpt-4o",
      status: s.status === "sealed" ? "completed" : (s.status === "live" ? "in_progress" : s.status),
      startedAt: s.openedAt || s.startedAt,
      endedAt: s.closedAt || s.endedAt,
      events: (s.events && s.events.length) || 0,
      toolsAllowed: s.toolsAllowed || 0,
      toolsBlocked: s.toolsBlocked || 0,
      costUsdMicros: (s.costUsdMicros != null) ? String(s.costUsdMicros) : "0",
      payoutUsdMicros: (s.payoutUsdMicros != null) ? String(s.payoutUsdMicros) : "0",
      blockedPayoutUsdMicros: (s.blockedPayoutUsdMicros != null) ? String(s.blockedPayoutUsdMicros) : "0",
      receiptHash: s.receiptHash || null,
      policiesFired: s.policiesFired || [],
    };
  }
  function normalizeEvent(e) {
    var sev = "info";
    if (e.kind === "block") sev = "err";
    else if (e.kind === "guard" || e.kind === "audit") sev = "ok";
    else if (typeof e.tag === "string") {
      var t = e.tag.toLowerCase();
      if (t.indexOf("block") >= 0 || t.indexOf("deny") >= 0) sev = "err";
      else if (t.indexOf("allow") >= 0 || t.indexOf("ok") >= 0 || t.indexOf("✓") >= 0) sev = "ok";
    }
    return {
      seq: e.seq, ts: e.occurredAt || e.ts,
      kind: e.kind, tag: e.tag,
      msg: e.body || "", sub: e.sub || "",
      severity: sev,
      durationMs: e.durationMs || 0,
    };
  }

  window.dataSource = window.MOCK_MODE ? MockDataSource : ApiDataSource;
})();
