/*
 * AgentVisor AI console — data source layer.
 *
 * Exposes an async API surface consumed by app.js. Two implementations:
 *   - MockDataSource: local Northwind Traders fixtures so /app/ works
 *     without a backend (used for the investor pitch and preview builds).
 *   - ApiDataSource: fetch()-based client for the hosted backend.
 *
 * Choice is driven by window.MOCK_MODE (set in index.html). Flip that flag
 * and set window.API_BASE to point at a real deployment.
 */

(function () {
  "use strict";

  /* ============================================================
   * MOCK — Northwind Traders fixtures
   * ============================================================ */

  var mockState = {
    session: null, // {user, org}
  };

  var NOW = Date.now();
  function isoDaysAgo(d) { return new Date(NOW - d * 86400000).toISOString(); }
  function isoMinsAgo(m) { return new Date(NOW - m * 60000).toISOString(); }

  var MOCK_ORGS = {
    "org_northwind": {
      id: "org_northwind",
      name: "Northwind Traders",
      slug: "northwind",
      createdAt: isoDaysAgo(42),
    },
  };

  var MOCK_DEPLOYMENTS = [
    {
      id: "dep_prod",
      orgId: "org_northwind",
      name: "northwind-prod",
      environment: "production",
      region: "us-east-1",
      status: "connected",
      version: "0.4.2",
      lastSeenAt: isoMinsAgo(1),
      createdAt: isoDaysAgo(38),
      ingestTokenHint: "av_live_••••4a9c",
      publicKeyHex: "3a5f7e2d1b8c9a4e6f1d2c3b4a5e6f7d8c9b0a1e2f3d4c5b6a7e8f9d0c1b2a3e",
    },
    {
      id: "dep_stage",
      orgId: "org_northwind",
      name: "northwind-staging",
      environment: "staging",
      region: "us-east-1",
      status: "connected",
      version: "0.4.2",
      lastSeenAt: isoMinsAgo(4),
      createdAt: isoDaysAgo(38),
      ingestTokenHint: "av_live_••••7b12",
      publicKeyHex: "8c9b0a1e2f3d4c5b6a7e8f9d0c1b2a3e3a5f7e2d1b8c9a4e6f1d2c3b4a5e6f7d",
    },
  ];

  var MOCK_SESSIONS = [
    {
      id: "sess_01H9K",
      externalId: "sess_01H9K7GRPX",
      deploymentId: "dep_prod",
      agent: "supply-planner",
      user: "olivia.tan@northwind.com",
      status: "completed",
      startedAt: isoMinsAgo(6),
      endedAt: isoMinsAgo(2),
      events: 42,
      toolsAllowed: 18,
      toolsBlocked: 1,
      costUsdMicros: "184000",
      payoutUsdMicros: "184000",
      blockedPayoutUsdMicros: "8400000000",
      receiptHash: "sha256:8f2c4e...",
    },
    {
      id: "sess_01H9J",
      externalId: "sess_01H9JQRPX2",
      deploymentId: "dep_prod",
      agent: "supply-planner",
      user: "olivia.tan@northwind.com",
      status: "completed",
      startedAt: isoMinsAgo(38),
      endedAt: isoMinsAgo(35),
      events: 28,
      toolsAllowed: 12,
      toolsBlocked: 0,
      costUsdMicros: "121000",
      payoutUsdMicros: "121000",
      blockedPayoutUsdMicros: "0",
      receiptHash: "sha256:3d1a9b...",
    },
    {
      id: "sess_01H9H",
      externalId: "sess_01H9HN2XKV",
      deploymentId: "dep_stage",
      agent: "returns-triage",
      user: "raj.patel@northwind.com",
      status: "completed",
      startedAt: isoMinsAgo(72),
      endedAt: isoMinsAgo(70),
      events: 15,
      toolsAllowed: 7,
      toolsBlocked: 0,
      costUsdMicros: "47000",
      payoutUsdMicros: "47000",
      blockedPayoutUsdMicros: "0",
      receiptHash: "sha256:c02f4e...",
    },
    {
      id: "sess_01H9G",
      externalId: "sess_01H9GXP4B7",
      deploymentId: "dep_prod",
      agent: "supply-planner",
      user: "olivia.tan@northwind.com",
      status: "completed",
      startedAt: isoMinsAgo(140),
      endedAt: isoMinsAgo(138),
      events: 22,
      toolsAllowed: 10,
      toolsBlocked: 0,
      costUsdMicros: "88000",
      payoutUsdMicros: "88000",
      blockedPayoutUsdMicros: "0",
      receiptHash: "sha256:71e8ab...",
    },
    {
      id: "sess_01H9F",
      externalId: "sess_01H9FMQ73C",
      deploymentId: "dep_prod",
      agent: "supply-planner",
      user: "olivia.tan@northwind.com",
      status: "completed",
      startedAt: isoMinsAgo(220),
      endedAt: isoMinsAgo(216),
      events: 34,
      toolsAllowed: 15,
      toolsBlocked: 2,
      costUsdMicros: "156000",
      payoutUsdMicros: "156000",
      blockedPayoutUsdMicros: "1200000000",
      receiptHash: "sha256:59a0f2...",
    },
    {
      id: "sess_01H9E",
      externalId: "sess_01H9EJPT81",
      deploymentId: "dep_stage",
      agent: "returns-triage",
      user: "sam.lee@northwind.com",
      status: "completed",
      startedAt: isoMinsAgo(340),
      endedAt: isoMinsAgo(337),
      events: 19,
      toolsAllowed: 9,
      toolsBlocked: 0,
      costUsdMicros: "62000",
      payoutUsdMicros: "62000",
      blockedPayoutUsdMicros: "0",
      receiptHash: "sha256:a4b8d1...",
    },
    {
      id: "sess_01H9D",
      externalId: "sess_01H9DPLK92",
      deploymentId: "dep_prod",
      agent: "supply-planner",
      user: "olivia.tan@northwind.com",
      status: "completed",
      startedAt: isoMinsAgo(480),
      endedAt: isoMinsAgo(477),
      events: 27,
      toolsAllowed: 13,
      toolsBlocked: 0,
      costUsdMicros: "97000",
      payoutUsdMicros: "97000",
      blockedPayoutUsdMicros: "0",
      receiptHash: "sha256:2fe0a7...",
    },
  ];

  var MOCK_EVENTS_FEATURED = [
    { seq: 1, ts: isoMinsAgo(6), kind: "session.start", msg: "supply-planner opened session", severity: "info" },
    { seq: 2, ts: isoMinsAgo(6), kind: "llm.request", msg: "gpt-4o · 812 tokens in", severity: "info" },
    { seq: 3, ts: isoMinsAgo(6), kind: "tool.call", msg: "search_inventory(sku=\"NW-1240\")", severity: "info" },
    { seq: 4, ts: isoMinsAgo(6), kind: "tool.allow", msg: "policy: read-only ✓ · budget: $0.02 / $10.00", severity: "ok" },
    { seq: 5, ts: isoMinsAgo(5), kind: "tool.result", msg: "inventory returned 4 rows in 128ms", severity: "info" },
    { seq: 6, ts: isoMinsAgo(5), kind: "llm.request", msg: "gpt-4o · 1,204 tokens in", severity: "info" },
    { seq: 7, ts: isoMinsAgo(5), kind: "tool.call", msg: "create_purchase_order(vendor=\"NexusParts\", total_usd=8400)", severity: "info" },
    { seq: 8, ts: isoMinsAgo(5), kind: "tool.block", msg: "BLOCKED — vendor \"NexusParts\" not in allowlist (policy: procurement.allowed_vendors)", severity: "err" },
    { seq: 9, ts: isoMinsAgo(5), kind: "llm.request", msg: "gpt-4o · retry with new vendor", severity: "info" },
    { seq: 10, ts: isoMinsAgo(4), kind: "tool.call", msg: "create_purchase_order(vendor=\"Contoso\", total_usd=8400)", severity: "info" },
    { seq: 11, ts: isoMinsAgo(4), kind: "tool.allow", msg: "policy: allowlist ✓ · budget check ✓ · human approval not required", severity: "ok" },
    { seq: 12, ts: isoMinsAgo(4), kind: "tool.result", msg: "PO #29841 created · $8,400", severity: "info" },
    { seq: 13, ts: isoMinsAgo(2), kind: "session.end", msg: "completed · 42 events · receipt sha256:8f2c4e…", severity: "ok" },
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
    policiesEnforced: ["procurement.allowed_vendors", "rate.per_session_usd:10", "runtime.write_scope"],
    contentHash: "sha256:8f2c4e2b71b0a1d3e5c6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8",
    signature: "ed25519:LmZk3TpJ2r0aQxvXbYc7WdRnSfE1UgHkO0pIiV8mAcNyBt6Zh4uFj9zKlP+g/ExampleSignature==",
    signingKeyFingerprint: "kf_3a5f7e2d1b8c9a4e",
  };

  function mockOverview(orgId) {
    var sessions = MOCK_SESSIONS.filter(function (s) {
      return MOCK_DEPLOYMENTS.some(function (d) { return d.id === s.deploymentId && d.orgId === orgId; });
    });
    return {
      period: "last_24h",
      sessions: sessions.length,
      events: sessions.reduce(function (a, s) { return a + s.events; }, 0),
      toolsAllowed: sessions.reduce(function (a, s) { return a + s.toolsAllowed; }, 0),
      toolsBlocked: sessions.reduce(function (a, s) { return a + s.toolsBlocked; }, 0),
      llmSpendUsd: (sessions.reduce(function (a, s) { return a + parseInt(s.costUsdMicros, 10); }, 0) / 1e6).toFixed(2),
      blockedSpendUsd: (sessions.reduce(function (a, s) { return a + parseInt(s.blockedPayoutUsdMicros, 10); }, 0) / 1e6).toFixed(0),
      deployments: MOCK_DEPLOYMENTS.filter(function (d) { return d.orgId === orgId; }).length,
      deploymentsHealthy: MOCK_DEPLOYMENTS.filter(function (d) { return d.orgId === orgId && d.status === "connected"; }).length,
    };
  }

  function delay(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

  var MockDataSource = {
    mode: "mock",
    async getSession() {
      // Persist sign-out across reloads so the login/signup flow is
      // reachable after the user clicks "sign out" in the demo.
      try {
        if (localStorage.getItem("av_mock_signed_out") === "1") return null;
      } catch (e) { /* private mode */ }
      if (!mockState.session) {
        // Auto-log-in as the demo user so /app/ shows something immediately.
        mockState.session = {
          user: { id: "usr_demo", email: "demo@northwind.com", displayName: "Olivia Tan" },
          org: MOCK_ORGS.org_northwind,
        };
      }
      return mockState.session;
    },
    async signup(input) {
      await delay(400);
      try { localStorage.removeItem("av_mock_signed_out"); } catch (e) {}
      mockState.session = {
        user: { id: "usr_demo", email: input.email, displayName: input.email.split("@")[0] },
        org: MOCK_ORGS.org_northwind,
      };
      return mockState.session;
    },
    async login(input) {
      await delay(400);
      try { localStorage.removeItem("av_mock_signed_out"); } catch (e) {}
      mockState.session = {
        user: { id: "usr_demo", email: input.email, displayName: input.email.split("@")[0] },
        org: MOCK_ORGS.org_northwind,
      };
      return mockState.session;
    },
    async logout() {
      try { localStorage.setItem("av_mock_signed_out", "1"); } catch (e) {}
      mockState.session = null;
    },
    async listDeployments() {
      await delay(150);
      return MOCK_DEPLOYMENTS.filter(function (d) { return d.orgId === "org_northwind"; });
    },
    async createDeployment(input) {
      await delay(300);
      var id = "dep_" + Math.random().toString(36).slice(2, 8);
      var token = "av_live_" + Math.random().toString(36).slice(2, 10) + Math.random().toString(36).slice(2, 10);
      var dep = {
        id: id,
        orgId: "org_northwind",
        name: input.name,
        environment: input.environment || "development",
        region: input.region || "us-east-1",
        status: "pending",
        version: null,
        lastSeenAt: null,
        createdAt: new Date().toISOString(),
        ingestTokenHint: "av_live_••••" + token.slice(-4),
        publicKeyHex: null,
      };
      MOCK_DEPLOYMENTS.push(dep);
      return { deployment: dep, ingestToken: token };
    },
    async rotateDeploymentToken(id) {
      await delay(200);
      var token = "av_live_" + Math.random().toString(36).slice(2, 10) + Math.random().toString(36).slice(2, 10);
      var dep = MOCK_DEPLOYMENTS.find(function (d) { return d.id === id; });
      if (dep) dep.ingestTokenHint = "av_live_••••" + token.slice(-4);
      return { ingestToken: token };
    },
    async deleteDeployment(id) {
      await delay(200);
      var i = MOCK_DEPLOYMENTS.findIndex(function (d) { return d.id === id; });
      if (i >= 0) MOCK_DEPLOYMENTS.splice(i, 1);
    },
    async getOverview() {
      await delay(120);
      return mockOverview("org_northwind");
    },
    async listSessions(params) {
      await delay(200);
      params = params || {};
      var results = MOCK_SESSIONS.slice();
      if (params.deploymentId) results = results.filter(function (s) { return s.deploymentId === params.deploymentId; });
      results.sort(function (a, b) { return new Date(b.startedAt) - new Date(a.startedAt); });
      return { sessions: results, total: results.length };
    },
    async getSessionById(id) {
      await delay(200);
      var s = MOCK_SESSIONS.find(function (x) { return x.id === id; });
      if (!s) throw new Error("not_found");
      var events = id === "sess_01H9K" ? MOCK_EVENTS_FEATURED : synthesizeEvents(s);
      return { session: s, events: events };
    },
    async getReceipt(sessionId) {
      await delay(150);
      if (sessionId === "sess_01H9K") return MOCK_RECEIPT_FEATURED;
      var s = MOCK_SESSIONS.find(function (x) { return x.id === sessionId; });
      if (!s) throw new Error("not_found");
      return {
        schemaVersion: "1.0",
        receiptId: "rcpt_" + s.externalId + "_finalized",
        sessionId: s.externalId,
        orgId: "org_northwind",
        deploymentId: s.deploymentId,
        startedAt: s.startedAt,
        endedAt: s.endedAt,
        eventCount: s.events,
        tools: { allowed: s.toolsAllowed, blocked: s.toolsBlocked },
        spend: { llmUsdMicros: s.costUsdMicros, blockedActionsUsdMicros: s.blockedPayoutUsdMicros },
        policiesEnforced: ["procurement.allowed_vendors", "rate.per_session_usd:10", "runtime.write_scope"],
        contentHash: "sha256:" + Math.random().toString(16).slice(2).padEnd(64, "0"),
        signature: "ed25519:example-signature-for-mock-mode",
        signingKeyFingerprint: "kf_mock",
      };
    },
  };

  function synthesizeEvents(s) {
    var out = [
      { seq: 1, ts: s.startedAt, kind: "session.start", msg: s.agent + " opened session", severity: "info" },
    ];
    var n = Math.min(s.events, 10);
    for (var i = 2; i <= n; i++) {
      out.push({
        seq: i,
        ts: s.startedAt,
        kind: i % 3 === 0 ? "tool.call" : "llm.request",
        msg: i % 3 === 0 ? "search_inventory()" : "gpt-4o · " + (400 + i * 30) + " tokens",
        severity: "info",
      });
    }
    if (s.toolsBlocked > 0) {
      out.push({ seq: n + 1, ts: s.endedAt, kind: "tool.block", msg: "BLOCKED — vendor not in allowlist", severity: "err" });
    }
    out.push({ seq: n + 2, ts: s.endedAt, kind: "session.end", msg: "completed · " + s.events + " events", severity: "ok" });
    return out;
  }

  /* ============================================================
   * API — real backend implementation
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
    var res = await fetch(apiUrl(path), {
      method: opts.method || "GET",
      credentials: "include",
      headers: headers,
      body: opts.body,
    });
    var text = await res.text();
    var data = text ? JSON.parse(text) : {};
    if (!res.ok) {
      var err = new Error(data.error || "http_" + res.status);
      err.status = res.status;
      err.data = data;
      throw err;
    }
    return data;
  }

  var ApiDataSource = {
    mode: "api",
    async getSession() {
      try {
        var r = await apiFetch("/api/v1/auth/me");
        return { user: r.user, org: r.org };
      } catch (e) {
        if (e.status === 401) return null;
        throw e;
      }
    },
    async signup(input) {
      var r = await apiFetch("/api/v1/auth/signup", {
        method: "POST",
        body: { email: input.email, password: input.password, orgName: input.orgName || input.email.split("@")[0] + "'s org" },
      });
      return { user: r.user, org: r.org };
    },
    async login(input) {
      var r = await apiFetch("/api/v1/auth/login", {
        method: "POST",
        body: { email: input.email, password: input.password },
      });
      return { user: r.user, org: r.org };
    },
    async logout() { await apiFetch("/api/v1/auth/logout", { method: "POST" }); },
    async listDeployments() {
      var r = await apiFetch("/api/v1/deployments");
      var deps = r.deployments || [];
      return deps.map(function (d) {
        return {
          id: d.id,
          orgId: d.orgId,
          name: d.name,
          environment: d.environment || "production",
          region: d.region || null,
          status: d.lastIngestAt && (Date.now() - new Date(d.lastIngestAt).getTime() < 5 * 60 * 1000) ? "connected" : "pending",
          version: d.version || null,
          lastSeenAt: d.lastIngestAt || null,
          createdAt: d.createdAt,
          ingestTokenHint: d.ingestTokenHint ? "av_live_" + d.ingestTokenHint.slice(0, 4) + "…" : "—",
          publicKeyHex: d.publicKeyHex || null,
        };
      });
    },
    async createDeployment(input) {
      var r = await apiFetch("/api/v1/deployments", { method: "POST", body: input });
      // Backend returns {id, name, environment, ingestToken}
      var dep = r.deployment || {
        id: r.id, orgId: null, name: r.name,
        environment: r.environment || input.environment || "production",
        region: input.region || null, status: "pending", version: null,
        lastSeenAt: null, createdAt: new Date().toISOString(),
        ingestTokenHint: "av_live_••••" + (r.ingestToken || "").slice(-4),
        publicKeyHex: null,
      };
      return { deployment: dep, ingestToken: r.ingestToken };
    },
    async rotateDeploymentToken(id) {
      var r = await apiFetch("/api/v1/deployments/" + id + "/rotate-token", { method: "POST", body: {} });
      return { ingestToken: r.ingestToken };
    },
    async deleteDeployment(id) {
      await apiFetch("/api/v1/deployments/" + id, { method: "DELETE" });
    },
    async getOverview() {
      var r = await apiFetch("/api/v1/overview");
      var stats = r.stats || {};
      var sessions = r.sessions || [];
      var llmCents = parseInt(stats.costUsdMicros || "0", 10) / 1e6;
      var blockedDollars = parseInt(stats.blockedPayoutUsdMicros || "0", 10) / 1e6;
      // Distinct deployments visible in window
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
      };
    },
    async listSessions(params) {
      var qs = "?limit=200";
      if (params && params.deploymentId) qs += "&deploymentId=" + encodeURIComponent(params.deploymentId);
      var r = await apiFetch("/api/v1/overview" + qs);
      var out = (r.sessions || []).map(normalizeSession);
      return { sessions: out, total: out.length };
    },
    async getSessionById(id) {
      var r = await apiFetch("/api/v1/sessions/" + id);
      var s = normalizeSession(r.session);
      var events = (r.session.events || []).map(normalizeEvent);
      return { session: s, events: events };
    },
    async getReceipt(sessionId) {
      try {
        var r = await apiFetch("/api/v1/receipts/" + sessionId);
        var rec = r.receipt || r;
        // The receipt's canonical body is stored as raw JSON string.
        var body;
        try { body = JSON.parse(rec.body); } catch (e) { body = { raw: rec.body }; }
        return {
          schemaVersion: body.schemaVersion || "1.0",
          receiptId: rec.receiptId,
          sessionId: sessionId,
          orgId: state && state.session ? state.session.org.id : null,
          deploymentId: rec.session && rec.session.deploymentId,
          startedAt: body.startedAt,
          endedAt: body.endedAt,
          eventCount: rec.eventCount,
          tools: body.tools || {},
          spend: body.spend || {},
          policiesEnforced: body.policiesEnforced || [],
          contentHash: body.contentHash,
          signature: rec.sigB64,
          signingKeyFingerprint: rec.keyIdHint,
        };
      } catch (e) {
        if (e.status === 404) return { note: "No signed receipt yet — the daemon posts one at session seal.", sessionId: sessionId };
        throw e;
      }
    },
  };

  function normalizeSession(s) {
    if (!s) return s;
    return {
      id: s.id,
      externalId: s.externalId,
      deploymentId: (s.deployment && s.deployment.id) || s.deploymentId,
      agent: s.agent,
      user: s.user || "—",
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
      seq: e.seq,
      ts: e.occurredAt || e.ts,
      kind: e.kind + (e.tag ? " · " + e.tag : ""),
      msg: (e.body || "") + (e.sub ? " · " + e.sub : ""),
      severity: sev,
    };
  }

  // Keep a reference to app state for receipt.orgId fallback.
  var state = null;
  window.__setDataSourceState = function (s) { state = s; };

  window.dataSource = window.MOCK_MODE ? MockDataSource : ApiDataSource;
})();
