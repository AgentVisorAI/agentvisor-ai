/*
 * AgentVisor AI console — application shell.
 *
 * Hash-based router. Views: /login, /signup, /overview, /sessions,
 * /sessions/:id, /deployments, /settings. All data flows through
 * window.dataSource (see datasource.js), which is either the mock
 * or the real API implementation depending on window.MOCK_MODE.
 */

(function () {
  "use strict";

  var $ = function (sel, root) { return (root || document).querySelector(sel); };
  var app = $("#app");

  var state = {
    session: null,   // {user, org} once authed
    route: null,     // current parsed route
    ds: window.dataSource,
  };

  /* ---------- routing ---------- */

  function parseHash() {
    var h = (location.hash || "#/overview").replace(/^#/, "");
    var parts = h.split("/").filter(Boolean);
    return { path: parts, hash: h };
  }

  function navigate(hash) {
    if (location.hash === hash) render();
    else location.hash = hash;
  }

  window.addEventListener("hashchange", render);

  /* ---------- session bootstrap ---------- */

  async function boot() {
    try {
      state.session = await state.ds.getSession();
    } catch (e) {
      console.error("session lookup failed", e);
    }
    if (!location.hash) location.hash = state.session ? "#/overview" : "#/login";
    else render();
  }

  /* ---------- render ---------- */

  async function render() {
    state.route = parseHash();
    var path = state.route.path;

    // Auth-required routes
    var publicRoutes = ["login", "signup"];
    if (!state.session && !publicRoutes.includes(path[0])) {
      navigate("#/login");
      return;
    }
    if (state.session && publicRoutes.includes(path[0])) {
      navigate("#/overview");
      return;
    }

    if (!state.session) {
      if (path[0] === "signup") return renderSignup();
      return renderLogin();
    }

    // Authed layout
    renderShell();
    var main = $("#view");
    if (path[0] === "overview" || !path[0]) return renderOverview(main);
    if (path[0] === "sessions" && path[1]) return renderSessionDetail(main, path[1]);
    if (path[0] === "sessions") return renderSessionsList(main);
    if (path[0] === "deployments") return renderDeployments(main);
    if (path[0] === "settings") return renderSettings(main);
    main.innerHTML = notFound();
  }

  /* ---------- helpers ---------- */

  function h(html) { var t = document.createElement("template"); t.innerHTML = html.trim(); return t.content.firstChild; }
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]; }); }
  function initials(name) { return String(name || "?").trim().slice(0, 1).toUpperCase(); }

  function timeAgo(iso) {
    if (!iso) return "—";
    var s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
    if (s < 60) return Math.floor(s) + "s ago";
    if (s < 3600) return Math.floor(s / 60) + "m ago";
    if (s < 86400) return Math.floor(s / 3600) + "h ago";
    return Math.floor(s / 86400) + "d ago";
  }

  function toast(msg) {
    var t = h('<div class="toast">' + esc(msg) + "</div>");
    document.body.appendChild(t);
    setTimeout(function () { t.remove(); }, 2500);
  }

  function loading() { return '<div class="loading"><span class="spinner"></span>Loading…</div>'; }
  function notFound() { return '<div class="empty"><h3>Not found</h3><p>The page you\'re looking for doesn\'t exist.</p><a class="btn" href="#/overview">Go to overview</a></div>'; }

  function usd(cents) { return "$" + Number(cents).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 }); }
  function usdMicros(str) {
    var n = typeof str === "string" ? parseInt(str, 10) : (str || 0);
    return "$" + (n / 1e6).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  }
  function usdMicrosBig(str) {
    var n = typeof str === "string" ? parseInt(str, 10) : (str || 0);
    var v = n / 1e6;
    if (v >= 1000) return "$" + Math.round(v).toLocaleString();
    return "$" + v.toFixed(2);
  }

  /* ============================================================
   * SHELL — sidebar + topbar
   * ============================================================ */

  function renderShell() {
    var current = state.route.path[0] || "overview";
    var org = state.session.org;
    var user = state.session.user;
    var modeChip = state.ds.mode === "mock"
      ? '<span class="env-pill mock" title="This console is displaying built-in demo data. Set window.MOCK_MODE=false to talk to a real backend.">Demo data</span>'
      : '<span class="env-pill">Live</span>';

    app.innerHTML = "";
    app.appendChild(h(
      '<div class="app-shell">' +
        '<header class="topbar">' +
          '<a class="brand" href="#/overview">' +
            '<span class="brand-mark">A</span> AgentVisor AI' +
          "</a>" +
          modeChip +
          '<div class="spacer"></div>' +
          '<button class="user-menu" id="userMenu">' +
            '<span class="avatar">' + esc(initials(user.displayName || user.email)) + "</span>" +
            "<span>" + esc(user.email) + "</span>" +
          "</button>" +
        "</header>" +
        '<nav class="sidebar">' +
          '<div class="group-label">' + esc(org.name) + "</div>" +
          navLink("overview", current, "Overview", iconChart()) +
          navLink("sessions", current, "Sessions", iconActivity()) +
          navLink("deployments", current, "Deployments", iconServer()) +
          '<div class="group-label">Account</div>' +
          navLink("settings", current, "Settings", iconGear()) +
        "</nav>" +
        '<main class="main" id="view"></main>' +
      "</div>"
    ));

    $("#userMenu").addEventListener("click", function () {
      if (confirm("Sign out?")) {
        state.ds.logout().then(function () {
          state.session = null;
          navigate("#/login");
        });
      }
    });
  }

  function navLink(key, current, label, icon) {
    var active = current === key ? ' class="active"' : "";
    return '<a href="#/' + key + '"' + active + ">" + icon + "<span>" + label + "</span></a>";
  }

  /* ---------- icons ---------- */

  function iconChart() { return '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M2 14V3M2 14h12M5 11V8M8 11V6M11 11v-4"/></svg>'; }
  function iconActivity() { return '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1.5 8h3l2-5 3 10 2-5h3"/></svg>'; }
  function iconServer() { return '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2" y="3" width="12" height="4" rx="1"/><rect x="2" y="9" width="12" height="4" rx="1"/><circle cx="5" cy="5" r=".7" fill="currentColor"/><circle cx="5" cy="11" r=".7" fill="currentColor"/></svg>'; }
  function iconGear() { return '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="8" cy="8" r="2"/><path d="M8 1v2M8 13v2M15 8h-2M3 8H1M13 3l-1.4 1.4M4.4 11.6L3 13M13 13l-1.4-1.4M4.4 4.4L3 3"/></svg>'; }

  /* ============================================================
   * LOGIN / SIGNUP
   * ============================================================ */

  function renderLogin() {
    app.innerHTML = "";
    app.appendChild(h(
      '<div class="auth-shell">' +
        '<div class="auth-card">' +
          '<div class="auth-brand">' +
            '<span class="auth-brand-mark">A</span> AgentVisor AI' +
          "</div>" +
          '<h1>Sign in</h1>' +
          '<p class="sub">Access your agent control plane.</p>' +
          '<form id="loginForm">' +
            '<div class="field">' +
              '<label for="email">Work email</label>' +
              '<input id="email" type="email" required autocomplete="email" placeholder="you@company.com" />' +
            "</div>" +
            '<div class="field">' +
              '<label for="password">Password</label>' +
              '<input id="password" type="password" required autocomplete="current-password" />' +
            "</div>" +
            '<div id="loginErr"></div>' +
            '<button class="primary" type="submit">Sign in</button>' +
          "</form>" +
          '<div class="auth-alt">' +
            "No account yet? " + '<a href="#/signup">Create one</a>' +
          "</div>" +
          (state.ds.mode === "mock" ?
            '<div class="mock-badge">Demo mode — any email &amp; password works.</div>' : "") +
        "</div>" +
      "</div>"
    ));
    $("#loginForm").addEventListener("submit", function (e) {
      e.preventDefault();
      var email = $("#email").value.trim();
      var pw = $("#password").value;
      var errEl = $("#loginErr");
      var btn = e.target.querySelector("button");
      btn.disabled = true;
      state.ds.login({ email: email, password: pw }).then(function (session) {
        state.session = session;
        navigate("#/overview");
      }).catch(function (err) {
        btn.disabled = false;
        errEl.innerHTML = '<div class="auth-err">' + esc(err.message || "Sign in failed") + "</div>";
      });
    });
  }

  function renderSignup() {
    app.innerHTML = "";
    app.appendChild(h(
      '<div class="auth-shell">' +
        '<div class="auth-card">' +
          '<div class="auth-brand">' +
            '<span class="auth-brand-mark">A</span> AgentVisor AI' +
          "</div>" +
          '<h1>Create an account</h1>' +
          '<p class="sub">Start policing your agent traffic in under 60 seconds.</p>' +
          '<form id="signupForm">' +
            '<div class="field">' +
              '<label for="orgName">Company name</label>' +
              '<input id="orgName" type="text" required placeholder="Acme Corp" />' +
            "</div>" +
            '<div class="field">' +
              '<label for="email">Work email</label>' +
              '<input id="email" type="email" required autocomplete="email" placeholder="you@company.com" />' +
            "</div>" +
            '<div class="field">' +
              '<label for="password">Password (min 8 characters)</label>' +
              '<input id="password" type="password" required minlength="8" autocomplete="new-password" />' +
            "</div>" +
            '<div id="signupErr"></div>' +
            '<button class="primary" type="submit">Create account</button>' +
          "</form>" +
          '<div class="auth-alt">' +
            "Already have an account? " + '<a href="#/login">Sign in</a>' +
          "</div>" +
          (state.ds.mode === "mock" ?
            '<div class="mock-badge">Demo mode — you\'ll land inside a pre-populated Northwind workspace.</div>' : "") +
        "</div>" +
      "</div>"
    ));
    $("#signupForm").addEventListener("submit", function (e) {
      e.preventDefault();
      var email = $("#email").value.trim();
      var pw = $("#password").value;
      var orgName = $("#orgName").value.trim();
      var errEl = $("#signupErr");
      var btn = e.target.querySelector("button");
      btn.disabled = true;
      state.ds.signup({ email: email, password: pw, orgName: orgName }).then(function (session) {
        state.session = session;
        navigate("#/overview");
      }).catch(function (err) {
        btn.disabled = false;
        errEl.innerHTML = '<div class="auth-err">' + esc(err.message || "Sign up failed") + "</div>";
      });
    });
  }

  /* ============================================================
   * OVERVIEW
   * ============================================================ */

  async function renderOverview(main) {
    main.innerHTML = pageHeader("Overview", "Fleet activity for the last 24 hours.") + loading();
    var stats, sessions;
    try {
      stats = await state.ds.getOverview();
      var res = await state.ds.listSessions();
      sessions = res.sessions.slice(0, 6);
    } catch (e) { return renderError(main, e); }

    var pctBlocked = stats.toolsAllowed + stats.toolsBlocked > 0
      ? Math.round((stats.toolsBlocked / (stats.toolsAllowed + stats.toolsBlocked)) * 100)
      : 0;

    main.innerHTML =
      pageHeader("Overview", "Fleet activity for the last 24 hours.") +
      '<div class="stats">' +
        stat("Sessions", stats.sessions, stats.deployments + " deployment" + (stats.deployments === 1 ? "" : "s")) +
        stat("Tool calls allowed", stats.toolsAllowed, "policy pass") +
        stat("Tool calls blocked", stats.toolsBlocked, pctBlocked + "% block rate", "blocks") +
        stat("LLM spend", "$" + stats.llmSpendUsd, "usage this window") +
        stat("Prevented losses", "$" + Number(stats.blockedSpendUsd).toLocaleString(), "blocked action value", "savings") +
      "</div>" +
      '<div class="card">' +
        '<h2>Recent sessions <span class="count">' + sessions.length + " shown</span></h2>" +
        sessionsTable(sessions) +
        (sessions.length > 0 ? '<div style="margin-top: 12px; text-align: right;"><a href="#/sessions">View all →</a></div>' : "") +
      "</div>";
  }

  function stat(label, value, delta, cls) {
    return '<div class="stat ' + (cls || "") + '">' +
      '<div class="label">' + esc(label) + "</div>" +
      '<div class="value">' + esc(value) + "</div>" +
      (delta ? '<div class="delta">' + esc(delta) + "</div>" : "") +
      "</div>";
  }

  function pageHeader(title, sub, actions) {
    return '<div class="page-header"><div><h1>' + esc(title) + "</h1>" +
      (sub ? '<div class="sub">' + esc(sub) + "</div>" : "") + "</div>" +
      (actions ? '<div class="actions">' + actions + "</div>" : "") + "</div>";
  }

  /* ============================================================
   * SESSIONS LIST
   * ============================================================ */

  async function renderSessionsList(main) {
    main.innerHTML = pageHeader("Sessions", "Every agent session policed by AgentVisor.") + loading();
    var res;
    try { res = await state.ds.listSessions(); }
    catch (e) { return renderError(main, e); }
    if (res.sessions.length === 0) {
      main.innerHTML = pageHeader("Sessions") + emptyState("No sessions yet", "Once your daemon streams traffic, sessions appear here.", "Set up a deployment", "#/deployments");
      return;
    }
    main.innerHTML =
      pageHeader("Sessions", res.sessions.length + " total") +
      '<div class="card" style="padding: 0;">' + sessionsTable(res.sessions) + "</div>";
  }

  function sessionsTable(sessions) {
    if (sessions.length === 0) return emptyState("No sessions yet", "Sessions from your daemons will appear here.");
    var rows = sessions.map(function (s) {
      var blocks = s.toolsBlocked > 0
        ? '<span class="pill err">' + s.toolsBlocked + " blocked</span>"
        : '<span class="pill ok">clean</span>';
      return '<tr data-id="' + esc(s.id) + '">' +
        '<td><div>' + esc(s.agent) + '</div><div class="id">' + esc(s.externalId) + "</div></td>" +
        "<td>" + esc(s.user || "—") + "</td>" +
        '<td class="num">' + s.events + "</td>" +
        '<td class="num">' + s.toolsAllowed + "</td>" +
        "<td>" + blocks + "</td>" +
        '<td class="num">' + usdMicros(s.costUsdMicros) + "</td>" +
        "<td>" + esc(timeAgo(s.startedAt)) + "</td>" +
      "</tr>";
    }).join("");
    var t = h('<div class="table-wrap"><table>' +
      "<thead><tr>" +
        "<th>Session</th><th>Actor</th>" +
        '<th class="num">Events</th><th class="num">Allowed</th>' +
        "<th>Blocked</th>" +
        '<th class="num">LLM cost</th>' +
        "<th>Started</th>" +
      "</tr></thead>" +
      "<tbody>" + rows + "</tbody>" +
    "</table></div>");
    t.addEventListener("click", function (e) {
      var tr = e.target.closest("tr[data-id]");
      if (tr) navigate("#/sessions/" + tr.getAttribute("data-id"));
    });
    return t.outerHTML;
  }

  /* ============================================================
   * SESSION DETAIL
   * ============================================================ */

  async function renderSessionDetail(main, id) {
    main.innerHTML = pageHeader("Session", "", '<a href="#/sessions" class="btn">← All sessions</a>') + loading();
    var data, receipt;
    try {
      data = await state.ds.getSessionById(id);
      receipt = await state.ds.getReceipt(id);
    } catch (e) { return renderError(main, e); }
    var s = data.session;
    var events = data.events || [];

    var eventsHtml = events.map(function (ev) {
      var sev = ev.severity === "err" ? "blocked" : (ev.severity === "ok" ? "allowed" : "");
      return '<div class="event ' + sev + '">' +
        '<span class="t">#' + esc(ev.seq) + "</span>" +
        '<span class="msg"><b>' + esc(ev.kind) + "</b> · " + esc(ev.msg) + "</span>" +
        '<span class="t">' + esc(timeAgo(ev.ts)) + "</span>" +
      "</div>";
    }).join("");

    main.innerHTML =
      pageHeader("Session " + s.externalId, s.agent + " · " + (s.user || "—"), '<a href="#/sessions" class="btn">← All sessions</a>') +
      '<div class="stats">' +
        stat("Events", s.events, "streamed to server") +
        stat("Tool calls allowed", s.toolsAllowed, "policy pass") +
        stat("Tool calls blocked", s.toolsBlocked, s.toolsBlocked > 0 ? "policy hit" : "clean", s.toolsBlocked > 0 ? "blocks" : "") +
        stat("LLM cost", usdMicros(s.costUsdMicros), "actual usage") +
      "</div>" +
      '<div class="detail-grid">' +
        '<div class="card">' +
          '<h2>Event stream <span class="count">' + events.length + " events</span></h2>" +
          '<div class="event-stream">' + eventsHtml + "</div>" +
        "</div>" +
        '<div>' +
          '<div class="card" style="margin-bottom: 16px;">' +
            "<h2>Session details</h2>" +
            '<dl class="kv">' +
              "<dt>Deployment</dt><dd>" + esc(s.deploymentId) + "</dd>" +
              "<dt>Started</dt><dd>" + esc(new Date(s.startedAt).toLocaleString()) + "</dd>" +
              "<dt>Ended</dt><dd>" + esc(s.endedAt ? new Date(s.endedAt).toLocaleString() : "in progress") + "</dd>" +
              "<dt>Blocked value</dt><dd>" + usdMicrosBig(s.blockedPayoutUsdMicros) + "</dd>" +
              "<dt>Receipt hash</dt><dd class=\"mono\">" + esc(s.receiptHash || "—") + "</dd>" +
            "</dl>" +
          "</div>" +
          '<div class="card">' +
            "<h2>Signed receipt</h2>" +
            '<pre class="receipt">' + esc(JSON.stringify(receipt, null, 2)) + "</pre>" +
          "</div>" +
        "</div>" +
      "</div>";
  }

  /* ============================================================
   * DEPLOYMENTS
   * ============================================================ */

  async function renderDeployments(main) {
    var actions = '<button class="btn primary" id="addDep">+ New deployment</button>';
    main.innerHTML = pageHeader("Deployments", "Each daemon streams events + signed receipts to this console.", actions) + loading();
    var deps;
    try { deps = await state.ds.listDeployments(); }
    catch (e) { return renderError(main, e); }

    var body;
    if (deps.length === 0) {
      body = '<div class="card">' + emptyState(
        "No deployments yet",
        "Add a deployment to get an ingest token. Point your agentvisord daemon at this console with that token and events start streaming here.",
        "+ New deployment", null, "addDep2"
      ) + "</div>";
    } else {
      var rows = deps.map(function (d) {
        var statusPill = d.status === "connected"
          ? '<span class="pill ok">connected</span>'
          : '<span class="pill neutral">' + esc(d.status) + "</span>";
        return '<tr data-id="' + esc(d.id) + '">' +
          "<td><div><b>" + esc(d.name) + "</b></div><div class=\"id\">" + esc(d.id) + "</div></td>" +
          '<td><span class="pill neutral">' + esc(d.environment) + "</span></td>" +
          "<td>" + esc(d.region || "—") + "</td>" +
          "<td>" + statusPill + "</td>" +
          "<td>" + esc(d.version || "—") + "</td>" +
          "<td>" + esc(timeAgo(d.lastSeenAt)) + "</td>" +
          '<td><button class="btn" data-action="rotate">Rotate token</button> <button class="btn danger" data-action="delete">Delete</button></td>' +
        "</tr>";
      }).join("");
      body = '<div class="card" style="padding: 0;"><div class="table-wrap"><table>' +
        "<thead><tr><th>Deployment</th><th>Environment</th><th>Region</th><th>Status</th><th>Version</th><th>Last seen</th><th></th></tr></thead>" +
        "<tbody>" + rows + "</tbody></table></div></div>";
    }
    main.innerHTML = pageHeader("Deployments", "Each daemon streams events + signed receipts to this console.", actions) + body;

    var openBtns = ["addDep", "addDep2"].map(function (id) { return document.getElementById(id); }).filter(Boolean);
    openBtns.forEach(function (b) { b.addEventListener("click", function () { openCreateDeploymentModal(); }); });

    var tbody = main.querySelector("tbody");
    if (tbody) {
      tbody.addEventListener("click", function (e) {
        var btn = e.target.closest("button[data-action]");
        var tr = e.target.closest("tr[data-id]");
        if (!tr) return;
        var id = tr.getAttribute("data-id");
        if (!btn) return;
        e.stopPropagation();
        if (btn.getAttribute("data-action") === "rotate") {
          if (!confirm("Rotate ingest token? The old token will stop working immediately.")) return;
          state.ds.rotateDeploymentToken(id).then(function (r) {
            showTokenModal(r.ingestToken, "Token rotated");
          }).catch(function (err) { toast(err.message || "Rotation failed"); });
        } else if (btn.getAttribute("data-action") === "delete") {
          if (!confirm("Delete this deployment? Existing sessions stay, but the daemon can no longer connect.")) return;
          state.ds.deleteDeployment(id).then(function () {
            toast("Deployment removed");
            renderDeployments(main);
          }).catch(function (err) { toast(err.message || "Delete failed"); });
        }
      });
    }
  }

  function openCreateDeploymentModal() {
    var backdrop = h(
      '<div class="modal-backdrop">' +
        '<div class="modal">' +
          "<h2>New deployment</h2>" +
          '<p class="sub">Register a daemon. You\'ll get an ingest token — copy it now; it won\'t be shown again.</p>' +
          '<form id="depForm">' +
            '<div class="field"><label>Name</label><input id="depName" required placeholder="acme-prod" pattern="[a-zA-Z0-9\\-_]+" /></div>' +
            '<div class="field"><label>Environment</label><select id="depEnv"><option>production</option><option>staging</option><option>development</option></select></div>' +
            '<div class="field"><label>Region (optional)</label><input id="depRegion" placeholder="us-east-1" /></div>' +
            '<div class="actions"><button type="button" class="btn" data-close>Cancel</button><button class="btn primary" type="submit">Create</button></div>' +
          "</form>" +
        "</div>" +
      "</div>"
    );
    document.body.appendChild(backdrop);
    backdrop.addEventListener("click", function (e) {
      if (e.target === backdrop || e.target.hasAttribute("data-close")) backdrop.remove();
    });
    backdrop.querySelector("#depForm").addEventListener("submit", function (e) {
      e.preventDefault();
      var name = $("#depName").value.trim();
      var env = $("#depEnv").value;
      var region = $("#depRegion").value.trim();
      var btn = e.target.querySelector('button[type="submit"]');
      btn.disabled = true;
      state.ds.createDeployment({ name: name, environment: env, region: region || undefined }).then(function (r) {
        backdrop.remove();
        showTokenModal(r.ingestToken, "Deployment created");
      }).catch(function (err) {
        btn.disabled = false;
        toast(err.message || "Create failed");
      });
    });
  }

  function showTokenModal(token, title) {
    var backdrop = h(
      '<div class="modal-backdrop">' +
        '<div class="modal">' +
          "<h2>" + esc(title || "Ingest token") + "</h2>" +
          '<p class="sub">Point your daemon at this console using the token below. Store it in your secret manager — it won\'t be shown again.</p>' +
          '<div class="token-display" id="tokBox">' + esc(token) + "</div>" +
          '<div class="notice">This is the only time you\'ll see the full token. If you lose it, rotate to get a new one.</div>' +
          '<div class="actions"><button type="button" class="btn" id="copyTok">Copy</button><button type="button" class="btn primary" data-close>Done</button></div>' +
        "</div>" +
      "</div>"
    );
    document.body.appendChild(backdrop);
    backdrop.addEventListener("click", function (e) {
      if (e.target === backdrop || e.target.hasAttribute("data-close")) {
        backdrop.remove();
        var main = $("#view");
        if (main) renderDeployments(main);
      }
    });
    backdrop.querySelector("#copyTok").addEventListener("click", function () {
      navigator.clipboard.writeText(token).then(function () { toast("Token copied"); });
    });
  }

  /* ============================================================
   * SETTINGS
   * ============================================================ */

  async function renderSettings(main) {
    main.innerHTML =
      pageHeader("Settings", "Organization and workspace preferences.") +
      '<div class="card" style="margin-bottom: 16px;">' +
        "<h2>Organization</h2>" +
        '<dl class="kv">' +
          "<dt>Name</dt><dd>" + esc(state.session.org.name) + "</dd>" +
          "<dt>Org ID</dt><dd class=\"mono\">" + esc(state.session.org.id) + "</dd>" +
          "<dt>Created</dt><dd>" + esc(new Date(state.session.org.createdAt).toLocaleDateString()) + "</dd>" +
        "</dl>" +
      "</div>" +
      '<div class="card" style="margin-bottom: 16px;">' +
        "<h2>Account</h2>" +
        '<dl class="kv">' +
          "<dt>Email</dt><dd>" + esc(state.session.user.email) + "</dd>" +
          "<dt>User ID</dt><dd class=\"mono\">" + esc(state.session.user.id) + "</dd>" +
        "</dl>" +
        '<div style="margin-top: 16px;"><button class="btn danger" id="signOut">Sign out</button></div>' +
      "</div>" +
      (state.ds.mode === "mock" ?
        '<div class="card"><h2>Demo mode</h2><p style="color: var(--fg-2); margin: 0 0 12px;">This console is running against built-in fixtures. To connect to a real backend, set <code>window.MOCK_MODE = false</code> and <code>window.API_BASE = "https://api.your-domain.com/api/v1"</code> in <code>docs/app/index.html</code>.</p><p style="color: var(--fg-2); margin: 0;">See the <a href="pitch/">pitch walkthrough</a> for a scripted demo of the end-to-end flow.</p></div>' : "");
    var btn = $("#signOut");
    if (btn) btn.addEventListener("click", function () {
      state.ds.logout().then(function () {
        state.session = null;
        navigate("#/login");
      });
    });
  }

  /* ============================================================
   * SHARED
   * ============================================================ */

  function emptyState(title, body, ctaLabel, ctaHref, ctaId) {
    var cta = "";
    if (ctaLabel && ctaHref) cta = '<a class="btn primary" href="' + esc(ctaHref) + '">' + esc(ctaLabel) + "</a>";
    else if (ctaLabel) cta = '<button class="btn primary" id="' + esc(ctaId || "cta") + '">' + esc(ctaLabel) + "</button>";
    return '<div class="empty"><h3>' + esc(title) + "</h3><p>" + esc(body) + "</p>" + cta + "</div>";
  }

  function renderError(main, err) {
    console.error(err);
    main.innerHTML = pageHeader("Error") + '<div class="card"><div class="empty"><h3>Something went wrong</h3><p>' + esc(err.message || "Unknown error") + '</p><button class="btn" onclick="location.reload()">Reload</button></div></div>';
  }

  /* ---------- go ---------- */

  boot();
})();
