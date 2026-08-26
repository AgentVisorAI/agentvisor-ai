/*
 * AgentVisor AI console — application.
 *
 * Hash-routed vanilla SPA. All data flows through window.dataSource
 * (mock or api). Views: /login /signup /overview /sessions /sessions/:id
 * /deployments /deployments/:id /policies /policies/:id /settings
 *
 * The console assumes a keyboard-first user: ⌘K palette, g-o / g-s / g-d /
 * g-p / g-, navigation shortcuts, ? for the shortcut sheet.
 */

(function () {
  "use strict";

  var $ = function (sel, root) { return (root || document).querySelector(sel); };
  var $$ = function (sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); };
  var app = $("#app");

  var state = {
    session: null,
    route: null,
    ds: window.dataSource,
    range: "24h",
    theme: null,
    gPrefixAt: 0,
    settingsTab: "general",
  };

  /* ---------- theme ---------- */

  function applyTheme(t) {
    document.documentElement.setAttribute("data-theme", t);
    state.theme = t;
    try { localStorage.setItem("av_theme", t); } catch (e) {}
  }
  function initTheme() {
    var saved;
    try { saved = localStorage.getItem("av_theme"); } catch (e) {}
    if (saved === "light" || saved === "dark") applyTheme(saved);
    else state.theme = matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  function toggleTheme() { applyTheme((state.theme === "dark") ? "light" : "dark"); render(); }

  /* ---------- routing ---------- */

  function parseHash() {
    var h = (location.hash || "#/overview").replace(/^#/, "");
    // Strip a query fragment (`#/reset?token=…&email=…`) before splitting.
    var pathPart = h.split("?")[0];
    var parts = pathPart.split("/").filter(Boolean);
    return { path: parts, hash: h };
  }
  function navigate(hash) {
    if (location.hash === hash) render();
    else location.hash = hash;
  }
  window.addEventListener("hashchange", render);

  /* ---------- session bootstrap ---------- */

  async function boot() {
    initTheme();
    try { state.session = await state.ds.getSession(); } catch (e) { console.error("session", e); }
    if (!location.hash) location.hash = state.session ? "#/overview" : "#/login";
    else render();
    installKeyboardShortcuts();
    if (state.session) startLiveStream();
  }

  var liveUnsub = null;
  var liveEventBuffer = [];
  function startLiveStream() {
    if (liveUnsub || !state.ds.subscribe) return;
    try {
      liveUnsub = state.ds.subscribe(function (msg) {
        // Meta messages control the pill's connection state.
        if (msg.type === "stream.open" || msg.type === "hello") {
          setLiveState("live");
          return;
        }
        if (msg.type === "stream.closed") {
          setLiveState("reconnecting");
          return;
        }
        liveEventBuffer.push({ at: Date.now(), msg: msg });
        if (liveEventBuffer.length > 40) liveEventBuffer.shift();
        pulseLiveIndicator();
        onLiveEvent(msg);
      });
    } catch (e) {
      console.warn("live stream unavailable", e);
    }
  }
  function stopLiveStream() {
    if (liveUnsub) { liveUnsub(); liveUnsub = null; }
  }
  function setLiveState(s) {
    var el = document.querySelector('.env-pill.live-pulse');
    if (!el) return;
    el.classList.toggle('reconnecting', s === "reconnecting");
    el.title = s === "reconnecting"
      ? "Reconnecting to the daemon stream…"
      : "Streaming events from the daemon";
    var label = el.querySelector('.live-label');
    if (label) label.textContent = s === "reconnecting" ? "Reconnecting" : "Live";
  }
  function pulseLiveIndicator() {
    var el = document.querySelector('.env-pill.live-pulse');
    if (!el) return;
    el.classList.remove('pulsing');
    // Force reflow so re-adding the class restarts the animation.
    void el.offsetWidth;
    el.classList.add('pulsing');
  }
  function onLiveEvent(msg) {
    // Overview: refresh KPIs + chart on any relevant event. Debounced so a
    // burst of events (common right after a session opens) only redraws once.
    var path = state.route && state.route.path;
    if (!path || !path[0]) return;
    if (path[0] === "overview") scheduleOverviewRefresh();
    else if (path[0] === "sessions" && path[1] && msg.type === "events.appended" && msg.data.sessionId === path[1]) {
      scheduleSessionDetailRefresh(path[1]);
    }
  }
  var _ovT;
  function scheduleOverviewRefresh() {
    clearTimeout(_ovT);
    _ovT = setTimeout(function () {
      var main = document.getElementById("view");
      if (main && (!state.route || state.route.path[0] === "overview")) renderOverview(main);
    }, 700);
  }
  var _sdT;
  function scheduleSessionDetailRefresh(id) {
    clearTimeout(_sdT);
    _sdT = setTimeout(function () {
      var main = document.getElementById("view");
      if (main && state.route && state.route.path[0] === "sessions" && state.route.path[1] === id) {
        renderSessionDetail(main, id);
      }
    }, 400);
  }

  /* ---------- main render ---------- */

  async function render() {
    state.route = parseHash();
    var path = state.route.path;
    var publicRoutes = ["login", "signup", "reset"];
    if (!state.session && !publicRoutes.includes(path[0])) return navigate("#/login");
    if (state.session && publicRoutes.includes(path[0])) return navigate("#/overview");
    if (!state.session) {
      if (path[0] === "signup") return renderSignup();
      if (path[0] === "reset") return renderReset();
      return renderLogin();
    }

    renderShell();
    var main = $("#view");
    if (path[0] === "overview" || !path[0]) return renderOverview(main);
    if (path[0] === "sessions" && path[1]) return renderSessionDetail(main, path[1]);
    if (path[0] === "sessions") return renderSessionsList(main);
    if (path[0] === "deployments" && path[1]) return renderDeploymentDetail(main, path[1]);
    if (path[0] === "deployments") return renderDeployments(main);
    if (path[0] === "policies" && path[1]) return renderPolicyDetail(main, path[1]);
    if (path[0] === "policies") return renderPolicies(main);
    if (path[0] === "settings") return renderSettings(main, path[1] || "general");
    main.innerHTML = notFound();
  }

  /* ---------- utilities ---------- */

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
  function toast(msg, err) {
    var t = h('<div class="toast ' + (err ? "err" : "") + '">' + esc(msg) + "</div>");
    document.body.appendChild(t);
    setTimeout(function () { t.remove(); }, 2200);
  }
  function loadingBlock(kind) {
    if (kind === "stats") {
      var boxes = "";
      for (var i = 0; i < 5; i++) boxes += '<div class="stat"><span class="skl h-12 w-4"></span><br/><span class="skl h-24 w-6" style="margin-top:6px"></span></div>';
      return '<div class="stats">' + boxes + '</div><div class="skl h-180 w-full"></div>';
    }
    if (kind === "table") {
      var rows = "";
      for (var j = 0; j < 6; j++) rows += '<div style="padding:12px 16px; border-bottom:1px solid var(--border);"><span class="skl h-16 w-4"></span></div>';
      return '<div class="table-wrap">' + rows + '</div>';
    }
    return '<div class="empty"><span class="spinner"></span>Loading…</div>';
  }
  function notFound() { return '<div class="empty"><h3>Not found</h3><p>The page you\'re looking for doesn\'t exist.</p><a class="btn" href="#/overview">Go to overview</a></div>'; }
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
   * SVG CHART GENERATORS
   * ============================================================ */

  function sparkline(values, opts) {
    opts = opts || {};
    var w = opts.w || 88, hh = opts.h || 28;
    var max = Math.max.apply(null, values.length ? values : [1]);
    var min = 0;
    var range = Math.max(1, max - min);
    var stepX = values.length > 1 ? w / (values.length - 1) : 0;
    var pts = values.map(function (v, i) {
      var x = i * stepX;
      var y = hh - ((v - min) / range) * (hh - 3) - 1;
      return x.toFixed(1) + "," + y.toFixed(1);
    }).join(" ");
    var color = opts.color || "var(--accent)";
    var fill = opts.fill || "var(--accent-bg)";
    var area = "0," + hh + " " + pts + " " + w + "," + hh;
    return '<svg class="spark" viewBox="0 0 ' + w + ' ' + hh + '" xmlns="http://www.w3.org/2000/svg">' +
      '<polygon fill="' + fill + '" points="' + area + '"/>' +
      '<polyline fill="none" stroke="' + color + '" stroke-width="1.5" stroke-linejoin="round" points="' + pts + '"/>' +
      '</svg>';
  }

  function stackedBarChart(series, opts) {
    opts = opts || {};
    var w = opts.w || 720, hh = opts.h || 180;
    var padL = 32, padR = 8, padT = 12, padB = 22;
    var chartW = w - padL - padR;
    var chartH = hh - padT - padB;
    var n = series.length;
    var gap = n <= 24 ? 3 : (n <= 30 ? 2 : 1);
    var barW = Math.max(2, chartW / n - gap);
    var max = Math.max.apply(null, series.map(function (s) { return s.allowed + s.blocked; }).concat([1]));
    max = Math.ceil(max / 5) * 5 || 5;
    var bars = "";
    var hoverRects = "";
    for (var i = 0; i < n; i++) {
      var s = series[i];
      var x = padL + i * (barW + gap);
      var totalH = ((s.allowed + s.blocked) / max) * chartH;
      var blockedH = (s.blocked / max) * chartH;
      var yAllowedTop = padT + chartH - totalH;
      var yBlockedTop = padT + chartH - blockedH;
      if (s.allowed) bars += '<rect class="bar" x="' + x.toFixed(1) + '" y="' + yAllowedTop.toFixed(1) + '" width="' + barW.toFixed(1) + '" height="' + (totalH - blockedH).toFixed(1) + '" rx="1.5"/>';
      if (s.blocked) bars += '<rect class="bar blocked" x="' + x.toFixed(1) + '" y="' + yBlockedTop.toFixed(1) + '" width="' + barW.toFixed(1) + '" height="' + blockedH.toFixed(1) + '" rx="1.5"/>';
      // Wide hover strip covering each bucket for tooltip pickup
      hoverRects += '<rect class="hover-strip" x="' + x.toFixed(1) + '" y="' + padT + '" width="' + (barW + gap).toFixed(1) + '" height="' + chartH + '" fill="transparent" data-idx="' + i + '" />';
    }
    var grid = "";
    for (var g = 0; g <= 4; g++) {
      var gy = (padT + (chartH / 4) * g).toFixed(1);
      grid += '<line x1="' + padL + '" y1="' + gy + '" x2="' + (w - padR) + '" y2="' + gy + '"/>';
    }
    var yLabels = "";
    for (var yi = 0; yi <= 4; yi++) {
      var yv = Math.round(max - (max / 4) * yi);
      var yy = (padT + (chartH / 4) * yi + 3).toFixed(1);
      yLabels += '<text x="' + (padL - 6) + '" y="' + yy + '" text-anchor="end">' + yv + '</text>';
    }
    var xStep = Math.max(1, Math.floor(n / 6));
    var xLabels = "";
    for (var xi = 0; xi < n; xi += xStep) {
      var xx = padL + xi * (barW + gap) + barW / 2;
      xLabels += '<text x="' + xx.toFixed(1) + '" y="' + (hh - 6) + '" text-anchor="middle">' + esc(series[xi].label || "") + '</text>';
    }
    var cursor = '<line class="cursor" id="chartCursor" x1="0" y1="' + padT + '" x2="0" y2="' + (padT + chartH) + '" style="opacity:0"/>';
    return '<svg class="chart-svg" viewBox="0 0 ' + w + ' ' + hh + '" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="none">' +
      '<g class="grid">' + grid + '</g>' +
      '<g class="axis">' + yLabels + xLabels + '</g>' +
      bars +
      cursor +
      '<g>' + hoverRects + '</g>' +
      '</svg>';
  }

  /* ============================================================
   * SHELL
   * ============================================================ */

  function signOut() {
    confirmModal({
      title: "Sign out?",
      body: "You'll need to sign in again to access this workspace.",
      confirmLabel: "Sign out",
      danger: false,
      onConfirm: function () {
        stopLiveStream();
        state.ds.logout().then(function () { state.session = null; navigate("#/login"); });
      },
    });
  }

  function renderShell() {
    var current = state.route.path[0] || "overview";
    var org = state.session.org;
    var user = state.session.user;
    var modeChip = state.ds.mode === "mock"
      ? '<span class="env-pill" title="Console is showing built-in demo data. Set MOCK_MODE=false to talk to a live backend.">Demo</span>'
      : '<span class="env-pill">Live</span>';
    var liveChip = '<span class="env-pill live-pulse" title="Streaming events from the daemon"><span class="live-label">Live</span></span>';

    app.innerHTML = "";
    app.appendChild(h(
      '<div class="app-shell">' +
        '<header class="topbar">' +
          '<a class="brand" href="#/overview">' +
            '<span class="brand-mark">A</span>' +
            '<span>AgentVisor</span>' +
          "</a>" +
          modeChip +
          liveChip +
          '<div class="spacer"></div>' +
          '<button class="cmdk-trigger" id="cmdkOpen">' +
            '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="7" cy="7" r="4.5"/><path d="M10.5 10.5L14 14"/></svg>' +
            '<span>Search or run a command…</span>' +
            '<span class="kbd">⌘K</span>' +
          "</button>" +
          '<button class="theme-btn" id="themeBtn" title="Toggle theme">' + iconTheme() + "</button>" +
          '<button class="user-btn" id="userBtn">' +
            '<span class="avatar">' + esc(initials(user.displayName || user.email)) + "</span>" +
            "<span>" + esc(user.email) + "</span>" +
          "</button>" +
        "</header>" +
        '<nav class="sidebar">' +
          '<div class="org-switcher">' +
            '<span class="avatar">' + esc(org.name.slice(0, 1).toUpperCase()) + "</span>" +
            "<span>" + esc(org.name) + "</span>" +
            '<span class="env">Production</span>' +
          "</div>" +
          navLink("overview", current, "Overview", iconChart(), "G O") +
          navLink("sessions", current, "Sessions", iconActivity(), "G S") +
          navLink("policies", current, "Policies", iconShield(), "G P") +
          navLink("deployments", current, "Deployments", iconServer(), "G D") +
          '<div class="group-label">Account</div>' +
          navLink("settings", current, "Settings", iconGear(), "G ,") +
        "</nav>" +
        '<main class="main" id="view"></main>' +
      "</div>"
    ));
    $("#cmdkOpen").addEventListener("click", openCmdK);
    $("#themeBtn").addEventListener("click", toggleTheme);
    $("#userBtn").addEventListener("click", signOut);
  }
  function navLink(key, current, label, icon, kbd) {
    var active = current === key ? ' class="active"' : "";
    return '<a href="#/' + key + '"' + active + ">" + icon + "<span>" + label + "</span>" +
      (kbd ? '<span class="kbd-hint">' + kbd + "</span>" : "") + "</a>";
  }

  /* ---------- icons ---------- */
  function iconChart() { return '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M2 14V3M2 14h12M5 11V8M8 11V6M11 11v-4"/></svg>'; }
  function iconActivity() { return '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M1.5 8h3l2-5 3 10 2-5h3"/></svg>'; }
  function iconServer() { return '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2" y="3" width="12" height="4" rx="1"/><rect x="2" y="9" width="12" height="4" rx="1"/><circle cx="5" cy="5" r=".7" fill="currentColor"/><circle cx="5" cy="11" r=".7" fill="currentColor"/></svg>'; }
  function iconGear() { return '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><circle cx="8" cy="8" r="2"/><path d="M8 1v2M8 13v2M15 8h-2M3 8H1M13 3l-1.4 1.4M4.4 11.6L3 13M13 13l-1.4-1.4M4.4 4.4L3 3"/></svg>'; }
  function iconShield() { return '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"><path d="M8 1.5l5.5 2v4c0 3-2.4 5.7-5.5 6.5C4.9 13.2 2.5 10.5 2.5 7.5v-4L8 1.5z"/><path d="M5.8 7.8l1.6 1.6L10.4 6.4" stroke-linecap="round"/></svg>'; }
  function iconTheme() { return '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="8" cy="8" r="3"/><path d="M8 1v1.5M8 13.5V15M1 8h1.5M13.5 8H15M3 3l1 1M12 12l1 1M3 13l1-1M12 4l1-1"/></svg>'; }
  function iconGoogle() { return '<svg viewBox="0 0 18 18"><path fill="#4285F4" d="M17.64 9.2c0-.64-.06-1.25-.16-1.84H9v3.48h4.84c-.21 1.13-.85 2.08-1.8 2.72v2.26h2.92c1.7-1.57 2.68-3.88 2.68-6.62z"/><path fill="#34A853" d="M9 18c2.43 0 4.47-.8 5.96-2.18l-2.92-2.26c-.8.54-1.83.86-3.04.86-2.34 0-4.32-1.58-5.03-3.7H.96v2.32C2.44 15.98 5.48 18 9 18z"/><path fill="#FBBC05" d="M3.97 10.72c-.18-.54-.28-1.12-.28-1.72s.1-1.18.28-1.72V4.96H.96C.35 6.18 0 7.55 0 9s.35 2.82.96 4.04l3.01-2.32z"/><path fill="#EA4335" d="M9 3.58c1.32 0 2.51.45 3.44 1.35l2.58-2.58C13.46.89 11.43 0 9 0 5.48 0 2.44 2.02.96 4.96l3.01 2.32C4.68 5.16 6.66 3.58 9 3.58z"/></svg>'; }
  function iconMicrosoft() { return '<svg viewBox="0 0 16 16"><rect x="1" y="1" width="6.5" height="6.5" fill="#F25022"/><rect x="8.5" y="1" width="6.5" height="6.5" fill="#7FBA00"/><rect x="1" y="8.5" width="6.5" height="6.5" fill="#00A4EF"/><rect x="8.5" y="8.5" width="6.5" height="6.5" fill="#FFB900"/></svg>'; }
  function iconKey() { return '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="5.5" cy="8.5" r="3"/><path d="M8.5 8.5H14M13 8.5V11M11 8.5V10"/></svg>'; }

  /* ============================================================
   * LOGIN / SIGNUP — split-screen with SSO
   * ============================================================ */

  function renderLogin() { renderAuth("login"); }
  function renderSignup() { renderAuth("signup"); }
  function renderAuth(kind) {
    var isSignup = kind === "signup";
    app.innerHTML = "";
    app.appendChild(h(
      '<div class="auth-shell">' +
        '<section class="auth-form">' +
          '<div class="auth-form-inner">' +
            '<div class="auth-brand"><span class="auth-brand-mark">A</span> AgentVisor</div>' +
            '<h1>' + (isSignup ? "Create your workspace" : "Sign in") + '</h1>' +
            '<p class="sub">' + (isSignup ? "Governance for every AI agent in your fleet." : "Access your agent control plane.") + '</p>' +
            '<div class="sso">' +
              '<button type="button" data-sso="google">' + iconGoogle() + '<span>Continue with Google</span></button>' +
              '<button type="button" data-sso="microsoft">' + iconMicrosoft() + '<span>Continue with Microsoft</span></button>' +
              '<button type="button" data-sso="saml">' + iconKey() + '<span>Continue with SAML SSO</span></button>' +
            "</div>" +
            '<div class="divider">or with email</div>' +
            '<form id="authForm">' +
              (isSignup ? '<div class="field"><label for="orgName">Company name</label><input id="orgName" type="text" required placeholder="Acme Corp" autocomplete="organization" /></div>' : "") +
              '<div class="field"><label for="email">Work email</label><input id="email" type="email" required autocomplete="email" placeholder="you@company.com" /></div>' +
              '<div class="field"><label for="password">Password' + (isSignup ? " (min 12 characters)" : "") + '</label><input id="password" type="password" required ' + (isSignup ? 'minlength="12" autocomplete="new-password"' : 'autocomplete="current-password"') + ' /></div>' +
              (isSignup ? "" : '<div style="margin-top: -4px; text-align: right;"><a href="#/reset" style="font-size: 12px; color: var(--fg-3);">Forgot password?</a></div>') +
              '<div id="authErr"></div>' +
              '<button class="primary" type="submit">' + (isSignup ? "Create account" : "Sign in") + '</button>' +
            "</form>" +
            '<div class="auth-alt">' +
              (isSignup ? "Already have an account? " + '<a href="#/login">Sign in</a>' : "New here? " + '<a href="#/signup">Create an account</a>') +
            "</div>" +
            (state.ds.mode === "mock"
              ? '<div class="mock-badge">Demo — any credentials work</div>'
              : "") +
          "</div>" +
        "</section>" +
        '<aside class="auth-panel"><div class="panel-inner">' +
          '<h2>Ship autonomous agents your compliance team trusts.</h2>' +
          '<p>Every LLM call, every tool call, every policy hit — captured, evaluated, and signed. In production, in real time.</p>' +
          '<div class="demo-stream">' +
            demoStreamRow(1, 6, '<b>tool.call</b> search_inventory(sku=\"NW-1240\")') +
            demoStreamRow(2, 5, '<b class="ok">TOOL ✓ allow</b> policy: read-only ✓') +
            demoStreamRow(3, 5, '<b>tool.call</b> create_purchase_order(vendor="NexusParts", $8,400)') +
            demoStreamRow(4, 5, '<b class="blk">BLOCKED</b> vendor not in procurement.allowed_vendors') +
            demoStreamRow(5, 4, '<b>tool.call</b> create_purchase_order(vendor="Contoso", $8,400)') +
            demoStreamRow(6, 4, '<b class="ok">TOOL ✓ allow</b> PO #29841 · $8,400') +
            demoStreamRow(7, 2, '<b class="ok">receipt</b> ed25519:kf_3a5f7e2d ✓ verified') +
          "</div>" +
        "</div></aside>" +
      "</div>"
    ));

    $$('[data-sso]').forEach(function (b) {
      b.addEventListener("click", function () {
        var p = b.getAttribute("data-sso");
        state.ds.loginWithProvider(p).then(function (s) {
        state.session = s; startLiveStream(); navigate("#/overview");
        }).catch(function (e) {
          $("#authErr").innerHTML = '<div class="auth-err">' + esc(e.message) + "</div>";
        });
      });
    });

    $("#authForm").addEventListener("submit", function (e) {
      e.preventDefault();
      var email = $("#email").value.trim();
      var pw = $("#password").value;
      var errEl = $("#authErr");
      var btn = e.target.querySelector("button[type=submit]");
      btn.disabled = true;
      var promise = isSignup
        ? state.ds.signup({ email: email, password: pw, orgName: ($("#orgName") || {}).value })
        : state.ds.login({ email: email, password: pw });
      promise.then(function (s) { state.session = s; startLiveStream(); navigate("#/overview"); })
        .catch(function (err) {
          btn.disabled = false;
          errEl.innerHTML = '<div class="auth-err">' + esc(err.message || "Failed") + "</div>";
        });
    });
  }
  function demoStreamRow(i, t, msg) {
    return '<div class="row" style="animation-delay:' + (i * 90) + 'ms">' +
      '<span class="seq">#' + i + '</span>' +
      '<span class="msg">' + msg + '</span>' +
      '<span class="t">' + t + 'm</span>' +
      '</div>';
  }

  /* ============================================================
   * PASSWORD RESET (two-step)
   * ============================================================ */

  function renderReset() {
    // Optional inline second step: if the URL is #/reset?email=...&token=...
    // (delivered by the reset email) skip straight to the "set new password"
    // form; otherwise start with the "enter your email" form.
    var qs = (location.hash.split("?")[1] || "");
    var params = new URLSearchParams(qs);
    var prefillEmail = params.get("email") || "";
    var prefillToken = params.get("token") || "";
    var stage = prefillToken ? "confirm" : "request";

    app.innerHTML = "";
    app.appendChild(h(
      '<div class="auth-shell">' +
        '<section class="auth-form">' +
          '<div class="auth-form-inner">' +
            '<div class="auth-brand"><span class="auth-brand-mark">A</span> AgentVisor</div>' +
            (stage === "request"
              ? '<h1>Reset your password</h1>' +
                '<p class="sub">We\'ll email you a link to pick a new one.</p>' +
                '<form id="resetReqForm">' +
                  '<div class="field"><label for="email">Work email</label><input id="email" type="email" required autocomplete="email" placeholder="you@company.com" value="' + esc(prefillEmail) + '"/></div>' +
                  '<div id="resetErr"></div>' +
                  '<button class="primary" type="submit">Send reset link</button>' +
                "</form>"
              : '<h1>Choose a new password</h1>' +
                '<p class="sub">Reset link verified. Pick something at least 12 characters.</p>' +
                '<form id="resetConfirmForm">' +
                  '<div class="field"><label for="email">Work email</label><input id="email" type="email" required autocomplete="email" value="' + esc(prefillEmail) + '"/></div>' +
                  '<input type="hidden" id="token" value="' + esc(prefillToken) + '"/>' +
                  '<div class="field"><label for="newPassword">New password</label><input id="newPassword" type="password" minlength="12" required autocomplete="new-password" /></div>' +
                  '<div id="resetErr"></div>' +
                  '<button class="primary" type="submit">Save new password</button>' +
                "</form>"
            ) +
            '<div class="auth-alt"><a href="#/login">← Back to sign in</a></div>' +
            (state.ds.mode === "mock"
              ? '<div class="mock-badge">Demo — the token is displayed inline after "Send reset link".</div>'
              : "") +
          "</div>" +
        "</section>" +
        '<aside class="auth-panel"><div class="panel-inner">' +
          '<h2>One reset link per address, valid for 24 hours.</h2>' +
          '<p>The token is argon2-hashed at rest and single-use. Rotate a compromised password and every prior session cookie stops working at next check-in.</p>' +
        "</div></aside>" +
      "</div>"
    ));

    var reqForm = $("#resetReqForm");
    if (reqForm) reqForm.addEventListener("submit", function (e) {
      e.preventDefault();
      var email = $("#email").value.trim();
      var btn = e.target.querySelector("button");
      btn.disabled = true;
      state.ds.requestPasswordReset({ email: email }).then(function (r) {
        // In mock mode surface the token inline so a reviewer can complete
        // the flow without an email server.
        if (state.ds.mode === "mock" && r.mockToken) {
          $("#resetErr").innerHTML =
            '<div class="mock-badge" style="margin-top: 0; text-align:left; padding: 10px 12px;">' +
              '<div style="margin-bottom: 6px;">Reset email sent. Demo token below:</div>' +
              '<div class="mono" style="word-break:break-all; padding: 6px 8px; background: var(--surface-hover); border-radius: 4px;">' + esc(r.mockToken) + '</div>' +
              '<div style="margin-top: 8px;"><a href="#/reset?email=' + encodeURIComponent(email) + '&token=' + encodeURIComponent(r.mockToken) + '">Continue →</a></div>' +
            '</div>';
        } else {
          $("#resetErr").innerHTML = '<div class="mock-badge" style="margin-top: 0;">If that email exists, a reset link is on the way.</div>';
        }
      }).catch(function (err) {
        btn.disabled = false;
        $("#resetErr").innerHTML = '<div class="auth-err">' + esc(err.message) + "</div>";
      });
    });

    var confirmForm = $("#resetConfirmForm");
    if (confirmForm) confirmForm.addEventListener("submit", function (e) {
      e.preventDefault();
      var email = $("#email").value.trim();
      var token = $("#token").value;
      var newPassword = $("#newPassword").value;
      var btn = e.target.querySelector("button");
      btn.disabled = true;
      state.ds.confirmPasswordReset({ email: email, token: token, newPassword: newPassword }).then(function () {
        toast("Password updated — please sign in");
        navigate("#/login");
      }).catch(function (err) {
        btn.disabled = false;
        var msg = err.status === 401 ? "This link is invalid or has expired." : (err.message || "Reset failed");
        $("#resetErr").innerHTML = '<div class="auth-err">' + esc(msg) + "</div>";
      });
    });
  }

  /* ============================================================
   * OVERVIEW — stats with sparklines + a real chart
   * ============================================================ */

  async function renderOverview(main) {
    var rangeLabel = { "1h": "the last hour", "24h": "the last 24 hours", "7d": "the last 7 days", "30d": "the last 30 days" }[state.range] || "the last 24 hours";
    main.innerHTML = pageHeader("Overview", "Fleet activity for " + rangeLabel + ".", rangeGroup()) + loadingBlock("stats");
    var stats, sessions;
    try {
      stats = await state.ds.getOverview(state.range);
      var res = await state.ds.listSessions();
      sessions = res.sessions.slice(0, 8);
    } catch (e) { return renderError(main, e); }

    var series = stats.series || [];
    var allowedByHour = series.map(function (b) { return b.allowed; });
    var blockedByHour = series.map(function (b) { return b.blocked; });
    var spendByHour = series.map(function (b) { return b.spendUsd; });
    // Cumulative running total of blocked action value across the last 24 h —
    // shape matches the "savings so far" story of the stat card.
    var blockedValueCumulative = [];
    var running = 0;
    series.forEach(function (b) { running += b.blockedValueUsd; blockedValueCumulative.push(running); });
    var pctBlocked = stats.toolsAllowed + stats.toolsBlocked > 0
      ? Math.round((stats.toolsBlocked / (stats.toolsAllowed + stats.toolsBlocked)) * 100) : 0;

    main.innerHTML =
      pageHeader("Overview", "Fleet activity for " + rangeLabel + ".", rangeGroup()) +
      '<div class="stats">' +
        stat("Sessions", stats.sessions, stats.deployments + " deployment" + (stats.deployments === 1 ? "" : "s"), sparkline(series.map(function (b) { return b.allowed + b.blocked; }))) +
        stat("Tool calls allowed", stats.toolsAllowed.toLocaleString(), "policy pass", sparkline(allowedByHour)) +
        stat("Tool calls blocked", stats.toolsBlocked.toLocaleString(), pctBlocked + "% block rate", sparkline(blockedByHour, { color: "var(--danger-solid)", fill: "var(--danger-bg)" }), "blocks") +
        stat("LLM spend", "$" + stats.llmSpendUsd, "usage this window", sparkline(spendByHour)) +
        stat("Prevented losses", "$" + Number(stats.blockedSpendUsd).toLocaleString(), "blocked action value", sparkline(blockedValueCumulative, { color: "var(--success-solid)", fill: "var(--success-bg)" }), "savings") +
      "</div>" +
      '<div class="chart-card">' +
        '<div class="head">' +
          '<h2>Tool call activity</h2>' +
          '<span class="sub">' + esc(rangeLabel) + ' · ' + { "1h": "1-minute", "24h": "hourly", "7d": "daily", "30d": "daily" }[state.range] + ' buckets</span>' +
          '<div class="legend">' +
            '<span><span class="dot" style="background: var(--accent)"></span> Allowed</span>' +
            '<span><span class="dot" style="background: var(--danger-solid)"></span> Blocked</span>' +
          "</div>" +
        "</div>" +
        stackedBarChart(series) +
      "</div>" +
      '<div class="card" style="padding:0">' +
        '<div style="padding:12px 16px; border-bottom: 1px solid var(--border); display:flex; align-items:baseline; gap:8px;">' +
          '<h2 style="margin:0; font-size: var(--t-section); font-weight:600">Recent sessions</h2>' +
          '<span style="color: var(--fg-3); font-size: var(--t-sec)">' + sessions.length + ' shown</span>' +
          '<div style="margin-left:auto"><a href="#/sessions" style="font-size: var(--t-sec)">View all →</a></div>' +
        "</div>" +
        sessionsTable(sessions) +
      "</div>";

    installRangeGroup(main);
    installChartHover(main, series);
  }

  function installChartHover(root, series) {
    var chart = root.querySelector(".chart-svg");
    if (!chart) return;
    var cursor = chart.querySelector("#chartCursor");
    var tip = h('<div class="chart-tip" style="display:none"></div>');
    root.querySelector(".chart-card").appendChild(tip);
    chart.addEventListener("mousemove", function (e) {
      var strip = e.target.closest(".hover-strip");
      if (!strip) { tip.style.display = "none"; cursor.style.opacity = "0"; return; }
      var idx = parseInt(strip.getAttribute("data-idx"), 10);
      var s = series[idx];
      var x = parseFloat(strip.getAttribute("x")) + parseFloat(strip.getAttribute("width")) / 2;
      cursor.setAttribute("x1", x);
      cursor.setAttribute("x2", x);
      cursor.style.opacity = "1";
      var box = chart.getBoundingClientRect();
      var relX = (x / 720) * box.width;
      tip.style.display = "block";
      tip.style.left = Math.min(Math.max(0, relX - 60), box.width - 140) + "px";
      tip.style.top = "-4px";
      tip.innerHTML =
        '<div class="tip-label">' + esc(s.label || "") + "</div>" +
        '<div class="tip-row"><span class="d" style="background: var(--accent)"></span>Allowed <b>' + s.allowed + "</b></div>" +
        '<div class="tip-row"><span class="d" style="background: var(--danger-solid)"></span>Blocked <b>' + s.blocked + "</b></div>" +
        (s.spendUsd > 0 ? '<div class="tip-row muted">Spend $' + s.spendUsd.toFixed(2) + "</div>" : "");
    });
    chart.addEventListener("mouseleave", function () {
      tip.style.display = "none";
      cursor.style.opacity = "0";
    });
  }
  function rangeGroup() {
    var opts = ["1h", "24h", "7d", "30d"];
    return '<div class="range-group">' + opts.map(function (o) {
      return '<button data-range="' + o + '"' + (state.range === o ? ' class="active"' : "") + '>' + o + '</button>';
    }).join("") + '</div>';
  }
  function installRangeGroup(root) {
    $$('.range-group button', root).forEach(function (b) {
      b.addEventListener("click", function () {
        state.range = b.getAttribute("data-range");
        render();
      });
    });
  }
  function stat(label, value, delta, spark, cls) {
    return '<div class="stat ' + (cls || "") + '">' +
      '<div class="head"><div class="label">' + esc(label) + "</div></div>" +
      '<div class="value">' + esc(value) + "</div>" +
      (delta ? '<div class="delta">' + esc(delta) + "</div>" : "") +
      (spark || "") +
      "</div>";
  }
  function pageHeader(title, sub, actions) {
    return '<div class="page-header"><div><h1>' + esc(title) + "</h1>" +
      (sub ? '<div class="sub">' + esc(sub) + "</div>" : "") + "</div>" +
      (actions ? '<div class="actions">' + actions + "</div>" : "") + "</div>";
  }

  /* ============================================================
   * SESSIONS LIST — with filter bar
   * ============================================================ */

  var sessionsFilter = { q: "", deploymentId: "", agent: "", blockedOnly: false, sinceHours: 24 };
  var sessionsPageSize = 50;
  var sessionsShown = sessionsPageSize;

  async function renderSessionsList(main) {
    main.innerHTML = pageHeader("Sessions", "Every agent session policed by AgentVisor.") + filterBar() + loadingBlock("table");
    var res, deps;
    try {
      deps = await state.ds.listDeployments();
      res = await state.ds.listSessions(sessionsFilter);
    } catch (e) { return renderError(main, e); }
    installFilters(main, deps);

    var visible = res.sessions.slice(0, sessionsShown);
    var body;
    if (res.sessions.length === 0) {
      body = emptyState("No sessions match your filters", "Try widening the date range or clearing the search.", null);
    } else {
      body = '<div class="card" style="padding:0">' + sessionsTable(visible) + '</div>';
      if (res.sessions.length > sessionsShown) {
        body += '<div style="margin-top:12px; text-align:center;">' +
          '<button class="btn" id="loadMore">Load more (' + (res.sessions.length - sessionsShown) + ' remaining)</button>' +
          "</div>";
      }
    }
    var totalChip = res.sessions.length > 0
      ? " · Showing " + visible.length + " of " + res.total
      : "";
    main.innerHTML = pageHeader("Sessions", res.total + " sessions" + totalChip) + filterBar() + body;
    installFilters(main, deps);
    var lm = $("#loadMore");
    if (lm) lm.addEventListener("click", function () { sessionsShown += sessionsPageSize; renderSessionsList(main); });
  }

  function filterBar() {
    return '<div class="filter-bar">' +
      '<div class="search">' +
        '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="7" cy="7" r="4.5"/><path d="M10.5 10.5L14 14"/></svg>' +
        '<input id="fSearch" type="search" placeholder="Search by session id, agent, or actor…" value="' + esc(sessionsFilter.q) + '" />' +
      "</div>" +
      '<select id="fRange">' +
        '<option value="1"' + (sessionsFilter.sinceHours === 1 ? " selected" : "") + '>Last 1h</option>' +
        '<option value="24"' + (sessionsFilter.sinceHours === 24 ? " selected" : "") + '>Last 24h</option>' +
        '<option value="168"' + (sessionsFilter.sinceHours === 168 ? " selected" : "") + '>Last 7d</option>' +
        '<option value="720"' + (sessionsFilter.sinceHours === 720 ? " selected" : "") + '>Last 30d</option>' +
      "</select>" +
      '<select id="fDep"><option value="">All deployments</option></select>' +
      '<select id="fAgent"><option value="">All agents</option></select>' +
      '<label class="toggle"><input id="fBlocked" type="checkbox"' + (sessionsFilter.blockedOnly ? " checked" : "") + '/> Blocked only</label>' +
      "</div>";
  }
  function installFilters(root, deps) {
    var fS = $("#fSearch", root);
    if (fS) {
      var timer;
      fS.addEventListener("input", function () {
        clearTimeout(timer);
        timer = setTimeout(function () { sessionsFilter.q = fS.value.trim(); renderSessionsList(root); }, 220);
      });
    }
    var fR = $("#fRange", root);
    if (fR) fR.addEventListener("change", function () { sessionsFilter.sinceHours = parseInt(fR.value, 10); renderSessionsList(root); });
    var fD = $("#fDep", root);
    if (fD && deps) {
      deps.forEach(function (d) {
        var o = document.createElement("option");
        o.value = d.id; o.textContent = d.name;
        if (sessionsFilter.deploymentId === d.id) o.selected = true;
        fD.appendChild(o);
      });
      fD.addEventListener("change", function () { sessionsFilter.deploymentId = fD.value; renderSessionsList(root); });
    }
    var fA = $("#fAgent", root);
    if (fA) {
      var agents = ["supply-planner", "returns-triage", "vendor-onboarding", "customer-emailer", "invoice-reconciler"];
      agents.forEach(function (a) {
        var o = document.createElement("option");
        o.value = a; o.textContent = a;
        if (sessionsFilter.agent === a) o.selected = true;
        fA.appendChild(o);
      });
      fA.addEventListener("change", function () { sessionsFilter.agent = fA.value; renderSessionsList(root); });
    }
    var fB = $("#fBlocked", root);
    if (fB) fB.addEventListener("change", function () { sessionsFilter.blockedOnly = fB.checked; renderSessionsList(root); });
  }

  function sessionsTable(sessions) {
    if (sessions.length === 0) return emptyState("No sessions yet", "Sessions from your daemons will appear here.");
    var rows = sessions.map(function (s) {
      var blocks = s.toolsBlocked > 0
        ? '<span class="pill err">' + s.toolsBlocked + " blocked</span>"
        : '<span class="pill ok">clean</span>';
      return '<tr data-clickable data-id="' + esc(s.id) + '" data-nav="#/sessions/" tabindex="0">' +
        '<td><div style="font-weight:500">' + esc(s.agent) + '</div><div class="id">' + esc(s.externalId) + "</div></td>" +
        '<td><div class="actor"><span class="av">' + esc(initials(s.user)) + '</span>' + esc(s.user || "—") + '</div></td>' +
        '<td class="num tabular">' + s.events + "</td>" +
        '<td class="num tabular">' + s.toolsAllowed + "</td>" +
        "<td>" + blocks + "</td>" +
        '<td class="num tabular">' + usdMicros(s.costUsdMicros) + "</td>" +
        '<td style="color: var(--fg-2)">' + esc(timeAgo(s.startedAt)) + "</td>" +
      "</tr>";
    }).join("");
    return '<div class="table-wrap"><table>' +
      "<thead><tr><th>Session</th><th>Actor</th><th class=\"num\">Events</th><th class=\"num\">Allowed</th><th>Blocked</th><th class=\"num\">LLM cost</th><th>Started</th></tr></thead>" +
      "<tbody>" + rows + "</tbody></table></div>";
  }

  // Global click delegation: any <tr data-clickable data-id data-nav>
  // navigates to `${data-nav}${data-id}` when the click isn't on a nested
  // button/link that stopped propagation.
  document.addEventListener("click", function (e) {
    var tr = e.target.closest("tr[data-clickable]");
    if (!tr) return;
    if (e.target.closest("button, a")) return;
    var id = tr.getAttribute("data-id");
    var prefix = tr.getAttribute("data-nav");
    if (id && prefix) navigate(prefix + id);
  });

  // Global keyboard nav for tables: arrow keys move focus, Enter opens.
  document.addEventListener("keydown", function (e) {
    if (!/^(ArrowDown|ArrowUp|Enter)$/.test(e.key)) return;
    var active = document.activeElement;
    if (!active || active.tagName !== "TR" || !active.hasAttribute("data-clickable")) return;
    if (e.key === "Enter") {
      e.preventDefault();
      active.click();
      return;
    }
    e.preventDefault();
    var next = e.key === "ArrowDown" ? active.nextElementSibling : active.previousElementSibling;
    while (next && (!next.hasAttribute("data-clickable"))) {
      next = e.key === "ArrowDown" ? next.nextElementSibling : next.previousElementSibling;
    }
    if (next) next.focus();
  });

  /* ============================================================
   * SESSION DETAIL — compact rows + right drawer + verified receipt
   * ============================================================ */

  async function renderSessionDetail(main, id) {
    main.innerHTML = pageHeader("Session", "", '<a href="#/sessions" class="btn">← All sessions</a>') + loadingBlock("stats");
    var data, receipt;
    try {
      data = await state.ds.getSessionById(id);
      receipt = await state.ds.getReceipt(id);
    } catch (e) { return renderError(main, e); }
    var s = data.session;
    var events = data.events || [];

    // Compute cumulative offsets from session start so the waterfall shows
    // when each event actually happened relative to the session's timeline,
    // and derive a parent-child depth so LLM → tool-call chains indent.
    var totalDur = events.reduce(function (a, e) { return a + (e.durationMs || 0); }, 0) || 1;
    var offset = 0;
    var parentLlm = -1;
    var eventsWithLayout = events.map(function (e, i) {
      var startPct = (offset / totalDur) * 100;
      var widthPct = Math.max(1, ((e.durationMs || 0) / totalDur) * 100);
      var depth = 0;
      if (e.kind === "llm") { parentLlm = i; depth = 0; }
      else if (e.kind === "tool" || e.kind === "guard" || e.kind === "block") {
        depth = parentLlm >= 0 ? 1 : 0;
      } else { depth = 0; }
      var layout = { startPct: startPct, widthPct: widthPct, depth: depth };
      offset += e.durationMs || 0;
      return Object.assign({}, e, { layout: layout });
    });

    var eventsHtml = eventsWithLayout.map(function (ev, i) {
      var sev = ev.severity === "err" ? "err" : (ev.severity === "ok" ? "ok" : "");
      var iconClass = ev.kind === "block" ? "err" : (ev.severity === "ok" ? "ok" : (ev.kind === "llm" ? "accent" : ""));
      var iconChar = ev.kind === "llm" ? "L" : ev.kind === "tool" ? "T" : ev.kind === "block" ? "!" : ev.kind === "guard" ? "✓" : ev.kind === "session" ? "S" : "•";
      var durTxt = ev.durationMs ? ev.durationMs + " ms" : "";
      var barColor = ev.severity === "err" ? "var(--danger-solid)" : (ev.severity === "ok" ? "var(--success-solid)" : "var(--accent)");
      return '<div class="evt ' + sev + '" data-i="' + i + '" style="--depth: ' + ev.layout.depth + ';">' +
        '<span class="seq">#' + esc(ev.seq) + "</span>" +
        '<span class="icon ' + iconClass + '">' + iconChar + "</span>" +
        '<span class="body"><b>' + esc(ev.tag || ev.kind) + '</b> ' + esc(ev.msg || "") +
          (ev.sub ? '<span class="sub">· ' + esc(ev.sub) + "</span>" : "") +
        "</span>" +
        '<span class="waterfall">' +
          '<span class="wf-track"></span>' +
          '<span class="wf-bar" style="left:' + ev.layout.startPct.toFixed(2) + '%; width:' + ev.layout.widthPct.toFixed(2) + '%; background:' + barColor + ';"></span>' +
        "</span>" +
        '<span class="dur">' + esc(durTxt) + "</span>" +
      "</div>";
    }).join("");

    main.innerHTML =
      pageHeader("Session " + s.externalId, s.agent + " · " + (s.user || "—") + " · " + (s.model || ""), '<a href="#/sessions" class="btn">← All sessions</a> <button class="btn" id="copyRcpt">Copy receipt</button>') +
      '<div class="session-summary">' +
        cell("Events", s.events, "streamed") +
        cell("Allowed", s.toolsAllowed, "tool calls") +
        cell("Blocked", s.toolsBlocked, "policy hits", s.toolsBlocked > 0 ? "blocks" : "") +
        cell("LLM cost", usdMicros(s.costUsdMicros), "actual usage") +
        cell("Blocked value", usdMicrosBig(s.blockedPayoutUsdMicros), "would-have-spent", parseInt(s.blockedPayoutUsdMicros, 10) > 0 ? "savings" : "") +
      "</div>" +
      '<div class="detail-grid">' +
        '<div class="events-card card">' +
          '<div class="events-head"><h2>Event stream</h2><span class="count">' + events.length + " events</span></div>" +
          '<div id="eventList">' + eventsHtml + "</div>" +
        "</div>" +
        '<div>' +
          receiptCard(receipt) +
          '<div class="event-drawer" id="eventDrawer" style="margin-top: 12px;">' +
            '<h3>Event detail</h3>' +
            '<div class="empty-mini">Click an event to inspect.</div>' +
          "</div>" +
        "</div>" +
      "</div>";

    // event click → drawer
    var evList = $("#eventList");
    var drawer = $("#eventDrawer");
    evList.addEventListener("click", function (e) {
      var row = e.target.closest(".evt");
      if (!row) return;
      $$('.evt', evList).forEach(function (r) { r.classList.remove("selected"); });
      row.classList.add("selected");
      var ev = events[parseInt(row.getAttribute("data-i"), 10)];
      renderEventDrawer(drawer, ev);
    });

    // Copy receipt button
    $("#copyRcpt").addEventListener("click", function () {
      navigator.clipboard.writeText(JSON.stringify(receipt, null, 2)).then(function () {
        toast("Receipt copied");
      });
    });

    // Fire the real Ed25519 verification. When it lands, the "Verifying…"
    // header flips to ✓ verified, ✗ INVALID, or ? not-supported.
    applyReceiptVerification(receipt);
  }

  function renderEventDrawer(root, ev) {
    var meta = [
      ["Seq", "#" + ev.seq],
      ["Kind", ev.kind + (ev.tag ? " · " + ev.tag : "")],
      ["Time", new Date(ev.ts).toLocaleTimeString()],
      ["Duration", ev.durationMs ? ev.durationMs + " ms" : "—"],
    ];
    if (ev.policyId) meta.push(["Policy", '<a href="#/policies/' + ev.policyId + '">' + ev.policyId + "</a>"]);
    if (ev.blockedValueUsd) meta.push(["Would-have-spent", "$" + ev.blockedValueUsd.toLocaleString()]);

    var payload = "";
    if (ev.details) {
      payload = '<pre class="payload">' +
        '<b>Model</b>  ' + esc(ev.details.model) + '\n' +
        '<b>Tokens</b> ' + esc(ev.details.promptTokens) + '\n\n' +
        '<b>Prompt</b>\n' + esc(ev.details.prompt) + '\n\n' +
        '<b>Response</b>\n' + esc(ev.details.response) +
        "</pre>";
    } else if (ev.severity === "err") {
      payload = '<pre class="payload">' + esc(JSON.stringify({ severity: ev.severity, msg: ev.msg, sub: ev.sub, policy: ev.policyId }, null, 2)) + "</pre>";
    } else {
      payload = '<div class="empty-mini">No payload attached.</div>';
    }

    root.innerHTML =
      '<h3>Event detail</h3>' +
      '<dl class="meta">' + meta.map(function (m) { return "<dt>" + esc(m[0]) + "</dt><dd>" + m[1] + "</dd>"; }).join("") + "</dl>" +
      payload;
  }

  function cell(label, value, sub, cls) {
    return '<div class="cell ' + (cls || "") + '">' +
      '<div class="label">' + esc(label) + "</div>" +
      '<div class="value">' + esc(value) + "</div>" +
      (sub ? '<div style="color: var(--fg-3); font-size: 11.5px; margin-top: 2px;">' + esc(sub) + "</div>" : "") +
      "</div>";
  }

  function receiptCard(r) {
    if (!r || r.note) {
      return '<div class="card"><h2>Signed receipt</h2><p style="color: var(--fg-2); font-size: var(--t-sec); margin:0">' + esc(r && r.note || "No receipt yet.") + "</p></div>";
    }
    var policies = (r.policiesEnforced || []).map(function (p) {
      return '<span class="pill accent status-dot">' + esc(p) + "</span>";
    }).join(" ");
    // Placeholder verifier state — the real answer arrives after the async
    // Web Crypto verify call. Marked "verifying" so the UI doesn't lie
    // about the outcome while we're still waiting.
    return '<div class="receipt-card card">' +
      '<div class="receipt-head" data-verify-state="pending">' +
        '<span class="check">…</span>' +
        '<div><div class="title">Verifying signature…</div>' +
             '<div style="font-size: 11px;">ed25519 · ' + esc(r.signingKeyFingerprint || "") + '</div></div>' +
        '<span class="kf">' + esc((r.receiptId || "").slice(0, 24)) + '…</span>' +
      "</div>" +
      '<div class="receipt-body">' +
        '<dl class="kv">' +
          "<dt>Receipt ID</dt><dd class=\"mono\">" + esc(r.receiptId || "") + "</dd>" +
          "<dt>Content hash</dt><dd class=\"mono\">" + esc(r.contentHash || "") + "</dd>" +
          "<dt>Events sealed</dt><dd>" + esc(r.eventCount || 0) + "</dd>" +
          "<dt>Tools</dt><dd>" + (r.tools ? esc(r.tools.allowed || 0) + " allowed · " + esc(r.tools.blocked || 0) + " blocked" : "—") + "</dd>" +
        "</dl>" +
        '<div style="font-size: 11.5px; color: var(--fg-3); text-transform: uppercase; letter-spacing: 0.04em; font-weight: 600; margin-bottom: 6px;">Policies enforced</div>' +
        '<div class="policies">' + policies + "</div>" +
        '<details class="raw-toggle"><summary>View raw signed body</summary>' +
          '<pre class="raw">' + esc(JSON.stringify(r, null, 2)) + "</pre>" +
        "</details>" +
      "</div>" +
      "</div>";
  }

  // Run the real Ed25519 verify and update the receipt-head with the result.
  // Kept out of receiptCard() because that runs synchronously as innerHTML.
  async function applyReceiptVerification(r) {
    var head = document.querySelector('.receipt-head[data-verify-state="pending"]');
    if (!head) return;
    if (!window.avVerifyReceipt) return;
    var res = await window.avVerifyReceipt(r.publicKeyHex, r.rawSignatureB64, r.rawBody);
    var check = head.querySelector('.check');
    var title = head.querySelector('.title');
    var sub = head.querySelector('div > div:last-child');
    if (!res.supported) {
      head.setAttribute("data-verify-state", "unsupported");
      head.classList.add("unsupported");
      check.textContent = "?";
      title.textContent = "Signature not verified";
      if (sub) sub.textContent = "This browser cannot verify Ed25519 signatures.";
      return;
    }
    if (res.ok) {
      head.setAttribute("data-verify-state", "verified");
      check.textContent = "✓";
      title.textContent = "Signature verified";
      if (sub) sub.textContent = "ed25519 · " + (r.signingKeyFingerprint || "");
    } else {
      head.setAttribute("data-verify-state", "invalid");
      head.classList.add("invalid");
      check.textContent = "✗";
      title.textContent = "Signature INVALID";
      if (sub) sub.textContent = "The receipt does not match the deployment's public key.";
    }
  }

  /* ============================================================
   * DEPLOYMENTS — list + detail + install snippet
   * ============================================================ */

  async function renderDeployments(main) {
    var actions = '<button class="btn accent" id="addDep">+ New deployment</button>';
    main.innerHTML = pageHeader("Deployments", "Each daemon streams events and signed receipts to this console.", actions) + loadingBlock("table");
    var deps;
    try { deps = await state.ds.listDeployments(); }
    catch (e) { return renderError(main, e); }

    var body;
    if (deps.length === 0) {
      body = deploymentEmptyHero();
    } else {
      var rows = deps.map(function (d) {
        var statusPill = d.status === "connected"
          ? '<span class="pill ok status-dot">connected</span>'
          : '<span class="pill neutral status-dot">' + esc(d.status) + "</span>";
        return '<tr data-clickable data-id="' + esc(d.id) + '" data-nav="#/deployments/" tabindex="0">' +
          '<td><div style="font-weight:500">' + esc(d.name) + '</div><div class="id">' + esc(d.id) + "</div></td>" +
          '<td><span class="pill neutral">' + esc(d.environment) + "</span></td>" +
          '<td>' + esc(d.region || "—") + "</td>" +
          "<td>" + statusPill + "</td>" +
          '<td class="mono">' + esc(d.version || "—") + "</td>" +
          '<td style="color: var(--fg-2)">' + esc(timeAgo(d.lastSeenAt)) + "</td>" +
          '<td>' +
            '<button class="btn" data-action="rotate">Rotate</button> ' +
            '<button class="btn danger" data-action="delete">Delete</button>' +
          "</td>" +
        "</tr>";
      }).join("");
      body =
        '<div class="empty-hero" style="margin-bottom: 16px; padding: 16px 20px; grid-template-columns: 1fr 1fr;">' +
          '<div><h2 style="font-size: 15px; margin: 0 0 4px">Connect a new daemon</h2>' +
          '<p style="margin: 0; font-size: 13px">Install <code>agentvisord</code> on your infra with the ingest token, and events start streaming here.</p></div>' +
          '<div class="snippet"><span class="prompt">$</span> <span class="cmd">curl -fsSL https://get.agentvisorai.me/install.sh | sh</span>\n<span class="prompt">$</span> <span class="cmd">agentvisord start --token=$AV_INGEST_TOKEN</span></div>' +
        "</div>" +
        '<div class="card" style="padding:0"><div class="table-wrap"><table>' +
          "<thead><tr><th>Deployment</th><th>Environment</th><th>Region</th><th>Status</th><th>Version</th><th>Last seen</th><th></th></tr></thead>" +
          "<tbody>" + rows + "</tbody></table></div></div>";
    }
    main.innerHTML = pageHeader("Deployments", "Each daemon streams events and signed receipts to this console.", actions) + body;

    var addBtn = $("#addDep");
    if (addBtn) addBtn.addEventListener("click", openCreateDeploymentModal);
    var addBtn2 = $("#addDep2");
    if (addBtn2) addBtn2.addEventListener("click", openCreateDeploymentModal);

    var tbody = main.querySelector("tbody");
    if (tbody) {
      tbody.addEventListener("click", function (e) {
        var tr = e.target.closest("tr[data-id]");
        if (!tr) return;
        var id = tr.getAttribute("data-id");
        var btn = e.target.closest("button[data-action]");
        if (btn) {
          e.stopPropagation();
          if (btn.getAttribute("data-action") === "rotate") {
            confirmModal({
              title: "Rotate ingest token?",
              body: "The old token stops working immediately. Any daemon using it will fail to connect until you paste the new one.",
              confirmLabel: "Rotate token",
              danger: true,
              onConfirm: function () {
                state.ds.rotateDeploymentToken(id).then(function (r) { showTokenModal(r.ingestToken, "Token rotated"); })
                  .catch(function (err) { toast(err.message || "Rotation failed", true); });
              },
            });
          } else if (btn.getAttribute("data-action") === "delete") {
            confirmModal({
              title: "Delete deployment?",
              body: "Existing sessions remain in the workspace, but the daemon can no longer connect.",
              confirmLabel: "Delete",
              danger: true,
              onConfirm: function () {
                state.ds.deleteDeployment(id).then(function () {
                  toast("Deployment removed");
                  renderDeployments(main);
                }).catch(function (err) { toast(err.message || "Delete failed", true); });
              },
            });
          }
          return;
        }
        navigate("#/deployments/" + id);
      });
    }
  }

  function deploymentEmptyHero() {
    return '<div class="empty-hero">' +
      '<div><h2>Connect your first agent</h2>' +
      '<p>Install the AgentVisor daemon on the box that runs your agent. Once it starts, sessions and signed receipts stream directly into this console.</p>' +
      '<button class="btn accent" id="addDep2">+ New deployment</button></div>' +
      '<div class="snippet"><span class="prompt">$</span> <span class="cmd">curl -fsSL https://get.agentvisorai.me/install.sh | sh</span>\n\n<span class="prompt">$</span> <span class="cmd">agentvisord start --token=$AV_INGEST_TOKEN</span></div>' +
      "</div>";
  }

  async function renderDeploymentDetail(main, id) {
    main.innerHTML = pageHeader("Deployment", "", '<a href="#/deployments" class="btn">← All deployments</a>') + loadingBlock("stats");
    var d, sessions;
    try {
      d = await state.ds.getDeployment(id);
      var res = await state.ds.listSessions({ deploymentId: id });
      sessions = res.sessions.slice(0, 8);
    } catch (e) { return renderError(main, e); }

    var statusPill = d.status === "connected"
      ? '<span class="pill ok status-dot">connected</span>'
      : '<span class="pill neutral status-dot">' + esc(d.status) + "</span>";

    main.innerHTML =
      pageHeader(d.name, d.environment + " · " + (d.region || ""), '<a href="#/deployments" class="btn">← All deployments</a>') +
      '<div class="dep-summary">' +
        depCell("Status", statusPill) +
        depCell("Version", d.version || "—", true) +
        depCell("Last seen", timeAgo(d.lastSeenAt)) +
        depCell("Sessions (24h)", d.sessions24h != null ? d.sessions24h : "—") +
        depCell("Spend (24h)", d.spend24h || "—") +
      "</div>" +
      '<div class="card" style="margin-bottom:12px">' +
        "<h2>Signing key</h2>" +
        '<dl class="kv" style="display:grid;grid-template-columns:140px 1fr;gap:5px 12px;font-size:13px">' +
          '<dt style="color:var(--fg-3)">Fingerprint</dt><dd class="mono">' + esc(d.keyFingerprint || "—") + "</dd>" +
          '<dt style="color:var(--fg-3)">Public key</dt><dd class="mono" style="word-break:break-all">' + esc(d.publicKeyHex || "—") + "</dd>" +
          '<dt style="color:var(--fg-3)">Ingest token</dt><dd class="mono">' + esc(d.ingestTokenHint || "—") + "</dd>" +
        "</dl>" +
        '<div style="margin-top: 12px; display:flex; gap:8px">' +
          '<button class="btn" id="depRotate">Rotate token</button>' +
          '<button class="btn danger" id="depDelete">Delete</button>' +
        "</div>" +
      "</div>" +
      '<div class="card" style="padding:0">' +
        '<div style="padding:12px 16px; border-bottom: 1px solid var(--border); display:flex; align-items:baseline; gap:8px;">' +
          '<h2 style="margin:0; font-size:var(--t-section); font-weight:600">Recent sessions</h2>' +
          '<span style="color:var(--fg-3); font-size:var(--t-sec)">' + sessions.length + " shown</span>" +
          '<div style="margin-left:auto"><a href="#/sessions" style="font-size:var(--t-sec)">View all →</a></div>' +
        "</div>" +
        (sessions.length ? sessionsTable(sessions) : emptyState("No sessions yet", "This deployment has not streamed any sessions.")) +
      "</div>";

    var rotBtn = $("#depRotate");
    if (rotBtn) rotBtn.addEventListener("click", function () {
      confirmModal({
        title: "Rotate ingest token?",
        body: "The old token stops working immediately.",
        confirmLabel: "Rotate", danger: true,
        onConfirm: function () {
          state.ds.rotateDeploymentToken(d.id).then(function (r) { showTokenModal(r.ingestToken, "Token rotated"); })
            .catch(function (err) { toast(err.message, true); });
        },
      });
    });
    var delBtn = $("#depDelete");
    if (delBtn) delBtn.addEventListener("click", function () {
      confirmModal({
        title: "Delete deployment?",
        body: "Sessions remain, the daemon can no longer connect.",
        confirmLabel: "Delete", danger: true,
        onConfirm: function () {
          state.ds.deleteDeployment(d.id).then(function () {
            toast("Deployment removed");
            navigate("#/deployments");
          });
        },
      });
    });
  }
  function depCell(label, value, mono) {
    return '<div class="cell"><div class="label">' + esc(label) + '</div><div class="value' + (mono ? " mono" : "") + '">' + value + "</div></div>";
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
            '<div class="actions"><button type="button" class="btn" data-close>Cancel</button><button class="btn accent" type="submit">Create</button></div>' +
          "</form>" +
        "</div>" +
      "</div>"
    );
    document.body.appendChild(backdrop);
    document.body.classList.add("locked");
    backdrop.addEventListener("click", function (e) {
      if (e.target === backdrop || e.target.hasAttribute("data-close")) { backdrop.remove(); document.body.classList.remove("locked"); }
    });
    backdrop.querySelector("#depForm").addEventListener("submit", function (e) {
      e.preventDefault();
      var btn = e.target.querySelector('button[type="submit"]');
      btn.disabled = true;
      state.ds.createDeployment({ name: $("#depName").value.trim(), environment: $("#depEnv").value, region: $("#depRegion").value.trim() || undefined })
        .then(function (r) { backdrop.remove(); document.body.classList.remove("locked"); showTokenModal(r.ingestToken, "Deployment created"); })
        .catch(function (err) { btn.disabled = false; toast(err.message || "Create failed", true); });
    });
  }

  function showTokenModal(token, title) {
    var backdrop = h(
      '<div class="modal-backdrop">' +
        '<div class="modal">' +
          "<h2>" + esc(title || "Ingest token") + "</h2>" +
          '<p class="sub">Point your daemon at this console using the token below. Store it in your secret manager — it won\'t be shown again.</p>' +
          '<div class="token-display">' + esc(token) + "</div>" +
          '<div class="notice"><svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M8 1L15 14H1L8 1z"/><path d="M8 6v3M8 11v.5"/></svg>' +
            '<span>This is the only time you\'ll see the full token. If you lose it, rotate to get a new one.</span></div>' +
          '<div class="actions"><button type="button" class="btn" id="copyTok">Copy</button><button type="button" class="btn accent" data-close>Done</button></div>' +
        "</div>" +
      "</div>"
    );
    document.body.appendChild(backdrop);
    document.body.classList.add("locked");
    backdrop.addEventListener("click", function (e) {
      if (e.target === backdrop || e.target.hasAttribute("data-close")) {
        backdrop.remove(); document.body.classList.remove("locked");
        var main = $("#view"); if (main) renderDeployments(main);
      }
    });
    backdrop.querySelector("#copyTok").addEventListener("click", function () {
      navigator.clipboard.writeText(token).then(function () { toast("Token copied"); });
    });
  }

  /* ============================================================
   * POLICIES
   * ============================================================ */

  async function renderPolicies(main) {
    main.innerHTML = pageHeader("Policies", "Rules the daemon enforces before any tool call or LLM egress.", '<button class="btn accent" id="addPol">+ New policy</button>') + loadingBlock("table");
    var pols;
    try { pols = await state.ds.listPolicies(); } catch (e) { return renderError(main, e); }
    var rows = pols.map(function (p) {
      var switchCls = p.enabled ? "on" : "";
      return '<tr data-clickable data-id="' + esc(p.id) + '" data-nav="#/policies/" tabindex="0">' +
        '<td class="policy-row"><div class="name">' + esc(p.name) + '</div><div class="kind">' + esc(p.kind) + " · " + esc(p.scope) + "</div></td>" +
        "<td>" + esc(p.description) + "</td>" +
        '<td class="num tabular">' + esc(p.hits24h) + "</td>" +
        '<td class="num tabular">' + (p.blocks24h > 0 ? '<span style="color: var(--danger-solid); font-weight:500">' + esc(p.blocks24h) + "</span>" : esc(p.blocks24h)) + "</td>" +
        '<td style="color:var(--fg-2)">' + esc(timeAgo(p.updatedAt)) + "</td>" +
        '<td onclick="event.stopPropagation()"><span class="switch ' + switchCls + '" data-id="' + esc(p.id) + '"></span></td>' +
        "</tr>";
    }).join("");
    main.innerHTML = pageHeader("Policies", pols.length + " policies · " + pols.filter(function (p) { return p.enabled; }).length + " enabled", '<button class="btn accent" id="addPol">+ New policy</button>') +
      '<div class="card" style="padding:0"><div class="table-wrap"><table>' +
        "<thead><tr><th>Policy</th><th>Description</th><th class=\"num\">Hits 24h</th><th class=\"num\">Blocks</th><th>Updated</th><th></th></tr></thead>" +
        "<tbody>" + rows + "</tbody></table></div></div>";
    var tbody = main.querySelector("tbody");
    tbody.addEventListener("click", function (e) {
      var sw = e.target.closest(".switch");
      if (sw) {
        e.stopPropagation();
        state.ds.togglePolicy(sw.getAttribute("data-id")).then(function () { renderPolicies(main); });
        return;
      }
      var tr = e.target.closest("tr[data-id]");
      if (tr) navigate("#/policies/" + tr.getAttribute("data-id"));
    });
    var addBtn = $("#addPol");
    if (addBtn) addBtn.addEventListener("click", function () {
      comingSoon("Write a new policy", "The policy editor supports a Rego-style DSL with autocomplete, dry-run against past sessions, and a shareable review link before rollout.");
    });
  }

  async function renderPolicyDetail(main, id) {
    main.innerHTML = pageHeader("Policy", "", '<a href="#/policies" class="btn">← All policies</a>') + loadingBlock("stats");
    var p;
    try { p = await state.ds.getPolicy(id); } catch (e) { return renderError(main, e); }
    var switchCls = p.enabled ? "on" : "";
    main.innerHTML =
      pageHeader(p.name, p.kind + " · " + p.scope, '<a href="#/policies" class="btn">← All policies</a> <span class="switch ' + switchCls + '" id="polSwitch" title="Toggle enabled"></span>') +
      '<div class="dep-summary">' +
        depCell("Status", p.enabled ? '<span class="pill ok status-dot">enabled</span>' : '<span class="pill neutral">disabled</span>') +
        depCell("Hits (24h)", p.hits24h.toLocaleString()) +
        depCell("Blocks (24h)", p.blocks24h > 0 ? '<span style="color: var(--danger-solid)">' + p.blocks24h + "</span>" : p.blocks24h) +
        depCell("Updated", timeAgo(p.updatedAt)) +
      "</div>" +
      '<div class="card"><h2>Description</h2><p style="margin:0;color:var(--fg-2);font-size:var(--t-body)">' + esc(p.description) + '</p></div>' +
      '<div class="card" style="margin-top:12px"><h2>Definition</h2><pre class="policy-body">' + syntaxPolicy(p.body) + "</pre></div>";
    $("#polSwitch").addEventListener("click", function () {
      state.ds.togglePolicy(id).then(function () { renderPolicyDetail(main, id); });
    });
  }
  function syntaxPolicy(src) {
    return esc(src)
      .replace(/\b(policy|applies_to|when|effect|reason|transform)\b/g, "<span class='k'>$1</span>")
      .replace(/&quot;[^&]*?&quot;/g, function (m) { return "<span class='s'>" + m + "</span>"; })
      .replace(/\b(\d+(?:\.\d+)?)\b/g, "<span class='n'>$1</span>");
  }

  /* ============================================================
   * SETTINGS — tabs
   * ============================================================ */

  var SETTINGS_TABS = [
    { id: "general", label: "General" },
    { id: "members", label: "Members" },
    { id: "keys", label: "API keys" },
    { id: "sso", label: "SSO" },
    { id: "webhooks", label: "Webhooks" },
    { id: "audit", label: "Audit log" },
    { id: "billing", label: "Billing" },
  ];

  async function renderSettings(main, tab) {
    state.settingsTab = tab;
    var nav = SETTINGS_TABS.map(function (t) {
      return '<button data-tab="' + t.id + '"' + (tab === t.id ? ' class="active"' : "") + ">" + esc(t.label) + "</button>";
    }).join("");
    main.innerHTML =
      pageHeader("Settings", "Organization and workspace preferences.") +
      '<div class="settings-shell">' +
        '<div class="settings-nav">' + nav + "</div>" +
        '<div class="settings-panel" id="setPanel"></div>' +
      "</div>";
    $$('.settings-nav button', main).forEach(function (b) {
      b.addEventListener("click", function () { navigate("#/settings/" + b.getAttribute("data-tab")); });
    });
    var panel = $("#setPanel");
    if (tab === "general") return renderSettingsGeneral(panel);
    if (tab === "members") return renderSettingsMembers(panel);
    if (tab === "keys") return renderSettingsKeys(panel);
    if (tab === "sso") return renderSettingsSSO(panel);
    if (tab === "webhooks") return renderSettingsWebhooks(panel);
    if (tab === "audit") return renderSettingsAudit(panel);
    if (tab === "billing") return renderSettingsBilling(panel);
  }

  function renderSettingsGeneral(root) {
    root.innerHTML =
      '<div class="card"><h2>Organization</h2>' +
        '<dl class="kv" style="display:grid;grid-template-columns:140px 1fr;gap:5px 12px;font-size:13px">' +
          "<dt style=\"color:var(--fg-3)\">Name</dt><dd>" + esc(state.session.org.name) + "</dd>" +
          "<dt style=\"color:var(--fg-3)\">Org ID</dt><dd class=\"mono\">" + esc(state.session.org.id) + "</dd>" +
          "<dt style=\"color:var(--fg-3)\">Created</dt><dd>" + esc(new Date(state.session.org.createdAt).toLocaleDateString()) + "</dd>" +
        "</dl>" +
      "</div>" +
      '<div class="card"><h2>Account</h2>' +
        '<dl class="kv" style="display:grid;grid-template-columns:140px 1fr;gap:5px 12px;font-size:13px">' +
          "<dt style=\"color:var(--fg-3)\">Email</dt><dd>" + esc(state.session.user.email) + "</dd>" +
          "<dt style=\"color:var(--fg-3)\">User ID</dt><dd class=\"mono\">" + esc(state.session.user.id) + "</dd>" +
        "</dl>" +
        '<div style="margin-top:12px"><button class="btn danger" id="signOut">Sign out</button></div>' +
      "</div>" +
      (state.ds.mode === "mock" ?
        '<div class="card"><h2>Demo mode</h2><p style="color: var(--fg-2); margin: 0 0 8px; font-size: var(--t-sec)">This console is running against built-in fixtures. To connect to a real backend, set <code>window.MOCK_MODE = false</code> in <code>docs/app/index.html</code>.</p></div>' : "");
    var so = $("#signOut", root);
    if (so) so.addEventListener("click", signOut);
  }
  function openInputModal(opts) {
    var backdrop = h(
      '<div class="modal-backdrop"><div class="modal">' +
        "<h2>" + esc(opts.title) + "</h2>" +
        (opts.sub ? '<p class="sub">' + esc(opts.sub) + "</p>" : "") +
        '<form id="inpForm">' +
          '<div class="field"><label>' + esc(opts.label || "Value") + "</label>" +
          '<input id="inpVal" type="text" required placeholder="' + esc(opts.placeholder || "") + '" /></div>' +
          '<div class="actions">' +
            '<button type="button" class="btn" data-close>Cancel</button>' +
            '<button class="btn accent" type="submit">' + esc(opts.confirmLabel || "Save") + "</button>" +
          "</div>" +
        "</form>" +
      "</div></div>"
    );
    document.body.appendChild(backdrop);
    document.body.classList.add("locked");
    function close() { backdrop.remove(); document.body.classList.remove("locked"); document.removeEventListener("keydown", onKey); }
    function onKey(e) { if (e.key === "Escape") close(); }
    document.addEventListener("keydown", onKey);
    backdrop.addEventListener("click", function (e) {
      if (e.target === backdrop || e.target.hasAttribute("data-close")) close();
    });
    backdrop.querySelector("#inpForm").addEventListener("submit", function (e) {
      e.preventDefault();
      var v = backdrop.querySelector("#inpVal").value.trim();
      if (!v) return;
      close();
      opts.onConfirm && opts.onConfirm(v);
    });
    setTimeout(function () { backdrop.querySelector("#inpVal").focus(); }, 20);
  }

  function comingSoon(title, body) {
    var backdrop = h(
      '<div class="modal-backdrop"><div class="modal">' +
        "<h2>" + esc(title) + "</h2>" +
        '<p class="sub">' + esc(body) + "</p>" +
        '<div class="notice"><svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="8" cy="8" r="6"/><path d="M8 5v3M8 11v.5"/></svg><span>This is a demo. Full flow will ship with the beta.</span></div>' +
        '<div class="actions"><button type="button" class="btn primary" data-close>Got it</button></div>' +
      "</div></div>"
    );
    document.body.appendChild(backdrop);
    document.body.classList.add("locked");
    function close() { backdrop.remove(); document.body.classList.remove("locked"); document.removeEventListener("keydown", onKey); }
    function onKey(ev) { if (ev.key === "Escape") close(); }
    document.addEventListener("keydown", onKey);
    backdrop.addEventListener("click", function (e) {
      if (e.target === backdrop || e.target.hasAttribute("data-close")) close();
    });
  }

  async function renderSettingsMembers(root) {
    root.innerHTML = '<div class="card">' + loadingBlock("table") + "</div>";
    var members = await state.ds.listMembers();
    var rows = members.map(function (m) {
      return "<tr>" +
        '<td><div class="actor"><span class="av">' + esc(initials(m.displayName)) + '</span><div><div style="font-weight:500">' + esc(m.displayName) + "</div><div class=\"id\">" + esc(m.email) + "</div></div></div></td>" +
        '<td><span class="pill neutral">' + esc(m.role) + "</span></td>" +
        '<td style="color:var(--fg-2)">' + esc(timeAgo(m.lastActive)) + "</td>" +
        '<td><button class="btn ghost">Manage</button></td>' +
      "</tr>";
    }).join("");
    root.innerHTML =
      '<div class="card" style="padding:0">' +
        '<div style="padding:12px 16px; border-bottom:1px solid var(--border); display:flex; align-items:baseline">' +
          '<h2 style="margin:0; font-size: var(--t-section); font-weight:600">Members</h2>' +
          '<span style="margin-left:8px; color:var(--fg-3); font-size:var(--t-sec)">' + members.length + " people</span>" +
          '<button class="btn accent" id="inviteBtn" style="margin-left:auto">+ Invite</button>' +
        "</div>" +
        '<div class="table-wrap"><table>' +
          "<thead><tr><th>Person</th><th>Role</th><th>Last active</th><th></th></tr></thead>" +
          "<tbody>" + rows + "</tbody>" +
        "</table></div>" +
      "</div>";
    var ib = $("#inviteBtn", root);
    if (ib) ib.addEventListener("click", function () {
      openInputModal({ title: "Invite a teammate", label: "Work email", placeholder: "teammate@company.com", confirmLabel: "Send invite", onConfirm: function (v) { toast("Invite sent to " + v); } });
    });
  }
  async function renderSettingsKeys(root) {
    root.innerHTML = '<div class="card">' + loadingBlock("table") + "</div>";
    var keys = await state.ds.listApiKeys();
    var rows = keys.map(function (k) {
      return "<tr>" +
        '<td><div style="font-weight:500">' + esc(k.name) + '</div><div class="id">' + esc(k.id) + "</div></td>" +
        '<td class="mono">' + esc(k.hint) + "</td>" +
        '<td style="color:var(--fg-2)">' + esc(timeAgo(k.lastUsedAt)) + "</td>" +
        '<td style="color:var(--fg-2)">' + esc(timeAgo(k.createdAt)) + "</td>" +
        '<td><button class="btn danger">Revoke</button></td>' +
      "</tr>";
    }).join("");
    root.innerHTML =
      '<div class="card" style="padding:0">' +
        '<div style="padding:12px 16px; border-bottom:1px solid var(--border); display:flex; align-items:baseline">' +
          '<h2 style="margin:0; font-size:var(--t-section); font-weight:600">API keys</h2>' +
          '<span style="margin-left:8px; color:var(--fg-3); font-size:var(--t-sec)">' + keys.length + " active</span>" +
          '<button class="btn accent" id="createKeyBtn" style="margin-left:auto">+ Create key</button>' +
        "</div>" +
        '<div class="table-wrap"><table>' +
          "<thead><tr><th>Name</th><th>Prefix</th><th>Last used</th><th>Created</th><th></th></tr></thead>" +
          "<tbody>" + rows + "</tbody>" +
        "</table></div>" +
      "</div>";
    var ck = $("#createKeyBtn", root);
    if (ck) ck.addEventListener("click", function () {
      openInputModal({ title: "Create an API key", label: "Key name", placeholder: "e.g. CI runner", confirmLabel: "Create", onConfirm: function (name) {
        var token = "av_srv_" + Math.random().toString(36).slice(2, 10) + Math.random().toString(36).slice(2, 10);
        showTokenModal(token, "API key created");
      }});
    });
  }
  function renderSettingsSSO(root) {
    root.innerHTML =
      '<div class="card">' +
        "<h2>Single sign-on</h2>" +
        '<p style="color: var(--fg-2); font-size: var(--t-sec); margin: 0 0 var(--s-4)">Require SSO for all members. Supports Google Workspace, Microsoft Entra, Okta, and any SAML 2.0 IdP.</p>' +
        '<div style="display:flex; gap:8px; flex-wrap:wrap">' +
          '<button class="btn" data-sso="google">' + iconGoogle() + '<span style="margin-left:6px">Configure Google</span></button>' +
          '<button class="btn" data-sso="microsoft">' + iconMicrosoft() + '<span style="margin-left:6px">Configure Microsoft</span></button>' +
          '<button class="btn" data-sso="saml">' + iconKey() + '<span style="margin-left:6px">SAML 2.0</span></button>' +
        "</div>" +
      "</div>" +
      '<div class="card">' +
        "<h2>Multi-factor auth</h2>" +
        '<p style="color: var(--fg-2); font-size: var(--t-sec); margin: 0 0 var(--s-4)">Require WebAuthn (passkeys) or TOTP for all sign-ins.</p>' +
        '<button class="btn accent" id="mfaBtn">Require MFA for all members</button>' +
      "</div>";
    $$('[data-sso]', root).forEach(function (b) {
      b.addEventListener("click", function () {
        var p = b.getAttribute("data-sso");
        var name = p === "google" ? "Google Workspace" : p === "microsoft" ? "Microsoft Entra" : "SAML 2.0";
        comingSoon("Connect " + name, "Federate every workspace login through " + name + ". Members without a matching account will be denied.");
      });
    });
    var mfa = $("#mfaBtn", root);
    if (mfa) mfa.addEventListener("click", function () { comingSoon("Require MFA", "Every member will be required to enroll a passkey or TOTP at their next sign-in."); });
  }
  function renderSettingsWebhooks(root) {
    root.innerHTML =
      '<div class="card">' +
        "<h2>Webhooks</h2>" +
        '<p style="color: var(--fg-2); font-size: var(--t-sec); margin: 0 0 var(--s-4)">Forward events to Slack, PagerDuty, or your own endpoint. Payloads are HMAC-signed.</p>' +
        '<div class="empty">' +
          '<div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M4 8h16M4 16h16M8 4v16M16 4v16"/></svg></div>' +
          '<h3>No webhooks yet</h3>' +
          '<p>Wire AgentVisor to your incident-response tools.</p>' +
          '<button class="btn accent" id="whAdd">+ Add webhook</button>' +
        "</div>" +
      "</div>";
    var b = $("#whAdd", root);
    if (b) b.addEventListener("click", function () {
      openInputModal({ title: "Add webhook", label: "Endpoint URL", placeholder: "https://hooks.example.com/agentvisor", confirmLabel: "Save", onConfirm: function (v) { toast("Webhook saved: " + v.slice(0, 40) + "…"); } });
    });
  }
  function renderSettingsBilling(root) {
    root.innerHTML =
      '<div class="card">' +
        "<h2>Plan</h2>" +
        '<div style="display:flex; align-items:baseline; gap:8px; margin-bottom: 12px"><span style="font-size:22px; font-weight:600">Free</span> <span class="pill accent">up to 10 deployments</span></div>' +
        '<p style="color: var(--fg-2); font-size: var(--t-sec); margin: 0 0 var(--s-3)">All governance features included. Upgrade to Team for SSO enforcement, longer retention, and priority support.</p>' +
        '<button class="btn accent" id="upgradeBtn">Upgrade to Team</button>' +
      "</div>";
    var b = $("#upgradeBtn", root);
    if (b) b.addEventListener("click", function () { comingSoon("Upgrade to Team", "Billing lands in the beta. In the meantime, ping the AgentVisor team to enable Team features on your workspace."); });
  }
  async function renderSettingsAudit(root) {
    root.innerHTML = '<div class="card">' + loadingBlock("table") + "</div>";
    var audit = await state.ds.listAudit();
    var rows = audit.map(function (a) {
      return '<tr><td class="mono" style="color:var(--fg-3); font-size:11.5px; white-space:nowrap">' + esc(new Date(a.at).toLocaleString()) + '</td>' +
        '<td><span style="font-weight:500">' + esc(a.event) + "</span></td>" +
        "<td>" + esc(a.actor) + "</td>" +
        "<td>" + esc(a.target || "—") + "</td>" +
        '<td style="color: var(--fg-2)">' + esc(a.note || "") + "</td></tr>";
    }).join("");
    root.innerHTML =
      '<div class="card" style="padding:0">' +
        '<div style="padding:12px 16px; border-bottom:1px solid var(--border)">' +
          '<h2 style="margin:0; font-size:var(--t-section); font-weight:600">Audit log</h2>' +
        "</div>" +
        '<div class="table-wrap"><table>' +
          "<thead><tr><th>When</th><th>Event</th><th>Actor</th><th>Target</th><th>Note</th></tr></thead>" +
          "<tbody>" + rows + "</tbody>" +
        "</table></div>" +
      "</div>";
  }
  function renderSettingsBilling_OLD_UNUSED(root) {
    root.innerHTML =
      '<div class="card">' +
        "<h2>Plan</h2>" +
        '<div style="display:flex; align-items:baseline; gap:8px; margin-bottom: 12px"><span style="font-size:22px; font-weight:600">Free</span> <span class="pill accent">up to 10 deployments</span></div>' +
        '<p style="color: var(--fg-2); font-size: var(--t-sec); margin: 0 0 var(--s-3)">All governance features included. Upgrade to Team for SSO enforcement, longer retention, and priority support.</p>' +
        '<button class="btn accent">Upgrade to Team</button>' +
      "</div>";
  }

  /* ============================================================
   * CONFIRM MODAL
   * ============================================================ */

  function confirmModal(opts) {
    var backdrop = h(
      '<div class="modal-backdrop">' +
        '<div class="modal ' + (opts.danger ? "confirm-danger" : "") + '">' +
          "<h2>" + esc(opts.title) + "</h2>" +
          '<p class="sub">' + esc(opts.body) + "</p>" +
          '<div class="actions">' +
            '<button type="button" class="btn" data-close>Cancel</button>' +
            '<button type="button" class="btn ' + (opts.danger ? "danger" : "primary") + '" data-confirm>' + esc(opts.confirmLabel || "Confirm") + "</button>" +
          "</div>" +
        "</div>" +
      "</div>"
    );
    document.body.appendChild(backdrop);
    document.body.classList.add("locked");
    function close() { backdrop.remove(); document.body.classList.remove("locked"); document.removeEventListener("keydown", onKey); }
    function onKey(e) { if (e.key === "Escape") close(); }
    document.addEventListener("keydown", onKey);
    backdrop.addEventListener("click", function (e) {
      if (e.target === backdrop || e.target.hasAttribute("data-close")) close();
      if (e.target.hasAttribute("data-confirm")) { close(); opts.onConfirm && opts.onConfirm(); }
    });
    // Focus the confirm button so Enter confirms
    setTimeout(function () { backdrop.querySelector("[data-confirm]").focus(); }, 20);
  }

  /* ============================================================
   * COMMAND PALETTE (⌘K)
   * ============================================================ */

  var cmdkOpen_ = false;
  async function openCmdK() {
    if (cmdkOpen_) return;
    cmdkOpen_ = true;
    document.body.classList.add("locked");

    // Gather targets
    var routes = [
      { g: "Navigate", label: "Overview", desc: "Fleet 24h dashboard", kbd: "G O", href: "#/overview", icon: iconChart() },
      { g: "Navigate", label: "Sessions", desc: "Every agent session", kbd: "G S", href: "#/sessions", icon: iconActivity() },
      { g: "Navigate", label: "Policies", desc: "Rules the daemon enforces", kbd: "G P", href: "#/policies", icon: iconShield() },
      { g: "Navigate", label: "Deployments", desc: "Daemons & tokens", kbd: "G D", href: "#/deployments", icon: iconServer() },
      { g: "Navigate", label: "Settings", desc: "Org, members, keys, audit", kbd: "G ,", href: "#/settings", icon: iconGear() },
    ];
    var actions = [
      { g: "Actions", label: "Toggle theme", desc: "Switch light / dark", run: function () { toggleTheme(); } },
      { g: "Actions", label: "New deployment", desc: "Register an agentvisord daemon", run: function () { navigate("#/deployments"); setTimeout(openCreateDeploymentModal, 100); } },
      { g: "Actions", label: "Sign out", desc: "Leave this workspace", run: signOut },
    ];
    var sessions = [], policies = [], deployments = [];
    try {
      var sres = await state.ds.listSessions(); sessions = sres.sessions.slice(0, 20).map(function (s) {
        return { g: "Sessions", label: s.externalId, desc: s.agent + " · " + s.user, href: "#/sessions/" + s.id, icon: iconActivity() };
      });
      policies = (await state.ds.listPolicies()).map(function (p) {
        return { g: "Policies", label: p.name, desc: p.description, href: "#/policies/" + p.id, icon: iconShield() };
      });
      deployments = (await state.ds.listDeployments()).map(function (d) {
        return { g: "Deployments", label: d.name, desc: d.environment + " · " + (d.region || ""), href: "#/deployments/" + d.id, icon: iconServer() };
      });
    } catch (e) {}
    var all = routes.concat(actions).concat(sessions).concat(policies).concat(deployments);

    var backdrop = h(
      '<div class="cmdk-backdrop">' +
        '<div class="cmdk">' +
          '<input type="text" placeholder="Search or run a command…" autocomplete="off" spellcheck="false" />' +
          '<div class="list" id="cmdkList"></div>' +
          '<div class="cmdk-footer">' +
            '<span class="hint"><span class="kbd">↑↓</span> navigate</span>' +
            '<span class="hint"><span class="kbd">↵</span> select</span>' +
            '<span class="hint"><span class="kbd">Esc</span> close</span>' +
          "</div>" +
        "</div>" +
      "</div>"
    );
    document.body.appendChild(backdrop);
    var input = backdrop.querySelector("input");
    var list = backdrop.querySelector("#cmdkList");
    var selected = 0;

    function fuzzyMatch(q, s) { s = s.toLowerCase(); q = q.toLowerCase(); var i = 0; for (var c of s) if (c === q[i]) i++; return i === q.length; }
    function paint() {
      var q = input.value.trim();
      var filtered = q ? all.filter(function (it) { return fuzzyMatch(q, it.label + " " + (it.desc || "")); }) : all;
      selected = Math.min(selected, filtered.length - 1);
      if (selected < 0) selected = 0;
      if (filtered.length === 0) {
        list.innerHTML = '<div class="empty-hint">No matches</div>';
        return;
      }
      var byGroup = {};
      filtered.forEach(function (it) { (byGroup[it.g] = byGroup[it.g] || []).push(it); });
      var html = "";
      var idx = 0;
      Object.keys(byGroup).forEach(function (g) {
        html += '<div class="group-label">' + esc(g) + "</div>";
        byGroup[g].forEach(function (it) {
          var isSel = idx === selected;
          html += '<div class="item' + (isSel ? " selected" : "") + '" data-idx="' + idx + '">' +
            (it.icon || "") +
            "<span>" + esc(it.label) + "</span>" +
            (it.desc ? '<span class="desc">' + esc(it.desc) + "</span>" : "") +
            (it.kbd ? '<span class="kbd">' + esc(it.kbd) + "</span>" : "") +
            "</div>";
          idx++;
        });
      });
      list.innerHTML = html;
      list._flat = filtered;
    }
    paint();
    setTimeout(function () { input.focus(); }, 10);

    input.addEventListener("input", function () { selected = 0; paint(); });
    input.addEventListener("keydown", function (e) {
      var flat = list._flat || [];
      if (e.key === "ArrowDown") { e.preventDefault(); selected = Math.min(selected + 1, flat.length - 1); paint(); }
      else if (e.key === "ArrowUp") { e.preventDefault(); selected = Math.max(selected - 1, 0); paint(); }
      else if (e.key === "Enter") { e.preventDefault(); run(flat[selected]); }
      else if (e.key === "Escape") close();
    });
    list.addEventListener("click", function (e) {
      var it = e.target.closest(".item");
      if (!it) return;
      var idx = parseInt(it.getAttribute("data-idx"), 10);
      run((list._flat || [])[idx]);
    });

    function close() {
      cmdkOpen_ = false;
      backdrop.remove();
      document.body.classList.remove("locked");
    }
    function run(it) {
      if (!it) return;
      if (it.href) { close(); navigate(it.href); }
      else if (it.run) { close(); it.run(); }
    }
    backdrop.addEventListener("click", function (e) { if (e.target === backdrop) close(); });
  }

  /* ============================================================
   * KEYBOARD SHORTCUTS
   * ============================================================ */

  function installKeyboardShortcuts() {
    document.addEventListener("keydown", function (e) {
      // ⌘K / Ctrl+K
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        openCmdK();
        return;
      }
      // Ignore keystrokes inside inputs
      if (/^(INPUT|TEXTAREA|SELECT)$/.test((e.target || {}).tagName || "")) return;
      // g-then-x shortcuts
      if (e.key.toLowerCase() === "g") {
        state.gPrefixAt = Date.now();
        return;
      }
      if (state.gPrefixAt && Date.now() - state.gPrefixAt < 900) {
        var k = e.key.toLowerCase();
        if (k === "o") { state.gPrefixAt = 0; navigate("#/overview"); }
        else if (k === "s") { state.gPrefixAt = 0; navigate("#/sessions"); }
        else if (k === "p") { state.gPrefixAt = 0; navigate("#/policies"); }
        else if (k === "d") { state.gPrefixAt = 0; navigate("#/deployments"); }
        else if (k === ",") { state.gPrefixAt = 0; navigate("#/settings"); }
      }
      if (e.key === "?") {
        openShortcutSheet();
      }
    });
  }

  function openShortcutSheet() {
    var groups = [
      { title: "Navigate", items: [
        ["G O", "Overview"], ["G S", "Sessions"], ["G P", "Policies"],
        ["G D", "Deployments"], ["G ,", "Settings"],
      ]},
      { title: "Actions", items: [
        ["⌘ K", "Open command palette"], ["Esc", "Close dialogs"], ["?", "Show this sheet"],
      ]},
    ];
    var html = groups.map(function (g) {
      return '<div style="margin-bottom: 16px;">' +
        '<div style="font-size: 11px; color: var(--fg-3); text-transform: uppercase; letter-spacing: 0.06em; font-weight: 600; margin-bottom: 8px;">' + g.title + "</div>" +
        g.items.map(function (i) {
          return '<div style="display: flex; align-items: center; padding: 6px 0; border-bottom: 1px solid var(--border);">' +
            '<span style="flex: 1; font-size: 13px;">' + i[1] + "</span>" +
            '<span class="kbd">' + i[0] + "</span>" +
            "</div>";
        }).join("") +
      "</div>";
    }).join("");
    var backdrop = h(
      '<div class="modal-backdrop"><div class="modal">' +
        "<h2>Keyboard shortcuts</h2>" +
        '<p class="sub">Move around without a mouse.</p>' +
        html +
        '<div class="actions"><button type="button" class="btn primary" data-close>Done</button></div>' +
      "</div></div>"
    );
    document.body.appendChild(backdrop);
    document.body.classList.add("locked");
    function close() { backdrop.remove(); document.body.classList.remove("locked"); document.removeEventListener("keydown", onKey); }
    function onKey(ev) { if (ev.key === "Escape") close(); }
    document.addEventListener("keydown", onKey);
    backdrop.addEventListener("click", function (e) {
      if (e.target === backdrop || e.target.hasAttribute("data-close")) close();
    });
  }

  /* ============================================================
   * MISC
   * ============================================================ */

  function emptyState(title, body, ctaLabel, ctaHref, ctaId) {
    var cta = "";
    if (ctaLabel && ctaHref) cta = '<a class="btn accent" href="' + esc(ctaHref) + '">' + esc(ctaLabel) + "</a>";
    else if (ctaLabel) cta = '<button class="btn accent" id="' + esc(ctaId || "cta") + '">' + esc(ctaLabel) + "</button>";
    return '<div class="empty">' +
      '<div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="9"/><path d="M8 12h8"/></svg></div>' +
      "<h3>" + esc(title) + "</h3><p>" + esc(body) + "</p>" + cta +
    "</div>";
  }

  function renderError(main, err) {
    console.error(err);
    main.innerHTML = pageHeader("Error") + '<div class="card"><div class="empty"><h3>Something went wrong</h3><p>' + esc(err.message || "Unknown error") + '</p><button class="btn" onclick="location.reload()">Reload</button></div></div>';
  }

  /* ---------- go ---------- */

  boot();
})();
