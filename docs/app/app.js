/*
 * AgentVisor AI console. Application.
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
  // Null-safe listener attach for async render paths. If the user
  // navigates away while a renderer is awaiting data, the target
  // element may already be gone by the time listeners attach; a raw
  // $(sel).addEventListener would throw and leave the new route with
  // a broken half-initialized handler set.
  var on = function (sel, evt, fn, root) {
    var el = typeof sel === "string" ? $(sel, root) : sel;
    if (el) el.addEventListener(evt, fn);
    return el;
  };
  var app = $("#app");

  var state = {
    session: null,
    route: null,
    ds: window.dataSource,
    range: "24h",
    theme: null,
    gPrefixAt: 0,
    settingsTab: "general",
    // Last list-page URL (with its filter/sort query) per section, so
    // "← All sessions" on a detail page returns to the view the user
    // actually came from instead of a reset list.
    lastList: {},
  };
  function rememberListUrl(section) {
    state.lastList[section] = location.hash || ("#/" + section);
  }
  function backToListUrl(section) {
    return state.lastList[section] || ("#/" + section);
  }

  /* ---------- theme ---------- */

  function applyTheme(t) {
    document.documentElement.setAttribute("data-theme", t);
    state.theme = t;
    try { localStorage.setItem("av_theme", t); } catch (e) {}
    // The in-app toggle overrides the OS scheme, so the scheme-paired
    // theme-color metas would keep tinting the browser chrome for the
    // wrong theme — collapse them to the explicit choice.
    var tint = t === "dark" ? "#0a0a0c" : "#f7f7f8";
    document.querySelectorAll('meta[name="theme-color"]').forEach(function (m) {
      m.setAttribute("content", tint);
      m.removeAttribute("media");
    });
  }
  function initTheme() {
    var saved;
    try { saved = localStorage.getItem("av_theme"); } catch (e) {}
    if (saved === "light" || saved === "dark") applyTheme(saved);
    else state.theme = matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    // Follow a LIVE OS scheme flip (sunset auto-dark etc.) while the
    // app is open — but only when the user never chose explicitly.
    // CSS already tracks prefers-color-scheme when data-theme is
    // absent; re-render so JS-derived bits (menu label) catch up.
    try {
      matchMedia("(prefers-color-scheme: dark)").addEventListener("change", function (ev) {
        var s;
        try { s = localStorage.getItem("av_theme"); } catch (e2) {}
        if (s === "light" || s === "dark") return; // explicit choice wins
        state.theme = ev.matches ? "dark" : "light";
        try { render(); } catch (e2) {}
      });
    } catch (e) { /* older Safari: addListener-only — scheme still applies via CSS */ }
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
  // Safety net: modals live on <body>, outside the #view container
  // the router re-renders. If any modal misses the hashchange-close
  // in installModalKeys, remove stray backdrops so they can't block
  // clicks on the new page.
  window.addEventListener("hashchange", function () {
    $$(".modal-backdrop, .cmdk-backdrop").forEach(function (b) { b.remove(); });
    document.body.classList.remove("locked");
  });

  /* ---------- session bootstrap ---------- */

  // Called after a successful login/signup to restore whatever route
  // the user was trying to visit before we bounced them to /login. We
  // only accept hash routes that start with # so an attacker can't
  // stash `javascript:` in sessionStorage from another tab.
  function consumeReturnTo() {
    try {
      var t = sessionStorage.getItem("av_return_to");
      sessionStorage.removeItem("av_return_to");
      if (typeof t === "string" && t.charAt(0) === "#" && t !== "#/login" && t !== "#/signup") {
        return t;
      }
    } catch (e) {}
    return null;
  }

  async function boot() {
    initTheme();
    try { state.session = await state.ds.getSession(); state.authedAt = Date.now(); } catch (e) { console.error("session", e); }
    if (!location.hash) location.hash = state.session ? "#/overview" : "#/login";
    else render();
    installKeyboardShortcuts();
    if (state.session) startLiveStream();
    // Listen for the datasource-emitted expiry signal. Any 401 that
    // isn't from the boot-time /me probe kicks the user to /login with
    // a toast so they know why. Redirect is a full navigate() so the
    // hash-router picks up "no session" cleanly.
    // A 401 from a request that was already in flight when the user
    // re-authenticated must not boot the FRESH session. Any expiry
    // event within 5s of a login is treated as stale.
    window.addEventListener("av-session-expired", function () {
      if (!state.session) return; // already logged out; ignore
      if (Date.now() - (state.authedAt || 0) < 5000) return; // stale 401 racing a fresh login
      state.session = null;
      stopLiveStream();
      // Remember where they were: a 7-day-TTL expiry mid-investigation
      // shouldn't dump the user on Overview after re-auth. Same
      // machinery the router's login-redirect uses.
      try {
        var full = location.hash || "";
        if (full && full !== "#/login") sessionStorage.setItem("av_return_to", full);
      } catch (e) {}
      toast("Your session expired. Please sign in again");
      navigate("#/login");
    });
    // Cross-tab sign-out: when another tab in this browser signs out,
    // it writes localStorage.av_signed_out_at. The storage event fires
    // in *other* tabs (not the writer). We drop our in-memory session
    // and bounce to login without waiting for the next API 401.
    window.addEventListener("storage", function (e) {
      if (e.key !== "av_signed_out_at" || !e.newValue) return;
      if (!state.session) return;
      state.session = null;
      stopLiveStream();
      toast("Signed out in another tab");
      navigate("#/login");
    });
    // Cross-tab sign-IN: the mirror image. A tab parked on the login
    // page after a cross-tab sign-out stayed stranded there even after
    // the user signed back in elsewhere. Re-check the session and let
    // the tab in.
    window.addEventListener("storage", function (e) {
      if (e.key !== "av_signed_in_at" || !e.newValue) return;
      if (state.session) return;
      state.ds.getSession().then(function (s) {
        if (!s || state.session) return;
        state.session = s;
        state.authedAt = Date.now();
        startLiveStream();
        toast("Signed in in another tab");
        navigate("#/overview");
      }).catch(function () { /* stay on login */ });
    });
    // Cross-tab theme: follow an explicit toggle made in another tab so
    // side-by-side windows don't end up half dark, half light.
    window.addEventListener("storage", function (e) {
      if (e.key !== "av_theme") return;
      if (e.newValue !== "light" && e.newValue !== "dark") return;
      if (state.theme === e.newValue) return;
      applyTheme(e.newValue);
      try { render(); } catch (err) { /* pre-boot */ }
    });
  }

  // Written on every successful login/signup so other tabs (parked on
  // the login page after a cross-tab sign-out) can let themselves in.
  function announceSignIn() {
    try { localStorage.setItem("av_signed_in_at", String(Date.now())); } catch (e) {}
  }

  var liveUnsub = null;
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
    } else if (path[0] === "sessions" && !path[1] && (msg.type === "session.upsert" || msg.type === "events.appended")) {
      // A new session or a batch of events came in. Refresh the list
      // so the operator sees new rows appear without hitting reload.
      // Debounced so a burst of events doesn't cause a re-render on
      // every message.
      scheduleSessionsListRefresh();
    }
  }
  var _ovT;
  function scheduleOverviewRefresh() {
    clearTimeout(_ovT);
    _ovT = setTimeout(function () {
      var main = document.getElementById("view");
      // quiet: this fires on every streamed event — repainting the
      // loading skeleton here made the whole dashboard blink (and any
      // DOM read between paint and data resolve hit a skeleton).
      if (main && (!state.route || state.route.path[0] === "overview")) renderOverview(main, true);
    }, 700);
  }
  var _sdT;
  function scheduleSessionDetailRefresh(id) {
    clearTimeout(_sdT);
    _sdT = setTimeout(async function () {
      var main = document.getElementById("view");
      if (!(main && state.route && state.route.path[0] === "sessions" && state.route.path[1] === id)) return;
      // Fetch BEFORE repainting: the old path re-rendered (skeleton
      // first) and a failed fetch replaced a perfectly good detail
      // page with the error card mid-stream. Now a failure just skips
      // this refresh, and success repaints without a skeleton flash.
      try {
        var data = await state.ds.getSessionById(id);
        var receipt = await state.ds.getReceipt(id);
        if (state.route && state.route.path[0] === "sessions" && state.route.path[1] === id) {
          renderSessionDetail(main, id, { data: data, receipt: receipt });
        }
      } catch (e) { console.warn("session refresh skipped", e); }
    }, 400);
  }
  var _slT;
  function scheduleSessionsListRefresh() {
    clearTimeout(_slT);
    _slT = setTimeout(async function () {
      var main = document.getElementById("view");
      if (!(main && state.route && state.route.path[0] === "sessions" && !state.route.path[1])) return;
      // Fetch first, repaint on success only: no skeleton flash, and a
      // transient failure skips the refresh instead of nuking the list
      // (renderSessionsBody restores in-flight search keystrokes).
      try {
        var mySeq = ++_sessionsFetchSeq;
        var deps = await state.ds.listDeployments();
        var firstPage = await state.ds.listSessions(Object.assign({ limit: sessionsPageSize }, sessionsFilter));
        if (mySeq !== _sessionsFetchSeq) return;
        if (!(state.route && state.route.path[0] === "sessions" && !state.route.path[1])) return;
        sessionsLoaded = firstPage.sessions;
        sessionsCursor = firstPage.nextCursor;
        renderSessionsBody(main, deps);
      } catch (e) { console.warn("sessions refresh skipped", e); }
    }, 400);
  }

  // Catch-up after a hidden stretch: background tabs throttle timers,
  // so after a lid-close/sleep the live views sit stale until the next
  // stream event happens to arrive. Returning to the tab (or the
  // network coming back) quietly refreshes whatever is on screen —
  // all three paths are fetch-first, so a failure just skips.
  function refreshCurrentView() {
    var path = state.route && state.route.path;
    if (!state.session || !path || !path[0]) return;
    if (path[0] === "overview") scheduleOverviewRefresh();
    else if (path[0] === "sessions" && path[1]) scheduleSessionDetailRefresh(path[1]);
    else if (path[0] === "sessions") scheduleSessionsListRefresh();
  }
  document.addEventListener("visibilitychange", function () {
    if (!document.hidden) refreshCurrentView();
  });
  window.addEventListener("online", refreshCurrentView);

  /* ---------- main render ---------- */

  // SPA navigation a11y: hash routing means the browser never
  // announces page changes, every history entry shares one static
  // <title>, and focus stays on whatever (now-removed) node had it.
  // On each real route change (not quiet refreshes, which bypass
  // render()): update document.title, announce the page politely,
  // and move focus to the content region.
  var _lastRouteKey = null;
  function routeTitle(path) {
    var names = {
      overview: "Overview", sessions: "Sessions", policies: "Policies",
      deployments: "Deployments", settings: "Settings", login: "Sign in",
      signup: "Create account", reset: "Reset password", "accept-invite": "Accept invite",
    };
    var base = names[path[0]] || "Console";
    if (path[0] === "sessions" && path[1]) base = "Session " + path[1];
    else if (path[0] === "policies" && path[1]) base = "Policy · " + path[1].replace(/^pol_/, "");
    else if (path[0] === "deployments" && path[1]) base = "Deployment · " + path[1];
    else if (path[0] === "settings" && path[1]) base = "Settings · " + path[1].charAt(0).toUpperCase() + path[1].slice(1);
    return base;
  }
  function announceRoute(path) {
    var key = path.join("/") || "overview";
    var title = routeTitle(path);
    document.title = title + " · AgentVisor AI";
    if (key === _lastRouteKey) return; // re-render of the same route
    var first = _lastRouteKey === null;
    _lastRouteKey = key;
    if (first) return; // initial load announces itself natively
    var live = document.getElementById("routeAnnouncer");
    if (!live) {
      live = h('<div id="routeAnnouncer" class="sr-only" aria-live="polite"></div>');
      document.body.appendChild(live);
    }
    live.textContent = title;
    // Focus the content region so keyboard/SR users start at the new
    // page instead of a removed node. #view carries tabindex="-1".
    var main = document.getElementById("view");
    if (main) { main.setAttribute("tabindex", "-1"); try { main.focus({ preventScroll: true }); } catch (e) { main.focus(); } }
  }

  // Scroll restoration: leaving a route remembers where you were;
  // returning to that exact URL (Back button, "← All sessions" links)
  // puts you back instead of dumping you at the top of a long list.
  // Keyed by full hash so a different filter set never inherits a
  // stale offset. Restored once, after the async data paint.
  var scrollMemory = {};
  var _scrollPrevHash = null;
  function restoreScrollFor(key) {
    var y = scrollMemory[key];
    delete scrollMemory[key];
    if (!y) return; // restoring to 0 is a no-op that can race (and cancel) a user scroll
    requestAnimationFrame(function () { window.scrollTo(0, y); });
  }
  async function render() {
    var _hashNow = location.hash || "#/overview";
    if (_scrollPrevHash !== null && _scrollPrevHash !== _hashNow) {
      if (window.scrollY > 0) scrollMemory[_scrollPrevHash] = window.scrollY;
      else delete scrollMemory[_scrollPrevHash];
    }
    _scrollPrevHash = _hashNow;
    state.route = parseHash();
    var path = state.route.path;
    var publicRoutes = ["login", "signup", "reset", "accept-invite"];
    if (!state.session && !publicRoutes.includes(path[0])) {
      // Remember where the user was trying to go so we can restore
      // after login. A deep-link from a Slack notification / email
      // shouldn't dump the user on Overview after they authenticate.
      try {
        var full = location.hash || "";
        if (full && full !== "#/login") sessionStorage.setItem("av_return_to", full);
      } catch (e) {}
      return navigate("#/login");
    }
    if (state.session && publicRoutes.includes(path[0])) return navigate("#/overview");
    if (!state.session) {
      announceRoute(path);
      if (path[0] === "signup") return renderSignup();
      if (path[0] === "reset") return renderReset();
      if (path[0] === "accept-invite") return renderAcceptInvite();
      return renderLogin();
    }

    renderShell();
    announceRoute(path);
    var main = $("#view");
    if (path[0] === "overview" || !path[0]) return renderOverview(main);
    if (path[0] === "sessions" && path[1]) return renderSessionDetail(main, path[1]);
    if (path[0] === "sessions") return renderSessionsList(main);
    if (path[0] === "deployments" && path[1]) return renderDeploymentDetail(main, path[1]);
    if (path[0] === "deployments") return renderDeployments(main);
    if (path[0] === "policies" && path[1]) return renderPolicyDetail(main, path[1]);
    if (path[0] === "policies") return renderPolicies(main);
    if (path[0] === "settings") return renderSettings(main, path[1] || "general");
    // Alias: billing is a settings tab, but "/billing" is what people
    // type. Redirect keeps the canonical URL in the address bar.
    if (path[0] === "billing") return navigate("#/settings/billing");
    main.innerHTML = notFound();
  }

  /* ---------- utilities ---------- */

  function h(html) { var t = document.createElement("template"); t.innerHTML = html.trim(); return t.content.firstChild; }
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]; }); }
  // Array.from splits by code point, not UTF-16 unit — .slice(0,1) on
  // an emoji-leading name ("🚀 Rocket Corp") rendered a broken "�".
  function initials(name) { return (Array.from(String(name || "?").trim())[0] || "?").toUpperCase(); }
  function timeUntil(iso) {
    if (!iso) return "—";
    var s = (new Date(iso).getTime() - Date.now()) / 1000;
    if (s <= 0) return "expired";
    if (s < 3600) return "in " + Math.ceil(s / 60) + "m";
    if (s < 86400) return "in " + Math.ceil(s / 3600) + "h";
    return "in " + Math.ceil(s / 86400) + "d";
  }
  function timeAgo(iso) {
    if (!iso) return "—";
    var t = new Date(iso).getTime();
    if (isNaN(t)) return "—"; // garbage timestamp from the API → dash, not "NaNd ago"
    var s = Math.max(0, (Date.now() - t) / 1000);
    if (s < 60) return Math.floor(s) + "s ago";
    if (s < 3600) return Math.floor(s / 60) + "m ago";
    if (s < 86400) return Math.floor(s / 3600) + "h ago";
    return Math.floor(s / 86400) + "d ago";
  }
  // Live relative timestamp: renders "2m ago" but keeps itself fresh —
  // a table left open used to drift stale ("2m ago" forever). One
  // interval updates every instance; title carries the absolute time.
  function timeAgoCell(iso) {
    if (!iso) return "—";
    var d = new Date(iso);
    return '<time datetime="' + esc(iso) + '" data-tago="' + esc(iso) + '" title="' + esc(d.toLocaleString()) + '">' + esc(timeAgo(iso)) + "</time>";
  }
  setInterval(function () {
    $$("[data-tago]").forEach(function (el) {
      var next = timeAgo(el.getAttribute("data-tago"));
      if (el.textContent !== next) el.textContent = next;
    });
  }, 30000);
  // All toasts land in one fixed stack so simultaneous toasts pile
  // upward instead of overlapping, and the stack sits clear of (and
  // above) the tour launcher pill.
  function toastStack() {
    var s = document.getElementById("toastStack");
    if (!s) {
      s = h('<div id="toastStack" role="status" aria-live="polite"></div>');
      document.body.appendChild(s);
    }
    return s;
  }
  // Newest-wins toast stack: rapid-fire events (bulk actions, streams)
  // once stacked a dozen toasts to the top of the screen. Cap at 4 by
  // evicting the oldest.
  function pushToast(t) {
    var st = toastStack();
    while (st.children.length >= 4) st.firstChild.remove();
    st.appendChild(t);
  }
  function toast(msg, err) {
    var t = h('<div class="toast ' + (err ? "err" : "") + '">' + esc(msg) + "</div>");
    pushToast(t);
    setTimeout(function () { t.remove(); }, 2600);
  }
  // Toast with an inline action — the Undo pattern for low-stakes
  // destructive operations (cheaper than a confirm dialog, safer than
  // nothing). Longer-lived than a plain toast so there's time to react.
  function toastAction(msg, label, fn) {
    var t = h('<div class="toast">' + esc(msg) + ' <button type="button" class="toast-undo">' + esc(label) + "</button></div>");
    t.querySelector(".toast-undo").addEventListener("click", function () { t.remove(); fn(); });
    pushToast(t);
    setTimeout(function () { t.remove(); }, 6500);
  }
  // Toast with a trailing action link; stays up longer so the link is
  // actually clickable. Used by the simulated-attack story.
  function toastLink(msg, href, label) {
    var t = h('<div class="toast">' + esc(msg) +
      ' <a href="' + esc(href) + '" style="color:inherit; font-weight:700; text-decoration:underline; white-space:nowrap">' + esc(label) + "</a></div>");
    pushToast(t);
    setTimeout(function () { t.remove(); }, 6500);
  }
  // Click-to-copy affordance for credential-ish values (fingerprints,
  // pubkeys, tokens). One delegated handler serves every instance.
  function copyable(value) {
    if (!value) return "—";
    return '<span class="copyable">' + esc(value) +
      '<button type="button" class="copy-btn" data-copy="' + esc(value) + '" title="Copy" aria-label="Copy to clipboard">⧉</button></span>';
  }
  // Clipboard writes must survive origins where the async Clipboard
  // API is missing (the documented offline fallback serves over plain
  // http on a LAN, where navigator.clipboard is undefined) — fall back
  // to the legacy hidden-textarea + execCommand path there.
  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.cssText = "position:fixed;top:-1000px;left:0;opacity:0";
      document.body.appendChild(ta);
      ta.select();
      var ok = false;
      try { ok = document.execCommand("copy"); } catch (e) {}
      ta.remove();
      if (ok) resolve(); else reject(new Error("clipboard unavailable"));
    });
  }
  document.addEventListener("click", function (e) {
    var b = e.target.closest("[data-copy]");
    if (!b) return;
    copyText(b.getAttribute("data-copy")).then(
      function () { toast("Copied to clipboard"); },
      function () { toast("Copy failed — select the text manually", true); }
    );
  });
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
  function notFound() {
    return '<div class="page-header"><div><h1>Page not found</h1>' +
      '<div class="sub">The URL you followed doesn\'t point at anything in this workspace.</div></div></div>' +
      '<div class="empty">' +
        '<h3>404. Nothing here</h3>' +
        '<p>The page you\'re looking for might have been renamed, or the link that brought you here is stale.</p>' +
        '<a class="btn accent" href="#/overview">Go to overview</a> ' +
        '<a class="btn" href="#/sessions">Or view sessions</a>' +
      '</div>';
  }
  function usdMicros(str) {
    var n = typeof str === "string" ? parseInt(str, 10) : (str || 0);
    if (isNaN(n)) n = 0; // "$NaN" is worse than "$0.00" for garbage input
    return "$" + (n / 1e6).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  }
  function usdMicrosBig(str) {
    var n = typeof str === "string" ? parseInt(str, 10) : (str || 0);
    if (isNaN(n)) n = 0;
    var v = n / 1e6;
    if (v >= 1000) return "$" + Math.round(v).toLocaleString();
    return "$" + v.toFixed(2);
  }

  // Plain-language recap for blocked sessions. Visitors arrive here
  // from the tour, the attack-demo toast, and the onboarding
  // checklist — before showing them 13 raw events, say what the
  // session means in one sentence a non-technical person can read.
  function storyBanner(s, events) {
    if (!(s.toolsBlocked > 0)) return "";
    var blk = null;
    for (var i = 0; i < events.length; i++) { if (events[i].kind === "block") { blk = events[i]; break; } }
    var value = usdMicrosBig(s.blockedPayoutUsdMicros);
    var recovered = blk && events.some(function (ev) {
      return ev.kind === "guard" && /allow/i.test(ev.tag || "") && ev.seq > blk.seq;
    });
    var reason = blk && /allowlist|vendor/i.test(blk.msg || "") ? "a vendor that isn't approved" : "somewhere policy forbids";
    return '<div class="story-banner" role="note">' +
      '<span class="sb-icon" aria-hidden="true">🛡</span>' +
      '<p><b>What happened here:</b> the <b>' + esc(s.agent) + '</b> agent tried to send <b>' + esc(value) + "</b> to " + reason + ". " +
      "AgentVisor blocked the payment before any money moved" + (blk ? " (event #" + esc(blk.seq) + ")" : "") +
      (recovered ? ", the agent recovered safely," : "") +
      " and the whole session is sealed under the signed receipt on this page.</p>" +
      (blk ? '<button class="btn" id="jumpToBlock">Jump to the block ↓</button>' : "") +
    "</div>";
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
    // Multiple of 4, because the axis draws quarter ticks — a multiple
    // of 5 produced fractional ticks that rounded into "5 4 3 1 0".
    max = Math.ceil(max / 4) * 4 || 4;
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
    // Text alternative: the tooltips are mouse-only, so summarize the
    // series for screen-reader users instead of leaving a silent image.
    var sumAllowed = 0, sumBlocked = 0;
    series.forEach(function (s) { sumAllowed += s.allowed; sumBlocked += s.blocked; });
    var chartLabel = "Bar chart of tool calls per interval: " + sumAllowed + " allowed and " + sumBlocked + " blocked across " + n + " intervals.";
    return '<svg class="chart-svg" viewBox="0 0 ' + w + ' ' + hh + '" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="none" role="img" aria-label="' + esc(chartLabel) + '">' +
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
        rolePreview = null; // a fresh login gets its real role, not a stale banner
        state.ds.logout().then(function () {
          state.session = null;
          // Cross-tab sync: any other console tab open in this browser
          // notices via a storage event and drops its own session state
          // without waiting for the next API 401. The value is a
          // timestamp so re-signing-out later fires the event again.
          try { localStorage.setItem("av_signed_out_at", String(Date.now())); } catch (e) {}
          navigate("#/login");
        });
      },
    });
  }

  /* ── Role preview. Owners/admins can see the console exactly as a
   *    member does — RBAC-hidden tabs and disabled management actions
   *    included — without a second account. In-memory only; a reload
   *    restores the real role. ─────────────────────────────────── */
  var rolePreview = null; // the real role while the preview is active

  function enterRolePreview() {
    if (rolePreview || !state.session) return;
    var real = (state.session.org && state.session.org.role) || "owner";
    if (real === "member") return;
    rolePreview = real;
    state.session.org.role = "member";
    render();
    toast("Previewing as member — admin-only areas are hidden");
  }
  function exitRolePreview() {
    if (!rolePreview || !state.session) return;
    state.session.org.role = rolePreview;
    rolePreview = null;
    render();
    toast("Preview ended — you're back to your own view");
  }

  function renderShell() {
    var current = state.route.path[0] || "overview";
    var org = state.session.org;
    var user = state.session.user;    // One status chip in the topbar, not two. In mock mode we surface
    // the "Demo" label so investors instantly see the data is fixtures.
    // In live/api mode a single pulsing "Live" pill doubles as SSE
    // stream health. It flips to "Reconnecting" when the EventSource
    // drops. Rendering both a mode chip AND a stream chip in live mode
    // duplicated the word "Live" next to itself.
    var statusChip = state.ds.mode === "mock"
      ? '<span class="env-pill" title="Console is showing built-in demo data. Set MOCK_MODE=false to talk to a live backend.">Demo</span>'
      : '<span class="env-pill live-pulse" title="Streaming events from the daemon"><span class="live-label">Live</span></span>';

    app.innerHTML = "";
    app.appendChild(h(
      '<div class="app-shell' + (rolePreview ? " has-preview" : "") + '">' +
        (rolePreview
          ? '<div class="preview-banner" role="status">' +
              '<span aria-hidden="true">👁</span>' +
              '<span>Previewing as <b>member</b> — admin-only tabs and management actions are hidden.</span>' +
              '<button class="btn" id="exitPreview">Exit preview</button>' +
            "</div>"
          : "") +
        '<header class="topbar" role="banner">' +
          '<a class="brand" href="#/overview">' +
            '<img class="brand-mark" src="../logo.png" alt="" width="22" height="22" />' +
            '<span>AgentVisor AI</span>' +
          "</a>" +
          statusChip +
          '<div class="spacer"></div>' +
          '<button class="cmdk-trigger" id="cmdkOpen" aria-label="Open command palette (⌘K)">' +
            '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><circle cx="7" cy="7" r="4.5"/><path d="M10.5 10.5L14 14"/></svg>' +
            '<span>Search or run a command…</span>' +
            '<span class="kbd">⌘K</span>' +
          "</button>" +
          '<button class="theme-btn" id="themeBtn" title="Toggle theme" aria-label="Toggle light/dark theme">' + iconTheme() + "</button>" +
          '<button class="user-btn" id="userBtn" aria-label="Account menu" aria-haspopup="menu" aria-expanded="false">' +
            '<span class="avatar" aria-hidden="true">' + esc(initials(user.displayName || user.email)) + "</span>" +
            "<span>" + esc(user.email) + "</span>" +
          "</button>" +
        "</header>" +
        '<nav class="sidebar" aria-label="Primary navigation">' +
          '<div class="org-switcher">' +
            '<span class="avatar">' + esc(initials(org.name)) + "</span>" +
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
        '<main class="main" id="view" aria-label="Main content"></main>' +
        // Phone-width navigation: the sidebar is display:none ≤760px,
        // so without this bar phones could render pages but never
        // switch sections. Standard bottom tab bar, same routes.
        '<nav class="tabbar" aria-label="Primary navigation (mobile)">' +
          tabLink("overview", current, "Overview", iconChart()) +
          tabLink("sessions", current, "Sessions", iconActivity()) +
          tabLink("policies", current, "Policies", iconShield()) +
          tabLink("deployments", current, "Deploys", iconServer()) +
          tabLink("settings", current, "Settings", iconGear()) +
        "</nav>" +
      "</div>"
    ));
    $("#cmdkOpen").addEventListener("click", openCmdK);
    $("#themeBtn").addEventListener("click", toggleTheme);
    $("#userBtn").addEventListener("click", toggleAccountMenu);
    var xp = $("#exitPreview");
    if (xp) xp.addEventListener("click", exitRolePreview);
  }

  /* ── Account menu. The avatar used to be a straight shortcut to the
   *    sign-out confirm — an account button should offer the account
   *    actions. Anchored dropdown, ARIA menu semantics, Escape /
   *    click-outside / navigation all close it. ─────────────────── */
  function closeAccountMenu() {
    var m = document.getElementById("accountMenu");
    if (m) m.remove();
    var btn = document.getElementById("userBtn");
    if (btn) btn.setAttribute("aria-expanded", "false");
    document.removeEventListener("click", onAccountMenuOutside, true);
    document.removeEventListener("keydown", onAccountMenuKey, true);
    document.removeEventListener("focusin", onAccountMenuFocus, true);
  }
  function onAccountMenuOutside(e) {
    if (e.target.closest("#accountMenu") || e.target.closest("#userBtn")) return;
    closeAccountMenu();
  }
  // Menus close when focus leaves them (Tab-out) — without this the
  // dropdown floated orphaned over the page while the user tabbed
  // through content behind it.
  function onAccountMenuFocus(e) {
    if (e.target.closest && (e.target.closest("#accountMenu") || e.target.closest("#userBtn"))) return;
    closeAccountMenu();
  }
  function onAccountMenuKey(e) {
    var m = document.getElementById("accountMenu");
    if (!m) return;
    if (e.key === "Escape") {
      e.preventDefault(); e.stopPropagation();
      closeAccountMenu();
      var btn = document.getElementById("userBtn");
      if (btn) btn.focus();
      return;
    }
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      var items = Array.prototype.slice.call(m.querySelectorAll("[role=menuitem]"));
      var i = items.indexOf(document.activeElement);
      var next = e.key === "ArrowDown" ? items[i + 1] || items[0] : items[i - 1] || items[items.length - 1];
      if (next) next.focus();
    }
  }
  function toggleAccountMenu() {
    if (document.getElementById("accountMenu")) return closeAccountMenu();
    var user = state.session.user, org = state.session.org;
    var canPreview = !rolePreview && org && org.role !== "member";
    var menu = h(
      '<div id="accountMenu" role="menu" aria-label="Account">' +
        '<div class="am-head">' +
          '<div style="font-weight:600">' + esc(user.displayName || user.email) + "</div>" +
          '<div class="am-sub">' + esc(user.email) + " · " + esc((org && org.role) || "member") + " @ " + esc(org.name) + "</div>" +
        "</div>" +
        '<button role="menuitem" data-act="shortcuts">Keyboard shortcuts <span class="kbd">?</span></button>' +
        '<button role="menuitem" data-act="theme">Switch to ' + (state.theme === "dark" ? "light" : "dark") + " theme</button>" +
        (canPreview ? '<button role="menuitem" data-act="preview">👁 Preview as member</button>' : "") +
        (rolePreview ? '<button role="menuitem" data-act="exitPreview">Exit member preview</button>' : "") +
        '<div class="am-sep"></div>' +
        '<button role="menuitem" data-act="signout" class="am-danger">Sign out…</button>' +
      "</div>"
    );
    document.body.appendChild(menu);
    var btn = document.getElementById("userBtn");
    btn.setAttribute("aria-expanded", "true");
    // anchor under the button, right-aligned
    var r = btn.getBoundingClientRect();
    menu.style.top = (r.bottom + 6) + "px";
    menu.style.right = Math.max(8, window.innerWidth - r.right) + "px";
    menu.addEventListener("click", function (e) {
      var it = e.target.closest("[data-act]");
      if (!it) return;
      var act = it.getAttribute("data-act");
      closeAccountMenu();
      if (act === "shortcuts") openShortcutSheet();
      else if (act === "theme") toggleTheme();
      else if (act === "preview") enterRolePreview();
      else if (act === "exitPreview") exitRolePreview();
      else if (act === "signout") signOut();
    });
    document.addEventListener("click", onAccountMenuOutside, true);
    document.addEventListener("keydown", onAccountMenuKey, true);
    document.addEventListener("focusin", onAccountMenuFocus, true);
    var first = menu.querySelector("[role=menuitem]");
    if (first) first.focus();
  }
  // route changes rebuild the shell — never leave a floating menu behind
  window.addEventListener("hashchange", closeAccountMenu);
  function navLink(key, current, label, icon, kbd) {
    var active = current === key ? ' class="active"' : "";
    return '<a href="#/' + key + '"' + active + ">" + icon + "<span>" + label + "</span>" +
      (kbd ? '<span class="kbd-hint">' + kbd + "</span>" : "") + "</a>";
  }
  function tabLink(key, current, label, icon) {
    var active = current === key;
    return '<a href="#/' + key + '"' + (active ? ' class="active" aria-current="page"' : "") + ">" +
      icon + "<span>" + label + "</span></a>";
  }

  /* ---------- icons ---------- */
  function iconChart() { return '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true" stroke-linecap="round" stroke-linejoin="round"><path d="M2 14V3M2 14h12M5 11V8M8 11V6M11 11v-4"/></svg>'; }
  function iconActivity() { return '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true" stroke-linecap="round" stroke-linejoin="round"><path d="M1.5 8h3l2-5 3 10 2-5h3"/></svg>'; }
  function iconServer() { return '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><rect x="2" y="3" width="12" height="4" rx="1"/><rect x="2" y="9" width="12" height="4" rx="1"/><circle cx="5" cy="5" r=".7" fill="currentColor"/><circle cx="5" cy="11" r=".7" fill="currentColor"/></svg>'; }
  function iconGear() { return '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true" stroke-linecap="round"><circle cx="8" cy="8" r="2"/><path d="M8 1v2M8 13v2M15 8h-2M3 8H1M13 3l-1.4 1.4M4.4 11.6L3 13M13 13l-1.4-1.4M4.4 4.4L3 3"/></svg>'; }
  function iconShield() { return '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true" stroke-linejoin="round"><path d="M8 1.5l5.5 2v4c0 3-2.4 5.7-5.5 6.5C4.9 13.2 2.5 10.5 2.5 7.5v-4L8 1.5z"/><path d="M5.8 7.8l1.6 1.6L10.4 6.4" stroke-linecap="round"/></svg>'; }
  function iconTheme() { return '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><circle cx="8" cy="8" r="3"/><path d="M8 1v1.5M8 13.5V15M1 8h1.5M13.5 8H15M3 3l1 1M12 12l1 1M3 13l1-1M12 4l1-1"/></svg>'; }
  function iconGoogle() { return '<svg viewBox="0 0 18 18"><path fill="#4285F4" d="M17.64 9.2c0-.64-.06-1.25-.16-1.84H9v3.48h4.84c-.21 1.13-.85 2.08-1.8 2.72v2.26h2.92c1.7-1.57 2.68-3.88 2.68-6.62z"/><path fill="#34A853" d="M9 18c2.43 0 4.47-.8 5.96-2.18l-2.92-2.26c-.8.54-1.83.86-3.04.86-2.34 0-4.32-1.58-5.03-3.7H.96v2.32C2.44 15.98 5.48 18 9 18z"/><path fill="#FBBC05" d="M3.97 10.72c-.18-.54-.28-1.12-.28-1.72s.1-1.18.28-1.72V4.96H.96C.35 6.18 0 7.55 0 9s.35 2.82.96 4.04l3.01-2.32z"/><path fill="#EA4335" d="M9 3.58c1.32 0 2.51.45 3.44 1.35l2.58-2.58C13.46.89 11.43 0 9 0 5.48 0 2.44 2.02.96 4.96l3.01 2.32C4.68 5.16 6.66 3.58 9 3.58z"/></svg>'; }
  function iconMicrosoft() { return '<svg viewBox="0 0 16 16"><rect x="1" y="1" width="6.5" height="6.5" fill="#F25022"/><rect x="8.5" y="1" width="6.5" height="6.5" fill="#7FBA00"/><rect x="1" y="8.5" width="6.5" height="6.5" fill="#00A4EF"/><rect x="8.5" y="8.5" width="6.5" height="6.5" fill="#FFB900"/></svg>'; }
  function iconKey() { return '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><circle cx="5.5" cy="8.5" r="3"/><path d="M8.5 8.5H14M13 8.5V11M11 8.5V10"/></svg>'; }

  /* ============================================================
   * LOGIN / SIGNUP. Split-screen with SSO
   * ============================================================ */

  function renderLogin() { renderAuth("login"); }
  function renderSignup() { renderAuth("signup"); }
  function renderAuth(kind) {
    var isSignup = kind === "signup";
    // Discover which SSO providers the backend actually has env for.
    // Rendering a button we can't honor would leave the user staring at
    // a 404 after they clicked "Continue with Microsoft".
    state.ds.getSSO().then(function (sso) {
      var providers = (sso && sso.providers) || [];
      renderAuthWithProviders(kind, providers);
    }).catch(function () {
      renderAuthWithProviders(kind, []);
    });
  }
  function renderAuthWithProviders(kind, providers) {
    var isSignup = kind === "signup";
    // R121 F2: read err/joined query params so we can render a
    // friendly banner for users bounced here by the OAuth MFA
    // gate (R120 F2) or the /invites/accept requiresLogin path
    // (R121 F1). Neither is an "error" from the user's POV.
    var authQs = (location.hash.split("?")[1] || "");
    var authParams = new URLSearchParams(authQs);
    var errCode = authParams.get("err") || "";
    var joinedFlag = authParams.get("joined") || "";
    var noteHtml = "";
    if (errCode === "mfa_required_use_password_login") {
      noteHtml = '<div class="auth-note">This account has a passkey enrolled. Sign in with your password so we can complete the WebAuthn step — SSO alone can\'t satisfy MFA.</div>';
    } else if (errCode.indexOf("oauth_") === 0) {
      // R122 F2: OAuth callback error paths now redirect here
      // instead of dead-ending in a raw-JSON tab. Slug map:
      //   oauth_provider_not_found      — bad :provider param
      //   oauth_provider_not_configured — env vars missing
      //   oauth_provider_mismatch       — state cookie provider drift
      //   oauth_missing_state_cookie    — cookie missing/tampered
      //   oauth_malformed_state_cookie  — JSON parse failed
      //   oauth_exchange_failed         — IdP code exchange rejected
      //   oauth_no_email_in_id_token    — IdP omitted email claim
      //   oauth_email_not_verified      — email_verified !== true
      //   oauth_no_membership           — server-side invariant
      var oauthMsg = errCode === "oauth_email_not_verified"
        ? "Your identity provider did not confirm the email address. Verify it with the provider and try again."
        : errCode === "oauth_no_email_in_id_token"
          ? "Your identity provider did not return an email address. Ask an admin to configure the OpenID email scope."
          : errCode === "oauth_exchange_failed"
            ? "Sign-in with your identity provider failed. Try again."
            : "Sign-in with your identity provider could not complete. Try again or use password sign-in.";
      noteHtml = '<div class="auth-note">' + esc(oauthMsg) + '</div>';
    } else if (errCode.indexOf("saml_") === 0) {
      // R122 F2: SAML ACS error paths redirect here. Slug map:
      //   saml_config_not_found          — config missing/inactive
      //   saml_config_uses_sha1_reject   — R114 F1 legacy sha1 guard
      //   saml_assertion_<err>           — consumeSamlResponse failure
      //   saml_jit_disabled              — new email, JIT off
      //   saml_user_exists_in_other_org  — R76 HIGH #1 cross-org guard
      //   saml_domain_allowlist_required — R76 HIGH #1 empty allowlist
      //   saml_domain_not_allowed        — email domain not on list
      var samlMsg = errCode === "saml_domain_not_allowed" || errCode === "saml_domain_allowlist_required"
        ? "Your identity provider asserted an email that isn't on this workspace's allowlist. Ask an admin to add your domain."
        : errCode === "saml_jit_disabled"
          ? "Your workspace does not auto-provision users. Ask an admin to add your account."
          : errCode === "saml_user_exists_in_other_org"
            ? "An account already exists for that email in another workspace. Contact support to consolidate."
            : errCode === "saml_config_uses_sha1_reject"
              ? "Your identity provider is signing with SHA-1 which we no longer accept. Ask your IdP admin to switch to SHA-256."
              : "SAML sign-in could not complete. Ask an admin to check the IdP configuration.";
      noteHtml = '<div class="auth-note">' + esc(samlMsg) + '</div>';
    } else if (joinedFlag) {
      noteHtml = '<div class="auth-note">You were added to the workspace. Sign in with your existing password to continue.</div>';
    }
    var byId = {};
    providers.forEach(function (p) { byId[p.id] = p; });
    var ssoButtons = "";
    if (byId.google)    ssoButtons += '<button type="button" data-sso="google">' + iconGoogle() + '<span>Continue with Google</span></button>';
    if (byId.microsoft) ssoButtons += '<button type="button" data-sso="microsoft">' + iconMicrosoft() + '<span>Continue with Microsoft</span></button>';
    // SAML/Okta = enterprise path. We're honest about not shipping it
    // yet: click routes to a contact-sales mailto. Still visible so the
    // login page communicates the roadmap without pretending.
    ssoButtons += '<button type="button" data-sso="saml">' + iconKey() + '<span>SAML SSO (contact sales)</span></button>';
    var showSsoBlock = ssoButtons !== "";
    app.innerHTML = "";
    app.appendChild(h(
      '<div class="auth-shell">' +
        '<section class="auth-form">' +
          '<div class="auth-form-inner">' +
            '<div class="auth-brand"><span class="auth-brand-mark">A</span> AgentVisor AI</div>' +
            '<h1>' + (isSignup ? "Create your workspace" : "Sign in") + '</h1>' +
            '<p class="sub">' + (isSignup ? "Governance for every AI agent in your fleet." : "Access your agent control plane.") + '</p>' +
            noteHtml +
            (showSsoBlock ? '<div class="sso">' + ssoButtons + "</div>" + '<div class="divider">or with email</div>' : '') +
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
              ? '<div class="mock-badge">Demo. Any credentials work</div>'
              : "") +
          "</div>" +
        "</section>" +
        '<aside class="auth-panel"><div class="panel-inner">' +
          '<h2>Ship autonomous agents your compliance team trusts.</h2>' +
          '<p>Every LLM call, every tool call, every policy hit. Captured, evaluated, and signed. In production, in real time.</p>' +
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
        if (p === "saml") {
          // Prompt for the email so we can look up the org's SAML
          // config, then redirect to its login endpoint. This is the
          // "Sign in with SSO" flow. No OAuth involved.
          openInputModal({
            title: "Sign in with SAML SSO",
            label: "Work email",
            placeholder: "you@company.com",
            confirmLabel: "Continue",
            sub: "We'll look up your workspace's identity provider by email domain.",
            onConfirm: function (email) {
              state.ds.discoverSaml(email).then(function (r) {
                if (!r.ssoConfig) {
                  toast("No SSO configured for that domain. Ask your admin to add your IdP in Settings → Single sign-on.", true);
                  return;
                }
                var relay = (sessionStorage.getItem("av_return_to") || "");
                var url = r.ssoConfig.loginUrl + (relay ? "?RelayState=" + encodeURIComponent(relay) : "");
                window.location.assign(url);
              }).catch(function (err) {
                toast(err.message || "SSO discovery failed", true);
              });
            },
          });
          return;
        }
        state.ds.loginWithProvider(p).then(function (s) {
          state.session = s; state.authedAt = Date.now(); startLiveStream(); announceSignIn();
          navigate(consumeReturnTo() || "#/overview");
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
      promise.then(async function (s) {
        // MFA gate. Server returned {mfaRequired: true} — no email is
        // included in the response (R85 F3 closed the password-validity
        // oracle by making /login's failure and mfaRequired responses
        // indistinguishable in wire shape). We already have the email
        // the user typed, so use that.
        if (s && s.mfaRequired) {
          errEl.innerHTML = '<div class="auth-hint" style="color: var(--fg-2); padding: 8px 12px;">Touch your passkey…</div>';
          try {
            var full = await runPasskeyLogin(s.email || email);
            state.session = full;
            state.authedAt = Date.now();
            announceSignIn();
            startLiveStream();
            navigate(consumeReturnTo() || "#/overview");
            return;
          } catch (err) {
            btn.disabled = false;
            errEl.innerHTML = '<div class="auth-err">' + esc(err.message || "Passkey step failed") + "</div>";
            return;
          }
        }
        state.session = s;
        state.authedAt = Date.now();
        announceSignIn();
        startLiveStream();
        if (isSignup) {
          // A brand-new workspace has none of the data behind whatever
          // deep link bounced the user to auth — drop the saved
          // return-to and land on onboarding instead of a stale 404.
          try { sessionStorage.removeItem("av_return_to"); } catch (e2) {}
          navigate("#/overview");
        } else {
          navigate(consumeReturnTo() || "#/overview");
        }
      })
        .catch(function (err) {
          btn.disabled = false;
          // 429 rate-limit → surface friendly message + countdown so
          // the user has actionable info (e.g. shared corporate NAT
          // where multiple people are hitting login at once).
          var friendly = err.friendlyMessage || err.message || "Failed";
          errEl.innerHTML = '<div class="auth-err">' + esc(friendly) + "</div>";
          // If the server told us how long to wait, kick a countdown
          // that re-enables the button when time's up.
          if (err.retryAfterSec && err.retryAfterSec > 0) {
            var left = err.retryAfterSec;
            btn.disabled = true;
            var iv = setInterval(function () {
              left -= 1;
              if (left <= 0) {
                clearInterval(iv);
                btn.disabled = false;
                errEl.innerHTML = "";
                return;
              }
              errEl.innerHTML = '<div class="auth-err">Too many attempts. Try again in ' + left + " second" + (left === 1 ? "" : "s") + ".</div>";
            }, 1000);
          }
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

  function renderAcceptInvite() {
    var qs = (location.hash.split("?")[1] || "");
    var params = new URLSearchParams(qs);
    var email = params.get("email") || "";
    var token = params.get("token") || "";
    if (!token) {
      app.innerHTML = "";
      app.appendChild(h('<div class="auth-shell"><section class="auth-form"><div class="auth-form-inner"><h1>Invite link invalid</h1><p class="sub">This link is missing its token. Ask your teammate to resend the invite.</p><a class="btn accent" href="#/login">Back to sign in</a></div></section></div>'));
      return;
    }
    app.innerHTML = "";
    app.appendChild(h(
      '<div class="auth-shell">' +
        '<section class="auth-form">' +
          '<div class="auth-form-inner">' +
            '<div class="auth-brand"><span class="auth-brand-mark">A</span> AgentVisor AI</div>' +
            '<h1>Join the workspace</h1>' +
            '<p class="sub">Accept your invite for <b>' + esc(email) + '</b> and set a password.</p>' +
            '<form id="acceptForm">' +
              '<div class="field"><label for="displayName">Your name</label><input id="displayName" type="text" placeholder="First Last" autocomplete="name" /></div>' +
              '<div class="field"><label for="password">Password (min 12)</label><input id="password" type="password" required minlength="12" autocomplete="new-password" /></div>' +
              '<div id="acceptErr"></div>' +
              '<button class="primary" type="submit">Accept invite</button>' +
            '</form>' +
            '<div class="auth-alt">Already have an account? <a href="#/login">Sign in</a> first, then click the invite link again.</div>' +
          '</div>' +
        '</section>' +
        '<aside class="auth-panel"><div class="panel-inner">' +
          '<h2>Team invites are single-use.</h2>' +
          '<p>The token is argon2-hashed at rest and expires in 7 days. Only the email address on the invite can accept it.</p>' +
        '</div></aside>' +
      '</div>'
    ));
    $("#acceptForm").addEventListener("submit", function (e) {
      e.preventDefault();
      var btn = e.target.querySelector('button[type="submit"]');
      btn.disabled = true;
      state.ds.acceptInvite({
        email: email,
        token: token,
        password: $("#password").value,
        displayName: ($("#displayName") || {}).value || undefined,
      }).then(function (s) {
        // R121 F1: server now returns { requiresLogin: true } on
        // the existing-user branch instead of minting a session
        // cookie — an invite token can't double as identity
        // authentication (would enable target-account takeover
        // via any attacker with a valid invite). Route the user
        // to /#/login with a friendly banner explaining they
        // were added to the org and need to sign in normally.
        if (s.requiresLogin) {
          toast("You were added to " + (s.org && s.org.name ? s.org.name : "the workspace") + ". Sign in with your existing password to continue.");
          navigate("#/login?joined=1");
          return;
        }
        state.session = { user: s.user, org: s.org };
        state.authedAt = Date.now();
        announceSignIn();
        startLiveStream();
        toast("Welcome to " + (s.org && s.org.name ? s.org.name : "the workspace"));
        navigate("#/overview");
      }).catch(function (err) {
        btn.disabled = false;
        $("#acceptErr").innerHTML = '<div class="auth-err">' + esc(err.message || "Accept failed") + '</div>';
      });
    });
  }

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
            '<div class="auth-brand"><span class="auth-brand-mark">A</span> AgentVisor AI</div>' +
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
              ? '<div class="mock-badge">Demo. The token is displayed inline after "Send reset link".</div>'
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
        toast("Password updated. Please sign in");
        navigate("#/login");
      }).catch(function (err) {
        btn.disabled = false;
        var msg = err.status === 401 ? "This link is invalid or has expired." : (err.message || "Reset failed");
        $("#resetErr").innerHTML = '<div class="auth-err">' + esc(msg) + "</div>";
      });
    });
  }

  /* ============================================================
   * OVERVIEW. Stats with sparklines + a real chart
   * ============================================================ */

  async function renderOverview(main, quiet) {
    // Range lives in the URL (#/overview?range=7d) like the sessions
    // filters, so a specific dashboard window is shareable.
    var rm = (location.hash.split("?")[1] || "").match(/(?:^|&)range=(1h|24h|7d|30d)/);
    if (rm) state.range = rm[1];
    var rangeLabel = { "1h": "the last hour", "24h": "the last 24 hours", "7d": "the last 7 days", "30d": "the last 30 days" }[state.range] || "the last 24 hours";
    if (!quiet) main.innerHTML = pageHeader("Overview", "Fleet activity for " + rangeLabel + ".", rangeGroup()) + loadingBlock("stats");
    var stats, sessions;
    try {
      stats = await state.ds.getOverview(state.range);
      var res = await state.ds.listSessions();
      sessions = res.sessions.slice(0, 8);
    } catch (e) {
      // A quiet (stream-driven) refresh must never replace a live
      // dashboard with the error card on a transient blip — keep the
      // stale view; the next refresh will catch up.
      if (quiet) { console.warn("overview refresh skipped", e); return; }
      return renderError(main, e);
    }

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
      pageHeader("Overview", "Fleet activity for " + rangeLabel + ".", attackBtn() + rangeGroup()) +
      onboardingCard(stats, sessions) +
      '<div class="stats">' +
        stat("Sessions", stats.sessions, stats.deployments + " deployment" + (stats.deployments === 1 ? "" : "s"), sparkline(series.map(function (b) { return b.allowed + b.blocked; }))) +
        stat("Tool calls allowed", stats.toolsAllowed.toLocaleString(), "policy pass", sparkline(allowedByHour)) +
        stat("Tool calls blocked", stats.toolsBlocked.toLocaleString(), pctBlocked + "% block rate", sparkline(blockedByHour, { color: "var(--danger-solid)", fill: "var(--danger-bg)" }), "blocks", "#/sessions?status=blocked") +
        stat("LLM spend", "$" + stats.llmSpendUsd, "usage this window", sparkline(spendByHour)) +
        stat("Prevented losses", "$" + Number(stats.blockedSpendUsd).toLocaleString(), "kept from bad orders", sparkline(blockedValueCumulative, { color: "var(--success-solid)", fill: "var(--success-bg)" }), "savings") +
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
    var sim = main.querySelector("#simAttack");
    if (sim) sim.addEventListener("click", runAttackDemo);
    // Fresh-workspace onboarding: the checklist ticks itself live as
    // the daemon connects and the first sessions stream in, so keep
    // re-rendering (quietly — no skeleton swap) while it's on screen.
    clearTimeout(overviewTimer);
    if (freshT0() != null && (state.route.path[0] || "overview") === "overview") {
      overviewTimer = setTimeout(function () {
        var m = $("#view");
        if (m && (state.route.path[0] || "overview") === "overview") renderOverview(m, true);
      }, 2500);
    }
  }

  /* ── Fresh-workspace onboarding checklist ────────────────────
   * Day-one guidance for a brand-new org (the meeting-notes ask:
   * "UI for onboarding"). Four steps that tick themselves as the
   * fresh simulation progresses: workspace → daemon → sessions →
   * first block. Invisible outside fresh mode. */
  var overviewTimer = null;
  function freshT0() {
    try { var v = localStorage.getItem("av_mock_fresh_t0"); return v ? +v : null; } catch (e) { return null; }
  }
  function onboardingCard(stats, sessions) {
    if (freshT0() == null) return "";
    var hasDep = stats.deployments > 0;
    var hasSess = stats.sessions > 0;
    var hasBlock = sessions.some(function (s) { return s.toolsBlocked > 0; });
    var blockedValue = sessions.reduce(function (a, s) { return a + (parseInt(s.blockedPayoutUsdMicros, 10) || 0) / 1e6; }, 0);
    var steps = [
      { done: true, label: "Create your workspace", sub: "Done — you're in" },
      { done: hasDep, label: "Connect your first daemon", sub: hasDep ? "northwind-prod is connected" : "Run the install command. This page updates by itself.", href: "#/deployments" },
      { done: hasSess, label: "Sessions stream in", sub: hasSess ? stats.sessions + " session" + (stats.sessions === 1 ? "" : "s") + " recorded so far" : "Waiting for your agent's first run…" },
      { done: hasBlock, label: "First bad order blocked", sub: hasBlock ? "$" + blockedValue.toLocaleString() + " kept — open the session to see why" : "Starter policies are armed and waiting", href: hasBlock ? "#/sessions" : null },
    ];
    var doneCount = steps.filter(function (s) { return s.done; }).length;
    var rows = steps.map(function (s, i) {
      var inner =
        '<span class="ob-tick' + (s.done ? " done" : "") + '">' + (s.done ? "✓" : i + 1) + "</span>" +
        '<span class="ob-body"><span class="ob-label">' + esc(s.label) + "</span>" +
        '<span class="ob-sub">' + esc(s.sub) + "</span></span>";
      return s.href && !s.done
        ? '<a class="ob-step" href="' + esc(s.href) + '">' + inner + "</a>"
        : s.href
          ? '<a class="ob-step done" href="' + esc(s.href) + '">' + inner + "</a>"
          : '<div class="ob-step' + (s.done ? " done" : "") + '">' + inner + "</div>";
    }).join("");
    return '<div class="onboard-card card" role="region" aria-label="Getting started">' +
      '<div class="ob-head"><h2>Getting started</h2><span class="ob-count">' + doneCount + " of " + steps.length + "</span>" +
      '<div class="ob-bar"><span style="width:' + (doneCount / steps.length) * 100 + '%"></span></div></div>' +
      '<div class="ob-steps">' + rows + "</div>" +
    "</div>";
  }

  /* ── Simulated attack (mock mode) ────────────────────────────
   * Stages the blocked-payment story live: an in_progress purchase
   * session appears, the payment gets blocked ~3 s later, the session
   * seals, and every stat on screen catches up. Pure fixture theater —
   * the datasource owns the state changes, this owns the pacing. */
  var attackRunning = false;
  function attackBtn() {
    if (state.ds.mode !== "mock" || typeof state.ds.simulateAttack !== "function") return "";
    try { if (localStorage.getItem("av_mock_fresh_t0")) return ""; } catch (e) {}
    return '<button class="btn" id="simAttack"' + (attackRunning ? " disabled" : "") +
      ' title="Stage a live blocked payment in this demo org">⚡ Simulate an attack</button> ';
  }
  async function runAttackDemo() {
    if (attackRunning || state.ds.mode !== "mock" || typeof state.ds.simulateAttack !== "function") return;
    attackRunning = true;
    var rerender = function () {
      var p = state.route.path[0] || "overview";
      if (p === "overview" || (p === "sessions" && !state.route.path[1])) render();
    };
    toast("vendor-onboarding picked up an invoice email…");
    var info = await state.ds.simulateAttack();
    setTimeout(rerender, 250);
    setTimeout(function () {
      toast('create_payment("' + info.vendor + '") — vendor not on the approved list. BLOCKED', true);
      rerender();
    }, info.blockAtMs + 200);
    setTimeout(function () {
      rerender();
      setTimeout(function () {
        var st = document.querySelector(".stat.savings");
        if (st) st.classList.add("av-pulse");
        var row = document.querySelector('tr[data-id="' + info.id + '"]');
        if (row) row.classList.add("av-new-row");
      }, 700);
      toastLink("Blocked before the money moved — $" + info.valueUsd.toLocaleString() + " kept. Receipt signed.", "#/sessions/" + info.id, "View session →");
      attackRunning = false;
    }, info.sealAtMs + 300);
  }

  function installChartHover(root, series) {
    var chart = root.querySelector(".chart-svg");
    if (!chart) return;
    var cursor = chart.querySelector("#chartCursor");
    var tip = h('<div class="chart-tip" style="display:none"></div>');
    root.querySelector(".chart-card").appendChild(tip);
    function showBucket(strip) {
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
    }
    function hideTip() { tip.style.display = "none"; cursor.style.opacity = "0"; }
    chart.addEventListener("mousemove", function (e) {
      var strip = e.target.closest(".hover-strip");
      if (!strip) { hideTip(); return; }
      showBucket(strip);
    });
    chart.addEventListener("mouseleave", hideTip);
    // Touch: tap a bucket to pin its tooltip, tap elsewhere to clear —
    // hover-only meant the chart said nothing on phones and tablets.
    chart.addEventListener("click", function (e) {
      var strip = e.target.closest(".hover-strip");
      if (!strip) { hideTip(); return; }
      if (tip.style.display === "block" && strip.getAttribute("data-idx") === tip.getAttribute("data-idx")) { hideTip(); return; }
      tip.setAttribute("data-idx", strip.getAttribute("data-idx"));
      showBucket(strip);
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
        try { history.replaceState(null, "", "#/overview" + (state.range === "24h" ? "" : "?range=" + state.range)); } catch (e) {}
        render();
      });
    });
  }
  function stat(label, value, delta, spark, cls, href) {
    var inner =
      '<div class="head"><div class="label">' + esc(label) + "</div></div>" +
      '<div class="value">' + esc(value) + "</div>" +
      (delta ? '<div class="delta">' + esc(delta) + "</div>" : "") +
      (spark || "");
    // With an href the stat becomes a drill-down (e.g. blocked calls →
    // the pre-filtered sessions list). Same box, same classes.
    if (href) return '<a class="stat linked ' + (cls || "") + '" href="' + esc(href) + '" title="' + esc(label) + ' — view matching sessions">' + inner + "</a>";
    return '<div class="stat ' + (cls || "") + '">' + inner + "</div>";
  }
  function pageHeader(title, sub, actions) {
    return '<div class="page-header"><div><h1>' + esc(title) + "</h1>" +
      (sub ? '<div class="sub">' + esc(sub) + "</div>" : "") + "</div>" +
      (actions ? '<div class="actions">' + actions + "</div>" : "") + "</div>";
  }

  /* ============================================================
   * SESSIONS LIST. With filter bar
   * ============================================================ */

  var sessionsFilter = { q: "", deploymentId: "", agent: "", blockedOnly: false, sinceHours: 24 };
  // Column sort for the sessions list. Newest-first is the natural
  // order the API returns; anything else is a client-side re-sort of
  // the loaded set, mirrored into the URL like the filters.
  var sessionsSort = { key: "started", dir: "desc" };
  var SESSIONS_SORTERS = {
    events: function (s) { return s.events; },
    allowed: function (s) { return s.toolsAllowed; },
    blocked: function (s) { return s.toolsBlocked; },
    cost: function (s) { return parseInt(s.costUsdMicros, 10) || 0; },
    started: function (s) { return new Date(s.startedAt).getTime() || 0; },
  };
  // The loaded set in display order (WYSIWYG for both the table and
  // the CSV export). API order is newest-first already, so the
  // default sort is a no-op copy.
  function sortedSessionsView() {
    var view = sessionsLoaded.slice();
    var sorter = SESSIONS_SORTERS[sessionsSort.key];
    if (sorter && !(sessionsSort.key === "started" && sessionsSort.dir === "desc")) {
      var mul = sessionsSort.dir === "asc" ? 1 : -1;
      view.sort(function (a, b) { return (sorter(a) - sorter(b)) * mul; });
    }
    return view;
  }

  // The filter state lives in the URL (#/sessions?q=…&status=blocked&…)
  // so a filtered view is shareable, survives reload, and the back
  // button works. Render reads from the hash; filter widgets write to
  // it (replaceState — tweaking a filter shouldn't spam history).
  var SESSIONS_RANGES = [1, 24, 168, 720];
  function readSessionsFilterFromHash() {
    var p = {};
    (location.hash.split("?")[1] || "").split("&").forEach(function (kv) {
      var i = kv.indexOf("=");
      if (i > 0) { try { p[kv.slice(0, i)] = decodeURIComponent(kv.slice(i + 1)); } catch (e) {} }
    });
    var range = parseInt(p.range, 10);
    sessionsFilter = {
      q: p.q || "",
      deploymentId: p.dep || "",
      agent: p.agent || "",
      blockedOnly: p.status === "blocked",
      sinceHours: SESSIONS_RANGES.indexOf(range) >= 0 ? range : 24,
      policyId: p.policy || "",
    };
    var sm = /^(events|allowed|blocked|cost|started)\.(asc|desc)$/.exec(p.sort || "");
    sessionsSort = sm ? { key: sm[1], dir: sm[2] } : { key: "started", dir: "desc" };
  }
  function writeSessionsFilterToHash() {
    var parts = [];
    if (sessionsFilter.q) parts.push("q=" + encodeURIComponent(sessionsFilter.q));
    if (sessionsFilter.blockedOnly) parts.push("status=blocked");
    if (sessionsFilter.sinceHours !== 24) parts.push("range=" + sessionsFilter.sinceHours);
    if (sessionsFilter.deploymentId) parts.push("dep=" + encodeURIComponent(sessionsFilter.deploymentId));
    if (sessionsFilter.agent) parts.push("agent=" + encodeURIComponent(sessionsFilter.agent));
    if (sessionsFilter.policyId) parts.push("policy=" + encodeURIComponent(sessionsFilter.policyId));
    if (sessionsSort.key !== "started" || sessionsSort.dir !== "desc") parts.push("sort=" + sessionsSort.key + "." + sessionsSort.dir);
    try { history.replaceState(null, "", "#/sessions" + (parts.length ? "?" + parts.join("&") : "")); } catch (e) {}
  }
  function sessionsFilterActive() {
    return !!(sessionsFilter.q || sessionsFilter.deploymentId || sessionsFilter.agent ||
      sessionsFilter.blockedOnly || sessionsFilter.sinceHours !== 24 || sessionsFilter.policyId);
  }
  var sessionsPageSize = 50;
  // Hard cap on DOM rows. At 1M sessions the API pages 50 at a time,
  // and "Load more" keeps appending. But we stop at 1000 rendered so
  // the browser never has to reflow 100k+ rows. Past this point the
  // filter bar is the correct escape hatch (search, date range, etc).
  var SESSIONS_DOM_CAP = 1000;
  var sessionsLoaded = []; // { sessions: [...], nextCursor }
  var sessionsCursor = null;

  // Monotonic token: every sessions-list fetch bumps it, and only the
  // continuation holding the latest token may mutate the shared
  // sessionsLoaded/sessionsCursor accumulators or paint. Without this,
  // two rapid filter changes raced: the SLOWER (stale) response landed
  // last and painted rows that didn't match the filter bar or URL.
  var _sessionsFetchSeq = 0;
  async function renderSessionsList(main) {
    readSessionsFilterFromHash();
    var mySeq = ++_sessionsFetchSeq;
    var firstPaint = !main.querySelector("#fSearch");
    if (firstPaint) {
      // Fresh entry to the route: paint the frame + skeleton. On filter
      // re-renders the existing bar stays live (repainting it killed
      // its listeners mid-debounce and dropped keystrokes) — the fetch
      // happens first and only a winning response repaints.
      main.innerHTML = pageHeader("Sessions", "Every agent session policed by AgentVisor.") + filterBar() + loadingBlock("table");
    }
    var deps;
    try {
      deps = await state.ds.listDeployments();
      var firstPage = await state.ds.listSessions(Object.assign({ limit: sessionsPageSize }, sessionsFilter));
      if (mySeq !== _sessionsFetchSeq) return; // a newer filter/render superseded this fetch
      sessionsLoaded = firstPage.sessions;
      sessionsCursor = firstPage.nextCursor;
    } catch (e) {
      if (mySeq !== _sessionsFetchSeq) return;
      return renderError(main, e);
    }
    renderSessionsBody(main, deps);
  }
  function restoreSearchFocus(root, val) {
    var el = $("#fSearch", root);
    if (!el) return;
    // `val` carries text typed after the last committed filter (a live
    // refresh can land mid-debounce) so keystrokes are never dropped.
    if (val != null && val !== el.value) el.value = val;
    el.focus();
    var end = el.value.length;
    try { el.setSelectionRange(end, end); } catch (e) {}
  }
  function renderSessionsBody(main, deps) {
    rememberListUrl("sessions");
    var searchHadFocus = document.activeElement && document.activeElement.id === "fSearch";
    var searchVal = searchHadFocus ? document.activeElement.value : null;
    var body;
    if (sessionsLoaded.length === 0) {
      body = emptyState("No sessions match your filters", "Try widening the date range or clearing the search.",
        sessionsFilterActive() ? "Clear filters" : null, null, "clearFilters");
    } else {
      body = '<div class="card" style="padding:0">' + sessionsTable(sortedSessionsView(), true) + '</div>';
      if (sessionsCursor && sessionsLoaded.length < SESSIONS_DOM_CAP) {
        body += '<div style="margin-top:12px; text-align:center;">' +
          '<button class="btn" id="loadMore">Load more</button>' +
          "</div>";
      } else if (sessionsCursor) {
        // Hit the DOM cap. Nudge users toward narrower filters.
        body += '<div style="margin-top:12px; text-align:center; color: var(--fg-2); font-size: var(--t-sec);">' +
          "Showing the newest " + sessionsLoaded.length.toLocaleString() + " sessions. " +
          "Narrow the date range or search to see older matches." +
          "</div>";
      }
    }
    var showingLabel = sessionsLoaded.length > 0
      ? sessionsLoaded.length.toLocaleString() + " session" + (sessionsLoaded.length === 1 ? "" : "s") + " shown"
      : "no sessions";
    var headerActions = sessionsLoaded.length > 0
      ? '<button class="btn" id="exportCsv" title="Download the sessions shown below (current filters applied) as CSV">↓ Export CSV</button>'
      : "";
    main.innerHTML = pageHeader("Sessions", showingLabel, headerActions) + filterBar() + body;
    installFilters(main, deps);
    if (searchHadFocus) restoreSearchFocus(main, searchVal);
    var xc = $("#exportCsv");
    if (xc) xc.addEventListener("click", function () { exportSessionsCsv(sortedSessionsView()); });
    // Column sort: click (or Enter on) a header button. Client-side
    // re-render only — no refetch, keeps Load-more pages.
    var thead = main.querySelector("thead");
    if (thead) thead.addEventListener("click", function (e) {
      var btn = e.target.closest(".th-sort");
      if (!btn) return;
      var key = btn.getAttribute("data-sort");
      if (sessionsSort.key === key) sessionsSort.dir = sessionsSort.dir === "asc" ? "desc" : "asc";
      else sessionsSort = { key: key, dir: key === "started" ? "desc" : "desc" };
      writeSessionsFilterToHash();
      renderSessionsBody(main, deps);
      // put focus back on the same header so keyboard users can toggle
      var again = main.querySelector('.th-sort[data-sort="' + key + '"]');
      if (again) again.focus();
    });
    var clr = $("#clearFilters");
    if (clr) clr.addEventListener("click", function () {
      try { history.replaceState(null, "", "#/sessions"); } catch (e) {}
      renderSessionsList(main);
    });
    var lm = $("#loadMore");
    if (lm) {
      lm.addEventListener("click", async function () {
        lm.disabled = true;
        lm.textContent = "Loading…";
        var mySeq = _sessionsFetchSeq; // abandon if a filter change lands mid-fetch
        try {
          var page = await state.ds.listSessions(Object.assign({ limit: sessionsPageSize, cursor: sessionsCursor }, sessionsFilter));
          if (mySeq !== _sessionsFetchSeq) return;
          sessionsLoaded = sessionsLoaded.concat(page.sessions);
          sessionsCursor = page.nextCursor;
          renderSessionsBody(main, deps);
        } catch (err) {
          if (mySeq !== _sessionsFetchSeq) return;
          toast(err.message || "Failed to load", true);
          lm.disabled = false;
          lm.textContent = "Load more";
        }
      });
    }
    restoreScrollFor(location.hash);
  }

  // CSV export of the currently loaded (filtered) sessions. Built
  // client-side — no server round-trip, works offline. Fields are
  // quoted, and values that could be interpreted as spreadsheet
  // formulas (=+-@ leads) are prefixed with ' so a hostile agent name
  // can't become an executing cell in Excel (CSV injection).
  function csvField(v) {
    var s = String(v == null ? "" : v);
    if (/^[=+\-@\t]/.test(s)) s = "'" + s;
    return '"' + s.replace(/"/g, '""') + '"';
  }
  function exportSessionsCsv(sessions) {
    var head = ["session_id", "agent", "actor", "model", "started_at", "events", "tools_allowed", "tools_blocked", "llm_cost_usd", "blocked_value_usd"];
    var lines = [head.join(",")].concat(sessions.map(function (s) {
      return [
        s.externalId || s.id, s.agent, s.user || "", s.model || "", s.startedAt || "",
        s.events, s.toolsAllowed, s.toolsBlocked,
        ((parseInt(s.costUsdMicros, 10) || 0) / 1e6).toFixed(4),
        ((parseInt(s.blockedPayoutUsdMicros || "0", 10) || 0) / 1e6).toFixed(2),
      ].map(csvField).join(",");
    }));
    var stamp = new Date().toISOString().slice(0, 16).replace(/[:T]/g, "-");
    var blob = new Blob(["\ufeff" + lines.join("\r\n")], { type: "text/csv;charset=utf-8" });
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "agentvisor-sessions-" + stamp + ".csv";
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 4000);
    toast(sessions.length + " session" + (sessions.length === 1 ? "" : "s") + " exported");
  }

  function filterBar() {
    return '<div class="filter-bar">' +
      '<div class="search">' +
        '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><circle cx="7" cy="7" r="4.5"/><path d="M10.5 10.5L14 14"/></svg>' +
        '<input id="fSearch" type="search" placeholder="Search by session id, agent, or actor…" aria-label="Search sessions" value="' + esc(sessionsFilter.q) + '" />' +
      "</div>" +
      '<select id="fRange" aria-label="Filter by time range">' +
        '<option value="1"' + (sessionsFilter.sinceHours === 1 ? " selected" : "") + '>Last 1h</option>' +
        '<option value="24"' + (sessionsFilter.sinceHours === 24 ? " selected" : "") + '>Last 24h</option>' +
        '<option value="168"' + (sessionsFilter.sinceHours === 168 ? " selected" : "") + '>Last 7d</option>' +
        '<option value="720"' + (sessionsFilter.sinceHours === 720 ? " selected" : "") + '>Last 30d</option>' +
      "</select>" +
      '<select id="fDep" aria-label="Filter by deployment"><option value="">All deployments</option></select>' +
      '<select id="fAgent" aria-label="Filter by agent"><option value="">All agents</option></select>' +
      '<label class="toggle"><input id="fBlocked" type="checkbox"' + (sessionsFilter.blockedOnly ? " checked" : "") + '/> Blocked only</label>' +
      // The policy filter arrives via cross-links (policy detail →
      // "View all") rather than a widget, so an active one must show
      // as a dismissible pill or the shortened list looks broken.
      (sessionsFilter.policyId
        ? '<span class="filter-pill">policy: <b>' + esc(sessionsFilter.policyId.replace(/^pol_/, "")) + '</b>' +
          '<button type="button" id="clearPolicyFilter" aria-label="Remove the policy filter" title="Remove the policy filter">✕</button></span>'
        : "") +
      "</div>";
  }
  function installFilters(root, deps) {
    function apply() { writeSessionsFilterToHash(); renderSessionsList(root); }
    var fS = $("#fSearch", root);
    if (fS) {
      var timer;
      fS.addEventListener("input", function () {
        clearTimeout(timer);
        timer = setTimeout(function () { sessionsFilter.q = fS.value.trim(); apply(); }, 220);
      });
    }
    var fR = $("#fRange", root);
    if (fR) fR.addEventListener("change", function () { sessionsFilter.sinceHours = parseInt(fR.value, 10); apply(); });
    var fD = $("#fDep", root);
    if (fD && deps) {
      deps.forEach(function (d) {
        var o = document.createElement("option");
        o.value = d.id; o.textContent = d.name;
        if (sessionsFilter.deploymentId === d.id) o.selected = true;
        fD.appendChild(o);
      });
      fD.addEventListener("change", function () { sessionsFilter.deploymentId = fD.value; apply(); });
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
      fA.addEventListener("change", function () { sessionsFilter.agent = fA.value; apply(); });
    }
    var fB = $("#fBlocked", root);
    if (fB) fB.addEventListener("change", function () { sessionsFilter.blockedOnly = fB.checked; apply(); });
    var cp = $("#clearPolicyFilter", root);
    if (cp) cp.addEventListener("click", function () { sessionsFilter.policyId = ""; apply(); });
  }

  function sessionsTable(sessions, sortable) {
    if (sessions.length === 0) return emptyState("No sessions yet", "Sessions from your daemons will appear here.");
    var rows = sessions.map(function (s) {
      var blocks = s.toolsBlocked > 0
        ? '<span class="pill err">' + s.toolsBlocked + " blocked</span>"
        : '<span class="pill ok">clean</span>';
      return '<tr data-clickable data-id="' + esc(s.id) + '" data-nav="#/sessions/" tabindex="0">' +
        '<td title="' + esc(s.agent + " · " + s.externalId) + '"><div style="font-weight:500">' + esc(s.agent) + '</div><div class="id">' + esc(s.externalId) + "</div></td>" +
        '<td title="' + esc(s.user || "") + '"><div class="actor"><span class="av">' + esc(initials(s.user)) + '</span>' + esc(s.user || "—") + '</div></td>' +
        '<td class="num tabular">' + s.events + "</td>" +
        '<td class="num tabular">' + s.toolsAllowed + "</td>" +
        "<td>" + blocks + "</td>" +
        '<td class="num tabular">' + usdMicros(s.costUsdMicros) + "</td>" +
        '<td style="color: var(--fg-2)">' + timeAgoCell(s.startedAt) + "</td>" +
      "</tr>";
    }).join("");
    // Sortable headers only on the sessions list (the overview's
    // recent-sessions card stays plain). Each sortable th is a real
    // button with aria-sort on the th, per the ARIA sortable-table
    // pattern; clicking toggles direction on the active column.
    function th(label, key, num) {
      if (!sortable || !key) return "<th" + (num ? ' class="num"' : "") + ">" + label + "</th>";
      var active = sessionsSort.key === key;
      var ariaSort = active ? (sessionsSort.dir === "asc" ? "ascending" : "descending") : "none";
      var arrow = active ? (sessionsSort.dir === "asc" ? " ↑" : " ↓") : "";
      return '<th' + (num ? ' class="num"' : "") + ' aria-sort="' + ariaSort + '">' +
        '<button type="button" class="th-sort' + (active ? " active" : "") + '" data-sort="' + key + '" title="Sort by ' + esc(label.toLowerCase()) + '">' + label + arrow + "</button></th>";
    }
    return '<div class="table-wrap"><table>' +
      "<thead><tr>" + th("Session") + th("Actor") + th("Events", "events", true) + th("Allowed", "allowed", true) +
        th("Blocked", "blocked") + th("LLM cost", "cost", true) + th("Started", "started") + "</tr></thead>" +
      "<tbody>" + rows + "</tbody></table></div>";
  }

  // Global click delegation: any <tr data-clickable data-id data-nav>
  // navigates to `${data-nav}${data-id}` when the click isn't on a nested
  // button/link that stopped propagation.
  // Selecting text in a cell also ends with a click on the row —
  // navigating away right after the user carefully selected an id to
  // copy was hostile. A live selection suppresses row navigation.
  function textSelActive() {
    var s = window.getSelection && window.getSelection();
    return !!(s && String(s).length);
  }
  document.addEventListener("click", function (e) {
    var tr = e.target.closest("tr[data-clickable]");
    if (!tr) return;
    if (e.target.closest("button, a")) return;
    if (textSelActive()) return;
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
   * SESSION DETAIL. Compact rows + right drawer + verified receipt
   * ============================================================ */

  async function renderSessionDetail(main, id, initial) {
    main.innerHTML = pageHeader("Session", "", '<a href="' + esc(backToListUrl("sessions")) + '" class="btn">← All sessions</a>') + loadingBlock("stats");
    var data, receipt;
    try {
      data = initial && initial.data ? initial.data : await state.ds.getSessionById(id);
      receipt = initial && initial.receipt ? initial.receipt : await state.ds.getReceipt(id);
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
      // R101 F2 + R102 F1: recognize the '[redacted-member-view]'
      // sentinel returned by the server for role=member on
      // /read/sessions/:id. Prior shape rendered the literal
      // sentinel string as if it were the LLM content — confusing
      // UX (users opened support tickets thinking the daemon was
      // broken). Now show a 🔒 pill.
      var REDACT = "[redacted-member-view]";
      var msgHtml = ev.msg === REDACT
        ? '<span class="redacted-pill" title="LLM prompt/response hidden for member role — ask an admin for access">🔒 redacted</span>'
        : esc(ev.msg || "");
      var subHtml = ev.sub === REDACT
        ? '<span class="sub redacted-pill" title="LLM sub-line hidden for member role">🔒 redacted</span>'
        : (ev.sub ? '<span class="sub">· ' + esc(ev.sub) + "</span>" : "");
      return '<div class="evt ' + sev + '" data-i="' + i + '" tabindex="0" role="option" aria-selected="false" style="--depth: ' + ev.layout.depth + ';">' +
        '<span class="seq">#' + esc(ev.seq) + "</span>" +
        '<span class="icon ' + iconClass + '">' + iconChar + "</span>" +
        '<span class="body"><b>' + esc(ev.tag || ev.kind) + '</b> ' + msgHtml +
          subHtml +
        "</span>" +
        '<span class="waterfall">' +
          '<span class="wf-track"></span>' +
          '<span class="wf-bar" style="left:' + ev.layout.startPct.toFixed(2) + '%; width:' + ev.layout.widthPct.toFixed(2) + '%; background:' + barColor + ';"></span>' +
        "</span>" +
        '<span class="dur">' + esc(durTxt) + "</span>" +
      "</div>";
    }).join("");

    // Kind filter chips: only for kinds actually present, with counts.
    // "Blocked" is the chip a reviewer reaches for first, so it gets
    // danger styling.
    var kindCounts = {};
    events.forEach(function (e2) { kindCounts[e2.kind] = (kindCounts[e2.kind] || 0) + 1; });
    var chipDefs = [
      { id: "llm", label: "LLM" }, { id: "tool", label: "Tools" },
      { id: "guard", label: "Guards" }, { id: "block", label: "Blocked" },
    ].filter(function (c) { return kindCounts[c.id]; });
    var evtChips = '<button class="evt-chip active" data-kind="" aria-pressed="true">All <span class="n">' + events.length + "</span></button>" +
      chipDefs.map(function (c) {
        return '<button class="evt-chip' + (c.id === "block" ? " chip-danger" : "") + '" data-kind="' + c.id + '" aria-pressed="false">' + c.label + ' <span class="n">' + kindCounts[c.id] + "</span></button>";
      }).join("");

    // Prev/next triage: when this session is part of the list the
    // user was just browsing (sessionsLoaded, in its current sort),
    // offer paging through that exact set — review blocked sessions
    // one after another without bouncing back to the list. Hidden on
    // direct visits (shared links) where there's no list context.
    var nav = "";
    var siblings = sortedSessionsView();
    var sidx = -1;
    for (var si = 0; si < siblings.length; si++) if (siblings[si].id === id) { sidx = si; break; }
    if (sidx >= 0 && siblings.length > 1) {
      var prevS = siblings[sidx - 1], nextS = siblings[sidx + 1];
      nav = '<span class="sess-nav">' +
        '<button class="btn" id="prevSess" aria-label="Previous session in your list" title="Previous session in your list ( [ )"' + (prevS ? ' data-id="' + esc(prevS.id) + '"' : " disabled") + ">‹</button>" +
        '<span class="sess-nav-pos" aria-label="Session ' + (sidx + 1) + ' of ' + siblings.length + '">' + (sidx + 1) + " / " + siblings.length + "</span>" +
        '<button class="btn" id="nextSess" aria-label="Next session in your list" title="Next session in your list ( ] )"' + (nextS ? ' data-id="' + esc(nextS.id) + '"' : " disabled") + ">›</button>" +
      "</span> ";
    }

    main.innerHTML =
      pageHeader("Session " + s.externalId, s.agent + " · " + (s.user || "—") + " · " + (s.model || ""), '<a href="' + esc(backToListUrl("sessions")) + '" class="btn">← All sessions</a> ' + nav + '<button class="btn" id="printPack" title="Print this page as a clean evidence pack — receipt and event trail included">🖨 Print evidence pack</button> <button class="btn" id="copyRcpt">Copy receipt</button> <button class="btn" id="shareRcpt">🔗 Share verify link</button> <button class="btn accent" id="dlRcpt">↓ Download receipt</button>') +
      '<div class="session-summary">' +
        cell("Events", s.events, "streamed") +
        cell("Allowed", s.toolsAllowed, "tool calls") +
        cell("Blocked", s.toolsBlocked, "policy hits", s.toolsBlocked > 0 ? "blocks" : "") +
        cell("LLM cost", usdMicros(s.costUsdMicros), "actual usage") +
        cell("Blocked value", usdMicrosBig(s.blockedPayoutUsdMicros), "would have been paid out", parseInt(s.blockedPayoutUsdMicros, 10) > 0 ? "savings" : "") +
      "</div>" +
      storyBanner(s, events) +
      '<div class="detail-grid">' +
        '<div class="events-card card">' +
          '<div class="events-head"><h2>Event stream</h2><span class="count" id="evtCount">' + events.length + " event" + (events.length === 1 ? "" : "s") +
            (data.nextEventCursor != null ? " (more available)" : "") + "</span>" +
            '<div class="evt-filters">' + evtChips +
              '<input id="evtSearch" type="search" placeholder="Filter events…" aria-label="Filter events by text" />' +
            "</div></div>" +
          '<div id="eventList" role="listbox" aria-label="Event stream. Use the arrow keys to browse events and Enter to inspect one.">' + eventsHtml + "</div>" +
          (data.nextEventCursor != null
            ? '<div style="padding: 12px 16px; text-align:center; border-top:1px solid var(--border);">' +
                '<button class="btn" id="loadMoreEv">Load more events</button>' +
              "</div>"
            : "") +
        "</div>" +
        '<div>' +
          receiptCard(receipt) +
          '<div class="event-drawer" id="eventDrawer" style="margin-top: 12px;" role="region" aria-label="Event detail" aria-live="polite">' +
            '<h3>Event detail</h3>' +
            '<div class="empty-mini">Click an event to inspect.</div>' +
          "</div>" +
        "</div>" +
      "</div>" +
      // Printed-only provenance footer. Screen never shows it; on
      // paper it tells the recipient how to verify independently.
      '<div class="print-only" style="margin-top:16px; padding-top:10px; border-top:1px solid var(--border); font-size:11px; color:var(--fg-2);">' +
        "Evidence pack · session " + esc(s.externalId) + " · " + events.length + " event" + (events.length === 1 ? "" : "s") +
        (data.nextEventCursor != null ? " (partial — more events not loaded; use Load more before printing for the full trail)" : "") +
        " · printed " + esc(new Date().toLocaleString()) +
        (receipt && receipt.receiptId ? " · receipt " + esc(receipt.receiptId) : "") +
        (receipt && receipt.signingKeyFingerprint ? " · signing key " + esc(receipt.signingKeyFingerprint) : "") +
        "<br/>Verify this receipt offline at <b>agentvisorai.me/verify</b> — paste the downloaded receipt JSON; the Ed25519 signature check runs in the browser, no account needed." +
      "</div>";

    // event click → drawer. Selection is mirrored into the hash as
    // `#/sessions/<id>?evt=<seq>` via replaceState (no re-render, no
    // history spam) so a specific decision is directly linkable — and
    // so the selection survives the live-stream refresh, which
    // re-renders this whole page whenever a new event arrives.
    var evList = $("#eventList");
    var drawer = $("#eventDrawer");
    if (!evList || !drawer) return; // user navigated away mid-await
    function selectEvent(row) {
      $$('.evt', evList).forEach(function (r) {
        r.classList.remove("selected");
        r.setAttribute("aria-selected", "false");
      });
      row.classList.add("selected");
      row.setAttribute("aria-selected", "true");
      var ev = events[parseInt(row.getAttribute("data-i"), 10)];
      var deepHash = "#/sessions/" + encodeURIComponent(id) + "?evt=" + ev.seq;
      try { history.replaceState(null, "", deepHash); } catch (e2) {}
      renderEventDrawer(drawer, ev, location.origin + location.pathname + deepHash);
    }
    evList.addEventListener("click", function (e) {
      var row = e.target.closest(".evt");
      if (row) selectEvent(row);
    });
    // Keyboard support: the rows are custom divs, so without this a
    // keyboard user could reach the list but never inspect an event.
    // Same interaction model as the clickable table rows: arrows move,
    // Enter/Space selects, Home/End jump.
    evList.addEventListener("keydown", function (e) {
      var row = e.target.closest(".evt");
      if (!row) return;
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        selectEvent(row);
        return;
      }
      if (!/^(ArrowDown|ArrowUp|Home|End)$/.test(e.key)) return;
      e.preventDefault();
      var rows = $$(".evt:not(.evt-hidden)", evList); // skip filtered-out rows
      var idx = rows.indexOf(row);
      var target = e.key === "ArrowDown" ? rows[idx + 1]
        : e.key === "ArrowUp" ? rows[idx - 1]
        : e.key === "Home" ? rows[0]
        : rows[rows.length - 1];
      if (target) target.focus();
    });

    // Honor an `?evt=<seq>` deep link (fresh visit, shared link, or a
    // live-refresh re-render restoring the previous selection). Scroll
    // only the first time we land on this session+seq so streaming
    // events don't yank the viewport back mid-read.
    var qm = (location.hash.split("?")[1] || "").match(/(?:^|&)evt=(\d+)/);
    if (qm) {
      var wantSeq = parseInt(qm[1], 10);
      var found = false;
      for (var wi = 0; wi < events.length; wi++) {
        if (events[wi].seq === wantSeq) {
          found = true;
          var wantRow = evList.querySelector('.evt[data-i="' + wi + '"]');
          if (wantRow) {
            selectEvent(wantRow);
            var scrollKey = id + ":" + wantSeq;
            if (_evtScrolledFor !== scrollKey) {
              _evtScrolledFor = scrollKey;
              wantRow.scrollIntoView({ block: "center" });
            }
          }
          break;
        }
      }
      // Deep link to an event beyond the first page: auto-load pages
      // until the target arrives (a shared link to event #600 of a
      // 700-event trail must land selected, not silently unselected).
      // The merge re-render re-runs this matcher; the cursor ending or
      // the 5000-event cap terminates the walk.
      if (!found && data.nextEventCursor != null && events.length < 5000) {
        state.ds.getSessionById(id, { eventCursor: data.nextEventCursor }).then(function (more) {
          // bail if the user navigated away while we fetched
          if (!document.getElementById("eventList")) return;
          renderSessionDetail(main, id, {
            data: Object.assign({}, data, {
              events: (data.events || []).concat(more.events || []),
              nextEventCursor: more.nextEventCursor,
            }),
            receipt: receipt,
          });
        }).catch(function () { /* leave the first page rendered */ });
      }
    }

    // Event triage: kind chips + free-text filter, all client-side.
    // Production trails run hundreds of events — finding the one tool
    // call that mattered shouldn't require scrolling.
    var evtSearch = $("#evtSearch");
    var activeKind = "";
    function applyEvtFilter() {
      var q = ((evtSearch && evtSearch.value) || "").trim().toLowerCase();
      var shown = 0;
      $$(".evt", evList).forEach(function (row) {
        var ev = events[parseInt(row.getAttribute("data-i"), 10)];
        var okKind = !activeKind || ev.kind === activeKind;
        var hay = ((ev.tag || "") + " " + (ev.msg || "") + " " + (ev.sub || "") + " " + ev.kind).toLowerCase();
        var show = okKind && (!q || hay.indexOf(q) >= 0);
        row.classList.toggle("evt-hidden", !show);
        if (show) shown++;
      });
      var count = $("#evtCount");
      if (count) count.textContent = shown === events.length
        ? events.length + " event" + (events.length === 1 ? "" : "s") + (data.nextEventCursor != null ? " (more available)" : "")
        : shown + " of " + events.length + " shown";
      var none = $("#evtNone");
      if (shown === 0 && !none) {
        evList.appendChild(h('<div class="empty-mini" id="evtNone" style="padding:16px">No events match — clear the filter to see all ' + events.length + ".</div>"));
      } else if (shown > 0 && none) none.remove();
    }
    var filterWrap = main.querySelector(".evt-filters");
    if (filterWrap) filterWrap.addEventListener("click", function (e) {
      var chip = e.target.closest(".evt-chip");
      if (!chip) return;
      $$(".evt-chip", filterWrap).forEach(function (c) {
        c.classList.toggle("active", c === chip);
        c.setAttribute("aria-pressed", c === chip ? "true" : "false");
      });
      activeKind = chip.getAttribute("data-kind");
      applyEvtFilter();
    });
    if (evtSearch) evtSearch.addEventListener("input", applyEvtFilter);

    // Story banner "Jump to the block": scroll the BLOCKED row into
    // view and open it in the drawer, so a non-technical visitor gets
    // straight to the moment that matters.
    var jump = main.querySelector("#jumpToBlock");
    if (jump) jump.addEventListener("click", function () {
      var row = evList.querySelector(".evt.err");
      if (!row) return;
      row.scrollIntoView({ block: "center", behavior: "smooth" });
      row.click();
    });

    // Load-more events for long sessions. The server caps at 500 per
    // request and returns nextEventCursor if there are more. Same
    // cursor pattern as the sessions list.
    var loadMoreEv = $("#loadMoreEv");
    if (loadMoreEv && data.nextEventCursor != null) {
      loadMoreEv.addEventListener("click", async function () {
        loadMoreEv.disabled = true;
        loadMoreEv.textContent = "Loading…";
        try {
          var more = await state.ds.getSessionById(id, { eventCursor: data.nextEventCursor });
          // Merge the fresh page into the current data snapshot and
          // re-render *without re-fetching*. Threading data through
          // renderSessionDetail as `initial` preserves the appended
          // events across renders. The previous version called
          // renderSessionDetail without an argument, which re-fetched
          // from scratch and threw away every appended page.
          var merged = Object.assign({}, data, {
            events: (data.events || []).concat(more.events || []),
            nextEventCursor: more.nextEventCursor,
          });
          renderSessionDetail(main, id, { data: merged, receipt: receipt });
        } catch (err) {
          toast(err.message || "Failed to load events", true);
          loadMoreEv.disabled = false;
          loadMoreEv.textContent = "Load more events";
        }
      });
    }

    // Copy receipt button
    // Print evidence pack: the @media print stylesheet strips chrome
    // and forces the light palette, so this is just window.print().
    on("#printPack", "click", function () { window.print(); });

    // Prev/next paging through the browsed list ( [ and ] also work).
    on("#prevSess", "click", function (e) {
      var pid = e.currentTarget.getAttribute("data-id");
      if (pid) navigate("#/sessions/" + pid);
    });
    on("#nextSess", "click", function (e) {
      var nid = e.currentTarget.getAttribute("data-id");
      if (nid) navigate("#/sessions/" + nid);
    });

    on("#copyRcpt", "click", function () {
      copyText(JSON.stringify(receipt, null, 2)).then(function () {
        toast("Receipt copied");
      }, function () {
        toast("Copy failed — use ⬇ Download instead", true);
      });
    });

    // Share receipt: encode the full bundle into a URL fragment and
    // copy the resulting agentvisorai.me/verify/#data=<...> to the
    // clipboard. Recipient opens the link -> auto-verifies in their
    // own browser. Fragment (not query) so the payload never touches
    // any server.
    on("#shareRcpt", "click", function () {
      var bundle = buildReceiptBundle(s, receipt);
      var json = JSON.stringify(bundle);
      // Convert UTF-8 string -> Uint8Array -> base64 -> base64url.
      var bytes = new TextEncoder().encode(json);
      var bin = "";
      for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
      var b64 = btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      var origin = window.VERIFY_BASE || "https://agentvisorai.me";
      var url = origin + "/verify/#data=" + b64;
      // Warn if it's really big. Many chat clients cap URLs around 8k.
      if (url.length > 32000) {
        toast("Receipt too large to share as a URL (" + url.length + " bytes). Use Download instead.", true);
        return;
      }
      copyText(url).then(function () {
        toast("Verify link copied. Recipient's browser will auto-verify it.");
      }, function () {
        // Fallback: show it in a modal so the user can copy manually.
        showTokenModal(url, "Share this verify link");
      });
    });

    // Build the portable verification bundle exactly once. Used by
    // both the Download and Share buttons so the recipient of either
    // gets the same shape as the offline verifier expects.
    function buildReceiptBundle(sess, rcpt) {
      return {
        format: "agentvisor.receipt.v1",
        exportedAt: new Date().toISOString(),
        session: {
          id: sess.id,
          externalId: sess.externalId,
          agent: sess.agent,
          user: sess.user,
          model: sess.model,
          openedAt: sess.openedAt,
          closedAt: sess.closedAt,
          events: sess.events,
          toolsAllowed: sess.toolsAllowed,
          toolsBlocked: sess.toolsBlocked,
        },
        receipt: rcpt,
        publicKey: rcpt && rcpt.publicKeyHex
          ? { algorithm: "ed25519", hex: rcpt.publicKeyHex }
          : null,
        verifyingInstructions: {
          algorithm: "Ed25519",
          message: "receipt.rawBody (UTF-8 bytes)",
          signature: "base64-decode(receipt.rawSignatureB64)",
          publicKey: "hex-decode(publicKey.hex)",
          command: "node server/scripts/verify-receipt.mjs " + (sess.externalId || sess.id) + ".json",
          docs: "https://agentvisorai.me/reference/receipts",
        },
      };
    }

    // Download receipt as a portable verification bundle.
    // The exported JSON is self-contained. Payload + signature +
    // public key + human-readable verification recipe. Anyone with
    // the file (an auditor, an insurer, a court) can verify the
    // signature offline without asking us or the customer for
    // anything else.
    on("#dlRcpt", "click", async function () {
      var bundle = buildReceiptBundle(s, receipt);
      var blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
      var url = URL.createObjectURL(blob);
      var a = document.createElement("a");
      a.href = url;
      a.download = "agentvisor-receipt-" + (s.externalId || s.id) + ".json";
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(function () { URL.revokeObjectURL(url); }, 5000);
      toast("Receipt downloaded. Verify offline with the bundled instructions.");
    });

    // Fire the real Ed25519 verification. When it lands, the "Verifying…"
    // header flips to ✓ verified, ✗ INVALID, or ? not-supported.
    applyReceiptVerification(receipt);
  }

  // Which session:seq we already auto-scrolled to, so live-stream
  // re-renders restore the selection without re-scrolling the page.
  var _evtScrolledFor = null;

  function renderEventDrawer(root, ev, deepLink) {
    // Values are plain-text by default; opt into HTML via a third
    // tuple element only when we control the markup (like the Policy
    // link below). Otherwise ev.tag / ev.policyId would carry any
    // <script>/<img onerror> the daemon put there straight into the
    // DOM. High-signal XSS surface since the daemon is customer code
    // and event tags flow through the console for every viewer of
    // that session.
    var meta = [
      ["Seq", "#" + ev.seq],
      ["Kind", ev.kind + (ev.tag ? " · " + ev.tag : "")],
      ["Time", new Date(ev.ts).toLocaleTimeString()],
      ["Duration", ev.durationMs ? ev.durationMs + " ms" : "—"],
    ];
    if (ev.policyId) meta.push(["Policy", '<a href="#/policies/' + encodeURIComponent(ev.policyId) + '">' + esc(ev.policyId) + "</a>", true]);
    if (ev.blockedValueUsd) meta.push(["Would-have-spent", "$" + Number(ev.blockedValueUsd).toLocaleString()]);
    if (deepLink) meta.push(["Share", '<button type="button" class="btn evt-link-btn" data-copy="' + esc(deepLink) + '" title="Copy a direct link to this event">🔗 Copy link to this event</button>', true]);

    var REDACT_D = "[redacted-member-view]";
    var payload = "";
    if (ev.details) {
      payload = '<pre class="payload">' +
        '<b>Model</b>  ' + esc(ev.details.model) + '\n' +
        '<b>Tokens</b> ' + esc(ev.details.promptTokens) + '\n\n' +
        '<b>Prompt</b>\n' + esc(ev.details.prompt) + '\n\n' +
        '<b>Response</b>\n' + esc(ev.details.response) +
        "</pre>";
    } else if (ev.severity === "err") {
      payload = '<pre class="payload">' + esc(JSON.stringify({
        severity: ev.severity,
        msg: ev.msg === REDACT_D ? "[hidden for member role]" : ev.msg,
        sub: ev.sub === REDACT_D ? "[hidden for member role]" : ev.sub,
        policy: ev.policyId,
      }, null, 2)) + "</pre>";
    } else {
      payload = '<div class="empty-mini">No payload attached.</div>';
    }

    root.innerHTML =
      '<h3>Event detail</h3>' +
      '<dl class="meta">' + meta.map(function (m) {
        // m[2] === true means m[1] is pre-built trusted HTML (e.g.
        // the Policy link we construct above). Everything else is
        // treated as plain text and escaped.
        var valueHtml = m[2] === true ? m[1] : esc(m[1]);
        return "<dt>" + esc(m[0]) + "</dt><dd>" + valueHtml + "</dd>";
      }).join("") + "</dl>" +
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
    // Placeholder verifier state. The real answer arrives after the async
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
    // R117 F1: server redacts receipt.body + sigB64 to
    // '[redacted-member-view]' for member-role callers so the
    // signed JSON's cost.cost_usd_micros doesn't leak. Skip the
    // verifier here — otherwise avVerifyReceipt returns
    // {supported:true, ok:false} on the sentinel and the head
    // flips to "Signature INVALID", which is UX-misleading (the
    // signature isn't invalid, it's simply not visible to
    // members). Show an "unsupported"-styled note instead.
    var REDACT = "[redacted-member-view]";
    if (r && (r.rawBody === REDACT || r.rawSignatureB64 === REDACT)) {
      head.setAttribute("data-verify-state", "unsupported");
      head.classList.add("unsupported");
      var checkR = head.querySelector('.check');
      var titleR = head.querySelector('.title');
      var subR = head.querySelector('div > div:last-child');
      if (checkR) checkR.textContent = "🔒";
      if (titleR) titleR.textContent = "Signature hidden — member view";
      if (subR) subR.textContent = "Ask an admin for signed-receipt access.";
      return;
    }
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
   * DEPLOYMENTS. List + detail + install snippet
   * ============================================================ */

  async function renderDeployments(main) {
    rememberListUrl("deployments");
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
          '<td style="color: var(--fg-2)">' + timeAgoCell(d.lastSeenAt) + "</td>" +
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
          "<thead><tr><th>Deployment</th><th>Environment</th><th>Region</th><th>Status</th><th>Version</th><th>Last seen</th><th class=\"act-2\"><span class=\"sr-only\">Actions</span></th></tr></thead>" +
          "<tbody>" + rows + "</tbody></table></div></div>";
    }
    main.innerHTML = pageHeader("Deployments", "Each daemon streams events and signed receipts to this console.", actions) + body;

    // #addDep / #addDep2 are handled by the delegated listener below —
    // same skeleton-phase fix as #addPol: the header button paints
    // before the async list resolves, and a fast click/tap during load
    // used to hit a button with no listener yet (found by a flaky
    // 390px tap in the mobile-modal probe).

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
        if (textSelActive()) return;
        navigate("#/deployments/" + id);
      });
    }
    restoreScrollFor(location.hash);
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
    main.innerHTML = pageHeader("Deployment", "", '<a href="' + esc(backToListUrl("deployments")) + '" class="btn">← All deployments</a>') + loadingBlock("stats");
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
      pageHeader(d.name, d.environment + " · " + (d.region || ""), '<a href="' + esc(backToListUrl("deployments")) + '" class="btn">← All deployments</a>') +
      '<div class="dep-summary">' +
        depCell("Status", statusPill, false, true) +
        depCell("Version", d.version || "—", true) +
        depCell("Last seen", timeAgoCell(d.lastSeenAt), false, true) +
        depCell("Sessions (24h)", d.sessions24h != null ? d.sessions24h : "—") +
        depCell("Spend (24h)", d.spend24h || "—") +
      "</div>" +
      '<div class="card" style="margin-bottom:12px">' +
        "<h2>Signing key</h2>" +
        '<dl class="kv" style="display:grid;grid-template-columns:140px 1fr;gap:5px 12px;font-size:13px">' +
          '<dt style="color:var(--fg-3)">Fingerprint</dt><dd class="mono">' + copyable(d.keyFingerprint) + "</dd>" +
          '<dt style="color:var(--fg-3)">Public key</dt><dd class="mono" style="word-break:break-all">' + copyable(d.publicKeyHex) + "</dd>" +
          '<dt style="color:var(--fg-3)">Ingest token</dt><dd class="mono">' + copyable(d.ingestTokenHint) + "</dd>" +
        "</dl>" +
        '<div style="margin-top: 12px; display:flex; gap:8px">' +
          '<button class="btn" id="depRotate">Rotate token</button>' +
          '<button class="btn danger" id="depDelete">Delete</button>' +
        "</div>" +
      "</div>" +
      // "Now what?" — the first question after creating a deployment.
      // A copyable env block that points a daemon at this workspace.
      '<div class="card" style="margin-bottom:12px">' +
        "<h2>Connect your daemon</h2>" +
        '<p style="color:var(--fg-2); font-size:var(--t-sec); margin:0 0 10px">Drop these into the daemon\'s environment (or your secret manager) and restart it. It shows up as <b>connected</b> above within a few seconds.</p>' +
        '<pre class="policy-body" style="margin:0 0 10px; user-select:all">' +
          "AV_INGEST_URL=https://ingest.agentvisorai.me/v1\n" +
          "AV_DEPLOYMENT=" + esc(d.id) + "\n" +
          "AV_INGEST_TOKEN=" + esc(d.ingestTokenHint || "av_live_…") + "  # full token shown once at create/rotate" +
        "</pre>" +
        '<button type="button" class="btn" data-copy="AV_INGEST_URL=https://ingest.agentvisorai.me/v1\nAV_DEPLOYMENT=' + esc(d.id) + '\nAV_INGEST_TOKEN=<your-token>">⧉ Copy env block</button>' +
        '<span style="margin-left:10px; color:var(--fg-3); font-size:11.5px">Lost the token? Rotate below — the old one stops working immediately.</span>' +
      "</div>" +
      '<div class="card" style="padding:0">' +
        '<div style="padding:12px 16px; border-bottom: 1px solid var(--border); display:flex; align-items:baseline; gap:8px;">' +
          '<h2 style="margin:0; font-size:var(--t-section); font-weight:600">Recent sessions</h2>' +
          '<span style="color:var(--fg-3); font-size:var(--t-sec)">' + sessions.length + " shown</span>" +
          '<div style="margin-left:auto"><a href="#/sessions?dep=' + encodeURIComponent(d.id) + '" style="font-size:var(--t-sec)">View all →</a></div>' +
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
  function depCell(label, value, mono, trustedHtml) {
    // R112 F4: escape `value` by default. Prior shape spliced
    // `value` raw into innerHTML while `label` was escaped —
    // asymmetric contract that the sibling helpers cell() and
    // stat() already respected. Today's call sites are safe
    // (all raw-string callers pass server-provided '—' or a
    // number toLocaleString'd) but any future migration adding
    // a daemon-supplied string to the deployment detail JSON
    // would land daemon-controlled bytes in innerHTML — the
    // daemon is customer code, so this is one refactor away
    // from stored-XSS-per-viewer. Callers that legitimately
    // pass pre-built HTML (statusPill, timeAgoCell,
    // enabled/disabled pill) opt into the trusted path via
    // the fourth parameter.
    var rendered = trustedHtml ? value : esc(value == null ? "" : String(value));
    return '<div class="cell"><div class="label">' + esc(label) + '</div><div class="value' + (mono ? " mono" : "") + '">' + rendered + "</div></div>";
  }

  function openCreateDeploymentModal() {
    // Guard against a rage-click / double-tap opening N stacked modals.
    if (document.body.classList.contains("locked")) return;
    var backdrop = h(
      '<div class="modal-backdrop" role="dialog" aria-modal="true">' +
        '<div class="modal">' +
          "<h2>New deployment</h2>" +
          '<p class="sub">Register a daemon. You\'ll get an ingest token. Copy it now; it won\'t be shown again.</p>' +
          '<form id="depForm">' +
            '<div class="field"><label for="depName">Name</label><input id="depName" required placeholder="acme-prod" pattern="[a-zA-Z0-9\\-_]+" /></div>' +
            '<div class="field"><label for="depEnv">Environment</label><select id="depEnv"><option>production</option><option>staging</option><option>development</option></select></div>' +
            '<div class="field"><label for="depRegion">Region (optional)</label><input id="depRegion" placeholder="us-east-1" /></div>' +
            '<div class="actions"><button type="button" class="btn" data-close>Cancel</button><button class="btn accent" type="submit">Create</button></div>' +
          "</form>" +
        "</div>" +
      "</div>"
    );
    document.body.appendChild(backdrop);
    document.body.classList.add("locked");
    var previouslyFocused = document.activeElement;
    var uninstall;
    function close() {
      backdrop.remove(); document.body.classList.remove("locked");
      if (uninstall) uninstall();
      if (previouslyFocused && previouslyFocused.focus) try { previouslyFocused.focus(); } catch (e) {}
    }
    uninstall = installModalKeys(backdrop, close);
    backdrop.addEventListener("click", function (e) {
      if (e.target === backdrop || e.target.hasAttribute("data-close")) close();
    });
    backdrop.querySelector("#depForm").addEventListener("submit", function (e) {
      e.preventDefault();
      var btn = e.target.querySelector('button[type="submit"]');
      btn.disabled = true;
      state.ds.createDeployment({ name: $("#depName").value.trim(), environment: $("#depEnv").value, region: $("#depRegion").value.trim() || undefined })
        .then(function (r) { close(); showTokenModal(r.ingestToken, "Deployment created"); })
        .catch(function (err) { btn.disabled = false; toast(err.message || "Create failed", true); });
    });
    setTimeout(function () { backdrop.querySelector('#depName').focus(); }, 20);
  }

  function showTokenModal(token, title) {
    if (document.body.classList.contains("locked")) return;
    var backdrop = h(
      '<div class="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="tokTitle">' +
        '<div class="modal">' +
          '<h2 id="tokTitle">' + esc(title || "Ingest token") + "</h2>" +
          '<p class="sub">Point your daemon at this console using the token below. Store it in your secret manager. It won\'t be shown again.</p>' +
          '<div class="token-display">' + esc(token) + "</div>" +
          '<div class="notice"><svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><path d="M8 1L15 14H1L8 1z"/><path d="M8 6v3M8 11v.5"/></svg>' +
            '<span>This is the only time you\'ll see the full token. If you lose it, rotate to get a new one.</span></div>' +
          '<div class="actions"><button type="button" class="btn" id="copyTok">Copy</button><button type="button" class="btn accent" data-close>Done</button></div>' +
        "</div>" +
      "</div>"
    );
    document.body.appendChild(backdrop);
    document.body.classList.add("locked");
    var previouslyFocused = document.activeElement;
    var uninstall;
    function close() {
      backdrop.remove(); document.body.classList.remove("locked");
      if (uninstall) uninstall();
      if (previouslyFocused && previouslyFocused.focus) try { previouslyFocused.focus(); } catch (e) {}
      // Re-render whatever route the user is actually on. This modal
      // opens from five different contexts (deployment created, token
      // rotated, API key created, share-verify-link); hardcoding one
      // renderer here used to teleport session detail / settings users
      // to the Deployments page on close.
      render();
    }
    uninstall = installModalKeys(backdrop, close);
    backdrop.addEventListener("click", function (e) {
      if (e.target === backdrop || e.target.hasAttribute("data-close")) close();
    });
    var copyBtn = backdrop.querySelector("#copyTok");
    copyBtn.addEventListener("click", function () {
      var doneText = "Copied ✓";
      var origText = copyBtn.textContent;
      function markCopied() {
        copyBtn.textContent = doneText;
        copyBtn.classList.add("ok-flash");
        setTimeout(function () { copyBtn.textContent = origText; copyBtn.classList.remove("ok-flash"); }, 1600);
      }
      copyText(token).then(markCopied, function () {
        toast("Copy blocked. Select the token manually");
      });
    });
    setTimeout(function () { backdrop.querySelector('[data-close]').focus(); }, 20);
  }

  /* ============================================================
   * POLICIES
   * ============================================================ */

  /* ── Policy creation. Template-driven: pick what to protect, tune
   *    one parameter, watch the DSL write itself. ───────────────── */

  var POLICY_TEMPLATES = [
    {
      id: "spend_cap",
      label: "💸 Spend cap",
      hint: "Block any payment above a dollar limit",
      kind: "budget",
      scope: "tool.create_payment",
      param: { label: "Maximum per payment (USD)", type: "number", value: "500", min: 1 },
      build: function (v) {
        var n = Math.max(1, parseInt(v, 10) || 500);
        return {
          name: "finance.payment_cap_usd:" + n,
          description: "Block any single payment above $" + n.toLocaleString() + " USD.",
          body: [
            'policy "finance.payment_cap_usd:' + n + '" {',
            '  applies_to = tool("create_payment")',
            "  when { arg.amount_usd > " + n + " }",
            "  effect = block",
            '  reason = "Payment of {{arg.amount_usd}} USD exceeds the $' + n + ' cap."',
            "}",
          ].join("\n"),
        };
      },
    },
    {
      id: "vendor_allowlist",
      label: "🏷 Vendor allowlist",
      hint: "Only named vendors can receive orders",
      kind: "allowlist",
      scope: "tool.create_purchase_order",
      param: { label: "Allowed vendors (comma-separated)", type: "text", value: "Contoso, Fabrikam" },
      build: function (v) {
        var vendors = String(v || "").split(",").map(function (s) { return s.trim(); }).filter(Boolean);
        if (!vendors.length) vendors = ["Contoso"];
        var list = vendors.map(function (s) { return '"' + s.replace(/["\\]/g, "") + '"'; }).join(", ");
        return {
          name: "procurement.vendors:" + vendors.length,
          description: "Purchase orders may only go to: " + vendors.join(", ") + ".",
          body: [
            'policy "procurement.vendors:' + vendors.length + '" {',
            '  applies_to = tool("create_purchase_order")',
            "  when { arg.vendor not in [" + list + "] }",
            "  effect = block",
            '  reason = "Vendor {{arg.vendor}} is not on the allowlist."',
            "}",
          ].join("\n"),
        };
      },
    },
    {
      id: "pii_guard",
      label: "🔒 PII egress guard",
      hint: "Stop SSNs and card numbers leaving via the LLM",
      kind: "guardrail",
      scope: "llm.egress",
      param: null,
      build: function () {
        return {
          name: "privacy.pii_egress",
          description: "Block LLM responses that contain SSNs or payment card numbers.",
          body: [
            'policy "privacy.pii_egress" {',
            "  applies_to = llm.egress",
            "  when { response matches pii(ssn) or response matches pii(card_number) }",
            "  effect = block",
            '  reason = "Response contains PII ({{match.kind}}) — blocked before egress."',
            "}",
          ].join("\n"),
        };
      },
    },
  ];

  function openCreatePolicyModal() {
    if (document.body.classList.contains("locked")) return;
    var chips = POLICY_TEMPLATES.map(function (t, i) {
      return '<label class="tpl-chip"><input type="radio" name="polTpl" value="' + t.id + '"' + (i === 0 ? " checked" : "") + ' />' +
        '<span class="tpl-body"><span class="tpl-label">' + t.label + '</span><span class="tpl-hint">' + esc(t.hint) + "</span></span></label>";
    }).join("");
    var backdrop = h(
      '<div class="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="polTitle">' +
        '<div class="modal modal-wide">' +
          '<h2 id="polTitle">New policy</h2>' +
          '<p class="sub">Start from a template — the rule writes itself and enforces on the next tool call. You can refine it any time.</p>' +
          '<form id="polForm">' +
            '<div class="tpl-row" role="radiogroup" aria-label="Policy template">' + chips + "</div>" +
            '<div class="field" id="polParamField"></div>' +
            '<div class="field"><label for="polPreview">Definition (generated)</label>' +
              '<pre class="policy-body policy-preview" id="polPreview" tabindex="0" aria-live="polite"></pre></div>' +
            '<div class="actions"><button type="button" class="btn" data-close>Cancel</button><button class="btn accent" type="submit">Create &amp; enable</button></div>' +
          "</form>" +
        "</div>" +
      "</div>"
    );
    document.body.appendChild(backdrop);
    document.body.classList.add("locked");
    var previouslyFocused = document.activeElement;
    var uninstall;
    function close() {
      backdrop.remove(); document.body.classList.remove("locked");
      if (uninstall) uninstall();
      if (previouslyFocused && previouslyFocused.focus) try { previouslyFocused.focus(); } catch (e) {}
    }
    uninstall = installModalKeys(backdrop, close);
    backdrop.addEventListener("click", function (e) {
      if (e.target === backdrop || e.target.hasAttribute("data-close")) close();
    });

    function currentTemplate() {
      var v = backdrop.querySelector('input[name="polTpl"]:checked').value;
      return POLICY_TEMPLATES.find(function (t) { return t.id === v; });
    }
    function paramValue() {
      var inp = backdrop.querySelector("#polParam");
      return inp ? inp.value : null;
    }
    function renderParam(t) {
      var f = backdrop.querySelector("#polParamField");
      if (!t.param) { f.innerHTML = ""; f.style.display = "none"; return; }
      f.style.display = "";
      f.innerHTML = '<label for="polParam">' + esc(t.param.label) + "</label>" +
        '<input id="polParam" type="' + t.param.type + '"' +
        (t.param.min ? ' min="' + t.param.min + '"' : "") +
        ' value="' + esc(t.param.value) + '" required />';
      f.querySelector("#polParam").addEventListener("input", refresh);
    }
    function refresh() {
      var t = currentTemplate();
      var built = t.build(paramValue());
      backdrop.querySelector("#polPreview").innerHTML = syntaxPolicy(built.body);
    }
    $$('input[name="polTpl"]', backdrop).forEach(function (r) {
      r.addEventListener("change", function () { renderParam(currentTemplate()); refresh(); });
    });
    renderParam(currentTemplate());
    refresh();

    backdrop.querySelector("#polForm").addEventListener("submit", function (e) {
      e.preventDefault();
      var btn = e.target.querySelector('button[type="submit"]');
      btn.disabled = true;
      var t = currentTemplate();
      var built = t.build(paramValue());
      state.ds.createPolicy({
        name: built.name, kind: t.kind, scope: t.scope,
        description: built.description, body: built.body,
      }).then(function (p) {
        close();
        toastLink("Policy created and enforcing — the daemon picks it up on its next sync.", "#/policies/" + p.id, "View policy →");
        navigate("#/policies/" + p.id);
      }).catch(function (err) {
        btn.disabled = false;
        toast(err.message || "Create failed", true);
      });
    });
  }

  // Delegated so the button works the instant it's painted — the
  // header (with #addPol) renders before the async policy list
  // resolves, and a fast click during load used to hit a button with
  // no listener yet.
  document.addEventListener("click", function (e) {
    if (e.target.closest("#addPol, #addPolCta")) openCreatePolicyModal();
    if (e.target.closest("#addDep, #addDep2")) openCreateDeploymentModal();
  });

  async function renderPolicies(main) {
    rememberListUrl("policies");
    main.innerHTML = pageHeader("Policies", "Rules the daemon enforces before any tool call or LLM egress.", '<button class="btn accent" id="addPol">+ New policy</button>') + loadingBlock("table");
    var pols;
    try { pols = await state.ds.listPolicies(); } catch (e) { return renderError(main, e); }
    if (!pols.length) {
      main.innerHTML = pageHeader("Policies", "0 policies · none enabled", '<button class="btn accent" id="addPol">+ New policy</button>') +
        emptyState("No policies yet", "Write your first policy to start blocking risky prompts, tool calls, or PII egress. The daemon evaluates policies before any request reaches your model.", "+ Write a policy", null, "addPolCta");
      // #addPol / #addPolCta are handled by the delegated listener above.
      return;
    }
    var rows = pols.map(function (p) {
      var switchCls = p.enabled ? "on" : "";
      return '<tr data-clickable data-id="' + esc(p.id) + '" data-nav="#/policies/" tabindex="0">' +
        '<td class="policy-row"><div class="name">' + esc(p.name) + '</div><div class="kind">' + esc(p.kind) + " · " + esc(p.scope) + "</div></td>" +
        '<td title="' + esc(p.description) + '">' + esc(p.description) + "</td>" +
        '<td class="num tabular">' + esc(p.hits24h) + "</td>" +
        '<td class="num tabular">' + (p.blocks24h > 0 ? '<span style="color: var(--danger-solid); font-weight:500">' + esc(p.blocks24h) + "</span>" : esc(p.blocks24h)) + "</td>" +
        '<td style="color:var(--fg-2)">' + timeAgoCell(p.updatedAt) + "</td>" +
        '<td><button class="switch ' + switchCls + '" data-id="' + esc(p.id) + '" aria-label="Toggle policy ' + esc(p.name) + '" role="switch" aria-checked="' + (p.enabled ? "true" : "false") + '"></button></td>' +
        "</tr>";
    }).join("");
    main.innerHTML = pageHeader("Policies", pols.length + " policies · " + pols.filter(function (p) { return p.enabled; }).length + " enabled", '<button class="btn accent" id="addPol">+ New policy</button>') +
      '<div class="card" style="padding:0"><div class="table-wrap"><table>' +
        "<thead><tr><th>Policy</th><th>Description</th><th class=\"num\">Hits 24h</th><th class=\"num\">Blocks</th><th>Updated</th><th class=\"act-1\"><span class=\"sr-only\">Actions</span></th></tr></thead>" +
        "<tbody>" + rows + "</tbody></table></div></div>";
    var tbody = main.querySelector("tbody");
    tbody.addEventListener("click", function (e) {
      var sw = e.target.closest(".switch");
      if (sw) {
        e.stopPropagation();
        // In-flight guard: rapid clicks queued concurrent toggles whose
        // responses could interleave with the re-render out of order.
        if (sw.getAttribute("aria-busy") === "true") return;
        sw.setAttribute("aria-busy", "true");
        state.ds.togglePolicy(sw.getAttribute("data-id")).then(function () { renderPolicies(main); }, function () { sw.removeAttribute("aria-busy"); });
        return;
      }
      var tr = e.target.closest("tr[data-id]");
      if (tr && !textSelActive()) navigate("#/policies/" + tr.getAttribute("data-id"));
    });
    restoreScrollFor(location.hash);
  }

  async function renderPolicyDetail(main, id) {
    main.innerHTML = pageHeader("Policy", "", '<a href="' + esc(backToListUrl("policies")) + '" class="btn">← All policies</a>') + loadingBlock("stats");
    var p, fired = [];
    try { p = await state.ds.getPolicy(id); } catch (e) { return renderError(main, e); }
    // Close the loop policy → session → receipt: list the sessions
    // this policy actually fired on, so "plain rules" lead straight
    // to the evidence.
    try {
      var resp = await state.ds.listSessions({ limit: 100 });
      fired = (resp.sessions || []).filter(function (s) { return (s.policiesFired || []).indexOf(id) >= 0; });
    } catch (e) { /* the policy page still renders without the list */ }
    var switchCls = p.enabled ? "on" : "";
    // Keep the headline consistent with the evidence below it: when we
    // have the fired-session list, derive the block count from it
    // instead of the fixture's static number.
    var blocks24 = fired.length
      ? fired.reduce(function (a, s) { return a + (s.toolsBlocked || 0); }, 0)
      : p.blocks24h;
    main.innerHTML =
      pageHeader(p.name, p.kind + " · " + p.scope, '<a href="' + esc(backToListUrl("policies")) + '" class="btn">← All policies</a> <button class="switch ' + switchCls + '" id="polSwitch" title="Toggle enabled" aria-label="Toggle policy enabled" role="switch" aria-checked="' + (p.enabled ? "true" : "false") + '"></button>') +
      '<div class="dep-summary">' +
        depCell("Status", p.enabled ? '<span class="pill ok status-dot">enabled</span>' : '<span class="pill neutral">disabled</span>', false, true) +
        depCell("Hits (24h)", p.hits24h.toLocaleString()) +
        depCell("Blocks (24h)", blocks24 > 0 ? '<span style="color: var(--danger-solid)">' + blocks24 + "</span>" : blocks24, false, true) +
        depCell("Updated", timeAgoCell(p.updatedAt), false, true) +
      "</div>" +
      '<div class="card"><h2>Description</h2><p style="margin:0;color:var(--fg-2);font-size:var(--t-body)">' + esc(p.description) + '</p></div>' +
      '<div class="card" style="margin-top:12px"><h2>Definition</h2><pre class="policy-body">' + syntaxPolicy(p.body) + "</pre></div>" +
      (fired.length
        ? '<div class="card" style="margin-top:12px; padding:0">' +
            '<div style="padding:12px 16px; border-bottom: 1px solid var(--border); display:flex; align-items:baseline; gap:8px;">' +
              '<h2 style="margin:0; font-size: var(--t-section); font-weight:600">Sessions this policy fired on</h2>' +
              '<span style="color: var(--fg-3); font-size: var(--t-sec)">' + fired.length + ' in the last 24 h · click one to see the block</span>' +
              '<div style="margin-left:auto"><a href="#/sessions?policy=' + encodeURIComponent(id) + '" style="font-size: var(--t-sec)">View all →</a></div>' +
            "</div>" +
            sessionsTable(fired.slice(0, 8)) +
          "</div>"
        : "");
    on("#polSwitch", "click", function (e) {
      var sw = e.currentTarget;
      if (sw.getAttribute("aria-busy") === "true") return;
      sw.setAttribute("aria-busy", "true");
      state.ds.togglePolicy(id).then(function () { renderPolicyDetail(main, id); }, function () { sw.removeAttribute("aria-busy"); });
    });
  }
  function syntaxPolicy(src) {
    return esc(src)
      .replace(/\b(policy|applies_to|when|effect|reason|transform)\b/g, "<span class='k'>$1</span>")
      .replace(/&quot;[^&]*?&quot;/g, function (m) { return "<span class='s'>" + m + "</span>"; })
      .replace(/\b(\d+(?:\.\d+)?)\b/g, "<span class='n'>$1</span>");
  }

  /* ============================================================
   * SETTINGS. Tabs
   * ============================================================ */

  var SETTINGS_TABS = [
    { id: "general", label: "General" },
    { id: "members", label: "Members" },
    { id: "keys", label: "API keys", ownerAdminOnly: true },
    { id: "sso", label: "SSO" },
    { id: "webhooks", label: "Webhooks", ownerAdminOnly: true },
    { id: "audit", label: "Audit log", ownerAdminOnly: true },
    { id: "billing", label: "Billing" },
  ];

  async function renderSettings(main, tab) {
    state.settingsTab = tab;
    // R90 F3: hide owner/admin-only tabs from members. The API
    // routes gate on membershipRole !== 'member' (see R89 F3
    // for webhooks, R90 F2 for keys); without a client-side
    // filter, members saw the tab, clicked it, and got a
    // "Could not load … — Forbidden" empty state. Now the
    // tab isn't rendered at all, and deep-linking a hidden
    // tab redirects to /general.
    var role = (state.session && state.session.org && state.session.org.role) || "member";
    var visibleTabs = SETTINGS_TABS.filter(function (t) {
      return !t.ownerAdminOnly || role !== "member";
    });
    var visibleIds = visibleTabs.map(function (t) { return t.id; });
    if (visibleIds.indexOf(tab) === -1) {
      return navigate("#/settings/general");
    }
    var nav = visibleTabs.map(function (t) {
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

  async function renderSettingsGeneral(root) {
    root.innerHTML =
      '<div class="card"><h2>Organization</h2>' +
        '<dl class="kv" style="display:grid;grid-template-columns:140px 1fr;gap:5px 12px;font-size:13px">' +
          "<dt style=\"color:var(--fg-3)\">Name</dt><dd>" + esc(state.session.org.name) + "</dd>" +
          "<dt style=\"color:var(--fg-3)\">Org ID</dt><dd class=\"mono\">" + esc(state.session.org.id) + "</dd>" +
          "<dt style=\"color:var(--fg-3)\">Created</dt><dd>" + esc(new Date(state.session.org.createdAt).toLocaleDateString()) + "</dd>" +
        "</dl>" +
      "</div>" +
      '<div class="card" id="retentionCard">' +
        '<h2>Data retention</h2>' +
        '<p style="color: var(--fg-2); font-size: var(--t-sec); margin: 0 0 12px">Sessions, events, receipts, and audit log entries older than the retention window are automatically purged. Set to 0 to keep everything forever.</p>' +
        loadingBlock("table") +
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

    // Retention: load current + render editor
    var card = $("#retentionCard", root);
    if (card && state.ds.getRetention) {
      try {
        var res = await state.ds.getRetention();
        var r = res.retention || { sessionRetentionDays: 90, auditRetentionDays: 365 };
        var editable = state.session.org.role === "owner" || state.session.org.role === "admin";
        card.innerHTML =
          '<h2>Data retention</h2>' +
          '<p style="color: var(--fg-2); font-size: var(--t-sec); margin: 0 0 12px">Sessions, events, receipts, and audit log entries older than the window are automatically purged. Set to 0 to keep everything forever.</p>' +
          '<div style="display:grid;grid-template-columns:200px 1fr;gap:12px 16px;font-size:13px;align-items:center">' +
            '<label for="retSess">Sessions + events</label>' +
            '<div style="display:flex;gap:8px;align-items:center">' +
              '<input id="retSess" type="number" min="0" max="3650" value="' + r.sessionRetentionDays + '" style="width:100px"' + (editable ? '' : ' disabled') + '>' +
              '<span style="color:var(--fg-3)">days</span>' +
            '</div>' +
            '<label for="retAudit">Audit log</label>' +
            '<div style="display:flex;gap:8px;align-items:center">' +
              '<input id="retAudit" type="number" min="0" max="3650" value="' + r.auditRetentionDays + '" style="width:100px"' + (editable ? '' : ' disabled') + '>' +
              '<span style="color:var(--fg-3)">days</span>' +
            '</div>' +
          '</div>' +
          (editable
            ? '<div style="margin-top:16px;display:flex;gap:8px">' +
                '<button class="btn accent" id="retSave">Save</button>' +
                '<button class="btn" id="retSweepNow">Run sweep now</button>' +
              '</div>'
            : '<p style="margin-top:12px;color:var(--fg-3);font-size:12px">Only owners and admins can change retention.</p>');
        if (editable) {
          $("#retSave", card).addEventListener("click", async function (e) {
            var saveBtn = e.currentTarget;
            if (saveBtn.disabled) return;
            var s = parseInt($("#retSess", card).value, 10);
            var a = parseInt($("#retAudit", card).value, 10);
            if (isNaN(s) || isNaN(a) || s < 0 || a < 0) { toast("Invalid values"); return; }
            saveBtn.disabled = true;
            try {
              await state.ds.updateRetention({ sessionRetentionDays: s, auditRetentionDays: a });
              toast("Retention updated.");
            } catch (e2) { toast(e2.message || "Save failed"); }
            saveBtn.disabled = false;
          });
          $("#retSweepNow", card).addEventListener("click", function () {
            confirmModal({
              title: "Run retention sweep now?",
              body: "Rows older than the retention window will be permanently deleted. This runs automatically every 6 hours anyway; use this button only if you need immediate cleanup.",
              confirmLabel: "Sweep now", danger: true,
              onConfirm: async function () {
                try {
                  var res = await state.ds.retentionSweepNow();
                  toast("Purged " + (res.result.sessionsPurged + res.result.auditPurged + res.result.webhookDeliveriesPurged) + " rows.");
                } catch (e) { toast(e.message || "Sweep failed"); }
              },
            });
          });
        }
      } catch (e) {
        card.innerHTML = '<h2>Data retention</h2><p style="color:var(--fg-2);font-size:var(--t-sec)">Could not load (' + esc(e.message || "network") + ').</p>';
      }
    }
  }
  // Wire Escape + Tab focus trap for a modal backdrop. Returns nothing;
  // the caller is expected to append the backdrop first and pass its
  // own close() so the same teardown path runs on Escape and on click.
  function installModalKeys(backdrop, close) {
    function focusables() {
      return Array.from(backdrop.querySelectorAll('button, [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'))
        .filter(function (el) { return el.offsetParent !== null || el.tagName === "INPUT"; });
    }
    function onKey(e) {
      if (e.key === "Escape") { e.preventDefault(); close(); return; }
      if (e.key === "Tab") {
        var els = focusables(); if (!els.length) return;
        var first = els[0], last = els[els.length - 1];
        if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
        else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
      }
    }
    // Close on navigation too. Modals are body-level; a route change
    // re-renders #view underneath them but would otherwise leave the
    // backdrop up, blocking every click on the new page.
    function onNav() { if (close) close(); }
    document.addEventListener("keydown", onKey);
    window.addEventListener("hashchange", onNav);
    return function uninstall() {
      document.removeEventListener("keydown", onKey);
      window.removeEventListener("hashchange", onNav);
    };
  }

  function openInputModal(opts) {
    if (document.body.classList.contains("locked")) return;
    var backdrop = h(
      '<div class="modal-backdrop" role="dialog" aria-modal="true"><div class="modal">' +
        "<h2>" + esc(opts.title) + "</h2>" +
        (opts.sub ? '<p class="sub">' + esc(opts.sub) + "</p>" : "") +
        '<form id="inpForm">' +
          '<div class="field"><label for="inpVal">' + esc(opts.label || "Value") + "</label>" +
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
    var previouslyFocused = document.activeElement;
    var uninstall;
    var handled = false;
    function close() {
      if (handled) return;
      handled = true;
      backdrop.remove(); document.body.classList.remove("locked");
      if (uninstall) uninstall();
      if (previouslyFocused && previouslyFocused.focus) try { previouslyFocused.focus(); } catch (e) {}
    }
    uninstall = installModalKeys(backdrop, close);
    backdrop.addEventListener("click", function (e) {
      if (handled) return;
      if (e.target === backdrop || e.target.hasAttribute("data-close")) close();
    });
    backdrop.querySelector("#inpForm").addEventListener("submit", function (e) {
      e.preventDefault();
      if (handled) return;
      var v = backdrop.querySelector("#inpVal").value.trim();
      if (!v) return;
      var cb = opts.onConfirm;
      close();
      if (cb) cb(v);
    });
    setTimeout(function () { backdrop.querySelector("#inpVal").focus(); }, 20);
  }

  function comingSoon(title, body) {
    if (document.body.classList.contains("locked")) return;
    var backdrop = h(
      '<div class="modal-backdrop" role="dialog" aria-modal="true"><div class="modal">' +
        "<h2>" + esc(title) + "</h2>" +
        '<p class="sub">' + esc(body) + "</p>" +
        '<div class="notice"><svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><circle cx="8" cy="8" r="6"/><path d="M8 5v3M8 11v.5"/></svg><span>This is a demo. Full flow will ship with the beta.</span></div>' +
        '<div class="actions"><button type="button" class="btn primary" data-close>Got it</button></div>' +
      "</div></div>"
    );
    document.body.appendChild(backdrop);
    document.body.classList.add("locked");
    var previouslyFocused = document.activeElement;
    var uninstall;
    function close() {
      backdrop.remove(); document.body.classList.remove("locked");
      if (uninstall) uninstall();
      if (previouslyFocused && previouslyFocused.focus) try { previouslyFocused.focus(); } catch (e) {}
    }
    uninstall = installModalKeys(backdrop, close);
    backdrop.addEventListener("click", function (e) {
      if (e.target === backdrop || e.target.hasAttribute("data-close")) close();
    });
    setTimeout(function () { backdrop.querySelector('[data-close]').focus(); }, 20);
  }

  async function renderSettingsMembers(root) {
    root.innerHTML = '<div class="card">' + loadingBlock("table") + "</div>";
    var members, invitesRes;
    try {
      members = await state.ds.listMembers();
      invitesRes = await state.ds.listInvites();
    } catch (e) {
      root.innerHTML = '<div class="card empty"><h3>Could not load members</h3><p>' + esc(e.message || "") + '</p></div>';
      return;
    }
    var invites = (invitesRes && invitesRes.invites) || [];
    // Members can see who's in the org but not manage anyone — same
    // rule the API enforces, mirrored here so the role preview (and
    // real member accounts) don't show buttons that would only 403.
    var myRole = (state.session.org && state.session.org.role) || "member";
    var canManage = myRole === "owner" || myRole === "admin";

    var memberRows = members.map(function (m) {
      var roles = ["owner", "admin", "member"];
      var selector = canManage
        ? '<select data-role-user="' + esc(m.userId || m.id) + '" aria-label="Role for ' + esc(m.email) + '">' +
            roles.map(function (r) { return '<option' + (m.role === r ? ' selected' : '') + '>' + r + '</option>'; }).join('') +
          '</select>'
        : '<span class="pill neutral">' + esc(m.role) + '</span>';
      return '<tr data-user="' + esc(m.userId || m.id) + '">' +
        '<td><div class="actor"><span class="av">' + esc(initials(m.displayName || m.email)) + '</span><div><div style="font-weight:500">' + esc(m.displayName || m.email) + '</div><div class="id">' + esc(m.email) + '</div></div></div></td>' +
        '<td>' + selector + '</td>' +
        '<td style="color:var(--fg-2)">' + timeAgoCell(m.lastActive) + '</td>' +
        '<td>' + (canManage ? '<button class="btn danger" data-act="remove">Remove</button>' : '') + '</td>' +
      '</tr>';
    }).join("");

    var membersCard =
      '<div class="card" style="padding:0">' +
        '<div style="padding:12px 16px; border-bottom:1px solid var(--border); display:flex; align-items:baseline; gap:8px">' +
          '<h2 style="margin:0; font-size: var(--t-section); font-weight:600">Members</h2>' +
          '<span style="color:var(--fg-3); font-size:var(--t-sec)">' + members.length + " people</span>" +
          (canManage
            ? '<button class="btn" id="previewRoleBtn" style="margin-left:auto" title="See the console exactly as a member does">👁 Preview as member</button>' +
              '<button class="btn accent" id="inviteBtn">+ Invite</button>'
            : '<span style="margin-left:auto; color:var(--fg-3); font-size:var(--t-sec)">Ask an owner or admin to manage members</span>') +
        "</div>" +
        '<div class="table-wrap"><table>' +
          '<thead><tr><th>Person</th><th>Role</th><th>Last active</th><th class="act-1"><span class="sr-only">Actions</span></th></tr></thead>' +
          '<tbody>' + memberRows + '</tbody>' +
        '</table></div>' +
      '</div>';

    var inviteRows = invites.map(function (i) {
      return '<tr data-invite="' + esc(i.id) + '">' +
        '<td><div style="font-weight:500">' + esc(i.email) + '</div><div class="id">by ' + esc(i.invitedByEmail || "?") + '</div></td>' +
        '<td><span class="pill neutral">' + esc(i.role) + "</span></td>" +
        '<td style="color:var(--fg-2)">expires ' + esc(timeUntil(i.expiresAt)) + '</td>' +
        // Revoking an invite is admin-gated on the API — same rule as
        // Remove above; members see the pending list without controls.
        '<td>' + (canManage ? '<button class="btn danger" data-act="revoke">Revoke</button>' : '') + '</td>' +
      '</tr>';
    }).join('');
    var invitesCard = invites.length
      ? ('<div class="card" style="padding:0">' +
          '<div style="padding:12px 16px; border-bottom:1px solid var(--border); display:flex; align-items:baseline">' +
            '<h2 style="margin:0; font-size:var(--t-section); font-weight:600">Pending invites</h2>' +
            '<span style="margin-left:8px; color:var(--fg-3); font-size:var(--t-sec)">' + invites.length + '</span>' +
          '</div>' +
          '<div class="table-wrap"><table>' +
            '<thead><tr><th>Email</th><th>Role</th><th>Expires</th><th class="act-1"><span class="sr-only">Actions</span></th></tr></thead>' +
            '<tbody>' + inviteRows + '</tbody>' +
          '</table></div>' +
        '</div>')
      : '';

    root.innerHTML = membersCard + invitesCard;

    var ib = $("#inviteBtn", root);
    if (ib) ib.addEventListener("click", function () { openInviteModal(root); });
    var pv = $("#previewRoleBtn", root);
    if (pv) pv.addEventListener("click", enterRolePreview);

    // Member row actions. Role change + remove
    var tables = root.querySelectorAll("table");
    tables[0].addEventListener("change", function (e) {
      var sel = e.target.closest("[data-role-user]");
      if (!sel) return;
      var uid = sel.getAttribute("data-role-user");
      state.ds.changeMemberRole(uid, sel.value).then(function () {
        toast("Role updated");
      }).catch(function (err) {
        toast(err.message || "Role change failed", true);
        renderSettingsMembers(root);
      });
    });
    tables[0].addEventListener("click", function (e) {
      var btn = e.target.closest("[data-act='remove']");
      if (!btn) return;
      var tr = e.target.closest("tr[data-user]");
      var uid = tr.getAttribute("data-user");
      confirmModal({
        title: "Remove member?",
        body: "They will lose access immediately. You can invite them again later.",
        confirmLabel: "Remove", danger: true,
        onConfirm: function () {
          state.ds.removeMember(uid).then(function () {
            toast("Member removed");
            renderSettingsMembers(root);
          }).catch(function (err) { toast(err.message || "Remove failed", true); });
        },
      });
    });
    if (tables[1]) tables[1].addEventListener("click", function (e) {
      var btn = e.target.closest("[data-act='revoke']");
      if (!btn) return;
      if (btn.disabled) return;
      btn.disabled = true; // a double-click fired two revokes; the second errored
      var tr = e.target.closest("tr[data-invite]");
      var invId = tr.getAttribute("data-invite");
      var inv = invites.filter(function (x) { return x.id === invId; })[0];
      state.ds.revokeInvite(invId).then(function () {
        renderSettingsMembers(root);
        // Undo instead of a confirm dialog: revoking an invite is
        // low-stakes (nothing is lost but the email link), so don't
        // interrupt — offer the way back for 6 seconds.
        if (inv) toastAction("Invite to " + inv.email + " revoked", "Undo", function () {
          state.ds.inviteMember({ email: inv.email, role: inv.role }).then(function () {
            toast("Invite restored");
            renderSettingsMembers(root);
          }).catch(function (err) { toast(err.message || "Could not restore the invite", true); });
        });
        else toast("Invite revoked");
      }).catch(function (err) { btn.disabled = false; toast(err.message || "Revoke failed", true); });
    });
  }

  function openInviteModal(rootAfterSave) {
    if (document.body.classList.contains("locked")) return;
    var backdrop = h(
      '<div class="modal-backdrop" role="dialog" aria-modal="true"><div class="modal">' +
        '<h2>Invite a teammate</h2>' +
        '<p class="sub">They\'ll get an email with a link to join. Links expire in 7 days.</p>' +
        '<form id="inviteForm">' +
          '<div class="field"><label for="inv_email">Work email</label><input id="inv_email" type="email" required placeholder="teammate@company.com"></div>' +
          '<div class="field"><label for="inv_role">Role</label><select id="inv_role"><option value="member">member</option><option value="admin">admin</option><option value="owner">owner</option></select></div>' +
          '<div class="actions"><button type="button" class="btn" data-close>Cancel</button><button type="submit" class="btn accent">Send invite</button></div>' +
        '</form>' +
      '</div></div>'
    );
    document.body.appendChild(backdrop);
    document.body.classList.add("locked");
    var previouslyFocused = document.activeElement;
    var uninstall;
    var handled = false;
    function close() { if (handled) return; handled = true; backdrop.remove(); document.body.classList.remove("locked"); if (uninstall) uninstall(); if (previouslyFocused && previouslyFocused.focus) try { previouslyFocused.focus(); } catch (e) {} }
    uninstall = installModalKeys(backdrop, close);
    backdrop.addEventListener("click", function (e) {
      if (handled) return;
      if (e.target === backdrop || e.target.hasAttribute("data-close")) close();
    });
    backdrop.querySelector("#inviteForm").addEventListener("submit", function (e) {
      e.preventDefault();
      if (handled) return;
      var email = backdrop.querySelector("#inv_email").value.trim();
      var role = backdrop.querySelector("#inv_role").value;
      var btn = e.target.querySelector('button[type="submit"]');
      btn.disabled = true;
      state.ds.inviteMember({ email: email, role: role }).then(function () {
        close();
        toast("Invite sent to " + email);
        if (rootAfterSave) renderSettingsMembers(rootAfterSave);
      }).catch(function (err) {
        btn.disabled = false;
        var msg = err.message || "Invite failed";
        if (err.errorCode === "already_a_member") msg = "This person is already a member.";
        toast(msg, true);
      });
    });
    setTimeout(function () { backdrop.querySelector("#inv_email").focus(); }, 20);
  }
  async function renderSettingsKeys(root) {
    root.innerHTML = '<div class="card">' + loadingBlock("table") + "</div>";
    var keys = [];
    try { keys = await state.ds.listApiKeys(); }
    catch (e) { root.innerHTML = '<div class="card empty"><h3>Could not load keys</h3><p>' + esc(e.message || "Try again in a moment.") + '</p></div>'; return; }
    function attachCreate(btn) {
      if (!btn) return;
      btn.addEventListener("click", function () {
        openInputModal({
          title: "Create an API key",
          label: "Key name",
          placeholder: "e.g. CI runner",
          confirmLabel: "Create",
          onConfirm: async function (name) {
            if (!name || !name.trim()) return;
            try {
              var res = await state.ds.createApiKey(name.trim());
              showTokenModal(res.plaintextToken, "API key created");
              await renderSettingsKeys(root);
            } catch (e) {
              toast(e && e.message ? e.message : "Could not create key");
            }
          },
        });
      });
    }
    if (!keys.length) {
      root.innerHTML =
        '<div class="card" style="padding:0">' +
          '<div style="padding:12px 16px; border-bottom:1px solid var(--border); display:flex; align-items:baseline">' +
            '<h2 style="margin:0; font-size:var(--t-section); font-weight:600">API keys</h2>' +
            '<span style="margin-left:8px; color:var(--fg-3); font-size:var(--t-sec)">0 active</span>' +
          "</div>" +
          '<div style="padding: 24px 16px">' +
          emptyState("No API keys yet", "Create a server-side key to script deployments, rotate ingest tokens, or wire AgentVisor into CI/CD.", "+ Create key", null, "createKeyBtn") +
          "</div></div>";
      attachCreate($("#createKeyBtn", root));
      return;
    }
    var rows = keys.map(function (k) {
      return '<tr data-id="' + esc(k.id) + '">' +
        '<td><div style="font-weight:500">' + esc(k.name) + '</div><div class="id">' + esc(k.id) + "</div></td>" +
        '<td class="mono">' + esc(k.hint) + "</td>" +
        '<td style="color:var(--fg-2)">' + timeAgoCell(k.lastUsedAt) + "</td>" +
        '<td style="color:var(--fg-2)">' + timeAgoCell(k.createdAt) + "</td>" +
        '<td><button class="btn danger" data-act="revoke">Revoke</button></td>' +
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
          "<thead><tr><th>Name</th><th>Prefix</th><th>Last used</th><th>Created</th><th class=\"act-1\"><span class=\"sr-only\">Actions</span></th></tr></thead>" +
          "<tbody>" + rows + "</tbody>" +
        "</table></div>" +
      "</div>";
    attachCreate($("#createKeyBtn", root));
    $$("tr[data-id] button[data-act='revoke']", root).forEach(function (btn) {
      btn.addEventListener("click", function () {
        var tr = btn.closest("tr");
        var id = tr && tr.getAttribute("data-id");
        if (!id) return;
        confirmModal({
          title: "Revoke this API key?",
          body: "Any script or dashboard using this key will immediately start returning 401. This cannot be undone.",
          confirmLabel: "Revoke",
          danger: true,
          onConfirm: async function () {
            try {
              await state.ds.revokeApiKey(id);
              toast("Key revoked.");
              await renderSettingsKeys(root);
            } catch (e) {
              toast(e && e.message ? e.message : "Could not revoke");
            }
          },
        });
      });
    });
  }
  async function renderSettingsSSO(root) {
    root.innerHTML = '<div class="card">' + loadingBlock("table") + "</div>";
    var res;
    try { res = await state.ds.listSamlConfigs(); }
    catch (e) { root.innerHTML = '<div class="card empty"><h3>Could not load SSO</h3><p>' + esc(e.message || "Try again in a moment.") + '</p></div>'; return; }
    var configs = res.configs || [];

    var oauthCard =
      '<div class="card">' +
        '<h2>Social sign-in (OAuth)</h2>' +
        '<p style="color: var(--fg-2); font-size: var(--t-sec); margin: 0 0 var(--s-4)">Anyone with a Google Workspace or Microsoft Entra account at your domain can sign in. Configured server-side via provider env vars.</p>' +
        '<div style="display:flex; gap:8px; flex-wrap:wrap">' +
          '<span class="pill neutral">' + iconGoogle() + '<span style="margin-left:6px">Google Workspace</span></span>' +
          '<span class="pill neutral">' + iconMicrosoft() + '<span style="margin-left:6px">Microsoft Entra</span></span>' +
        "</div>" +
      "</div>";

    // R90's rule, applied inside the member-visible SSO tab: viewing
    // which IdPs exist is fine, but Add/Edit/Delete hit admin-gated
    // API routes that would 403 — don't render dead controls.
    var canManageSso = ((state.session && state.session.org && state.session.org.role) || "member") !== "member";
    var samlList = configs.length
      ? '<div class="table-wrap"><table>' +
          '<thead><tr><th>Display name</th><th>IdP entity ID</th><th>Domains</th><th>JIT</th><th>Status</th><th class="act-3"><span class="sr-only">Actions</span></th></tr></thead>' +
          '<tbody>' + configs.map(function (c) {
            return '<tr data-id="' + esc(c.id) + '">' +
              '<td><div style="font-weight:500">' + esc(c.displayName) + '</div><div class="id">' + esc((c.spEntityId || '').slice(-40)) + '</div></td>' +
              '<td class="mono" style="font-size:11.5px">' + esc((c.entityIdIdp || '').slice(0, 50)) + (c.entityIdIdp && c.entityIdIdp.length > 50 ? '…' : '') + '</td>' +
              '<td class="mono" style="font-size:11.5px">' + esc(c.allowedDomains || "(any)") + '</td>' +
              '<td>' + (c.jitEnabled ? '<span class="pill ok">on · ' + esc(c.jitDefaultRole) + '</span>' : '<span class="pill neutral">off</span>') + '</td>' +
              '<td>' + (c.isActive ? '<span class="pill ok status-dot">active</span>' : '<span class="pill neutral">disabled</span>') + '</td>' +
              '<td>' +
                '<button class="btn" data-act="details">Details</button>' +
                (canManageSso
                  ? ' <button class="btn" data-act="edit">Edit</button> ' +
                    '<button class="btn danger" data-act="delete">Delete</button>'
                  : '') +
              '</td>' +
            '</tr>';
          }).join('') + '</tbody>' +
        '</table></div>'
      : (canManageSso
          ? emptyState("No SAML IdPs yet", "Wire an Okta / Auth0 / Microsoft Entra / Ping / any SAML 2.0 provider into the workspace.", "+ Add IdP", null, "addSamlBtn")
          : emptyState("No SAML IdPs yet", "Ask an owner or admin to wire your identity provider into the workspace."));

    var samlCard =
      '<div class="card" style="padding:0">' +
        '<div style="padding:12px 16px; border-bottom:1px solid var(--border); display:flex; align-items:baseline">' +
          '<h2 style="margin:0; font-size:var(--t-section); font-weight:600">SAML 2.0 identity providers</h2>' +
          '<span style="margin-left:8px; color:var(--fg-3); font-size:var(--t-sec)">' + configs.length + ' configured</span>' +
          (configs.length && canManageSso ? '<button class="btn accent" id="addSamlBtn" style="margin-left:auto">+ Add IdP</button>' : '') +
        '</div>' +
        '<div style="padding: 20px 16px">' + samlList + '</div>' +
      '</div>';

    // Fetch passkeys inline so the MFA card is populated before render.
    var passkeys = [];
    try { passkeys = (await state.ds.webauthnListCredentials()).credentials || []; }
    catch (e) { passkeys = []; }

    var mfaRows = passkeys.length
      ? '<div class="table-wrap"><table>' +
          '<thead><tr><th>Passkey</th><th>Transport</th><th>Last used</th><th>Registered</th><th class="act-1"><span class="sr-only">Actions</span></th></tr></thead>' +
          '<tbody>' + passkeys.map(function (p) {
            return '<tr data-pk="' + esc(p.id) + '">' +
              '<td><div style="font-weight:500">' + esc(p.label) + '</div><div class="id">' + esc((p.aaguid || 'aaguid unknown').slice(0, 24)) + '</div></td>' +
              '<td>' + (p.transports || []).map(function (t) { return '<span class="pill neutral">' + esc(t) + '</span>'; }).join(' ') + '</td>' +
              '<td style="color: var(--fg-2)">' + (p.lastUsedAt ? timeAgoCell(p.lastUsedAt) : "never") + '</td>' +
              '<td style="color: var(--fg-2)">' + timeAgoCell(p.createdAt) + '</td>' +
              '<td><button class="btn danger" data-pk-act="revoke">Revoke</button></td>' +
            '</tr>';
          }).join('') + '</tbody>' +
        '</table></div>'
      : emptyState("No passkeys yet", "Add a hardware key or platform authenticator (Touch ID, Windows Hello, iCloud) to require a passkey on every sign-in. WebAuthn is phishing-resistant and requires no shared secrets.", "+ Add passkey", null, "addPasskeyBtn");

    var mfaCard =
      '<div class="card" style="padding:0">' +
        '<div style="padding:12px 16px; border-bottom:1px solid var(--border); display:flex; align-items:baseline">' +
          '<h2 style="margin:0; font-size:var(--t-section); font-weight:600">Multi-factor auth (passkeys)</h2>' +
          '<span style="margin-left:8px; color:var(--fg-3); font-size:var(--t-sec)">' + passkeys.length + ' registered</span>' +
          (passkeys.length ? '<button class="btn accent" id="addPasskeyBtn" style="margin-left:auto">+ Add passkey</button>' : '') +
        '</div>' +
        '<div style="padding: 20px 16px">' + mfaRows + '</div>' +
      '</div>';

    root.innerHTML = oauthCard + samlCard + mfaCard;

    var addBtn = $("#addSamlBtn", root);
    if (addBtn) addBtn.addEventListener("click", function () { openSamlEditor(root, null); });
    var addPk = $("#addPasskeyBtn", root);
    if (addPk) addPk.addEventListener("click", function () { addPasskey(root); });

    // Passkey row actions
    var pkTbody = $$("main .table-wrap tbody", root)[1] || null; // sometimes there are two tables. SSO + MFA
    var pkTables = root.querySelectorAll("table");
    for (var pi = 0; pi < pkTables.length; pi++) {
      pkTables[pi].addEventListener("click", function (e) {
        var btn = e.target.closest("[data-pk-act]");
        if (!btn) return;
        var tr = e.target.closest("tr[data-pk]");
        if (!tr) return;
        var pkId = tr.getAttribute("data-pk");
        confirmModal({
          title: "Revoke passkey?",
          // R125 F1: R124 F1 turned DELETE /credentials/:id into a
          // session-wide fence (sessionRevokedAt bumped + all
          // av_srv_ tokens the user created revoked). The prior
          // body copy neglected both side-effects. Warn the user
          // explicitly so a legitimate rotation ("swap yubikeys")
          // isn't a surprise CI-tokens-broken incident.
          body: "This passkey will stop working immediately. You'll be signed out on every device, and any API keys you created will be revoked. You'll need to sign in with your password, register a new passkey, and re-issue automation tokens.",
          confirmLabel: "Revoke",
          danger: true,
          onConfirm: function () {
            state.ds.webauthnRevoke(pkId).then(function () {
              // R125 F1: skip renderSettingsSSO(root) — the next
              // fetch is guaranteed to 401 (cookie iat now < new
              // sessionRevokedAt) which fires the generic
              // "session expired" toast on top of "Passkey
              // revoked" and boots the user to /#/login anyway.
              // Do a purposeful sign-out matching signOut() at
              // app.js:690-710 so the UX is one deliberate flow,
              // not two stacked toasts.
              stopLiveStream();
              rolePreview = null;
              state.session = null;
              try { localStorage.setItem("av_signed_out_at", String(Date.now())); } catch (e) {}
              toast("Passkey revoked. Sign in again to continue.");
              navigate("#/login");
            }).catch(function (err) { toast(err.message || "Revoke failed", true); });
          },
        });
      });
    }

    var tbody = root.querySelector("tbody");
    if (tbody) tbody.addEventListener("click", function (e) {
      var tr = e.target.closest("tr[data-id]");
      if (!tr) return;
      var id = tr.getAttribute("data-id");
      var cfg = configs.find(function (c) { return c.id === id; });
      var act = (e.target.closest("[data-act]") || {}).getAttribute && (e.target.closest("[data-act]")).getAttribute("data-act");
      if (!act || !cfg) return;
      e.stopPropagation();
      if (act === "details") openSamlDetails(cfg);
      else if (act === "edit") openSamlEditor(root, cfg);
      else if (act === "delete") {
        confirmModal({
          title: "Delete SSO config?",
          body: "The '" + cfg.displayName + "' IdP will be removed. Members signed in via it will need to re-authenticate.",
          confirmLabel: "Delete", danger: true,
          onConfirm: function () {
            state.ds.deleteSamlConfig(cfg.id).then(function () {
              toast("SSO config deleted");
              renderSettingsSSO(root);
            }).catch(function (err) { toast(err.message || "Delete failed", true); });
          },
        });
      }
    });
  }

  // ---------- SAML details drawer ----------

  function openSamlDetails(cfg) {
    if (document.body.classList.contains("locked")) return;
    var backdrop = h(
      '<div class="modal-backdrop" role="dialog" aria-modal="true">' +
        '<div class="modal" style="max-width: 640px">' +
          '<h2>' + esc(cfg.displayName) + '</h2>' +
          '<p class="sub">Give these values to your IdP administrator.</p>' +
          '<dl class="kv" style="grid-template-columns: 200px 1fr; gap: 8px 14px;">' +
            '<dt>SP Entity ID</dt><dd class="mono" style="font-size:11.5px; word-break:break-all;">' + esc(cfg.spEntityId) + '</dd>' +
            '<dt>ACS (Reply) URL</dt><dd class="mono" style="font-size:11.5px; word-break:break-all;">' + esc(cfg.spAcsUrl) + '</dd>' +
            '<dt>SLO URL</dt><dd class="mono" style="font-size:11.5px; word-break:break-all;">' + esc(cfg.spSloUrl) + '</dd>' +
            '<dt>Metadata URL</dt><dd class="mono" style="font-size:11.5px; word-break:break-all;"><a href="' + esc(cfg.spMetadataUrl) + '" target="_blank">' + esc(cfg.spMetadataUrl) + '</a></dd>' +
            '<dt>IdP cert fingerprint</dt><dd class="mono" style="font-size:11.5px; word-break:break-all;">' + esc(cfg.x509CertFingerprint || "(not parsed)") + '</dd>' +
            '<dt>SP signing keypair</dt><dd>' + (cfg.hasSpKeypair ? '<span class="pill ok">present</span>' : '<span class="pill neutral">none. Using unsigned AuthnRequests</span>') + '</dd>' +
            '<dt>NameID format</dt><dd class="mono" style="font-size:11.5px">' + esc(cfg.nameIdFormat) + '</dd>' +
            '<dt>JIT provisioning</dt><dd>' + (cfg.jitEnabled ? 'enabled · default role = ' + esc(cfg.jitDefaultRole) : 'disabled') + '</dd>' +
            '<dt>Allowed domains</dt><dd class="mono" style="font-size:11.5px">' + esc(cfg.allowedDomains || "(any)") + '</dd>' +
          '</dl>' +
          '<div class="actions">' +
            // Regenerating the SP keypair is an admin mutation (would
            // 403 for members) — same rule as the list's Edit/Delete.
            (((state.session && state.session.org && state.session.org.role) || "member") !== "member"
              ? '<button class="btn" data-act="regen">Regenerate SP keypair</button>'
              : '') +
            '<button class="btn accent" data-close>Done</button>' +
          '</div>' +
        '</div>' +
      '</div>'
    );
    document.body.appendChild(backdrop);
    document.body.classList.add("locked");
    var previouslyFocused = document.activeElement;
    var uninstall;
    function close() { backdrop.remove(); document.body.classList.remove("locked"); if (uninstall) uninstall(); if (previouslyFocused && previouslyFocused.focus) try { previouslyFocused.focus(); } catch (e) {} }
    uninstall = installModalKeys(backdrop, close);
    backdrop.addEventListener("click", function (e) {
      if (e.target === backdrop || e.target.hasAttribute("data-close")) return close();
      var act = e.target.closest("[data-act]");
      if (act && act.getAttribute("data-act") === "regen") {
        // Rotating the SP keypair invalidates the cert the IdP has on
        // file — SSO breaks until the IdP side is updated. confirmModal
        // can't stack on this modal (body is locked), so use an inline
        // arm-then-confirm: first click arms, second fires, 5s revert.
        if (act.getAttribute("data-armed") !== "1") {
          act.setAttribute("data-armed", "1");
          act.classList.add("danger");
          act.textContent = "Click again to confirm — SSO breaks until the IdP is updated";
          setTimeout(function () {
            if (!act.isConnected || act.disabled) return;
            act.removeAttribute("data-armed");
            act.classList.remove("danger");
            act.textContent = "Regenerate SP keypair";
          }, 5000);
          return;
        }
        act.disabled = true;
        state.ds.regenerateSamlSpKeypair(cfg.id).then(function (r) {
          toast("SP keypair regenerated");
          // Close this modal BEFORE showing the cert: showTokenModal
          // no-ops while body is locked, so the new SP cert was
          // silently never displayed (pre-existing bug).
          close();
          showTokenModal(r.spCertPem, "New SP certificate");
        }).catch(function (err) { toast(err.message || "Regenerate failed", true); act.disabled = false; });
      }
    });
    setTimeout(function () { backdrop.querySelector('[data-close]').focus(); }, 20);
  }

  // ---------- WebAuthn / passkey ----------

  // base64url <-> ArrayBuffer helpers. WebAuthn API returns ArrayBuffers
  // for the challenge, credentialId, and signature; we send them to the
  // server as base64url strings.
  function b64uToBuffer(s) {
    var pad = 4 - (s.length % 4);
    var b64 = s.replace(/-/g, "+").replace(/_/g, "/") + (pad === 4 ? "" : new Array(pad + 1).join("="));
    var bin = atob(b64);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }
  function bufferToB64u(buf) {
    var bytes = new Uint8Array(buf);
    var bin = "";
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  async function addPasskey(rootAfterAdd) {
    if (!window.PublicKeyCredential) {
      toast("This browser doesn't support WebAuthn.", true);
      return;
    }
    // Ask for a label first
    openInputModal({
      title: "Add a passkey",
      label: "Name this passkey",
      placeholder: "iPhone 15 Pro, YubiKey 5C, laptop, …",
      confirmLabel: "Continue",
      onConfirm: async function (label) {
        try {
          var opts = (await state.ds.webauthnRegisterStart()).options;
          // Convert challenge + user.id + excludeCredentials[].id to ArrayBuffer.
          opts.challenge = b64uToBuffer(opts.challenge);
          opts.user.id = b64uToBuffer(opts.user.id);
          if (opts.excludeCredentials) {
            opts.excludeCredentials = opts.excludeCredentials.map(function (c) {
              return Object.assign({}, c, { id: b64uToBuffer(c.id) });
            });
          }
          var cred = await navigator.credentials.create({ publicKey: opts });
          if (!cred) throw new Error("no_credential_returned");
          var response = {
            id: cred.id,
            rawId: bufferToB64u(cred.rawId),
            type: cred.type,
            response: {
              attestationObject: bufferToB64u(cred.response.attestationObject),
              clientDataJSON: bufferToB64u(cred.response.clientDataJSON),
              transports: cred.response.getTransports ? cred.response.getTransports() : [],
            },
            clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
            authenticatorAttachment: cred.authenticatorAttachment || null,
          };
          await state.ds.webauthnRegisterFinish(response, label);
          toast("Passkey added");
          if (rootAfterAdd) renderSettingsSSO(rootAfterAdd);
        } catch (err) {
          toast(err.message || "Passkey registration failed", true);
        }
      },
    });
  }

  async function runPasskeyLogin(email) {
    if (!window.PublicKeyCredential) {
      throw new Error("browser_no_webauthn");
    }
    var start = await state.ds.webauthnAuthStart(email);
    if (!start.hasCredential) throw new Error("no_credential_for_email");
    var opts = start.options;
    opts.challenge = b64uToBuffer(opts.challenge);
    if (opts.allowCredentials) {
      opts.allowCredentials = opts.allowCredentials.map(function (c) {
        return Object.assign({}, c, { id: b64uToBuffer(c.id) });
      });
    }
    var cred = await navigator.credentials.get({ publicKey: opts });
    if (!cred) throw new Error("no_credential_returned");
    var response = {
      id: cred.id,
      rawId: bufferToB64u(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bufferToB64u(cred.response.clientDataJSON),
        authenticatorData: bufferToB64u(cred.response.authenticatorData),
        signature: bufferToB64u(cred.response.signature),
        userHandle: cred.response.userHandle ? bufferToB64u(cred.response.userHandle) : null,
      },
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
      authenticatorAttachment: cred.authenticatorAttachment || null,
    };
    return state.ds.webauthnAuthFinish(response);
  }


  // ---------- SAML editor ----------

  function openSamlEditor(rootAfterSave, existing) {
    if (document.body.classList.contains("locked")) return;
    var c = existing || {
      displayName: "", ssoUrl: "", sloUrl: "", entityIdIdp: "", x509Cert: "",
      wantAssertionsSigned: true, wantResponseSigned: false, allowEncryptedAssertions: true,
      signatureAlgorithm: "sha256", digestAlgorithm: "sha256",
      nameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
      jitEnabled: true, jitDefaultRole: "member", allowedDomains: "",
    };
    var backdrop = h(
      '<div class="modal-backdrop" role="dialog" aria-modal="true">' +
        '<div class="modal" style="max-width:680px">' +
          '<h2>' + (existing ? 'Edit SAML IdP' : 'New SAML IdP') + '</h2>' +
          '<p class="sub">Paste values from your Okta / Auth0 / Entra / SAML IdP admin console.</p>' +
          '<form id="samlForm">' +
            '<div class="field"><label for="s_name">Display name</label><input id="s_name" required maxlength="80" placeholder="Okta production" value="' + esc(c.displayName) + '"></div>' +
            '<div class="field"><label for="s_ssoUrl">IdP SSO URL</label><input id="s_ssoUrl" required type="url" placeholder="https://acme.okta.com/app/agentvisor/sso/saml" value="' + esc(c.ssoUrl) + '"></div>' +
            '<div class="field"><label for="s_sloUrl">IdP SLO URL (optional)</label><input id="s_sloUrl" type="url" placeholder="https://acme.okta.com/app/agentvisor/slo/saml" value="' + esc(c.sloUrl || "") + '"></div>' +
            '<div class="field"><label for="s_entityIdIdp">IdP Entity ID</label><input id="s_entityIdIdp" required placeholder="http://www.okta.com/exkABCDE" value="' + esc(c.entityIdIdp) + '"></div>' +
            '<div class="field"><label for="s_x509">IdP X.509 Certificate (PEM)</label><textarea id="s_x509" required rows="6" style="font-family: SF Mono, ui-monospace, monospace; font-size:11.5px" placeholder="-----BEGIN CERTIFICATE-----&#10;MIIDpDCC...&#10;-----END CERTIFICATE-----">' + esc(c.x509Cert) + '</textarea></div>' +
            '<div style="display:grid; grid-template-columns:1fr 1fr; gap:12px">' +
              '<div class="field"><label for="s_nameIdFormat">NameID format</label><select id="s_nameIdFormat">' +
                ["emailAddress","persistent","transient","unspecified"].map(function (n) {
                  var v = "urn:oasis:names:tc:SAML:" + (n === "unspecified" ? "1.1:nameid-format:" : (n === "persistent" || n === "transient" ? "2.0:nameid-format:" : "1.1:nameid-format:")) + n;
                  return '<option value="' + esc(v) + '"' + (c.nameIdFormat === v ? ' selected' : '') + '>' + esc(n) + '</option>';
                }).join('') +
              '</select></div>' +
              '<div class="field"><label for="s_sig">Signature algorithm</label><select id="s_sig">' +
                ["sha256","sha512","sha1"].map(function (a) { return '<option' + (c.signatureAlgorithm === a ? ' selected' : '') + '>' + a + '</option>'; }).join('') +
              '</select></div>' +
            '</div>' +
            '<div class="field"><label class="toggle"><input type="checkbox" id="s_wantAssertionsSigned"' + (c.wantAssertionsSigned ? ' checked' : '') + '> Require signed assertions</label></div>' +
            '<div class="field"><label class="toggle"><input type="checkbox" id="s_wantResponseSigned"' + (c.wantResponseSigned ? ' checked' : '') + '> Require signed response envelope</label></div>' +
            '<div class="field"><label class="toggle"><input type="checkbox" id="s_allowEncrypted"' + (c.allowEncryptedAssertions ? ' checked' : '') + '> Accept encrypted assertions</label></div>' +
            '<hr style="border:0; border-top:1px solid var(--border); margin:12px 0">' +
            '<div class="field"><label class="toggle"><input type="checkbox" id="s_jit"' + (c.jitEnabled ? ' checked' : '') + '> Just-in-time provisioning</label></div>' +
            '<div style="display:grid; grid-template-columns:1fr 1fr; gap:12px">' +
              '<div class="field"><label for="s_jitRole">Default role for new users</label><select id="s_jitRole">' +
                ["member","admin"].map(function (r) { return '<option' + (c.jitDefaultRole === r ? ' selected' : '') + '>' + r + '</option>'; }).join('') +
              '</select></div>' +
              '<div class="field"><label for="s_domains">Allowed email domains (comma-separated)</label><input id="s_domains" placeholder="acme.com,acme.co.uk" value="' + esc(c.allowedDomains) + '"></div>' +
            '</div>' +
            '<div class="actions"><button type="button" class="btn" data-close>Cancel</button><button type="submit" class="btn accent">' + (existing ? 'Save' : 'Create') + '</button></div>' +
          '</form>' +
        '</div>' +
      '</div>'
    );
    document.body.appendChild(backdrop);
    document.body.classList.add("locked");
    var previouslyFocused = document.activeElement;
    var uninstall;
    var handled = false;
    function close() { if (handled) return; handled = true; backdrop.remove(); document.body.classList.remove("locked"); if (uninstall) uninstall(); if (previouslyFocused && previouslyFocused.focus) try { previouslyFocused.focus(); } catch (e) {} }
    uninstall = installModalKeys(backdrop, close);
    backdrop.addEventListener("click", function (e) {
      if (handled) return;
      if (e.target === backdrop || e.target.hasAttribute("data-close")) close();
    });
    backdrop.querySelector("#samlForm").addEventListener("submit", function (e) {
      e.preventDefault();
      if (handled) return;
      var input = {
        displayName: backdrop.querySelector("#s_name").value.trim(),
        ssoUrl: backdrop.querySelector("#s_ssoUrl").value.trim(),
        sloUrl: backdrop.querySelector("#s_sloUrl").value.trim() || null,
        entityIdIdp: backdrop.querySelector("#s_entityIdIdp").value.trim(),
        x509Cert: backdrop.querySelector("#s_x509").value.trim(),
        wantAssertionsSigned: backdrop.querySelector("#s_wantAssertionsSigned").checked,
        wantResponseSigned: backdrop.querySelector("#s_wantResponseSigned").checked,
        allowEncryptedAssertions: backdrop.querySelector("#s_allowEncrypted").checked,
        signatureAlgorithm: backdrop.querySelector("#s_sig").value,
        digestAlgorithm: backdrop.querySelector("#s_sig").value,
        nameIdFormat: backdrop.querySelector("#s_nameIdFormat").value,
        jitEnabled: backdrop.querySelector("#s_jit").checked,
        jitDefaultRole: backdrop.querySelector("#s_jitRole").value,
        allowedDomains: backdrop.querySelector("#s_domains").value.trim(),
      };
      var btn = e.target.querySelector('button[type="submit"]');
      btn.disabled = true;
      var promise = existing
        ? state.ds.updateSamlConfig(existing.id, input)
        : state.ds.createSamlConfig(input);
      promise.then(function () {
        close();
        toast(existing ? "SSO config saved" : "SSO config created");
        renderSettingsSSO(rootAfterSave);
      }).catch(function (err) {
        btn.disabled = false;
        var msg = err.message || "Save failed";
        if ((err.errorCode || err.detail) === "displayname_in_use") msg = "Another IdP already uses that display name.";
        toast(msg, true);
      });
    });
    setTimeout(function () { backdrop.querySelector("#s_name").focus(); }, 20);
  }
  async function renderSettingsWebhooks(root) {
    root.innerHTML = '<div class="card">' + loadingBlock("table") + "</div>";
    var endpoints;
    try { endpoints = await state.ds.listWebhooks(); }
    catch (e) { root.innerHTML = '<div class="card empty"><h3>Could not load webhooks</h3><p>' + esc(e.message || "Try again in a moment.") + '</p></div>'; return; }

    function openAddModal() {
      if (document.body.classList.contains("locked")) return;
      var events = ["policy.block", "member.invited", "apikey.created", "apikey.revoked", "webhook.test_fired", "*"];
      var backdrop = h(
        '<div class="modal-backdrop" role="dialog" aria-modal="true">' +
          '<div class="modal">' +
            '<h2>Add webhook</h2>' +
            '<p class="sub">Forward events to Slack, PagerDuty, Datadog, or your own endpoint. Payloads are signed with HMAC-SHA256.</p>' +
            '<label style="display:block;margin-top:12px"><span style="display:block;font-size:12px;color:var(--fg-2);margin-bottom:4px">Name</span>' +
              '<input type="text" id="whName" placeholder="e.g. Slack #ops" style="width:100%">' +
            '</label>' +
            '<label style="display:block;margin-top:12px"><span style="display:block;font-size:12px;color:var(--fg-2);margin-bottom:4px">URL</span>' +
              '<input type="url" id="whUrl" placeholder="https://hooks.slack.com/services/…" style="width:100%">' +
            '</label>' +
            '<div style="margin-top:12px"><div style="font-size:12px;color:var(--fg-2);margin-bottom:4px">Events</div>' +
              '<div style="display:flex;flex-wrap:wrap;gap:6px" id="whEventsPicker">' +
                events.map(function (ev) {
                  // policy.block pre-checked: it's why people add a
                  // webhook, and an all-unchecked picker made the only
                  // path to success a validation error.
                  var checked = ev === "policy.block" ? " checked" : "";
                  return '<label class="pill neutral" style="cursor:pointer;user-select:none"><input type="checkbox" value="' + esc(ev) + '"' + checked + ' style="margin-right:6px">' + esc(ev) + '</label>';
                }).join("") +
              '</div>' +
            '</div>' +
            '<div class="actions">' +
              '<button type="button" class="btn" data-close>Cancel</button>' +
              '<button type="button" class="btn primary" id="whSave">Create endpoint</button>' +
            '</div>' +
          '</div>' +
        '</div>',
      );
      document.body.appendChild(backdrop);
      document.body.classList.add("locked");
      var previouslyFocused = document.activeElement;
      // The standard modal contract: a real close() that also
      // uninstalls the document-level key handler. This modal used to
      // call installModalKeys(backdrop) with NO close callback —
      // Escape inside it threw ("close is not a function"), and the
      // leaked keydown listener made every later Escape anywhere in
      // the app throw too.
      var uninstallWh;
      function closeWh() {
        backdrop.remove();
        document.body.classList.remove("locked");
        if (uninstallWh) uninstallWh();
        if (previouslyFocused && previouslyFocused.focus) try { previouslyFocused.focus(); } catch (e2) {}
      }
      uninstallWh = installModalKeys(backdrop, closeWh);
      backdrop.querySelectorAll("[data-close]").forEach(function (b) { b.addEventListener("click", closeWh); });
      backdrop.addEventListener("click", function (e) { if (e.target === backdrop) closeWh(); });
      on($("#whSave", backdrop), "click", async function (e) {
        var saveBtn = e.currentTarget;
        if (saveBtn.disabled) return;
        var name = $("#whName", backdrop).value.trim();
        var url = $("#whUrl", backdrop).value.trim();
        var events = Array.from(backdrop.querySelectorAll("#whEventsPicker input:checked")).map(function (i) { return i.value; });
        if (!name || !url) { toast("Name and URL are required"); return; }
        if (!events.length) { toast("Pick at least one event"); return; }
        // Disable while in flight: a double-click here used to create
        // two identical endpoints (each with its own secret).
        saveBtn.disabled = true;
        try {
          var res = await state.ds.createWebhook({ name: name, url: url, events: events });
          closeWh();
          showTokenModal(res.secret, "Webhook secret");
          await renderSettingsWebhooks(root);
        } catch (e2) {
          saveBtn.disabled = false;
          toast(e2 && e2.message ? e2.message : "Could not create webhook");
        }
      });
    }

    if (!endpoints.length) {
      root.innerHTML =
        '<div class="card" style="padding:0">' +
          '<div style="padding:12px 16px; border-bottom:1px solid var(--border); display:flex; align-items:baseline">' +
            '<h2 style="margin:0; font-size:var(--t-section); font-weight:600">Webhooks</h2>' +
            '<span style="margin-left:8px; color:var(--fg-3); font-size:var(--t-sec)">0 endpoints</span>' +
          "</div>" +
          '<div style="padding: 24px 16px">' +
          emptyState("No webhooks yet", "Wire AgentVisor to Slack / PagerDuty / Datadog / your own service. Payloads are HMAC-SHA256 signed.", "+ Add webhook", null, "whAdd") +
          "</div></div>";
      on($("#whAdd", root), "click", openAddModal);
      return;
    }

    var rows = endpoints.map(function (e) {
      return '<tr data-id="' + esc(e.id) + '" tabindex="0" title="Click for recent deliveries">' +
        '<td><div style="font-weight:500">' + esc(e.name) + '</div><div class="id">' + esc(e.id) + ' · click for deliveries</div></td>' +
        '<td class="mono" style="font-size:11.5px;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + esc(e.url) + '">' + esc(e.url) + '</td>' +
        '<td style="font-size:12px">' + (e.events || []).map(function (ev) { return '<span class="pill neutral" style="margin-right:4px">' + esc(ev) + '</span>'; }).join("") + '</td>' +
        '<td>' + (e.isActive ? '<span class="pill ok status-dot">active</span>' : '<span class="pill neutral">paused</span>') + '</td>' +
        '<td>' +
          '<button class="btn" data-act="test">Send test</button> ' +
          '<button class="btn" data-act="toggle">' + (e.isActive ? "Pause" : "Resume") + '</button> ' +
          '<button class="btn" data-act="rotate">Rotate secret</button> ' +
          '<button class="btn danger" data-act="delete">Delete</button>' +
        '</td>' +
      '</tr>';
    }).join("");

    root.innerHTML =
      '<div class="card" style="padding:0">' +
        '<div style="padding:12px 16px; border-bottom:1px solid var(--border); display:flex; align-items:baseline">' +
          '<h2 style="margin:0; font-size:var(--t-section); font-weight:600">Webhooks</h2>' +
          '<span style="margin-left:8px; color:var(--fg-3); font-size:var(--t-sec)">' + endpoints.length + " endpoint" + (endpoints.length === 1 ? "" : "s") + "</span>" +
          '<button class="btn accent" id="whAdd" style="margin-left:auto">+ Add webhook</button>' +
        "</div>" +
        '<div class="table-wrap"><table>' +
          "<thead><tr><th>Name</th><th>URL</th><th>Events</th><th>Status</th><th class=\"act-4\"><span class=\"sr-only\">Actions</span></th></tr></thead>" +
          "<tbody>" + rows + "</tbody>" +
        "</table></div>" +
      "</div>";

    on($("#whAdd", root), "click", openAddModal);

    // Recent deliveries per endpoint (Stripe/GitHub-style): click the
    // row (not its action buttons) for status, attempts, HTTP code,
    // and latency of the last events. Keyboard: Enter/Space on a row.
    async function openDeliveriesModal(id) {
      if (document.body.classList.contains("locked")) return;
      var ep = endpoints.find(function (x) { return x.id === id; });
      var backdrop = h(
        '<div class="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="whdTitle">' +
          '<div class="modal" style="max-width:640px">' +
            '<h2 id="whdTitle">Recent deliveries · ' + esc(ep ? ep.name : id) + '</h2>' +
            '<div id="whdBody">' + loadingBlock("table") + '</div>' +
            '<div class="actions"><button type="button" class="btn accent" data-close>Done</button></div>' +
          '</div>' +
        '</div>'
      );
      document.body.appendChild(backdrop);
      document.body.classList.add("locked");
      var previouslyFocused = document.activeElement;
      var uninstall;
      function close() {
        backdrop.remove(); document.body.classList.remove("locked");
        if (uninstall) uninstall();
        if (previouslyFocused && previouslyFocused.focus) try { previouslyFocused.focus(); } catch (e2) {}
      }
      uninstall = installModalKeys(backdrop, close);
      backdrop.addEventListener("click", function (e) {
        if (e.target === backdrop || e.target.hasAttribute("data-close")) close();
      });
      setTimeout(function () { var c = backdrop.querySelector("[data-close]"); if (c) c.focus(); }, 20);
      var list = [];
      try { list = await state.ds.listWebhookDeliveries(id); }
      catch (err) {
        var bodyEl = backdrop.querySelector("#whdBody");
        if (bodyEl) bodyEl.innerHTML = '<p class="sub">Could not load deliveries (' + esc(err.message || "network") + ').</p>';
        return;
      }
      var bodyEl2 = backdrop.querySelector("#whdBody");
      if (!bodyEl2) return; // closed while loading
      bodyEl2.innerHTML = list.length
        ? '<div class="table-wrap"><table>' +
            '<thead><tr><th>Event</th><th>Status</th><th class="num">Attempts</th><th class="num">HTTP</th><th class="num">Latency</th><th>When</th></tr></thead>' +
            '<tbody>' + list.map(function (d) {
              var ms = d.deliveredAt ? (new Date(d.deliveredAt) - new Date(d.createdAt)) : null;
              return '<tr>' +
                '<td class="mono" style="font-size:11.5px">' + esc(d.event) + (d.errorMessage ? '<div class="id" title="' + esc(d.errorMessage) + '">' + esc(d.errorMessage) + '</div>' : '') + '</td>' +
                '<td>' + (d.status === "delivered" ? '<span class="pill ok">delivered</span>' : '<span class="pill neutral">' + esc(d.status) + '</span>') + '</td>' +
                '<td class="num">' + esc(d.attempt) + '</td>' +
                '<td class="num">' + esc(d.responseCode || "—") + '</td>' +
                '<td class="num">' + (ms != null ? (ms >= 1000 ? (ms / 1000).toFixed(1) + " s" : ms + " ms") : "—") + '</td>' +
                '<td>' + timeAgoCell(d.createdAt) + '</td>' +
              '</tr>';
            }).join('') + '</tbody>' +
          '</table></div>'
        : '<p class="sub">No deliveries yet — fire a test event to see one here.</p>';
    }

    root.addEventListener("keydown", function (e) {
      if (e.key !== "Enter" && e.key !== " ") return;
      var row = e.target.closest && e.target.closest("tr[data-id]");
      if (!row || e.target.tagName === "BUTTON") return;
      e.preventDefault();
      openDeliveriesModal(row.getAttribute("data-id"));
    });
    root.addEventListener("click", async function (e) {
      var btn = e.target.closest("button[data-act]");
      if (!btn) {
        var row = e.target.closest("tr[data-id]");
        if (row && !e.target.closest("button, a") && !textSelActive()) openDeliveriesModal(row.getAttribute("data-id"));
        return;
      }
      var tr = btn.closest("tr[data-id]");
      if (!tr) return;
      var id = tr.getAttribute("data-id");
      var act = btn.getAttribute("data-act");
      var current = endpoints.find(function (x) { return x.id === id; });
      if (!current) return;
      if (act === "test") {
        try { await state.ds.testWebhook(id); toast("Test event fired."); }
        catch (err) { toast(err.message || "Test failed"); }
      } else if (act === "toggle") {
        try {
          await state.ds.updateWebhook(id, { isActive: !current.isActive });
          toast(current.isActive ? "Paused." : "Resumed.");
          await renderSettingsWebhooks(root);
        } catch (err) { toast(err.message || "Update failed"); }
      } else if (act === "rotate") {
        // R113 F1: mint a new signing secret. R112 F3 shipped
        // the /rotate-secret endpoint but no console UI. The
        // returned plaintext is shown once via showTokenModal
        // matching the deployment rotate-token UX. Operators
        // are warned via the modal body that the old secret
        // is invalid immediately; they must swap on the
        // receiving service before the next event fires.
        confirmModal({
          title: "Rotate this webhook's signing secret?",
          body: "A new secret will be minted. The receiving service must be updated with the new value BEFORE the next event, or signature verification will fail on the consumer side.",
          confirmLabel: "Rotate", danger: true,
          onConfirm: async function () {
            try {
              var res = await state.ds.rotateWebhookSecret(id);
              showTokenModal(res.secret, "New webhook secret");
            } catch (err) { toast(err.message || "Rotate failed"); }
          },
        });
      } else if (act === "delete") {
        confirmModal({
          title: "Delete this webhook?",
          body: "The endpoint and its delivery history will be permanently removed.",
          confirmLabel: "Delete", danger: true,
          onConfirm: async function () {
            try { await state.ds.deleteWebhook(id); toast("Deleted."); await renderSettingsWebhooks(root); }
            catch (err) { toast(err.message || "Delete failed"); }
          },
        });
      }
    });
  }
  async function renderSettingsBilling(root) {
    root.innerHTML = '<div class="card">' + loadingBlock("table") + "</div>";
    // Pull the org's real usage so the pricing story runs on the same
    // numbers the investor just saw on the Overview.
    var stats = null;
    try { stats = await state.ds.getOverview("24h"); } catch (e) { /* tiers still render */ }
    var calls = stats ? (stats.toolsAllowed + stats.toolsBlocked) : 0;
    var meteredUsd = (calls / 1000) * 0.10;
    var kept = stats ? Number(stats.blockedSpendUsd) : 0;
    var tier = function (name, price, priceSub, items, cta, highlight) {
      return '<div class="price-tier' + (highlight ? " highlight" : "") + '">' +
        '<h3>' + esc(name) + "</h3>" +
        '<div class="pt-price">' + price + "</div>" +
        '<div class="pt-price-sub">' + esc(priceSub) + "</div>" +
        "<ul>" + items.map(function (i) { return "<li>" + esc(i) + "</li>"; }).join("") + "</ul>" +
        cta +
      "</div>";
    };
    root.innerHTML =
      '<div class="card">' +
        "<h2>Plan</h2>" +
        '<div style="display:flex; align-items:baseline; gap:8px; margin-bottom: 12px"><span style="font-size:22px; font-weight:600">Free</span> <span class="pill accent">current plan</span></div>' +
        '<p style="color: var(--fg-2); font-size: var(--t-sec); margin: 0">All governance features included while AgentVisor is in preview. Pricing below is what launches with the beta.</p>' +
      "</div>" +
      '<div class="pricing-grid">' +
        tier("Free", "$0", "up to 10 deployments",
          ["Every governance feature", "Signed receipts + offline verify", "90-day retention", "Community support"],
          '<span class="pill ok">You are here</span>') +
        tier("Team", "$99<span class=\"pt-per\">/mo</span>", "+ $0.10 per 1,000 policed tool calls",
          ["Everything in Free", "SSO enforcement + SCIM", "1-year retention", "Priority support"],
          '<button class="btn accent" id="upgradeBtn">Upgrade to Team</button>', true) +
        tier("Enterprise", "Custom", "annual, self-hosted or dedicated",
          ["Self-hosted control plane", "Custom receipt trust anchors", "SLAs + dedicated support", "Airgapped verify tooling"],
          '<button class="btn" id="contactBtn">Contact us</button>') +
      "</div>" +
      (stats
        ? '<div class="card" style="margin-top:12px">' +
            "<h2>What Team pricing would cost this workspace</h2>" +
            '<div class="billing-math">' +
              '<div><div class="bm-num">' + calls.toLocaleString() + '</div><div class="bm-label">policed tool calls (24 h)</div></div>' +
              '<div><div class="bm-num">$' + meteredUsd.toFixed(2) + '</div><div class="bm-label">metered cost of those calls</div></div>' +
              '<div><div class="bm-num" style="color: var(--success-solid)">$' + kept.toLocaleString() + '</div><div class="bm-label">kept from bad orders in the same window</div></div>' +
            "</div>" +
            '<p style="color: var(--fg-2); font-size: var(--t-sec); margin: 12px 0 0">Policing an agent\'s tool call costs a fraction of a cent. One blocked bad order pays for years of it.</p>' +
          "</div>"
        : "");
    var b = $("#upgradeBtn", root);
    if (b) b.addEventListener("click", function () { comingSoon("Upgrade to Team", "Billing lands in the beta. In the meantime, ping the AgentVisor team to enable Team features on your workspace."); });
    var c = $("#contactBtn", root);
    if (c) c.addEventListener("click", function () { comingSoon("Enterprise", "Talk to us about a self-hosted control plane, custom trust anchors, and SLAs: hello@agentvisorai.me"); });
  }
  async function renderSettingsAudit(root) {
    // R124 F2: if the user was bounced here from a failed
    // /audit.csv attempt (top-level nav dead-end), the URL
    // will carry ?err=audit_forbidden_member or
    // ?err=audit_invalid_before. Surface a toast so the user
    // knows why they landed on the audit tab instead of
    // getting a download.
    var auditQs = (location.hash.split("?")[1] || "");
    var auditParams = new URLSearchParams(auditQs);
    var auditErr = auditParams.get("err") || "";
    if (auditErr === "audit_forbidden_member") {
      toast("Only owner/admin roles can export the audit log.", true);
    } else if (auditErr === "audit_invalid_before") {
      toast("Invalid audit export cursor. Showing the current audit log.", true);
    }
    // R125 F2: drop the ?err=... fragment so a page refresh or a
    // return visit doesn't re-fire the toast. history.replaceState
    // is safe from a hash route because we only rewrite the hash
    // portion, leaving pathname and search intact. Matches the
    // "banner clears after read" pattern used for post-login
    // redirects.
    if (auditErr) {
      try {
        var auditBase = location.hash.split("?")[0];
        history.replaceState(null, "", location.pathname + location.search + auditBase);
      } catch (e) {}
    }
    root.innerHTML = '<div class="card">' + loadingBlock("table") + "</div>";
    var audit;
    try { audit = await state.ds.listAudit(); }
    catch (e) { root.innerHTML = '<div class="card empty"><h3>Could not load the audit log</h3><p>' + esc(e.message || "Try again in a moment.") + '</p></div>'; return; }
    if (!audit.length) {
      root.innerHTML =
        '<div class="card" style="padding:0">' +
          '<div style="padding:12px 16px; border-bottom:1px solid var(--border)"><h2 style="margin:0; font-size:var(--t-section); font-weight:600">Audit log</h2></div>' +
          '<div style="padding: 24px 16px">' +
          emptyState("No audit entries yet", "Sign-ins, deployment rotations, policy changes, and receipt verifications will appear here as your team uses the console.") +
          "</div></div>";
      return;
    }

    // Category chips from event prefixes actually present (policy.*,
    // member.*, auth.* …) — same interaction model as the event-stream
    // triage chips on session detail.
    var catCounts = {};
    audit.forEach(function (a) { var c = a.event.split(".")[0]; catCounts[c] = (catCounts[c] || 0) + 1; });
    var cats = Object.keys(catCounts).sort();
    var chips = '<button class="evt-chip active" data-cat="" aria-pressed="true">All <span class="n">' + audit.length + "</span></button>" +
      cats.map(function (c) {
        return '<button class="evt-chip" data-cat="' + esc(c) + '" aria-pressed="false">' + esc(c) + ' <span class="n">' + catCounts[c] + "</span></button>";
      }).join("");

    var rowsHtml = function (list) {
      return list.map(function (a) {
        return '<tr><td class="mono" style="color:var(--fg-3); font-size:11.5px; white-space:nowrap">' + esc(new Date(a.at).toLocaleString()) + '</td>' +
          '<td><span style="font-weight:500">' + esc(a.event) + "</span></td>" +
          "<td>" + esc(a.actor) + "</td>" +
          "<td>" + esc(a.target || "—") + "</td>" +
          '<td style="color: var(--fg-2)">' + esc(a.note || "") + "</td></tr>";
      }).join("");
    };

    root.innerHTML =
      '<div class="card" style="padding:0">' +
        '<div style="padding:12px 16px; border-bottom:1px solid var(--border); display:flex; align-items:center; gap:8px; flex-wrap:wrap">' +
          '<h2 style="margin:0; font-size:var(--t-section); font-weight:600">Audit log</h2>' +
          '<span style="color:var(--fg-3); font-size:var(--t-sec)" id="auditCount">' + audit.length + " events</span>" +
          '<div class="evt-filters" style="margin-left:auto">' + chips +
            '<input id="auditSearch" type="search" placeholder="Filter by actor, event, target…" aria-label="Filter audit entries" style="width:180px" />' +
          "</div>" +
          '<button class="btn" id="auditExportBtn" title="Download the entries shown below as CSV">↓ Export CSV</button>' +
        "</div>" +
        '<div class="table-wrap"><table>' +
          "<thead><tr><th>When</th><th>Event</th><th>Actor</th><th>Target</th><th>Note</th></tr></thead>" +
          '<tbody id="auditBody">' + rowsHtml(audit) + "</tbody>" +
        "</table></div>" +
        '<div class="empty-mini" id="auditNone" style="padding:16px; display:none">No entries match — clear the filter to see all ' + audit.length + ".</div>" +
      "</div>";

    var activeCat = "";
    var search = $("#auditSearch", root);
    function filtered() {
      var q = ((search && search.value) || "").trim().toLowerCase();
      return audit.filter(function (a) {
        if (activeCat && a.event.split(".")[0] !== activeCat) return false;
        if (!q) return true;
        return (a.event + " " + a.actor + " " + (a.target || "") + " " + (a.note || "")).toLowerCase().indexOf(q) >= 0;
      });
    }
    function apply() {
      var list = filtered();
      // tbody-only update: the search input keeps focus, nothing blinks.
      $("#auditBody", root).innerHTML = rowsHtml(list);
      $("#auditCount", root).textContent = list.length === audit.length
        ? audit.length + " events" : list.length + " of " + audit.length + " shown";
      $("#auditNone", root).style.display = list.length ? "none" : "";
    }
    if (search) search.addEventListener("input", apply);
    root.querySelector(".evt-filters").addEventListener("click", function (e) {
      var chip = e.target.closest(".evt-chip");
      if (!chip) return;
      $$(".evt-chip", root).forEach(function (c) {
        c.classList.toggle("active", c === chip);
        c.setAttribute("aria-pressed", c === chip ? "true" : "false");
      });
      activeCat = chip.getAttribute("data-cat");
      apply();
    });

    var exp = $("#auditExportBtn", root);
    if (exp) exp.addEventListener("click", function () {
      // Server-side stream when the API offers it; otherwise build the
      // CSV client-side from the filtered view (WYSIWYG, works in demo
      // mode too — this used to toast 'not available in demo mode').
      if (state.ds.downloadAuditCsv) return state.ds.downloadAuditCsv();
      var list = filtered();
      var lines = [["at", "event", "actor", "target", "note"].join(",")].concat(list.map(function (a) {
        return [a.at, a.event, a.actor, a.target || "", a.note || ""].map(csvField).join(",");
      }));
      var stamp = new Date().toISOString().slice(0, 16).replace(/[:T]/g, "-");
      var blob = new Blob(["\ufeff" + lines.join("\r\n")], { type: "text/csv;charset=utf-8" });
      var a2 = document.createElement("a");
      a2.href = URL.createObjectURL(blob);
      a2.download = "agentvisor-audit-" + stamp + ".csv";
      document.body.appendChild(a2); a2.click(); a2.remove();
      setTimeout(function () { URL.revokeObjectURL(a2.href); }, 4000);
      toast(list.length + " audit entr" + (list.length === 1 ? "y" : "ies") + " exported");
    });
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
    if (document.body.classList.contains("locked")) return;
    var backdrop = h(
      '<div class="modal-backdrop" role="dialog" aria-modal="true">' +
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
    var previouslyFocused = document.activeElement;
    var uninstall;
    var handled = false;
    function close() {
      if (handled) return;
      handled = true;
      backdrop.remove(); document.body.classList.remove("locked");
      if (uninstall) uninstall();
      if (previouslyFocused && previouslyFocused.focus) try { previouslyFocused.focus(); } catch (e) {}
    }
    uninstall = installModalKeys(backdrop, close);
    backdrop.addEventListener("click", function (e) {
      if (handled) return;
      if (e.target === backdrop || e.target.hasAttribute("data-close")) { close(); return; }
      if (e.target.hasAttribute("data-confirm")) {
        var cb = opts.onConfirm;
        close();
        if (cb) cb();
      }
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

    // Gather static targets synchronously. These render immediately so
    // the palette shell is on screen the same tick as the ⌘K keystroke.
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
    if (state.ds.mode === "mock") {
      if (window.AVTour) actions.unshift({ g: "Actions", label: "See the full flow", desc: "Guided tour of the money story", run: function () { window.AVTour.start(); } });
      if (typeof state.ds.simulateAttack === "function") actions.push({ g: "Actions", label: "Simulate an agent attack", desc: "Stage a live blocked payment", run: function () { navigate("#/overview"); setTimeout(runAttackDemo, 250); } });
    }
    actions.push({ g: "Actions", label: "New policy", desc: "Create a spend cap, vendor allowlist, or PII guard", run: function () { navigate("#/policies"); setTimeout(openCreatePolicyModal, 250); } });
    actions.push({ g: "Actions", label: "Keyboard shortcuts", desc: "Everything the keyboard can do", kbd: "?", run: function () { setTimeout(openShortcutSheet, 250); } });
    if (state.ds.mode === "mock") {
      var big = false;
      try { big = localStorage.getItem("av_mock_bigdata") === "1"; } catch (e) {}
      actions.push({
        g: "Actions",
        label: big ? "Back to the 24h dataset" : "Load the 30-day dataset (280 sessions)",
        desc: big ? "Return to the focused demo data" : "What the console looks like at scale — pagination, sort, exports",
        run: function () {
          try { localStorage.setItem("av_mock_bigdata", big ? "0" : "1"); } catch (e) {}
          // navigate() renders (hashchange, or directly when the hash
          // is unchanged) — an extra render() here raced it with two
          // parallel renderSessionsList fetches clobbering each other.
          navigate("#/sessions?range=720");
        },
      });
    }
    if (rolePreview) actions.push({ g: "Actions", label: "Exit member preview", desc: "Back to your own role", run: exitRolePreview });
    else if (state.session && state.session.org && state.session.org.role !== "member")
      actions.push({ g: "Actions", label: "Preview as member", desc: "See the console the way a member does", run: enterRolePreview });
    // Sibling pages: the verifier and the pitch live outside the SPA,
    // so open them as real navigations instead of hash routes.
    var pages = [
      { g: "Pages", label: "Verify a receipt", desc: "Public offline verifier — green tick, no account", run: function () { window.open("../verify/", "_blank", "noopener"); } },
      { g: "Pages", label: "Watch the pitch", desc: "30 s hero + 130 s full tour, with transcripts", run: function () { window.open("../pitch/", "_blank", "noopener"); } },
      { g: "Pages", label: "Read the code", desc: "github.com/AgentVisorAI/agentvisor-ai", run: function () { window.open("https://github.com/AgentVisorAI/agentvisor-ai", "_blank", "noopener"); } },
    ];
    if (state.ds.mode === "mock") {
      // Demo-table reset: judges hand the laptop around; this returns
      // the console to the pristine Northwind showcase in one action.
      pages.push({ g: "Pages", label: "Reset demo data", desc: "Back to the pristine showcase workspace", run: function () {
        try {
          ["av_mock_fresh_t0", "av_mock_fresh_identity", "av_mock_signed_out", "av_tour_dismissed", "av_mock_bigdata"].forEach(function (k) { localStorage.removeItem(k); });
        } catch (e) {}
        location.hash = "#/overview";
        location.reload();
      } });
    }
    // Dynamic targets get filled in when the async datasource calls
    // resolve. Palette shell is already interactive. User can navigate
    // + search static entries with zero latency.
    var sessions = [], policies = [], deployments = [];
    var all = routes.concat(actions).concat(pages);

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
    // Rank: label prefix < label substring < desc substring < scattered
    // subsequence. Without this, "reset" selected "SeTtings" (its
    // letters appear in order) above the literal "Reset demo data".
    function matchRank(q, it) {
      q = q.toLowerCase();
      var label = String(it.label || "").toLowerCase();
      var desc = String(it.desc || "").toLowerCase();
      if (label.indexOf(q) === 0) return 0;
      if (label.indexOf(q) >= 0) return 1;
      if (desc.indexOf(q) >= 0) return 2;
      return 3;
    }
    function paint() {
      var q = input.value.trim();
      var filtered = q ? all.filter(function (it) { return fuzzyMatch(q, it.label + " " + (it.desc || "")); }) : all;
      if (q) {
        filtered = filtered
          .map(function (it, i) { return { it: it, rank: matchRank(q, it), i: i }; })
          .sort(function (a, b) { return a.rank - b.rank || a.i - b.i; })
          .map(function (x) { return x.it; });
      }
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

    // Populate dynamic entries in the background. Palette is already
    // interactive with the 8 static routes/actions above. When the data
    // arrives we extend `all` and repaint (throttled to the current
    // query). Any error is silently absorbed; the palette stays useful
    // even offline.
    (async function loadDynamic() {
      try {
        var sres = await state.ds.listSessions();
        sessions = sres.sessions.slice(0, 20).map(function (s) {
          return { g: "Sessions", label: s.externalId, desc: s.agent + " · " + s.user, href: "#/sessions/" + s.id, icon: iconActivity() };
        });
        all = all.concat(sessions);
        if (backdrop.isConnected) paint();
      } catch (e) {}
      try {
        policies = (await state.ds.listPolicies()).map(function (p) {
          return { g: "Policies", label: p.name, desc: p.description, href: "#/policies/" + p.id, icon: iconShield() };
        });
        all = all.concat(policies);
        if (backdrop.isConnected) paint();
      } catch (e) {}
      try {
        deployments = (await state.ds.listDeployments()).map(function (d) {
          return { g: "Deployments", label: d.name, desc: d.environment + " · " + (d.region || ""), href: "#/deployments/" + d.id, icon: iconServer() };
        });
        all = all.concat(deployments);
        if (backdrop.isConnected) paint();
      } catch (e) {}
    }());

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
      window.removeEventListener("hashchange", close);
      backdrop.remove();
      document.body.classList.remove("locked");
    }
    function run(it) {
      if (!it) return;
      if (it.href) { close(); navigate(it.href); }
      else if (it.run) { close(); it.run(); }
    }
    backdrop.addEventListener("click", function (e) { if (e.target === backdrop) close(); });
    // Browser Back (or any route change) while the palette is open:
    // without this the backdrop outlived the navigation and ate every
    // click on the new page, and cmdkOpen_ stayed stuck at true.
    window.addEventListener("hashchange", close);
  }

  /* ============================================================
   * KEYBOARD SHORTCUTS
   * ============================================================ */

  function installKeyboardShortcuts() {
    document.addEventListener("keydown", function (e) {
      // ⌘K / Ctrl+K
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        // If any modal / overlay is open, don't stack the palette on top.
        // The palette itself sets `.locked` so pressing ⌘K twice can't
        // reopen it either.
        if (document.body.classList.contains("locked")) return;
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
      // "/" focuses the page's search/filter input (sessions search,
      // event-stream filter, audit search) — standard list-page UX.
      if (e.key === "/") {
        var target = document.getElementById("fSearch") || document.getElementById("evtSearch") || document.getElementById("auditSearch");
        if (target) { e.preventDefault(); target.focus(); target.select(); }
      }
      // "[" / "]" page through the browsed session list from a detail.
      if (e.key === "[" || e.key === "]") {
        var pn = document.getElementById(e.key === "[" ? "prevSess" : "nextSess");
        if (pn && !pn.disabled) { e.preventDefault(); pn.click(); }
      }
    });
  }

  function openShortcutSheet() {
    // Same stacking rule as every other modal: don't pile a second
    // sheet (or a sheet over the palette) — pressing ? twice used to
    // stack two copies with no way to close the bottom one.
    if (document.body.classList.contains("locked")) return;
    var groups = [
      { title: "Navigate", items: [
        ["G O", "Overview"], ["G S", "Sessions"], ["G P", "Policies"],
        ["G D", "Deployments"], ["G ,", "Settings"],
      ]},
      { title: "Lists & tables", items: [
        ["↑ ↓", "Move between rows"], ["Enter", "Open the focused row"], ["/", "Focus the search field"],
        ["[ ]", "Previous / next session (on a detail page)"],
      ]},
      { title: "Event stream", items: [
        ["↑ ↓", "Move between events"], ["Home / End", "Jump to first / last"],
        ["Enter / Space", "Inspect the event (updates the shareable URL)"],
      ]},
      { title: "Guided tour", items: [
        ["→ / Enter", "Next step"], ["←", "Previous step"], ["Esc", "Exit the tour"],
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
      '<div class="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="shortcutsTitle"><div class="modal">' +
        '<h2 id="shortcutsTitle">Keyboard shortcuts</h2>' +
        '<p class="sub">Move around without a mouse.</p>' +
        html +
        '<div class="actions"><button type="button" class="btn primary" data-close>Done</button></div>' +
      "</div></div>"
    );
    document.body.appendChild(backdrop);
    document.body.classList.add("locked");
    var previouslyFocused = document.activeElement;
    function close() {
      backdrop.remove(); document.body.classList.remove("locked"); document.removeEventListener("keydown", onKey);
      if (previouslyFocused && previouslyFocused.focus) try { previouslyFocused.focus(); } catch (e) {}
    }
    function onKey(ev) { if (ev.key === "Escape") close(); }
    document.addEventListener("keydown", onKey);
    backdrop.addEventListener("click", function (e) {
      if (e.target === backdrop || e.target.hasAttribute("data-close")) close();
    });
    setTimeout(function () { var d = backdrop.querySelector("[data-close]"); if (d) d.focus(); }, 20);
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
    // Log the original once so ops can grep the browser console (or
    // Sentry when we wire it). But don't render the raw message; a
    // customer-facing "Something went wrong" is a better UX than
    // "not_found" for a stale bookmark.
    console.error(err);
    var isNotFound = err && (err.message === "not_found" || err.status === 404);
    var title = isNotFound ? "Not found" : "Something went wrong";
    var detail = isNotFound
      ? "That item doesn't exist, or you don't have access to it."
      : "This shouldn't happen. Try again in a moment or reload the page."
        + (err && err.requestId ? " (request id: " + esc(err.requestId) + ")" : "");
    var actions = isNotFound
      ? '<a class="btn accent" href="#/sessions">Back to sessions</a> <a class="btn" href="#/overview">Overview</a>'
      : '<button class="btn accent" onclick="location.reload()">Reload</button> <a class="btn" href="#/overview">Overview</a>';
    main.innerHTML = pageHeader(title) + '<div class="card"><div class="empty"><h3>' + esc(title) + "</h3><p>" + detail + "</p>" + actions + "</div></div>";
  }

  /* ---------- go ---------- */

  boot();
})();
