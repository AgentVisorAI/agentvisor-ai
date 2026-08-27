/* AgentVisor console — guided flow tour.
 *
 * A six-step spotlight walkthrough that carries a first-time visitor
 * (an investor, not an engineer) through the exact loop the pitch
 * videos show: money kept → the session that kept it → the moment the
 * bad payment was blocked → the signed receipt → the public verifier.
 *
 * Self-contained on purpose: it drives the app only through
 * location.hash and DOM selectors, so app.js stays untouched except
 * for the palette entries that call window.AVTour.start().
 */
(function () {
  "use strict";
  if (!window.MOCK_MODE) return; // guided tour narrates the demo fixtures

  var DISMISS_KEY = "av_tour_dismissed";

  var STEPS = [
    {
      route: "#/overview",
      waitFor: ".stat.savings",
      target: ".stat.savings",
      title: "Start with the money",
      body: "Northwind's AI agents order stock and pay invoices on their own. " +
        "This is what AgentVisor kept from leaving the building: <b>$31,840</b> " +
        "in payments that policy stopped before any money moved.",
    },
    {
      route: "#/overview",
      waitFor: ".stat.blocks",
      target: ".stat.blocks",
      title: "Every tool call is checked first",
      body: "Agents don't touch money or systems directly — every tool call " +
        "passes through AgentVisor's policy engine. Most are allowed. " +
        "The dangerous ones end up here.",
    },
    {
      route: "#/sessions",
      waitFor: 'tr[data-id="sess_01H9K"]',
      target: 'tr[data-id="sess_01H9K"]',
      title: "Every run becomes a session",
      body: "Each agent run is recorded end to end. This one is the story: " +
        "the <b>supply-planner</b> agent was tricked into paying a fake " +
        "vendor <b>$8,400</b> — and got blocked. Let's open it.",
    },
    {
      route: "#/sessions/sess_01H9K",
      waitFor: ".evt.err",
      target: ".evt.err",
      title: "The exact moment it was stopped",
      body: "Event #8: the agent tried <code>create_purchase_order</code> for a " +
        "vendor not on the approved list. Blocked in 6&nbsp;ms, before the " +
        "money moved. The safe retry with an approved vendor went through.",
    },
    {
      route: "#/sessions/sess_01H9K",
      waitFor: ".receipt-card",
      target: ".receipt-card",
      title: "Sealed into a signed receipt",
      body: "The whole session — every prompt, tool call, and block — is " +
        "sealed under an <b>Ed25519 signature</b>. Change one byte and the " +
        "signature breaks. This is the audit trail you hand to an auditor.",
    },
    {
      route: "#/sessions/sess_01H9K",
      waitFor: "#dlRcpt",
      target: null, // centered finale
      title: "Don't trust us — verify it",
      body: "Download this receipt and drop it into our public verifier. " +
        "It checks the real cryptography in your browser — green tick, " +
        "no account, works offline. And when you're back: hit " +
        "<b>⚡ Simulate an attack</b> on the Overview to watch a live " +
        "block happen in front of you.",
      cta: { label: "Open the verifier ↗", href: "../verify/", blank: true },
    },
  ];

  var state = { i: -1, overlay: null, pollTimer: null, reposition: null };

  function el(html) {
    var t = document.createElement("template");
    t.innerHTML = html.trim();
    return t.content.firstChild;
  }

  function freshMode() {
    try { return !!localStorage.getItem("av_mock_fresh_t0"); } catch (e) { return false; }
  }
  function inShell() { return !!document.querySelector(".app-shell"); }

  /* ── Launcher pill ─────────────────────────────────────────── */

  function ensureLauncher() {
    var existing = document.getElementById("avTourLauncher");
    var want = inShell() && state.i < 0 && !dismissed() && !freshMode();
    if (want && !existing) {
      var pill = el(
        '<div id="avTourLauncher" role="complementary" aria-label="Guided tour">' +
          '<button type="button" id="avTourStart">▶&nbsp; See the full flow</button>' +
          '<button type="button" id="avTourDismiss" aria-label="Dismiss guided tour">✕</button>' +
        "</div>"
      );
      document.body.appendChild(pill);
      pill.querySelector("#avTourStart").addEventListener("click", function () { start(); });
      pill.querySelector("#avTourDismiss").addEventListener("click", function () {
        try { localStorage.setItem(DISMISS_KEY, "1"); } catch (e) {}
        pill.remove();
      });
    } else if (!want && existing) {
      existing.remove();
    }
  }
  function dismissed() {
    try { return localStorage.getItem(DISMISS_KEY) === "1"; } catch (e) { return false; }
  }

  /* ── Spotlight engine ──────────────────────────────────────── */

  function buildOverlay() {
    var o = el(
      '<div id="avTour" aria-live="polite">' +
        '<div class="av-tour-hole" aria-hidden="true"></div>' +
        '<div class="av-tour-card" role="dialog" aria-modal="false">' +
          '<div class="av-tour-step"></div>' +
          '<h3></h3>' +
          '<p></p>' +
          '<div class="av-tour-actions">' +
            '<button type="button" class="av-tour-skip">Skip tour</button>' +
            '<span class="av-tour-spacer"></span>' +
            '<button type="button" class="av-tour-back">Back</button>' +
            '<button type="button" class="av-tour-next">Next</button>' +
          "</div>" +
        "</div>" +
      "</div>"
    );
    o.querySelector(".av-tour-skip").addEventListener("click", stop);
    o.querySelector(".av-tour-back").addEventListener("click", function () { go(state.i - 1); });
    o.querySelector(".av-tour-next").addEventListener("click", function () {
      if (state.i >= STEPS.length - 1) stop();
      else go(state.i + 1);
    });
    document.addEventListener("keydown", onKey);
    return o;
  }

  function onKey(e) {
    if (state.i < 0) return;
    if (e.key === "Escape") { e.preventDefault(); stop(); }
    if (e.key === "ArrowRight" || e.key === "Enter") {
      if (e.target && /INPUT|TEXTAREA/.test(e.target.tagName)) return;
      e.preventDefault();
      if (state.i >= STEPS.length - 1) stop(); else go(state.i + 1);
    }
    if (e.key === "ArrowLeft") { e.preventDefault(); if (state.i > 0) go(state.i - 1); }
  }

  function positionAround(target, step) {
    var hole = state.overlay.querySelector(".av-tour-hole");
    var card = state.overlay.querySelector(".av-tour-card");
    if (!target) {
      hole.style.display = "none";
      card.classList.add("centered");
      card.style.left = "";
      card.style.top = "";
      return;
    }
    card.classList.remove("centered");
    var r = target.getBoundingClientRect();
    var pad = 8;
    hole.style.display = "block";
    hole.style.left = (r.left - pad) + "px";
    hole.style.top = (r.top - pad) + "px";
    hole.style.width = (r.width + pad * 2) + "px";
    hole.style.height = (r.height + pad * 2) + "px";

    // Card below the target when there's room, above otherwise;
    // clamped to the viewport (including viewports narrower than the card).
    var cw = Math.min(380, window.innerWidth - 24), chGuess = 210, gap = 14;
    var left = Math.min(Math.max(12, r.left), Math.max(12, window.innerWidth - cw - 12));
    var top = r.bottom + gap;
    if (top + chGuess > window.innerHeight - 12) top = Math.max(12, r.top - chGuess - gap);
    card.style.width = cw + "px";
    card.style.left = left + "px";
    card.style.top = top + "px";
  }

  function waitFor(selector, timeoutMs) {
    return new Promise(function (resolve) {
      var t0 = Date.now();
      (function poll() {
        var n = document.querySelector(selector);
        if (n) return resolve(n);
        if (Date.now() - t0 > (timeoutMs || 6000)) return resolve(null);
        state.pollTimer = setTimeout(poll, 120);
      })();
    });
  }

  async function go(i) {
    if (i < 0 || i >= STEPS.length) return;
    clearTimeout(state.pollTimer);
    state.i = i;
    var step = STEPS[i];
    ensureLauncher();

    if (location.hash !== step.route) location.hash = step.route;
    var anchor = await waitFor(step.waitFor);
    if (state.i !== i) return; // user skipped ahead while we were waiting

    var card = state.overlay.querySelector(".av-tour-card");
    card.querySelector(".av-tour-step").textContent = "Step " + (i + 1) + " of " + STEPS.length;
    card.querySelector("h3").textContent = step.title;
    card.querySelector("p").innerHTML = step.body;

    var back = card.querySelector(".av-tour-back");
    var next = card.querySelector(".av-tour-next");
    back.style.visibility = i === 0 ? "hidden" : "visible";
    if (step.cta) {
      next.innerHTML = step.cta.label;
      next.onclick = function () {
        window.open(step.cta.href, step.cta.blank ? "_blank" : "_self", "noopener");
        stop();
      };
    } else {
      next.textContent = i === STEPS.length - 1 ? "Finish" : "Next";
      next.onclick = null;
    }

    var target = step.target ? (document.querySelector(step.target) || anchor) : null;
    if (target && target.scrollIntoView) {
      var reduced = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      target.scrollIntoView({ block: "center", behavior: reduced ? "auto" : "smooth" });
    }

    // Wait one frame for the scroll to start, then track the target so
    // the spotlight follows smooth-scrolling and window resizes.
    positionAround(target, step);
    if (state.reposition) { window.removeEventListener("resize", state.reposition); clearInterval(state.repositionTimer); }
    state.reposition = function () { if (state.i === i) positionAround(step.target ? document.querySelector(step.target) : null, step); };
    window.addEventListener("resize", state.reposition);
    state.repositionTimer = setInterval(state.reposition, 250);
  }

  function start() {
    if (state.i >= 0) return;
    if (!inShell()) { // signed out → the tour makes no sense; go sign in first
      location.hash = "#/overview";
    }
    if (!state.overlay) {
      state.overlay = buildOverlay();
      document.body.appendChild(state.overlay);
    }
    state.overlay.style.display = "block";
    go(0);
  }

  function stop() {
    clearTimeout(state.pollTimer);
    clearInterval(state.repositionTimer);
    if (state.reposition) window.removeEventListener("resize", state.reposition);
    state.reposition = null;
    if (state.overlay) state.overlay.style.display = "none";
    state.i = -1;
    ensureLauncher();
  }

  window.AVTour = { start: start, stop: stop };

  /* ── Boot ──────────────────────────────────────────────────── */

  window.addEventListener("hashchange", function () { setTimeout(ensureLauncher, 50); });
  var boot = setInterval(function () {
    ensureLauncher();
    if (inShell()) {
      // ?tour=1 deep link (used by the landing page CTA) auto-starts once.
      if (/[?&]tour=1/.test(location.search) && state.i < 0 && !state._autoStarted) {
        state._autoStarted = true;
        setTimeout(start, 600);
      }
      clearInterval(boot);
      setInterval(ensureLauncher, 1200);
    }
  }, 300);
})();
