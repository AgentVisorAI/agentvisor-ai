// Boot-time safety net. If anything throws before or during the app's
// own error handler installs, the user sees a small centered crash
// card with a Reload button + a request-id (when known). This runs
// BEFORE the app scripts load so a syntax error in either app.js or
// datasource.js doesn't leave a blank page.
//
// Extracted from index.html so that a strict Content-Security-Policy
// (`script-src 'self'`) can be enforced without allowing 'unsafe-inline'.
(function () {
  function crashCard(msg, requestId) {
    try {
      var host = document.getElementById("app") || document.body;
      host.textContent = "";
      var card = document.createElement("div");
      card.style.cssText = "max-width:520px;margin:96px auto;padding:24px 28px;font:14px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#fff;border:1px solid #e0e0e0;border-radius:12px;box-shadow:0 6px 24px rgba(0,0,0,.06)";
      var h = document.createElement("div");
      h.style.cssText = "font-size:15px;font-weight:600;margin-bottom:6px";
      h.textContent = "The console hit an error";
      card.appendChild(h);
      var m = document.createElement("div");
      m.style.cssText = "color:#4a4a4a;margin-bottom:16px";
      m.textContent = String(msg || "Unknown error");
      card.appendChild(m);
      if (requestId) {
        var r = document.createElement("div");
        r.style.cssText = "font:12px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;color:#888;margin-bottom:16px";
        r.textContent = "request-id: " + String(requestId);
        card.appendChild(r);
      }
      var btn = document.createElement("button");
      btn.style.cssText = "border:0;background:#0a5c8b;color:#fff;padding:8px 16px;border-radius:8px;font-weight:500;cursor:pointer";
      btn.textContent = "Reload";
      btn.addEventListener("click", function () { location.reload(); });
      card.appendChild(btn);
      var a = document.createElement("a");
      a.style.cssText = "margin-left:12px;color:#0a5c8b;text-decoration:none";
      a.href = "mailto:hello@agentvisorai.me?subject=Console%20crash";
      a.textContent = "Contact support";
      card.appendChild(a);
      host.appendChild(card);
    } catch (e) {
      // Truly wedged — fall back to a native alert.
      alert("Console crashed: " + msg + (requestId ? " (request-id " + requestId + ")" : ""));
    }
  }
  window.addEventListener("error", function (ev) {
    var msg = (ev.error && ev.error.message) || ev.message || "Uncaught error";
    crashCard(msg, window.__lastRequestId);
  });
  window.addEventListener("unhandledrejection", function (ev) {
    var reason = ev.reason;
    var msg = (reason && (reason.message || reason.detail || reason.toString && reason.toString())) || "Unhandled promise rejection";
    crashCard(msg, window.__lastRequestId);
  });
}());
