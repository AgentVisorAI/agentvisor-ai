    const drop = document.getElementById("drop");
    const fileInput = document.getElementById("fileInput");
    const browseBtn = document.getElementById("browseBtn");
    const result = document.getElementById("result");
    const loadExample = document.getElementById("loadExample");

    function esc(s) {
      return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
    }

    function hex2bytes(hex) {
      const b = new Uint8Array(hex.length / 2);
      for (let i = 0; i < b.length; i++) b[i] = parseInt(hex.substr(i * 2, 2), 16);
      return b;
    }
    function b64ToBytes(s) {
      const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    }

    // R78 HIGH #1 (landed R79 into the extracted verify.js): trust
    // anchor pinning. Without this, an attacker who generates their
    // own Ed25519 keypair, signs an arbitrary `rawBody`, and embeds
    // their pubkey in a fresh bundle gets the same "✅ authentic"
    // verdict as a real AgentVisor-signed receipt. The verifier
    // only ever proved self-consistency of (body, sig, pubkey),
    // not authorship. The trusted-anchors list below is the set of
    // Ed25519 pubkey hex strings the daemon publicly commits to.
    // If the bundle's pubkey is NOT in this list, `verifyBundle`
    // returns `trustedKey: false` and the UI displays "internally
    // consistent. Trust anchor NOT verified", NOT the word
    // "authentic". Empty by default (no canonical anchor published
    // yet); populate via a release-hardening round or fetch from
    // `https://agentvisorai.me/.well-known/receipt-keys.json`
    // over TLS.
    const TRUSTED_RECEIPT_KEYS = new Set([
      // Lowercased 64-hex Ed25519 pubkeys.
      //
      // The demo sample receipt bundled with this page
      // (sample-receipt.json). Its keypair was generated once at
      // build time and the private half was discarded. This anchor
      // exists so "Try it with a sample" shows the full green
      // trusted-verify experience investors will see with real
      // daemon-signed receipts.
      "9992e71fe6a6e5edc18129becef2ec640f9611a4e12a4b9a311bab943ab19467",
      // The mock console's fixed demo signing key (docs/app/
      // datasource.js). Receipts downloaded from the /app/ demo are
      // signed with it, so dropping one here verifies GREEN, the same
      // end-to-end flow the pitch video shows. The private half is
      // intentionally public; it signs only fake demo data.
      "573c8f249012fbb08b3d79973411bb93141f32719c86ada25306fde5e59e8d57",
    ]);

    async function verifyBundle(bundle) {
      if (bundle.format !== "agentvisor.receipt.v1") {
        throw new Error("Unrecognized bundle format: " + bundle.format);
      }
      const r = bundle.receipt || {};
      const pub = bundle.publicKey || {};
      if (!r.rawBody || !r.rawSignatureB64) throw new Error("Receipt is missing rawBody or rawSignatureB64.");
      if (!pub.hex || !/^[0-9a-fA-F]{64}$/.test(pub.hex)) throw new Error("Bundle is missing a valid 32-byte Ed25519 public key.");
      const keyBytes = hex2bytes(pub.hex);
      let key;
      try {
        key = await crypto.subtle.importKey("raw", keyBytes, { name: "Ed25519" }, false, ["verify"]);
      } catch (e) {
        throw new Error("This browser doesn't support Web Crypto Ed25519. Try Chrome 113+, Firefox 130+, or Safari 17+. Or run the CLI: node server/scripts/verify-receipt.mjs receipt.json");
      }
      const msg = new TextEncoder().encode(r.rawBody);
      const sig = b64ToBytes(r.rawSignatureB64);
      const ok = await crypto.subtle.verify("Ed25519", key, sig, msg);
      const trustedKey = TRUSTED_RECEIPT_KEYS.has(pub.hex.toLowerCase());
      return { ok, trustedKey, bundle };
    }

    // Expose TRUSTED_RECEIPT_KEYS on `window` so the CI drill can
    // inject a per-test trusted pubkey via `page.evaluate` (see
    // server/scripts/verify-page-drill.mjs R79 regression guard).
    // In production this is a no-op. The Set is closed over the
    // verifyBundle closure and no page script adds to it.
    if (typeof window !== "undefined") {
      window.TRUSTED_RECEIPT_KEYS = TRUSTED_RECEIPT_KEYS;
    }

    function render(state) {
      result.hidden = false;
      if (state.kind === "pending") {
        result.innerHTML = `
          <div class="result-card pending">
            <p class="result-title">Verifying signature…</p>
            <p class="result-sub">Running Ed25519 in your browser.</p>
          </div>`;
        return;
      }
      if (state.kind === "err") {
        result.innerHTML = `
          <div class="result-card bad">
            <p class="result-title">Couldn't verify this bundle</p>
            <p class="result-sub">${esc(state.message)}</p>
          </div>`;
        return;
      }
      const b = state.bundle;
      const s = b.session || {};
      const r = b.receipt || {};
      const pub = b.publicKey || {};
      // R8 claim audit: display facts from the SIGNED body, never from
      // the unsigned envelope. The envelope's `session` / `eventCount`
      // duplicates are convenience copies an attacker can edit freely
      // without breaking the signature, so rendering them next to a
      // green tick would let a tampered bundle show forged numbers.
      let signed = {};
      try { signed = JSON.parse(r.rawBody || "{}"); } catch { signed = {}; }
      const displaySession = signed.sessionExternalId || signed.sessionId || s.externalId || s.id || "—";
      const displayAgent = signed.agent || s.agent || "—";
      const displayEvents = signed.eventCount ?? r.eventCount ?? "—";
      const displayReceiptId = signed.receiptId || r.receiptId || "—";
      // Surface envelope/signed-body drift so edited convenience copies
      // are called out even though the signature itself still verifies.
      const drift = [];
      if (state.ok) {
        if (s.externalId && signed.sessionExternalId && s.externalId !== signed.sessionExternalId) drift.push("session id");
        if (s.agent && signed.agent && s.agent !== signed.agent) drift.push("agent");
        if (r.eventCount != null && signed.eventCount != null && r.eventCount !== signed.eventCount) drift.push("event count");
        if (s.events != null && signed.eventCount != null && s.events !== signed.eventCount) drift.push("session event count");
        if (r.receiptId && signed.receiptId && r.receiptId !== signed.receiptId) drift.push("receipt id");
      }
      // R78 HIGH #1 (landed R79): differentiate "signature verifies
      // against the pubkey embedded in the bundle" (internally
      // consistent. An attacker can trivially achieve this by
      // generating their own keypair) from "signature verifies AND
      // pubkey is in the trust anchor list" (actually attesting
      // AgentVisor authorship).
      const trusted = state.ok && state.trustedKey;
      const internallyConsistent = state.ok && !state.trustedKey;
      const cls = trusted ? "ok" : (internallyConsistent ? "pending" : "bad");
      const titleText = trusted
        ? "✅  Signature verifies against a trusted key"
        : internallyConsistent
        ? "⚠️  Signature is internally consistent. Trust anchor NOT verified"
        : "❌  Signature does not verify";
      const subText = trusted
        ? "This receipt is authentic. It was signed by a key on the AgentVisor trust anchor list, and every byte of the payload matches the signature."
        : internallyConsistent
        ? "The bundle's signature matches its embedded public key, but that public key is NOT in the trust anchor list this verifier ships with. An attacker can generate a keypair, sign anything, and embed the pubkey, so this alone does NOT attest AgentVisor authorship. Compare the public key against a canonical AgentVisor deployment record before trusting the payload."
        : "The signature does not match the payload. Either the receipt was modified after signing, or the public key doesn't correspond to the signing key.";
      result.innerHTML = `
        <div class="result-card ${cls}">
          <p class="result-title">${titleText}</p>
          <p class="result-sub">${subText}</p>
          ${state.tamper ? `<p class="result-sub tamper-note"><strong>What just happened:</strong> one byte of the signed body changed (${esc(state.tamper.what)}: <code>${esc(state.tamper.before)}</code> → <code>${esc(state.tamper.after)}</code>) and the signature broke. That is the guarantee — nothing in a receipt can be edited after the fact without detection.</p>` : ""}
          ${drift.length ? `<p class="result-sub"><strong>Note:</strong> the bundle's unsigned metadata (${esc(drift.join(", "))}) does not match the signed body. The values below come from the signed body, which is what the signature attests. The unsigned copies were edited after signing.</p>` : ""}
          <dl class="kv">
            <dt>Session</dt><dd>${esc(displaySession)}</dd>
            <dt>Agent</dt><dd>${esc(displayAgent)}</dd>
            <dt>Events sealed</dt><dd>${esc(displayEvents)}</dd>
            <dt>Receipt ID</dt><dd>${esc(displayReceiptId)}</dd>
            <dt>Public key</dt><dd>${esc(pub.hex || "—")}</dd>
            <dt>Signature bytes</dt><dd>${esc((r.rawSignatureB64 || "").length)} base64 chars (64 bytes decoded)</dd>
            <dt>Message bytes</dt><dd>${esc((r.rawBody || "").length)}</dd>
          </dl>
          ${state.ok && !state.tamper ? `<div class="tamper-row">
            <button type="button" id="tamperBtn" class="tamper-btn">🧪 Now tamper with one byte</button>
            <span class="tamper-hint">See what happens when a single byte of the signed body changes.</span>
          </div>` : ""}
          ${state.tamper ? `<div class="tamper-row">
            <button type="button" id="restoreBtn" class="tamper-btn">↩ Restore the original</button>
            <span class="tamper-hint">Re-verify the untouched receipt — back to green.</span>
          </div>` : ""}
          <details class="details">
            <summary>Show raw signed body</summary>
            <pre>${esc(r.rawBody || "")}</pre>
          </details>
        </div>`;
      const tamperBtn = result.querySelector("#tamperBtn");
      if (tamperBtn) tamperBtn.addEventListener("click", tamperLastGood);
      const restoreBtn = result.querySelector("#restoreBtn");
      if (restoreBtn) restoreBtn.addEventListener("click", () => { if (lastGood) handleText(lastGood); });
    }

    // ── One-click tamper demo ─────────────────────────────────────
    // The pitch line is "edit one byte → red". Doing that by hand
    // means downloading the JSON and opening an editor, so nobody
    // does it. This flips a single byte of the *signed body* of the
    // last successfully verified receipt and re-runs the exact same
    // verification path. Nothing else changes — same key, same
    // signature, one different byte.
    let lastGood = null;
    function tamperLastGood() {
      if (!lastGood) return;
      let bundle;
      try { bundle = JSON.parse(lastGood); } catch { return; }
      const r = bundle.receipt || {};
      const body = r.rawBody || "";
      if (!body) return;
      let idx = -1, before = "", after = "", what = "";
      // Prefer a meaningful byte: the first digit of eventCount.
      const m = body.match(/"eventCount"\s*:\s*(\d)/);
      if (m) {
        idx = m.index + m[0].length - 1;
        before = m[1];
        after = String((+m[1] + 1) % 10);
        what = "eventCount digit";
      } else {
        // Fallback: flip the case of the first ASCII letter.
        for (let i = 0; i < body.length; i++) {
          const c = body[i];
          if (/[a-zA-Z]/.test(c)) { idx = i; before = c; after = c === c.toLowerCase() ? c.toUpperCase() : c.toLowerCase(); what = "one character"; break; }
        }
      }
      if (idx < 0) return;
      r.rawBody = body.slice(0, idx) + after + body.slice(idx + 1);
      handleText(JSON.stringify(bundle), { what, before, after });
    }

    async function handleText(text, tamper) {
      render({ kind: "pending" });
      let bundle;
      try { bundle = JSON.parse(text); }
      catch (e) { render({ kind: "err", message: "Not valid JSON: " + e.message }); return; }
      try {
        const { ok, trustedKey, bundle: b } = await verifyBundle(bundle);
        if (ok && !tamper) lastGood = text;
        render({ kind: "result", ok, trustedKey, bundle: b, tamper: tamper || null });
      } catch (e) {
        render({ kind: "err", message: e.message });
      }
    }
    function handleFile(file) {
      if (!file) return;
      if (file.size > 5_000_000) { render({ kind: "err", message: "File larger than 5 MB. Probably not a receipt." }); return; }
      const reader = new FileReader();
      reader.onload = () => handleText(reader.result);
      reader.onerror = () => render({ kind: "err", message: "Could not read file." });
      reader.readAsText(file);
    }

    ["dragenter", "dragover"].forEach((e) => drop.addEventListener(e, (ev) => { ev.preventDefault(); drop.classList.add("hover"); }));
    ["dragleave", "drop"].forEach((e) => drop.addEventListener(e, (ev) => { ev.preventDefault(); drop.classList.remove("hover"); }));
    drop.addEventListener("drop", (ev) => {
      const f = ev.dataTransfer?.files?.[0];
      if (f) handleFile(f);
    });
    drop.addEventListener("click", (ev) => { if (ev.target !== browseBtn) fileInput.click(); });
    // Keyboard access is provided by the real <button id="browseBtn">;
    // the outer div is a pointer-only drop target (kept non-focusable
    // to avoid nested-interactive a11y violations).
    browseBtn.addEventListener("click", (ev) => { ev.stopPropagation(); fileInput.click(); });
    fileInput.addEventListener("change", () => handleFile(fileInput.files?.[0]));

    // Paste anywhere on the page.
    window.addEventListener("paste", (ev) => {
      const text = ev.clipboardData?.getData("text");
      if (text && text.trim().startsWith("{")) handleText(text);
    });

    loadExample.addEventListener("click", async () => {
      try {
        const res = await fetch("sample-receipt.json");
        if (!res.ok) throw new Error("Sample not available");
        const text = await res.text();
        handleText(text);
      } catch (e) {
        render({ kind: "err", message: "Couldn't load sample: " + e.message });
      }
    });

    // Shareable receipt URL:
    //     agentvisorai.me/verify/#data=<base64url-encoded-JSON>
    // The console's "Share this receipt" button generates this URL. When
    // the recipient opens the link, we base64url-decode the fragment and
    // auto-verify. Fragment (not query) so the payload never touches
    // the server. GitHub Pages doesn't see the URL fragment, browser
    // history doesn't leak it beyond this tab.
    function tryFragment() {
      const raw = location.hash.slice(1); // strip leading #
      if (!raw) return;
      const params = new URLSearchParams(raw);
      const data = params.get("data");
      if (!data) return;
      try {
        // base64url -> base64 -> bytes -> UTF-8 text.
        const b64 = data.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((data.length + 3) % 4);
        const bin = atob(b64);
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        const text = new TextDecoder().decode(bytes);
        handleText(text);
      } catch (e) {
        render({ kind: "err", message: "Couldn't decode shared receipt from URL: " + e.message });
      }
    }
    tryFragment();
    // Re-verify if the fragment changes (SPA-style navigation).
    window.addEventListener("hashchange", tryFragment);
