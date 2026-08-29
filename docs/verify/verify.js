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

    // R193 F1: enforce identity binding — the receipt.body's
    // `key_id` field (a 32-hex-char prefix of SHA-256(pubkey))
    // must derive from the pubkey we're verifying against.
    // Rust `Receipt::verify_embedded()` at
    // crates/av-receipts/src/receipt.rs:371-374 refuses
    // `KeyMismatch` when derived_id != body.key_id. Prior JS
    // verifier accepted a receipt whose body claimed a
    // different `key_id` than the pubkey in the bundle
    // (attribution confusion: attacker with signing key S_a
    // signs a body claiming `key_id: <victim's_id>`, embeds
    // their own pubkey P_a, Ed25519 sig verifies, but an
    // auditor reading body.key_id sees the victim's key
    // rather than the actual signer). Same class as R190 —
    // Rust-vs-JS semantic parity gap. v1 backward-compat: if
    // body.key_id is missing (sample-receipt.json legacy),
    // skip the check.
    async function sha256Hex(bytes) {
      const digest = await crypto.subtle.digest("SHA-256", bytes);
      return Array.from(new Uint8Array(digest))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
    }
    async function deriveKeyIdFromPubHex(hex) {
      const bytes = hex2bytes(hex);
      const full = await sha256Hex(bytes);
      return full.slice(0, 32);
    }

    // R190 F1: build the exact byte message the Rust `av-receipts`
    // crate signs. Rust `signing_message(receipt_version, canonical)`
    // (crates/av-receipts/src/receipt.rs:50-64) dispatches on
    // `receipt_version`:
    //   * v1 → bare canonical bytes (legacy wire format)
    //   * v2 → RECEIPT_DOMAIN_TAG_V2 (b"agentvisor-receipt-v2\0",
    //          22 bytes) || u64_be(canonical.len()) || canonical
    // Rust defaults `RECEIPT_VERSION = 2` (receipt.rs:30), so every
    // modern daemon posts v2 receipts. Prior JS verifier used
    // TextEncoder().encode(rawBody) unconditionally — that's v1
    // semantics only. A legitimately-signed v2 receipt would show
    // "Signature does not verify" on this page. Now: parse
    // receipt.body to find `receipt_version`, dispatch to the
    // correct framing.
    const RECEIPT_DOMAIN_TAG_V2 = new TextEncoder().encode("agentvisor-receipt-v2\0");
    function receiptSigningMessage(rawBody) {
      const canonical = new TextEncoder().encode(rawBody);
      let receiptVersion = 1;
      try {
        const parsed = JSON.parse(rawBody);
        if (typeof parsed.receipt_version === "number") {
          receiptVersion = parsed.receipt_version;
        }
      } catch {
        // Body not valid JSON — leave as v1. The Ed25519 verify
        // will then fail and the UI will report "Signature does
        // not verify" which is the correct verdict for garbage.
      }
      if (receiptVersion === 1) return canonical;
      if (receiptVersion === 2) {
        const lenBytes = new Uint8Array(8);
        const view = new DataView(lenBytes.buffer);
        view.setBigUint64(0, BigInt(canonical.length), false); // big-endian
        const out = new Uint8Array(RECEIPT_DOMAIN_TAG_V2.length + 8 + canonical.length);
        out.set(RECEIPT_DOMAIN_TAG_V2, 0);
        out.set(lenBytes, RECEIPT_DOMAIN_TAG_V2.length);
        out.set(canonical, RECEIPT_DOMAIN_TAG_V2.length + 8);
        return out;
      }
      // Unknown version — return an obviously-wrong message so
      // verify returns false. Better to fail-closed than to guess
      // a future framing.
      return new Uint8Array(0);
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
        throw new Error("This browser doesn't support Web Crypto Ed25519. Try Chrome 113+, Firefox 130+, or Safari 17+. Or run the CLI: node tools/verify-receipt.mjs receipt.json");
      }
      const msg = receiptSigningMessage(r.rawBody);
      const sig = b64ToBytes(r.rawSignatureB64);
      const ok = await crypto.subtle.verify("Ed25519", key, sig, msg);
      // R193 F1: even when Ed25519 sig verifies, refuse the receipt
      // if body claims a `key_id` that doesn't derive from the
      // embedded pubkey. Mirrors Rust `verify_embedded()` at
      // receipt.rs:371-374 which returns `KeyMismatch` in that
      // exact shape. v1 legacy receipts (sample-receipt.json)
      // have no body.key_id — skip the check to preserve backward
      // compat.
      let keyIdOk = true;
      let pubkeyOk = true;
      if (ok) {
        try {
          const parsed = JSON.parse(r.rawBody);
          if (typeof parsed.key_id === "string" && parsed.key_id.length > 0) {
            const derived = await deriveKeyIdFromPubHex(pub.hex.toLowerCase());
            if (derived !== parsed.key_id.toLowerCase()) keyIdOk = false;
          }
          // R199 F1: enforce body.public_key_b64 ↔ bundle.publicKey.hex
          // binding. Rust `verify_embedded()` at
          // crates/av-receipts/src/receipt.rs:365-368 uses
          // body.public_key_b64 AS the verifying pubkey (self-
          // contained offline verification). Our JS verifier uses
          // bundle.publicKey.hex (envelope). If those refer to
          // different 32-byte keys, an attacker with signing key
          // K_a can sign a body whose public_key_b64 claims
          // K_victim while the bundle's pubkey hex is K_a — sig
          // verifies (JS uses K_a from bundle), R193 passes if
          // body.key_id = derive(K_a), but an auditor decoding
          // body.public_key_b64 sees K_victim. Attribution split
          // sibling of R193. Fix: refuse on mismatch. Legacy
          // v1 receipts (sample-receipt.json) have no
          // public_key_b64 in body — skip.
          if (typeof parsed.public_key_b64 === "string" && parsed.public_key_b64.length > 0) {
            try {
              const bodyPubBytes = b64ToBytes(parsed.public_key_b64);
              const bundlePubBytes = hex2bytes(pub.hex);
              if (bodyPubBytes.length !== bundlePubBytes.length ||
                  !bodyPubBytes.every((b, i) => b === bundlePubBytes[i])) {
                pubkeyOk = false;
              }
            } catch {
              pubkeyOk = false;
            }
          }
        } catch {
          // Body not JSON — sig either verified over structured
          // bytes or it didn't. Leave both checks true.
        }
      }
      const trustedKey = ok && keyIdOk && pubkeyOk && TRUSTED_RECEIPT_KEYS.has(pub.hex.toLowerCase());
      return { ok: ok && keyIdOk && pubkeyOk, trustedKey, bundle };
    }

    // R91 F4: only expose the mutable Set when the ?ci-drill=1
    // URL flag is set. Prior shape unconditionally exposed the
    // Set on window so the Playwright CI drill (server/scripts/
    // verify-page-drill.mjs) could `page.evaluate` a per-test
    // trusted pubkey. But that exposure is a same-origin bypass
    // for the R78/R79 trust-anchor pinning: any script loaded
    // by the docs Pages source (persistent XSS, future
    // analytics tag, marketing-snippet drop-in) could call
    // window.TRUSTED_RECEIPT_KEYS.add("<attacker pubkey>") and
    // verifyBundle would happily green-light a forged bundle.
    // Fix: gate the exposure on ?ci-drill=1, which the drill
    // script sets when it navigates the page and which is
    // invisible in normal production traffic. Preserves the CI
    // guard while shipping production without the exposure.
    if (
      typeof window !== "undefined" &&
      typeof window.location !== "undefined" &&
      /(?:\?|&)ci-drill=1(?:&|$)/.test(window.location.search || "")
    ) {
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
      // R82 F4: match the FULL run of digits and tamper the LAST one.
      // Prior shape matched a single leading digit (`(\d)`) and
      // incremented it — on `"eventCount":90` this produced
      // `"eventCount":00` (JSON.parse rejects; UI shows "—") and
      // on `12` it flipped to `22` (+10, not +1), undermining the
      // "single byte matters" tamper narrative. Now `\d+` captures
      // the full integer, we tamper the LAST digit only, and the
      // JSON stays valid across any count.
      const m = body.match(/"eventCount"\s*:\s*(\d+)/);
      if (m) {
        idx = m.index + m[0].length - 1;
        before = body[idx];
        after = String((+before + 1) % 10);
        what = "eventCount last digit";
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
      if (f) { handleFile(f); return; }
      // Dragged *text* (a receipt selected in a mail/Slack window)
      // has no files — it used to be dropped silently. Treat it like
      // a paste, with the same 5 MB cap.
      const text = ev.dataTransfer?.getData("text") || "";
      if (!text.trim()) return;
      if (text.length > 5_000_000) { render({ kind: "err", message: "Dropped text larger than 5 MB. Probably not a receipt." }); return; }
      handleText(text);
    });
    drop.addEventListener("click", (ev) => { if (ev.target !== browseBtn) fileInput.click(); });
    // Keyboard access is provided by the real <button id="browseBtn">;
    // the outer div is a pointer-only drop target (kept non-focusable
    // to avoid nested-interactive a11y violations).
    browseBtn.addEventListener("click", (ev) => { ev.stopPropagation(); fileInput.click(); });
    fileInput.addEventListener("change", () => handleFile(fileInput.files?.[0]));

    // Paste anywhere on the page.
    // R115 F2: cap the paste size to match the file-drop 5 MB
    // limit. Prior shape passed raw clipboard bytes to
    // handleText → JSON.parse on the main thread — a recipient
    // who accidentally pasted a giant blob (a copied file, a
    // large log, hostile data from a link) would freeze the
    // tab on the synchronous parse. File-drop and URL fragment
    // paths already have this cap; paste was the missing spot.
    window.addEventListener("paste", (ev) => {
      const text = ev.clipboardData?.getData("text");
      if (!text || !text.trim().startsWith("{")) return;
      if (text.length > 5_000_000) {
        render({ kind: "err", message: "Pasted input larger than 5 MB. Probably not a receipt." });
        return;
      }
      handleText(text);
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

    // The buttons ship disabled in the HTML: on a slow CDN this script
    // arrives noticeably after first paint, and a click on the not-yet-
    // wired buttons silently did nothing (the skeleton-phase dead-
    // button class — caught by the venue-wifi rehearsal in CI). Enable
    // only now that every handler above is attached.
    browseBtn.disabled = false;
    loadExample.disabled = false;

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
      // R120 F3: mirror the paste-path 5 MB cap (R115 F2).
      // R115 F2's comment claimed the fragment path was already
      // capped, but grep showed only file-drop (line 253) and
      // paste (line 284) enforced 5_000_000. A hostile shared
      // link (agentvisorai.me/verify/#data=<multi-MB base64>)
      // synchronously blocked the main thread on atob + JSON.parse
      // — same self-inflicted-tab-freeze class R115 F2 closed on
      // paste. The base64 encoding is ~4/3 the raw byte length,
      // and the sample-receipt is ~2 kB, so 5 MB base64 (~3.7 MB
      // raw) is orders of magnitude above legitimate receipts.
      if (data.length > 5_000_000) {
        render({
          kind: "err",
          message:
            "Shared receipt in URL is larger than 5 MB. Probably not a receipt.",
        });
        return;
      }
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
