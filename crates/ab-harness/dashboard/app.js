/*
 * AgentBridge dashboard app.
 * Polls /api/v1/dashboard/{stats,sessions} every REFRESH_MS and re-renders.
 * No framework: vanilla DOM.
 */

'use strict';

const REFRESH_MS = 5000;
const FETCH_TIMEOUT_MS = 10000;
const STATS_URL = '/api/v1/dashboard/stats';
const LIST_URL = '/api/v1/dashboard/sessions';
const DETAIL_URL = (id) => `/api/v1/dashboard/sessions/${encodeURIComponent(id)}`;

const state = {
  paused: false,
  filterStatus: 'all',
  filterWorkflow: 'all',
  timer: null,
  activeSession: null,
  lastRefreshMs: 0,
  // Monotonic id incremented on every refresh trigger. Late fetches whose
  // generation does not match the latest gen are discarded — this stops
  // a slow stats/list response from overwriting a fresher one issued
  // after a filter change or a rapid pause/resume.
  refreshGen: 0,
  // AbortController for the drawer's in-flight detail fetch, so a filter
  // click or drawer close does not leak an old response into a newly
  // opened session.
  drawerAbort: null,
};

// ---- Utilities ------------------------------------------------------

function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v === null || v === undefined || v === false) continue;
      if (k === 'class') node.className = v;
      else if (k === 'text') node.textContent = v;
      else if (k.startsWith('on') && typeof v === 'function') {
        node.addEventListener(k.slice(2).toLowerCase(), v);
      } else if (v === true) {
        node.setAttribute(k, '');
      } else {
        node.setAttribute(k, v);
      }
    }
  }
  for (const child of children) {
    if (child == null || child === false) continue;
    if (typeof child === 'string' || typeof child === 'number') {
      node.appendChild(document.createTextNode(String(child)));
    } else {
      node.appendChild(child);
    }
  }
  return node;
}

function fmtInt(n) {
  if (n == null || Number.isNaN(n)) return '—';
  return new Intl.NumberFormat().format(n);
}

function fmtUsdFromMicros(micros) {
  if (micros == null || Number.isNaN(micros)) return '—';
  const dollars = micros / 1_000_000;
  if (dollars === 0) return '$0.00';
  if (dollars < 0.01) return '<$0.01';
  return dollars.toLocaleString(undefined, {
    style: 'currency',
    currency: 'USD',
    maximumFractionDigits: dollars < 1 ? 4 : 2,
  });
}

function fmtAge(ms) {
  if (!ms) return '—';
  const seconds = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h ago`;
  return `${Math.round(seconds / 86400)}d ago`;
}

function fmtWhen(ms) {
  if (!ms) return '—';
  const d = new Date(ms);
  return d.toLocaleString();
}

function shortId(id) {
  if (!id) return '—';
  if (id.length <= 20) return id;
  return `${id.slice(0, 12)}…${id.slice(-6)}`;
}

async function fetchJson(url, { signal } = {}) {
  // Compose the caller signal (if any) with our own timeout: aborting
  // either one aborts the fetch. Doing this via a dedicated controller
  // means the 10s guard fires even when the caller passed a signal —
  // an earlier version silently disabled the timeout in that case.
  const controller = new AbortController();
  const onCallerAbort = () => controller.abort(signal?.reason);
  if (signal) {
    if (signal.aborted) {
      controller.abort(signal.reason);
    } else {
      signal.addEventListener('abort', onCallerAbort, { once: true });
    }
  }
  const timeout = window.setTimeout(
    () => controller.abort(new Error('fetch timeout')),
    FETCH_TIMEOUT_MS,
  );
  try {
    const response = await fetch(url, {
      headers: { accept: 'application/json' },
      credentials: 'same-origin',
      signal: controller.signal,
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status} on ${url}`);
    }
    return await response.json();
  } finally {
    window.clearTimeout(timeout);
    if (signal) signal.removeEventListener('abort', onCallerAbort);
  }
}

// ---- Stats strip ----------------------------------------------------

function renderStats(stats) {
  const bindings = {
    session_count: fmtInt(stats.session_count),
    open_count: fmtInt(stats.open_count),
    closed_count: fmtInt(stats.closed_count),
    capture_failed_count: fmtInt(stats.capture_failed_count),
    cost_display: fmtUsdFromMicros(stats.total_cost_usd_micros),
    cost_micros_raw: fmtInt(stats.total_cost_usd_micros),
    tokens_total: fmtInt(
      (stats.total_prompt_tokens ?? 0) + (stats.total_completion_tokens ?? 0),
    ),
    total_prompt_tokens: fmtInt(stats.total_prompt_tokens),
    total_completion_tokens: fmtInt(stats.total_completion_tokens),
    total_tool_calls: fmtInt(stats.total_tool_calls),
    total_tool_allowed: fmtInt(stats.total_tool_allowed),
    total_tool_blocked: fmtInt(stats.total_tool_blocked),
    workflow_signed: fmtInt(stats.workflow_signed),
    workflow_unsigned: fmtInt(stats.workflow_unsigned),
    workflow_signed_pct: (() => {
      const total = (stats.workflow_signed ?? 0) + (stats.workflow_unsigned ?? 0);
      if (!total) return '—';
      const pct = Math.round((100 * (stats.workflow_signed ?? 0)) / total);
      return `${pct}%`;
    })(),
  };
  for (const [key, value] of Object.entries(bindings)) {
    const nodes = document.querySelectorAll(`[data-stat="${key}"]`);
    nodes.forEach((node) => {
      node.textContent = value;
    });
  }
}

// ---- Sessions table -------------------------------------------------

function statusOf(s) {
  if (s.capture_failed) return { label: 'Capture failed', className: 'failed' };
  if (s.close_complete) return { label: 'Sealed', className: 'closed' };
  if (s.closed) return { label: 'Closing', className: 'closed' };
  // Recovered ATIF sessions have `artifact_committed=1` but `closed=0`
  // — `open=false` catches that; treat as sealed for the UI.
  if (!s.open) return { label: 'Sealed', className: 'closed' };
  return { label: 'Live', className: 'open' };
}

function stopReasonCaption(s) {
  if (!s.stop_reason || s.stop_reason === 'unknown') return '—';
  return s.stop_reason;
}

function renderSessions(rows) {
  const body = document.getElementById('session-body');
  body.innerHTML = '';
  const empty = document.getElementById('empty-hint');
  if (!rows.length) {
    empty.hidden = false;
    return;
  }
  empty.hidden = true;
  for (const s of rows) {
    const status = statusOf(s);
    const identityText = s.identity && s.identity.instance_uid
      ? `${s.identity.charter} · ${shortId(s.identity.instance_uid)}`
      : '—';
    const blockRatio = s.tool_blocked > 0
      ? el('div', { class: 'block-ratio' }, `${s.tool_blocked} blocked`)
      : null;
    const tr = el(
      'tr',
      {
        onclick: () => openSession(s.id),
        'data-session-id': s.id,
      },
      el(
        'td',
        { class: 'col-id' },
        el('span', { class: 'sid', title: s.id }, shortId(s.id)),
        el('span', { class: 'wf' }, s.workflow),
        el('div', { class: 'identity' }, identityText),
      ),
      el(
        'td',
        null,
        el(
          'span',
          { class: `status ${status.className}` },
          el('span', { class: 'status-dot' }),
          status.label,
        ),
      ),
      el(
        'td',
        { class: 'col-num' },
        String(s.tool_calls),
        blockRatio,
      ),
      el(
        'td',
        { class: 'col-num' },
        `${fmtInt(s.prompt_tokens)} / ${fmtInt(s.completion_tokens)}`,
      ),
      el('td', { class: 'col-num' }, fmtUsdFromMicros(s.cost_usd_micros)),
      el(
        'td',
        null,
        el('span', { class: 'age', title: fmtWhen(s.last_activity_ms) }, fmtAge(s.last_activity_ms)),
      ),
      el('td', { class: 'stop-reason' }, stopReasonCaption(s)),
      el(
        'td',
        { class: 'col-actions' },
        el(
          'button',
          {
            class: 'pill-btn',
            onclick: (event) => {
              event.stopPropagation();
              openSession(s.id);
            },
          },
          'Details',
        ),
      ),
    );
    body.appendChild(tr);
  }
}

// ---- Session drawer -------------------------------------------------

function highlightJson(value) {
  const json = JSON.stringify(value, null, 2);
  const escaped = json
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
  return escaped.replace(
    /("(?:\\.|[^"\\])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g,
    (match, _g1, colon) => {
      if (colon) return `<span class="k">${match}</span>`;
      if (/^"/.test(match)) return `<span class="s">${match}</span>`;
      // Round-28 F6: booleans/null get a distinct class from numbers
      // so the receipt drawer visually differentiates them. Previously
      // the boolean/null branch and the numeric else-branch both
      // emitted class="n" (copy-paste from the numeric case).
      if (/^(true|false|null)$/.test(match)) return `<span class="b">${match}</span>`;
      return `<span class="n">${match}</span>`;
    },
  );
}

async function openSession(id) {
  const drawer = document.getElementById('session-drawer');
  const body = document.getElementById('drawer-body');
  const titleEl = document.getElementById('drawer-title');
  // Cancel any in-flight detail fetch from a previous session so a slow
  // response cannot bleed into the freshly-opened drawer.
  if (state.drawerAbort) {
    state.drawerAbort.abort();
  }
  const controller = new AbortController();
  state.drawerAbort = controller;
  state.activeSession = id;
  drawer.hidden = false;
  titleEl.textContent = id;
  body.innerHTML = '<p class="muted">Loading…</p>';
  try {
    const detail = await fetchJson(DETAIL_URL(id), { signal: controller.signal });
    // Guard against the user opening a different session before this
    // completed — the drawer already moved on and rendering a stale
    // detail would corrupt the view.
    if (state.activeSession !== id) return;
    renderSessionDetail(detail);
  } catch (err) {
    if (state.activeSession !== id || controller.signal.aborted) return;
    body.innerHTML = '';
    body.appendChild(
      el('p', { class: 'muted' }, `Could not load session detail: ${err.message}`),
    );
  }
}

function closeDrawer() {
  const drawer = document.getElementById('session-drawer');
  drawer.hidden = true;
  state.activeSession = null;
  if (state.drawerAbort) {
    state.drawerAbort.abort();
    state.drawerAbort = null;
  }
}

function renderSessionDetail(detail) {
  const s = detail.summary;
  const body = document.getElementById('drawer-body');
  body.innerHTML = '';

  const status = statusOf(s);
  body.appendChild(
    el(
      'div',
      { class: 'kv' },
      el('dt', null, 'Status'),
      el(
        'dd',
        null,
        el(
          'span',
          { class: `status ${status.className}` },
          el('span', { class: 'status-dot' }),
          status.label,
        ),
      ),
      el('dt', null, 'Workflow'), el('dd', null, s.workflow),
      el('dt', null, 'Last activity'), el('dd', null, fmtWhen(s.last_activity_ms)),
      el('dt', null, 'Stop reason'), el('dd', null, stopReasonCaption(s)),
    ),
  );

  body.appendChild(el('h4', null, 'Agent identity'));
  body.appendChild(
    el(
      'div',
      { class: 'kv' },
      el('dt', null, 'Instance UID'), el('dd', null, s.identity.instance_uid || '—'),
      el('dt', null, 'Charter'), el('dd', null, s.identity.charter || '—'),
      el('dt', null, 'Version'), el('dd', null, s.identity.version || '—'),
      el('dt', null, 'TTL remaining'),
      el(
        'dd',
        null,
        s.identity.ttl_remaining_s != null ? `${fmtInt(s.identity.ttl_remaining_s)} s` : '—',
      ),
    ),
  );

  body.appendChild(el('h4', null, 'Totals'));
  body.appendChild(
    el(
      'div',
      { class: 'kv' },
      el('dt', null, 'Tool calls'), el('dd', null, fmtInt(s.tool_calls)),
      el('dt', null, 'Tool allowed'), el('dd', null, fmtInt(s.tool_allowed)),
      el('dt', null, 'Tool blocked'), el('dd', null, fmtInt(s.tool_blocked)),
      el('dt', null, 'Prompt tokens'), el('dd', null, fmtInt(s.prompt_tokens)),
      el('dt', null, 'Completion tokens'), el('dd', null, fmtInt(s.completion_tokens)),
      el('dt', null, 'Cached tokens'), el('dd', null, fmtInt(s.cached_tokens)),
      el('dt', null, 'Cost'), el('dd', null, `${fmtUsdFromMicros(s.cost_usd_micros)} (${fmtInt(s.cost_usd_micros)} µUSD)`),
      el('dt', null, 'Pending jobs'), el('dd', null, fmtInt(s.pending_jobs)),
      el('dt', null, 'Active streams'), el('dd', null, fmtInt(s.active_streams)),
    ),
  );

  body.appendChild(el('h4', null, 'Provenance'));
  body.appendChild(
    el(
      'div',
      { class: 'kv' },
      el('dt', null, 'Chain events'), el('dd', null, fmtInt(detail.chain?.count)),
      el('dt', null, 'Chain head'),
      el('dd', null, detail.chain?.head_hex ? shortId(detail.chain.head_hex) : '—'),
      el('dt', null, 'Artifact committed'),
      el('dd', null, s.artifact_committed ? 'yes' : 'no'),
      el('dt', null, 'Close complete'), el('dd', null, s.close_complete ? 'yes' : 'no'),
      el('dt', null, 'Capture failed'),
      el(
        'dd',
        null,
        s.capture_failed ? el('span', { class: 'fail' }, 'yes') : 'no',
      ),
      el('dt', null, 'ATIF artifact'), el('dd', null, detail.atif_filename || '—'),
    ),
  );

  body.appendChild(el('h4', null, 'Receipt'));
  if (detail.receipt) {
    const pre = document.createElement('pre');
    pre.className = 'receipt-block';
    pre.innerHTML = highlightJson(detail.receipt);
    body.appendChild(pre);
  } else {
    body.appendChild(
      el(
        'p',
        { class: 'muted' },
        'No receipt yet — will appear once the session is closed.',
      ),
    );
  }
}

// ---- Refresh loop ---------------------------------------------------

function currentListUrl() {
  const params = new URLSearchParams();
  if (state.filterStatus !== 'all') params.set('status', state.filterStatus);
  if (state.filterWorkflow !== 'all') params.set('workflow', state.filterWorkflow);
  const qs = params.toString();
  return qs ? `${LIST_URL}?${qs}` : LIST_URL;
}

async function refresh() {
  if (state.paused) return;
  const gen = ++state.refreshGen;
  try {
    const [stats, list] = await Promise.all([
      fetchJson(STATS_URL),
      fetchJson(currentListUrl()),
    ]);
    // A newer refresh has already started (or a filter change bumped
    // the generation) — this response is stale and would clobber the
    // fresher one, so drop it silently.
    if (gen !== state.refreshGen) return;
    renderStats(stats);
    renderSessions(list.sessions || []);
    setLive({ ok: true });
    if (state.activeSession) {
      const sid = state.activeSession;
      try {
        const detail = await fetchJson(DETAIL_URL(sid));
        if (state.activeSession !== sid || gen !== state.refreshGen) return;
        renderSessionDetail(detail);
      } catch (_err) {
        // Session likely evicted or the user closed the drawer while
        // the fetch was in flight; leave the drawer as-is.
      }
    }
  } catch (err) {
    if (gen !== state.refreshGen) return;
    setLive({ error: err.message });
  }
  state.lastRefreshMs = Date.now();
}

function setLive({ ok, error }) {
  const badge = document.getElementById('live-badge');
  const text = document.getElementById('live-text');
  if (state.paused) {
    badge.className = 'live paused';
    text.textContent = 'Paused';
    return;
  }
  if (ok) {
    badge.className = 'live';
    text.textContent = 'Live · updated just now';
  } else if (error) {
    badge.className = 'live errored';
    text.textContent = `Error: ${error}`;
  }
}

function togglePause() {
  state.paused = !state.paused;
  document.getElementById('pause-btn').textContent = state.paused ? 'Resume' : 'Pause';
  setLive(state.paused ? {} : { ok: true });
  if (!state.paused) refresh();
}

// ---- Wire up --------------------------------------------------------

function setupFilters() {
  document.querySelectorAll('[data-filter-status]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const value = btn.dataset.filterStatus;
      state.filterStatus = value;
      document.querySelectorAll('[data-filter-status]').forEach((other) => {
        const on = other.dataset.filterStatus === value;
        other.classList.toggle('on', on);
        other.setAttribute('aria-selected', on ? 'true' : 'false');
      });
      refresh();
    });
  });
  document.querySelectorAll('[data-filter-workflow]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const value = btn.dataset.filterWorkflow;
      state.filterWorkflow = value;
      document.querySelectorAll('[data-filter-workflow]').forEach((other) => {
        const on = other.dataset.filterWorkflow === value;
        other.classList.toggle('on', on);
        other.setAttribute('aria-selected', on ? 'true' : 'false');
      });
      refresh();
    });
  });
}

function setupDrawer() {
  document.querySelectorAll('[data-drawer-close]').forEach((btn) => {
    btn.addEventListener('click', closeDrawer);
  });
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') closeDrawer();
  });
}

function init() {
  setupFilters();
  setupDrawer();
  document.getElementById('pause-btn').addEventListener('click', togglePause);
  refresh();
  state.timer = window.setInterval(refresh, REFRESH_MS);
  window.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') refresh();
  });
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
