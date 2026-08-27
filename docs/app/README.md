# AgentVisor AI Console

The console served at `agentvisorai.me/app/` is a real multi-tenant SPA:
sign in, view your fleet of policed agent sessions, add & rotate deployment
ingest tokens, and inspect any session's event stream and signed receipt.

## Two operating modes

The console is built as a client-side app with a swappable data source. The
switch lives at the top of [`index.html`](./index.html):

```html
<script>
  window.MOCK_MODE = true;
  window.API_BASE = "";
</script>
```

### Mock mode (default — investor / preview use)

When `MOCK_MODE=true` the console runs against built-in **Northwind Traders**
fixtures baked into [`datasource.js`](./datasource.js). Anyone landing on the
URL sees a fully populated workspace: 2 deployments, 7 sessions with events
and receipts, headline KPIs. Any email + password combination signs you in.

This is what powers the investor pitch until the backend is deployed to
production. Mock mode also ships two investor-facing extras (both inert in
live mode):

- **Guided tour** ([`tour.js`](./tour.js)) — a six-step spotlight walkthrough
  of the money story: prevented losses → the blocked session → the exact
  blocked event → the signed receipt → the public verifier. Launched from
  the floating "See the full flow" pill, the command palette, or the
  `/app/?tour=1` deep link used by the landing-page CTA.
- **Simulate an attack** (Overview header, also in the palette) — stages a
  live blocked payment: an in-progress purchase session appears, the
  payment gets blocked ~3 s later, and every stat, chart, and receipt on
  screen catches up in real time.
- **Onboarding checklist** (Overview, fresh workspaces) — after signup a
  four-step "Getting started" card (workspace → daemon → sessions →
  first block) ticks itself live as the fresh-workspace simulation
  progresses, without a reload.

### Live mode

Set:

```js
window.MOCK_MODE = false;
window.API_BASE = "https://api.agentvisorai.me/api/v1";
```

…and the same UI now talks to the real hosted backend defined in [`../../server/`](../../server/).
Signup / login create real users and orgs. Deployments mint real ingest
tokens. Session data is streamed by real `agentvisord` daemons.

See [`server/README.md`](../../server/README.md) for the full deploy runbook.

## Structure

| File | Purpose |
|---|---|
| `index.html` | Entry, sets `MOCK_MODE`, mounts `#app` |
| `styles.css` | Design tokens + shell / auth / cards / tables |
| `datasource.js` | Swappable data layer — `MockDataSource` vs `ApiDataSource` |
| `app.js` | Hash router, auth, view renderers |
| `pitch/` | The original scripted narrative walkthrough (kept for reference) |

## Views

- `#/login`, `#/signup` — unauth
- `#/overview` — 24h fleet KPIs + recent sessions
- `#/sessions` — full list
- `#/sessions/:id` — event stream + signed receipt for one session
- `#/deployments` — create, rotate token, delete
- `#/settings` — org/user metadata + mock-mode escape hatch

## The scripted pitch demo

The linear investor walkthrough previously served at this URL now lives at
[`pitch/`](./pitch/). It's a scripted narrative — Northwind Traders onboards,
first agent session flows through, a rogue purchase order is blocked, a
signed receipt is minted, and audit evidence is exported. Useful when the
audience needs the story, not a playground.
