# Video pipeline changelog

## v5 — cinematic edit (2026-08-27)

Iteration on the raw v4 walkthrough. Adds motion, focus, and a
proper "click happens on-screen" moment for the /verify scene.

**New:**

* **Ken Burns zoom** on all 3 UI scenes via CSS animation on
  `<body>`. Slow 1.00 → 1.055 scale over the scene duration.
* **Radial vignette** darkening the corners on UI scenes so the eye
  lands on the middle third.
* **Pulse-glow highlight** on target elements (the $8,400 cell in
  scene 5, the ✅ verified card in scene 6). Three ~1.6s breathing
  cycles land attention right when the caption reads the callback.
* **Live click in scene 6**: shows the empty drop zone → mouse
  moves visibly → click → verified card materializes. No more
  arriving at a pre-verified state.
* **Timed caption gates** in `compose.sh`: scene 6's caption uses
  `enable='gte(t,2.5)'` so it only appears after the click. Matches
  what the viewer is seeing.
* **Pre-warmed auth** via a two-phase pattern:
  1. Warm context: log in + wait for storage state.
  2. Recorded context: restore storage, navigate directly to the
     target hash. Recording starts on a fully-loaded page.
  Fixes the "loading skeleton visible for 1-2s at scene start"
  bug that plagued v4.

**Metrics:**

* Duration: 43.7s (same as v4)
* Size: 7.5 MB (up from 3.4 MB — motion needs more bits)
* Resolution: 1920×1080 H.264, 30fps
* Regeneration: ~4 min total from scratch

## v4 — initial pipeline (2026-08-27)

First draft with title cards + UI scenes + basic captions.

## v6 — copy + typography pass (2026-08-27)

Lowered cognitive load per frame. Every title card now has less
text, sharper copy, and stagger-animates line by line instead of
fading in as a block.

**Copy changes:**

* Removed redundant "AGENTVISOR AI" kickers on scenes 1, 3, 7 —
  the persistent brand bar at the bottom already says it.
* Scene 1: "AI agents are making real decisions — with real money."
  → "AI agents make real decisions with real money." (removed
  em-dash + "are making" progressive tense).
* Scene 2: "An agent buys the wrong vendor. $8,400 gone. Nobody
  signed off." → "Bad tool call. $8,400 gone." (12 words → 5 + a
  number). Punch lands harder.
* Scene 3: "Every agent decision, captured. Enforced. Signed." →
  "Every decision: captured. enforced. signed." (colon list
  rhythm, lowercase for tenet feel).
* Scene 4 caption: "Every session — every tool call — captured in
  real time." (abstract) → "32 sessions · 7 blocked · $31,840
  saved." (concrete numbers matching the KPI tiles on screen).

**Typography:**

* Line-by-line reveal animation. Each `<br>`-separated line in the
  headline gets `<span class="line">` with a stagger animation-delay
  (0.15s + 0.18s per line). Eye's rhythm matches text's rhythm.
* Subline delay computed from `lines.length` so multi-line
  headlines still land before the sub does.

**Metrics:**

* Duration: 44.1s (up 0.4s from v5 — line staggers cost nothing but
  the overall pacing is unchanged)
* Size: 7.4 MB (unchanged)

