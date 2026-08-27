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
