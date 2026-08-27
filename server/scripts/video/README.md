# Investor mockup video pipeline

Reproducible 43-second walkthrough of the AgentVisor console for the
pitch. Renders against the live site at https://agentvisorai.me so it
always reflects what an investor visiting the URL would see.

## Requirements

* Node 20+ with `playwright` installed (already a devDependency of the
  `server/` workspace).
* `ffmpeg` on `PATH` (Homebrew: `brew install ffmpeg`).
* macOS: uses `/System/Library/Fonts/Supplemental/Arial Bold.ttf` for
  burned-in captions. On Linux, edit `compose.sh` to point at any
  installed TTF (Fira Sans / DejaVu Sans / Inter).

## Regenerate

```sh
# From server/ so playwright resolves.
cd server
node scripts/video/record-scenes.mjs   # ~90s, writes /tmp/video-v4/scenes/*.webm
bash scripts/video/compose.sh           # ~90s, writes /tmp/video-v4/agentvisor-mockup-v4.mp4
```

Result: `/tmp/video-v4/agentvisor-mockup-v4.mp4` — 43s @ 1920×1080 H.264,
~3.4 MB.

## Uploading to GitHub for a shareable URL

```sh
FILE=/tmp/video-v4/agentvisor-mockup-v4.mp4
NAME='agentvisor-mockup-final.mp4'
REPO_ID="$(gh api repos/AgentVisorAI/agentvisor-ai --jq .id)"
curl --fail-with-body -sS -X POST \
  "https://uploads.github.com/user-attachments/assets" \
  --url-query "name=$NAME" \
  --url-query "content_type=video/mp4" \
  --url-query "repository_id=$REPO_ID" \
  -H "Content-Type: application/octet-stream" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  -H "Authorization: Bearer $(gh auth token)" \
  --data-binary "@$FILE" | jq -r .url
```

## Storyboard

See `STORYBOARD.md` for the full narrative arc and design decisions.

## When to re-record

* SPA visual changes (any change to `docs/app/styles.css` or the
  overview/session-detail rendering).
* Landing page hero copy changes (affects verify page background).
* Trust-anchor list changes (would break the green sample-verify
  scene 6).
