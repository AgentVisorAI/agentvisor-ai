#!/usr/bin/env bash
# Stitch the 8 scenes of the full-flow walkthrough into one video
# with crossfades and burned-in captions on the UI scenes.
#
# Scene structure (v16 full-flow):
#   01-landing  — marketing site, brief Ken Burns
#   02-signin   — live login form fill
#   03-overview — dashboard first-load, zoom to $31,840 tile
#   04-sessions — sessions list, pulse blocked pill
#   05-session  — session detail, pulse $8,400 blocked value
#   06-download — hover + click Download receipt
#   07-verify   — public verifier, drop file, green tick
#   08-close    — CTA card
set -euo pipefail

SCENES=/tmp/video-v4/scenes
OUT=/tmp/video-v4
FONT="/System/Library/Fonts/Supplemental/Arial Bold.ttf"

if [ ! -f "$FONT" ]; then
  FONT=$(fc-list | awk -F: 'NR==1{print $1; exit}')
fi
echo "Using font: $FONT"

dur() {
  ffprobe -v error -select_streams v:0 -show_entries stream=duration -of default=nokey=1:noprint_wrappers=1 "$1"
}

mkdir -p "$OUT/norm"

# Scenes with no burned-in caption: landing, signin, close.
#
# Scene 1 (landing) gets a 0.3s trim off the front to skip the
# brief white flash Playwright emits while the page loads. The
# first frame of the final video is the thumbnail everyone sees
# when the URL is shared — it has to be the fully-composed
# landing page, not a white flash.
for name in 01-landing 02-signin 08-close; do
  if [ "$name" = "01-landing" ] || [ "$name" = "08-close" ]; then
    trim="-ss 0.30"
  else
    trim=""
  fi
  ffmpeg -y $trim -i "$SCENES/$name.webm" \
    -vf "fps=30,scale=1920:1080:flags=lanczos,format=yuv420p" \
    -c:v libx264 -preset medium -crf 20 -pix_fmt yuv420p \
    "$OUT/norm/$name.mp4" 2>&1 | tail -1
done

# UI scenes: caption bar at bottom, with optional time gate
add_caption() {
  local input=$1
  local output=$2
  local caption=$3
  local enable=${4:-1}     # "1" = always visible; else an ffmpeg expression like "gte(t,2)"
  local escaped=$(printf '%s' "$caption" | sed "s/'/\\\\\\\\'/g; s/:/\\\\:/g")
  local drawbox="drawbox=x=0:y=ih-140:w=iw:h=140:color=black@0.72:t=fill:enable='$enable'"
  local drawtext="drawtext=fontfile='$FONT':text='$escaped':fontsize=42:fontcolor=white:x=(w-text_w)/2:y=h-100:enable='$enable'"
  ffmpeg -y -i "$input" -vf "
    fps=30,
    scale=1920:1080:flags=lanczos,
    $drawbox,
    $drawtext,
    format=yuv420p
  " -c:v libx264 -preset medium -crf 20 -pix_fmt yuv420p "$output" 2>&1 | tail -1
}

add_caption "$SCENES/03-overview.webm" "$OUT/norm/03-overview.mp4" \
  "32 sessions · 7 blocked · \$31,840 saved."

add_caption "$SCENES/04-sessions.webm" "$OUT/norm/04-sessions.mp4" \
  "One session was blocked."

add_caption "$SCENES/05-session.webm" "$OUT/norm/05-session.mp4" \
  "Blocked at \$8,400. Signed. Auditable."

add_caption "$SCENES/06-download.webm" "$OUT/norm/06-download.mp4" \
  "Downloadable. Portable. Provable."

# Scene 7 is interactive — empty drop zone in the first ~1.5s (cursor
# pre-positioned near the sample link, so viewer's eye is already
# there), then click, then verified state. Caption fades in at t=2.0s
# once the verified card is centered on screen.
add_caption "$SCENES/07-verify.webm" "$OUT/norm/07-verify.mp4" \
  "Drop the receipt. Verified in the browser. No account." \
  "gte(t,2.0)"

D1=$(dur "$OUT/norm/01-landing.mp4")
D2=$(dur "$OUT/norm/02-signin.mp4")
D3=$(dur "$OUT/norm/03-overview.mp4")
D4=$(dur "$OUT/norm/04-sessions.mp4")
D5=$(dur "$OUT/norm/05-session.mp4")
D6=$(dur "$OUT/norm/06-download.mp4")
D7=$(dur "$OUT/norm/07-verify.mp4")
D8=$(dur "$OUT/norm/08-close.mp4")
echo "Durations: 1=$D1 2=$D2 3=$D3 4=$D4 5=$D5 6=$D6 7=$D7 8=$D8"

XF=0.5
O2=$(awk "BEGIN{printf \"%.3f\", $D1 - $XF}")
O3=$(awk "BEGIN{printf \"%.3f\", $O2 + $D2 - $XF}")
O4=$(awk "BEGIN{printf \"%.3f\", $O3 + $D3 - $XF}")
O5=$(awk "BEGIN{printf \"%.3f\", $O4 + $D4 - $XF}")
O6=$(awk "BEGIN{printf \"%.3f\", $O5 + $D5 - $XF}")
O7=$(awk "BEGIN{printf \"%.3f\", $O6 + $D6 - $XF}")
O8=$(awk "BEGIN{printf \"%.3f\", $O7 + $D7 - $XF}")
echo "Offsets: 2=$O2 3=$O3 4=$O4 5=$O5 6=$O6 7=$O7 8=$O8"

ffmpeg -y \
  -i "$OUT/norm/01-landing.mp4" \
  -i "$OUT/norm/02-signin.mp4" \
  -i "$OUT/norm/03-overview.mp4" \
  -i "$OUT/norm/04-sessions.mp4" \
  -i "$OUT/norm/05-session.mp4" \
  -i "$OUT/norm/06-download.mp4" \
  -i "$OUT/norm/07-verify.mp4" \
  -i "$OUT/norm/08-close.mp4" \
  -filter_complex "
    [0:v][1:v]xfade=transition=fade:duration=$XF:offset=$O2[v01];
    [v01][2:v]xfade=transition=fade:duration=$XF:offset=$O3[v02];
    [v02][3:v]xfade=transition=fade:duration=$XF:offset=$O4[v03];
    [v03][4:v]xfade=transition=fade:duration=$XF:offset=$O5[v04];
    [v04][5:v]xfade=transition=fade:duration=$XF:offset=$O6[v05];
    [v05][6:v]xfade=transition=fade:duration=$XF:offset=$O7[v06];
    [v06][7:v]xfade=transition=fade:duration=$XF:offset=$O8[v07];
    [v07]fade=t=out:st=$(awk "BEGIN{printf \"%.3f\", $O8 + $D8 - 0.8}"):d=0.8:color=black[vout]
  " \
  -map "[vout]" \
  -c:v libx264 -preset medium -crf 20 -pix_fmt yuv420p -movflags +faststart \
  "$OUT/agentvisor-mockup-v4.mp4" 2>&1 | tail -3

ffprobe "$OUT/agentvisor-mockup-v4.mp4" 2>&1 | grep -E "Duration|Stream" | head -3
ls -lh "$OUT/agentvisor-mockup-v4.mp4"

# Auto-mux audio if a soundtrack exists. Silent video feels like a
# screen recording; even minimal punctuation makes it feel produced.
if [ -f "$OUT/audio/soundtrack-44s.aac" ]; then
  echo "→ Muxing subtle-audio cut (whooshes only)"
  ffmpeg -y -i "$OUT/agentvisor-mockup-v4.mp4" -i "$OUT/audio/soundtrack-44s.aac" \
    -c:v copy -c:a aac -shortest \
    "$OUT/agentvisor-mockup-v9-audio.mp4" 2>&1 | tail -1
  ls -lh "$OUT/agentvisor-mockup-v9-audio.mp4"
fi

# Auto-mux narrated cut if the narration bed exists. This is the
# definitive full-flow cut (voice + whoosh bed).
if [ -f "$OUT/audio/narration-44s.aac" ]; then
  echo "→ Muxing narrated cut (definitive full-flow)"
  ffmpeg -y -i "$OUT/agentvisor-mockup-v4.mp4" -i "$OUT/audio/narration-44s.aac" \
    -c:v copy -c:a aac -shortest \
    "$OUT/agentvisor-mockup-v16-fullflow.mp4" 2>&1 | tail -1
  ls -lh "$OUT/agentvisor-mockup-v16-fullflow.mp4"
fi
