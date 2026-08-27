#!/usr/bin/env bash
# Stitch the 7 scenes into one video with crossfades and burned-in
# captions on the UI scenes.
set -euo pipefail

SCENES=/tmp/video-v4/scenes
OUT=/tmp/video-v4
FONT="/System/Library/Fonts/Supplemental/Arial Bold.ttf"

# Fallback font check
if [ ! -f "$FONT" ]; then
  FONT=$(fc-list | awk -F: 'NR==1{print $1; exit}')
fi
echo "Using font: $FONT"

# Get each scene's actual duration (Playwright's WebM sometimes clips
# slightly short of the requested duration).
dur() {
  ffprobe -v error -select_streams v:0 -show_entries stream=duration -of default=nokey=1:noprint_wrappers=1 "$1"
}

# ═════════════════════════════════════════════════════════════════
# Step 1: normalize each scene to 30fps H.264, adding captions where
# the underlying video is a UI scene (no captions on title cards).
# ═════════════════════════════════════════════════════════════════
mkdir -p "$OUT/norm"

# Title cards: just re-encode as-is
for name in 01-intro 02-problem 03-solution 07-close; do
  ffmpeg -y -i "$SCENES/$name.webm" \
    -vf "fps=30,scale=1920:1080:flags=lanczos,format=yuv420p" \
    -c:v libx264 -preset medium -crf 20 -pix_fmt yuv420p \
    "$OUT/norm/$name.mp4" 2>&1 | tail -1
done

# UI scenes: overlay a caption bar at bottom
add_caption() {
  local input=$1
  local output=$2
  local caption=$3
  # Escape apostrophes for ffmpeg drawtext
  local escaped=$(printf '%s' "$caption" | sed "s/'/\\\\\\\\'/g; s/:/\\\\:/g")
  # Draw a solid black bar (66% opacity) at bottom, then text over it
  ffmpeg -y -i "$input" -vf "
    fps=30,
    scale=1920:1080:flags=lanczos,
    drawbox=x=0:y=ih-140:w=iw:h=140:color=black@0.72:t=fill,
    drawtext=fontfile='$FONT':text='$escaped':fontsize=42:fontcolor=white:x=(w-text_w)/2:y=h-100,
    format=yuv420p
  " -c:v libx264 -preset medium -crf 20 -pix_fmt yuv420p "$output" 2>&1 | tail -1
}

add_caption "$SCENES/04-console.webm" "$OUT/norm/04-console.mp4" \
  "Every session — every tool call — captured in real time."

add_caption "$SCENES/05-session.webm" "$OUT/norm/05-session.mp4" \
  "Blocked at \$8,400. Signed. Auditable."

add_caption "$SCENES/06-verify.webm" "$OUT/norm/06-verify.mp4" \
  "Drop the receipt. Verified in the browser. No account."

# ═════════════════════════════════════════════════════════════════
# Step 2: crossfade all 7 clips together.
# ═════════════════════════════════════════════════════════════════
# Get durations
D1=$(dur "$OUT/norm/01-intro.mp4")
D2=$(dur "$OUT/norm/02-problem.mp4")
D3=$(dur "$OUT/norm/03-solution.mp4")
D4=$(dur "$OUT/norm/04-console.mp4")
D5=$(dur "$OUT/norm/05-session.mp4")
D6=$(dur "$OUT/norm/06-verify.mp4")
D7=$(dur "$OUT/norm/07-close.mp4")
echo "Durations: 1=$D1 2=$D2 3=$D3 4=$D4 5=$D5 6=$D6 7=$D7"

# xfade needs offsets (start time of each crossfade transition)
# Each crossfade lasts 0.5s
XF=0.5
# Offset formula: sum of previous durations minus (XF * number of previous transitions)
# t2_offset = D1 - XF
# t3_offset = t2_offset + D2 - XF
# etc.
O2=$(awk "BEGIN{printf \"%.3f\", $D1 - $XF}")
O3=$(awk "BEGIN{printf \"%.3f\", $O2 + $D2 - $XF}")
O4=$(awk "BEGIN{printf \"%.3f\", $O3 + $D3 - $XF}")
O5=$(awk "BEGIN{printf \"%.3f\", $O4 + $D4 - $XF}")
O6=$(awk "BEGIN{printf \"%.3f\", $O5 + $D5 - $XF}")
O7=$(awk "BEGIN{printf \"%.3f\", $O6 + $D6 - $XF}")
echo "Offsets: 2=$O2 3=$O3 4=$O4 5=$O5 6=$O6 7=$O7"

ffmpeg -y \
  -i "$OUT/norm/01-intro.mp4" \
  -i "$OUT/norm/02-problem.mp4" \
  -i "$OUT/norm/03-solution.mp4" \
  -i "$OUT/norm/04-console.mp4" \
  -i "$OUT/norm/05-session.mp4" \
  -i "$OUT/norm/06-verify.mp4" \
  -i "$OUT/norm/07-close.mp4" \
  -filter_complex "
    [0:v][1:v]xfade=transition=fade:duration=$XF:offset=$O2[v01];
    [v01][2:v]xfade=transition=fade:duration=$XF:offset=$O3[v02];
    [v02][3:v]xfade=transition=fade:duration=$XF:offset=$O4[v03];
    [v03][4:v]xfade=transition=fade:duration=$XF:offset=$O5[v04];
    [v04][5:v]xfade=transition=fade:duration=$XF:offset=$O6[v05];
    [v05][6:v]xfade=transition=fade:duration=$XF:offset=$O7[vout]
  " \
  -map "[vout]" \
  -c:v libx264 -preset medium -crf 20 -pix_fmt yuv420p -movflags +faststart \
  "$OUT/agentvisor-mockup-v4.mp4" 2>&1 | tail -3

ffprobe "$OUT/agentvisor-mockup-v4.mp4" 2>&1 | grep -E "Duration|Stream" | head -3
ls -lh "$OUT/agentvisor-mockup-v4.mp4"
