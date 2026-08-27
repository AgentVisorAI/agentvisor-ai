#!/usr/bin/env bash
# Stitch the 5 scenes of the v21 distilled mock (~27s final).
#
#   01-problem  — "One wrong decision. $8,400 gone."
#   02-overview — dashboard, zoom to $31,840
#   03-session  — the blocked $8,400, signed
#   04-verify   — receipt verifies in the browser, green tick
#   05-close    — CTA card
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

# Cards (no captions). Head-trim skips the Playwright load flash;
# the first frame of the final video is the share thumbnail.
for name in 01-problem 05-close; do
  ffmpeg -y -ss 0.30 -i "$SCENES/$name.webm" \
    -vf "fps=30,scale=1920:1080:flags=lanczos:out_color_matrix=bt709,setparams=color_primaries=bt709:color_trc=bt709:colorspace=bt709,format=yuv420p" \
    -c:v libx264 -preset medium -crf 20 -pix_fmt yuv420p \
    -colorspace bt709 -color_primaries bt709 -color_trc bt709 \
    "$OUT/norm/$name.mp4" 2>&1 | tail -1
done

add_caption() {
  local input=$1
  local output=$2
  local caption=$3
  local enable=${4:-1}
  local escaped=$(printf '%s' "$caption" | sed "s/'/\\\\\\\\'/g; s/:/\\\\:/g")
  local drawbox="drawbox=x=0:y=ih-140:w=iw:h=140:color=black@0.72:t=fill:enable='$enable'"
  local drawtext="drawtext=fontfile='$FONT':text='$escaped':fontsize=42:fontcolor=white:x=(w-text_w)/2:y=h-100:enable='$enable'"
  ffmpeg -y -i "$input" -vf "
    fps=30,
    scale=1920:1080:flags=lanczos:out_color_matrix=bt709,
    setparams=color_primaries=bt709:color_trc=bt709:colorspace=bt709,
    $drawbox,
    $drawtext,
    format=yuv420p
  " -c:v libx264 -preset medium -crf 20 -pix_fmt yuv420p \
    -colorspace bt709 -color_primaries bt709 -color_trc bt709 "$output" 2>&1 | tail -1
}

add_caption "$SCENES/02-overview.webm" "$OUT/norm/02-overview.mp4" \
  "AgentVisor watches every AI agent. \$31,840 in prevented losses."

add_caption "$SCENES/03-session.webm" "$OUT/norm/03-session.mp4" \
  "Blocked at \$8,400. Signed."

add_caption "$SCENES/04-verify.webm" "$OUT/norm/04-verify.mp4" \
  "Verified in the browser. No account." \
  "gte(t,1.6)"

D1=$(dur "$OUT/norm/01-problem.mp4")
D2=$(dur "$OUT/norm/02-overview.mp4")
D3=$(dur "$OUT/norm/03-session.mp4")
D4=$(dur "$OUT/norm/04-verify.mp4")
D5=$(dur "$OUT/norm/05-close.mp4")
echo "Durations: 1=$D1 2=$D2 3=$D3 4=$D4 5=$D5"

XF=0.5
O2=$(awk "BEGIN{printf \"%.3f\", $D1 - $XF}")
O3=$(awk "BEGIN{printf \"%.3f\", $O2 + $D2 - $XF}")
O4=$(awk "BEGIN{printf \"%.3f\", $O3 + $D3 - $XF}")
O5=$(awk "BEGIN{printf \"%.3f\", $O4 + $D4 - $XF}")
echo "Offsets: 2=$O2 3=$O3 4=$O4 5=$O5"

ffmpeg -y \
  -i "$OUT/norm/01-problem.mp4" \
  -i "$OUT/norm/02-overview.mp4" \
  -i "$OUT/norm/03-session.mp4" \
  -i "$OUT/norm/04-verify.mp4" \
  -i "$OUT/norm/05-close.mp4" \
  -filter_complex "
    [0:v][1:v]xfade=transition=fade:duration=$XF:offset=$O2[v01];
    [v01][2:v]xfade=transition=fade:duration=$XF:offset=$O3[v02];
    [v02][3:v]xfade=transition=fade:duration=$XF:offset=$O4[v03];
    [v03][4:v]xfade=transition=fade:duration=$XF:offset=$O5[v04];
    [v04]fade=t=out:st=$(awk "BEGIN{printf \"%.3f\", $O5 + $D5 - 0.8}"):d=0.8:color=black[vout]
  " \
  -map "[vout]" \
  -c:v libx264 -preset medium -crf 20 -pix_fmt yuv420p -movflags +faststart \
  -colorspace bt709 -color_primaries bt709 -color_trc bt709 \
  "$OUT/agentvisor-mockup-v4.mp4" 2>&1 | tail -3

ffprobe "$OUT/agentvisor-mockup-v4.mp4" 2>&1 | grep -E "Duration|Stream" | head -3
ls -lh "$OUT/agentvisor-mockup-v4.mp4"

if [ -f "$OUT/audio/soundtrack-44s.aac" ]; then
  echo "→ Muxing subtle-audio cut (whooshes only)"
  ffmpeg -y -i "$OUT/agentvisor-mockup-v4.mp4" -i "$OUT/audio/soundtrack-44s.aac" \
    -c:v copy -c:a aac -ar 48000 -shortest -movflags +faststart \
    "$OUT/agentvisor-mockup-v9-audio.mp4" 2>&1 | tail -1
  ls -lh "$OUT/agentvisor-mockup-v9-audio.mp4"
fi

if [ -f "$OUT/audio/narration-44s.aac" ]; then
  echo "→ Muxing narrated cut (definitive v21 distilled)"
  ffmpeg -y -i "$OUT/agentvisor-mockup-v4.mp4" -i "$OUT/audio/narration-44s.aac" \
    -c:v copy -af "volume=4dB" -c:a aac -ar 48000 -shortest -movflags +faststart \
    "$OUT/agentvisor-mockup-v21-distilled.mp4" 2>&1 | tail -1
  ls -lh "$OUT/agentvisor-mockup-v21-distilled.mp4"
fi
