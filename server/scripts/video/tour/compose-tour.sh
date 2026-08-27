#!/usr/bin/env bash
# Stitch the 11 scenes of the v20 novice tour into one video with
# crossfades and burned-in captions on the UI scenes.
#
# Scene structure (v20 full tour):
#   01-landing     — marketing site, Ken Burns to CTA
#   02-signup      — live workspace creation (org, email, password)
#   03-overview    — dashboard, chart hover, zoom to $31,840
#   04-sessions    — search, clear, blocked-only filter
#   05-session     — blocked $8,400 detail + event drawer
#   06-download    — click Download receipt
#   07-verify      — public verifier, green tick
#   08-policies    — the rule that blocked the money, in plain text
#   09-deployments — per-deployment keys + tokens
#   10-settings    — members, API keys, webhooks
#   11-close       — CTA card
set -euo pipefail

SCENES=/tmp/video-tour/scenes
OUT=/tmp/video-tour
FONT="/System/Library/Fonts/Supplemental/Arial Bold.ttf"

if [ ! -f "$FONT" ]; then
  FONT=$(fc-list | awk -F: 'NR==1{print $1; exit}')
fi
echo "Using font: $FONT"

dur() {
  ffprobe -v error -select_streams v:0 -show_entries stream=duration -of default=nokey=1:noprint_wrappers=1 "$1"
}

mkdir -p "$OUT/norm"

# Scenes with no burned-in caption: landing, signup, close.
# Landing + close get a 0.3s head-trim to skip the Playwright load
# flash. The first frame of the final video is the share thumbnail.
for name in 01-landing 02-signup 11-close; do
  if [ "$name" = "01-landing" ] || [ "$name" = "11-close" ]; then
    trim="-ss 0.30"
  else
    trim=""
  fi
  ffmpeg -y $trim -i "$SCENES/$name.webm" \
    -vf "fps=30,scale=1920:1080:flags=lanczos:out_color_matrix=bt709,setparams=color_primaries=bt709:color_trc=bt709:colorspace=bt709,format=yuv420p" \
    -c:v libx264 -preset medium -crf 20 -pix_fmt yuv420p -colorspace bt709 -color_primaries bt709 -color_trc bt709 -movflags +faststart \
    "$OUT/norm/$name.mp4" 2>&1 | tail -1
done

# UI scenes: caption bar at bottom, with optional time gate.
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
  " -c:v libx264 -preset medium -crf 20 -pix_fmt yuv420p -colorspace bt709 -color_primaries bt709 -color_trc bt709 "$output" 2>&1 | tail -1
}

add_caption "$SCENES/03-overview.webm" "$OUT/norm/03-overview.mp4" \
  "32 sessions · 7 blocked · \$31,840 saved."

add_caption "$SCENES/04-sessions.webm" "$OUT/norm/04-sessions.mp4" \
  "Search, filter, isolate the blocked ones."

add_caption "$SCENES/05-session.webm" "$OUT/norm/05-session.mp4" \
  "Blocked at \$8,400. Every event inspectable."

add_caption "$SCENES/06-download.webm" "$OUT/norm/06-download.mp4" \
  "Downloadable. Portable. Provable."

add_caption "$SCENES/07-verify.webm" "$OUT/norm/07-verify.mp4" \
  "Drop the receipt. Verified in the browser. No account." \
  "gte(t,1.6)"

add_caption "$SCENES/08-policies.webm" "$OUT/norm/08-policies.mp4" \
  "Policies are readable rules, enforced in real time."

add_caption "$SCENES/09-deployments.webm" "$OUT/norm/09-deployments.mp4" \
  "Every deployment gets its own signing key."

add_caption "$SCENES/10-settings.webm" "$OUT/norm/10-settings.mp4" \
  "Members, API keys, webhooks. Fully self-serve."

D1=$(dur "$OUT/norm/01-landing.mp4")
D2=$(dur "$OUT/norm/02-signup.mp4")
D3=$(dur "$OUT/norm/03-overview.mp4")
D4=$(dur "$OUT/norm/04-sessions.mp4")
D5=$(dur "$OUT/norm/05-session.mp4")
D6=$(dur "$OUT/norm/06-download.mp4")
D7=$(dur "$OUT/norm/07-verify.mp4")
D8=$(dur "$OUT/norm/08-policies.mp4")
D9=$(dur "$OUT/norm/09-deployments.mp4")
D10=$(dur "$OUT/norm/10-settings.mp4")
D11=$(dur "$OUT/norm/11-close.mp4")
echo "Durations: 1=$D1 2=$D2 3=$D3 4=$D4 5=$D5 6=$D6 7=$D7 8=$D8 9=$D9 10=$D10 11=$D11"

XF=0.5
O2=$(awk "BEGIN{printf \"%.3f\", $D1 - $XF}")
O3=$(awk "BEGIN{printf \"%.3f\", $O2 + $D2 - $XF}")
O4=$(awk "BEGIN{printf \"%.3f\", $O3 + $D3 - $XF}")
O5=$(awk "BEGIN{printf \"%.3f\", $O4 + $D4 - $XF}")
O6=$(awk "BEGIN{printf \"%.3f\", $O5 + $D5 - $XF}")
O7=$(awk "BEGIN{printf \"%.3f\", $O6 + $D6 - $XF}")
O8=$(awk "BEGIN{printf \"%.3f\", $O7 + $D7 - $XF}")
O9=$(awk "BEGIN{printf \"%.3f\", $O8 + $D8 - $XF}")
O10=$(awk "BEGIN{printf \"%.3f\", $O9 + $D9 - $XF}")
O11=$(awk "BEGIN{printf \"%.3f\", $O10 + $D10 - $XF}")
echo "Offsets: 2=$O2 3=$O3 4=$O4 5=$O5 6=$O6 7=$O7 8=$O8 9=$O9 10=$O10 11=$O11"

ffmpeg -y \
  -i "$OUT/norm/01-landing.mp4" \
  -i "$OUT/norm/02-signup.mp4" \
  -i "$OUT/norm/03-overview.mp4" \
  -i "$OUT/norm/04-sessions.mp4" \
  -i "$OUT/norm/05-session.mp4" \
  -i "$OUT/norm/06-download.mp4" \
  -i "$OUT/norm/07-verify.mp4" \
  -i "$OUT/norm/08-policies.mp4" \
  -i "$OUT/norm/09-deployments.mp4" \
  -i "$OUT/norm/10-settings.mp4" \
  -i "$OUT/norm/11-close.mp4" \
  -filter_complex "
    [0:v][1:v]xfade=transition=fade:duration=$XF:offset=$O2[v01];
    [v01][2:v]xfade=transition=fade:duration=$XF:offset=$O3[v02];
    [v02][3:v]xfade=transition=fade:duration=$XF:offset=$O4[v03];
    [v03][4:v]xfade=transition=fade:duration=$XF:offset=$O5[v04];
    [v04][5:v]xfade=transition=fade:duration=$XF:offset=$O6[v05];
    [v05][6:v]xfade=transition=fade:duration=$XF:offset=$O7[v06];
    [v06][7:v]xfade=transition=fade:duration=$XF:offset=$O8[v07];
    [v07][8:v]xfade=transition=fade:duration=$XF:offset=$O9[v08];
    [v08][9:v]xfade=transition=fade:duration=$XF:offset=$O10[v09];
    [v09][10:v]xfade=transition=fade:duration=$XF:offset=$O11[v10];
    [v10]fade=t=out:st=$(awk "BEGIN{printf \"%.3f\", $O11 + $D11 - 0.8}"):d=0.8:color=black[vout]
  " \
  -map "[vout]" \
  -c:v libx264 -preset medium -crf 20 -pix_fmt yuv420p -movflags +faststart \
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
  echo "→ Muxing narrated cut (definitive v20 tour)"
  ffmpeg -y -i "$OUT/agentvisor-mockup-v4.mp4" -i "$OUT/audio/narration-44s.aac" \
    -c:v copy -af "volume=4dB" -c:a aac -ar 48000 -shortest -movflags +faststart \
    "$OUT/agentvisor-mockup-v20-tour.mp4" 2>&1 | tail -1
  ls -lh "$OUT/agentvisor-mockup-v20-tour.mp4"
fi
