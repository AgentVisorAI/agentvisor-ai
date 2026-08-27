#!/usr/bin/env bash
# 15-second social teaser for LinkedIn / Twitter / X feeds.
#
# Uses the same source scenes as the 44s cut but truncated + tightened.
# Perfect for the "click-to-play muted preview" moment on a feed.
set -euo pipefail

SCENES=/tmp/video-v4/scenes
OUT=/tmp/video-v4
NORM=$OUT/norm-teaser
FONT="/System/Library/Fonts/Supplemental/Arial Bold.ttf"

if [ ! -f "$FONT" ]; then
  FONT=$(fc-list | awk -F: 'NR==1{print $1; exit}')
fi

mkdir -p "$NORM"

# 2-second scene 2 (problem hook — $8,400 gone)
ffmpeg -y -ss 1.2 -t 2.4 -i "$SCENES/02-problem.webm" \
  -vf "fps=30,scale=1920:1080:flags=lanczos,format=yuv420p" \
  -c:v libx264 -preset medium -crf 20 -pix_fmt yuv420p \
  "$NORM/02.mp4" 2>&1 | tail -1

# 4-second scene 5 (the receipt — $8,400 pulse + Signature verified)
add_caption_gate() {
  local input=$1 output=$2 caption=$3 start=$4 duration=$5
  local escaped=$(printf '%s' "$caption" | sed "s/'/\\\\\\\\'/g; s/:/\\\\:/g")
  ffmpeg -y -ss "$start" -t "$duration" -i "$input" -vf "
    fps=30,
    scale=1920:1080:flags=lanczos,
    drawbox=x=0:y=ih-140:w=iw:h=140:color=black@0.72:t=fill,
    drawtext=fontfile='$FONT':text='$escaped':fontsize=42:fontcolor=white:x=(w-text_w)/2:y=h-100,
    format=yuv420p
  " -c:v libx264 -preset medium -crf 20 -pix_fmt yuv420p "$output" 2>&1 | tail -1
}

add_caption_gate "$SCENES/05-session.webm" "$NORM/05.mp4" \
  "Blocked at \$8,400. Signed." 1.5 4.0

# 4-second scene 6 (verified state after skip to click completion)
add_caption_gate "$SCENES/06-verify.webm" "$NORM/06.mp4" \
  "Anyone can verify. In their browser." 3.5 4.0

# 3-second closing (fade out to black over 0.8s)
ffmpeg -y -t 3.0 -i "$SCENES/07-close.webm" \
  -vf "fps=30,scale=1920:1080:flags=lanczos,format=yuv420p" \
  -c:v libx264 -preset medium -crf 20 -pix_fmt yuv420p \
  "$NORM/07.mp4" 2>&1 | tail -1

# Get durations
dur() { ffprobe -v error -select_streams v:0 -show_entries stream=duration -of default=nokey=1:noprint_wrappers=1 "$1"; }
D2=$(dur "$NORM/02.mp4")
D5=$(dur "$NORM/05.mp4")
D6=$(dur "$NORM/06.mp4")
D7=$(dur "$NORM/07.mp4")
echo "Durations: 2=$D2 5=$D5 6=$D6 7=$D7"

XF=0.35
O5=$(awk "BEGIN{printf \"%.3f\", $D2 - $XF}")
O6=$(awk "BEGIN{printf \"%.3f\", $O5 + $D5 - $XF}")
O7=$(awk "BEGIN{printf \"%.3f\", $O6 + $D6 - $XF}")

ffmpeg -y \
  -i "$NORM/02.mp4" \
  -i "$NORM/05.mp4" \
  -i "$NORM/06.mp4" \
  -i "$NORM/07.mp4" \
  -filter_complex "
    [0:v][1:v]xfade=transition=fade:duration=$XF:offset=$O5[v01];
    [v01][2:v]xfade=transition=fade:duration=$XF:offset=$O6[v02];
    [v02][3:v]xfade=transition=fade:duration=$XF:offset=$O7[v03];
    [v03]fade=t=in:st=0:d=0.4:color=black,fade=t=out:st=$(awk "BEGIN{printf \"%.3f\", $O7 + $D7 - 0.6}"):d=0.6:color=black[vout]
  " \
  -map "[vout]" \
  -c:v libx264 -preset medium -crf 20 -pix_fmt yuv420p -movflags +faststart \
  "$OUT/agentvisor-mockup-teaser.mp4" 2>&1 | tail -3

ffprobe "$OUT/agentvisor-mockup-teaser.mp4" 2>&1 | grep -E "Duration|Stream" | head -3
ls -lh "$OUT/agentvisor-mockup-teaser.mp4"
