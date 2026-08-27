#!/usr/bin/env bash
# Build a subtle audio bed for the v17 flow-with-hook walkthrough
# (~35s target). 7 scenes = 6 transitions.
#
# Design principles:
#   * NO music. Nothing tonal.
#   * Just soft "punctuation" — bandpass-filtered pink noise
#     whoosh at each scene crossfade.
#   * Very low volume.
set -euo pipefail

OUT=/tmp/video-v4/audio
mkdir -p "$OUT"

gen_whoosh() {
  local out=$1
  local vol=$2
  ffmpeg -y -f lavfi -i "anoisesrc=duration=0.4:color=pink:amplitude=0.7" \
    -af "highpass=f=180,lowpass=f=2200,volume=$vol,afade=t=in:st=0:d=0.03,afade=t=out:st=0.10:d=0.30" \
    -c:a pcm_s16le -ar 44100 -ac 2 "$out" 2>&1 | tail -1
}

gen_whoosh "$OUT/w-normal.wav" 0.42
gen_whoosh "$OUT/w-strong.wav" 0.70   # scene 1 → 2 (problem-to-product impact)
gen_whoosh "$OUT/w-soft.wav"   0.28   # last transition (into close)

# Silent bed for 40 seconds (covers ~35s expected total).
ffmpeg -y -f lavfi -i "anullsrc=r=44100:cl=stereo:d=40" \
  -c:a pcm_s16le "$OUT/silence.wav" 2>&1 | tail -1

# Transition offsets in ms — retimed from compose.sh's `Offsets:`
# after first record.
T1=3167    # 1 → 2  (problem → signin)
T2=6900    # 2 → 3  (signin → overview)
T3=13800   # 3 → 4  (overview → session)
T4=21533   # 4 → 5  (session → download)
T5=24866   # 5 → 6  (download → verify)
T6=31499   # 6 → 7  (verify → close)

ffmpeg -y \
  -i "$OUT/silence.wav" \
  -i "$OUT/w-strong.wav" \
  -i "$OUT/w-normal.wav" \
  -i "$OUT/w-normal.wav" \
  -i "$OUT/w-normal.wav" \
  -i "$OUT/w-normal.wav" \
  -i "$OUT/w-soft.wav" \
  -filter_complex "
    [1]adelay=${T1}|${T1}[w1];
    [2]adelay=${T2}|${T2}[w2];
    [3]adelay=${T3}|${T3}[w3];
    [4]adelay=${T4}|${T4}[w4];
    [5]adelay=${T5}|${T5}[w5];
    [6]adelay=${T6}|${T6}[w6];
    [0][w1][w2][w3][w4][w5][w6]amix=inputs=7:duration=first:normalize=0[mix];
    [mix]loudnorm=I=-24:LRA=8:TP=-3.0[out]
  " \
  -map "[out]" -c:a aac -b:a 128k "$OUT/soundtrack-44s.aac" 2>&1 | tail -1

ls -lh "$OUT/soundtrack-44s.aac"
