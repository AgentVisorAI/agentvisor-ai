#!/usr/bin/env bash
# Build a subtle audio bed for the full-flow walkthrough (~50s).
#
# Design principles:
#   * NO music. Nothing tonal. Nothing that could sound cheap.
#   * Just soft "punctuation" — a short bandpass-filtered noise
#     whoosh at each scene crossfade.
#   * Very low volume — barely perceptible individually.
#
# 8 scenes = 7 transitions. First transition (landing → signin)
# is slightly stronger; last transition (verify → close) is soft.
set -euo pipefail

OUT=/tmp/video-v4/audio
mkdir -p "$OUT"

# Generate a single whoosh (~400ms)
gen_whoosh() {
  local out=$1
  local vol=$2
  ffmpeg -y -f lavfi -i "anoisesrc=duration=0.4:color=pink:amplitude=0.7" \
    -af "highpass=f=180,lowpass=f=2200,volume=$vol,afade=t=in:st=0:d=0.03,afade=t=out:st=0.10:d=0.30" \
    -c:a pcm_s16le -ar 44100 -ac 2 "$out" 2>&1 | tail -1
}

gen_whoosh "$OUT/w-normal.wav" 0.42
gen_whoosh "$OUT/w-strong.wav" 0.65   # scene 1 → 2 (into the app)
gen_whoosh "$OUT/w-soft.wav"   0.28   # last transition (into close)

# Silent bed for 52 seconds (covers ~50s expected total).
ffmpeg -y -f lavfi -i "anullsrc=r=44100:cl=stereo:d=52" \
  -c:a pcm_s16le "$OUT/silence.wav" 2>&1 | tail -1

# Transition offsets in ms — from compose.sh's `Offsets:` output.
T1=6367    # 1 → 2  (landing → signin)
T2=12934   # 2 → 3  (signin → overview)
T3=20267   # 3 → 4  (overview → sessions)
T4=26534   # 4 → 5  (sessions → session)
T5=35767   # 5 → 6  (session → download)
T6=40500   # 6 → 7  (download → verify)
T7=48233   # 7 → 8  (verify → close)

ffmpeg -y \
  -i "$OUT/silence.wav" \
  -i "$OUT/w-strong.wav" \
  -i "$OUT/w-normal.wav" \
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
    [7]adelay=${T7}|${T7}[w7];
    [0][w1][w2][w3][w4][w5][w6][w7]amix=inputs=8:duration=first:normalize=0[mix];
    [mix]loudnorm=I=-24:LRA=8:TP=-3.0[out]
  " \
  -map "[out]" -c:a aac -b:a 128k "$OUT/soundtrack-44s.aac" 2>&1 | tail -2

ls -lh "$OUT/soundtrack-44s.aac"
