#!/usr/bin/env bash
# Build a subtle audio bed for the 44s full video.
#
# Design principles:
#   * NO music. Nothing tonal. Nothing that could sound cheap.
#   * Just soft "punctuation" — a short bandpass-filtered noise
#     whoosh at each of the 6 scene transitions.
#   * Very low volume — barely perceptible individually.
#   * Total soundtrack budget: silence + 6 whooshes ~= 2 seconds of
#     actual audible content over 44s.
#
# The point: silent video feels like a screen record. Even the
# barest punctuation feels like produced content.
set -euo pipefail

OUT=/tmp/video-v4/audio
mkdir -p "$OUT"

# ── Transition timeline (calculated from scene durations) ─────────
# Crossfades happen at:
#   scene 1 -> 2 at 5.48 - 0.25 = 5.23s
#   scene 2 -> 3 at ~10.42s
#   scene 3 -> 4 at ~13.88s
#   scene 4 -> 5 at ~22.18s
#   scene 5 -> 6 at ~31.92s
#   scene 6 -> 7 at ~39.86s
#
# We fire the whoosh at the START of each crossfade so it "punctuates"
# the transition rather than trailing behind it.

# Generate a single whoosh (~400ms)
gen_whoosh() {
  local out=$1
  local vol=$2
  ffmpeg -y -f lavfi -i "anoisesrc=duration=0.4:color=pink:amplitude=0.7" \
    -af "highpass=f=180,lowpass=f=2200,volume=$vol,afade=t=in:st=0:d=0.03,afade=t=out:st=0.10:d=0.30" \
    -c:a pcm_s16le -ar 44100 -ac 2 "$out" 2>&1 | tail -1
}

# Slightly different tones for different transitions — the impact
# whoosh at the "problem" moment is more intense.
gen_whoosh "$OUT/w-normal.wav" 0.42
gen_whoosh "$OUT/w-problem.wav" 0.70   # scene 1 → 2 (impact)
gen_whoosh "$OUT/w-soft.wav" 0.30      # scene 6 → 7 (denouement)

# Silent bed for 44 seconds
ffmpeg -y -f lavfi -i "anullsrc=r=44100:cl=stereo:d=44" \
  -c:a pcm_s16le "$OUT/silence.wav" 2>&1 | tail -1

# Overlay whooshes at transition points using amix + adelay
# Transition offsets in ms:
T1=5230    # scene 1 → 2 (problem impact)
T2=10420   # scene 2 → 3
T3=13880   # scene 3 → 4
T4=22180   # scene 4 → 5
T5=31920   # scene 5 → 6
T6=39860   # scene 6 → 7 (soft denouement)

ffmpeg -y \
  -i "$OUT/silence.wav" \
  -i "$OUT/w-problem.wav" \
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
  -map "[out]" -c:a aac -b:a 128k "$OUT/soundtrack-44s.aac" 2>&1 | tail -2

ls -lh "$OUT/soundtrack-44s.aac"
