#!/usr/bin/env bash
# Whoosh bed for the v21 distilled mock (~30s). 5 scenes = 4
# transitions. Pink-noise punctuation only; no music.
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
gen_whoosh "$OUT/w-strong.wav" 0.65   # problem -> value
gen_whoosh "$OUT/w-soft.wav"   0.28   # proof -> close

ffmpeg -y -f lavfi -i "anullsrc=r=44100:cl=stereo:d=32" \
  -c:a pcm_s16le "$OUT/silence.wav" 2>&1 | tail -1

# From compose.sh `Offsets:` output.
T1=3467
T2=10367
T3=18234
T4=24701

ffmpeg -y \
  -i "$OUT/silence.wav" \
  -i "$OUT/w-strong.wav" \
  -i "$OUT/w-normal.wav" \
  -i "$OUT/w-normal.wav" \
  -i "$OUT/w-soft.wav" \
  -filter_complex "
    [1]adelay=${T1}|${T1}[w1];
    [2]adelay=${T2}|${T2}[w2];
    [3]adelay=${T3}|${T3}[w3];
    [4]adelay=${T4}|${T4}[w4];
    [0][w1][w2][w3][w4]amix=inputs=5:duration=first:normalize=0[mix];
    [mix]loudnorm=I=-24:LRA=8:TP=-3.0[out]
  " \
  -map "[out]" -c:a aac -b:a 128k "$OUT/soundtrack-44s.aac" 2>&1 | tail -1

ls -lh "$OUT/soundtrack-44s.aac"
